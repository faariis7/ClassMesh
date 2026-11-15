//! Read-only roster metadata screening. This is NOT signature verification or authorization.
//! No approved issuer/trust anchor is configured: all candidates are denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterRejection {
    MissingRoster,
    ExpiredRoster,
    UnsignedRoster,
    WrongPrincipal,
    WrongRole,
    StaleAuthorization,
    MissingApprovedVerifier,
    EmptyStudentDeviceRoster,
    InvalidStudentDeviceRoster,
    InvalidPrincipalOrRole,
    InvalidIssuedTimestamp,
    OversizedStudentDeviceRoster,
}

#[derive(Debug, Clone, Copy)]
pub struct RosterEvidence<'a> {
    pub teacher_principal: &'a str,
    pub role: &'a str,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    /// Untrusted bytes: presence alone never proves a signature.
    pub signature: Option<&'a [u8]>,
    pub student_device_ids: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
pub struct TeacherRosterRequest<'a> {
    pub teacher_principal: &'a str,
    pub required_role: &'a str,
    pub now_unix_ms: u64,
    pub authorization_not_before_unix_ms: u64,
    pub roster: Option<RosterEvidence<'a>>,
}

/// Screens untrusted metadata for explicit denial reasons, never granting authority.
///
/// A production allow decision requires independently verified issuer provenance,
/// signature, Teacher authorization, identity-to-CNG binding, and trusted session/peer.
/// None is supplied by this API. Its return type intentionally has no Allow variant.
pub fn qualify_teacher_roster(request: &TeacherRosterRequest<'_>) -> Result<(), RosterRejection> {
    let roster = request.roster.ok_or(RosterRejection::MissingRoster)?;
    // Reject ambiguous or noncanonical identities before comparing principals/roles.
    for value in [
        request.teacher_principal,
        request.required_role,
        roster.teacher_principal,
        roster.role,
    ] {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(RosterRejection::InvalidPrincipalOrRole);
        }
    }
    if roster.issued_unix_ms == 0 {
        return Err(RosterRejection::InvalidIssuedTimestamp);
    }
    if roster.expires_unix_ms <= request.now_unix_ms
        || roster.expires_unix_ms <= roster.issued_unix_ms
    {
        return Err(RosterRejection::ExpiredRoster);
    }
    if roster.signature.is_none_or(|bytes| bytes.is_empty()) {
        return Err(RosterRejection::UnsignedRoster);
    }
    if roster.teacher_principal != request.teacher_principal {
        return Err(RosterRejection::WrongPrincipal);
    }
    if roster.role != request.required_role {
        return Err(RosterRejection::WrongRole);
    }
    if roster.issued_unix_ms < request.authorization_not_before_unix_ms
        || roster.issued_unix_ms > request.now_unix_ms
    {
        return Err(RosterRejection::StaleAuthorization);
    }
    // Bound work on attacker-controlled metadata before the quadratic duplicate scan.
    // This is a deny-only resource guard, not an enrollment policy or trust decision.
    if roster.student_device_ids.len() > 1024 {
        return Err(RosterRejection::OversizedStudentDeviceRoster);
    }
    if roster.student_device_ids.is_empty() {
        return Err(RosterRejection::EmptyStudentDeviceRoster);
    }
    for (index, id) in roster.student_device_ids.iter().enumerate() {
        if id.is_empty()
            || id.trim() != *id
            || id.chars().any(char::is_control)
            || roster.student_device_ids[..index].contains(id)
        {
            return Err(RosterRejection::InvalidStudentDeviceRoster);
        }
    }
    // Never interpret unverified signature bytes or embedded roster as authority.
    Err(RosterRejection::MissingApprovedVerifier)
}

#[cfg(test)]
mod identifier_hardening_tests {
    use super::*;

    fn request_with_ids<'a>(ids: &'a [&'a str]) -> TeacherRosterRequest<'a> {
        TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster: Some(RosterEvidence {
                teacher_principal: "teacher-1",
                role: "Teacher",
                issued_unix_ms: 150,
                expires_unix_ms: 300,
                signature: Some(&[1]),
                student_device_ids: ids,
            }),
        }
    }

    #[test]
    fn rejects_noncanonical_student_device_identifiers() {
        for ids in [
            &[" device-1"][..],
            &["device-1 "][..],
            &["device-1\n"][..],
            &["device-1\t"][..],
        ] {
            assert_eq!(
                qualify_teacher_roster(&request_with_ids(ids)),
                Err(RosterRejection::InvalidStudentDeviceRoster)
            );
        }
    }

    #[test]
    fn valid_identifiers_still_require_approved_verifier() {
        assert_eq!(
            qualify_teacher_roster(&request_with_ids(&["device-1", "device-2"])),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }
}

#[cfg(test)]
mod malformed_roster_metadata_tests {
    use super::*;

    fn request<'a>(principal: &'a str, role: &'a str, issued: u64) -> TeacherRosterRequest<'a> {
        TeacherRosterRequest {
            teacher_principal: principal,
            required_role: role,
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster: Some(RosterEvidence {
                teacher_principal: principal,
                role,
                issued_unix_ms: issued,
                expires_unix_ms: 300,
                signature: Some(&[1]),
                student_device_ids: &["device-1"],
            }),
        }
    }

    #[test]
    fn malformed_teacher_principal_and_role_are_denied() {
        for (principal, role) in [
            ("", "Teacher"),
            (" teacher-1", "Teacher"),
            ("teacher-1\n", "Teacher"),
            ("teacher-1", ""),
            ("teacher-1", "Teacher\t"),
        ] {
            assert_eq!(
                qualify_teacher_roster(&request(principal, role, 150)),
                Err(RosterRejection::InvalidPrincipalOrRole)
            );
        }
    }

    #[test]
    fn zero_issued_timestamp_is_denied() {
        assert_eq!(
            qualify_teacher_roster(&request("teacher-1", "Teacher", 0)),
            Err(RosterRejection::InvalidIssuedTimestamp)
        );
    }

    #[test]
    fn well_formed_metadata_still_never_authorizes() {
        assert_eq!(
            qualify_teacher_roster(&request("teacher-1", "Teacher", 150)),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }
}

#[cfg(test)]
mod roster_resource_bounds_tests {
    use super::*;

    #[test]
    fn oversized_untrusted_roster_is_denied_before_duplicate_scan() {
        let ids = vec!["device-1"; 1025];
        let request = TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster: Some(RosterEvidence {
                teacher_principal: "teacher-1",
                role: "Teacher",
                issued_unix_ms: 150,
                expires_unix_ms: 300,
                signature: Some(&[1]),
                student_device_ids: &ids,
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::OversizedStudentDeviceRoster)
        );
    }
}
