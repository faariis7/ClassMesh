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
    if roster.student_device_ids.is_empty() {
        return Err(RosterRejection::EmptyStudentDeviceRoster);
    }
    for (index, id) in roster.student_device_ids.iter().enumerate() {
        if id.is_empty()\n            || id.trim() != *id\n            || id.chars().any(char::is_control)\n            || roster.student_device_ids[..index].contains(id)\n        {
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
        for ids in [&[" device-1"][..], &["device-1 "][..], &["device-1\\n"][..]] {
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
