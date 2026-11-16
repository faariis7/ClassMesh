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
    MissingAuthorizationEpoch,
    FutureAuthorizationEpoch,
    OversizedStudentDeviceRoster,
    OversizedStudentDeviceIdentifier,
    OversizedUntrustedSignature,
    OversizedPrincipalOrRole,
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

// Reject invisible format characters that can make distinct IDs look identical.
// This is input screening, not an issuer identity normalization contract.
fn contains_invisible_formatting(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{2060}'
                | '\u{feff}'
                | '\u{fe0e}'
                | '\u{fe0f}'
                | '\u{e0000}'..='\u{e007f}'
        )
    })
}

fn contains_bidi_formatting(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'
        )
    })
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
        if value.is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || contains_bidi_formatting(value)
            || contains_invisible_formatting(value)
        {
            return Err(RosterRejection::InvalidPrincipalOrRole);
        }
    }
    // Bound untrusted identity strings before comparisons; this is not an identity policy.
    if [
        request.teacher_principal,
        request.required_role,
        roster.teacher_principal,
        roster.role,
    ]
    .iter()
    .any(|value| value.len() > 256)
    {
        return Err(RosterRejection::OversizedPrincipalOrRole);
    }
    // A missing authorization epoch cannot establish freshness or prevent replay.
    if request.authorization_not_before_unix_ms == 0 {
        return Err(RosterRejection::MissingAuthorizationEpoch);
    }
    // Reject a local clock older than the authorization epoch before assessing roster age.
    if request.authorization_not_before_unix_ms > request.now_unix_ms {
        return Err(RosterRejection::FutureAuthorizationEpoch);
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
    // Bound attacker-controlled signature bytes without treating them as verified.
    // This is a screening limit only, not a cryptographic algorithm policy.
    if roster.signature.is_some_and(|bytes| bytes.len() > 4096) {
        return Err(RosterRejection::OversizedUntrustedSignature);
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
    let mut seen = std::collections::HashSet::with_capacity(roster.student_device_ids.len());
    for id in roster.student_device_ids {
        // Bound individual untrusted strings as well as roster cardinality.
        if id.len() > 256 {
            return Err(RosterRejection::OversizedStudentDeviceIdentifier);
        }
        if id.is_empty()
            || id.trim() != *id
            || id.chars().any(char::is_control)
            || contains_bidi_formatting(id)
            || contains_invisible_formatting(id)
            || !seen.insert(*id)
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
    fn bidi_override_student_device_identifier_is_denied() {
        assert_eq!(
            qualify_teacher_roster(&request_with_ids(&["device-\u{202e}1"])),
            Err(RosterRejection::InvalidStudentDeviceRoster)
        );
    }

    #[test]
    fn invisible_student_device_format_characters_are_denied() {
        for id in [
            "device-\u{00ad}1",
            "device-\u{034f}1",
            "device-\u{061c}1",
            "device-\u{180e}1",
            "device-\u{200b}1",
            "device-\u{200c}1",
            "device-\u{200d}1",
            "device-\u{2060}1",
            "device-\u{feff}1",
            "device-\u{fe0e}1",
            "device-\u{fe0f}1",
            "device-\u{e0001}1",
            "device-\u{e007f}1",
        ] {
            assert_eq!(
                qualify_teacher_roster(&request_with_ids(&[id])),
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
    fn bidi_isolates_in_teacher_identity_or_role_are_denied() {
        for (principal, role) in [
            ("teacher-\u{2066}1", "Teacher"),
            ("teacher-1", "Teach\u{202e}er"),
        ] {
            assert_eq!(
                qualify_teacher_roster(&request(principal, role, 150)),
                Err(RosterRejection::InvalidPrincipalOrRole)
            );
        }
    }

    #[test]
    fn invisible_teacher_identity_and_role_format_characters_are_denied() {
        for (principal, role) in [
            ("teacher-\u{00ad}1", "Teacher"),
            ("teacher-\u{034f}1", "Teacher"),
            ("teacher-\u{061c}1", "Teacher"),
            ("teacher-\u{180e}1", "Teacher"),
            ("teacher-\u{200b}1", "Teacher"),
            ("teacher-1", "Teach\u{2060}er"),
            ("teacher-\u{fe0f}1", "Teacher"),
            ("teacher-\u{e0001}1", "Teacher"),
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

#[cfg(test)]
mod roster_identifier_length_tests {
    use super::*;

    #[test]
    fn oversized_identifier_is_denied_even_in_small_roster() {
        let oversized = "d".repeat(257);
        let ids = [oversized.as_str()];
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
            Err(RosterRejection::OversizedStudentDeviceIdentifier)
        );
    }
}

#[cfg(test)]
mod roster_duplicate_screening_tests {
    use super::*;

    fn screen(ids: &[&str]) -> Result<(), RosterRejection> {
        qualify_teacher_roster(&TeacherRosterRequest {
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
        })
    }

    #[test]
    fn duplicate_at_end_of_maximum_roster_is_denied() {
        let names: Vec<String> = (0..1023).map(|i| format!("device-{i}")).collect();
        let mut ids: Vec<&str> = names.iter().map(String::as_str).collect();
        ids.push("device-0");
        assert_eq!(
            screen(&ids),
            Err(RosterRejection::InvalidStudentDeviceRoster)
        );
    }

    #[test]
    fn maximum_unique_roster_still_denied_without_approved_verifier() {
        let names: Vec<String> = (0..1024).map(|i| format!("device-{i}")).collect();
        let ids: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(screen(&ids), Err(RosterRejection::MissingApprovedVerifier));
    }
}

#[cfg(test)]
mod untrusted_signature_bounds_tests {
    use super::*;

    #[test]
    fn oversized_unverified_signature_is_denied() {
        let signature = vec![1_u8; 4097];
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
                signature: Some(&signature),
                student_device_ids: &["device-1"],
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::OversizedUntrustedSignature)
        );
    }

    #[test]
    fn bounded_unverified_signature_still_cannot_authorize() {
        let signature = vec![1_u8; 4096];
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
                signature: Some(&signature),
                student_device_ids: &["device-1"],
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }
}

#[cfg(test)]
mod authorization_epoch_tests {
    use super::*;

    #[test]
    fn clock_rollback_before_authorization_epoch_is_denied() {
        let request = TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 99,
            authorization_not_before_unix_ms: 100,
            roster: Some(RosterEvidence {
                teacher_principal: "teacher-1",
                role: "Teacher",
                issued_unix_ms: 100,
                expires_unix_ms: 300,
                signature: Some(&[1]),
                student_device_ids: &["device-1"],
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::FutureAuthorizationEpoch)
        );
    }

    #[test]
    fn zero_authorization_epoch_is_denied_even_with_plausible_roster() {
        let request = TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 0,
            roster: Some(RosterEvidence {
                teacher_principal: "teacher-1",
                role: "Teacher",
                issued_unix_ms: 150,
                expires_unix_ms: 300,
                signature: Some(&[1]),
                student_device_ids: &["device-1"],
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::MissingAuthorizationEpoch)
        );
    }
}

#[cfg(test)]
mod principal_role_bounds_tests {
    use super::*;

    #[test]
    fn oversized_principal_or_role_is_denied_before_trust_evaluation() {
        let long = "t".repeat(257);
        for (principal, role, roster_principal, roster_role) in [
            (long.as_str(), "Teacher", long.as_str(), "Teacher"),
            ("teacher-1", long.as_str(), "teacher-1", long.as_str()),
            ("teacher-1", "Teacher", long.as_str(), "Teacher"),
            ("teacher-1", "Teacher", "teacher-1", long.as_str()),
        ] {
            let request = TeacherRosterRequest {
                teacher_principal: principal,
                required_role: role,
                now_unix_ms: 200,
                authorization_not_before_unix_ms: 100,
                roster: Some(RosterEvidence {
                    teacher_principal: roster_principal,
                    role: roster_role,
                    issued_unix_ms: 150,
                    expires_unix_ms: 300,
                    signature: Some(&[1]),
                    student_device_ids: &["device-1"],
                }),
            };
            assert_eq!(
                qualify_teacher_roster(&request),
                Err(RosterRejection::OversizedPrincipalOrRole)
            );
        }
    }
}
