//! Read-only roster metadata screening. This is NOT signature verification or authorization.
//! No approved issuer/trust anchor is configured: all candidates are denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterRejection {
    MissingRoster,
    ExpiredRoster,
    UnboundedRosterExpiry,
    UnsignedRoster,
    WrongPrincipal,
    WrongRole,
    StaleAuthorization,
    MissingApprovedVerifier,
    UnlistedStudentDevice,
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
                | '\u{2028}'
                | '\u{2029}'
                | '\u{e0000}'..='\u{e007f}'
        )
    })
}

// Unicode noncharacters have no valid identity semantics in this untrusted roster.
// Reject them without inventing a canonicalization or enrollment contract.
fn contains_unicode_noncharacter(value: &str) -> bool {
    value.chars().any(|ch| {
        let cp = ch as u32;
        (0xfdd0..=0xfdef).contains(&cp) || (cp & 0xfffe == 0xfffe)
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
            || value.chars().any(char::is_whitespace)
            || contains_bidi_formatting(value)
            || contains_invisible_formatting(value)
            || contains_unicode_noncharacter(value)
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
    // A maximum timestamp is an effectively permanent unverified grant; deny it.
    if roster.expires_unix_ms == u64::MAX {
        return Err(RosterRejection::UnboundedRosterExpiry);
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
            || id.chars().any(char::is_whitespace)
            || contains_bidi_formatting(id)
            || contains_invisible_formatting(id)
            || contains_unicode_noncharacter(id)
            || !seen.insert(*id)
        {
            return Err(RosterRejection::InvalidStudentDeviceRoster);
        }
    }
    // Never interpret unverified signature bytes or embedded roster as authority.
    Err(RosterRejection::MissingApprovedVerifier)
}

/// Deny-only screening for a specifically requested StudentDevice.
/// Membership in unverified roster metadata is never authorization.
/// All plausible inputs remain denied until approved provenance exists.
pub fn qualify_teacher_device_roster(
    request: &TeacherRosterRequest<'_>,
    requested_student_device_id: &str,
) -> Result<(), RosterRejection> {
    match qualify_teacher_roster(request) {
        Err(RosterRejection::MissingApprovedVerifier) => {}
        other => return other,
    }
    if requested_student_device_id.len() > 256 {
        return Err(RosterRejection::OversizedStudentDeviceIdentifier);
    }
    if requested_student_device_id.is_empty()
        || requested_student_device_id.trim() != requested_student_device_id
        || requested_student_device_id.chars().any(char::is_control)
        || requested_student_device_id.chars().any(char::is_whitespace)
        || contains_bidi_formatting(requested_student_device_id)
        || contains_invisible_formatting(requested_student_device_id)
        || contains_unicode_noncharacter(requested_student_device_id)
    {
        return Err(RosterRejection::InvalidStudentDeviceRoster);
    }
    // Preserve fail-closed behavior even if the upstream screening order changes.
    let Some(roster) = request.roster else {
        return Err(RosterRejection::MissingRoster);
    };
    if !roster
        .student_device_ids
        .contains(&requested_student_device_id)
    {
        return Err(RosterRejection::UnlistedStudentDevice);
    }
    Err(RosterRejection::MissingApprovedVerifier)
}

/// Deny-only screening for a bounded set of requested StudentDevices.
/// Every requested device must appear in the untrusted roster; matching is
/// never proof of provenance or authorization.
pub fn qualify_teacher_device_roster_batch(
    request: &TeacherRosterRequest<'_>,
    requested_student_device_ids: &[&str],
) -> Result<(), RosterRejection> {
    if requested_student_device_ids.is_empty() {
        return Err(RosterRejection::EmptyStudentDeviceRoster);
    }
    if requested_student_device_ids.len() > 1024 {
        return Err(RosterRejection::OversizedStudentDeviceRoster);
    }
    for id in requested_student_device_ids {
        match qualify_teacher_device_roster(request, id) {
            Err(RosterRejection::MissingApprovedVerifier) => {}
            other => return other,
        }
    }
    Err(RosterRejection::MissingApprovedVerifier)
}

#[cfg(test)]
mod scoped_batch_roster_tests {
    use super::*;

    fn request<'a>(ids: &'a [&'a str]) -> TeacherRosterRequest<'a> {
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
    fn all_listed_devices_still_denied_without_approved_verifier() {
        assert_eq!(
            qualify_teacher_device_roster_batch(
                &request(&["device-1", "device-2"]),
                &["device-1", "device-2"],
            ),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }

    #[test]
    fn one_unlisted_device_denies_entire_batch() {
        assert_eq!(
            qualify_teacher_device_roster_batch(
                &request(&["device-1", "device-2"]),
                &["device-1", "device-3"],
            ),
            Err(RosterRejection::UnlistedStudentDevice)
        );
    }

    #[test]
    fn missing_roster_denies_batch() {
        let mut candidate = request(&["device-1"]);
        candidate.roster = None;
        assert_eq!(
            qualify_teacher_device_roster_batch(&candidate, &["device-1"]),
            Err(RosterRejection::MissingRoster)
        );
    }

    #[test]
    fn empty_batch_is_denied() {
        assert_eq!(
            qualify_teacher_device_roster_batch(&request(&["device-1"]), &[]),
            Err(RosterRejection::EmptyStudentDeviceRoster)
        );
    }

    #[test]
    fn oversized_batch_is_denied_before_membership_scan() {
        let ids = vec!["device-1"; 1025];
        assert_eq!(
            qualify_teacher_device_roster_batch(&request(&["device-1"]), &ids),
            Err(RosterRejection::OversizedStudentDeviceRoster)
        );
    }
}

#[cfg(test)]
mod scoped_student_device_tests {
    use super::*;

    fn request<'a>(ids: &'a [&'a str]) -> TeacherRosterRequest<'a> {
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
    fn unlisted_device_is_denied() {
        assert_eq!(
            qualify_teacher_device_roster(&request(&["device-1"]), "device-2"),
            Err(RosterRejection::UnlistedStudentDevice)
        );
    }

    #[test]
    fn listed_device_still_requires_approved_verifier() {
        assert_eq!(
            qualify_teacher_device_roster(&request(&["device-1"]), "device-1"),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }

    #[test]
    fn malformed_requested_device_is_denied() {
        assert_eq!(
            qualify_teacher_device_roster(&request(&["device-1"]), "device-\u{202e}1"),
            Err(RosterRejection::InvalidStudentDeviceRoster)
        );
    }

    #[test]
    fn oversized_requested_device_is_rejected_with_resource_bound_reason() {
        let oversized = "d".repeat(257);
        assert_eq!(
            qualify_teacher_device_roster(&request(&["device-1"]), &oversized),
            Err(RosterRejection::OversizedStudentDeviceIdentifier)
        );
    }

    #[test]
    fn maximum_length_unlisted_device_is_denied_without_authorization() {
        let max_length = "d".repeat(256);
        assert_eq!(
            qualify_teacher_device_roster(&request(&["device-1"]), &max_length),
            Err(RosterRejection::UnlistedStudentDevice)
        );
    }

    #[test]
    fn missing_roster_is_denied_before_device_lookup() {
        let mut candidate = request(&["device-1"]);
        candidate.roster = None;
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::MissingRoster)
        );
    }
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
            "device-\u{2028}1",
            "device-\u{2029}1",
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
    fn unicode_noncharacters_in_student_ids_are_denied() {
        for id in ["device-\u{fdd0}1", "device-\u{ffff}1", "device-\u{10ffff}1"] {
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
            ("teacher-\u{2028}1", "Teacher"),
            ("teacher-1", "Teach\u{2029}er"),
            ("teacher-\u{e0001}1", "Teacher"),
        ] {
            assert_eq!(
                qualify_teacher_roster(&request(principal, role, 150)),
                Err(RosterRejection::InvalidPrincipalOrRole)
            );
        }
    }

    #[test]
    fn unicode_noncharacters_in_principal_or_role_are_denied() {
        for (principal, role) in [
            ("teacher-\u{fdd0}1", "Teacher"),
            ("teacher-1", "Teach\u{ffff}er"),
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

#[cfg(test)]
mod fail_closed_provenance_regression_tests {
    use super::*;

    fn request<'a>(roster: Option<RosterEvidence<'a>>) -> TeacherRosterRequest<'a> {
        TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster,
        }
    }

    fn evidence() -> RosterEvidence<'static> {
        RosterEvidence {
            teacher_principal: "teacher-1",
            role: "Teacher",
            issued_unix_ms: 150,
            expires_unix_ms: 300,
            signature: Some(&[1]),
            student_device_ids: &["device-1"],
        }
    }

    #[test]
    fn missing_roster_is_denied() {
        assert_eq!(
            qualify_teacher_roster(&request(None)),
            Err(RosterRejection::MissingRoster)
        );
    }

    #[test]
    fn expired_roster_at_exact_boundary_is_denied() {
        let mut roster = evidence();
        roster.expires_unix_ms = 200;
        assert_eq!(
            qualify_teacher_roster(&request(Some(roster))),
            Err(RosterRejection::ExpiredRoster)
        );
    }

    #[test]
    fn missing_and_empty_signatures_are_denied() {
        for signature in [None, Some(&[][..])] {
            let mut roster = evidence();
            roster.signature = signature;
            assert_eq!(
                qualify_teacher_roster(&request(Some(roster))),
                Err(RosterRejection::UnsignedRoster)
            );
        }
    }

    #[test]
    fn wrong_teacher_principal_is_denied() {
        let mut roster = evidence();
        roster.teacher_principal = "another-teacher";
        assert_eq!(
            qualify_teacher_roster(&request(Some(roster))),
            Err(RosterRejection::WrongPrincipal)
        );
    }

    #[test]
    fn wrong_teacher_role_is_denied() {
        let mut roster = evidence();
        roster.role = "Student";
        assert_eq!(
            qualify_teacher_roster(&request(Some(roster))),
            Err(RosterRejection::WrongRole)
        );
    }

    #[test]
    fn stale_authorization_epoch_is_denied() {
        let mut roster = evidence();
        roster.issued_unix_ms = 99;
        assert_eq!(
            qualify_teacher_roster(&request(Some(roster))),
            Err(RosterRejection::StaleAuthorization)
        );
    }

    #[test]
    fn plausible_unverified_roster_still_cannot_authorize() {
        assert_eq!(
            qualify_teacher_roster(&request(Some(evidence()))),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }
}

#[cfg(test)]
mod interior_whitespace_denial_tests {
    use super::*;

    #[test]
    fn untrusted_identity_fields_reject_interior_unicode_whitespace() {
        let ids = &["device-1"];
        let roster = RosterEvidence {
            teacher_principal: "teacher-1",
            role: "Teacher",
            issued_unix_ms: 150,
            expires_unix_ms: 300,
            signature: Some(&[1]),
            student_device_ids: ids,
        };
        let mut request = TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster: Some(roster),
        };
        request.teacher_principal = "teacher\u{00a0}1";
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::InvalidPrincipalOrRole)
        );
        request.teacher_principal = "teacher-1";
        request.required_role = "Tea\u{2003}cher";
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::InvalidPrincipalOrRole)
        );
        request.required_role = "Teacher";
        assert_eq!(
            qualify_teacher_device_roster(&request, "device\u{00a0}1"),
            Err(RosterRejection::InvalidStudentDeviceRoster)
        );
        request.roster.as_mut().unwrap().student_device_ids = &["device\u{2003}1"];
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::InvalidStudentDeviceRoster)
        );
    }
}

#[cfg(test)]
mod unbounded_expiry_denial_tests {
    use super::*;

    #[test]
    fn indefinite_roster_expiry_is_denied_before_provenance_screening() {
        let request = TeacherRosterRequest {
            teacher_principal: "teacher-1",
            required_role: "Teacher",
            now_unix_ms: 200,
            authorization_not_before_unix_ms: 100,
            roster: Some(RosterEvidence {
                teacher_principal: "teacher-1",
                role: "Teacher",
                issued_unix_ms: 150,
                expires_unix_ms: u64::MAX,
                signature: Some(&[1]),
                student_device_ids: &["device-1"],
            }),
        };
        assert_eq!(
            qualify_teacher_roster(&request),
            Err(RosterRejection::UnboundedRosterExpiry)
        );
        assert_eq!(
            qualify_teacher_device_roster(&request, "device-1"),
            Err(RosterRejection::UnboundedRosterExpiry)
        );
    }
}

#[cfg(test)]
mod device_denial_propagation_tests {
    use super::*;

    fn request() -> TeacherRosterRequest<'static> {
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
                student_device_ids: &["device-1"],
            }),
        }
    }

    #[test]
    fn device_lookup_preserves_missing_roster_denial() {
        let mut candidate = request();
        candidate.roster = None;
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::MissingRoster)
        );
    }

    #[test]
    fn device_lookup_preserves_expired_and_unsigned_denials() {
        let mut candidate = request();
        candidate.roster.as_mut().unwrap().expires_unix_ms = 200;
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::ExpiredRoster)
        );

        let mut candidate = request();
        candidate.roster.as_mut().unwrap().signature = None;
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::UnsignedRoster)
        );
    }

    #[test]
    fn device_lookup_preserves_principal_and_role_denials() {
        let mut candidate = request();
        candidate.roster.as_mut().unwrap().teacher_principal = "other-teacher";
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::WrongPrincipal)
        );

        let mut candidate = request();
        candidate.roster.as_mut().unwrap().role = "Student";
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::WrongRole)
        );
    }

    #[test]
    fn device_lookup_preserves_stale_authorization_denial() {
        let mut candidate = request();
        candidate.authorization_not_before_unix_ms = 160;
        assert_eq!(
            qualify_teacher_device_roster(&candidate, "device-1"),
            Err(RosterRejection::StaleAuthorization)
        );
    }

    #[test]
    fn matching_device_and_unverified_signature_never_authorize() {
        assert_eq!(
            qualify_teacher_device_roster(&request(), "device-1"),
            Err(RosterRejection::MissingApprovedVerifier)
        );
    }
}
