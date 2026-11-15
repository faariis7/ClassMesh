//! Contract tests: unverified roster metadata must never authorize Teacher startup.
use classmesh_identity_win::{
    RosterEvidence, RosterRejection, TeacherRosterRequest, qualify_teacher_roster,
};

fn request<'a>(roster: Option<RosterEvidence<'a>>) -> TeacherRosterRequest<'a> {
    TeacherRosterRequest {
        teacher_principal: "teacher-a",
        required_role: "teacher",
        now_unix_ms: 100,
        authorization_not_before_unix_ms: 90,
        roster,
    }
}

#[test]
fn missing_roster_denied() {
    assert_eq!(
        qualify_teacher_roster(&request(None)),
        Err(RosterRejection::MissingRoster)
    );
}

#[test]
fn expired_roster_denied() {
    let roster = RosterEvidence {
        teacher_principal: "teacher-a",
        role: "teacher",
        issued_unix_ms: 50,
        expires_unix_ms: 99,
        signature: Some(&[1]),
        student_device_ids: &["device-a"],
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::ExpiredRoster)
    );
}

#[test]
fn unsigned_roster_denied() {
    let roster = RosterEvidence {
        teacher_principal: "teacher-a",
        role: "teacher",
        issued_unix_ms: 95,
        expires_unix_ms: 200,
        signature: None,
        student_device_ids: &["device-a"],
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::UnsignedRoster)
    );
}

#[test]
fn wrong_principal_and_role_denied() {
    let roster = RosterEvidence {
        teacher_principal: "teacher-b",
        role: "student",
        issued_unix_ms: 95,
        expires_unix_ms: 200,
        signature: Some(&[1]),
        student_device_ids: &["device-a"],
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::WrongPrincipal)
    );
    let roster = RosterEvidence {
        teacher_principal: "teacher-a",
        ..roster
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::WrongRole)
    );
}

#[test]
fn stale_authorization_denied() {
    let roster = RosterEvidence {
        teacher_principal: "teacher-a",
        role: "teacher",
        issued_unix_ms: 80,
        expires_unix_ms: 200,
        signature: Some(&[1]),
        student_device_ids: &["device-a"],
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::StaleAuthorization)
    );
}

#[test]
fn apparently_valid_unverified_signature_still_denied() {
    let roster = RosterEvidence {
        teacher_principal: "teacher-a",
        role: "teacher",
        issued_unix_ms: 95,
        expires_unix_ms: 200,
        signature: Some(&[1, 2, 3]),
        student_device_ids: &["device-a"],
    };
    assert_eq!(
        qualify_teacher_roster(&request(Some(roster))),
        Err(RosterRejection::MissingApprovedVerifier)
    );
}
