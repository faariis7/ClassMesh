//! Offline structural diff checker: never interprets audit metadata as authority.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_candidate_invariants::{
        CandidateInvariantError, check_classroom_candidate_invariants,
    },
    classroom_policy_change_stage::{ClassroomAuditIntent, stage_classroom_permission_change},
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};
use std::collections::{BTreeMap, BTreeSet};

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn fingerprint(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}
fn principal(n: u8, kind: PrincipalKind, permissions: &[Permission]) -> Principal {
    Principal {
        id: id(n),
        kind,
        enabled: true,
        permissions: BTreeSet::from_iter(permissions.iter().copied()),
        credentials: BTreeMap::from([(
            fingerprint(n),
            CredentialRecord::active(fingerprint(n), 100),
        )]),
    }
}
fn baseline() -> AuthorizationStore {
    let mut store = AuthorizationStore::default();
    store
        .upsert(principal(
            1,
            PrincipalKind::Administrator,
            &[Permission::ManagePolicy],
        ))
        .unwrap();
    store
        .upsert(principal(
            2,
            PrincipalKind::Teacher,
            &[Permission::StartPresentation],
        ))
        .unwrap();
    store
        .upsert(principal(
            3,
            PrincipalKind::StudentDevice,
            &[Permission::ReceivePresentation],
        ))
        .unwrap();
    store
        .upsert(principal(4, PrincipalKind::Service, &[]))
        .unwrap();
    store
}
fn staged(
    store: &AuthorizationStore,
    target: u8,
    permission: ClassroomPermission,
    grant: bool,
) -> (AuthorizationStore, ClassroomAuditIntent) {
    let draft = stage_classroom_permission_change(
        store,
        fingerprint(1),
        ClassroomPermissionChange {
            target: id(target),
            permission,
            grant,
            request_id: 77,
            expected_policy_generation: 9,
        },
        150,
    )
    .unwrap();
    (draft.candidate().clone(), *draft.audit_intent())
}
#[test]
fn exact_teacher_grant_and_student_revoke_match_entire_snapshot() {
    let store = baseline();
    let (granted, grant_audit) = staged(&store, 2, ClassroomPermission::ViewMonitoring, true);
    assert_eq!(
        check_classroom_candidate_invariants(&store, &granted, &grant_audit),
        Ok(())
    );
    let (revoked, revoke_audit) =
        staged(&store, 3, ClassroomPermission::ReceivePresentation, false);
    assert_eq!(
        check_classroom_candidate_invariants(&store, &revoked, &revoke_audit),
        Ok(())
    );
    assert!(!store.authorize(id(2), Permission::ViewMonitoring));
    assert!(store.authorize(id(3), Permission::ReceivePresentation));
}
#[test]
fn detects_unrelated_permission_changes_even_when_intended_change_is_present() {
    let store = baseline();
    let (mut candidate, audit) = staged(&store, 2, ClassroomPermission::ViewMonitoring, true);
    let mut student = candidate.principal(id(3)).unwrap().clone();
    student.permissions.insert(Permission::ReadClipboard);
    candidate.upsert(student).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&store, &candidate, &audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
}
#[test]
fn detects_credential_reassignment_disable_and_extra_principal() {
    let store = baseline();
    let (mut candidate, audit) = staged(&store, 2, ClassroomPermission::ViewInteractive, true);
    let mut teacher = candidate.principal(id(2)).unwrap().clone();
    teacher
        .credentials
        .get_mut(&fingerprint(2))
        .unwrap()
        .revoke(151);
    candidate.upsert(teacher).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&store, &candidate, &audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
    let (mut candidate, audit) = staged(&store, 2, ClassroomPermission::ViewInteractive, true);
    candidate.disable(id(4));
    assert_eq!(
        check_classroom_candidate_invariants(&store, &candidate, &audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
    let (mut candidate, audit) = staged(&store, 2, ClassroomPermission::ViewInteractive, true);
    candidate
        .upsert(principal(
            88,
            PrincipalKind::Teacher,
            &[Permission::ViewMonitoring],
        ))
        .unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&store, &candidate, &audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
}
#[test]
fn rejects_candidate_that_omits_the_claimed_change() {
    let store = baseline();
    let (_candidate, audit) = staged(&store, 2, ClassroomPermission::ViewMonitoring, true);
    assert_eq!(
        check_classroom_candidate_invariants(&store, &store, &audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
}
#[test]
fn audit_from_another_snapshot_cannot_approve_unrelated_candidate() {
    let store = baseline();
    let (candidate, _actual) = staged(&store, 2, ClassroomPermission::ViewMonitoring, true);
    let (_other_candidate, other_audit) =
        staged(&store, 3, ClassroomPermission::ReceivePresentation, false);
    assert_eq!(
        check_classroom_candidate_invariants(&store, &candidate, &other_audit),
        Err(CandidateInvariantError::UnexpectedPolicyDiff),
    );
}
#[test]
fn actor_disabled_after_intent_cannot_have_structurally_consistent_evidence() {
    let source = baseline();
    let (candidate, audit) = staged(&source, 2, ClassroomPermission::ViewMonitoring, true);
    let mut changed_source = source.clone();
    assert!(changed_source.disable(id(1)));
    assert_eq!(
        check_classroom_candidate_invariants(&changed_source, &candidate, &audit),
        Err(CandidateInvariantError::ActorUnavailable),
    );
}

#[test]
fn actor_role_demotion_after_intent_is_detected_before_candidate_comparison() {
    let source = baseline();
    let (candidate, audit) = staged(&source, 2, ClassroomPermission::ViewMonitoring, true);
    let mut changed_source = source.clone();
    let mut actor = changed_source.principal(id(1)).unwrap().clone();
    actor.kind = PrincipalKind::Teacher;
    changed_source.upsert(actor).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&changed_source, &candidate, &audit),
        Err(CandidateInvariantError::ActorNotAdministrator),
    );
}

#[test]
fn policy_management_grant_revoked_after_intent_is_detected() {
    let source = baseline();
    let (candidate, audit) = staged(&source, 2, ClassroomPermission::ViewMonitoring, true);
    let mut changed_source = source.clone();
    let mut actor = changed_source.principal(id(1)).unwrap().clone();
    assert!(actor.permissions.remove(&Permission::ManagePolicy));
    changed_source.upsert(actor).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&changed_source, &candidate, &audit),
        Err(CandidateInvariantError::ActorNotAuthorized),
    );
}

#[test]
fn no_currently_accepted_actor_credential_cannot_support_audit_intent() {
    let source = baseline();
    let (candidate, audit) = staged(&source, 2, ClassroomPermission::ViewMonitoring, true);
    let mut changed_source = source.clone();
    let mut actor = changed_source.principal(id(1)).unwrap().clone();
    actor.revoke_credential(fingerprint(1), 149).unwrap();
    changed_source.upsert(actor).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&changed_source, &candidate, &audit),
        Err(CandidateInvariantError::ActorCredentialUnavailable),
    );
}

#[test]
fn baseline_drift_and_protected_target_fail_closed() {
    let store = baseline();
    let (candidate, audit) = staged(&store, 2, ClassroomPermission::ViewMonitoring, true);
    let mut new_baseline = store.clone();
    let mut principal = new_baseline.principal(id(2)).unwrap().clone();
    principal.permissions.insert(Permission::ViewMonitoring);
    new_baseline.upsert(principal).unwrap();
    assert_eq!(
        check_classroom_candidate_invariants(&new_baseline, &candidate, &audit),
        Err(CandidateInvariantError::BeforeMismatch),
    );
    let mut new_baseline = store.clone();
    new_baseline.disable(id(2));
    assert_eq!(
        check_classroom_candidate_invariants(&new_baseline, &candidate, &audit),
        Err(CandidateInvariantError::TargetUnavailable),
    );
}
