//! Caller-provided, offline audit-baseline consistency only: no trusted epoch.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_audit_baseline_consistency::{
        AuditBaselineConsistencyError, check_classroom_audit_batch_against_baseline,
        check_classroom_audit_batch_final_state,
    },
    classroom_audit_batch_consistency::AuditBatchConsistencyError,
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
    classroom_policy_change_stage::stage_classroom_permission_change,
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};
use std::collections::{BTreeMap, BTreeSet};

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn cred(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}
fn principal(n: u8, kind: PrincipalKind, perms: &[Permission]) -> Principal {
    Principal {
        id: id(n),
        kind,
        enabled: true,
        permissions: BTreeSet::from_iter(perms.iter().copied()),
        credentials: BTreeMap::from([(cred(n), CredentialRecord::active(cred(n), 100))]),
    }
}
fn baseline() -> AuthorizationStore {
    let mut s = AuthorizationStore::default();
    s.upsert(principal(
        1,
        PrincipalKind::Administrator,
        &[Permission::ManagePolicy],
    ))
    .unwrap();
    s.upsert(principal(
        2,
        PrincipalKind::Teacher,
        &[Permission::StartPresentation],
    ))
    .unwrap();
    s.upsert(principal(
        3,
        PrincipalKind::StudentDevice,
        &[Permission::ReceivePresentation],
    ))
    .unwrap();
    s.upsert(principal(4, PrincipalKind::Service, &[])).unwrap();
    s
}
fn intent(
    source: &AuthorizationStore,
    target: u8,
    permission: ClassroomPermission,
    grant: bool,
    generation: u64,
    request_id: u64,
    time: u64,
) -> ClassroomAuditIntentRecord {
    let draft = stage_classroom_permission_change(
        source,
        cred(1),
        ClassroomPermissionChange {
            target: id(target),
            permission,
            grant,
            request_id,
            expected_policy_generation: generation,
        },
        time,
    )
    .unwrap();
    ClassroomAuditIntentRecord::from_intent(draft.audit_intent()).unwrap()
}
fn teacher_with_monitoring(mut state: AuthorizationStore) -> AuthorizationStore {
    let mut teacher = state.principal(id(2)).unwrap().clone();
    teacher.permissions.insert(Permission::ViewMonitoring);
    state.upsert(teacher).unwrap();
    state
}
#[test]
fn valid_two_step_grant_revoke_respects_initial_policy_without_mutation() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let after_grant = teacher_with_monitoring(initial.clone());
    let revoke = intent(
        &after_grant,
        2,
        ClassroomPermission::ViewMonitoring,
        false,
        8,
        42,
        151,
    );
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&initial, 7, &[grant, revoke]),
        Ok(())
    );
    assert!(!initial.authorize(id(2), Permission::ViewMonitoring));
    assert!(initial.authorize(id(2), Permission::StartPresentation));
}
#[test]
fn valid_distinct_targets_and_permissions_do_not_collide() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        12,
        51,
        150,
    );
    let revoke_student = intent(
        &initial,
        3,
        ClassroomPermission::ReceivePresentation,
        false,
        13,
        52,
        151,
    );
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&initial, 12, &[grant, revoke_student]),
        Ok(())
    );
}
#[test]
fn first_intent_cannot_claim_permission_preexisting_when_initial_denies() {
    let initial = baseline();
    let asserted_prior = intent(
        &teacher_with_monitoring(initial.clone()),
        2,
        ClassroomPermission::ViewMonitoring,
        false,
        7,
        41,
        150,
    );
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&initial, 7, &[asserted_prior]),
        Err(AuditBaselineConsistencyError::BeforeStateMismatch { index: 0 }),
    );
}
#[test]
fn first_intent_cannot_claim_permission_missing_when_initial_already_grants() {
    let initial = teacher_with_monitoring(baseline());
    let claimed_grant = intent(
        &baseline(),
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&initial, 7, &[claimed_grant]),
        Err(AuditBaselineConsistencyError::BeforeStateMismatch { index: 0 }),
    );
}
#[test]
fn role_confusion_and_disabled_target_fail_closed() {
    let original = baseline();
    let grant = intent(
        &original,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let mut wrong_role = original.clone();
    let mut target = wrong_role.principal(id(2)).unwrap().clone();
    target.kind = PrincipalKind::StudentDevice;
    wrong_role.upsert(target).unwrap();
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&wrong_role, 7, std::slice::from_ref(&grant)),
        Err(AuditBaselineConsistencyError::UnsupportedRolePermission { index: 0 })
    );
    let mut disabled = original;
    assert!(disabled.disable(id(2)));
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&disabled, 7, &[grant]),
        Err(AuditBaselineConsistencyError::TargetUnavailable { index: 0 })
    );
}
#[test]
fn revoked_admin_authority_in_initial_snapshot_cannot_validate_record() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let mut denied = initial.clone();
    let mut actor = denied.principal(id(1)).unwrap().clone();
    actor.permissions.remove(&Permission::ManagePolicy);
    denied.upsert(actor).unwrap();
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&denied, 7, std::slice::from_ref(&grant)),
        Err(AuditBaselineConsistencyError::ActorNotAuthorized { index: 0 })
    );
    let mut revoked = initial;
    let mut actor = revoked.principal(id(1)).unwrap().clone();
    actor.revoke_credential(cred(1), 149).unwrap();
    revoked.upsert(actor).unwrap();
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&revoked, 7, &[grant]),
        Err(AuditBaselineConsistencyError::ActorCredentialUnavailable { index: 0 })
    );
}
#[test]
fn batch_syntax_checks_run_before_baseline_verification() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    assert_eq!(
        check_classroom_audit_batch_against_baseline(&initial, 7, &[grant.clone(), grant]),
        Err(AuditBaselineConsistencyError::Batch(
            AuditBatchConsistencyError::VersionGap {
                index: 1,
                expected: 8,
                found: 7,
            }
        ))
    );
}

#[test]
fn exact_final_policy_accepts_only_the_claimed_grant() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let expected_final = teacher_with_monitoring(initial.clone());
    assert_eq!(
        check_classroom_audit_batch_final_state(&initial, &expected_final, 7, &[grant]),
        Ok(())
    );
    assert!(!initial.authorize(id(2), Permission::ViewMonitoring));
}

#[test]
fn missing_recorded_grant_cannot_match_the_claimed_final_policy() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    assert_eq!(
        check_classroom_audit_batch_final_state(&initial, &initial, 7, &[grant]),
        Err(AuditBaselineConsistencyError::FinalStateMismatch)
    );
}

#[test]
fn unrelated_privilege_or_service_disable_cannot_hide_in_final_policy() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let mut different = teacher_with_monitoring(initial.clone());
    let mut student = different.principal(id(3)).unwrap().clone();
    student.permissions.insert(Permission::ReadClipboard);
    different.upsert(student).unwrap();
    assert_eq!(
        check_classroom_audit_batch_final_state(
            &initial,
            &different,
            7,
            std::slice::from_ref(&grant)
        ),
        Err(AuditBaselineConsistencyError::FinalStateMismatch)
    );
    let mut different = teacher_with_monitoring(initial.clone());
    assert!(different.disable(id(4)));
    assert_eq!(
        check_classroom_audit_batch_final_state(&initial, &different, 7, &[grant]),
        Err(AuditBaselineConsistencyError::FinalStateMismatch)
    );
}

#[test]
fn unauthorized_credential_changes_or_principal_additions_mismatch_final() {
    let initial = baseline();
    let grant = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let mut different = teacher_with_monitoring(initial.clone());
    let mut teacher = different.principal(id(2)).unwrap().clone();
    teacher.revoke_credential(cred(2), 151).unwrap();
    different.upsert(teacher).unwrap();
    assert_eq!(
        check_classroom_audit_batch_final_state(
            &initial,
            &different,
            7,
            std::slice::from_ref(&grant)
        ),
        Err(AuditBaselineConsistencyError::FinalStateMismatch)
    );
    let mut different = teacher_with_monitoring(initial.clone());
    different
        .upsert(principal(66, PrincipalKind::Teacher, &[]))
        .unwrap();
    assert_eq!(
        check_classroom_audit_batch_final_state(&initial, &different, 7, &[grant]),
        Err(AuditBaselineConsistencyError::FinalStateMismatch)
    );
}

#[test]
fn invalid_intent_state_is_rejected_before_post_state_comparison() {
    let initial = baseline();
    let recorded = intent(
        &initial,
        2,
        ClassroomPermission::ViewMonitoring,
        true,
        7,
        41,
        150,
    );
    let unexpected_initial = teacher_with_monitoring(initial.clone());
    assert_eq!(
        check_classroom_audit_batch_final_state(
            &unexpected_initial,
            &unexpected_initial,
            7,
            &[recorded]
        ),
        Err(AuditBaselineConsistencyError::BeforeStateMismatch { index: 0 })
    );
}
