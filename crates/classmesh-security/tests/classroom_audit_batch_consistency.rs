//! Phase 12F: in-memory consistency ONLY, not committed audit journal or replay defense.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_audit_batch_consistency::{
        AuditBatchConsistencyError, MAX_AUDIT_BATCH_ENTRIES,
        check_classroom_audit_batch_consistency,
    },
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
    classroom_policy_change_stage::stage_classroom_permission_change,
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};
use std::collections::{BTreeMap, BTreeSet};

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn credential(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}
fn store() -> AuthorizationStore {
    let mut policy = AuthorizationStore::default();
    for (n, kind, perms) in [
        (
            1,
            PrincipalKind::Administrator,
            vec![Permission::ManagePolicy],
        ),
        (
            2,
            PrincipalKind::Teacher,
            vec![Permission::StartPresentation],
        ),
        (
            3,
            PrincipalKind::StudentDevice,
            vec![Permission::ReceivePresentation],
        ),
    ] {
        policy
            .upsert(Principal {
                id: id(n),
                kind,
                enabled: true,
                permissions: BTreeSet::from_iter(perms),
                credentials: BTreeMap::from([(
                    credential(n),
                    CredentialRecord::active(credential(n), 100),
                )]),
            })
            .unwrap();
    }
    policy
}
fn record(version: u64, request_id: u64, now: u64) -> ClassroomAuditIntentRecord {
    let policy = store();
    let draft = stage_classroom_permission_change(
        &policy,
        credential(1),
        ClassroomPermissionChange {
            target: id(2),
            permission: ClassroomPermission::ViewMonitoring,
            grant: true,
            request_id,
            expected_policy_generation: version,
        },
        now,
    )
    .unwrap();
    ClassroomAuditIntentRecord::from_intent(draft.audit_intent()).unwrap()
}
#[test]
fn accepts_nonempty_strictly_sequential_version_and_non_decreasing_timestamps() {
    let entries = vec![record(7, 51, 150), record(8, 52, 150), record(9, 53, 160)];
    assert_eq!(check_classroom_audit_batch_consistency(7, &entries), Ok(()));
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &entries[..1]),
        Ok(())
    );
}
#[test]
fn rejects_empty_batches_and_invalid_anchor_metadata() {
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[]),
        Err(AuditBatchConsistencyError::Empty),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(0, &[record(7, 51, 150)]),
        Err(AuditBatchConsistencyError::InvalidStartingGeneration),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(u64::MAX, &[record(7, 51, 150)]),
        Err(AuditBatchConsistencyError::InvalidStartingGeneration),
    );
}
#[test]
fn rejects_stale_future_and_skipped_generations() {
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(6, 51, 150)]),
        Err(AuditBatchConsistencyError::VersionGap {
            index: 0,
            expected: 7,
            found: 6
        }),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(8, 51, 150)]),
        Err(AuditBatchConsistencyError::VersionGap {
            index: 0,
            expected: 7,
            found: 8
        }),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(7, 51, 150), record(9, 52, 151)]),
        Err(AuditBatchConsistencyError::VersionGap {
            index: 1,
            expected: 8,
            found: 9
        }),
    );
}
#[test]
fn rejects_repeated_actor_request_tuple_inside_same_batch() {
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(7, 51, 150), record(8, 51, 151)]),
        Err(AuditBatchConsistencyError::DuplicateRequest { index: 1 }),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(7, 51, 150), record(8, 52, 151)]),
        Ok(()),
    );
}
#[test]
fn rejects_reversed_audit_times_and_overlong_batches() {
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &[record(7, 51, 151), record(8, 52, 150)]),
        Err(AuditBatchConsistencyError::TimestampRegression { index: 1 }),
    );
    let repeated = vec![record(7, 51, 150); MAX_AUDIT_BATCH_ENTRIES + 1];
    assert_eq!(
        check_classroom_audit_batch_consistency(7, &repeated),
        Err(AuditBatchConsistencyError::TooMany),
    );
}
#[test]
fn accepts_final_version_before_overflow_and_rejects_unrepresentable_followup() {
    assert_eq!(
        check_classroom_audit_batch_consistency(u64::MAX - 1, &[record(u64::MAX - 1, 51, 150)]),
        Ok(()),
    );
    assert_eq!(
        check_classroom_audit_batch_consistency(
            u64::MAX - 1,
            &[record(u64::MAX - 1, 51, 150), record(7, 52, 151)]
        ),
        Err(AuditBatchConsistencyError::GenerationExhausted),
    );
}
