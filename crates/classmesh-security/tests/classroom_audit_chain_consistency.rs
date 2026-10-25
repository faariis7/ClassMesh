//! Pure multi-batch claimed audit-intent consistency (NEVER a trusted journal).
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_audit_batch_consistency::AuditBatchConsistencyError,
    classroom_audit_chain_consistency::{
        AuditChainConsistencyError, MAX_AUDIT_CHAIN_BATCHES,
        check_classroom_audit_chain_consistency,
    },
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
    classroom_policy_change_stage::stage_classroom_permission_change,
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};
use std::collections::{BTreeMap, BTreeSet};
fn id(x: u8) -> PrincipalId {
    PrincipalId([x; 32])
}
fn cred(x: u8) -> CredentialFingerprint {
    CredentialFingerprint([x; 32])
}
fn store(granted: bool) -> AuthorizationStore {
    let mut s = AuthorizationStore::default();
    for (x, kind, perms) in [
        (
            1,
            PrincipalKind::Administrator,
            vec![Permission::ManagePolicy],
        ),
        (
            2,
            PrincipalKind::Teacher,
            if granted {
                vec![Permission::StartPresentation, Permission::ViewMonitoring]
            } else {
                vec![Permission::StartPresentation]
            },
        ),
        (
            3,
            PrincipalKind::StudentDevice,
            vec![Permission::ReceivePresentation],
        ),
    ] {
        s.upsert(Principal {
            id: id(x),
            kind,
            enabled: true,
            permissions: BTreeSet::from_iter(perms),
            credentials: BTreeMap::from([(cred(x), CredentialRecord::active(cred(x), 100))]),
        })
        .unwrap();
    }
    s
}
fn intent(
    generation: u64,
    request: u64,
    time: u64,
    target: u8,
    grant: bool,
) -> ClassroomAuditIntentRecord {
    let mut source = store(!grant);
    if target == 3 {
        source = store(false);
    }
    let perm = if target == 3 {
        ClassroomPermission::ReceivePresentation
    } else {
        ClassroomPermission::ViewMonitoring
    };
    let operation = if target == 3 { false } else { grant };
    let draft = stage_classroom_permission_change(
        &source,
        cred(1),
        ClassroomPermissionChange {
            target: id(target),
            permission: perm,
            grant: operation,
            request_id: request,
            expected_policy_generation: generation,
        },
        time,
    )
    .unwrap();
    ClassroomAuditIntentRecord::from_intent(draft.audit_intent()).unwrap()
}
#[test]
fn consecutive_two_batches_with_correct_interleaved_changes_pass() {
    let b1 = [intent(7, 11, 150, 2, true), intent(8, 12, 150, 3, false)];
    let b2 = [intent(9, 13, 151, 2, false), intent(10, 14, 152, 2, true)];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&b1, &b2]),
        Ok(())
    );
}
#[test]
fn replayed_actor_request_across_batch_boundary_is_rejected() {
    let first = [intent(7, 11, 150, 2, true)];
    let second = [intent(8, 11, 151, 2, false)];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&first, &second]),
        Err(AuditChainConsistencyError::DuplicateRequest {
            batch_index: 1,
            index: 0
        })
    );
}
#[test]
fn claimed_before_state_must_track_previous_batches_even_when_interleaved() {
    let first = [intent(7, 11, 150, 2, true)];
    let second = [intent(8, 12, 151, 3, false), intent(9, 13, 151, 2, true)];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&first, &second]),
        Err(AuditChainConsistencyError::ContradictoryPriorPermission {
            batch_index: 1,
            index: 1
        })
    );
}
#[test]
fn crossing_to_earlier_timestamp_in_next_batch_is_rejected() {
    let first = [intent(7, 11, 200, 2, true)];
    let second = [intent(8, 12, 199, 2, false)];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&first, &second]),
        Err(AuditChainConsistencyError::TimestampRegression {
            batch_index: 1,
            index: 0
        })
    );
}
#[test]
fn invalid_individual_batch_and_version_gap_fails_closed() {
    let first = [intent(7, 11, 150, 2, true)];
    let second = [intent(10, 12, 151, 2, false)];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&first, &second]),
        Err(AuditChainConsistencyError::InvalidBatch {
            batch_index: 1,
            reason: AuditBatchConsistencyError::VersionGap {
                index: 0,
                expected: 8,
                found: 10
            }
        })
    );
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[&first, &[]]),
        Err(AuditChainConsistencyError::InvalidBatch {
            batch_index: 1,
            reason: AuditBatchConsistencyError::Empty
        })
    );
}
#[test]
fn bounded_batch_count_empty_chain_and_generation_overflow_are_rejected() {
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &[]),
        Err(AuditChainConsistencyError::EmptyChain)
    );
    let first = [intent(7, 11, 150, 2, true)];
    let refs = vec![first.as_slice(); MAX_AUDIT_CHAIN_BATCHES + 1];
    assert_eq!(
        check_classroom_audit_chain_consistency(7, &refs),
        Err(AuditChainConsistencyError::TooManyBatches)
    );
    let end = [intent(u64::MAX - 1, 11, 150, 2, true)];
    let second = [intent(1, 12, 151, 2, false)];
    assert_eq!(
        check_classroom_audit_chain_consistency(u64::MAX - 1, &[&end, &second]),
        Err(AuditChainConsistencyError::GenerationExhausted)
    );
}
