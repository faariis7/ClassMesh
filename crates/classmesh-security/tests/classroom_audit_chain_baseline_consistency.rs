//! Pure OFFLINE chain-to-baseline and claimed-final comparison; never trusted authority.
use std::collections::{BTreeMap, BTreeSet};

use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_audit_baseline_consistency::AuditBaselineConsistencyError,
    classroom_audit_chain_baseline_consistency::{
        AuditChainBaselineError, check_classroom_audit_chain_against_baseline,
    },
    classroom_audit_chain_consistency::AuditChainConsistencyError,
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
    classroom_policy_change_stage::stage_classroom_permission_change,
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn cred(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}

fn baseline() -> AuthorizationStore {
    let mut store = AuthorizationStore::default();
    for (n, kind, permissions) in [
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
        store
            .upsert(Principal {
                id: id(n),
                kind,
                enabled: true,
                permissions: BTreeSet::from_iter(permissions),
                credentials: BTreeMap::from([(cred(n), CredentialRecord::active(cred(n), 100))]),
            })
            .unwrap();
    }
    store
}

fn with_monitoring(mut store: AuthorizationStore) -> AuthorizationStore {
    let mut teacher = store.principal(id(2)).unwrap().clone();
    teacher.permissions.insert(Permission::ViewMonitoring);
    store.upsert(teacher).unwrap();
    store
}

fn intent(
    source: &AuthorizationStore,
    grant: bool,
    generation: u64,
    request_id: u64,
    time: u64,
) -> ClassroomAuditIntentRecord {
    let draft = stage_classroom_permission_change(
        source,
        cred(1),
        ClassroomPermissionChange {
            target: id(2),
            permission: ClassroomPermission::ViewMonitoring,
            grant,
            request_id,
            expected_policy_generation: generation,
        },
        time,
    )
    .unwrap();
    ClassroomAuditIntentRecord::from_intent(draft.audit_intent()).unwrap()
}

#[test]
fn valid_grant_then_revoke_across_batches_matches_initial_snapshot() {
    let initial = baseline();
    let granted = with_monitoring(initial.clone());
    let first = [intent(&initial, true, 7, 41, 150)];
    let second = [intent(&granted, false, 8, 42, 151)];
    assert_eq!(
        check_classroom_audit_chain_against_baseline(&initial, &initial, 7, &[&first, &second]),
        Ok(())
    );
    assert!(!initial.authorize(id(2), Permission::ViewMonitoring));
}

#[test]
fn first_batch_cannot_invent_a_different_initial_permission() {
    let initial = baseline();
    let recorded = [intent(&initial, true, 7, 41, 150)];
    let wrong_initial = with_monitoring(initial);
    assert_eq!(
        check_classroom_audit_chain_against_baseline(
            &wrong_initial,
            &wrong_initial,
            7,
            &[&recorded]
        ),
        Err(AuditChainBaselineError::BatchBaseline {
            batch_index: 0,
            reason: AuditBaselineConsistencyError::BeforeStateMismatch { index: 0 },
        })
    );
}

#[test]
fn final_snapshot_cannot_omit_a_recorded_grant() {
    let initial = baseline();
    let first = [intent(&initial, true, 7, 41, 150)];
    assert_eq!(
        check_classroom_audit_chain_against_baseline(&initial, &initial, 7, &[&first]),
        Err(AuditChainBaselineError::FinalStateMismatch)
    );
}

#[test]
fn chain_replay_checks_precede_baseline_and_final_checks() {
    let initial = baseline();
    let granted = with_monitoring(initial.clone());
    let first = [intent(&initial, true, 7, 41, 150)];
    let second = [intent(&granted, false, 8, 41, 151)];
    assert_eq!(
        check_classroom_audit_chain_against_baseline(&initial, &initial, 7, &[&first, &second]),
        Err(AuditChainBaselineError::Chain(
            AuditChainConsistencyError::DuplicateRequest {
                batch_index: 1,
                index: 0
            }
        ))
    );
}

#[test]
fn revoked_admin_credential_in_claimed_initial_snapshot_is_rejected() {
    let initial = baseline();
    let first = [intent(&initial, true, 7, 41, 150)];
    let mut revoked = initial;
    let mut admin = revoked.principal(id(1)).unwrap().clone();
    admin.revoke_credential(cred(1), 149).unwrap();
    revoked.upsert(admin).unwrap();
    assert_eq!(
        check_classroom_audit_chain_against_baseline(&revoked, &revoked, 7, &[&first]),
        Err(AuditChainBaselineError::BatchBaseline {
            batch_index: 0,
            reason: AuditBaselineConsistencyError::ActorCredentialUnavailable { index: 0 },
        })
    );
}
