//! Phase 12F: candidate proposal + audit intent, NEVER a durable commit.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_policy_change_stage::{ClassroomPolicyStageError, stage_classroom_permission_change},
    classroom_policy_preview::{
        ClassroomPermission, ClassroomPermissionChange, ClassroomPolicyPreviewError,
    },
};
use std::collections::BTreeMap;

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn credential(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}
fn principal(n: u8, kind: PrincipalKind, permissions: &[Permission]) -> Principal {
    Principal {
        id: id(n),
        kind,
        enabled: true,
        permissions: permissions.iter().copied().collect(),
        credentials: BTreeMap::from([(
            credential(n),
            CredentialRecord::active(credential(n), 100),
        )]),
    }
}
fn fixtures() -> AuthorizationStore {
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
}
fn change(target: u8, permission: ClassroomPermission, grant: bool) -> ClassroomPermissionChange {
    ClassroomPermissionChange {
        target: id(target),
        permission,
        grant,
        request_id: 91,
        expected_policy_generation: 3,
    }
}
#[test]
fn proposed_grant_has_canonical_candidate_and_non_secret_audit_intent() {
    let store = fixtures();
    let draft = stage_classroom_permission_change(
        &store,
        credential(1),
        change(2, ClassroomPermission::ViewMonitoring, true),
        150,
    )
    .unwrap();
    let audit = draft.audit_intent();
    assert_eq!(audit.actor(), id(1));
    assert_eq!(audit.target(), id(2));
    assert_eq!(audit.permission(), ClassroomPermission::ViewMonitoring);
    assert!(!audit.previous_grant());
    assert!(audit.new_grant());
    assert_eq!(audit.expected_policy_generation(), 3);
    assert_eq!(audit.request_id(), 91);
    assert_eq!(audit.checked_at_unix_ms(), 150);
    assert!(
        draft
            .candidate()
            .authorize(id(2), Permission::ViewMonitoring)
    );
    assert!(
        draft
            .candidate()
            .authorize(id(2), Permission::StartPresentation)
    );
    assert!(
        !store.authorize(id(2), Permission::ViewMonitoring),
        "source policy MUST remain unmodified"
    );
    assert!(store.authorize(id(2), Permission::StartPresentation));
}
#[test]
fn proposed_revocation_changes_only_candidate_and_keeps_credential_index() {
    let store = fixtures();
    let draft = stage_classroom_permission_change(
        &store,
        credential(1),
        change(3, ClassroomPermission::ReceivePresentation, false),
        150,
    )
    .unwrap();
    assert!(
        !draft
            .candidate()
            .authorize(id(3), Permission::ReceivePresentation)
    );
    assert!(store.authorize(id(3), Permission::ReceivePresentation));
    assert_eq!(
        draft
            .candidate()
            .principal_for_credential(credential(2), 150),
        Some(id(2))
    );
    assert_eq!(
        draft
            .candidate()
            .principal_for_credential(credential(3), 150),
        Some(id(3))
    );
    assert_eq!(
        draft
            .candidate()
            .principal_for_credential(credential(1), 150),
        Some(id(1))
    );
    assert!(
        draft
            .candidate()
            .authorize_credential(credential(1), Permission::ManagePolicy, 150)
    );
    assert!(
        draft
            .candidate()
            .authorize(id(2), Permission::StartPresentation)
    );
    assert!(draft.audit_intent().previous_grant());
    assert!(!draft.audit_intent().new_grant());
}
#[test]
fn protected_role_and_cross_role_edit_cannot_produce_candidate_or_audit() {
    let store = fixtures();
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(1, ClassroomPermission::ViewMonitoring, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::ProtectedTarget
        ))
    );
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(3, ClassroomPermission::ViewInteractive, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::UnsupportedRolePermission
        ))
    );
}
#[test]
fn duplicate_or_disabled_target_never_yields_audit_intent() {
    let mut store = fixtures();
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(2, ClassroomPermission::StartPresentation, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::NoChange
        ))
    );
    store.disable(id(2));
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(2, ClassroomPermission::ViewMonitoring, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::TargetUnavailable
        ))
    );
}
#[test]
fn revoked_admin_credential_or_missing_manage_policy_cannot_stage() {
    let mut store = fixtures();
    let mut admin = store.principal(id(1)).unwrap().clone();
    admin.revoke_credential(credential(1), 149).unwrap();
    store.upsert(admin).unwrap();
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(2, ClassroomPermission::ViewMonitoring, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::Unauthenticated
        ))
    );
    let mut store = fixtures();
    let mut admin = store.principal(id(1)).unwrap().clone();
    admin.permissions.clear();
    store.upsert(admin).unwrap();
    assert_eq!(
        stage_classroom_permission_change(
            &store,
            credential(1),
            change(2, ClassroomPermission::ViewMonitoring, true),
            150
        )
        .err(),
        Some(ClassroomPolicyStageError::Denied(
            ClassroomPolicyPreviewError::NotAuthorized
        ))
    );
}
#[test]
fn two_proposals_from_same_source_never_mutate_each_other_or_source() {
    let store = fixtures();
    let first = stage_classroom_permission_change(
        &store,
        credential(1),
        change(2, ClassroomPermission::ViewMonitoring, true),
        150,
    )
    .unwrap();
    let second = stage_classroom_permission_change(
        &store,
        credential(1),
        change(3, ClassroomPermission::ReceivePresentation, false),
        150,
    )
    .unwrap();
    assert!(
        first
            .candidate()
            .authorize(id(3), Permission::ReceivePresentation)
    );
    assert!(
        !second
            .candidate()
            .authorize(id(2), Permission::ViewMonitoring)
    );
    assert!(!store.authorize(id(2), Permission::ViewMonitoring));
    assert!(store.authorize(id(3), Permission::ReceivePresentation));
}
