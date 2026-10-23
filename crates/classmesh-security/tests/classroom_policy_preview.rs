//! Phase 12F: preview-only classroom changes; no policy mutation or authority token.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_policy_preview::{
        ClassroomPermission, ClassroomPermissionChange, ClassroomPolicyPreviewError,
        preview_classroom_permission_change,
    },
};
use std::collections::{BTreeMap, BTreeSet};

fn id(value: u8) -> PrincipalId {
    PrincipalId([value; 32])
}
fn credential(value: u8) -> CredentialFingerprint {
    CredentialFingerprint([value; 32])
}
fn principal(number: u8, kind: PrincipalKind, allowed: &[Permission], active: bool) -> Principal {
    Principal {
        id: id(number),
        kind,
        enabled: active,
        permissions: BTreeSet::from_iter(allowed.iter().copied()),
        credentials: BTreeMap::from([(
            credential(number),
            CredentialRecord::active(credential(number), 100),
        )]),
    }
}
fn fixture() -> AuthorizationStore {
    let mut store = AuthorizationStore::default();
    store
        .upsert(principal(
            1,
            PrincipalKind::Administrator,
            &[Permission::ManagePolicy],
            true,
        ))
        .unwrap();
    store
        .upsert(principal(
            2,
            PrincipalKind::Teacher,
            &[Permission::StartPresentation],
            true,
        ))
        .unwrap();
    store
        .upsert(principal(
            3,
            PrincipalKind::StudentDevice,
            &[Permission::ReceivePresentation],
            true,
        ))
        .unwrap();
    store
}
fn preview(
    store: &AuthorizationStore,
    actor: u8,
    target: u8,
    permission: ClassroomPermission,
    enable: bool,
) -> Result<
    classmesh_security::classroom_policy_preview::ClassroomPolicyPreview,
    ClassroomPolicyPreviewError,
> {
    preview_classroom_permission_change(
        store,
        credential(actor),
        ClassroomPermissionChange {
            target: id(target),
            permission,
            grant: enable,
            request_id: 71,
            expected_policy_generation: 9,
        },
        150,
    )
}
#[test]
fn authorized_admin_can_preview_exact_teacher_grant_without_mutating_store() {
    let store = fixture();
    let plan = preview(&store, 1, 2, ClassroomPermission::ViewMonitoring, true).unwrap();
    assert_eq!(plan.actor(), id(1));
    assert_eq!(plan.target(), id(2));
    assert_eq!(plan.permission(), ClassroomPermission::ViewMonitoring);
    assert!(plan.grant());
    assert_eq!(plan.request_id(), 71);
    assert_eq!(plan.expected_policy_generation(), 9);
    assert!(
        !store.authorize(id(2), Permission::ViewMonitoring),
        "preview must not apply"
    );
}
#[test]
fn authorized_admin_can_preview_narrow_student_revocation_without_changing_store() {
    let store = fixture();
    let plan = preview(
        &store,
        1,
        3,
        ClassroomPermission::ReceivePresentation,
        false,
    )
    .unwrap();
    assert!(!plan.grant());
    assert!(store.authorize(id(3), Permission::ReceivePresentation));
}
#[test]
fn teacher_cannot_gain_admin_privilege_even_if_manage_policy_was_misgranted() {
    let mut store = fixture();
    let mut teacher = store.principal(id(2)).unwrap().clone();
    teacher.permissions.insert(Permission::ManagePolicy);
    store.upsert(teacher).unwrap();
    assert_eq!(
        preview(
            &store,
            2,
            3,
            ClassroomPermission::ReceivePresentation,
            false
        )
        .err(),
        Some(ClassroomPolicyPreviewError::NotAdministrator),
    );
}
#[test]
fn admin_without_manage_policy_or_live_credential_is_denied() {
    let mut store = fixture();
    let mut admin = store.principal(id(1)).unwrap().clone();
    admin.permissions.clear();
    store.upsert(admin).unwrap();
    assert_eq!(
        preview(&store, 1, 2, ClassroomPermission::ViewMonitoring, true).err(),
        Some(ClassroomPolicyPreviewError::NotAuthorized),
    );
    let mut store = fixture();
    let mut admin = store.principal(id(1)).unwrap().clone();
    admin
        .credentials
        .get_mut(&credential(1))
        .unwrap()
        .revoke(120);
    store.upsert(admin).unwrap();
    assert_eq!(
        preview(&store, 1, 2, ClassroomPermission::ViewMonitoring, true).err(),
        Some(ClassroomPolicyPreviewError::Unauthenticated),
    );
}
#[test]
fn protected_roles_missing_and_disabled_targets_remain_out_of_scope() {
    let mut store = fixture();
    store
        .upsert(principal(4, PrincipalKind::Service, &[], true))
        .unwrap();
    assert_eq!(
        preview(&store, 1, 1, ClassroomPermission::ViewMonitoring, true).err(),
        Some(ClassroomPolicyPreviewError::ProtectedTarget),
    );
    assert_eq!(
        preview(&store, 1, 4, ClassroomPermission::ViewMonitoring, true).err(),
        Some(ClassroomPolicyPreviewError::ProtectedTarget),
    );
    assert_eq!(
        preview(&store, 1, 98, ClassroomPermission::ViewMonitoring, true).err(),
        Some(ClassroomPolicyPreviewError::TargetUnavailable),
    );
    store.disable(id(3));
    assert_eq!(
        preview(
            &store,
            1,
            3,
            ClassroomPermission::ReceivePresentation,
            false
        )
        .err(),
        Some(ClassroomPolicyPreviewError::TargetUnavailable),
    );
}
#[test]
fn rejects_role_permission_confusion_and_duplicate_change() {
    let store = fixture();
    assert_eq!(
        preview(&store, 1, 3, ClassroomPermission::ViewInteractive, true).err(),
        Some(ClassroomPolicyPreviewError::UnsupportedRolePermission),
    );
    assert_eq!(
        preview(&store, 1, 2, ClassroomPermission::ReceivePresentation, true).err(),
        Some(ClassroomPolicyPreviewError::UnsupportedRolePermission),
    );
    assert_eq!(
        preview(&store, 1, 2, ClassroomPermission::StartPresentation, true).err(),
        Some(ClassroomPolicyPreviewError::NoChange),
    );
}
#[test]
fn no_request_or_generation_cannot_produce_preview() {
    let store = fixture();
    for (request_id, generation) in [(0, 9), (71, 0)] {
        assert_eq!(
            preview_classroom_permission_change(
                &store,
                credential(1),
                ClassroomPermissionChange {
                    target: id(2),
                    permission: ClassroomPermission::ViewMonitoring,
                    grant: true,
                    request_id,
                    expected_policy_generation: generation,
                },
                150,
            )
            .err(),
            Some(ClassroomPolicyPreviewError::InvalidRequest),
        );
    }
}
