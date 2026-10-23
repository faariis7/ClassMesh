//! Phase12F: an inactive review gate that re-reads current policy and generation.
use classmesh_control::{
    classroom_live_policy_review::{ClassroomLiveReviewError, review_current_classroom_permission},
    live_authorization::LiveAuthorizationStore,
};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
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
fn policy(admin_can_manage: bool) -> AuthorizationStore {
    let mut store = AuthorizationStore::default();
    let rights: Vec<Permission> = if admin_can_manage {
        vec![Permission::ManagePolicy]
    } else {
        vec![]
    };
    store
        .upsert(principal(1, PrincipalKind::Administrator, &rights))
        .unwrap();
    store
        .upsert(principal(
            2,
            PrincipalKind::Teacher,
            &[Permission::StartPresentation],
        ))
        .unwrap();
    store
}
fn request(generation: u64) -> ClassroomPermissionChange {
    ClassroomPermissionChange {
        target: id(2),
        permission: ClassroomPermission::ViewMonitoring,
        grant: true,
        request_id: 87,
        expected_policy_generation: generation,
    }
}
#[test]
fn matches_current_service_owned_snapshot_without_changing_live_policy() {
    let live = LiveAuthorizationStore::new(policy(true));
    let reviewed =
        review_current_classroom_permission(&live, credential(1), request(1), 150).unwrap();
    assert_eq!(reviewed.actor(), id(1));
    assert_eq!(reviewed.target(), id(2));
    assert_eq!(reviewed.expected_policy_generation(), 1);
    assert!(reviewed.grant());
    assert!(
        !live
            .snapshot()
            .unwrap()
            .store()
            .authorize(id(2), Permission::ViewMonitoring)
    );
    assert_eq!(live.snapshot().unwrap().version(), 1);
}
#[test]
fn rejects_stale_or_speculative_generation_without_preview() {
    let live = LiveAuthorizationStore::new(policy(true));
    assert_eq!(
        review_current_classroom_permission(&live, credential(1), request(2), 150).err(),
        Some(ClassroomLiveReviewError::StaleGeneration {
            expected: 2,
            current: 1
        })
    );
    assert_eq!(live.publish_if_version(1, policy(true)), Ok(2));
    assert_eq!(
        review_current_classroom_permission(&live, credential(1), request(1), 150).err(),
        Some(ClassroomLiveReviewError::StaleGeneration {
            expected: 1,
            current: 2
        })
    );
    assert!(review_current_classroom_permission(&live, credential(1), request(2), 150).is_ok());
}
#[test]
fn currently_published_admin_grant_is_used_not_old_capture() {
    let live = LiveAuthorizationStore::new(policy(true));
    let old = live.snapshot().unwrap();
    assert!(old.store().authorize(id(1), Permission::ManagePolicy));
    assert_eq!(live.publish_if_version(1, policy(false)), Ok(2));
    assert_eq!(
        review_current_classroom_permission(&live, credential(1), request(2), 151).err(),
        Some(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::NotAuthorized
        ))
    );
}
#[test]
fn revoked_credential_or_protected_role_is_denied_against_latest_policy() {
    let live = LiveAuthorizationStore::new(policy(true));
    let mut next = policy(true);
    let mut admin = next.principal(id(1)).unwrap().clone();
    admin.revoke_credential(credential(1), 120).unwrap();
    next.upsert(admin).unwrap();
    assert_eq!(live.publish_if_version(1, next), Ok(2));
    assert_eq!(
        review_current_classroom_permission(&live, credential(1), request(2), 150).err(),
        Some(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::Unauthenticated
        ))
    );
}
#[test]
fn invalid_zero_generation_never_bypasses_review() {
    let live = LiveAuthorizationStore::new(policy(true));
    assert_eq!(
        review_current_classroom_permission(&live, credential(1), request(0), 150).err(),
        Some(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::InvalidRequest
        ))
    );
}
