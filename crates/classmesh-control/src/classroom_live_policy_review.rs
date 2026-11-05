//! Phase 12F: read-only classroom policy review against the CURRENT
//! Service-owned authorization snapshot, never a caller's cached policy.
//!
//! This is NOT a policy mutation, authenticated RPC, audit-commit, or durable
//! anti-rollback mechanism. The caller must obtain actor_credential from the
//! independently verified enrolled client, never from request-body metadata.
//! Review results are not authorization tokens; a future durable writer must
//! recheck identity, current generation and target within its commit boundary.

use classmesh_security::{
    CredentialFingerprint, Permission, PrincipalKind,
    classroom_policy_preview::{
        ClassroomPermissionChange, ClassroomPolicyPreview, ClassroomPolicyPreviewError,
        preview_classroom_permission_change,
    },
};

use crate::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassroomLiveReviewError {
    AuthorityUnavailable,
    StaleGeneration { expected: u64, current: u64 },
    Denied(ClassroomPolicyPreviewError),
}

/// Reacquire the latest coherent Service policy snapshot before review.
///
/// Prevents a request with an old or speculative generation from being
/// described as ready for a later commit. Checks actor authority *before*
/// disclosing the policy generation. Does not write or publish a new policy.
pub fn review_current_classroom_permission(
    source: &LiveAuthorizationStore,
    actor_credential: CredentialFingerprint,
    request: ClassroomPermissionChange,
    now_unix_ms: u64,
) -> Result<ClassroomPolicyPreview, ClassroomLiveReviewError> {
    if request.request_id == 0 || request.expected_policy_generation == 0 {
        return Err(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::InvalidRequest,
        ));
    }

    let snapshot = source
        .snapshot()
        .map_err(|_cause: LiveAuthorizationError| ClassroomLiveReviewError::AuthorityUnavailable)?;

    // The version is only ever disclosed to an authenticated current Admin.
    // Do not allow a revoked or non-admin credential to use this in-process
    // method as a policy-generation query.
    let store = snapshot.store();
    let actor = store
        .principal_for_credential(actor_credential, now_unix_ms)
        .ok_or(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::Unauthenticated,
        ))?;
    let principal = store
        .principal(actor)
        .ok_or(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::Unauthenticated,
        ))?;
    if principal.kind != PrincipalKind::Administrator {
        return Err(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::NotAdministrator,
        ));
    }
    if !store.authorize_credential(actor_credential, Permission::ManagePolicy, now_unix_ms) {
        return Err(ClassroomLiveReviewError::Denied(
            ClassroomPolicyPreviewError::NotAuthorized,
        ));
    }
    if request.expected_policy_generation != snapshot.version() {
        return Err(ClassroomLiveReviewError::StaleGeneration {
            expected: request.expected_policy_generation,
            current: snapshot.version(),
        });
    }
    preview_classroom_permission_change(store, actor_credential, request, now_unix_ms)
        .map_err(ClassroomLiveReviewError::Denied)
}
