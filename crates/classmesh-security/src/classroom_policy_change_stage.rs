//! Phase 12F — copy-on-write classroom policy candidate + audit INTENT.
//!
//! This intentionally does not publish or persist permissions and does NOT
//! establish a trusted admin RPC or authenticated actor identity. It performs
//! in-memory staging from an explicit snapshot only. Caller-supplied expected
//! generation is metadata here, NOT proof that any current durable epoch agrees.
//! The future protected durable writer MUST verify live enrolled Administrator
//! credentials, ManagePolicy, version, request replay and audit atomically
//! at commit. A proposal/audit intent is never a reusable authorization token.

use crate::{
    AuthorizationStore, AuthorizationStoreError, CredentialFingerprint, Permission, PrincipalId,
    classroom_policy_preview::{
        ClassroomPermission, ClassroomPermissionChange, ClassroomPolicyPreviewError,
        preview_classroom_permission_change,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassroomPolicyStageError {
    Denied(ClassroomPolicyPreviewError),
    /// An unexpected canonical index conflict must never produce a candidate.
    CandidateConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassroomAuditIntent {
    actor: PrincipalId,
    target: PrincipalId,
    permission: ClassroomPermission,
    previous_grant: bool,
    new_grant: bool,
    request_id: u64,
    expected_policy_generation: u64,
    checked_at_unix_ms: u64,
}

impl ClassroomAuditIntent {
    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    #[must_use]
    pub const fn target(&self) -> PrincipalId {
        self.target
    }
    #[must_use]
    pub const fn permission(&self) -> ClassroomPermission {
        self.permission
    }
    #[must_use]
    pub const fn previous_grant(&self) -> bool {
        self.previous_grant
    }
    #[must_use]
    pub const fn new_grant(&self) -> bool {
        self.new_grant
    }
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    #[must_use]
    pub const fn expected_policy_generation(&self) -> u64 {
        self.expected_policy_generation
    }
    #[must_use]
    pub const fn checked_at_unix_ms(&self) -> u64 {
        self.checked_at_unix_ms
    }
}

/// A candidate isolated from its source store; neither source nor Service
/// policy changes. The intent is NOT a persisted audit event.
#[derive(Debug)]
#[must_use = "a draft is not permission to commit; it contains only proposed state"]
pub struct ClassroomPolicyDraft {
    candidate: AuthorizationStore,
    audit: ClassroomAuditIntent,
}

impl ClassroomPolicyDraft {
    /// Read-only proposed snapshot. Publishing it without a separately
    /// reviewed atomic durable policy+audit commit would be unsafe.
    #[must_use]
    pub const fn candidate(&self) -> &AuthorizationStore {
        &self.candidate
    }

    #[must_use]
    pub const fn audit_intent(&self) -> &ClassroomAuditIntent {
        &self.audit
    }
}

/// Validate against the supplied snapshot, copy its canonical credential
/// indexes, and change ONLY the bounded target permission in the copy.
///
/// Does not verify that the supplied policy snapshot/generation is current.
/// Does not update a live store, persist, audit, or contact any OS/Worker.
pub fn stage_classroom_permission_change(
    store: &AuthorizationStore,
    actor_credential: CredentialFingerprint,
    change: ClassroomPermissionChange,
    now_unix_ms: u64,
) -> Result<ClassroomPolicyDraft, ClassroomPolicyStageError> {
    let preview = preview_classroom_permission_change(store, actor_credential, change, now_unix_ms)
        .map_err(ClassroomPolicyStageError::Denied)?;

    let mut candidate = store.clone();
    let mut target = candidate
        .principal(preview.target())
        .cloned()
        .ok_or(ClassroomPolicyStageError::CandidateConflict)?;
    let permission: Permission = preview.permission().underlying_permission();
    if preview.grant() {
        target.permissions.insert(permission);
    } else {
        target.permissions.remove(&permission);
    }
    candidate
        .upsert(target)
        .map_err(|_err: AuthorizationStoreError| ClassroomPolicyStageError::CandidateConflict)?;

    let audit = ClassroomAuditIntent {
        actor: preview.actor(),
        target: preview.target(),
        permission: preview.permission(),
        previous_grant: preview.previously_granted(),
        new_grant: preview.grant(),
        request_id: preview.request_id(),
        expected_policy_generation: preview.expected_policy_generation(),
        checked_at_unix_ms: preview.checked_at_unix_ms(),
    };
    Ok(ClassroomPolicyDraft { candidate, audit })
}
