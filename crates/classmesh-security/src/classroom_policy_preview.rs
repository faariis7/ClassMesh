//! Phase 12F: read-only, bounded classroom permission change preview.
//!
//! No policy updates, audit log writes, database transactions, administrative
//! RPCs, credentials, or runtime activation are implemented here. The returned
//! description is NOT a reusable authorization token: an eventual trusted
//! writer must re-read current authority, expected policy generation and the
//! target's current permission in the SAME durable commit transaction.
use crate::{AuthorizationStore, CredentialFingerprint, Permission, PrincipalId, PrincipalKind};

/// Closed, role-aware classroom preview surface. Deliberately excludes
/// ManagePolicy, ManageEnrollment, clipboard, power, file and OS interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassroomPermission {
    ViewMonitoring,
    ViewInteractive,
    StartPresentation,
    ReceivePresentation,
}

impl ClassroomPermission {
    #[must_use]
    pub const fn underlying_permission(self) -> Permission {
        match self {
            Self::ViewMonitoring => Permission::ViewMonitoring,
            Self::ViewInteractive => Permission::ViewInteractive,
            Self::StartPresentation => Permission::StartPresentation,
            Self::ReceivePresentation => Permission::ReceivePresentation,
        }
    }

    const fn allowed_for(self, role: PrincipalKind) -> bool {
        matches!(
            (role, self),
            (
                PrincipalKind::Teacher,
                Self::ViewMonitoring | Self::ViewInteractive | Self::StartPresentation
            ) | (PrincipalKind::StudentDevice, Self::ReceivePresentation)
        )
    }
}

/// Bounded preview request only; never sufficient authority to commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassroomPermissionChange {
    pub target: PrincipalId,
    pub permission: ClassroomPermission,
    pub grant: bool,
    pub request_id: u64,
    pub expected_policy_generation: u64,
}

/// Non-sensitive, non-authorizing denial reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassroomPolicyPreviewError {
    InvalidRequest,
    Unauthenticated,
    NotAdministrator,
    NotAuthorized,
    TargetUnavailable,
    ProtectedTarget,
    UnsupportedRolePermission,
    NoChange,
}

/// Snapshot-bound intent for display/review ONLY, not permission to commit.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a preview does not persist or authorize a policy change"]
pub struct ClassroomPolicyPreview {
    actor: PrincipalId,
    target: PrincipalId,
    permission: ClassroomPermission,
    grant: bool,
    previously_granted: bool,
    request_id: u64,
    expected_policy_generation: u64,
    checked_at_unix_ms: u64,
}

impl ClassroomPolicyPreview {
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
    pub const fn grant(&self) -> bool {
        self.grant
    }

    #[must_use]
    pub const fn previously_granted(&self) -> bool {
        self.previously_granted
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

/// Validate current enrolled Admin credential + ManagePolicy authority and
/// target role before returning a read-only intent. The supplied policy
/// generation is caller-owned metadata; this function cannot attest that it
/// came from a trusted durable snapshot or make it safe for a later write.
pub fn preview_classroom_permission_change(
    store: &AuthorizationStore,
    actor_credential: CredentialFingerprint,
    request: ClassroomPermissionChange,
    now_unix_ms: u64,
) -> Result<ClassroomPolicyPreview, ClassroomPolicyPreviewError> {
    let ClassroomPermissionChange {
        target,
        permission,
        grant,
        request_id,
        expected_policy_generation,
    } = request;
    if request_id == 0 || expected_policy_generation == 0 {
        return Err(ClassroomPolicyPreviewError::InvalidRequest);
    }
    let actor = store
        .principal_for_credential(actor_credential, now_unix_ms)
        .ok_or(ClassroomPolicyPreviewError::Unauthenticated)?;
    let actor_record = store
        .principal(actor)
        .ok_or(ClassroomPolicyPreviewError::Unauthenticated)?;
    if actor_record.kind != PrincipalKind::Administrator {
        return Err(ClassroomPolicyPreviewError::NotAdministrator);
    }
    if !store.authorize_credential(actor_credential, Permission::ManagePolicy, now_unix_ms) {
        return Err(ClassroomPolicyPreviewError::NotAuthorized);
    }
    let target_record = store
        .principal(target)
        .filter(|p| p.enabled)
        .ok_or(ClassroomPolicyPreviewError::TargetUnavailable)?;
    if !matches!(
        target_record.kind,
        PrincipalKind::Teacher | PrincipalKind::StudentDevice
    ) {
        return Err(ClassroomPolicyPreviewError::ProtectedTarget);
    }
    if !permission.allowed_for(target_record.kind) {
        return Err(ClassroomPolicyPreviewError::UnsupportedRolePermission);
    }
    let previously_granted = target_record
        .permissions
        .contains(&permission.underlying_permission());
    if previously_granted == grant {
        return Err(ClassroomPolicyPreviewError::NoChange);
    }
    Ok(ClassroomPolicyPreview {
        actor,
        target,
        permission,
        grant,
        previously_granted,
        request_id,
        expected_policy_generation,
        checked_at_unix_ms: now_unix_ms,
    })
}
