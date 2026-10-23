//! Offline, non-authorizing integrity check for a proposed classroom policy.
//!
//! This detects unrelated differences between a caller-supplied baseline and
//! candidate; it neither authenticates either snapshot nor makes an audit
//! intent a trusted approval. It never persists or publishes permissions.
//! A separately reviewed durable writer must re-check enrolled Admin identity,
//! current grants, trusted policy epoch, replay and crash-safe audit atomically.
use crate::{
    AuthorizationStore, Permission, PrincipalKind,
    classroom_policy_change_stage::ClassroomAuditIntent,
    classroom_policy_preview::ClassroomPermission,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateInvariantError {
    InvalidIntent,
    TargetUnavailable,
    UnsupportedRolePermission,
    BeforeMismatch,
    UnexpectedPolicyDiff,
}

pub fn check_classroom_candidate_invariants(
    baseline: &AuthorizationStore,
    candidate: &AuthorizationStore,
    intent: &ClassroomAuditIntent,
) -> Result<(), CandidateInvariantError> {
    if intent.actor() == intent.target()
        || intent.request_id() == 0
        || intent.expected_policy_generation() == 0
        || intent.checked_at_unix_ms() == 0
        || intent.previous_grant() == intent.new_grant()
    {
        return Err(CandidateInvariantError::InvalidIntent);
    }
    let target = baseline
        .principal(intent.target())
        .filter(|principal| principal.enabled)
        .ok_or(CandidateInvariantError::TargetUnavailable)?;
    let role_ok = matches!(
        (target.kind, intent.permission()),
        (
            PrincipalKind::Teacher,
            ClassroomPermission::ViewMonitoring
                | ClassroomPermission::ViewInteractive
                | ClassroomPermission::StartPresentation
        ) | (
            PrincipalKind::StudentDevice,
            ClassroomPermission::ReceivePresentation
        )
    );
    if !role_ok {
        return Err(CandidateInvariantError::UnsupportedRolePermission);
    }
    let permission: Permission = intent.permission().underlying_permission();
    if target.permissions.contains(&permission) != intent.previous_grant() {
        return Err(CandidateInvariantError::BeforeMismatch);
    }

    // Reconstruct the ONLY expected change using a fresh clone of the
    // supplied baseline; compare the entire principal AND credential-index
    // maps to reject stealth additions, removals and credential mutations.
    let mut expected = baseline.clone();
    let mut corrected_target = target.clone();
    if intent.new_grant() {
        corrected_target.permissions.insert(permission);
    } else {
        corrected_target.permissions.remove(&permission);
    }
    expected
        .upsert(corrected_target)
        .map_err(|_| CandidateInvariantError::UnexpectedPolicyDiff)?;
    if &expected != candidate {
        return Err(CandidateInvariantError::UnexpectedPolicyDiff);
    }
    Ok(())
}
