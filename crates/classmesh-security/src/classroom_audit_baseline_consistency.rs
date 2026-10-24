//! Offline comparison of untrusted audit intents against a caller-supplied baseline.
//!
//! Passing this check is NOT evidence of an authenticated actor, a trusted policy
//! generation, durable audit, replay protection, or permission to publish policy.
use crate::{
    AuthorizationStore, Permission, PrincipalKind,
    classroom_audit_batch_consistency::{
        AuditBatchConsistencyError, check_classroom_audit_batch_consistency,
    },
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
    classroom_policy_preview::ClassroomPermission,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditBaselineConsistencyError {
    Batch(AuditBatchConsistencyError),
    BeforeStateMismatch { index: usize },
    UnsupportedRolePermission { index: usize },
    TargetUnavailable { index: usize },
    ActorNotAuthorized { index: usize },
    ActorCredentialUnavailable { index: usize },
}

/// Verify a bounded batch against an explicitly untrusted initial policy snapshot.
/// No OS, Service, network, persistence, or privilege-changing operations occur.
pub fn check_classroom_audit_batch_against_baseline(
    initial: &AuthorizationStore,
    starting_generation: u64,
    records: &[ClassroomAuditIntentRecord],
) -> Result<(), AuditBaselineConsistencyError> {
    check_classroom_audit_batch_consistency(starting_generation, records)
        .map_err(AuditBaselineConsistencyError::Batch)?;

    let mut candidate = initial.clone();
    for (index, record) in records.iter().enumerate() {
        let actor = candidate
            .principal(record.actor())
            .ok_or(AuditBaselineConsistencyError::ActorNotAuthorized { index })?;
        if !actor.enabled
            || actor.kind != PrincipalKind::Administrator
            || !actor.permissions.contains(&Permission::ManagePolicy)
        {
            return Err(AuditBaselineConsistencyError::ActorNotAuthorized { index });
        }
        if !actor
            .credentials
            .values()
            .any(|credential| credential.is_accepted_at(record.checked_at_unix_ms()))
        {
            return Err(AuditBaselineConsistencyError::ActorCredentialUnavailable { index });
        }
        let mut target = candidate
            .principal(record.target())
            .ok_or(AuditBaselineConsistencyError::TargetUnavailable { index })?
            .clone();
        if !target.enabled {
            return Err(AuditBaselineConsistencyError::TargetUnavailable { index });
        }
        let permission = match record.permission() {
            ClassroomPermission::ViewMonitoring => Permission::ViewMonitoring,
            ClassroomPermission::ViewInteractive => Permission::ViewInteractive,
            ClassroomPermission::StartPresentation => Permission::StartPresentation,
            ClassroomPermission::ReceivePresentation => Permission::ReceivePresentation,
        };
        if !matches!(
            target.kind,
            PrincipalKind::Teacher | PrincipalKind::StudentDevice
        ) || !matches!(
            (target.kind, permission),
            (PrincipalKind::Teacher, Permission::ViewMonitoring)
                | (PrincipalKind::Teacher, Permission::ViewInteractive)
                | (PrincipalKind::Teacher, Permission::StartPresentation)
                | (
                    PrincipalKind::StudentDevice,
                    Permission::ReceivePresentation
                )
        ) {
            return Err(AuditBaselineConsistencyError::UnsupportedRolePermission { index });
        }
        if target.permissions.contains(&permission) != record.previous_grant() {
            return Err(AuditBaselineConsistencyError::BeforeStateMismatch { index });
        }
        if record.new_grant() {
            target.permissions.insert(permission);
        } else {
            target.permissions.remove(&permission);
        }
        candidate
            .upsert(target)
            .map_err(|_| AuditBaselineConsistencyError::TargetUnavailable { index })?;
    }
    Ok(())
}
