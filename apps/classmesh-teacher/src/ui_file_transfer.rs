//! Capability-gated, selection-bound Teacher file-pull request preparation.
//! This is a portable contract only. The UI/transport handoff and runtime
//! qualification are separate slices; no filesystem path crosses this boundary.
use std::collections::BTreeSet;

use classmesh_protocol::control_wire::{FileSourcePolicy, FileTransferPullRequest};
use classmesh_protocol::file_transfer::{
    FileTransferError, file_transfer_pull_available, validate_pull_request,
};
use classmesh_protocol::{Capability, ProtocolVersion};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeacherFilePullContext {
    pub source_id: MonitoringSourceId,
    pub control_session_id: u64,
    pub version: ProtocolVersion,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TeacherFilePullAction {
    pub source_id: MonitoringSourceId,
    pub control_session_id: u64,
    pub request: FileTransferPullRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeacherFilePullError {
    SelectionChanged,
    MissingContext,
    StaleContext,
    InvalidSession,
    CapabilityUnavailable,
    InvalidRequest(FileTransferError),
}

/// The caller owns the current selected source and authenticated session.
/// Revalidate immediately before enqueuing the action, not just at click time.
pub fn validate_file_pull_action(
    action: &TeacherFilePullAction,
    selection: Option<MonitoringSourceId>,
    context: Option<&TeacherFilePullContext>,
) -> Result<(), TeacherFilePullError> {
    if selection != Some(action.source_id) {
        return Err(TeacherFilePullError::SelectionChanged);
    }
    let context = context.ok_or(TeacherFilePullError::MissingContext)?;
    if context.source_id != action.source_id {
        return Err(TeacherFilePullError::StaleContext);
    }
    if action.control_session_id == 0 || context.control_session_id == 0 {
        return Err(TeacherFilePullError::InvalidSession);
    }
    if action.control_session_id != context.control_session_id {
        return Err(TeacherFilePullError::StaleContext);
    }
    validate_pull_request(&action.request).map_err(TeacherFilePullError::InvalidRequest)?;
    if !file_transfer_pull_available(context.version, &context.capabilities) {
        return Err(TeacherFilePullError::CapabilityUnavailable);
    }
    Ok(())
}

pub fn prepare_file_pull_action(
    source_id: MonitoringSourceId,
    transfer_id: [u8; 16],
    source_id_opaque: [u8; 16],
    selection: Option<MonitoringSourceId>,
    context: Option<&TeacherFilePullContext>,
) -> Result<TeacherFilePullAction, TeacherFilePullError> {
    let context = context.ok_or(TeacherFilePullError::MissingContext)?;
    let action = TeacherFilePullAction {
        source_id,
        control_session_id: context.control_session_id,
        request: FileTransferPullRequest {
            transfer_id: transfer_id.to_vec(),
            source_id: source_id_opaque.to_vec(),
            source: FileSourcePolicy::AppOutbox as i32,
        },
    };
    validate_file_pull_action(&action, selection, Some(context))?;
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> TeacherFilePullContext {
        TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 22,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        }
    }

    fn prepared() -> TeacherFilePullAction {
        prepare_file_pull_action(
            MonitoringSourceId(7), [1; 16], [2; 16],
            Some(MonitoringSourceId(7)), Some(&context()),
        ).unwrap()
    }

    #[test]
    fn prepares_only_opaque_app_owned_pull() {
        let action = prepared();
        assert_eq!(action.control_session_id, 22);
        assert_eq!(action.request.transfer_id, vec![1; 16]);
        assert_eq!(action.request.source_id, vec![2; 16]);
        assert_eq!(action.request.source, FileSourcePolicy::AppOutbox as i32);
    }

    #[test]
    fn rejects_stale_selection_and_session_before_dispatch() {
        let action = prepared();
        assert_eq!(
            validate_file_pull_action(&action, Some(MonitoringSourceId(8)), Some(&context())),
            Err(TeacherFilePullError::SelectionChanged)
        );
        let mut changed = context();
        changed.control_session_id = 23;
        assert_eq!(
            validate_file_pull_action(&action, Some(MonitoringSourceId(7)), Some(&changed)),
            Err(TeacherFilePullError::StaleContext)
        );
        changed.control_session_id = 0;
        assert_eq!(
            validate_file_pull_action(&action, Some(MonitoringSourceId(7)), Some(&changed)),
            Err(TeacherFilePullError::InvalidSession)
        );
    }

    #[test]
    fn rejects_missing_capability_old_version_and_malformed_ids() {
        let action = prepared();
        let mut unavailable = context();
        unavailable.capabilities.clear();
        assert_eq!(
            validate_file_pull_action(&action, Some(MonitoringSourceId(7)), Some(&unavailable)),
            Err(TeacherFilePullError::CapabilityUnavailable)
        );
        unavailable = context();
        unavailable.version = ProtocolVersion { major: 0, minor: 7 };
        assert_eq!(
            validate_file_pull_action(&action, Some(MonitoringSourceId(7)), Some(&unavailable)),
            Err(TeacherFilePullError::CapabilityUnavailable)
        );
        let mut malformed = action;
        malformed.request.source_id = vec![0; 16];
        assert_eq!(
            validate_file_pull_action(&malformed, Some(MonitoringSourceId(7)), Some(&context())),
            Err(TeacherFilePullError::InvalidRequest(FileTransferError::InvalidSourceId))
        );
    }
}
