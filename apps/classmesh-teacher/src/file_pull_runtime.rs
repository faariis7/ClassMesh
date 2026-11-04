//! Real Teacher UI file-pull handoff on the existing exclusive QUIC control stream.
//!
//! This does not create an enrolled client connection or start a second receive
//! loop. The owning Teacher runtime supplies its verified device binding and
//! an already connected authenticated session. This function consumes the
//! validated UI action, sends the pull, receives its actual chunks into an
//! app-owned inbox, and only reports success after verified disk publication.
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_control::teacher_file_pull_receive::{
    TeacherFilePullInbox, TeacherFilePullReceiveError,
};
use classmesh_control::teacher_file_pull_send::{
    TeacherFilePullTransportError, send_authenticated_file_pull_request,
};
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::{FileTransferState, FileTransferStatus};
use classmesh_security::PrincipalId;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::file_inbox::TeacherFileInbox;
use crate::ui_file_transfer::{
    TeacherFilePullAction, TeacherFilePullContext, TeacherFilePullError, validate_file_pull_action,
};

/// Maximum control response frames for a single transfer, so a sender cannot
/// keep a live session occupied forever by resending a valid offer.
const MAX_TRANSFER_FRAMES: u64 = 65_536;

#[derive(Debug)]
pub enum TeacherFilePullRuntimeError {
    Ui(TeacherFilePullError),
    StaleControlSession,
    CapabilityChanged,
    InvalidTransferId,
    Send(TeacherFilePullTransportError),
    Receive(TeacherFilePullReceiveError),
    UnexpectedStatus(FileTransferState),
    StalledProgress,
    FrameLimitExceeded,
    SequenceExhausted,
}

impl Display for TeacherFilePullRuntimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TeacherFilePullRuntimeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeacherFilePullCompletion {
    pub transfer_id: [u8; 16],
    pub completed_path: PathBuf,
    pub total_size: u64,
    pub last_inbound_sequence: u64,
}

/// Call this from the single owning authenticated Teacher session dispatcher
/// after taking `TeacherUiAction::FilePull` from the actual Teacher GUI.
/// Do not call in parallel with any other reads/writes on this same channel.
///
/// The Teacher's local ReceiveFile permission and the exact TLS-authenticated
/// Student principal are rechecked by `send_authenticated_file_pull_request`
/// using fresh trusted policy snapshots. This method does not authorize a
/// destination root: `inbox` must be pre-provisioned by a trusted caller.
///
/// Neither the initial request nor the Accepted/Progress status is success.
/// The returned completion is only issued following SHA-256 verification and
/// successful sink publication, acknowledged to the Student over QUIC.
#[allow(clippy::too_many_arguments)]
pub async fn run_authenticated_teacher_file_pull(
    action: &TeacherFilePullAction,
    current_selection: Option<MonitoringSourceId>,
    current_context: &TeacherFilePullContext,
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    expected_student: PrincipalId,
    last_inbound_sequence: u64,
    outbound_sequence: &mut u64,
    request_id: u64,
    inbox: TeacherFileInbox,
    now_unix_ms: impl Fn() -> u64,
    mut on_status: impl FnMut(&FileTransferStatus),
) -> Result<TeacherFilePullCompletion, TeacherFilePullRuntimeError> {
    validate_file_pull_action(action, current_selection, Some(current_context))
        .map_err(TeacherFilePullRuntimeError::Ui)?;

    let negotiated = &session.established.negotiated;
    if session.established.control_session_id != action.control_session_id {
        return Err(TeacherFilePullRuntimeError::StaleControlSession);
    }
    if negotiated.version != current_context.version
        || negotiated.capabilities != current_context.capabilities
        || !negotiated.capabilities.contains(&Capability::FileTransfer)
    {
        return Err(TeacherFilePullRuntimeError::CapabilityChanged);
    }
    if action.request.transfer_id.len() != 16 {
        return Err(TeacherFilePullRuntimeError::InvalidTransferId);
    }
    let mut transfer_id = [0_u8; 16];
    transfer_id.copy_from_slice(&action.request.transfer_id);

    // Construct the unique request-bound inbox BEFORE emitting the request,
    // ensuring a failed local admission does not create remote work.
    let mut receiver = TeacherFilePullInbox::new(
        session,
        expected_student,
        request_id,
        transfer_id,
        last_inbound_sequence,
        inbox,
    )
    .map_err(TeacherFilePullRuntimeError::Receive)?;

    send_authenticated_file_pull_request(
        session,
        authorization,
        expected_student,
        &action.request,
        outbound_sequence,
        request_id,
        &now_unix_ms,
    )
    .await
    .map_err(TeacherFilePullRuntimeError::Send)?;

    let mut previous_offset = 0;
    for received in 1..=MAX_TRANSFER_FRAMES {
        let status = receiver
            .receive_and_reply(session, authorization, outbound_sequence, &now_unix_ms)
            .await
            .map_err(TeacherFilePullRuntimeError::Receive)?;
        let state = FileTransferState::try_from(status.state).map_err(|_| {
            TeacherFilePullRuntimeError::UnexpectedStatus(FileTransferState::Unspecified)
        })?;
        if state == FileTransferState::Progress && status.next_offset <= previous_offset {
            session
                .connection
                .close(0_u32.into(), b"file pull stalled progress");
            return Err(TeacherFilePullRuntimeError::StalledProgress);
        }
        previous_offset = status.next_offset;
        on_status(&status);
        if state == FileTransferState::Completed {
            let last_inbound_sequence = last_inbound_sequence
                .checked_add(received)
                .ok_or(TeacherFilePullRuntimeError::SequenceExhausted)?;
            return Ok(TeacherFilePullCompletion {
                transfer_id,
                completed_path: receiver.sink().completed_path(&transfer_id),
                total_size: status.next_offset,
                last_inbound_sequence,
            });
        }
        if state != FileTransferState::Accepted && state != FileTransferState::Progress {
            return Err(TeacherFilePullRuntimeError::UnexpectedStatus(state));
        }
    }
    session
        .connection
        .close(0_u32.into(), b"file pull frame limit");
    Err(TeacherFilePullRuntimeError::FrameLimitExceeded)
}
