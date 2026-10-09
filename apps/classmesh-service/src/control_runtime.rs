use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use classmesh_control::authorization::AuthenticatedControlGuard;
use classmesh_control::diagnostics::{
    command_authorization_diagnostic_code, handshake_diagnostic_code, heartbeat_diagnostic_code,
    privileged_dispatch_diagnostic_code, stream_offer_diagnostic_code, transport_diagnostic_code,
};
use classmesh_control::dispatch::{
    AuthorizedSystemAction, PrivilegedControlCommand, dispatch_privileged_command,
};
use classmesh_control::group_media_feedback::build_presentation_feedback_envelope;
use classmesh_control::group_media_key::{
    InstalledPresentationKeyBinding, build_presentation_key_ack_from_binding,
    zeroize_received_presentation_key,
};
use classmesh_control::handshake::{
    EstablishedAuthenticatedPeer, EstablishedControlSession, ServerHelloConfig,
    server_hello_enrolled,
};
use classmesh_control::presentation_state::{PresentationOwnership, PresentationOwnershipError};
use classmesh_control::quic::{
    ControlChannel, ControlTransportError, DEFAULT_IO_TIMEOUT, enrolled_server_config_with_resolver,
};
use classmesh_control::stream::{
    ValidatedPresentationStreamOffer, ValidatedPresentationUnicastFallbackOffer,
    peer_bound_udp_unicast_destination, stream_profile_to_wire, validate_interactive_stream_offer,
    validate_presentation_stream_offer, validate_presentation_unicast_fallback_offer,
};
use classmesh_control::{DEFAULT_OFFLINE_AFTER, HeartbeatSample, HeartbeatTracker};
use classmesh_core::adaptation::{
    AdaptationPolicy, FocusedProfileController, HysteresisConfig, QualityTier,
};
use classmesh_core::{NetworkMetrics, StreamKind};
use classmesh_identity_win::{CngMachineKey, MachineIdentityBundle, cng_server_cert_resolver};
use classmesh_network::runtime_multicast_probe::probe_local_multicast_interface;
use classmesh_protocol::control_wire::{
    ControlEnvelope, FileTransferCancel, FileTransferChunk, FileTransferFinish, FileTransferOffer,
    FileTransferState, FileTransferStatus, HeartbeatAck, InputEvent, KeyframeRequest,
    MediaTransport as WireMediaTransport, Nack, PresentationState as WirePresentationState,
    PresentationStatus, ProtocolVersion as WireProtocolVersion, ReceiverFeedback, StreamAnswer,
    StreamKind as WireStreamKind, StreamReconfigure, SystemAction, SystemActionResult,
    SystemActionState, TeacherInteractionKind, TeacherInteractionRequest, TeacherInteractionResult,
    TeacherInteractionState, control_envelope,
};
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::file_transfer::{
    file_transfer_available, validate_status as validate_file_transfer_status,
};
use classmesh_protocol::{Capability, MediaHealth, PROTOCOL_VERSION, ProtocolVersion};
use classmesh_security::{AuthorizationStore, Permission, PrincipalId};
use classmesh_windows_runtime::ipc::{
    ServicePresentationMulticastStart, ServicePresentationUnicastStart, ServiceUdpStreamStart,
    WorkerPresentationFeedback,
};
use classmesh_windows_runtime::ipc_sensitive::{
    PresentationKeyInstallBinding, SensitivePresentationKeyInstall,
};
use quinn::Endpoint;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc as tokio_mpsc, oneshot};

const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const PRESENTATION_KEY_INSTALL_TIMEOUT: Duration = Duration::from_secs(1);
const PRESENTATION_START_TIMEOUT: Duration = Duration::from_secs(1);
const SYSTEM_ACTION_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
const TEACHER_INTERACTION_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
const FILE_TRANSFER_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
const PRESENTATION_FEEDBACK_BUS_CAPACITY: usize = 64;
const CONTROL_INBOUND_QUEUE_CAPACITY: usize = 32;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputAvailability {
    Unavailable = 0,
    Ready = 1,
    Suspended = 2,
    Starting = 3,
}

impl InputAvailability {
    pub(crate) fn load(value: &AtomicU8) -> Self {
        match value.load(Ordering::Acquire) {
            1 => Self::Ready,
            2 => Self::Suspended,
            3 => Self::Starting,
            _ => Self::Unavailable,
        }
    }

    pub(crate) fn store(self, value: &AtomicU8) {
        value.store(self as u8, Ordering::Release);
    }

    const fn rejection_code(self) -> &'static str {
        match self {
            Self::Ready => "control.command.input_ready",
            Self::Suspended => "control.command.session_suspended",
            Self::Starting => "control.command.executor_starting",
            Self::Unavailable => "control.command.executor_unavailable",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InputDispatchChannels {
    pub(crate) event_tx: mpsc::SyncSender<InputEvent>,
    pub(crate) cleanup_tx: mpsc::SyncSender<()>,
    pub(crate) availability: Arc<AtomicU8>,
}

const SYSTEM_ACTION_PENDING: u8 = 0;
const SYSTEM_ACTION_COMMITTED: u8 = 1;
const SYSTEM_ACTION_CANCELLED: u8 = 2;

#[derive(Debug, Clone)]
pub(crate) struct SystemActionCommit(Arc<AtomicU8>);

impl SystemActionCommit {
    fn pending() -> Self {
        Self(Arc::new(AtomicU8::new(SYSTEM_ACTION_PENDING)))
    }

    pub(crate) fn try_commit(&self) -> bool {
        self.0
            .compare_exchange(
                SYSTEM_ACTION_PENDING,
                SYSTEM_ACTION_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel(&self) -> bool {
        self.0
            .compare_exchange(
                SYSTEM_ACTION_PENDING,
                SYSTEM_ACTION_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn is_committed(&self) -> bool {
        self.0.load(Ordering::Acquire) == SYSTEM_ACTION_COMMITTED
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemActionDispatchOutcome {
    Accepted,
    WorkerUnavailable,
    Backpressure,
    ServiceUnavailable,
    WriteFailed,
    ExecutionFailed,
    Unsupported,
    ReplyDropped,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct SystemActionDispatch {
    pub(crate) request_id: u64,
    pub(crate) action: AuthorizedSystemAction,
    pub(crate) commit: SystemActionCommit,
    pub(crate) reply_tx: oneshot::Sender<SystemActionDispatchOutcome>,
}

#[derive(Debug, Clone)]
pub(crate) struct SystemActionDispatchChannels {
    pub(crate) tx: mpsc::SyncSender<SystemActionDispatch>,
}

#[derive(Debug)]
pub(crate) struct TeacherInteractionDispatch {
    pub(crate) control_session_id: u64,
    pub(crate) request_id: u64,
    pub(crate) request: TeacherInteractionRequest,
    pub(crate) commit: SystemActionCommit,
    pub(crate) reply_tx: oneshot::Sender<TeacherInteractionDispatchOutcome>,
}

#[derive(Debug, Clone)]
pub(crate) struct TeacherInteractionDispatchChannels {
    pub(crate) tx: mpsc::SyncSender<TeacherInteractionDispatch>,
}

#[derive(Debug, Clone)]
pub(crate) struct AdministrativeDispatchChannels {
    pub(crate) system_actions: SystemActionDispatchChannels,
    pub(crate) teacher_interactions: TeacherInteractionDispatchChannels,
    pub(crate) file_transfers: FileTransferDispatchChannels,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FileTransferDispatchPayload {
    Offer(FileTransferOffer),
    Chunk(FileTransferChunk),
    Finish(FileTransferFinish),
    Cancel(FileTransferCancel),
}

impl FileTransferDispatchPayload {
    pub(crate) fn transfer_id(&self) -> &[u8] {
        match self {
            Self::Offer(value) => &value.transfer_id,
            Self::Chunk(value) => &value.transfer_id,
            Self::Finish(value) => &value.transfer_id,
            Self::Cancel(value) => &value.transfer_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FileTransferDispatch {
    principal_id: PrincipalId,
    pub(crate) control_session_id: u64,
    pub(crate) request_id: u64,
    payload: FileTransferDispatchPayload,
    pub(crate) commit: SystemActionCommit,
    pub(crate) reply_tx: oneshot::Sender<FileTransferDispatchOutcome>,
}

impl FileTransferDispatch {
    pub(crate) fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    pub(crate) fn payload(&self) -> &FileTransferDispatchPayload {
        &self.payload
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileTransferDispatchChannels {
    pub(crate) tx: mpsc::SyncSender<FileTransferDispatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileTransferDispatchOutcome {
    Backpressure,
    ServiceUnavailable,
    StorageUnavailable,
    ReplyDropped,
    TimedOut,
    Cancelled,
}

fn file_transfer_failure(
    transfer_id: &[u8],
    outcome: FileTransferDispatchOutcome,
) -> FileTransferStatus {
    let (state, diagnostic) = match outcome {
        FileTransferDispatchOutcome::Backpressure => (
            FileTransferState::Rejected,
            "file_transfer.service_backpressure",
        ),
        FileTransferDispatchOutcome::ServiceUnavailable => (
            FileTransferState::Rejected,
            "file_transfer.service_unavailable",
        ),
        FileTransferDispatchOutcome::StorageUnavailable => (
            FileTransferState::Rejected,
            "file_transfer.storage_unavailable",
        ),
        FileTransferDispatchOutcome::ReplyDropped => (
            FileTransferState::Failed,
            "file_transfer.service_reply_dropped",
        ),
        FileTransferDispatchOutcome::TimedOut => {
            (FileTransferState::Failed, "file_transfer.service_timeout")
        }
        FileTransferDispatchOutcome::Cancelled => {
            (FileTransferState::Cancelled, "file_transfer.cancelled")
        }
    };
    FileTransferStatus {
        transfer_id: transfer_id.to_vec(),
        state: state as i32,
        next_offset: 0,
        diagnostic: diagnostic.to_owned(),
    }
}

async fn await_file_transfer_dispatch(
    commit: SystemActionCommit,
    reply_rx: &mut oneshot::Receiver<FileTransferDispatchOutcome>,
) -> FileTransferDispatchOutcome {
    match tokio::time::timeout(FILE_TRANSFER_REPLY_TIMEOUT, &mut *reply_rx).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => FileTransferDispatchOutcome::ReplyDropped,
        Err(_) if commit.cancel() => FileTransferDispatchOutcome::TimedOut,
        Err(_) if commit.is_committed() => reply_rx
            .await
            .unwrap_or(FileTransferDispatchOutcome::ReplyDropped),
        Err(_) => FileTransferDispatchOutcome::Cancelled,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TeacherInteractionDispatchOutcome {
    Result(TeacherInteractionResult),
    WorkerUnavailable,
    Backpressure,
    ServiceUnavailable,
    WriteFailed,
    ReplyDropped,
    TimedOut,
    Cancelled,
}

fn teacher_interaction_failure(
    kind: TeacherInteractionKind,
    outcome: TeacherInteractionDispatchOutcome,
) -> TeacherInteractionResult {
    let (state, diagnostic) = match outcome {
        TeacherInteractionDispatchOutcome::Result(result) => return result,
        TeacherInteractionDispatchOutcome::WorkerUnavailable => (
            TeacherInteractionState::Rejected,
            "teacher_interaction.worker_unavailable",
        ),
        TeacherInteractionDispatchOutcome::Backpressure => (
            TeacherInteractionState::Rejected,
            "teacher_interaction.service_backpressure",
        ),
        TeacherInteractionDispatchOutcome::ServiceUnavailable => (
            TeacherInteractionState::Rejected,
            "teacher_interaction.service_unavailable",
        ),
        TeacherInteractionDispatchOutcome::WriteFailed => (
            TeacherInteractionState::Failed,
            "teacher_interaction.worker_write_failed",
        ),
        TeacherInteractionDispatchOutcome::ReplyDropped => (
            TeacherInteractionState::Failed,
            "teacher_interaction.service_reply_dropped",
        ),
        TeacherInteractionDispatchOutcome::TimedOut => (
            TeacherInteractionState::Failed,
            "teacher_interaction.service_timeout",
        ),
        TeacherInteractionDispatchOutcome::Cancelled => (
            TeacherInteractionState::Rejected,
            "teacher_interaction.cancelled",
        ),
    };
    TeacherInteractionResult {
        kind: kind as i32,
        state: state as i32,
        diagnostic: diagnostic.to_owned(),
    }
}

async fn await_teacher_interaction_dispatch(
    commit: SystemActionCommit,
    reply_rx: &mut oneshot::Receiver<TeacherInteractionDispatchOutcome>,
) -> TeacherInteractionDispatchOutcome {
    match tokio::time::timeout(TEACHER_INTERACTION_REPLY_TIMEOUT, &mut *reply_rx).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => TeacherInteractionDispatchOutcome::ReplyDropped,
        Err(_) if commit.cancel() => TeacherInteractionDispatchOutcome::TimedOut,
        Err(_) if commit.is_committed() => reply_rx
            .await
            .unwrap_or(TeacherInteractionDispatchOutcome::ReplyDropped),
        Err(_) => TeacherInteractionDispatchOutcome::Cancelled,
    }
}

fn system_action_result(
    action: SystemAction,
    outcome: SystemActionDispatchOutcome,
) -> SystemActionResult {
    let (state, diagnostic) = match outcome {
        SystemActionDispatchOutcome::Accepted => (SystemActionState::Accepted, ""),
        SystemActionDispatchOutcome::WorkerUnavailable => (
            SystemActionState::Rejected,
            "system_action.worker_unavailable",
        ),
        SystemActionDispatchOutcome::Backpressure => (
            SystemActionState::Rejected,
            "system_action.service_backpressure",
        ),
        SystemActionDispatchOutcome::ServiceUnavailable => (
            SystemActionState::Rejected,
            "system_action.service_unavailable",
        ),
        SystemActionDispatchOutcome::WriteFailed => (
            SystemActionState::Failed,
            "system_action.worker_write_failed",
        ),
        SystemActionDispatchOutcome::ExecutionFailed => {
            (SystemActionState::Failed, "system_action.execution_failed")
        }
        SystemActionDispatchOutcome::Unsupported => (
            SystemActionState::Rejected,
            "system_action.executor_unavailable",
        ),
        SystemActionDispatchOutcome::ReplyDropped => (
            SystemActionState::Failed,
            "system_action.service_reply_dropped",
        ),
        SystemActionDispatchOutcome::TimedOut => {
            (SystemActionState::Failed, "system_action.service_timeout")
        }
        SystemActionDispatchOutcome::Cancelled => {
            (SystemActionState::Rejected, "system_action.cancelled")
        }
    };

    SystemActionResult {
        action: action as i32,
        state: state as i32,
        diagnostic: diagnostic.to_owned(),
    }
}

fn build_system_action_response(
    control_session_id: u64,
    sequence: u64,
    request_id: u64,
    version: ProtocolVersion,
    action: SystemAction,
    outcome: SystemActionDispatchOutcome,
) -> ControlEnvelope {
    ControlEnvelope {
        control_session_id,
        sequence,
        protocol_version: Some(WireProtocolVersion {
            major: u32::from(version.major),
            minor: u32::from(version.minor),
        }),
        request_id,
        payload: Some(control_envelope::Payload::SystemActionResult(
            system_action_result(action, outcome),
        )),
    }
}

async fn await_system_action_dispatch(
    commit: SystemActionCommit,
    reply_rx: &mut oneshot::Receiver<SystemActionDispatchOutcome>,
) -> SystemActionDispatchOutcome {
    match tokio::time::timeout(SYSTEM_ACTION_REPLY_TIMEOUT, &mut *reply_rx).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => SystemActionDispatchOutcome::ReplyDropped,
        Err(_) if commit.cancel() => SystemActionDispatchOutcome::TimedOut,
        Err(_) if commit.is_committed() => reply_rx
            .await
            .unwrap_or(SystemActionDispatchOutcome::ReplyDropped),
        Err(_) => SystemActionDispatchOutcome::Cancelled,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FocusedMediaReconfigure {
    pub(crate) control_session_id: u64,
    pub(crate) reconfigure: StreamReconfigure,
}

#[derive(Debug, Clone)]
pub(crate) struct FocusedMediaFeedback {
    pub(crate) control_session_id: u64,
    pub(crate) feedback: FeedbackMessage,
}

const MEDIA_START_PENDING: u8 = 0;
const MEDIA_START_COMMITTED: u8 = 1;
const MEDIA_START_CANCELLED: u8 = 2;

#[derive(Debug, Clone)]
pub(crate) struct MediaStartCommit(Arc<AtomicU8>);

impl MediaStartCommit {
    fn pending() -> Self {
        Self(Arc::new(AtomicU8::new(MEDIA_START_PENDING)))
    }

    pub(crate) fn try_commit(&self) -> bool {
        self.0
            .compare_exchange(
                MEDIA_START_PENDING,
                MEDIA_START_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel(&self) -> bool {
        self.0
            .compare_exchange(
                MEDIA_START_PENDING,
                MEDIA_START_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn is_committed(&self) -> bool {
        self.0.load(Ordering::Acquire) == MEDIA_START_COMMITTED
    }
}

#[derive(Debug)]
pub(crate) struct FocusedMediaStart {
    pub(crate) control_session_id: u64,
    pub(crate) start: ServiceUdpStreamStart,
    pub(crate) commit: MediaStartCommit,
    pub(crate) reply_tx: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct FocusedMediaDispatchChannels {
    pub(crate) start_tx: mpsc::SyncSender<FocusedMediaStart>,
    pub(crate) reconfigure_tx: mpsc::SyncSender<FocusedMediaReconfigure>,
    pub(crate) feedback_tx: mpsc::SyncSender<FocusedMediaFeedback>,
    pub(crate) released_session_floor: Arc<AtomicU64>,
    pub(crate) owner: Arc<AtomicU64>,
}

#[derive(Debug)]
pub(crate) struct PresentationKeyInstallDispatch {
    pub(crate) install: SensitivePresentationKeyInstall,
    pub(crate) reply_tx: oneshot::Sender<Result<PresentationKeyInstallBinding, String>>,
}

#[derive(Debug)]
pub(crate) struct PresentationMulticastStartDispatch {
    pub(crate) start: ServicePresentationMulticastStart,
    pub(crate) commit: MediaStartCommit,
    pub(crate) reply_tx: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug)]
pub(crate) struct PresentationUnicastStartDispatch {
    pub(crate) start: ServicePresentationUnicastStart,
    pub(crate) commit: MediaStartCommit,
    pub(crate) reply_tx: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PresentationDispatchChannels {
    pub(crate) key_install_tx: mpsc::SyncSender<PresentationKeyInstallDispatch>,
    pub(crate) key_clear_tx: mpsc::SyncSender<PresentationKeyInstallBinding>,
    pub(crate) multicast_start_tx: mpsc::SyncSender<PresentationMulticastStartDispatch>,
    pub(crate) unicast_start_tx: mpsc::SyncSender<PresentationUnicastStartDispatch>,
}

#[derive(Debug, Clone)]
pub(crate) struct PresentationFeedbackBus {
    tx: broadcast::Sender<WorkerPresentationFeedback>,
}

impl Default for PresentationFeedbackBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(PRESENTATION_FEEDBACK_BUS_CAPACITY);
        Self { tx }
    }
}

impl PresentationFeedbackBus {
    pub(crate) fn publish(&self, feedback: WorkerPresentationFeedback) -> bool {
        self.tx.send(feedback).is_ok()
    }

    fn subscribe(&self) -> broadcast::Receiver<WorkerPresentationFeedback> {
        self.tx.subscribe()
    }
}

#[derive(Debug)]
struct PresentationKeyWorkerLease {
    clear_tx: mpsc::SyncSender<PresentationKeyInstallBinding>,
    binding: Option<PresentationKeyInstallBinding>,
}

impl PresentationKeyWorkerLease {
    fn new(clear_tx: mpsc::SyncSender<PresentationKeyInstallBinding>) -> Self {
        Self {
            clear_tx,
            binding: None,
        }
    }

    fn replace(&mut self, binding: PresentationKeyInstallBinding) {
        self.binding = Some(binding);
    }

    fn clear_now(&mut self) {
        let Some(binding) = self.binding.take() else {
            return;
        };
        if let Err(error) = self.clear_tx.send(binding) {
            eprintln!("ClassMesh presentation-key cleanup queue disconnected: {error}");
        }
    }

    fn accepts_feedback(&self, feedback: &WorkerPresentationFeedback) -> bool {
        self.binding.is_some_and(|binding| {
            feedback.control_session_id == binding.control_session_id
                && feedback.request_id == binding.request_id
                && feedback.presentation_id == binding.presentation_id
                && feedback.feedback.stream_id() == binding.stream_id
                && feedback.epoch == binding.epoch
        })
    }

    fn matches_installed(
        &self,
        control_session_id: u64,
        installed: InstalledPresentationKeyBinding,
    ) -> bool {
        self.binding.is_some_and(|binding| {
            binding.control_session_id == control_session_id
                && binding.presentation_id == installed.presentation_id()
                && binding.stream_id == installed.stream_id()
                && binding.epoch == installed.epoch()
        })
    }
}

impl Drop for PresentationKeyWorkerLease {
    fn drop(&mut self) {
        self.clear_now();
    }
}

impl FocusedMediaDispatchChannels {
    fn try_acquire_owner(&self, session_id: u64) -> bool {
        if session_id == 0 {
            return false;
        }
        match self
            .owner
            .compare_exchange(0, session_id, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(current) => current == session_id,
        }
    }

    fn is_owner(&self, session_id: u64) -> bool {
        session_id != 0 && self.owner.load(Ordering::Acquire) == session_id
    }

    fn release_owner(&self, session_id: u64) -> bool {
        self.owner
            .compare_exchange(session_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WorkerCapabilitySnapshot {
    generation: u64,
    process_id: u32,
    session_id: u32,
    flags: u8,
}

#[derive(Debug, Default)]
pub(crate) struct WorkerCapabilityState {
    snapshot: Mutex<WorkerCapabilitySnapshot>,
}

const WORKER_CAP_DXGI_CAPTURE: u8 = 1 << 0;
const WORKER_CAP_H264_HARDWARE_ENCODE: u8 = 1 << 1;

impl WorkerCapabilityState {
    pub(crate) fn activate(&self, generation: u64, process_id: u32, session_id: u32) {
        let mut snapshot = self.lock_snapshot();
        *snapshot = WorkerCapabilitySnapshot {
            generation,
            process_id,
            session_id,
            flags: 0,
        };
    }

    pub(crate) fn clear(&self) {
        *self.lock_snapshot() = WorkerCapabilitySnapshot::default();
    }

    pub(crate) fn is_current(&self, generation: u64, process_id: u32, session_id: u32) -> bool {
        let snapshot = *self.lock_snapshot();
        generation != 0
            && snapshot.generation == generation
            && snapshot.process_id == process_id
            && snapshot.session_id == session_id
    }

    pub(crate) fn clear_report_if_current(
        &self,
        generation: u64,
        process_id: u32,
        session_id: u32,
    ) -> bool {
        let mut snapshot = self.lock_snapshot();
        if snapshot.generation != generation
            || snapshot.process_id != process_id
            || snapshot.session_id != session_id
        {
            return false;
        }
        snapshot.flags = 0;
        true
    }

    pub(crate) fn apply_h264_qualification(
        &self,
        generation: u64,
        process_id: u32,
        session_id: u32,
        qualified: bool,
    ) -> bool {
        let mut snapshot = self.lock_snapshot();
        if generation == 0
            || snapshot.generation != generation
            || snapshot.process_id != process_id
            || snapshot.session_id != session_id
        {
            return false;
        }

        if qualified {
            snapshot.flags |= WORKER_CAP_H264_HARDWARE_ENCODE;
        } else {
            snapshot.flags &= !WORKER_CAP_H264_HARDWARE_ENCODE;
        }
        true
    }

    pub(crate) fn apply_report(
        &self,
        generation: u64,
        process_id: u32,
        session_id: u32,
        dxgi_capture: bool,
        h264_hardware_encode: bool,
    ) -> bool {
        let mut snapshot = self.lock_snapshot();
        if generation == 0
            || snapshot.generation != generation
            || snapshot.process_id != process_id
            || snapshot.session_id != session_id
        {
            return false;
        }

        let mut flags = 0_u8;
        if dxgi_capture {
            flags |= WORKER_CAP_DXGI_CAPTURE;
        }
        if h264_hardware_encode {
            flags |= WORKER_CAP_H264_HARDWARE_ENCODE;
        }
        snapshot.flags = flags;
        true
    }

    fn has_live_worker(&self) -> bool {
        let snapshot = *self.lock_snapshot();
        snapshot.generation != 0 && snapshot.process_id != 0 && snapshot.session_id != 0
    }

    fn hello_capabilities(&self) -> BTreeSet<Capability> {
        let snapshot = *self.lock_snapshot();
        let mut capabilities = BTreeSet::from([Capability::ServiceSessionWorker]);
        if snapshot.generation == 0 || snapshot.process_id == 0 || snapshot.session_id == 0 {
            return capabilities;
        }
        if snapshot.flags & WORKER_CAP_DXGI_CAPTURE != 0 {
            capabilities.insert(Capability::DxgiCapture);
        }
        if snapshot.flags & WORKER_CAP_H264_HARDWARE_ENCODE != 0 {
            capabilities.insert(Capability::H264HardwareEncode);
        }
        if snapshot.flags & WORKER_CAP_DXGI_CAPTURE != 0
            && snapshot.flags & WORKER_CAP_H264_HARDWARE_ENCODE != 0
        {
            capabilities.insert(Capability::UdpUnicast);
        }
        capabilities
    }

    fn lock_snapshot(&self) -> std::sync::MutexGuard<'_, WorkerCapabilitySnapshot> {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Clone)]
struct InputDispatchState {
    channels: InputDispatchChannels,
    owner: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Default)]
struct PresentationDispatchState {
    ownership: Arc<Mutex<PresentationOwnership>>,
}

impl PresentationDispatchState {
    fn start(
        &self,
        principal_id: PrincipalId,
        control_session_id: u64,
        presentation_id: u64,
        stream_id: u64,
    ) -> PresentationStatus {
        let result = self
            .ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .start(principal_id, control_session_id, presentation_id, stream_id);
        match result {
            Ok(owner) => PresentationStatus {
                presentation_id: owner.presentation_id,
                stream_id: owner.stream_id,
                state: WirePresentationState::Starting as i32,
                diagnostic: String::new(),
            },
            Err(PresentationOwnershipError::Busy) => PresentationStatus {
                presentation_id,
                stream_id,
                state: WirePresentationState::Rejected as i32,
                diagnostic: "control.presentation.busy".to_owned(),
            },
            Err(_) => PresentationStatus {
                presentation_id,
                stream_id: 0,
                state: WirePresentationState::Rejected as i32,
                diagnostic: "control.presentation.invalid_state".to_owned(),
            },
        }
    }

    fn stop(
        &self,
        principal_id: PrincipalId,
        control_session_id: u64,
        presentation_id: u64,
    ) -> PresentationStatus {
        let result = self
            .ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stop(principal_id, control_session_id, presentation_id);
        match result {
            Ok(owner) => PresentationStatus {
                presentation_id: owner.presentation_id,
                stream_id: owner.stream_id,
                state: WirePresentationState::Stopped as i32,
                diagnostic: String::new(),
            },
            Err(PresentationOwnershipError::NotOwner)
            | Err(PresentationOwnershipError::PresentationMismatch) => PresentationStatus {
                presentation_id,
                stream_id: 0,
                state: WirePresentationState::Rejected as i32,
                diagnostic: "control.presentation.not_owner".to_owned(),
            },
            Err(_) => PresentationStatus {
                presentation_id,
                stream_id: 0,
                state: WirePresentationState::Rejected as i32,
                diagnostic: "control.presentation.invalid_state".to_owned(),
            },
        }
    }

    fn matches_owner(
        &self,
        principal_id: PrincipalId,
        control_session_id: u64,
        presentation_id: u64,
        stream_id: u64,
    ) -> bool {
        self.ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owner()
            .is_some_and(|owner| {
                owner.principal_id == principal_id
                    && owner.control_session_id == control_session_id
                    && owner.presentation_id == presentation_id
                    && owner.stream_id == stream_id
            })
    }

    fn owner_for_stream(
        &self,
        principal_id: PrincipalId,
        control_session_id: u64,
        stream_id: u64,
    ) -> Option<classmesh_control::presentation_state::PresentationOwner> {
        self.ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owner()
            .filter(|owner| {
                owner.principal_id == principal_id
                    && owner.control_session_id == control_session_id
                    && owner.stream_id == stream_id
            })
    }

    fn release_session(&self, principal_id: PrincipalId, control_session_id: u64) -> bool {
        self.ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_session(principal_id, control_session_id)
            .is_some()
    }

    #[cfg(test)]
    fn owner(&self) -> Option<classmesh_control::presentation_state::PresentationOwner> {
        self.ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owner()
    }
}

#[derive(Debug)]
struct FocusedAdaptationState {
    stream_id: Option<u64>,
    controller: FocusedProfileController,
}

impl FocusedAdaptationState {
    fn new() -> Self {
        Self {
            stream_id: None,
            controller: focused_profile_controller(),
        }
    }

    fn observe(
        &mut self,
        feedback: &ReceiverFeedback,
    ) -> Result<Option<StreamReconfigure>, &'static str> {
        if feedback.stream_id == 0 {
            return Err("control.feedback.invalid_stream");
        }
        let metrics =
            receiver_feedback_metrics(feedback).ok_or("control.feedback.invalid_metrics")?;

        if self.stream_id != Some(feedback.stream_id) {
            self.stream_id = Some(feedback.stream_id);
            self.controller = focused_profile_controller();
        }

        let decision = self.controller.observe(metrics);
        if !decision.changed {
            return Ok(None);
        }

        Ok(Some(StreamReconfigure {
            stream_id: feedback.stream_id,
            profile: Some(stream_profile_to_wire(decision.profile)),
            transport: WireMediaTransport::Unspecified as i32,
            transport_parameters: Vec::new(),
        }))
    }
}

fn feedback_message_from_nack(nack: &Nack) -> Result<FeedbackMessage, &'static str> {
    let stream_id =
        u32::try_from(nack.stream_id).map_err(|_| "control.media.feedback_invalid_stream")?;
    if stream_id == 0 {
        return Err("control.media.feedback_invalid_stream");
    }
    if nack.missing_packet_indices.is_empty()
        || nack.missing_packet_indices.len() > MAX_NACK_PACKET_INDICES
    {
        return Err("control.media.feedback_invalid_nack");
    }
    let missing_packet_indices = nack
        .missing_packet_indices
        .iter()
        .copied()
        .map(|index| {
            u16::try_from(index).map_err(|_| "control.media.feedback_invalid_packet_index")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FeedbackMessage::Nack {
        stream_id,
        frame_id: nack.frame_id,
        missing_packet_indices,
    })
}

fn feedback_message_from_keyframe(
    request: &KeyframeRequest,
) -> Result<FeedbackMessage, &'static str> {
    let stream_id =
        u32::try_from(request.stream_id).map_err(|_| "control.media.feedback_invalid_stream")?;
    if stream_id == 0 {
        return Err("control.media.feedback_invalid_stream");
    }
    Ok(FeedbackMessage::RequestKeyframe {
        stream_id,
        after_frame_id: request.last_decodable_frame_id,
    })
}

fn dispatch_media_feedback(
    media: &FocusedMediaDispatchChannels,
    control_session_id: u64,
    feedback: FeedbackMessage,
) {
    if !media.is_owner(control_session_id) {
        eprintln!("ClassMesh media feedback ignored: control.media.feedback_not_owner");
        return;
    }
    match media.feedback_tx.try_send(FocusedMediaFeedback {
        control_session_id,
        feedback,
    }) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            eprintln!("ClassMesh media feedback dropped: control.media.feedback_backpressure");
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            eprintln!("ClassMesh media feedback dropped: control.media.feedback_disconnected");
        }
    }
}

fn focused_profile_controller() -> FocusedProfileController {
    FocusedProfileController::with_initial_tier(
        StreamKind::Interactive,
        AdaptationPolicy::default(),
        HysteresisConfig::default(),
        QualityTier::High,
    )
}

fn receiver_feedback_metrics(feedback: &ReceiverFeedback) -> Option<NetworkMetrics> {
    let finite_nonnegative = [
        feedback.rtt_ms,
        feedback.packet_loss,
        feedback.jitter_ms,
        feedback.decode_fps,
        feedback.decode_latency_ms,
        feedback.render_latency_ms,
        feedback.queue_delay_ms,
    ]
    .into_iter()
    .all(|value| value.is_finite() && value >= 0.0);
    if !finite_nonnegative || !(0.0..=1.0).contains(&feedback.packet_loss) {
        return None;
    }

    let metrics = NetworkMetrics {
        rtt_ms: feedback.rtt_ms,
        packet_loss: feedback.packet_loss,
        jitter_ms: feedback.jitter_ms,
        decode_fps: feedback.decode_fps,
        queue_delay_ms: feedback.queue_delay_ms,
        estimated_mbps: feedback.received_bitrate_bps as f32 / 1_000_000.0,
        // ReceiverFeedback does not declare topology. Focused 6D adaptation is profile-only,
        // so these fields are deliberately neutral and never used to select a transport here.
        multicast_viable: false,
        wireless: false,
    };
    metrics.is_valid().then_some(metrics)
}

#[derive(Debug)]
pub(crate) struct ControlRuntimeState {
    pub(crate) identity: MachineIdentityBundle,
    pub(crate) authorization: AuthorizationStore,
    pub(crate) key: CngMachineKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlRuntimeConfig {
    pub(crate) bind_address: SocketAddr,
    pub(crate) multicast_interface: Option<Ipv4Addr>,
}

#[derive(Debug, Deserialize)]
struct PersistedControlRuntimeConfig {
    version: u32,
    bind_address: String,
    multicast_interface: Option<String>,
}

impl ControlRuntimeConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("control runtime config metadata failed: {error}"))?;
        let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if declared > MAX_CONFIG_BYTES {
            return Err(format!(
                "control runtime config is {declared} bytes; maximum is {MAX_CONFIG_BYTES}"
            ));
        }

        let file = File::open(path)
            .map_err(|error| format!("control runtime config open failed: {error}"))?;
        let mut bytes = Vec::with_capacity(declared.min(MAX_CONFIG_BYTES));
        file.take(u64::try_from(MAX_CONFIG_BYTES + 1).expect("config bound fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("control runtime config read failed: {error}"))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "control runtime config is {} bytes; maximum is {MAX_CONFIG_BYTES}",
                bytes.len()
            ));
        }

        let persisted: PersistedControlRuntimeConfig = serde_json::from_slice(&bytes)
            .map_err(|error| format!("control runtime config JSON failed: {error}"))?;
        if persisted.version != CONFIG_VERSION {
            return Err(format!(
                "unsupported control runtime config version {}",
                persisted.version
            ));
        }

        let bind_address = persisted
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|_| "control runtime bind_address must be a socket address".to_owned())?;
        if bind_address.port() == 0 {
            return Err("control runtime bind port must be non-zero".to_owned());
        }

        let multicast_interface = persisted
            .multicast_interface
            .map(|value| {
                value.parse::<Ipv4Addr>().map_err(|_| {
                    "control runtime multicast_interface must be an IPv4 address".to_owned()
                })
            })
            .transpose()?;

        Ok(Self {
            bind_address,
            multicast_interface,
        })
    }
}

pub(crate) struct ControlRuntimeDispatch {
    input: InputDispatchChannels,
    administrative: AdministrativeDispatchChannels,
    media: FocusedMediaDispatchChannels,
    presentation_dispatch: PresentationDispatchChannels,
    presentation_feedback: PresentationFeedbackBus,
    worker_capabilities: Arc<WorkerCapabilityState>,
}

impl ControlRuntimeDispatch {
    pub(crate) fn new(
        input: InputDispatchChannels,
        administrative: AdministrativeDispatchChannels,
        media: FocusedMediaDispatchChannels,
        presentation_dispatch: PresentationDispatchChannels,
        presentation_feedback: PresentationFeedbackBus,
        worker_capabilities: Arc<WorkerCapabilityState>,
    ) -> Self {
        Self {
            input,
            administrative,
            media,
            presentation_dispatch,
            presentation_feedback,
            worker_capabilities,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ControlRuntime {
    stop_tx: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    local_address: SocketAddr,
}

impl ControlRuntime {
    pub(crate) fn start(
        state: ControlRuntimeState,
        config: ControlRuntimeConfig,
        dispatch: ControlRuntimeDispatch,
    ) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (stop_tx, stop_rx) = oneshot::channel();

        let thread = thread::Builder::new()
            .name("classmesh-control".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "control Tokio runtime creation failed: {error}"
                        )));
                        return;
                    }
                };

                runtime.block_on(run_listener(state, config, ready_tx, stop_rx, dispatch));
            })
            .map_err(|error| format!("control runtime thread creation failed: {error}"))?;

        let local_address = match ready_rx.recv_timeout(READY_TIMEOUT) {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => {
                let _ = thread.join();
                return Err(error);
            }
            Err(error) => {
                let _ = stop_tx.send(());
                let _ = thread.join();
                return Err(format!("control runtime readiness failed: {error}"));
            }
        };

        Ok(Self {
            stop_tx: Some(stop_tx),
            thread: Some(thread),
            local_address,
        })
    }

    #[must_use]
    pub(crate) const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    #[must_use]
    pub(crate) fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    pub(crate) fn stop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                eprintln!("ClassMesh control runtime thread panicked during shutdown");
            }
        }
    }
}

impl Drop for ControlRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn run_listener(
    state: ControlRuntimeState,
    config: ControlRuntimeConfig,
    ready_tx: mpsc::SyncSender<Result<SocketAddr, String>>,
    mut stop_rx: oneshot::Receiver<()>,
    dispatch: ControlRuntimeDispatch,
) {
    let ControlRuntimeDispatch {
        input,
        administrative,
        media,
        presentation_dispatch,
        presentation_feedback,
        worker_capabilities,
    } = dispatch;
    let udp_multicast_available = local_udp_multicast_capability(config.multicast_interface);
    let multicast_interface = if udp_multicast_available {
        config.multicast_interface
    } else {
        None
    };
    let endpoint = match build_endpoint(&state, config) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = ready_tx.send(Err(error));
            return;
        }
    };
    let local_address = match endpoint.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let _ = ready_tx.send(Err(format!(
                "control listener local address failed: {error}"
            )));
            return;
        }
    };
    if ready_tx.send(Ok(local_address)).is_err() {
        endpoint.close(0_u32.into(), b"service startup abandoned");
        return;
    }

    let authorization = Arc::new(state.authorization);
    let session_ids = Arc::new(AtomicU64::new(1));
    let input = InputDispatchState {
        channels: input,
        owner: Arc::new(AtomicU64::new(0)),
    };
    let presentation = PresentationDispatchState::default();

    loop {
        tokio::select! {
            _ = &mut stop_rx => {
                endpoint.close(0_u32.into(), b"service stopping");
                endpoint.wait_idle().await;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let authorization = Arc::clone(&authorization);
                let session_ids = Arc::clone(&session_ids);
                let input = input.clone();
                let system_actions = administrative.system_actions.clone();
                let teacher_interactions = administrative.teacher_interactions.clone();
                let file_transfers = administrative.file_transfers.clone();
                let media = media.clone();
                let presentation_dispatch = presentation_dispatch.clone();
                let presentation_feedback = presentation_feedback.clone();
                let presentation = presentation.clone();
                let worker_capabilities = Arc::clone(&worker_capabilities);
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    let mut channel = match ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT).await {
                        Ok(channel) => channel,
                        Err(_) => {
                            connection.close(0_u32.into(), b"control stream rejected");
                            return;
                        }
                    };

                    let session_id = next_session_id(&session_ids);
                    let hello_config = ServerHelloConfig {
                        local_version: PROTOCOL_VERSION,
                        local_capabilities: service_hello_capabilities(
                            &worker_capabilities,
                            udp_multicast_available,
                        ),
                        control_session_id: session_id,
                    };
                    let now_unix_ms = match unix_time_ms() {
                        Ok(value) => value,
                        Err(_) => {
                            connection.close(0_u32.into(), b"invalid service clock");
                            return;
                        }
                    };

                    match server_hello_enrolled(
                        &connection,
                        &mut channel,
                        &hello_config,
                        authorization.as_ref(),
                        now_unix_ms,
                    )
                    .await
                    {
                        Ok((session, peer)) => {
                            eprintln!(
                                "ClassMesh enrolled control session {} established",
                                peer.control_session_id
                            );
                            run_established_session(
                                &connection,
                                channel,
                                &session,
                                peer,
                                EstablishedSessionRuntime {
                                    authorization: authorization.as_ref(),
                                    input: &input,
                                    system_actions: &system_actions,
                                    teacher_interactions: &teacher_interactions,
                                    file_transfers: &file_transfers,
                                    media: &media,
                                    presentation_dispatch: &presentation_dispatch,
                                    presentation_feedback: &presentation_feedback,
                                    presentation: &presentation,
                                    multicast_interface,
                                },
                            )
                            .await;
                            let _ = input.release_owner(session.control_session_id);
                            let _ = presentation.release_session(
                                peer.identity.principal_id(),
                                session.control_session_id,
                            );
                            if media.release_owner(session.control_session_id) {
                                media
                                    .released_session_floor
                                    .fetch_max(session.control_session_id, Ordering::AcqRel);
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "ClassMesh control handshake rejected: {}",
                                handshake_diagnostic_code(&error)
                            );
                            connection.close(0_u32.into(), b"control handshake rejected");
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EstablishedSessionRuntime<'a> {
    authorization: &'a AuthorizationStore,
    input: &'a InputDispatchState,
    system_actions: &'a SystemActionDispatchChannels,
    teacher_interactions: &'a TeacherInteractionDispatchChannels,
    file_transfers: &'a FileTransferDispatchChannels,
    media: &'a FocusedMediaDispatchChannels,
    presentation_dispatch: &'a PresentationDispatchChannels,
    presentation_feedback: &'a PresentationFeedbackBus,
    presentation: &'a PresentationDispatchState,
    multicast_interface: Option<Ipv4Addr>,
}

#[derive(Debug)]
enum ControlInboundEvent {
    Envelope(ControlEnvelope),
    Timeout,
    Failed(String),
}

#[derive(Debug)]
struct ReceivePumpGuard(tokio::task::JoinHandle<()>);

impl Drop for ReceivePumpGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn await_presentation_start(
    commit: MediaStartCommit,
    reply_rx: &mut oneshot::Receiver<Result<(), String>>,
) -> Result<(), String> {
    match tokio::time::timeout(PRESENTATION_START_TIMEOUT, &mut *reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("control.presentation.start_reply_dropped".to_owned()),
        Err(_) if commit.cancel() => Err("control.presentation.start_timeout".to_owned()),
        Err(_) if commit.is_committed() => reply_rx
            .await
            .unwrap_or_else(|_| Err("control.presentation.start_reply_dropped".to_owned())),
        Err(_) => Err("control.presentation.start_cancelled".to_owned()),
    }
}

async fn run_established_session(
    connection: &quinn::Connection,
    channel: ControlChannel,
    session: &EstablishedControlSession,
    peer: EstablishedAuthenticatedPeer,
    runtime: EstablishedSessionRuntime<'_>,
) {
    const HELLO_SEQUENCE: u64 = 1;
    let EstablishedSessionRuntime {
        authorization,
        input,
        system_actions,
        teacher_interactions,
        file_transfers,
        media,
        presentation_dispatch,
        presentation_feedback,
        presentation,
        multicast_interface,
    } = runtime;

    let mut guard = AuthenticatedControlGuard::new(
        peer.identity,
        session.control_session_id,
        session.negotiated.version,
        HELLO_SEQUENCE,
    );
    let mut heartbeat = HeartbeatTracker::new(session.control_session_id, MediaHealth::Idle);
    let session_clock = Instant::now();
    let mut last_inbound_at = Instant::now();
    let mut outbound_sequence = HELLO_SEQUENCE;
    let mut focused_adaptation = FocusedAdaptationState::new();
    let mut installed_presentation_key: Option<InstalledPresentationKeyBinding> = None;
    let mut worker_key_lease =
        PresentationKeyWorkerLease::new(presentation_dispatch.key_clear_tx.clone());
    let mut presentation_feedback_rx = presentation_feedback.subscribe();
    let (mut send, mut receive) = channel.into_split();
    let (inbound_tx, mut inbound_rx) =
        tokio_mpsc::channel::<ControlInboundEvent>(CONTROL_INBOUND_QUEUE_CAPACITY);
    let receive_pump = tokio::spawn(async move {
        loop {
            let (event, terminal) = match receive.receive().await {
                Ok(envelope) => (ControlInboundEvent::Envelope(envelope), false),
                Err(ControlTransportError::Timeout { .. }) => (ControlInboundEvent::Timeout, false),
                Err(error) => (
                    ControlInboundEvent::Failed(transport_diagnostic_code(&error).to_owned()),
                    true,
                ),
            };
            if inbound_tx.send(event).await.is_err() || terminal {
                return;
            }
        }
    });
    let _receive_pump = ReceivePumpGuard(receive_pump);

    loop {
        let mut envelope = tokio::select! {
            inbound = inbound_rx.recv() => {
                match inbound {
                    Some(ControlInboundEvent::Envelope(envelope)) => envelope,
                    Some(ControlInboundEvent::Timeout) => {
                        if last_inbound_at.elapsed() >= DEFAULT_OFFLINE_AFTER {
                            eprintln!("ClassMesh control session closed: control.heartbeat.offline");
                            connection.close(0_u32.into(), b"control peer offline");
                            return;
                        }
                        continue;
                    }
                    Some(ControlInboundEvent::Failed(code)) => {
                        eprintln!("ClassMesh control session transport failed: {code}");
                        connection.close(0_u32.into(), b"control transport failed");
                        return;
                    }
                    None => {
                        connection.close(0_u32.into(), b"control receive pump stopped");
                        return;
                    }
                }
            }
            feedback = presentation_feedback_rx.recv() => {
                let report = match feedback {
                    Ok(report) => report,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        eprintln!(
                            "ClassMesh presentation feedback dropped under bounded backpressure: skipped={skipped}"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        connection.close(0_u32.into(), b"presentation feedback bus closed");
                        return;
                    }
                };

                if report.control_session_id != session.control_session_id
                    || !worker_key_lease.accepts_feedback(&report)
                {
                    continue;
                }
                let Some(installed) = installed_presentation_key else {
                    continue;
                };
                if report.presentation_id != installed.presentation_id()
                    || report.feedback.stream_id() != installed.stream_id()
                    || report.epoch != installed.epoch()
                    || !presentation.matches_owner(
                        peer.identity.principal_id(),
                        session.control_session_id,
                        report.presentation_id,
                        u64::from(report.feedback.stream_id()),
                    )
                {
                    continue;
                }

                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                if authorization.principal_for_credential(
                    peer.identity.credential_fingerprint(),
                    now_unix_ms,
                ) != Some(peer.identity.principal_id())
                    || !authorization.authorize_credential(
                        peer.identity.credential_fingerprint(),
                        Permission::StartPresentation,
                        now_unix_ms,
                    )
                {
                    eprintln!(
                        "ClassMesh presentation feedback stopped: control.presentation.peer_no_longer_authorized"
                    );
                    connection.close(
                        0_u32.into(),
                        b"presentation feedback peer unauthorized",
                    );
                    return;
                }

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                let feedback_envelope = match build_presentation_feedback_envelope(
                    session.control_session_id,
                    session.negotiated.version,
                    next_sequence,
                    &report.feedback,
                ) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        eprintln!("ClassMesh presentation feedback rejected locally: {error}");
                        continue;
                    }
                };
                if let Err(error) = send.send(&feedback_envelope).await {
                    eprintln!(
                        "ClassMesh presentation feedback send failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"presentation feedback send failed");
                    return;
                }
                outbound_sequence = next_sequence;
                continue;
            }
        };
        last_inbound_at = Instant::now();

        match envelope.payload.as_ref() {
            Some(control_envelope::Payload::Heartbeat(sample)) => {
                if let Err(error) = guard.validate_envelope(&envelope) {
                    eprintln!(
                        "ClassMesh control envelope rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"invalid control envelope");
                    return;
                }

                let Some(media_health) = media_health_from_wire(sample.media) else {
                    eprintln!(
                        "ClassMesh heartbeat rejected: control.heartbeat.invalid_media_health"
                    );
                    connection.close(0_u32.into(), b"invalid heartbeat");
                    return;
                };
                if let Err(error) = heartbeat.observe(
                    session_clock.elapsed(),
                    HeartbeatSample {
                        control_session_id: sample.control_session_id,
                        sequence: envelope.sequence,
                        media_health,
                    },
                ) {
                    eprintln!(
                        "ClassMesh heartbeat rejected: {}",
                        heartbeat_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"invalid heartbeat");
                    return;
                }

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let ack = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id: envelope.request_id,
                    payload: Some(control_envelope::Payload::HeartbeatAck(HeartbeatAck {
                        heartbeat_sequence: envelope.sequence,
                        monotonic_time_us: duration_micros_u64(session_clock.elapsed()),
                    })),
                };
                if let Err(error) = send.send(&ack).await {
                    eprintln!(
                        "ClassMesh heartbeat ack failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"heartbeat ack failed");
                    return;
                }
            }
            Some(control_envelope::Payload::StreamOffer(offer)) => {
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                let presentation_offer = offer.kind == WireStreamKind::TeacherPresentation as i32;
                let required_permission = if presentation_offer {
                    Permission::StartPresentation
                } else {
                    Permission::ViewInteractive
                };
                if let Err(error) =
                    guard.authorize(authorization, &envelope, required_permission, now_unix_ms)
                {
                    eprintln!(
                        "ClassMesh stream offer rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"stream offer unauthorized");
                    return;
                }

                let answer = if presentation_offer {
                    let supported =
                        negotiated_presentation_transports(&session.negotiated.capabilities);
                    match validate_presentation_offer_for_dispatch(
                        offer,
                        &session.negotiated.capabilities,
                    ) {
                        Err(error) => StreamAnswer {
                            stream_id: offer.stream_id,
                            accepted: false,
                            rejection_reason: stream_offer_diagnostic_code(&error).to_owned(),
                            supported_transports: supported,
                        },
                        Ok(validated) => {
                            let (validated_stream_id, profile) = match &validated {
                                ValidatedPresentationDispatchOffer::Multicast(validated) => {
                                    (validated.stream_id, validated.profile)
                                }
                                ValidatedPresentationDispatchOffer::Unicast(validated) => {
                                    (validated.stream_id, validated.profile)
                                }
                            };
                            let owner = presentation.owner_for_stream(
                                peer.identity.principal_id(),
                                session.control_session_id,
                                validated_stream_id,
                            );
                            let installed = installed_presentation_key.filter(|installed| {
                                owner.is_some_and(|owner| {
                                    installed.presentation_id() == owner.presentation_id
                                        && u64::from(installed.stream_id()) == owner.stream_id
                                })
                            });
                            let worker_ready = installed.is_some_and(|installed| {
                                worker_key_lease
                                    .matches_installed(session.control_session_id, installed)
                            });

                            let dispatch_result = match (
                                owner,
                                installed,
                                worker_ready,
                                envelope.request_id,
                            ) {
                                (None, _, _, _) => {
                                    Err("control.presentation.stream_not_owner".to_owned())
                                }
                                (_, None, _, _) | (_, _, false, _) => {
                                    Err("control.presentation.worker_key_not_installed".to_owned())
                                }
                                (_, _, _, 0) => {
                                    Err("control.presentation.invalid_request_id".to_owned())
                                }
                                (Some(owner), Some(_), true, _) => {
                                    let stream_id = u32::try_from(validated_stream_id)
                                        .expect("validated stream id fits media header");
                                    match validated {
                                        ValidatedPresentationDispatchOffer::Multicast(
                                            validated,
                                        ) => {
                                            match (
                                                multicast_interface,
                                                connection.remote_address().ip(),
                                            ) {
                                                (None, _) => Err(
                                                    "control.presentation.multicast_unavailable"
                                                        .to_owned(),
                                                ),
                                                (_, std::net::IpAddr::V6(_)) => Err(
                                                    "control.presentation.multicast_peer_not_ipv4"
                                                        .to_owned(),
                                                ),
                                                (
                                                    Some(interface),
                                                    std::net::IpAddr::V4(teacher_source),
                                                ) => {
                                                    let start = ServicePresentationMulticastStart {
                                                        control_session_id: session
                                                            .control_session_id,
                                                        request_id: envelope.request_id,
                                                        presentation_id: owner.presentation_id,
                                                        stream_id,
                                                        width: profile.width,
                                                        height: profile.height,
                                                        fps: profile.fps,
                                                        bitrate_kbps: profile.bitrate_kbps,
                                                        group: validated.multicast.group,
                                                        port: validated.multicast.port,
                                                        interface,
                                                        teacher_source,
                                                    };
                                                    let (reply_tx, mut reply_rx) =
                                                        oneshot::channel();
                                                    let commit = MediaStartCommit::pending();
                                                    match presentation_dispatch
                                                        .multicast_start_tx
                                                        .try_send(
                                                            PresentationMulticastStartDispatch {
                                                                start,
                                                                commit: commit.clone(),
                                                                reply_tx,
                                                            },
                                                        ) {
                                                        Ok(()) => {
                                                            await_presentation_start(
                                                                commit,
                                                                &mut reply_rx,
                                                            )
                                                            .await
                                                        }
                                                        Err(mpsc::TrySendError::Full(_)) => Err(
                                                            "control.presentation.start_backpressure"
                                                                .to_owned(),
                                                        ),
                                                        Err(
                                                            mpsc::TrySendError::Disconnected(_),
                                                        ) => Err(
                                                            "control.presentation.start_disconnected"
                                                                .to_owned(),
                                                        ),
                                                    }
                                                }
                                            }
                                        }
                                        ValidatedPresentationDispatchOffer::Unicast(validated) => {
                                            let start = ServicePresentationUnicastStart {
                                                control_session_id: session.control_session_id,
                                                request_id: envelope.request_id,
                                                presentation_id: owner.presentation_id,
                                                stream_id,
                                                width: profile.width,
                                                height: profile.height,
                                                fps: profile.fps,
                                                bitrate_kbps: profile.bitrate_kbps,
                                                port: validated.port,
                                                teacher_source: connection.remote_address().ip(),
                                            };
                                            let (reply_tx, mut reply_rx) = oneshot::channel();
                                            let commit = MediaStartCommit::pending();
                                            match presentation_dispatch.unicast_start_tx.try_send(
                                                PresentationUnicastStartDispatch {
                                                    start,
                                                    commit: commit.clone(),
                                                    reply_tx,
                                                },
                                            ) {
                                                Ok(()) => {
                                                    await_presentation_start(commit, &mut reply_rx)
                                                        .await
                                                }
                                                Err(mpsc::TrySendError::Full(_)) => {
                                                    Err("control.presentation.start_backpressure"
                                                        .to_owned())
                                                }
                                                Err(mpsc::TrySendError::Disconnected(_)) => {
                                                    Err("control.presentation.start_disconnected"
                                                        .to_owned())
                                                }
                                            }
                                        }
                                    }
                                }
                            };

                            match dispatch_result {
                                Ok(()) => StreamAnswer {
                                    stream_id: offer.stream_id,
                                    accepted: true,
                                    rejection_reason: String::new(),
                                    supported_transports: supported,
                                },
                                Err(code) => StreamAnswer {
                                    stream_id: offer.stream_id,
                                    accepted: false,
                                    rejection_reason: code,
                                    supported_transports: supported,
                                },
                            }
                        }
                    }
                } else {
                    match validate_interactive_stream_offer(offer, &session.negotiated.capabilities)
                    {
                        Err(error) => StreamAnswer {
                            stream_id: offer.stream_id,
                            accepted: false,
                            rejection_reason: stream_offer_diagnostic_code(&error).to_owned(),
                            supported_transports: negotiated_interactive_transports(
                                &session.negotiated.capabilities,
                            ),
                        },
                        Ok(validated) if validated.transport == WireMediaTransport::UdpUnicast => {
                            if !media.try_acquire_owner(session.control_session_id) {
                                StreamAnswer {
                                    stream_id: offer.stream_id,
                                    accepted: false,
                                    rejection_reason: "control.media.focused_busy".to_owned(),
                                    supported_transports: negotiated_interactive_transports(
                                        &session.negotiated.capabilities,
                                    ),
                                }
                            } else {
                                let destination = peer_bound_udp_unicast_destination(
                                    connection.remote_address().ip(),
                                    &validated.transport_parameters,
                                );
                                let dispatch_result = match destination {
                                    Ok(destination) => {
                                        let stream_id = u32::try_from(validated.stream_id)
                                            .expect("validated stream id fits media header");
                                        let start = ServiceUdpStreamStart {
                                            stream_id,
                                            destination,
                                            width: validated.profile.width,
                                            height: validated.profile.height,
                                            fps: validated.profile.fps,
                                            bitrate_kbps: validated.profile.bitrate_kbps,
                                        };
                                        let (reply_tx, mut reply_rx) = oneshot::channel();
                                        let commit = MediaStartCommit::pending();
                                        match media.start_tx.try_send(FocusedMediaStart {
                                            control_session_id: session.control_session_id,
                                            start,
                                            commit: commit.clone(),
                                            reply_tx,
                                        }) {
                                            Ok(()) => match tokio::time::timeout(
                                                Duration::from_secs(1),
                                                &mut reply_rx,
                                            )
                                            .await
                                            {
                                                Ok(Ok(result)) => result,
                                                Ok(Err(_)) => {
                                                    Err("control.media.start_reply_dropped"
                                                        .to_owned())
                                                }
                                                Err(_) if commit.cancel() => {
                                                    Err("control.media.start_timeout".to_owned())
                                                }
                                                Err(_) if commit.is_committed() => {
                                                    reply_rx.await.unwrap_or_else(|_| {
                                                        Err("control.media.start_reply_dropped"
                                                            .to_owned())
                                                    })
                                                }
                                                Err(_) => {
                                                    Err("control.media.start_cancelled".to_owned())
                                                }
                                            },
                                            Err(mpsc::TrySendError::Full(_)) => {
                                                Err("control.media.start_backpressure".to_owned())
                                            }
                                            Err(mpsc::TrySendError::Disconnected(_)) => {
                                                Err("control.media.start_disconnected".to_owned())
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        Err(stream_offer_diagnostic_code(&error).to_owned())
                                    }
                                };
                                match dispatch_result {
                                    Ok(()) => StreamAnswer {
                                        stream_id: offer.stream_id,
                                        accepted: true,
                                        rejection_reason: String::new(),
                                        supported_transports: negotiated_interactive_transports(
                                            &session.negotiated.capabilities,
                                        ),
                                    },
                                    Err(code) => {
                                        let _ = media.release_owner(session.control_session_id);
                                        StreamAnswer {
                                            stream_id: offer.stream_id,
                                            accepted: false,
                                            rejection_reason: code,
                                            supported_transports: negotiated_interactive_transports(
                                                &session.negotiated.capabilities,
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => StreamAnswer {
                            stream_id: offer.stream_id,
                            accepted: false,
                            rejection_reason: "control.stream.runtime_not_ready".to_owned(),
                            supported_transports: negotiated_interactive_transports(
                                &session.negotiated.capabilities,
                            ),
                        },
                    }
                };
                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id: envelope.request_id,
                    payload: Some(control_envelope::Payload::StreamAnswer(answer)),
                };
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh stream answer failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"stream answer failed");
                    return;
                }
            }
            Some(control_envelope::Payload::ReceiverFeedback(feedback)) => {
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                if let Err(error) = guard.authorize(
                    authorization,
                    &envelope,
                    Permission::ControlInput,
                    now_unix_ms,
                ) {
                    eprintln!(
                        "ClassMesh receiver feedback rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"receiver feedback unauthorized");
                    return;
                }
                if !input.try_acquire_owner(session.control_session_id) {
                    eprintln!(
                        "ClassMesh receiver feedback rejected: control.command.controller_busy"
                    );
                    connection.close(0_u32.into(), b"interactive controller busy");
                    return;
                }

                let reconfigure = match focused_adaptation.observe(feedback) {
                    Ok(reconfigure) => reconfigure,
                    Err(code) => {
                        eprintln!("ClassMesh receiver feedback rejected: {code}");
                        connection.close(0_u32.into(), b"invalid receiver feedback");
                        return;
                    }
                };
                let Some(reconfigure) = reconfigure else {
                    continue;
                };

                match media.reconfigure_tx.try_send(FocusedMediaReconfigure {
                    control_session_id: session.control_session_id,
                    reconfigure: reconfigure.clone(),
                }) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(_)) => {
                        eprintln!(
                            "ClassMesh focused media rejected: control.media.reconfigure_backpressure"
                        );
                        connection.close(0_u32.into(), b"media reconfigure backpressure");
                        return;
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        eprintln!(
                            "ClassMesh focused media rejected: control.media.reconfigure_disconnected"
                        );
                        connection.close(0_u32.into(), b"media reconfigure disconnected");
                        return;
                    }
                }

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id: envelope.request_id,
                    payload: Some(control_envelope::Payload::StreamReconfigure(reconfigure)),
                };
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh stream reconfigure failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"stream reconfigure failed");
                    return;
                }
            }
            Some(control_envelope::Payload::Nack(nack)) => {
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                if let Err(error) = guard.authorize(
                    authorization,
                    &envelope,
                    Permission::ViewInteractive,
                    now_unix_ms,
                ) {
                    eprintln!(
                        "ClassMesh NACK rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"media feedback unauthorized");
                    return;
                }
                match feedback_message_from_nack(nack) {
                    Ok(feedback) => {
                        dispatch_media_feedback(media, session.control_session_id, feedback);
                    }
                    Err(code) => {
                        eprintln!("ClassMesh NACK ignored: {code}");
                    }
                }
            }
            Some(control_envelope::Payload::KeyframeRequest(request)) => {
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                if let Err(error) = guard.authorize(
                    authorization,
                    &envelope,
                    Permission::ViewInteractive,
                    now_unix_ms,
                ) {
                    eprintln!(
                        "ClassMesh keyframe request rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"media feedback unauthorized");
                    return;
                }
                match feedback_message_from_keyframe(request) {
                    Ok(feedback) => {
                        dispatch_media_feedback(media, session.control_session_id, feedback);
                    }
                    Err(code) => {
                        eprintln!("ClassMesh keyframe request ignored: {code}");
                    }
                }
            }
            Some(control_envelope::Payload::PresentationKeyGrant(_)) => {
                if !group_media_capability_negotiated(&session.negotiated.capabilities) {
                    eprintln!(
                        "ClassMesh presentation key rejected: control.presentation.group_media_capability_not_negotiated"
                    );
                    zeroize_presentation_key_envelope(&mut envelope);
                    connection.close(0_u32.into(), b"group-media capability not negotiated");
                    return;
                }

                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        zeroize_presentation_key_envelope(&mut envelope);
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                if let Err(error) = guard.authorize(
                    authorization,
                    &envelope,
                    Permission::StartPresentation,
                    now_unix_ms,
                ) {
                    eprintln!(
                        "ClassMesh presentation key rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    zeroize_presentation_key_envelope(&mut envelope);
                    connection.close(0_u32.into(), b"presentation key unauthorized");
                    return;
                }

                let (presentation_id, stream_id, epoch) = match envelope.payload.as_ref() {
                    Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                        (grant.presentation_id, grant.stream_id, grant.epoch)
                    }
                    _ => unreachable!("presentation key arm requires PresentationKeyGrant"),
                };
                if !presentation.matches_owner(
                    peer.identity.principal_id(),
                    session.control_session_id,
                    presentation_id,
                    stream_id,
                ) {
                    eprintln!(
                        "ClassMesh presentation key rejected: control.presentation.key_not_owner"
                    );
                    zeroize_presentation_key_envelope(&mut envelope);
                    connection.close(0_u32.into(), b"presentation key owner mismatch");
                    return;
                }
                if !presentation_key_epoch_is_fresh(
                    installed_presentation_key.as_ref(),
                    presentation_id,
                    stream_id,
                    epoch,
                ) {
                    eprintln!(
                        "ClassMesh presentation key rejected: control.presentation.key_epoch_stale"
                    );
                    zeroize_presentation_key_envelope(&mut envelope);
                    connection.close(0_u32.into(), b"stale presentation key epoch");
                    return;
                }

                let install = match envelope.payload.as_mut() {
                    Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                        match SensitivePresentationKeyInstall::take_from_control_grant(
                            session.control_session_id,
                            envelope.request_id,
                            grant,
                        ) {
                            Ok(install) => install,
                            Err(_) => {
                                eprintln!(
                                    "ClassMesh presentation key rejected: control.presentation.key_invalid"
                                );
                                connection.close(0_u32.into(), b"invalid presentation key");
                                return;
                            }
                        }
                    }
                    _ => unreachable!("presentation key arm requires PresentationKeyGrant"),
                };
                let expected_binding = install.binding();
                let (reply_tx, mut reply_rx) = oneshot::channel();
                match presentation_dispatch
                    .key_install_tx
                    .try_send(PresentationKeyInstallDispatch { install, reply_tx })
                {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(_)) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_backpressure"
                        );
                        connection.close(0_u32.into(), b"presentation key worker busy");
                        return;
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_unavailable"
                        );
                        connection.close(0_u32.into(), b"presentation key worker unavailable");
                        return;
                    }
                }

                let installed_binding = match tokio::time::timeout(
                    PRESENTATION_KEY_INSTALL_TIMEOUT,
                    &mut reply_rx,
                )
                .await
                {
                    Ok(Ok(Ok(binding))) if binding == expected_binding => binding,
                    Ok(Ok(Ok(_))) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_binding_mismatch"
                        );
                        connection.close(0_u32.into(), b"presentation key worker mismatch");
                        return;
                    }
                    Ok(Ok(Err(code))) => {
                        eprintln!("ClassMesh presentation key rejected: {code}");
                        connection.close(0_u32.into(), b"presentation key worker rejected");
                        return;
                    }
                    Ok(Err(_)) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_reply_dropped"
                        );
                        connection.close(0_u32.into(), b"presentation key worker reply dropped");
                        return;
                    }
                    Err(_) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_timeout"
                        );
                        connection.close(0_u32.into(), b"presentation key worker timeout");
                        return;
                    }
                };
                let installed = match InstalledPresentationKeyBinding::new(
                    installed_binding.presentation_id,
                    installed_binding.stream_id,
                    installed_binding.epoch,
                ) {
                    Ok(installed) => installed,
                    Err(_) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.worker_binding_invalid"
                        );
                        connection.close(0_u32.into(), b"presentation key worker binding invalid");
                        return;
                    }
                };

                worker_key_lease.replace(installed_binding);

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                let ack = match build_presentation_key_ack_from_binding(
                    &envelope,
                    installed,
                    next_sequence,
                ) {
                    Ok(ack) => ack,
                    Err(_) => {
                        eprintln!(
                            "ClassMesh presentation key rejected: control.presentation.key_ack_invalid"
                        );
                        connection.close(0_u32.into(), b"presentation key ack invalid");
                        return;
                    }
                };
                if let Err(error) = send.send(&ack).await {
                    eprintln!(
                        "ClassMesh presentation key ACK failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"presentation key ack failed");
                    return;
                }
                outbound_sequence = next_sequence;
                installed_presentation_key = Some(installed);
            }
            Some(control_envelope::Payload::PresentationStart(_))
            | Some(control_envelope::Payload::PresentationStop(_)) => {
                if !presentation_capability_negotiated(&session.negotiated.capabilities) {
                    eprintln!(
                        "ClassMesh presentation command rejected: control.presentation.capability_not_negotiated"
                    );
                    connection.close(0_u32.into(), b"presentation capability not negotiated");
                    return;
                }
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                let status = match dispatch_privileged_command(
                    &mut guard,
                    authorization,
                    &envelope,
                    now_unix_ms,
                ) {
                    Ok(PrivilegedControlCommand::PresentationStart(start)) => presentation.start(
                        peer.identity.principal_id(),
                        session.control_session_id,
                        start.presentation_id,
                        start.stream_id,
                    ),
                    Ok(PrivilegedControlCommand::PresentationStop(stop)) => presentation.stop(
                        peer.identity.principal_id(),
                        session.control_session_id,
                        stop.presentation_id,
                    ),
                    Ok(_) => {
                        eprintln!(
                            "ClassMesh presentation command rejected: control.command.payload_mismatch"
                        );
                        connection.close(0_u32.into(), b"privileged payload mismatch");
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "ClassMesh presentation command rejected: {}",
                            privileged_dispatch_diagnostic_code(&error)
                        );
                        connection.close(0_u32.into(), b"privileged command rejected");
                        return;
                    }
                };

                if status.state == WirePresentationState::Stopped as i32 {
                    installed_presentation_key = None;
                    worker_key_lease.clear_now();
                }

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id: envelope.request_id,
                    payload: Some(control_envelope::Payload::PresentationStatus(status)),
                };
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh presentation status failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"presentation status failed");
                    return;
                }
            }
            Some(control_envelope::Payload::SystemActionRequest(_)) => {
                if !system_action_capability_negotiated(&session.negotiated.capabilities) {
                    eprintln!(
                        "ClassMesh system action rejected: control.system_action.capability_not_negotiated"
                    );
                    connection.close(0_u32.into(), b"system action capability not negotiated");
                    return;
                }

                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                let action = match dispatch_privileged_command(
                    &mut guard,
                    authorization,
                    &envelope,
                    now_unix_ms,
                ) {
                    Ok(PrivilegedControlCommand::SystemAction(action)) => action,
                    Ok(_) => {
                        eprintln!(
                            "ClassMesh system action rejected: control.command.payload_mismatch"
                        );
                        connection.close(0_u32.into(), b"privileged payload mismatch");
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "ClassMesh system action rejected: {}",
                            privileged_dispatch_diagnostic_code(&error)
                        );
                        connection.close(0_u32.into(), b"privileged command rejected");
                        return;
                    }
                };

                let wire_action = action.action();
                let request_id = envelope.request_id;
                let commit = SystemActionCommit::pending();
                let (reply_tx, mut reply_rx) = oneshot::channel();
                let dispatch = SystemActionDispatch {
                    request_id,
                    action,
                    commit: commit.clone(),
                    reply_tx,
                };
                let outcome = match system_actions.tx.try_send(dispatch) {
                    Ok(()) => await_system_action_dispatch(commit, &mut reply_rx).await,
                    Err(mpsc::TrySendError::Full(_)) => SystemActionDispatchOutcome::Backpressure,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        SystemActionDispatchOutcome::ServiceUnavailable
                    }
                };

                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    eprintln!("ClassMesh control session closed: control.sequence.exhausted");
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = build_system_action_response(
                    session.control_session_id,
                    outbound_sequence,
                    request_id,
                    session.negotiated.version,
                    wire_action,
                    outcome,
                );
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh system action result failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"system action result failed");
                    return;
                }
            }
            Some(control_envelope::Payload::TeacherInteractionRequest(request)) => {
                let kind = match classmesh_protocol::teacher_interaction::validate_request(request)
                {
                    Ok(kind) => kind,
                    Err(_) => {
                        connection.close(0_u32.into(), b"teacher interaction invalid");
                        return;
                    }
                };
                if !teacher_interaction_capability_negotiated(
                    kind,
                    &session.negotiated.capabilities,
                ) {
                    eprintln!(
                        "ClassMesh Teacher interaction rejected: control.teacher_interaction.capability_not_negotiated"
                    );
                    connection.close(
                        0_u32.into(),
                        b"teacher interaction capability not negotiated",
                    );
                    return;
                }

                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                let request = match dispatch_privileged_command(
                    &mut guard,
                    authorization,
                    &envelope,
                    now_unix_ms,
                ) {
                    Ok(PrivilegedControlCommand::TeacherInteraction(request)) => request,
                    Ok(_) => {
                        connection.close(0_u32.into(), b"privileged payload mismatch");
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "ClassMesh Teacher interaction rejected: {}",
                            privileged_dispatch_diagnostic_code(&error)
                        );
                        connection.close(0_u32.into(), b"privileged command rejected");
                        return;
                    }
                };
                match classmesh_protocol::teacher_interaction::validate_request(&request) {
                    Ok(revalidated_kind) if revalidated_kind == kind => {}
                    _ => {
                        connection.close(0_u32.into(), b"teacher interaction invalid");
                        return;
                    }
                }
                let request_id = envelope.request_id;
                let commit = SystemActionCommit::pending();
                let (reply_tx, mut reply_rx) = oneshot::channel();
                let dispatch = TeacherInteractionDispatch {
                    control_session_id: session.control_session_id,
                    request_id,
                    request,
                    commit: commit.clone(),
                    reply_tx,
                };
                let outcome = match teacher_interactions.tx.try_send(dispatch) {
                    Ok(()) => await_teacher_interaction_dispatch(commit, &mut reply_rx).await,
                    Err(mpsc::TrySendError::Full(_)) => {
                        TeacherInteractionDispatchOutcome::Backpressure
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        TeacherInteractionDispatchOutcome::ServiceUnavailable
                    }
                };
                let result = teacher_interaction_failure(kind, outcome);
                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id,
                    payload: Some(control_envelope::Payload::TeacherInteractionResult(result)),
                };
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh Teacher interaction result failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"teacher interaction result failed");
                    return;
                }
            }
            Some(control_envelope::Payload::FileTransferOffer(_))
            | Some(control_envelope::Payload::FileTransferChunk(_))
            | Some(control_envelope::Payload::FileTransferFinish(_))
            | Some(control_envelope::Payload::FileTransferCancel(_)) => {
                if !file_transfer_available(
                    session.negotiated.version,
                    &session.negotiated.capabilities,
                ) {
                    eprintln!(
                        "ClassMesh file transfer rejected: control.file_transfer.capability_not_negotiated"
                    );
                    connection.close(0_u32.into(), b"file transfer capability not negotiated");
                    return;
                }
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                let payload = match dispatch_privileged_command(
                    &mut guard,
                    authorization,
                    &envelope,
                    now_unix_ms,
                ) {
                    Ok(PrivilegedControlCommand::FileTransferOffer(value)) => {
                        FileTransferDispatchPayload::Offer(value)
                    }
                    Ok(PrivilegedControlCommand::FileTransferChunk(value)) => {
                        FileTransferDispatchPayload::Chunk(value)
                    }
                    Ok(PrivilegedControlCommand::FileTransferFinish(value)) => {
                        FileTransferDispatchPayload::Finish(value)
                    }
                    Ok(PrivilegedControlCommand::FileTransferCancel(value)) => {
                        FileTransferDispatchPayload::Cancel(value)
                    }
                    Ok(_) => {
                        connection.close(0_u32.into(), b"privileged payload mismatch");
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "ClassMesh file transfer rejected: {}",
                            privileged_dispatch_diagnostic_code(&error)
                        );
                        connection.close(0_u32.into(), b"privileged command rejected");
                        return;
                    }
                };
                let transfer_id = payload.transfer_id().to_vec();
                let request_id = envelope.request_id;
                let commit = SystemActionCommit::pending();
                let (reply_tx, mut reply_rx) = oneshot::channel();
                let dispatch = FileTransferDispatch {
                    principal_id: peer.identity.principal_id(),
                    control_session_id: session.control_session_id,
                    request_id,
                    payload,
                    commit: commit.clone(),
                    reply_tx,
                };
                let outcome = match file_transfers.tx.try_send(dispatch) {
                    Ok(()) => await_file_transfer_dispatch(commit, &mut reply_rx).await,
                    Err(mpsc::TrySendError::Full(_)) => FileTransferDispatchOutcome::Backpressure,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        FileTransferDispatchOutcome::ServiceUnavailable
                    }
                };
                let status = file_transfer_failure(&transfer_id, outcome);
                if validate_file_transfer_status(&status).is_err() {
                    connection.close(0_u32.into(), b"file transfer status invalid");
                    return;
                }
                let Some(next_sequence) = outbound_sequence.checked_add(1) else {
                    connection.close(0_u32.into(), b"control sequence exhausted");
                    return;
                };
                outbound_sequence = next_sequence;
                let response = ControlEnvelope {
                    control_session_id: session.control_session_id,
                    sequence: outbound_sequence,
                    protocol_version: Some(WireProtocolVersion {
                        major: u32::from(session.negotiated.version.major),
                        minor: u32::from(session.negotiated.version.minor),
                    }),
                    request_id,
                    payload: Some(control_envelope::Payload::FileTransferStatus(status)),
                };
                if let Err(error) = send.send(&response).await {
                    eprintln!(
                        "ClassMesh file transfer status failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"file transfer status failed");
                    return;
                }
            }
            Some(control_envelope::Payload::InputEvent(_)) => {
                let now_unix_ms = match unix_time_ms() {
                    Ok(value) => value,
                    Err(_) => {
                        connection.close(0_u32.into(), b"invalid service clock");
                        return;
                    }
                };
                match dispatch_privileged_command(&mut guard, authorization, &envelope, now_unix_ms)
                {
                    Ok(PrivilegedControlCommand::InputEvent(event)) => {
                        let availability =
                            InputAvailability::load(input.channels.availability.as_ref());
                        if availability != InputAvailability::Ready {
                            eprintln!(
                                "ClassMesh authorized input rejected: {}",
                                availability.rejection_code()
                            );
                            connection.close(0_u32.into(), b"input executor unavailable");
                            return;
                        }
                        if !input.try_acquire_owner(session.control_session_id) {
                            eprintln!(
                                "ClassMesh authorized input rejected: control.command.controller_busy"
                            );
                            connection.close(0_u32.into(), b"interactive controller busy");
                            return;
                        }
                        match input.channels.event_tx.try_send(event) {
                            Ok(()) => {}
                            Err(mpsc::TrySendError::Full(_)) => {
                                eprintln!(
                                    "ClassMesh authorized input rejected: control.command.input_backpressure"
                                );
                                connection.close(0_u32.into(), b"input backpressure");
                                return;
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => {
                                eprintln!(
                                    "ClassMesh authorized input rejected: control.command.executor_disconnected"
                                );
                                connection.close(0_u32.into(), b"input executor disconnected");
                                return;
                            }
                        }
                    }
                    Ok(_) => {
                        eprintln!(
                            "ClassMesh privileged command rejected: control.command.payload_mismatch"
                        );
                        connection.close(0_u32.into(), b"privileged payload mismatch");
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "ClassMesh privileged command rejected: {}",
                            privileged_dispatch_diagnostic_code(&error)
                        );
                        connection.close(0_u32.into(), b"privileged command rejected");
                        return;
                    }
                }
            }
            _ => {
                if let Err(error) = guard.validate_envelope(&envelope) {
                    eprintln!(
                        "ClassMesh control envelope rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                } else {
                    eprintln!(
                        "ClassMesh control payload rejected: control.command.unsupported_payload"
                    );
                }
                connection.close(0_u32.into(), b"unsupported control payload");
                return;
            }
        }
    }
}

impl InputDispatchState {
    fn try_acquire_owner(&self, session_id: u64) -> bool {
        let current = self.owner.load(Ordering::Acquire);
        if current == session_id {
            return true;
        }
        current == 0
            && self
                .owner
                .compare_exchange(0, session_id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    fn release_owner(&self, session_id: u64) -> bool {
        if self.owner.load(Ordering::Acquire) != session_id {
            return false;
        }

        if InputAvailability::load(self.channels.availability.as_ref()) == InputAvailability::Ready
        {
            match self.channels.cleanup_tx.try_send(()) {
                Ok(()) | Err(mpsc::TrySendError::Full(())) => {}
                Err(mpsc::TrySendError::Disconnected(())) => {
                    eprintln!("ClassMesh input cleanup skipped: executor channel disconnected");
                }
            }
        }

        self.owner
            .compare_exchange(session_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

fn zeroize_presentation_key_envelope(envelope: &mut ControlEnvelope) {
    if let Some(control_envelope::Payload::PresentationKeyGrant(grant)) = envelope.payload.as_mut()
    {
        zeroize_received_presentation_key(grant);
    }
}

fn service_hello_capabilities(
    worker_capabilities: &WorkerCapabilityState,
    udp_multicast_available: bool,
) -> BTreeSet<Capability> {
    let mut capabilities = worker_capabilities.hello_capabilities();
    capabilities.insert(Capability::TeacherPresentation);
    capabilities.insert(Capability::SframeGroupMedia);
    capabilities.insert(Capability::SystemActions);
    if worker_capabilities.has_live_worker() {
        capabilities.insert(Capability::TeacherMessage);
        capabilities.insert(Capability::OpenTarget);
    }
    if udp_multicast_available {
        capabilities.insert(Capability::UdpMulticast);
    }
    capabilities
}

fn local_udp_multicast_capability(interface: Option<Ipv4Addr>) -> bool {
    let Some(interface) = interface else {
        return false;
    };
    match probe_local_multicast_interface(interface) {
        Ok(outcome) if outcome.can_advertise_udp_multicast() => {
            eprintln!(
                "ClassMesh local UDP multicast probe passed on interface {interface}; capability enabled"
            );
            true
        }
        Ok(outcome) => {
            eprintln!(
                "ClassMesh local UDP multicast probe unavailable on interface {interface}: {outcome:?}"
            );
            false
        }
        Err(error) => {
            eprintln!(
                "ClassMesh local UDP multicast probe failed closed on interface {interface}: {error}"
            );
            false
        }
    }
}

fn presentation_capability_negotiated(capabilities: &BTreeSet<Capability>) -> bool {
    capabilities.contains(&Capability::TeacherPresentation)
}

fn system_action_capability_negotiated(capabilities: &BTreeSet<Capability>) -> bool {
    capabilities.contains(&Capability::SystemActions)
}

fn teacher_interaction_capability_negotiated(
    kind: TeacherInteractionKind,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    match kind {
        TeacherInteractionKind::Message => capabilities.contains(&Capability::TeacherMessage),
        TeacherInteractionKind::OpenTarget => capabilities.contains(&Capability::OpenTarget),
        TeacherInteractionKind::Unspecified => false,
    }
}

fn group_media_capability_negotiated(capabilities: &BTreeSet<Capability>) -> bool {
    capabilities.contains(&Capability::TeacherPresentation)
        && capabilities.contains(&Capability::SframeGroupMedia)
}

fn presentation_key_epoch_is_fresh(
    current: Option<&InstalledPresentationKeyBinding>,
    presentation_id: u64,
    stream_id: u64,
    epoch: u32,
) -> bool {
    match current {
        None => epoch != 0,
        Some(current) => {
            current.presentation_id() == presentation_id
                && u64::from(current.stream_id()) == stream_id
                && epoch > current.epoch()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValidatedPresentationDispatchOffer {
    Multicast(ValidatedPresentationStreamOffer),
    Unicast(ValidatedPresentationUnicastFallbackOffer),
}

fn validate_presentation_offer_for_dispatch(
    offer: &classmesh_protocol::control_wire::StreamOffer,
    capabilities: &BTreeSet<Capability>,
) -> Result<ValidatedPresentationDispatchOffer, classmesh_control::stream::StreamOfferError> {
    let transport = WireMediaTransport::try_from(offer.transport)
        .map_err(|_| classmesh_control::stream::StreamOfferError::UnsupportedTransport)?;
    match transport {
        WireMediaTransport::UdpMulticast => validate_presentation_stream_offer(offer, capabilities)
            .map(ValidatedPresentationDispatchOffer::Multicast),
        WireMediaTransport::UdpUnicast => {
            validate_presentation_unicast_fallback_offer(offer, capabilities)
                .map(ValidatedPresentationDispatchOffer::Unicast)
        }
        WireMediaTransport::Unspecified
        | WireMediaTransport::QuicDatagram
        | WireMediaTransport::Webrtc
        | WireMediaTransport::ReliableFallback => {
            Err(classmesh_control::stream::StreamOfferError::UnsupportedTransport)
        }
    }
}

fn negotiated_presentation_transports(capabilities: &BTreeSet<Capability>) -> Vec<i32> {
    if !capabilities.contains(&Capability::TeacherPresentation)
        || !capabilities.contains(&Capability::SframeGroupMedia)
    {
        return Vec::new();
    }

    let mut transports = Vec::with_capacity(2);
    if capabilities.contains(&Capability::UdpMulticast) {
        transports.push(WireMediaTransport::UdpMulticast as i32);
    }
    if capabilities.contains(&Capability::UdpUnicast) {
        transports.push(WireMediaTransport::UdpUnicast as i32);
    }
    transports
}

fn negotiated_interactive_transports(capabilities: &BTreeSet<Capability>) -> Vec<i32> {
    let mut transports = Vec::with_capacity(3);
    if capabilities.contains(&Capability::UdpUnicast) {
        transports.push(WireMediaTransport::UdpUnicast as i32);
    }
    if capabilities.contains(&Capability::QuicDatagram) {
        transports.push(WireMediaTransport::QuicDatagram as i32);
    }
    if capabilities.contains(&Capability::WebRtc) {
        transports.push(WireMediaTransport::Webrtc as i32);
    }
    transports
}

fn media_health_from_wire(value: i32) -> Option<MediaHealth> {
    match value {
        1 => Some(MediaHealth::Idle),
        2 => Some(MediaHealth::Starting),
        3 => Some(MediaHealth::Streaming),
        4 => Some(MediaHealth::Degraded),
        5 => Some(MediaHealth::Recovering),
        6 => Some(MediaHealth::Suspended),
        7 => Some(MediaHealth::Failed),
        _ => None,
    }
}

fn duration_micros_u64(value: Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}

fn build_endpoint(
    state: &ControlRuntimeState,
    config: ControlRuntimeConfig,
) -> Result<Endpoint, String> {
    if state.identity.trust_roots_der.is_empty() {
        return Err("machine identity has no client trust roots".to_owned());
    }

    let mut roots = RootCertStore::empty();
    for root in &state.identity.trust_roots_der {
        roots
            .add(CertificateDer::from(root.clone()))
            .map_err(|_| "machine identity contains an invalid client trust root".to_owned())?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|error| format!("client certificate verifier creation failed: {error}"))?;

    let certificate_chain = state
        .identity
        .certificate_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let resolver = cng_server_cert_resolver(certificate_chain, state.key.clone())
        .map_err(|error| format!("protected server credential rejected: {error}"))?;
    let server_config = enrolled_server_config_with_resolver(resolver, verifier)
        .map_err(|error| format!("enrolled QUIC server configuration failed: {error}"))?;

    Endpoint::server(server_config, config.bind_address)
        .map_err(|error| format!("control listener bind failed: {error}"))
}

fn unix_time_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "system clock cannot be represented in milliseconds".to_owned())
}

fn next_session_id(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn test_path() -> std::path::PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "classmesh-control-runtime-config-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test directory");
        directory.join("control-runtime.json")
    }

    #[test]
    fn config_requires_supported_version_and_nonzero_port() {
        let path = test_path();
        fs::write(&path, r#"{"version":1,"bind_address":"127.0.0.1:44991"}"#)
            .expect("write config");
        assert_eq!(
            ControlRuntimeConfig::load(&path).expect("valid config"),
            ControlRuntimeConfig {
                bind_address: "127.0.0.1:44991".parse().expect("socket"),
                multicast_interface: None,
            }
        );

        fs::write(&path, r#"{"version":1,"bind_address":"127.0.0.1:0"}"#)
            .expect("write invalid port");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        fs::write(&path, r#"{"version":2,"bind_address":"127.0.0.1:44991"}"#)
            .expect("write invalid version");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        fs::write(
            &path,
            r#"{"version":1,"bind_address":"127.0.0.1:44991","multicast_interface":"192.0.2.10"}"#,
        )
        .expect("write multicast config");
        assert_eq!(
            ControlRuntimeConfig::load(&path)
                .expect("valid multicast config")
                .multicast_interface,
            Some(Ipv4Addr::new(192, 0, 2, 10))
        );

        fs::write(
            &path,
            r#"{"version":1,"bind_address":"127.0.0.1:44991","multicast_interface":"not-an-ip"}"#,
        )
        .expect("write invalid multicast interface");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn system_action_result_mapping_is_bounded_non_sensitive_and_correlated() {
        use classmesh_protocol::system_action::validate_result;

        for (outcome, state, diagnostic) in [
            (
                SystemActionDispatchOutcome::Accepted,
                SystemActionState::Accepted,
                "",
            ),
            (
                SystemActionDispatchOutcome::WorkerUnavailable,
                SystemActionState::Rejected,
                "system_action.worker_unavailable",
            ),
            (
                SystemActionDispatchOutcome::Backpressure,
                SystemActionState::Rejected,
                "system_action.service_backpressure",
            ),
            (
                SystemActionDispatchOutcome::ServiceUnavailable,
                SystemActionState::Rejected,
                "system_action.service_unavailable",
            ),
            (
                SystemActionDispatchOutcome::WriteFailed,
                SystemActionState::Failed,
                "system_action.worker_write_failed",
            ),
            (
                SystemActionDispatchOutcome::ExecutionFailed,
                SystemActionState::Failed,
                "system_action.execution_failed",
            ),
            (
                SystemActionDispatchOutcome::Unsupported,
                SystemActionState::Rejected,
                "system_action.executor_unavailable",
            ),
            (
                SystemActionDispatchOutcome::ReplyDropped,
                SystemActionState::Failed,
                "system_action.service_reply_dropped",
            ),
            (
                SystemActionDispatchOutcome::TimedOut,
                SystemActionState::Failed,
                "system_action.service_timeout",
            ),
            (
                SystemActionDispatchOutcome::Cancelled,
                SystemActionState::Rejected,
                "system_action.cancelled",
            ),
        ] {
            let envelope = build_system_action_response(
                77,
                12,
                991,
                ProtocolVersion { major: 0, minor: 5 },
                SystemAction::Lock,
                outcome,
            );
            assert_eq!(envelope.control_session_id, 77);
            assert_eq!(envelope.sequence, 12);
            assert_eq!(envelope.request_id, 991);
            let Some(control_envelope::Payload::SystemActionResult(result)) = envelope.payload
            else {
                panic!("expected system action result");
            };
            assert_eq!(result.action, SystemAction::Lock as i32);
            assert_eq!(result.state, state as i32);
            assert_eq!(result.diagnostic, diagnostic);
            assert!(result.diagnostic.len() <= 1024);
            assert_eq!(validate_result(&result), Ok(()));
        }
    }

    #[test]
    fn system_action_commit_prevents_late_execution_after_cancellation() {
        let commit = SystemActionCommit::pending();
        assert!(commit.cancel());
        assert!(!commit.try_commit());

        let committed = SystemActionCommit::pending();
        assert!(committed.try_commit());
        assert!(committed.is_committed());
        assert!(!committed.cancel());
    }

    #[test]
    fn teacher_interaction_capabilities_require_an_exact_live_worker() {
        let worker = WorkerCapabilityState::default();

        let unavailable = service_hello_capabilities(&worker, false);
        assert!(!unavailable.contains(&Capability::TeacherMessage));
        assert!(!unavailable.contains(&Capability::OpenTarget));

        worker.activate(3, 42, 7);
        let available = service_hello_capabilities(&worker, false);
        assert!(available.contains(&Capability::TeacherMessage));
        assert!(available.contains(&Capability::OpenTarget));

        assert!(!worker.is_current(2, 42, 7));
        assert!(worker.is_current(3, 42, 7));
        worker.clear();

        let cleared = service_hello_capabilities(&worker, false);
        assert!(!cleared.contains(&Capability::TeacherMessage));
        assert!(!cleared.contains(&Capability::OpenTarget));
    }

    #[test]
    fn teacher_interaction_negotiation_requires_the_exact_action_capability() {
        let message_only = BTreeSet::from([Capability::TeacherMessage]);
        assert!(teacher_interaction_capability_negotiated(
            TeacherInteractionKind::Message,
            &message_only,
        ));
        assert!(!teacher_interaction_capability_negotiated(
            TeacherInteractionKind::OpenTarget,
            &message_only,
        ));

        let target_only = BTreeSet::from([Capability::OpenTarget]);
        assert!(teacher_interaction_capability_negotiated(
            TeacherInteractionKind::OpenTarget,
            &target_only,
        ));
        assert!(!teacher_interaction_capability_negotiated(
            TeacherInteractionKind::Message,
            &target_only,
        ));

        assert!(!teacher_interaction_capability_negotiated(
            TeacherInteractionKind::Unspecified,
            &BTreeSet::from([Capability::TeacherMessage, Capability::OpenTarget]),
        ));
        assert!(!teacher_interaction_capability_negotiated(
            TeacherInteractionKind::Message,
            &BTreeSet::new(),
        ));
    }

    #[test]
    fn file_transfer_routing_failure_statuses_are_bounded_and_valid() {
        let transfer_id = vec![7_u8; 16];
        for (outcome, expected_state, expected_diagnostic) in [
            (
                FileTransferDispatchOutcome::Backpressure,
                FileTransferState::Rejected,
                "file_transfer.service_backpressure",
            ),
            (
                FileTransferDispatchOutcome::ServiceUnavailable,
                FileTransferState::Rejected,
                "file_transfer.service_unavailable",
            ),
            (
                FileTransferDispatchOutcome::StorageUnavailable,
                FileTransferState::Rejected,
                "file_transfer.storage_unavailable",
            ),
            (
                FileTransferDispatchOutcome::ReplyDropped,
                FileTransferState::Failed,
                "file_transfer.service_reply_dropped",
            ),
            (
                FileTransferDispatchOutcome::TimedOut,
                FileTransferState::Failed,
                "file_transfer.service_timeout",
            ),
            (
                FileTransferDispatchOutcome::Cancelled,
                FileTransferState::Cancelled,
                "file_transfer.cancelled",
            ),
        ] {
            let status = file_transfer_failure(&transfer_id, outcome);
            assert_eq!(status.transfer_id, transfer_id);
            assert_eq!(status.state, expected_state as i32);
            assert_eq!(status.next_offset, 0);
            assert_eq!(status.diagnostic, expected_diagnostic);
            assert_eq!(
                classmesh_protocol::file_transfer::validate_status(&status),
                Ok(())
            );
        }
    }

    #[test]
    fn file_transfer_capability_stays_off_until_storage_is_serviceable() {
        let worker = WorkerCapabilityState::default();
        let capabilities = service_hello_capabilities(&worker, false);
        assert!(!capabilities.contains(&Capability::FileTransfer));

        worker.activate(3, 42, 7);
        let with_worker = service_hello_capabilities(&worker, false);
        assert!(!with_worker.contains(&Capability::FileTransfer));
        assert!(!file_transfer_available(PROTOCOL_VERSION, &with_worker));
    }

    #[test]
    fn presentation_runtime_capability_is_explicit_and_probe_gated() {
        let worker = WorkerCapabilityState::default();
        let capabilities = service_hello_capabilities(&worker, false);
        assert!(capabilities.contains(&Capability::TeacherPresentation));
        assert!(capabilities.contains(&Capability::SframeGroupMedia));
        assert!(capabilities.contains(&Capability::ServiceSessionWorker));
        assert!(capabilities.contains(&Capability::SystemActions));
        assert!(!capabilities.contains(&Capability::TeacherMessage));
        assert!(!capabilities.contains(&Capability::OpenTarget));
        assert!(!capabilities.contains(&Capability::UdpUnicast));
        assert!(!capabilities.contains(&Capability::QuicDatagram));
        assert!(!capabilities.contains(&Capability::UdpMulticast));

        let probed = service_hello_capabilities(&worker, true);
        assert!(probed.contains(&Capability::TeacherPresentation));
        assert!(probed.contains(&Capability::SframeGroupMedia));
        assert!(probed.contains(&Capability::UdpMulticast));

        assert!(presentation_capability_negotiated(&capabilities));
        assert!(group_media_capability_negotiated(&capabilities));
        assert!(system_action_capability_negotiated(&capabilities));
        assert!(!presentation_capability_negotiated(&BTreeSet::new()));
        assert!(!group_media_capability_negotiated(&BTreeSet::from([
            Capability::TeacherPresentation,
        ])));
    }

    #[test]
    fn presentation_runtime_resolves_only_exact_owner_stream() {
        let presentation = PresentationDispatchState::default();
        let owner = PrincipalId([9; 32]);
        let other = PrincipalId([8; 32]);
        let _ = presentation.start(owner, 10, 20, 30);

        assert_eq!(
            presentation
                .owner_for_stream(owner, 10, 30)
                .map(|value| value.presentation_id),
            Some(20)
        );
        assert!(presentation.owner_for_stream(owner, 10, 31).is_none());
        assert!(presentation.owner_for_stream(owner, 11, 30).is_none());
        assert!(presentation.owner_for_stream(other, 10, 30).is_none());
    }

    #[test]
    fn worker_key_lease_matches_only_exact_confirmed_media_binding() {
        let (clear_tx, _clear_rx) = mpsc::sync_channel(1);
        let mut lease = PresentationKeyWorkerLease::new(clear_tx);
        let binding = PresentationKeyInstallBinding {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        };
        lease.replace(binding);
        let installed =
            InstalledPresentationKeyBinding::new(55, 7, 3).expect("valid installed key");

        assert!(lease.matches_installed(77, installed));
        assert!(!lease.matches_installed(78, installed));
        assert!(!lease.matches_installed(
            77,
            InstalledPresentationKeyBinding::new(56, 7, 3).expect("valid alternate key"),
        ));
        assert!(!lease.matches_installed(
            77,
            InstalledPresentationKeyBinding::new(55, 7, 4).expect("valid newer key"),
        ));
    }

    #[test]
    fn presentation_transport_answer_advertises_each_full_protected_contract() {
        let full = BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpMulticast,
            Capability::UdpUnicast,
        ]);
        assert_eq!(
            negotiated_presentation_transports(&full),
            vec![
                WireMediaTransport::UdpMulticast as i32,
                WireMediaTransport::UdpUnicast as i32,
            ]
        );

        let multicast_only = BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpMulticast,
        ]);
        assert_eq!(
            negotiated_presentation_transports(&multicast_only),
            vec![WireMediaTransport::UdpMulticast as i32]
        );

        let unicast_only = BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpUnicast,
        ]);
        assert_eq!(
            negotiated_presentation_transports(&unicast_only),
            vec![WireMediaTransport::UdpUnicast as i32]
        );

        assert!(
            negotiated_presentation_transports(&BTreeSet::from([
                Capability::TeacherPresentation,
                Capability::UdpUnicast,
            ]))
            .is_empty()
        );
    }

    #[test]
    fn presentation_offer_dispatch_validation_is_transport_explicit() {
        use classmesh_control::stream::{
            UDP_MULTICAST_PARAMETERS_VERSION, UDP_UNICAST_PARAMETERS_VERSION,
        };
        use classmesh_protocol::control_wire::{StreamOffer, VideoCodec, VideoProfile};

        let capabilities = BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpMulticast,
            Capability::UdpUnicast,
        ]);
        let profile = Some(VideoProfile {
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 5_000,
            codec: VideoCodec::H264 as i32,
        });

        let multicast = StreamOffer {
            stream_id: 9,
            kind: WireStreamKind::TeacherPresentation as i32,
            transport: WireMediaTransport::UdpMulticast as i32,
            profile,
            transport_parameters: vec![
                UDP_MULTICAST_PARAMETERS_VERSION,
                239,
                10,
                20,
                30,
                0xc3,
                0x50,
            ],
        };
        assert!(matches!(
            validate_presentation_offer_for_dispatch(&multicast, &capabilities),
            Ok(ValidatedPresentationDispatchOffer::Multicast(_))
        ));

        let unicast = StreamOffer {
            stream_id: 9,
            kind: WireStreamKind::TeacherPresentation as i32,
            transport: WireMediaTransport::UdpUnicast as i32,
            profile,
            transport_parameters: vec![UDP_UNICAST_PARAMETERS_VERSION, 0xc3, 0x50],
        };
        assert!(matches!(
            validate_presentation_offer_for_dispatch(&unicast, &capabilities),
            Ok(ValidatedPresentationDispatchOffer::Unicast(_))
        ));
    }

    #[test]
    fn presentation_runtime_enforces_exact_owner_and_bounded_rejection() {
        let presentation = PresentationDispatchState::default();
        let owner = PrincipalId([1; 32]);
        let other = PrincipalId([2; 32]);

        let started = presentation.start(owner, 10, 20, 30);
        assert_eq!(started.state, WirePresentationState::Starting as i32);
        assert_eq!((started.presentation_id, started.stream_id), (20, 30));

        let busy = presentation.start(other, 11, 21, 31);
        assert_eq!(busy.state, WirePresentationState::Rejected as i32);
        assert_eq!(busy.diagnostic, "control.presentation.busy");
        assert_eq!(
            presentation.owner().map(|value| value.principal_id),
            Some(owner)
        );

        let rejected_stop = presentation.stop(other, 11, 20);
        assert_eq!(rejected_stop.state, WirePresentationState::Rejected as i32);
        assert_eq!(rejected_stop.stream_id, 0);
        assert_eq!(rejected_stop.diagnostic, "control.presentation.not_owner");
        assert!(presentation.owner().is_some());

        let stopped = presentation.stop(owner, 10, 20);
        assert_eq!(stopped.state, WirePresentationState::Stopped as i32);
        assert_eq!((stopped.presentation_id, stopped.stream_id), (20, 30));
        assert!(presentation.owner().is_none());
    }

    #[test]
    fn presentation_disconnect_cleanup_requires_exact_authenticated_session() {
        let presentation = PresentationDispatchState::default();
        let owner = PrincipalId([3; 32]);
        let other = PrincipalId([4; 32]);
        let _ = presentation.start(owner, 40, 50, 60);

        assert!(!presentation.release_session(owner, 41));
        assert!(!presentation.release_session(other, 40));
        assert!(presentation.owner().is_some());
        assert!(presentation.release_session(owner, 40));
        assert!(presentation.owner().is_none());
    }

    #[test]
    fn presentation_key_binding_requires_exact_active_owner_tuple() {
        let presentation = PresentationDispatchState::default();
        let owner = PrincipalId([5; 32]);
        let other = PrincipalId([6; 32]);
        let _ = presentation.start(owner, 70, 80, 90);

        assert!(presentation.matches_owner(owner, 70, 80, 90));
        assert!(!presentation.matches_owner(other, 70, 80, 90));
        assert!(!presentation.matches_owner(owner, 71, 80, 90));
        assert!(!presentation.matches_owner(owner, 70, 81, 90));
        assert!(!presentation.matches_owner(owner, 70, 80, 91));
    }

    #[test]
    fn worker_key_lease_schedules_exact_binding_once() {
        let (clear_tx, clear_rx) = mpsc::sync_channel(1);
        let binding = PresentationKeyInstallBinding {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        };
        {
            let mut lease = PresentationKeyWorkerLease::new(clear_tx);
            lease.replace(binding);
            lease.clear_now();
        }

        assert_eq!(clear_rx.try_recv(), Ok(binding));
        assert!(matches!(
            clear_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn presentation_feedback_requires_exact_installed_worker_key_lease() {
        let (clear_tx, _clear_rx) = mpsc::sync_channel(1);
        let mut lease = PresentationKeyWorkerLease::new(clear_tx);
        let binding = PresentationKeyInstallBinding {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        };
        lease.replace(binding);

        let exact = WorkerPresentationFeedback {
            process_id: 42,
            session_id: 9,
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            epoch: 3,
            feedback: FeedbackMessage::RequestKeyframe {
                stream_id: 7,
                after_frame_id: 10,
            },
        };
        assert!(lease.accepts_feedback(&exact));

        for report in [
            WorkerPresentationFeedback {
                request_id: 45,
                ..exact.clone()
            },
            WorkerPresentationFeedback {
                presentation_id: 56,
                ..exact.clone()
            },
            WorkerPresentationFeedback {
                epoch: 4,
                ..exact.clone()
            },
            WorkerPresentationFeedback {
                feedback: FeedbackMessage::RequestKeyframe {
                    stream_id: 8,
                    after_frame_id: 10,
                },
                ..exact.clone()
            },
        ] {
            assert!(!lease.accepts_feedback(&report));
        }
    }

    #[test]
    fn presentation_key_epoch_must_increase_within_exact_live_binding() {
        let installed =
            InstalledPresentationKeyBinding::new(80, 90, 3).expect("valid test binding");

        assert!(!presentation_key_epoch_is_fresh(
            Some(&installed),
            80,
            90,
            3
        ));
        assert!(!presentation_key_epoch_is_fresh(
            Some(&installed),
            80,
            90,
            2
        ));
        assert!(presentation_key_epoch_is_fresh(Some(&installed), 80, 90, 4));
        assert!(!presentation_key_epoch_is_fresh(
            Some(&installed),
            81,
            90,
            4
        ));
        assert!(!presentation_key_epoch_is_fresh(None, 80, 90, 0));
        assert!(presentation_key_epoch_is_fresh(None, 80, 90, 1));
    }

    #[test]
    fn stream_offer_supported_transport_list_is_deterministic_and_explicit() {
        let capabilities = BTreeSet::from([
            Capability::WebRtc,
            Capability::QuicDatagram,
            Capability::UdpUnicast,
            Capability::DxgiCapture,
        ]);
        assert_eq!(
            negotiated_interactive_transports(&capabilities),
            vec![
                WireMediaTransport::UdpUnicast as i32,
                WireMediaTransport::QuicDatagram as i32,
                WireMediaTransport::Webrtc as i32,
            ]
        );
    }

    #[test]
    fn focused_media_start_commit_is_single_winner() {
        let cancelled = MediaStartCommit::pending();
        assert!(cancelled.cancel());
        assert!(!cancelled.try_commit());
        assert!(!cancelled.is_committed());

        let committed = MediaStartCommit::pending();
        assert!(committed.try_commit());
        assert!(committed.is_committed());
        assert!(!committed.cancel());
    }

    #[test]
    fn focused_media_owner_is_independent_and_session_bound() {
        let channels = FocusedMediaDispatchChannels {
            start_tx: mpsc::sync_channel(1).0,
            reconfigure_tx: mpsc::sync_channel(1).0,
            feedback_tx: mpsc::sync_channel(1).0,
            released_session_floor: Arc::new(AtomicU64::new(0)),
            owner: Arc::new(AtomicU64::new(0)),
        };
        assert!(channels.try_acquire_owner(7));
        assert!(channels.try_acquire_owner(7));
        assert!(!channels.try_acquire_owner(8));
        assert!(!channels.release_owner(8));
        assert!(channels.release_owner(7));
        assert!(channels.try_acquire_owner(8));
    }

    #[test]
    fn wire_recovery_feedback_is_bounded_and_stream_safe() {
        assert_eq!(
            feedback_message_from_nack(&Nack {
                stream_id: 7,
                frame_id: 42,
                missing_packet_indices: vec![0, 3, u32::from(u16::MAX)],
                recovery_deadline_us: 123,
            }),
            Ok(FeedbackMessage::Nack {
                stream_id: 7,
                frame_id: 42,
                missing_packet_indices: vec![0, 3, u16::MAX],
            })
        );
        assert_eq!(
            feedback_message_from_keyframe(&KeyframeRequest {
                stream_id: 7,
                last_decodable_frame_id: 42,
            }),
            Ok(FeedbackMessage::RequestKeyframe {
                stream_id: 7,
                after_frame_id: 42,
            })
        );

        assert_eq!(
            feedback_message_from_nack(&Nack {
                stream_id: 0,
                frame_id: 42,
                missing_packet_indices: vec![0],
                recovery_deadline_us: 123,
            }),
            Err("control.media.feedback_invalid_stream")
        );
        assert_eq!(
            feedback_message_from_nack(&Nack {
                stream_id: 7,
                frame_id: 42,
                missing_packet_indices: vec![u32::from(u16::MAX) + 1],
                recovery_deadline_us: 123,
            }),
            Err("control.media.feedback_invalid_packet_index")
        );
        assert_eq!(
            feedback_message_from_nack(&Nack {
                stream_id: 7,
                frame_id: 42,
                missing_packet_indices: vec![0; MAX_NACK_PACKET_INDICES + 1],
                recovery_deadline_us: 123,
            }),
            Err("control.media.feedback_invalid_nack")
        );
    }

    #[test]
    fn wire_media_health_rejects_unspecified_and_unknown_values() {
        assert_eq!(media_health_from_wire(0), None);
        assert_eq!(media_health_from_wire(99), None);
        assert_eq!(media_health_from_wire(3), Some(MediaHealth::Streaming));
        assert_eq!(media_health_from_wire(5), Some(MediaHealth::Recovering));
    }

    fn healthy_receiver_feedback(stream_id: u64) -> ReceiverFeedback {
        ReceiverFeedback {
            stream_id,
            rtt_ms: 8.0,
            packet_loss: 0.001,
            jitter_ms: 1.0,
            decode_fps: 30.0,
            decode_latency_ms: 4.0,
            render_latency_ms: 4.0,
            queue_delay_ms: 4.0,
            dropped_frames: 0,
            reordered_packets: 0,
            received_bitrate_bps: 5_000_000,
        }
    }

    #[test]
    fn focused_feedback_emits_profile_only_reconfigure_after_hysteresis() {
        let mut adaptation = FocusedAdaptationState::new();
        let healthy = healthy_receiver_feedback(7);
        assert!(
            adaptation
                .observe(&healthy)
                .expect("healthy feedback")
                .is_none()
        );

        let mut degraded = healthy;
        degraded.packet_loss = 0.12;
        assert!(
            adaptation
                .observe(&degraded)
                .expect("first degraded sample")
                .is_none()
        );

        let reconfigure = adaptation
            .observe(&degraded)
            .expect("second degraded sample")
            .expect("profile should change after hysteresis");
        let profile = reconfigure.profile.expect("video profile");
        assert_eq!(reconfigure.stream_id, 7);
        assert_eq!((profile.width, profile.height, profile.fps), (640, 360, 20));
        assert_eq!(
            profile.codec,
            classmesh_protocol::control_wire::VideoCodec::H264 as i32
        );
        assert_eq!(
            reconfigure.transport,
            WireMediaTransport::Unspecified as i32
        );
        assert!(reconfigure.transport_parameters.is_empty());
    }

    #[test]
    fn focused_feedback_rejects_invalid_stream_and_metrics() {
        let mut adaptation = FocusedAdaptationState::new();
        let invalid_stream = healthy_receiver_feedback(0);
        assert_eq!(
            adaptation.observe(&invalid_stream),
            Err("control.feedback.invalid_stream")
        );

        let mut invalid_metrics = healthy_receiver_feedback(8);
        invalid_metrics.packet_loss = f32::NAN;
        assert_eq!(
            adaptation.observe(&invalid_metrics),
            Err("control.feedback.invalid_metrics")
        );
    }

    #[test]
    fn worker_capabilities_gate_explicit_udp_on_verified_h264_and_dxgi() {
        let state = WorkerCapabilityState::default();
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );

        state.activate(3, 42, 7);
        assert!(!state.apply_report(2, 42, 7, true, true));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );

        assert!(state.apply_report(3, 42, 7, true, true));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([
                Capability::DxgiCapture,
                Capability::H264HardwareEncode,
                Capability::ServiceSessionWorker,
                Capability::UdpUnicast,
            ])
        );
        assert!(state.hello_capabilities().contains(&Capability::UdpUnicast));
        assert!(
            !state
                .hello_capabilities()
                .contains(&Capability::QuicDatagram)
        );

        state.clear();
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );
    }

    #[test]
    fn h264_qualification_updates_only_the_current_worker_generation() {
        let state = WorkerCapabilityState::default();
        state.activate(12, 120, 7);
        assert!(state.apply_report(12, 120, 7, true, false));

        assert!(!state.apply_h264_qualification(11, 120, 7, true));
        assert!(
            !state
                .hello_capabilities()
                .contains(&Capability::H264HardwareEncode)
        );
        assert!(
            state
                .hello_capabilities()
                .contains(&Capability::DxgiCapture)
        );

        assert!(state.apply_h264_qualification(12, 120, 7, true));
        assert!(
            state
                .hello_capabilities()
                .contains(&Capability::H264HardwareEncode)
        );
        assert!(
            state
                .hello_capabilities()
                .contains(&Capability::DxgiCapture)
        );
        assert!(state.hello_capabilities().contains(&Capability::UdpUnicast));

        assert!(state.apply_h264_qualification(12, 120, 7, false));
        assert!(
            !state
                .hello_capabilities()
                .contains(&Capability::H264HardwareEncode)
        );
        assert!(
            state
                .hello_capabilities()
                .contains(&Capability::DxgiCapture)
        );
    }

    #[test]
    fn old_generation_cannot_restore_flags_after_worker_replacement() {
        let state = WorkerCapabilityState::default();
        state.activate(4, 40, 8);
        assert!(state.apply_report(4, 40, 8, true, true));

        state.activate(5, 50, 9);
        assert!(!state.apply_report(4, 40, 8, true, true));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );

        assert!(state.apply_report(5, 50, 9, true, false));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::DxgiCapture, Capability::ServiceSessionWorker,])
        );
    }

    #[test]
    fn stale_capability_reader_cannot_clear_replacement_worker_flags() {
        let state = WorkerCapabilityState::default();
        state.activate(10, 100, 4);
        assert!(state.apply_report(10, 100, 4, true, false));

        state.activate(11, 101, 5);
        assert!(state.apply_report(11, 101, 5, true, false));
        assert!(!state.clear_report_if_current(10, 100, 4));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::DxgiCapture, Capability::ServiceSessionWorker,])
        );

        assert!(state.clear_report_if_current(11, 101, 5));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );
    }

    #[test]
    fn stale_worker_identity_cannot_publish_capabilities() {
        let state = WorkerCapabilityState::default();
        state.activate(9, 100, 5);

        assert!(!state.apply_report(9, 101, 5, true, false));
        assert!(!state.apply_report(9, 100, 6, true, false));
        assert!(!state.apply_report(10, 100, 5, true, false));
        assert_eq!(
            state.hello_capabilities(),
            BTreeSet::from([Capability::ServiceSessionWorker])
        );
    }

    #[test]
    fn input_availability_codes_are_stable() {
        assert_eq!(
            InputAvailability::Suspended.rejection_code(),
            "control.command.session_suspended"
        );
        assert_eq!(
            InputAvailability::Starting.rejection_code(),
            "control.command.executor_starting"
        );
        assert_eq!(
            InputAvailability::Unavailable.rejection_code(),
            "control.command.executor_unavailable"
        );
    }

    #[test]
    fn input_owner_is_exclusive_and_reusable_after_release() {
        let (event_tx, _event_rx) = mpsc::sync_channel(1);
        let (cleanup_tx, cleanup_rx) = mpsc::sync_channel(1);
        let input = InputDispatchState {
            channels: InputDispatchChannels {
                event_tx,
                cleanup_tx,
                availability: Arc::new(AtomicU8::new(InputAvailability::Ready as u8)),
            },
            owner: Arc::new(AtomicU64::new(0)),
        };

        assert!(input.try_acquire_owner(41));
        assert!(input.try_acquire_owner(41));
        assert!(!input.try_acquire_owner(42));
        assert_eq!(input.owner.load(Ordering::Acquire), 41);

        assert!(input.release_owner(41));
        assert_eq!(cleanup_rx.try_recv(), Ok(()));
        assert_eq!(input.owner.load(Ordering::Acquire), 0);
        assert!(input.try_acquire_owner(42));
    }

    #[test]
    fn session_ids_are_nonzero_and_monotonic() {
        let counter = AtomicU64::new(1);
        assert_eq!(next_session_id(&counter), 1);
        assert_eq!(next_session_id(&counter), 2);
        assert_eq!(next_session_id(&counter), 3);
    }
}
