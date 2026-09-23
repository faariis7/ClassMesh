use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
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
use classmesh_control::dispatch::{PrivilegedControlCommand, dispatch_privileged_command};
use classmesh_control::handshake::{
    EstablishedAuthenticatedPeer, EstablishedControlSession, ServerHelloConfig,
    server_hello_enrolled,
};
use classmesh_control::presentation_state::{PresentationOwnership, PresentationOwnershipError};
use classmesh_control::quic::{
    ControlChannel, ControlTransportError, DEFAULT_IO_TIMEOUT, enrolled_server_config_with_resolver,
};
use classmesh_control::stream::{
    peer_bound_udp_unicast_destination, stream_profile_to_wire, validate_interactive_stream_offer,
};
use classmesh_control::{DEFAULT_OFFLINE_AFTER, HeartbeatSample, HeartbeatTracker};
use classmesh_core::adaptation::{
    AdaptationPolicy, FocusedProfileController, HysteresisConfig, QualityTier,
};
use classmesh_core::{NetworkMetrics, StreamKind};
use classmesh_identity_win::{CngMachineKey, MachineIdentityBundle, cng_server_cert_resolver};
use classmesh_protocol::control_wire::{
    ControlEnvelope, HeartbeatAck, InputEvent, KeyframeRequest,
    MediaTransport as WireMediaTransport, Nack, PresentationState as WirePresentationState,
    PresentationStatus, ProtocolVersion as WireProtocolVersion, ReceiverFeedback, StreamAnswer,
    StreamReconfigure, control_envelope,
};
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::{Capability, MediaHealth, PROTOCOL_VERSION};
use classmesh_security::{AuthorizationStore, Permission, PrincipalId};
use classmesh_windows_runtime::ipc::ServiceUdpStreamStart;
use quinn::Endpoint;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use serde::Deserialize;
use tokio::sync::oneshot;

const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(10);

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
pub(crate) struct FocusedMediaStartCommit(Arc<AtomicU8>);

impl FocusedMediaStartCommit {
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
    pub(crate) commit: FocusedMediaStartCommit,
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
}

#[derive(Debug, Deserialize)]
struct PersistedControlRuntimeConfig {
    version: u32,
    bind_address: String,
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

        Ok(Self { bind_address })
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
        input: InputDispatchChannels,
        media: FocusedMediaDispatchChannels,
        worker_capabilities: Arc<WorkerCapabilityState>,
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

                runtime.block_on(run_listener(
                    state,
                    config,
                    ready_tx,
                    stop_rx,
                    input,
                    media,
                    worker_capabilities,
                ));
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
    input: InputDispatchChannels,
    media: FocusedMediaDispatchChannels,
    worker_capabilities: Arc<WorkerCapabilityState>,
) {
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
                let media = media.clone();
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
                        local_capabilities: service_hello_capabilities(&worker_capabilities),
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
                                &mut channel,
                                &session,
                                peer,
                                authorization.as_ref(),
                                &input,
                                &media,
                                &presentation,
                            )
                            .await;
                            let _ = input.release_owner(session.control_session_id);
                            let _ = presentation.release_session(
                                peer.identity.principal_id,
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

async fn run_established_session(
    connection: &quinn::Connection,
    channel: &mut ControlChannel,
    session: &EstablishedControlSession,
    peer: EstablishedAuthenticatedPeer,
    authorization: &AuthorizationStore,
    input: &InputDispatchState,
    media: &FocusedMediaDispatchChannels,
    presentation: &PresentationDispatchState,
) {
    const HELLO_SEQUENCE: u64 = 1;

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

    loop {
        let envelope = match channel.receive().await {
            Ok(envelope) => envelope,
            Err(ControlTransportError::Timeout { .. }) => {
                if last_inbound_at.elapsed() >= DEFAULT_OFFLINE_AFTER {
                    eprintln!("ClassMesh control session closed: control.heartbeat.offline");
                    connection.close(0_u32.into(), b"control peer offline");
                    return;
                }
                continue;
            }
            Err(error) => {
                eprintln!(
                    "ClassMesh control session transport failed: {}",
                    transport_diagnostic_code(&error)
                );
                connection.close(0_u32.into(), b"control transport failed");
                return;
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
                if let Err(error) = channel.send(&ack).await {
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
                if let Err(error) = guard.authorize(
                    authorization,
                    &envelope,
                    Permission::ViewInteractive,
                    now_unix_ms,
                ) {
                    eprintln!(
                        "ClassMesh stream offer rejected: {}",
                        command_authorization_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"stream offer unauthorized");
                    return;
                }

                let answer = match validate_interactive_stream_offer(
                    offer,
                    &session.negotiated.capabilities,
                ) {
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
                                    let commit = FocusedMediaStartCommit::pending();
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
                                                Err("control.media.start_reply_dropped".to_owned())
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
                                Err(error) => Err(stream_offer_diagnostic_code(&error).to_owned()),
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
                if let Err(error) = channel.send(&response).await {
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
                if let Err(error) = channel.send(&response).await {
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
                        peer.identity.principal_id,
                        session.control_session_id,
                        start.presentation_id,
                        start.stream_id,
                    ),
                    Ok(PrivilegedControlCommand::PresentationStop(stop)) => presentation.stop(
                        peer.identity.principal_id,
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
                if let Err(error) = channel.send(&response).await {
                    eprintln!(
                        "ClassMesh presentation status failed: {}",
                        transport_diagnostic_code(&error)
                    );
                    connection.close(0_u32.into(), b"presentation status failed");
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

fn service_hello_capabilities(worker_capabilities: &WorkerCapabilityState) -> BTreeSet<Capability> {
    let mut capabilities = worker_capabilities.hello_capabilities();
    capabilities.insert(Capability::TeacherPresentation);
    capabilities
}

fn presentation_capability_negotiated(capabilities: &BTreeSet<Capability>) -> bool {
    capabilities.contains(&Capability::TeacherPresentation)
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
            }
        );

        fs::write(&path, r#"{"version":1,"bind_address":"127.0.0.1:0"}"#)
            .expect("write invalid port");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        fs::write(&path, r#"{"version":2,"bind_address":"127.0.0.1:44991"}"#)
            .expect("write invalid version");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn presentation_runtime_capability_is_explicit_and_transport_neutral() {
        let worker = WorkerCapabilityState::default();
        let capabilities = service_hello_capabilities(&worker);
        assert!(capabilities.contains(&Capability::TeacherPresentation));
        assert!(capabilities.contains(&Capability::ServiceSessionWorker));
        assert!(!capabilities.contains(&Capability::UdpUnicast));
        assert!(!capabilities.contains(&Capability::QuicDatagram));
        assert!(presentation_capability_negotiated(&capabilities));
        assert!(!presentation_capability_negotiated(&BTreeSet::new()));
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
        let cancelled = FocusedMediaStartCommit::pending();
        assert!(cancelled.cancel());
        assert!(!cancelled.try_commit());
        assert!(!cancelled.is_committed());

        let committed = FocusedMediaStartCommit::pending();
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
