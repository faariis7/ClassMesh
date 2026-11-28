//! Opt-in presentation on the installed Teacher's enrolled control session.
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{Receiver, SyncSender, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use classmesh_capture_win::{
    CaptureStep, DxgiCaptureFactory, RecoveringCapture, enumerate_displays,
};
use classmesh_control::{
    authorization::AuthenticatedControlGuard,
    group_media_session::{
        BoundGroupMediaReceiverSession, PendingPresentationKeyAck, PresentationKeyGrantRequest,
    },
    handshake::EstablishedControlSession,
    live_authorization::LiveAuthorizationStore,
    peer_identity::authenticated_peer_identity,
    presentation_recovery::PresentationRecoveryCoordinator,
    quic::ControlSendHalf,
    stream::{
        UDP_UNICAST_PARAMETERS_VERSION, peer_bound_udp_unicast_destination,
        stream_profile_from_wire, udp_multicast_transport_parameters,
    },
    teacher_playback_receive::AuthenticatedTeacherControlMessage,
};
use classmesh_core::{keyframe::PresentationKeyframeRequest, recovery::RecoveryPolicy};
use classmesh_network::{
    multicast::{MulticastMembership, MulticastProbeOutcome},
    multicast_sender::ProtectedMulticastSenderConfig,
    protected_unicast_sender::{ProtectedUnicastFanoutDelivery, ProtectedUnicastSenderConfig},
    runtime_multicast_probe::probe_local_multicast_interface,
};
use classmesh_protocol::{
    Capability,
    control_wire::{
        MediaTransport, PresentationStart, PresentationStop, StreamKind, StreamOffer, VideoCodec,
        VideoProfile, control_envelope::Payload,
    },
};
use classmesh_security::{
    Permission, group_media::GroupMediaEpoch, group_media_coordinator::GroupMediaCoordinator,
};
use classmesh_video::distributor::SinkId;
use classmesh_worker::{
    presentation::PresentationTarget, presentation_multicast_send::PresentationMulticastSendRuntime,
};
use quinn::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use crate::{
    TeacherVideoEngineDirective, TeacherVideoEngineLifecycle,
    connected_command::{TeacherCommandSender, TeacherControlRoute, verify_current_student},
    presentation_control::{PresentationControl, PresentationReply},
    presentation_view::{
        PresentationBindingView, PresentationRuntimeSnapshot, PresentationUiStatus,
        PresentationUpdate,
    },
    ui_shell::{TeacherPresentationUiAction, apply_presentation_ui_action},
};

const REPLY_DEADLINE: Duration = Duration::from_secs(10);
const QUEUE_CAPACITY: usize = 2;
pub(crate) type TeacherClock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresentationPolicy {
    #[serde(default)]
    transport: ConfiguredTransport,
    interface: Option<Ipv4Addr>,
    group: Option<Ipv4Addr>,
    port: u16,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_kbps: u32,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ConfiguredTransport {
    #[default]
    Multicast,
    Unicast,
}

#[derive(Clone, Copy)]
enum PresentationTransport {
    Multicast {
        membership: MulticastMembership,
        probe: Option<MulticastProbeOutcome>,
    },
    Unicast,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedPresentation {
    transport: PresentationTransport,
    port: u16,
    profile: VideoProfile,
}

impl PresentationPolicy {
    pub(crate) fn prepare(self) -> io::Result<PreparedPresentation> {
        let invalid_transport = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid protected presentation transport",
            )
        };
        if self.port == 0 {
            return Err(invalid_transport());
        }
        let transport = match (self.transport, self.group, self.interface) {
            (ConfiguredTransport::Multicast, Some(group), Some(interface)) => {
                PresentationTransport::Multicast {
                    membership: MulticastMembership::new(group, interface).map_err(error)?,
                    probe: None,
                }
            }
            (ConfiguredTransport::Unicast, None, None) => PresentationTransport::Unicast,
            _ => return Err(invalid_transport()),
        };
        let profile = VideoProfile {
            width: self.width,
            height: self.height,
            fps: self.fps,
            bitrate_kbps: self.bitrate_kbps,
            codec: VideoCodec::H264 as i32,
        };
        stream_profile_from_wire(&profile).map_err(error)?;
        Ok(PreparedPresentation {
            transport,
            port: self.port,
            profile,
        })
    }
}

impl PreparedPresentation {
    pub(crate) fn prepare_egress(mut self) -> Option<Self> {
        if let PresentationTransport::Multicast { membership, probe } = &mut self.transport {
            let outcome = probe_local_multicast_interface(membership.interface()).ok()?;
            if !outcome.can_advertise_udp_multicast() {
                return None;
            }
            *probe = Some(outcome);
        }
        Some(self)
    }

    pub(crate) fn capability(&self) -> Capability {
        match self.transport {
            PresentationTransport::Multicast { .. } => Capability::UdpMulticast,
            PresentationTransport::Unicast => Capability::UdpUnicast,
        }
    }

    fn wire_transport(&self) -> MediaTransport {
        match self.transport {
            PresentationTransport::Multicast { .. } => MediaTransport::UdpMulticast,
            PresentationTransport::Unicast => MediaTransport::UdpUnicast,
        }
    }

    fn offer(&self, stream_id: u32) -> io::Result<StreamOffer> {
        let parameters = match self.transport {
            PresentationTransport::Multicast { membership, .. } => {
                udp_multicast_transport_parameters(membership.group(), self.port)
                    .map_err(error)?
                    .to_vec()
            }
            PresentationTransport::Unicast => {
                let [high, low] = self.port.to_be_bytes();
                vec![UDP_UNICAST_PARAMETERS_VERSION, high, low]
            }
        };
        Ok(StreamOffer {
            stream_id: stream_id.into(),
            kind: StreamKind::TeacherPresentation as i32,
            transport: self.wire_transport() as i32,
            profile: Some(self.profile),
            transport_parameters: parameters,
        })
    }

    fn bind_sender(
        &self,
        peer_ip: IpAddr,
        binding: PresentationBindingView,
        epoch: GroupMediaEpoch,
        target: PresentationTarget,
    ) -> io::Result<PresentationMulticastSendRuntime> {
        match self.transport {
            PresentationTransport::Multicast {
                membership,
                probe: Some(probe),
            } => {
                let config = ProtectedMulticastSenderConfig::new(
                    membership,
                    self.port,
                    binding.presentation_id,
                    binding.stream_id,
                    epoch,
                    probe,
                )
                .map_err(error)?;
                PresentationMulticastSendRuntime::bind(target, config, SinkId(1)).map_err(error)
            }
            PresentationTransport::Unicast => {
                let offer = self.offer(binding.stream_id)?;
                let destination =
                    peer_bound_udp_unicast_destination(peer_ip, &offer.transport_parameters)
                        .map_err(error)?;
                let config = ProtectedUnicastSenderConfig::new(
                    destination,
                    binding.presentation_id,
                    binding.stream_id,
                    epoch,
                )
                .map_err(error)?;
                PresentationMulticastSendRuntime::bind_unicast(
                    target,
                    config,
                    SinkId(1),
                    QUEUE_CAPACITY,
                )
                .map_err(error)
            }
            PresentationTransport::Multicast { probe: None, .. } => {
                Err(io::Error::other("No local multicast probe"))
            }
        }
    }
}

pub(crate) struct PresentationRoute {
    pub(crate) route: TeacherControlRoute,
    pub(crate) authorization: Arc<LiveAuthorizationStore>,
    pub(crate) clock: TeacherClock,
}

pub(crate) struct InstalledPresentation {
    config: Option<PreparedPresentation>,
    pub(crate) binding: PresentationRoute,
    active: Option<ActivePresentation>,
    worker: Option<PresentationWorker>,
    stopped: Option<SenderRetirement>,
}

struct SenderRetirement {
    status: PresentationUiStatus,
    deadline: Instant,
}

impl SenderRetirement {
    fn check_deadline(&self, now: Instant) -> io::Result<()> {
        if now >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Local presentation sender did not retire in time",
            ));
        }
        Ok(())
    }
}

struct ActivePresentation {
    control: PresentationControl,
    coordinator: Option<GroupMediaCoordinator>,
    pending_key: Option<PendingPresentationKeyAck>,
    deadline: Instant,
    peer_ip: Option<IpAddr>,
    failure: Option<&'static str>,
}

impl InstalledPresentation {
    pub(crate) fn new(config: Option<PreparedPresentation>, binding: PresentationRoute) -> Self {
        Self {
            config,
            binding,
            active: None,
            worker: None,
            stopped: None,
        }
    }

    /// Disconnect retires the key and local sender before another connection can run.
    pub(crate) async fn retire(&mut self) -> io::Result<()> {
        self.active = None;
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.cancel();
        let wait = async {
            while !worker.thread.is_finished() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(REPLY_DEADLINE, wait)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Local presentation sender did not retire in time",
                )
            })?;
        let _ = worker
            .thread
            .join()
            .map_err(|_| io::Error::other("Presentation sender panicked"))?;
        Ok(())
    }

    pub(crate) fn availability(&self, session: &EstablishedControlSession) -> PresentationUiStatus {
        let Some(config) = &self.config else {
            return PresentationUiStatus::Unavailable(
                "An administrator must configure an available presentation transport.",
            );
        };
        if ![
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            config.capability(),
        ]
        .iter()
        .all(|capability| session.negotiated.capabilities.contains(capability))
        {
            return PresentationUiStatus::Unavailable(
                "The Student did not negotiate the configured presentation transport.",
            );
        }
        PresentationUiStatus::Ready(config.wire_transport())
    }

    pub(crate) async fn action(
        &mut self,
        action: TeacherPresentationUiAction,
        writer: &mut TeacherCommandSender,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
    ) -> io::Result<Option<PresentationUpdate>> {
        let mut payload_writer = PresentationWriter {
            binding: &self.binding,
            writer,
            session,
            sender,
        };
        match action {
            TeacherPresentationUiAction::Start => {
                if self.active.is_some() || self.worker.is_some() {
                    return Ok(None);
                }
                let status = self.availability(session.1);
                let PresentationUiStatus::Ready(transport) = status else {
                    return Ok(Some(status.into()));
                };
                let now = (self.binding.clock)();
                let snapshot = self.binding.authorization.snapshot().map_err(error)?;
                BoundGroupMediaReceiverSession::bind_client_parts(
                    session.0,
                    session.1,
                    self.binding.route.expected_student(),
                    snapshot.store(),
                    now,
                )
                .map_err(error)?;
                let mut coordinator = GroupMediaCoordinator::with_limit(1).map_err(error)?;
                coordinator
                    .register_receiver(snapshot.store(), self.binding.route.expected_student())
                    .map_err(error)?;
                let epoch = coordinator.begin_epoch().map_err(error)?;
                let mut id = [0; 12];
                SystemRandom::new().fill(&mut id).map_err(error)?;
                let binding = PresentationBindingView {
                    presentation_id: u64::from_le_bytes(id[..8].try_into().expect("fixed id")),
                    stream_id: u32::from_le_bytes(id[8..].try_into().expect("fixed id")),
                    epoch: epoch.get(),
                };
                if binding.presentation_id == 0 || binding.stream_id == 0 {
                    return Err(io::Error::other("Presentation identifier invalid"));
                }
                let request = payload_writer
                    .send(Payload::PresentationStart(PresentationStart {
                        presentation_id: binding.presentation_id,
                        stream_id: binding.stream_id.into(),
                    }))
                    .await?;
                self.active = Some(ActivePresentation {
                    control: PresentationControl::new(
                        binding,
                        session.1.control_session_id,
                        request,
                        transport,
                    ),
                    coordinator: Some(coordinator),
                    pending_key: None,
                    deadline: Instant::now() + REPLY_DEADLINE,
                    peer_ip: None,
                    failure: None,
                });
                Ok(Some(PresentationUpdate {
                    status: PresentationUiStatus::Reserving,
                    snapshot: Some(PresentationRuntimeSnapshot {
                        binding: Some(binding),
                        ..Default::default()
                    }),
                }))
            }
            TeacherPresentationUiAction::Stop { binding } => {
                let Some(active) = self
                    .active
                    .as_mut()
                    .filter(|active| active.control.can_stop(binding))
                else {
                    return Ok(None);
                };
                if let Some(worker) = &self.worker {
                    worker.cancel();
                }
                active.stop(&mut payload_writer).await?;
                Ok(Some(PresentationUiStatus::Stopping.into()))
            }
        }
    }

    pub(crate) async fn reply(
        &mut self,
        verified: &AuthenticatedTeacherControlMessage,
        writer: &mut TeacherCommandSender,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
    ) -> io::Result<Option<PresentationUpdate>> {
        let Some(active) = &mut self.active else {
            return Ok(None);
        };
        let envelope = verified.envelope();
        if envelope.request_id == 0
            && let Some(Payload::KeyframeRequest(request)) = &envelope.payload
            && request.stream_id == u64::from(active.control.binding.stream_id)
            && active.control.ready()
            && let Some(worker) = &mut self.worker
        {
            worker.request_keyframe(active.control.binding, request.last_decodable_frame_id)?;
            return Ok(None);
        }
        let Some(reply) = envelope.payload.as_ref().and_then(|payload| {
            active
                .control
                .accept(envelope.control_session_id, envelope.request_id, payload)
        }) else {
            return Ok(None);
        };
        let binding = active.control.binding;
        let mut payload_writer = PresentationWriter {
            binding: &self.binding,
            writer,
            session,
            sender,
        };
        active.deadline = Instant::now() + REPLY_DEADLINE;
        let status = match reply {
            PresentationReply::Started => {
                let now = (self.binding.clock)();
                let snapshot = self.binding.authorization.snapshot().map_err(error)?;
                let bound = BoundGroupMediaReceiverSession::bind_client_parts(
                    session.0,
                    session.1,
                    self.binding.route.expected_student(),
                    snapshot.store(),
                    now,
                )
                .map_err(error)?;
                let coordinator = active
                    .coordinator
                    .as_mut()
                    .expect("start retains coordinator");
                let request = payload_writer
                    .writer
                    .send_presentation_key(
                        self.binding.route,
                        session,
                        payload_writer.sender,
                        &self.binding.authorization,
                        |request, sequence| {
                            let (grant, pending) = bound
                                .issue_key_grant(
                                    coordinator,
                                    snapshot.store(),
                                    PresentationKeyGrantRequest::new(
                                        binding.presentation_id,
                                        binding.stream_id.into(),
                                        request,
                                        sequence,
                                    ),
                                    now,
                                )
                                .map_err(error)?;
                            active.pending_key = Some(pending);
                            Ok(grant)
                        },
                        &*self.binding.clock,
                    )
                    .await?;
                active.control.wait_for_key(request);
                PresentationUiStatus::InstallingKey
            }
            PresentationReply::KeyInstalled => {
                let now = (self.binding.clock)();
                let snapshot = self.binding.authorization.snapshot().map_err(error)?;
                let peer =
                    authenticated_peer_identity(session.0, snapshot.store(), now).map_err(error)?;
                // The owning reader already consumed the session-global sequence.
                // This second check applies the key-specific permission and
                // consumes the exact pending request against that same peer.
                let mut guard = AuthenticatedControlGuard::new(
                    peer,
                    session.1.control_session_id,
                    session.1.negotiated.version,
                    envelope.sequence.saturating_sub(1),
                );
                active
                    .pending_key
                    .take()
                    .expect("key reply has a pending grant")
                    .accept(
                        &mut guard,
                        snapshot.store(),
                        active
                            .coordinator
                            .as_mut()
                            .expect("key retains coordinator"),
                        envelope,
                        now,
                    )
                    .map_err(error)?;
                let config = self
                    .config
                    .as_ref()
                    .expect("presentation requires configuration");
                let peer_ip = session.0.remote_address().ip();
                let request = payload_writer
                    .send(Payload::StreamOffer(config.offer(binding.stream_id)?))
                    .await?;
                active.peer_ip = Some(peer_ip);
                active.control.wait_for_offer(request);
                PresentationUiStatus::PreparingReceiver
            }
            PresentationReply::TransportReady => {
                let config = self
                    .config
                    .as_ref()
                    .expect("presentation requires configuration");
                let coordinator = active
                    .coordinator
                    .take()
                    .expect("transport retains coordinator");
                let peer_ip = active.peer_ip.expect("transport follows an offer");
                if peer_ip != session.0.remote_address().ip() {
                    return Err(io::Error::other(
                        "The Student network address changed during presentation setup.",
                    ));
                }
                match PresentationWorker::start(
                    &self.binding,
                    session.0.clone(),
                    peer_ip,
                    binding,
                    config,
                    coordinator,
                ) {
                    Ok(worker) => {
                        self.worker = Some(worker);
                        PresentationUiStatus::StartingCapture
                    }
                    Err(_) => {
                        active.failure =
                            Some("Could not initialize the local presentation sender.");
                        active.stop(&mut payload_writer).await?;
                        PresentationUiStatus::Stopping
                    }
                }
            }
            PresentationReply::Stopped => {
                let deadline = active.deadline;
                let status = active.failure.map_or_else(
                    || self.availability(session.1),
                    PresentationUiStatus::Failed,
                );
                self.active = None;
                if self.worker.is_some() {
                    self.stopped = Some(SenderRetirement { status, deadline });
                    return Ok(None);
                }
                return Ok(Some(PresentationUpdate::idle(status)));
            }
            PresentationReply::StartRejected => {
                self.active = None;
                return Ok(Some(PresentationUpdate::idle(
                    PresentationUiStatus::Failed(
                        "The Student Service refused to reserve the presentation.",
                    ),
                )));
            }
            PresentationReply::OfferRejected => {
                active.failure =
                    Some("The Student Worker could not start the configured receiver.");
                active.stop(&mut payload_writer).await?;
                PresentationUiStatus::Stopping
            }
            PresentationReply::StopRejected => {
                return Err(io::Error::other(
                    "The Student Service rejected presentation Stop.",
                ));
            }
        };
        Ok(Some(status.into()))
    }

    pub(crate) async fn poll(
        &mut self,
        writer: &mut TeacherCommandSender,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
    ) -> io::Result<Option<PresentationUpdate>> {
        if self
            .active
            .as_ref()
            .is_some_and(|p| p.control.waiting() && Instant::now() >= p.deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out awaiting the exact presentation response",
            ));
        }
        let Some(worker) = &self.worker else {
            return Ok(None);
        };
        if worker.thread.is_finished() {
            let worker = self.worker.take().expect("worker was present");
            let expected = worker.cancelled.load(Ordering::Acquire);
            let outcome = worker
                .thread
                .join()
                .map_err(|_| io::Error::other("Presentation sender panicked"))?;
            if expected {
                return Ok(self
                    .stopped
                    .take()
                    .map(|stop| PresentationUpdate::idle(stop.status)));
            }
            let Err(cause) = outcome else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Presentation lost its authenticated route or authorization.",
                ));
            };
            eprintln!("ClassMesh local presentation sender: {cause}");
            let Some(active) = self.active.as_mut() else {
                return Err(cause);
            };
            active.failure =
                Some("The Teacher capture, encoder or sender failed. See the local diagnostics.");
            active
                .stop(&mut PresentationWriter {
                    binding: &self.binding,
                    writer,
                    session,
                    sender,
                })
                .await?;
            return Ok(Some(PresentationUiStatus::Stopping.into()));
        }
        if let Some(stop) = &self.stopped {
            stop.check_deadline(Instant::now())?;
        }
        // Buffered observations from a retired worker must never restart UI.
        if worker.cancelled.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(worker.snapshots.try_recv().ok())
    }
}

impl ActivePresentation {
    async fn stop(&mut self, writer: &mut PresentationWriter<'_>) -> io::Result<()> {
        self.coordinator = None;
        self.pending_key = None;
        let request = writer
            .send(Payload::PresentationStop(PresentationStop {
                presentation_id: self.control.binding.presentation_id,
            }))
            .await?;
        self.control.wait_for_stop(request);
        self.deadline = Instant::now() + REPLY_DEADLINE;
        Ok(())
    }
}

impl Drop for InstalledPresentation {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.cancel();
        }
    }
}

struct PresentationWriter<'a> {
    binding: &'a PresentationRoute,
    writer: &'a mut TeacherCommandSender,
    session: (&'a Connection, &'a EstablishedControlSession),
    sender: &'a mut ControlSendHalf,
}

impl PresentationWriter<'_> {
    async fn send(&mut self, payload: Payload) -> io::Result<u64> {
        self.writer
            .send_presentation(
                self.binding.route,
                self.session,
                self.sender,
                &self.binding.authorization,
                payload,
                &*self.binding.clock,
            )
            .await
            .map_err(error)
    }
}

struct PresentationWorker {
    cancelled: Arc<AtomicBool>,
    snapshots: Receiver<PresentationUpdate>,
    keyframes: SyncSender<PresentationKeyframeRequest>,
    recovery: PresentationRecoveryCoordinator,
    started: Instant,
    thread: JoinHandle<io::Result<()>>,
}

impl PresentationWorker {
    fn start(
        route: &PresentationRoute,
        connection: Connection,
        peer_ip: IpAddr,
        binding: PresentationBindingView,
        config: &PreparedPresentation,
        mut coordinator: GroupMediaCoordinator,
    ) -> io::Result<Self> {
        let receiver = route.route.expected_student();
        let authorization = Arc::clone(&route.authorization);
        let clock = Arc::clone(&route.clock);
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let (events, snapshots) = sync_channel(1);
        let (keyframes, requests) = sync_channel(1);
        let recovery =
            PresentationRecoveryCoordinator::for_stream(binding.stream_id).map_err(error)?;
        let epoch = coordinator
            .active_epoch()
            .ok_or_else(|| io::Error::other("Missing active presentation epoch"))?;
        let target =
            PresentationTarget::try_from(stream_profile_from_wire(&config.profile).map_err(error)?)
                .map_err(error)?;
        let config = *config;
        let period = Duration::from_secs(1) / target.fps;
        let thread = thread::Builder::new()
            .name("classmesh-presentation".into())
            .spawn(move || {
                let is_current = || {
                    !stop.load(Ordering::Acquire)
                        && connection.close_reason().is_none()
                        && connection.remote_address().ip() == peer_ip
                        && verify_current_student(receiver, &connection, &authorization, clock())
                            .is_ok()
                        && authorization.snapshot().is_ok_and(|snapshot| {
                            snapshot
                                .store()
                                .authorize(receiver, Permission::ReceivePresentation)
                        })
                };
                if !is_current() {
                    return Ok(());
                }
                let displays = enumerate_displays().map_err(error)?;
                let display = displays
                    .iter()
                    .find(|display| display.primary)
                    .ok_or_else(|| io::Error::other("No primary display available"))?;
                let mut capture = RecoveringCapture::new(
                    display.id,
                    DxgiCaptureFactory,
                    RecoveryPolicy::default(),
                );
                capture.start().map_err(error)?;
                let sender = config.bind_sender(peer_ip, binding, epoch, target)?;
                let mut lifecycle = TeacherVideoEngineLifecycle::default();
                apply_presentation_ui_action(
                    TeacherPresentationUiAction::Start,
                    &mut lifecycle,
                    Some((sender, QUEUE_CAPACITY)),
                )
                .map_err(error)?;
                let mut publish = Instant::now();
                let mut retry_at = publish;
                let mut is_sending = false;
                while is_current() {
                    let next_tick = Instant::now() + period;
                    if let Ok(request) = requests.try_recv() {
                        lifecycle
                            .apply(TeacherVideoEngineDirective::Keyframe(request))
                            .map_err(error)?;
                    }
                    if Instant::now() < retry_at {
                        thread::sleep(period);
                        continue;
                    }
                    let snapshot = authorization.snapshot().map_err(error)?;
                    match capture.poll(0) {
                        CaptureStep::Frame { meta, frame } => {
                            let Some(delivery) = lifecycle
                                .process_frame_if_current(
                                    meta,
                                    frame,
                                    &mut coordinator,
                                    snapshot.store(),
                                    is_current,
                                )
                                .map_err(error)?
                            else {
                                break;
                            };
                            is_sending |= delivery.sent.is_some()
                                || delivery.unicast_deliveries.iter().any(|delivery| {
                                    matches!(delivery, ProtectedUnicastFanoutDelivery::Sent { .. })
                                });
                            if let Some(ProtectedUnicastFanoutDelivery::Failed {
                                error: cause,
                                ..
                            }) = delivery.unicast_deliveries.into_iter().find(|delivery| {
                                matches!(delivery, ProtectedUnicastFanoutDelivery::Failed { .. })
                            }) {
                                return Err(error(cause));
                            }
                        }
                        CaptureStep::NoFrame => {}
                        CaptureStep::RetryAfter { delay_ms, .. } => {
                            lifecycle.reset_capture_pipeline();
                            is_sending = false;
                            let _ = events.try_send(PresentationUiStatus::RecoveringCapture.into());
                            retry_at = Instant::now() + Duration::from_millis(delay_ms);
                        }
                        CaptureStep::Suspended(reason) | CaptureStep::Failed(reason) => {
                            return Err(error(reason));
                        }
                    }
                    if Instant::now() >= publish {
                        let _ = events.try_send(PresentationUpdate {
                            status: if is_sending {
                                PresentationUiStatus::Sending
                            } else {
                                PresentationUiStatus::StartingCapture
                            },
                            snapshot: Some(lifecycle.presentation_snapshot()),
                        });
                        publish = Instant::now() + Duration::from_millis(500);
                    }
                    thread::sleep(next_tick.saturating_duration_since(Instant::now()));
                }
                apply_presentation_ui_action(
                    TeacherPresentationUiAction::Stop { binding },
                    &mut lifecycle,
                    None,
                )
                .map_err(error)?;
                Ok(())
            })?;
        Ok(Self {
            cancelled,
            snapshots,
            keyframes,
            recovery,
            started: Instant::now(),
            thread,
        })
    }

    fn request_keyframe(
        &mut self,
        binding: PresentationBindingView,
        after_frame_id: u64,
    ) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        let now_us = self
            .started
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);
        let feedback = classmesh_protocol::feedback::FeedbackMessage::RequestKeyframe {
            stream_id: binding.stream_id,
            after_frame_id,
        };
        if let Some(request) = self
            .recovery
            .observe_and_plan(binding.presentation_id, now_us, &feedback)
            .map_err(error)?
            .keyframe_request
        {
            let _ = self.keyframes.try_send(request);
        }
        Ok(())
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

pub(crate) fn error(e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PresentationPolicy {
        serde_json::from_str(
            r#"{
            "interface":"192.0.2.10","group":"239.11.0.5","port":57000,
            "width":1280,"height":720,"fps":30,"bitrate_kbps":3000
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn local_sender_retirement_is_bounded_even_after_remote_stop() {
        let since = Instant::now();
        let stop = SenderRetirement {
            deadline: since + REPLY_DEADLINE,
            status: PresentationUiStatus::Ready(MediaTransport::UdpUnicast),
        };
        assert!(stop.check_deadline(since).is_ok());
        assert_eq!(
            stop.check_deadline(since + REPLY_DEADLINE)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn unicast_policy_selects_only_unicast_and_uses_a_port_only_offer() {
        let raw = r#"{
            "transport":"unicast","port":57000,
            "width":1280,"height":720,"fps":30,"bitrate_kbps":3000
        }"#;
        let policy = serde_json::from_str::<PresentationPolicy>(raw)
            .unwrap()
            .prepare()
            .unwrap();
        let prepared = policy.prepare_egress().unwrap();
        assert_eq!(prepared.wire_transport(), MediaTransport::UdpUnicast);
        assert_eq!(prepared.capability(), Capability::UdpUnicast);
        let offer = prepared.offer(9).unwrap();
        assert_eq!(offer.transport_parameters, [1, 0xde, 0xa8]);
        assert!(
            serde_json::from_str::<PresentationPolicy>(
                &raw.replace(r#""port":57000"#, r#""port":57000,"group":"239.11.0.5""#,)
            )
            .unwrap()
            .prepare()
            .is_err()
        );
    }

    #[test]
    fn installed_presentation_requires_bounded_profile_and_explicit_local_multicast() {
        assert!(policy().prepare().is_ok());
        for disabled in [
            PresentationPolicy {
                interface: Some(Ipv4Addr::UNSPECIFIED),
                ..policy()
            },
            PresentationPolicy {
                group: Some(Ipv4Addr::new(224, 0, 0, 1)),
                ..policy()
            },
            PresentationPolicy {
                port: 0,
                ..policy()
            },
            PresentationPolicy {
                width: 1279,
                ..policy()
            },
        ] {
            assert!(disabled.prepare().is_err());
        }
    }
}
