//! Opt-in presentation on the installed Teacher's enrolled control session.
use std::io;
use std::net::Ipv4Addr;
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
    stream::{stream_profile_from_wire, udp_multicast_transport_parameters},
    teacher_playback_receive::AuthenticatedTeacherControlMessage,
};
use classmesh_core::{keyframe::PresentationKeyframeRequest, recovery::RecoveryPolicy};
use classmesh_network::{
    multicast::{MulticastMembership, MulticastProbeOutcome},
    multicast_sender::ProtectedMulticastSenderConfig,
    runtime_multicast_probe::probe_local_multicast_interface,
};
use classmesh_protocol::{
    Capability,
    control_wire::{
        MediaTransport, PresentationStart, PresentationStop, StreamKind, StreamOffer, VideoCodec,
        VideoProfile, control_envelope::Payload,
    },
};
use classmesh_security::{Permission, group_media_coordinator::GroupMediaCoordinator};
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
    presentation_view::{PresentationBindingView, PresentationRuntimeSnapshot},
    ui_shell::{TeacherPresentationUiAction, apply_presentation_ui_action},
};

const REPLY_DEADLINE: Duration = Duration::from_secs(10);
const QUEUE_CAPACITY: usize = 2;
pub(crate) type TeacherClock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresentationPolicy {
    interface: Ipv4Addr,
    group: Ipv4Addr,
    port: u16,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_kbps: u32,
}

pub(crate) struct PreparedPresentation {
    membership: MulticastMembership,
    port: u16,
    profile: VideoProfile,
}

impl PresentationPolicy {
    pub(crate) fn prepare(self) -> io::Result<PreparedPresentation> {
        let membership = MulticastMembership::new(self.group, self.interface).map_err(error)?;
        udp_multicast_transport_parameters(self.group, self.port).map_err(error)?;
        let profile = VideoProfile {
            width: self.width,
            height: self.height,
            fps: self.fps,
            bitrate_kbps: self.bitrate_kbps,
            codec: VideoCodec::H264 as i32,
        };
        stream_profile_from_wire(&profile).map_err(error)?;
        Ok(PreparedPresentation {
            membership,
            port: self.port,
            profile,
        })
    }
}

impl PreparedPresentation {
    pub(crate) fn with_local_probe(self) -> Option<(Self, MulticastProbeOutcome)> {
        let outcome = probe_local_multicast_interface(self.membership.interface()).ok()?;
        outcome
            .can_advertise_udp_multicast()
            .then_some((self, outcome))
    }
}

pub(crate) struct PresentationRoute {
    pub(crate) route: TeacherControlRoute,
    pub(crate) authorization: Arc<LiveAuthorizationStore>,
    pub(crate) clock: TeacherClock,
}

pub(crate) struct InstalledPresentation {
    config: Option<(PreparedPresentation, MulticastProbeOutcome)>,
    pub(crate) binding: PresentationRoute,
    active: Option<ActivePresentation>,
    worker: Option<PresentationWorker>,
}

struct ActivePresentation {
    control: PresentationControl,
    coordinator: Option<GroupMediaCoordinator>,
    pending_key: Option<PendingPresentationKeyAck>,
    deadline: Instant,
}

impl InstalledPresentation {
    pub(crate) fn new(
        config: Option<(PreparedPresentation, MulticastProbeOutcome)>,
        binding: PresentationRoute,
    ) -> Self {
        Self {
            config,
            binding,
            active: None,
            worker: None,
        }
    }

    pub(crate) async fn action(
        &mut self,
        action: TeacherPresentationUiAction,
        writer: &mut TeacherCommandSender,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
    ) -> io::Result<Option<PresentationRuntimeSnapshot>> {
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
                if self.config.is_none()
                    || ![
                        Capability::TeacherPresentation,
                        Capability::SframeGroupMedia,
                        Capability::UdpMulticast,
                    ]
                    .iter()
                    .all(|capability| session.1.negotiated.capabilities.contains(capability))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Protected multicast presentation is unavailable for this session",
                    ));
                }
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
                    control: PresentationControl::new(binding, request),
                    coordinator: Some(coordinator),
                    pending_key: None,
                    deadline: Instant::now() + REPLY_DEADLINE,
                });
                Ok(Some(PresentationRuntimeSnapshot {
                    binding: Some(binding),
                    ..Default::default()
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
                active.coordinator = None;
                active.pending_key = None;
                let request = payload_writer
                    .send(Payload::PresentationStop(PresentationStop {
                        presentation_id: binding.presentation_id,
                    }))
                    .await?;
                active.control.wait_for_stop(request);
                active.deadline = Instant::now() + REPLY_DEADLINE;
                Ok(None)
            }
        }
    }

    pub(crate) async fn reply(
        &mut self,
        verified: &AuthenticatedTeacherControlMessage,
        writer: &mut TeacherCommandSender,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
    ) -> io::Result<Option<PresentationRuntimeSnapshot>> {
        let Some(active) = &mut self.active else {
            return Ok(None);
        };
        let envelope = verified.envelope();
        if envelope.request_id == 0
            && let Some(Payload::KeyframeRequest(request)) = &envelope.payload
            && request.stream_id == u64::from(active.control.binding.stream_id)
            && !active.control.waiting()
            && let Some(worker) = &mut self.worker
        {
            worker.request_keyframe(active.control.binding, request.last_decodable_frame_id)?;
            return Ok(None);
        }
        let Some(reply) = envelope
            .payload
            .as_ref()
            .and_then(|payload| active.control.accept(envelope.request_id, payload))
        else {
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
        match reply {
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
                let config = &self
                    .config
                    .as_ref()
                    .expect("presentation requires configuration")
                    .0;
                let request = payload_writer
                    .send(Payload::StreamOffer(StreamOffer {
                        stream_id: binding.stream_id.into(),
                        kind: StreamKind::TeacherPresentation as i32,
                        transport: MediaTransport::UdpMulticast as i32,
                        profile: Some(config.profile),
                        transport_parameters: udp_multicast_transport_parameters(
                            config.membership.group(),
                            config.port,
                        )
                        .map_err(error)?
                        .to_vec(),
                    }))
                    .await?;
                active.control.wait_for_offer(request);
            }
            PresentationReply::TransportReady => {
                let (config, probe) = self
                    .config
                    .as_ref()
                    .expect("presentation requires configuration");
                let coordinator = active
                    .coordinator
                    .take()
                    .expect("transport retains coordinator");
                self.worker = Some(PresentationWorker::start(
                    &self.binding,
                    session.0.clone(),
                    binding,
                    config,
                    *probe,
                    coordinator,
                )?);
            }
            PresentationReply::Stopped => {
                self.active = None;
                return Ok(Some(PresentationRuntimeSnapshot::default()));
            }
            PresentationReply::Rejected => {
                // Retiring the connection releases any remote ownership or
                // Worker key, including a rejected Stop or transport offer.
                return Err(io::Error::other(
                    "Student Service rejected the presentation",
                ));
            }
        }
        Ok(None)
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<PresentationRuntimeSnapshot>> {
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
            worker
                .thread
                .join()
                .map_err(|_| io::Error::other("Presentation worker panicked"))??;
            if !expected {
                return Err(io::Error::other("Presentation worker retired"));
            }
            return Ok(None);
        }
        // Buffered observations from a retired worker must never restart UI.
        if worker.cancelled.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(worker.snapshots.try_recv().ok())
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
    snapshots: Receiver<PresentationRuntimeSnapshot>,
    keyframes: SyncSender<PresentationKeyframeRequest>,
    recovery: PresentationRecoveryCoordinator,
    started: Instant,
    thread: JoinHandle<io::Result<()>>,
}

impl PresentationWorker {
    fn start(
        route: &PresentationRoute,
        connection: Connection,
        binding: PresentationBindingView,
        config: &PreparedPresentation,
        probe: MulticastProbeOutcome,
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
        let sender_config = ProtectedMulticastSenderConfig::new(
            config.membership,
            config.port,
            binding.presentation_id,
            binding.stream_id,
            coordinator
                .active_epoch()
                .ok_or_else(|| io::Error::other("Missing active presentation epoch"))?,
            probe,
        )
        .map_err(error)?;
        let target =
            PresentationTarget::try_from(stream_profile_from_wire(&config.profile).map_err(error)?)
                .map_err(error)?;
        let period = Duration::from_secs(1) / target.fps;
        let thread = thread::Builder::new()
            .name("classmesh-presentation".into())
            .spawn(move || {
                let is_current = || {
                    !stop.load(Ordering::Acquire)
                        && connection.close_reason().is_none()
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
                let sender =
                    PresentationMulticastSendRuntime::bind(target, sender_config, SinkId(1))
                        .map_err(error)?;
                let mut lifecycle = TeacherVideoEngineLifecycle::default();
                apply_presentation_ui_action(
                    TeacherPresentationUiAction::Start,
                    &mut lifecycle,
                    Some((sender, QUEUE_CAPACITY)),
                )
                .map_err(error)?;
                let mut publish = Instant::now();
                let mut retry_at = publish;
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
                            lifecycle
                                .process_frame_if_current(
                                    meta,
                                    frame,
                                    &mut coordinator,
                                    snapshot.store(),
                                    is_current,
                                )
                                .map_err(error)?;
                        }
                        CaptureStep::NoFrame => {}
                        CaptureStep::RetryAfter { delay_ms, .. } => {
                            lifecycle.reset_capture_pipeline();
                            retry_at = Instant::now() + Duration::from_millis(delay_ms);
                        }
                        CaptureStep::Suspended(reason) | CaptureStep::Failed(reason) => {
                            return Err(error(reason));
                        }
                    }
                    if Instant::now() >= publish {
                        let _ = events.try_send(lifecycle.presentation_snapshot());
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
    fn installed_presentation_requires_bounded_profile_and_explicit_local_multicast() {
        assert!(policy().prepare().is_ok());
        for disabled in [
            PresentationPolicy {
                interface: Ipv4Addr::UNSPECIFIED,
                ..policy()
            },
            PresentationPolicy {
                group: Ipv4Addr::new(224, 0, 0, 1),
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
