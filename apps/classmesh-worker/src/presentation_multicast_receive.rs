use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use classmesh_network::multicast::{
    MulticastContractError, MulticastMembership, MulticastProbeOutcome,
};
use classmesh_network::multicast_diagnostics::{DeliveryStage, DeliveryTrace};
use classmesh_network::multicast_receiver::{
    ProtectedMulticastFrameReceiver, ProtectedMulticastReceiveError,
    ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiverConfig,
};
use classmesh_windows_runtime::ipc::ServicePresentationMulticastStart;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

// Candidate frames are assembled before SFrame authentication. At most eight
// full 8-MiB ciphertext candidates may queue; the Worker drains eight events
// per media-loop iteration and drops overflow rather than retaining 512 MiB.
const PRESENTATION_MULTICAST_EVENT_CAPACITY: usize = 8;
const PRESENTATION_MULTICAST_START_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum WorkerPresentationMulticastStartError {
    Membership(MulticastContractError),
    Receiver(ProtectedMulticastReceiveError),
    ThreadSpawn(std::io::Error),
    StartupTimeout,
    StartupChannelClosed,
}

impl Display for WorkerPresentationMulticastStartError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Membership(error) => write!(formatter, "invalid multicast membership: {error:?}"),
            Self::Receiver(error) => {
                write!(formatter, "multicast receiver startup failed: {error}")
            }
            Self::ThreadSpawn(error) => {
                write!(formatter, "multicast receive thread failed: {error}")
            }
            Self::StartupTimeout => formatter.write_str("multicast receiver startup timed out"),
            Self::StartupChannelClosed => {
                formatter.write_str("multicast receiver startup channel closed")
            }
        }
    }
}

impl Error for WorkerPresentationMulticastStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Receiver(error) => Some(error),
            Self::ThreadSpawn(error) => Some(error),
            Self::Membership(_) | Self::StartupTimeout | Self::StartupChannelClosed => None,
        }
    }
}

impl From<MulticastContractError> for WorkerPresentationMulticastStartError {
    fn from(value: MulticastContractError) -> Self {
        Self::Membership(value)
    }
}

impl From<ProtectedMulticastReceiveError> for WorkerPresentationMulticastStartError {
    fn from(value: ProtectedMulticastReceiveError) -> Self {
        Self::Receiver(value)
    }
}

enum StartupOutcome {
    Started,
    Rejected(ProtectedMulticastReceiveError),
}

pub struct WorkerPresentationMulticastRuntime {
    binding: ServicePresentationMulticastStart,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
    receive_rx: Receiver<ProtectedMulticastReceiveOutcome>,
    thread: Option<JoinHandle<Option<DeliveryTrace>>>,
}

impl std::fmt::Debug for WorkerPresentationMulticastRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerPresentationMulticastRuntime")
            .field("binding", &self.binding)
            .field("failed", &self.failed())
            .field("dropped_events", &self.dropped_events())
            .finish_non_exhaustive()
    }
}

impl WorkerPresentationMulticastRuntime {
    pub fn start(
        binding: ServicePresentationMulticastStart,
    ) -> Result<Self, WorkerPresentationMulticastStartError> {
        Self::start_inner(binding, None)
    }

    /// Starts the same receiver with a bounded metadata trace on its socket thread.
    pub fn start_diagnostics(
        binding: ServicePresentationMulticastStart,
    ) -> Result<Self, WorkerPresentationMulticastStartError> {
        Self::start_inner(binding, Some(DeliveryTrace::new()))
    }

    fn start_inner(
        binding: ServicePresentationMulticastStart,
        mut trace: Option<DeliveryTrace>,
    ) -> Result<Self, WorkerPresentationMulticastStartError> {
        let config = receiver_config(binding)?;
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (receive_tx, receive_rx) = mpsc::sync_channel(PRESENTATION_MULTICAST_EVENT_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_failed = Arc::clone(&failed);
        let thread_dropped_events = Arc::clone(&dropped_events);

        let thread = thread::Builder::new()
            .name("classmesh-presentation-multicast".to_owned())
            .spawn(move || {
                let mut receiver = match ProtectedMulticastFrameReceiver::bind(config) {
                    Ok(receiver) => receiver,
                    Err(error) => {
                        let _ = startup_tx.send(StartupOutcome::Rejected(error));
                        return trace;
                    }
                };
                if startup_tx.send(StartupOutcome::Started).is_err() {
                    return trace;
                }

                let clock = Instant::now();
                while !thread_stop.load(Ordering::Acquire) {
                    // Sample after recv_from or timeout so the socket wait cannot age a frame.
                    let outcome = receiver.receive_once_observed(
                        || u64::try_from(clock.elapsed().as_micros()).unwrap_or(u64::MAX),
                        trace.as_mut(),
                    );
                    match outcome {
                        Ok(outcome) => {
                            if !publish_outcome(
                                &receive_tx,
                                &thread_dropped_events,
                                trace.as_mut(),
                                outcome,
                            ) {
                                break;
                            }
                        }
                        Err(_) => {
                            thread_failed.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
                trace
            })
            .map_err(WorkerPresentationMulticastStartError::ThreadSpawn)?;

        match startup_rx.recv_timeout(PRESENTATION_MULTICAST_START_TIMEOUT) {
            Ok(StartupOutcome::Started) => Ok(Self {
                binding,
                stop,
                failed,
                dropped_events,
                receive_rx,
                thread: Some(thread),
            }),
            Ok(StartupOutcome::Rejected(error)) => {
                let _ = thread.join();
                Err(error.into())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                stop.store(true, Ordering::Release);
                let _ = thread.join();
                Err(WorkerPresentationMulticastStartError::StartupTimeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Release);
                let _ = thread.join();
                Err(WorkerPresentationMulticastStartError::StartupChannelClosed)
            }
        }
    }

    #[must_use]
    pub const fn binding(&self) -> ServicePresentationMulticastStart {
        self.binding
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn try_receive(&self) -> Option<ProtectedMulticastReceiveOutcome> {
        self.receive_rx.try_recv().ok()
    }

    #[must_use]
    pub fn same_media_configuration(&self, candidate: ServicePresentationMulticastStart) -> bool {
        same_media_configuration(self.binding, candidate)
    }

    pub fn adopt_retry(&mut self, candidate: ServicePresentationMulticastStart) -> bool {
        if !self.same_media_configuration(candidate) {
            return false;
        }
        self.binding.request_id = candidate.request_id;
        true
    }

    #[must_use]
    pub fn matches_key_binding(&self, key: PresentationKeyInstallBinding) -> bool {
        start_matches_key_binding(self.binding, key)
    }

    /// Stops the producer and returns a consistent report after its final enqueue.
    /// Already queued outcomes can still be drained with `try_receive`.
    pub fn finish_diagnostics(&mut self) -> Option<DeliveryTrace> {
        self.stop.store(true, Ordering::Release);
        self.thread.take()?.join().ok().flatten()
    }
}

impl Drop for WorkerPresentationMulticastRuntime {
    fn drop(&mut self) {
        let _ = self.finish_diagnostics();
    }
}

fn publish_outcome(
    tx: &SyncSender<ProtectedMulticastReceiveOutcome>,
    dropped_events: &AtomicU64,
    mut trace: Option<&mut DeliveryTrace>,
    outcome: ProtectedMulticastReceiveOutcome,
) -> bool {
    if let ProtectedMulticastReceiveOutcome::Events(batch) = &outcome {
        if batch.is_empty() {
            return true;
        }
        if let Some(trace) = trace.as_deref_mut() {
            for frame in &batch.frames {
                trace.record(DeliveryStage::FrameAssembled, Some(frame.frame_id()), None);
            }
            for _ in 0..batch.dropped_stale_frames {
                trace.record(DeliveryStage::StaleFrame, None, None);
            }
            for _ in 0..batch.dropped_invalid_frames {
                trace.record(DeliveryStage::InvalidFrame, None, None);
            }
        }
    }

    match tx.try_send(outcome) {
        Ok(()) => {
            if let Some(trace) = trace {
                trace.record(DeliveryStage::Queued, None, None);
            }
            true
        }
        Err(error) => {
            let (stage, frame_stage, dropped) = match error {
                TrySendError::Full(outcome) => {
                    dropped_events.fetch_add(1, Ordering::Relaxed);
                    (
                        DeliveryStage::QueueFull,
                        DeliveryStage::FrameQueueFull,
                        outcome,
                    )
                }
                TrySendError::Disconnected(outcome) => (
                    DeliveryStage::QueueDisconnected,
                    DeliveryStage::FrameQueueDisconnected,
                    outcome,
                ),
            };
            if let Some(trace) = trace {
                trace.record(stage, None, None);
                if let ProtectedMulticastReceiveOutcome::Events(batch) = dropped {
                    for frame in &batch.frames {
                        trace.record(frame_stage, Some(frame.frame_id()), None);
                    }
                }
            }
            stage == DeliveryStage::QueueFull
        }
    }
}

pub fn receiver_config(
    start: ServicePresentationMulticastStart,
) -> Result<ProtectedMulticastReceiverConfig, WorkerPresentationMulticastStartError> {
    let membership = MulticastMembership::new(start.group, start.interface)?;
    ProtectedMulticastReceiverConfig::new(
        membership,
        start.port,
        start.teacher_source,
        start.stream_id,
        MulticastProbeOutcome::Available,
    )
    .map_err(Into::into)
}

#[must_use]
pub fn same_media_configuration(
    current: ServicePresentationMulticastStart,
    candidate: ServicePresentationMulticastStart,
) -> bool {
    current.control_session_id == candidate.control_session_id
        && current.presentation_id == candidate.presentation_id
        && current.stream_id == candidate.stream_id
        && current.width == candidate.width
        && current.height == candidate.height
        && current.fps == candidate.fps
        && current.bitrate_kbps == candidate.bitrate_kbps
        && current.group == candidate.group
        && current.port == candidate.port
        && current.interface == candidate.interface
        && current.teacher_source == candidate.teacher_source
}

#[must_use]
pub fn start_matches_key_binding(
    start: ServicePresentationMulticastStart,
    key: PresentationKeyInstallBinding,
) -> bool {
    start.control_session_id == key.control_session_id
        && start.presentation_id == key.presentation_id
        && start.stream_id == key.stream_id
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use classmesh_network::multicast_receiver::MulticastPacketDropReason;

    use super::*;

    #[test]
    fn unauthenticated_ciphertext_queue_stays_under_ninety_six_mib() {
        // Each queued result can hold a complete, but not yet authenticated,
        // SFrame ciphertext. Capacity must be bounded by bytes, not just events.
        let max_sealed = classmesh_security::group_media::MAX_GROUP_MEDIA_SEALED_BYTES;
        assert!(
            PRESENTATION_MULTICAST_EVENT_CAPACITY * max_sealed <= 96 * 1024 * 1024,
            "unverified UDP candidates can retain too much memory"
        );
    }

    fn start(request_id: u64) -> ServicePresentationMulticastStart {
        ServicePresentationMulticastStart {
            control_session_id: 77,
            request_id,
            presentation_id: 55,
            stream_id: 9,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 6_000,
            group: Ipv4Addr::new(239, 10, 20, 30),
            port: 49_000,
            interface: Ipv4Addr::new(192, 0, 2, 10),
            teacher_source: Ipv4Addr::new(192, 0, 2, 44),
        }
    }

    #[test]
    fn receiver_config_preserves_exact_local_transport_binding() {
        let start = start(44);
        let config = receiver_config(start).expect("valid receiver config");
        assert_eq!(config.membership().group(), start.group);
        assert_eq!(config.membership().interface(), start.interface);
        assert_eq!(config.expected_sender(), start.teacher_source);
        assert_eq!(config.stream_id(), start.stream_id);
        assert_eq!(
            config.local_bind(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, start.port))
        );
    }

    #[test]
    fn an_occupied_port_cannot_report_multicast_startup_ready() {
        use classmesh_network::udp::DatagramError;

        let reservation = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let start = ServicePresentationMulticastStart {
            port: reservation.local_addr().unwrap().port(),
            ..start(44)
        };
        let result = WorkerPresentationMulticastRuntime::start(start);
        assert!(matches!(
            result,
            Err(WorkerPresentationMulticastStartError::Receiver(
                ProtectedMulticastReceiveError::Datagram(DatagramError::Io(error))
            )) if error.kind() == std::io::ErrorKind::AddrInUse
        ));
    }

    #[test]
    fn retry_request_id_does_not_change_media_configuration() {
        assert!(same_media_configuration(start(44), start(45)));
    }

    #[test]
    fn changed_media_binding_requires_runtime_replacement() {
        let current = start(44);
        for candidate in [
            ServicePresentationMulticastStart {
                presentation_id: 56,
                ..current
            },
            ServicePresentationMulticastStart {
                stream_id: 10,
                ..current
            },
            ServicePresentationMulticastStart {
                group: Ipv4Addr::new(239, 10, 20, 31),
                ..current
            },
            ServicePresentationMulticastStart {
                interface: Ipv4Addr::new(192, 0, 2, 11),
                ..current
            },
            ServicePresentationMulticastStart {
                teacher_source: Ipv4Addr::new(192, 0, 2, 45),
                ..current
            },
        ] {
            assert!(!same_media_configuration(current, candidate));
        }
    }

    #[test]
    fn key_binding_requires_exact_control_presentation_and_stream() {
        let start = start(44);
        let exact = PresentationKeyInstallBinding {
            control_session_id: start.control_session_id,
            request_id: 99,
            presentation_id: start.presentation_id,
            stream_id: start.stream_id,
            epoch: 3,
        };
        assert!(start_matches_key_binding(start, exact));

        for key in [
            PresentationKeyInstallBinding {
                control_session_id: exact.control_session_id + 1,
                ..exact
            },
            PresentationKeyInstallBinding {
                presentation_id: exact.presentation_id + 1,
                ..exact
            },
            PresentationKeyInstallBinding {
                stream_id: exact.stream_id + 1,
                ..exact
            },
        ] {
            assert!(!start_matches_key_binding(start, key));
        }
    }

    #[test]
    fn full_worker_queue_counts_a_drop_without_losing_socket_accounting() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let dropped = AtomicU64::new(0);
        let mut trace = DeliveryTrace::new();
        for _ in 0..2 {
            trace.record(DeliveryStage::Malformed, None, None);
            assert!(publish_outcome(
                &tx,
                &dropped,
                Some(&mut trace),
                ProtectedMulticastReceiveOutcome::Dropped(
                    MulticastPacketDropReason::MalformedDatagram
                ),
            ));
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(trace.count(DeliveryStage::Malformed), 2);
        assert_eq!(trace.count(DeliveryStage::Queued), 1);
        assert_eq!(trace.count(DeliveryStage::QueueFull), 1);
    }

    #[test]
    fn queue_pressure_preserves_the_id_of_the_discarded_candidate() {
        use classmesh_network::multicast_receiver::ProtectedMulticastReceiveState;
        use classmesh_network::{PacketizeMeta, packetize_frame};

        let binding = start(1);
        let mut state =
            ProtectedMulticastReceiveState::new(receiver_config(binding).unwrap()).unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let dropped = AtomicU64::new(0);
        let mut trace = DeliveryTrace::new();
        for frame_id in 1..=2 {
            let packets = packetize_frame(
                &[0x5a; 32],
                PacketizeMeta {
                    protocol_major: 0,
                    protocol_minor: 4,
                    stream_id: binding.stream_id,
                    frame_id,
                    first_sequence: frame_id as u32,
                    timestamp_us: frame_id,
                    keyframe: true,
                },
            )
            .unwrap();
            let outcome = state.push_packet(
                frame_id,
                &packets[0],
                (binding.teacher_source, 12345).into(),
            );
            assert!(publish_outcome(&tx, &dropped, Some(&mut trace), outcome));
        }
        let ProtectedMulticastReceiveOutcome::Events(batch) = rx.try_recv().unwrap() else {
            panic!("expected a completed ciphertext candidate");
        };
        assert_eq!(batch.frames[0].frame_id(), 1);
        assert_eq!(state.stats().assembled_ciphertext_frames, 2);
        assert_eq!(trace.count(DeliveryStage::FrameAssembled), 2);
        assert_eq!(trace.count(DeliveryStage::FrameQueueFull), 1);
        assert_eq!(
            trace
                .events()
                .iter()
                .find(|event| event.stage == DeliveryStage::FrameQueueFull)
                .unwrap()
                .frame_id,
            Some(2)
        );
    }
}
