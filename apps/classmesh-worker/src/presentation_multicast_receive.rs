use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use classmesh_network::multicast::{
    MulticastContractError, MulticastMembership, MulticastProbeOutcome,
};
use classmesh_network::multicast_receiver::{
    ProtectedMulticastFrameReceiver, ProtectedMulticastReceiveError,
    ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiverConfig,
};
use classmesh_windows_runtime::ipc::ServicePresentationMulticastStart;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

const PRESENTATION_MULTICAST_EVENT_CAPACITY: usize = 64;
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
    thread: Option<JoinHandle<()>>,
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
                        return;
                    }
                };
                if startup_tx.send(StartupOutcome::Started).is_err() {
                    return;
                }

                let clock = Instant::now();
                while !thread_stop.load(Ordering::Acquire) {
                    let now_us = u64::try_from(clock.elapsed().as_micros()).unwrap_or(u64::MAX);
                    match receiver.receive_once(now_us) {
                        Ok(ProtectedMulticastReceiveOutcome::Events(batch)) if batch.is_empty() => {
                        }
                        Ok(outcome) => match receive_tx.try_send(outcome) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                thread_dropped_events.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => return,
                        },
                        Err(_) => {
                            thread_failed.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
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
}

impl Drop for WorkerPresentationMulticastRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
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

    use super::*;

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
}
