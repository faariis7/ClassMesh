use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use classmesh_network::protected_unicast_receiver::{
    ProtectedUnicastFrameReceiver, ProtectedUnicastReceiveError, ProtectedUnicastReceiveOutcome,
    ProtectedUnicastReceiverConfig,
};
use classmesh_windows_runtime::ipc::ServicePresentationUnicastStart;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

const PRESENTATION_UNICAST_EVENT_CAPACITY: usize = 64;
const PRESENTATION_UNICAST_START_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum WorkerPresentationUnicastStartError {
    Receiver(ProtectedUnicastReceiveError),
    ThreadSpawn(std::io::Error),
    StartupTimeout,
    StartupChannelClosed,
}

impl Display for WorkerPresentationUnicastStartError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Receiver(error) => write!(formatter, "unicast receiver startup failed: {error}"),
            Self::ThreadSpawn(error) => write!(formatter, "unicast receive thread failed: {error}"),
            Self::StartupTimeout => formatter.write_str("unicast receiver startup timed out"),
            Self::StartupChannelClosed => {
                formatter.write_str("unicast receiver startup channel closed")
            }
        }
    }
}

impl Error for WorkerPresentationUnicastStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Receiver(error) => Some(error),
            Self::ThreadSpawn(error) => Some(error),
            Self::StartupTimeout | Self::StartupChannelClosed => None,
        }
    }
}

impl From<ProtectedUnicastReceiveError> for WorkerPresentationUnicastStartError {
    fn from(value: ProtectedUnicastReceiveError) -> Self {
        Self::Receiver(value)
    }
}

enum StartupOutcome {
    Started,
    Rejected(ProtectedUnicastReceiveError),
}

pub struct WorkerPresentationUnicastRuntime {
    binding: ServicePresentationUnicastStart,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
    receive_rx: Receiver<ProtectedUnicastReceiveOutcome>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for WorkerPresentationUnicastRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerPresentationUnicastRuntime")
            .field("binding", &self.binding)
            .field("failed", &self.failed())
            .field("dropped_events", &self.dropped_events())
            .finish_non_exhaustive()
    }
}

impl WorkerPresentationUnicastRuntime {
    pub fn start(
        binding: ServicePresentationUnicastStart,
    ) -> Result<Self, WorkerPresentationUnicastStartError> {
        let config = receiver_config(binding)?;
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (receive_tx, receive_rx) = mpsc::sync_channel(PRESENTATION_UNICAST_EVENT_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_failed = Arc::clone(&failed);
        let thread_dropped_events = Arc::clone(&dropped_events);

        let thread = thread::Builder::new()
            .name("classmesh-presentation-unicast".to_owned())
            .spawn(move || {
                let mut receiver = match ProtectedUnicastFrameReceiver::bind(config) {
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
                        Ok(ProtectedUnicastReceiveOutcome::Events(batch)) if batch.is_empty() => {}
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
            .map_err(WorkerPresentationUnicastStartError::ThreadSpawn)?;

        match startup_rx.recv_timeout(PRESENTATION_UNICAST_START_TIMEOUT) {
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
                Err(WorkerPresentationUnicastStartError::StartupTimeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Release);
                let _ = thread.join();
                Err(WorkerPresentationUnicastStartError::StartupChannelClosed)
            }
        }
    }

    #[must_use]
    pub const fn binding(&self) -> ServicePresentationUnicastStart {
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

    pub fn try_receive(&self) -> Option<ProtectedUnicastReceiveOutcome> {
        self.receive_rx.try_recv().ok()
    }

    #[must_use]
    pub fn same_media_configuration(&self, candidate: ServicePresentationUnicastStart) -> bool {
        same_media_configuration(self.binding, candidate)
    }

    pub fn adopt_retry(&mut self, candidate: ServicePresentationUnicastStart) -> bool {
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

impl Drop for WorkerPresentationUnicastRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn receiver_config(
    start: ServicePresentationUnicastStart,
) -> Result<ProtectedUnicastReceiverConfig, WorkerPresentationUnicastStartError> {
    ProtectedUnicastReceiverConfig::new(start.port, start.teacher_source, start.stream_id)
        .map_err(Into::into)
}

#[must_use]
pub fn same_media_configuration(
    current: ServicePresentationUnicastStart,
    candidate: ServicePresentationUnicastStart,
) -> bool {
    current.control_session_id == candidate.control_session_id
        && current.presentation_id == candidate.presentation_id
        && current.stream_id == candidate.stream_id
        && current.width == candidate.width
        && current.height == candidate.height
        && current.fps == candidate.fps
        && current.bitrate_kbps == candidate.bitrate_kbps
        && current.port == candidate.port
        && current.teacher_source == candidate.teacher_source
}

#[must_use]
pub fn start_matches_key_binding(
    start: ServicePresentationUnicastStart,
    key: PresentationKeyInstallBinding,
) -> bool {
    start.control_session_id == key.control_session_id
        && start.presentation_id == key.presentation_id
        && start.stream_id == key.stream_id
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    fn start(request_id: u64, teacher_source: IpAddr) -> ServicePresentationUnicastStart {
        ServicePresentationUnicastStart {
            control_session_id: 77,
            request_id,
            presentation_id: 55,
            stream_id: 9,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 6_000,
            port: 49_000,
            teacher_source,
        }
    }

    #[test]
    fn receiver_config_preserves_exact_unicast_binding_for_both_ip_families() {
        for teacher_source in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let start = start(44, teacher_source);
            let config = receiver_config(start).expect("valid receiver config");
            assert_eq!(config.expected_sender(), start.teacher_source);
            assert_eq!(config.stream_id(), start.stream_id);
            assert_eq!(config.port(), start.port);
            assert_eq!(
                config.local_bind(),
                SocketAddr::new(
                    match start.teacher_source {
                        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    },
                    start.port,
                )
            );
        }
    }

    #[test]
    fn retry_request_id_does_not_change_unicast_media_configuration() {
        let teacher = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
        assert!(same_media_configuration(
            start(44, teacher),
            start(45, teacher)
        ));
    }

    #[test]
    fn changed_unicast_media_binding_requires_runtime_replacement() {
        let current = start(44, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
        for candidate in [
            ServicePresentationUnicastStart {
                presentation_id: 56,
                ..current
            },
            ServicePresentationUnicastStart {
                stream_id: 10,
                ..current
            },
            ServicePresentationUnicastStart {
                port: 49_001,
                ..current
            },
            ServicePresentationUnicastStart {
                teacher_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)),
                ..current
            },
        ] {
            assert!(!same_media_configuration(current, candidate));
        }
    }

    #[test]
    fn runtime_binds_reserved_loopback_port_and_adopts_request_only_retry() {
        let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback port");
        let port = reservation.local_addr().expect("reserved address").port();
        drop(reservation);

        let first = ServicePresentationUnicastStart {
            port,
            teacher_source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ..start(44, IpAddr::V4(Ipv4Addr::LOCALHOST))
        };
        let mut runtime =
            WorkerPresentationUnicastRuntime::start(first).expect("unicast runtime starts");
        assert_eq!(runtime.binding(), first);
        assert!(!runtime.failed());

        let retry = ServicePresentationUnicastStart {
            request_id: 45,
            ..first
        };
        assert!(runtime.adopt_retry(retry));
        assert_eq!(runtime.binding().request_id, 45);
    }

    #[test]
    fn key_binding_requires_exact_control_presentation_and_stream() {
        let start = start(44, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
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
