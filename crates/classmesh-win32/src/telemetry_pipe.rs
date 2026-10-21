//! Inactive Phase 10 diagnostics-only Windows local channel primitives.
//!
//! Unlike the privileged control IPC and future sensitive clipboard pipe, this
//! endpoint is write-only for a Worker and read-only for the Service, never
//! inherits handles, rejects remote clients, uses a DACL, and runs overlapped
//! IO with bounded requests and cancellation. Creating or connecting here
//! DOES NOT install/authorize receiver telemetry or publish Teacher feedback.
//!
//! The Service must obtain TelemetryPipeIdentity from its authenticated
//! Worker/key/receiver ledger. Native OS peer checks must be repeated against
//! the Service-launched Worker HANDLE and the *current* receiver identity.
//! A separate low-priority thread and a serialized Service admission owner
//! are REQUIRED before live deployment: none is created here.

use std::time::Duration;

use crate::named_pipe::{NamedPipeClient, NamedPipeServer, PipeError, PipePeer};
use crate::session_process::SessionProcess;
use crate::telemetry_pipe_name::TelemetryPipeIdentity;

const ACCESS_DENIED: u32 = 5;

#[derive(Debug)]
pub struct ReceiverTelemetryPipeListener {
    binding: TelemetryPipeIdentity,
    pipe: NamedPipeServer,
    attempted: bool,
    accepted: Option<PipePeer>,
}

impl ReceiverTelemetryPipeListener {
    /// Service-only. Do not expose this channel to an untrusted identity or
    /// use the temporary ACL test SID in production.
    pub fn create(binding: TelemetryPipeIdentity, user_sid: &[u8]) -> Result<Self, PipeError> {
        if !binding.is_valid() || binding.service_process_id != std::process::id() {
            return Err(denied("TelemetryServiceIdentity"));
        }
        let name = binding.pipe_name().ok_or(denied("TelemetryPipeBinding"))?;
        let pipe = NamedPipeServer::create_telemetry_overlapped_for_user(&name, user_sid)?;
        Ok(Self {
            binding,
            pipe,
            attempted: false,
            accepted: None,
        })
    }

    /// No grant can be inferred from the socket/pipe address. The Service
    /// supplies a fresh receiver-ledger snapshot before + after waiting and
    /// retains the real launched Worker HANDLE for PID-reuse-safe admission.
    pub fn accept_bound_worker(
        &mut self,
        timeout: Duration,
        worker: &SessionProcess,
        mut current: impl FnMut() -> Option<TelemetryPipeIdentity>,
    ) -> Result<(), PipeError> {
        if self.attempted {
            return Err(denied("TelemetryConnectionAlreadyAttempted"));
        }
        self.attempted = true;
        if timeout.as_millis() == 0 || timeout > Duration::from_millis(2_500) {
            return Err(denied("TelemetryConnectDeadline"));
        }
        if current() != Some(self.binding)
            || worker.process_id() != self.binding.worker_process_id
            || worker.session_id() != self.binding.worker_session_id
            || !worker
                .is_running()
                .map_err(|_| denied("TelemetryWorkerHandle"))?
        {
            return Err(denied("TelemetryWorkerNotCurrent"));
        }
        let peer = self.pipe.wait_for_overlapped_peer(timeout)?;
        if current() != Some(self.binding)
            || !worker
                .matches_live_pipe_peer(&peer)
                .map_err(|_| denied("TelemetryWorkerHandle"))?
        {
            let _ = self.pipe.disconnect();
            return Err(denied("TelemetryOsPeerNotCurrent"));
        }
        self.accepted = Some(peer);
        Ok(())
    }

    /// One bounded native receive. The caller is the dedicated Service
    /// diagnostic thread; it passes the immutable current receiver identity
    /// and verifies it at the real Service admission boundary again. If the
    /// Worker exited/revoked mid-read the bytes are DISCARDED, not parsed.
    pub fn read_authenticated_chunk(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
        worker: &SessionProcess,
        mut current: impl FnMut() -> Option<TelemetryPipeIdentity>,
    ) -> Result<Option<usize>, PipeError> {
        let peer = self
            .accepted
            .ok_or(denied("TelemetryConnectionNotAuthenticated"))?;
        if current() != Some(self.binding)
            || !worker
                .matches_live_pipe_peer(&peer)
                .map_err(|_| denied("TelemetryWorkerHandle"))?
        {
            self.disconnect_permanently();
            return Err(denied("TelemetryWorkerNotCurrent"));
        }
        // A cancelled+drained read after an ordinary 250ms idle window is
        // *not* a failed connection: genuine playback reports arrive about
        // every five seconds. Keep the same peer/handle but independently
        // recheck Worker and receiver authority AFTER every elapsed wait.
        // All other read failures/disconnects permanently retire this pipe.
        let result = match self.pipe.telemetry_read_bounded(buffer, timeout) {
            Ok(0) => {
                self.disconnect_permanently();
                return Err(denied("TelemetryPipeDisconnected"));
            }
            Ok(len) => Some(len),
            Err(error) if error.stage == "TelemetryIoTimeout" => None,
            Err(error) => {
                self.disconnect_permanently();
                return Err(error);
            }
        };
        let still_running = worker.matches_live_pipe_peer(&peer);
        if current() != Some(self.binding) || !matches!(still_running, Ok(true)) {
            self.disconnect_permanently();
            return Err(denied("TelemetryWorkerNotCurrentAfterRead"));
        }
        Ok(result)
    }

    fn disconnect_permanently(&mut self) {
        self.accepted = None;
        let _ = self.pipe.disconnect();
    }

    #[must_use]
    pub fn identity(&self) -> TelemetryPipeIdentity {
        self.binding
    }
}

/// One-shot, write-only endpoint. Worker must receive its identity from an
/// authenticated existing control pipe, never from a requested pipe address.
/// Must live on a separate low-priority sender thread, not the media loop.
#[derive(Debug)]
pub struct ReceiverTelemetryPipeClient {
    pipe: Option<NamedPipeClient>,
}

impl ReceiverTelemetryPipeClient {
    pub fn connect_from_verified_service(
        binding: TelemetryPipeIdentity,
    ) -> Result<Self, PipeError> {
        if !binding.is_valid()
            || binding.worker_process_id != std::process::id()
            || binding.worker_session_id
                != crate::session::current_session_id()
                    .map_err(|_| denied("TelemetryClientSession"))?
        {
            return Err(denied("TelemetryWorkerClientIdentity"));
        }
        let name = binding
            .pipe_name()
            .ok_or(denied("TelemetryClientBinding"))?;
        let pipe = NamedPipeClient::connect_telemetry_once(&name, binding.service_process_id)?;
        Ok(Self { pipe: Some(pipe) })
    }

    /// Single complete 136-byte v1 report. This cannot be used to send
    /// clipboard plaintext, remote control commands or variable-size IPC.
    /// Any error must retire this client; NO retry is allowed.
    pub fn send_once(&mut self, frame: &[u8; 136], timeout: Duration) -> Result<(), PipeError> {
        let Some(pipe) = self.pipe.as_ref() else {
            return Err(denied("TelemetryClientRetired"));
        };
        match pipe.telemetry_write_bounded(frame, timeout) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The overlapped operation has been cancelled and drained.
                // A failed frame retires this pipe incarnation permanently.
                self.pipe = None;
                Err(error)
            }
        }
    }
}

fn denied(stage: &'static str) -> PipeError {
    PipeError {
        stage,
        win32_error: ACCESS_DENIED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinAuthenticatedUserSid,
    };

    static NEXT_RECEIVER: AtomicU64 = AtomicU64::new(1);

    fn test_sid() -> Vec<u8> {
        // A group SID is permitted only in this local test; real Service
        // uses the intended interactive user SID, not all authenticated users.
        let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut length = sid.len() as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinAuthenticatedUserSid,
                    null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            0
        );
        sid.truncate(length as usize);
        sid
    }

    fn identity() -> TelemetryPipeIdentity {
        TelemetryPipeIdentity {
            service_process_id: std::process::id(),
            worker_process_id: std::process::id(),
            worker_session_id: crate::current_session_id().expect("real Windows session"),
            worker_generation: 5,
            receiver_generation: NEXT_RECEIVER.fetch_add(1, Ordering::Relaxed),
        }
    }

    #[test]
    fn native_idle_poll_cancels_drained_reads_but_stays_connected_for_next_report() {
        let binding = identity();
        let mut listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let mut client =
            ReceiverTelemetryPipeClient::connect_from_verified_service(binding).unwrap();
        let peer = listener
            .pipe
            .wait_for_overlapped_peer(Duration::from_millis(250))
            .unwrap();
        listener.accepted = Some(peer);
        let worker = SessionProcess::duplicate_current_process_for_test(binding.worker_session_id);
        let mut frame = [0_u8; 136];
        for _ in 0..3 {
            assert_eq!(
                listener.read_authenticated_chunk(
                    &mut frame,
                    Duration::from_millis(25),
                    &worker,
                    || Some(binding),
                ),
                Ok(None),
                "idle timeout must NOT retire an otherwise live receiver"
            );
        }
        client
            .send_once(&[0x72; 136], Duration::from_millis(250))
            .unwrap();
        assert_eq!(
            listener.read_authenticated_chunk(
                &mut frame,
                Duration::from_millis(250),
                &worker,
                || Some(binding),
            ),
            Ok(Some(136))
        );
        assert_eq!(frame, [0x72; 136]);
    }

    #[test]
    fn revocation_after_idle_poll_rejects_old_worker_without_new_read() {
        let binding = identity();
        let mut listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let _client = ReceiverTelemetryPipeClient::connect_from_verified_service(binding).unwrap();
        let peer = listener
            .pipe
            .wait_for_overlapped_peer(Duration::from_millis(250))
            .unwrap();
        listener.accepted = Some(peer);
        let worker = SessionProcess::duplicate_current_process_for_test(binding.worker_session_id);
        let mut frame = [0_u8; 136];
        assert_eq!(
            listener.read_authenticated_chunk(
                &mut frame,
                Duration::from_millis(25),
                &worker,
                || Some(binding),
            ),
            Ok(None)
        );
        assert_eq!(
            listener
                .read_authenticated_chunk(&mut frame, Duration::from_millis(25), &worker, || None,)
                .unwrap_err()
                .stage,
            "TelemetryWorkerNotCurrent"
        );
        assert_eq!(
            listener
                .read_authenticated_chunk(&mut frame, Duration::from_millis(25), &worker, || Some(
                    binding
                ),)
                .unwrap_err()
                .stage,
            "TelemetryConnectionNotAuthenticated"
        );
    }

    #[test]
    fn native_local_pipe_transfers_one_fixed_frame_and_reports_os_peer() {
        let binding = identity();
        let mut listener =
            ReceiverTelemetryPipeListener::create(binding, &test_sid()).expect("one local pipe");
        let mut client = ReceiverTelemetryPipeClient::connect_from_verified_service(binding)
            .expect("client must verify actual OS Service PID");
        let peer = listener
            .pipe
            .wait_for_overlapped_peer(Duration::from_millis(500))
            .unwrap();
        assert_eq!(peer.process_id(), std::process::id());
        assert_eq!(peer.session_id(), crate::current_session_id().unwrap());
        let frame = [0x5a_u8; 136];
        client
            .send_once(&frame, Duration::from_millis(80))
            .expect("bounded write");
        let mut received = [0_u8; 136];
        assert_eq!(
            listener
                .pipe
                .telemetry_read_bounded(&mut received, Duration::from_millis(80)),
            Ok(136),
        );
        assert_eq!(frame, received);
        assert_eq!(listener.identity(), binding);
    }

    #[test]
    fn wrong_os_server_pid_is_rejected_without_granting_access() {
        let binding = identity();
        let _listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let error = NamedPipeClient::connect_telemetry_once(
            &binding.pipe_name().unwrap(),
            binding.service_process_id.wrapping_add(1),
        )
        .unwrap_err();
        assert_eq!(error.stage, "TelemetryServerPidMismatch");
    }

    #[test]
    fn stalled_native_read_cancels_and_drains_before_buffer_drop() {
        let binding = identity();
        let mut listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let _client = ReceiverTelemetryPipeClient::connect_from_verified_service(binding).unwrap();
        listener
            .pipe
            .wait_for_overlapped_peer(Duration::from_millis(500))
            .unwrap();
        let mut buffer = [0_u8; 136];
        let started = std::time::Instant::now();
        let error = listener
            .pipe
            .telemetry_read_bounded(&mut buffer, Duration::from_millis(35))
            .unwrap_err();
        assert_eq!(error.stage, "TelemetryIoTimeout");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(listener); // Windows no longer borrows buffer/event/OVERLAPPED
    }

    #[test]
    fn invalid_deadline_and_frame_length_rejected_before_io() {
        let binding = identity();
        let listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let mut empty = [];
        assert_eq!(
            listener
                .pipe
                .telemetry_read_bounded(&mut empty, Duration::from_millis(20))
                .unwrap_err()
                .stage,
            "TelemetryReadSize",
        );
        let mut buffer = [0_u8; 136];
        for timeout in [Duration::ZERO, Duration::from_secs(1)] {
            assert_eq!(
                listener
                    .pipe
                    .telemetry_read_bounded(&mut buffer, timeout)
                    .unwrap_err()
                    .stage,
                "TelemetryIoDeadline",
            );
        }
        let mut client =
            ReceiverTelemetryPipeClient::connect_from_verified_service(binding).unwrap();
        // Validate the low-level length rejection while the client still
        // owns the pipe. A subsequent failed send deliberately RETIRES it.
        assert_eq!(
            client
                .pipe
                .as_ref()
                .unwrap()
                .telemetry_write_bounded(&[0; 1], Duration::from_millis(30))
                .unwrap_err()
                .stage,
            "TelemetryFrameLength",
        );
        assert_eq!(
            client
                .send_once(&[0; 136], Duration::ZERO)
                .unwrap_err()
                .stage,
            "TelemetryIoDeadline",
        );
        assert_eq!(
            client
                .send_once(&[0; 136], Duration::from_millis(30))
                .unwrap_err()
                .stage,
            "TelemetryClientRetired",
        );
    }

    #[test]
    fn unbound_or_wrong_worker_cannot_create_or_join_native_pipe() {
        let mut invalid = identity();
        invalid.worker_generation = 0;
        assert_eq!(
            ReceiverTelemetryPipeListener::create(invalid, &test_sid())
                .unwrap_err()
                .stage,
            "TelemetryServiceIdentity",
        );
        let mut wrong_worker = identity();
        wrong_worker.worker_process_id = wrong_worker.worker_process_id.wrapping_add(1);
        assert_eq!(
            ReceiverTelemetryPipeClient::connect_from_verified_service(wrong_worker)
                .unwrap_err()
                .stage,
            "TelemetryWorkerClientIdentity",
        );
    }

    #[test]
    fn failed_native_telemetry_send_retires_connection_permanently() {
        let binding = identity();
        let _listener = ReceiverTelemetryPipeListener::create(binding, &test_sid()).unwrap();
        let mut client = ReceiverTelemetryPipeClient::connect_from_verified_service(binding)
            .expect("test-only local server PID attested");
        assert_eq!(
            client
                .send_once(&[0; 136], Duration::ZERO)
                .unwrap_err()
                .stage,
            "TelemetryIoDeadline"
        );
        assert_eq!(
            client
                .send_once(&[0; 136], Duration::from_millis(25))
                .unwrap_err()
                .stage,
            "TelemetryClientRetired"
        );
    }

    /// Invoked only as a child of the native process test; regular test runs
    /// must never create or join any local pipe from ambient configuration.
    #[test]
    fn telemetry_child_process_one_shot_sender() {
        let Ok(name) = std::env::var("CLASSMESH_NATIVE_TELEMETRY_TEST_PIPE") else {
            return;
        };
        let server_pid: u32 = std::env::var("CLASSMESH_NATIVE_TELEMETRY_TEST_SERVICE_PID")
            .expect("parent Service PID in test harness")
            .parse()
            .expect("numeric PID");
        let client = NamedPipeClient::connect_telemetry_once(&name, server_pid)
            .expect("separate-process test client verifies kernel server PID");
        client
            .telemetry_write_bounded(&[0xa7; 136], Duration::from_millis(250))
            .expect("native child sends one bounded telemetry frame");
    }

    #[test]
    fn native_two_process_telemetry_wire_uses_real_os_pid_and_fixed_frame() {
        let binding = identity();
        let mut listener = ReceiverTelemetryPipeListener::create(binding, &test_sid())
            .expect("isolated local pipe with test SID");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "telemetry_pipe::tests::telemetry_child_process_one_shot_sender",
                "--nocapture",
            ])
            .env(
                "CLASSMESH_NATIVE_TELEMETRY_TEST_PIPE",
                binding.pipe_name().unwrap(),
            )
            .env(
                "CLASSMESH_NATIVE_TELEMETRY_TEST_SERVICE_PID",
                std::process::id().to_string(),
            )
            .spawn()
            .expect("launch independent Windows test process");
        let actual_pid = child.id();
        let peer = listener
            .pipe
            .wait_for_overlapped_peer(Duration::from_millis(1_500))
            .expect("Service OS named pipe accepts separate Worker process");
        assert_eq!(peer.process_id(), actual_pid);
        assert_eq!(peer.session_id(), crate::current_session_id().unwrap());
        let mut payload = [0_u8; 136];
        assert_eq!(
            listener
                .pipe
                .telemetry_read_bounded(&mut payload, Duration::from_millis(250)),
            Ok(136)
        );
        let finished = child.wait_with_output().expect("collect child result");
        // This test intentionally uses two Windows processes, not two
        // threads in one process; OS PID attestation must identify the child.
        assert_ne!(actual_pid, std::process::id());
        assert_eq!(payload, [0xa7; 136]);
        assert!(
            finished.status.success(),
            "native sender failed: {}",
            String::from_utf8_lossy(&finished.stderr)
        );
    }
}
