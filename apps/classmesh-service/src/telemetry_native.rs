use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_service_lifecycle::ReceiverTelemetryCurrentWorker;
use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryServiceRuntime;
use classmesh_win32::{
    ReceiverTelemetryPipeListener, SessionProcess, telemetry_pipe_name::TelemetryPipeIdentity,
};

const ONE_REPORT_BYTES: usize = 136;
const NATIVE_DIAGNOSTIC_READ_TIMEOUT: Duration = Duration::from_millis(250);
const NATIVE_DIAGNOSTIC_PARTIAL_TIMEOUT: Duration = Duration::from_secs(2);

// Check BOTH before and after a potentially blocking native read. A last
// fragment may complete after the deadline even if the read began before it.
fn partial_report_expired(began: Option<Instant>, now: Instant) -> bool {
    began.is_some_and(|at| now.saturating_duration_since(at) >= NATIVE_DIAGNOSTIC_PARTIAL_TIMEOUT)
}

struct AuthorizedNativeStart {
    pipe: ReceiverTelemetryPipeListener,
    worker: SessionProcess,
    identity: TelemetryPipeIdentity,
}
struct NativeReport {
    identity: TelemetryPipeIdentity,
    // Service-owned first-byte time, not a timestamp supplied by Worker.
    // Keep it through the bounded mailbox to reject reports delayed in queue.
    began: Instant,
    data: [u8; ONE_REPORT_BYTES],
}
impl NativeReport {
    fn is_fresh_at(&self, now: Instant) -> bool {
        !partial_report_expired(Some(self.began), now)
    }
}

/// Single independent diagnostics reader. The privileged Service loop never
/// waits for pipe connect/read or for backpressure. The current incarnation
/// is mirrored from Service-owned receiver state, never from Worker bytes.
pub(super) struct ServiceTelemetryReader {
    // Active transport is distinct from an otherwise authorized runtime.
    // A failed grant send must never re-arm the OS reader by polling state.
    armed: Option<TelemetryPipeIdentity>,
    current: Arc<Mutex<Option<TelemetryPipeIdentity>>>,
    starts: mpsc::SyncSender<AuthorizedNativeStart>,
    reports: mpsc::Receiver<NativeReport>,
}
impl ServiceTelemetryReader {
    pub(super) fn new() -> Self {
        let current = Arc::new(Mutex::new(None));
        let (starts, start_rx) = mpsc::sync_channel::<AuthorizedNativeStart>(1);
        let (report_tx, reports) = mpsc::sync_channel::<NativeReport>(1);
        let background_current = Arc::clone(&current);
        let _reader = thread::Builder::new()
            .name("classmesh-phase10-telemetry-reader".to_owned())
            .spawn(move || {
                while let Ok(start) = start_rx.recv() {
                    run_one_listener(start, &background_current, &report_tx);
                }
            });
        Self {
            armed: None,
            current,
            starts,
            reports,
        }
    }

    pub(super) fn arm(
        &mut self,
        receiver: ReceiverTelemetryBinding,
        worker: &SessionProcess,
        user_sid: &[u8],
    ) -> Result<TelemetryPipeIdentity, &'static str> {
        if !receiver.is_valid()
            || receiver.process_id != worker.process_id()
            || receiver.session_id != worker.session_id()
        {
            return Err("TelemetryWorkerBinding");
        }
        let identity = TelemetryPipeIdentity {
            service_process_id: std::process::id(),
            worker_process_id: receiver.process_id,
            worker_session_id: receiver.session_id,
            worker_generation: receiver.worker_generation,
            receiver_generation: receiver.receiver_generation,
        };
        let pipe = ReceiverTelemetryPipeListener::create(identity, user_sid)
            .map_err(|_| "TelemetryPipeCreate")?;
        let owned_worker = worker
            .try_clone()
            .map_err(|_| "TelemetryWorkerHandleClone")?;
        self.armed = Some(identity);
        self.set_current(Some(identity));
        match self.starts.try_send(AuthorizedNativeStart {
            pipe,
            worker: owned_worker,
            identity,
        }) {
            Ok(()) => Ok(identity),
            Err(_) => {
                self.retire();
                Err("TelemetryReaderBusy")
            }
        }
    }

    pub(super) fn sync_current(&mut self, current: Option<ReceiverTelemetryBinding>) {
        let target = current.map(|r| TelemetryPipeIdentity {
            service_process_id: std::process::id(),
            worker_process_id: r.process_id,
            worker_session_id: r.session_id,
            worker_generation: r.worker_generation,
            receiver_generation: r.receiver_generation,
        });
        if target != self.armed {
            self.retire();
        } else {
            self.set_current(target);
        }
    }

    pub(super) fn retire(&mut self) {
        self.armed = None;
        self.set_current(None);
    }

    fn set_current(&self, target: Option<TelemetryPipeIdentity>) {
        if let Ok(mut guard) = self.current.lock() {
            *guard = target;
        }
    }

    pub(super) fn drain(
        &mut self,
        runtime: &mut ReceiverTelemetryServiceRuntime,
        current_worker: Option<ReceiverTelemetryCurrentWorker>,
    ) {
        self.sync_current(runtime.current());
        for _ in 0..4 {
            let Ok(incoming) = self.reports.try_recv() else {
                break;
            };
            // Revocation or a failed control-grant send can leave a report in
            // the one-slot mailbox while the runtime binding is still valid.
            // Only an explicitly armed native transport may feed admission.
            if self.armed != Some(incoming.identity) {
                continue;
            }
            // The reader may be descheduled after its last deadline check,
            // or the one-slot mailbox may remain unread past the 2s limit.
            // Reject at privileged admission too; Worker cannot forge began.
            if !incoming.is_fresh_at(Instant::now()) {
                continue;
            }
            let Some(worker) = current_worker else {
                continue;
            };
            let Some(authorized) = runtime.worker_grant_after_verified_peer(worker) else {
                continue;
            };
            let r = authorized.receiver();
            if incoming.identity
                != (TelemetryPipeIdentity {
                    service_process_id: std::process::id(),
                    worker_process_id: r.process_id,
                    worker_session_id: r.session_id,
                    worker_generation: r.worker_generation,
                    receiver_generation: r.receiver_generation,
                })
            {
                continue;
            }
            // Recheck immediately before admission: grant/identity checks
            // above can themselves be delayed by thread scheduling.
            if !incoming.is_fresh_at(Instant::now()) {
                continue;
            }
            // The main Service loop owns and serializes key lifecycle and
            // admission. The untrusted data NEVER defines its own authority.
            if let Err(error) = runtime.observe_stream_chunk_after_verified_peer(
                worker,
                &incoming.data,
                Instant::now(),
            ) {
                eprintln!("ClassMesh Phase10 telemetry frame rejected: {error:?}");
            }
        }
        self.sync_current(runtime.current());
    }
}

fn run_one_listener(
    mut start: AuthorizedNativeStart,
    current: &Mutex<Option<TelemetryPipeIdentity>>,
    out: &mpsc::SyncSender<NativeReport>,
) {
    let identity = start.identity;
    let live = || current.lock().ok().and_then(|state| *state);
    if start
        .pipe
        .accept_bound_worker(Duration::from_secs(2), &start.worker, live)
        .is_err()
    {
        return;
    }
    let mut frame = [0_u8; ONE_REPORT_BYTES];
    let mut filled = 0_usize;
    let mut began: Option<Instant> = None;
    while live() == Some(identity) {
        if filled != 0 && partial_report_expired(began, Instant::now()) {
            return;
        }
        let received = start.pipe.read_authenticated_chunk(
            &mut frame[filled..],
            NATIVE_DIAGNOSTIC_READ_TIMEOUT,
            &start.worker,
            live,
        );
        // A read can finish after the 2s partial deadline. Reject even a
        // complete final fragment rather than publishing a stale frame.
        if filled != 0 && partial_report_expired(began, Instant::now()) {
            return;
        }
        match received {
            Ok(Some(n)) => {
                if filled == 0 {
                    began = Some(Instant::now());
                }
                filled += n;
                if filled == ONE_REPORT_BYTES {
                    // A thread can be descheduled between the post-read check
                    // and publication. Never enqueue a frame whose first byte
                    // is already outside the partial-frame deadline.
                    if partial_report_expired(began, Instant::now()) {
                        return;
                    }
                    // If full, DROP the entire record, not a partial frame.
                    let Some(began_at) = began else {
                        return; // a complete frame must have a first byte
                    };
                    let _ = out.try_send(NativeReport {
                        identity,
                        began: began_at,
                        data: frame,
                    });
                    filled = 0;
                    began = None;
                    frame = [0_u8; ONE_REPORT_BYTES];
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_native_report_must_expire_even_if_final_read_completes_late() {
        let now = Instant::now();
        let first_chunk = now - Duration::from_millis(1_900);
        assert!(!partial_report_expired(Some(first_chunk), now));
        // A final read that began within the 2s window may finish AFTER it.
        // Such a completed frame must be discarded, not admitted.
        assert!(partial_report_expired(
            Some(first_chunk),
            now + Duration::from_millis(101),
        ));
        assert!(!partial_report_expired(None, now));
        // The exact 2s boundary is expired (fail closed), not just >2s.
        assert!(!partial_report_expired(
            Some(now - Duration::from_millis(1_999)),
            now,
        ));
        assert!(partial_report_expired(
            Some(now - Duration::from_secs(2)),
            now,
        ));
    }

    #[test]
    fn queued_native_report_expires_before_privileged_admission() {
        let received = Instant::now();
        let queued_at = received - Duration::from_millis(1_999);
        let report = NativeReport {
            identity: TelemetryPipeIdentity {
                service_process_id: 1,
                worker_process_id: 2,
                worker_session_id: 3,
                worker_generation: 4,
                receiver_generation: 5,
            },
            began: queued_at,
            data: [0; ONE_REPORT_BYTES],
        };
        // A completed report can sit in the one-slot mailbox or the reader
        // can be paused after checking. Its Service-owned first-byte time
        // remains authoritative even when it reaches admission later.
        assert!(report.is_fresh_at(received));
        assert!(!report.is_fresh_at(received + Duration::from_millis(1)));
    }

    #[test]
    fn retired_native_reader_discards_queued_report_even_with_live_runtime_binding() {
        use classmesh_control::receiver_telemetry::{
            ReceiverPlaybackCounters, ReceiverTelemetrySnapshot,
        };
        use classmesh_control::receiver_telemetry_service_lifecycle::{
            ReceiverTelemetryStart, ReceiverTelemetryStartAck, ReceiverTelemetryStartAckStatus,
        };
        use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryAuthorizedKey;
        use classmesh_control::receiver_telemetry_transport::encode_receiver_telemetry;

        let worker = ReceiverTelemetryCurrentWorker {
            process_id: 501,
            session_id: 7,
            worker_generation: 4,
        };
        let mut runtime = ReceiverTelemetryServiceRuntime::default();
        runtime
            .confirm_key_installed(
                ReceiverTelemetryAuthorizedKey {
                    control_session_id: 50,
                    key_grant_request_id: 60,
                    presentation_id: 70,
                    stream_id: 8,
                    epoch: 9,
                },
                worker,
            )
            .unwrap();
        let binding = runtime
            .activate_correlated_start(
                ReceiverTelemetryStart {
                    process_id: 501,
                    session_id: 7,
                    worker_generation: 4,
                    control_session_id: 50,
                    request_id: 61,
                    presentation_id: 70,
                    stream_id: 8,
                    epoch: 9,
                },
                worker,
                ReceiverTelemetryStartAck {
                    process_id: 501,
                    session_id: 7,
                    control_session_id: 50,
                    request_id: 61,
                    presentation_id: 70,
                    stream_id: 8,
                    status: ReceiverTelemetryStartAckStatus::Started,
                },
            )
            .unwrap();
        let wire = encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
            binding,
            sequence: 1,
            counters: ReceiverPlaybackCounters {
                authenticated_frames: 11,
                decoded_frames: 6,
                presented_frames: 1,
                ..Default::default()
            },
        })
        .unwrap();
        let identity = TelemetryPipeIdentity {
            service_process_id: std::process::id(),
            worker_process_id: binding.process_id,
            worker_session_id: binding.session_id,
            worker_generation: binding.worker_generation,
            receiver_generation: binding.receiver_generation,
        };
        let (sender, reports) = mpsc::sync_channel(1);
        let mut reader = ServiceTelemetryReader::new();
        reader.reports = reports;
        // Model an actually armed reader before a failed control-grant send.
        // Without this setup, the test could pass merely because no pipe was
        // ever armed, rather than proving that retirement revokes admission.
        reader.armed = Some(identity);
        reader.set_current(Some(identity));
        assert_eq!(reader.armed, Some(identity));
        // Simulate a report already queued before control-grant send failed.
        // Runtime authorization survives, but the native transport was retired.
        assert!(
            sender
                .try_send(NativeReport {
                    identity,
                    began: Instant::now(),
                    data: wire,
                })
                .is_ok()
        );
        reader.retire();
        assert_eq!(reader.armed, None);
        assert_eq!(runtime.current(), Some(binding));
        reader.drain(&mut runtime, Some(worker));
        assert!(reader.reports.try_recv().is_err());
        assert_eq!(runtime.current(), Some(binding));
        assert!(!runtime.has_fresh_for_verified_peer(worker, Instant::now()));
    }

    #[test]
    fn service_does_not_implicitly_activate_a_runtime_receiver_without_native_pipe() {
        let mut reader = ServiceTelemetryReader::new();
        let binding = ReceiverTelemetryBinding {
            process_id: 22,
            session_id: 33,
            worker_generation: 44,
            control_session_id: 55,
            request_id: 66,
            presentation_id: 77,
            stream_id: 88,
            epoch: 99,
            receiver_generation: 111,
        };
        // A valid passive Service lifetime is NOT permission to spawn
        // reader/emit IPC without explicitly arming a verified native pipe.
        reader.sync_current(Some(binding));
        assert_eq!(*reader.current.lock().unwrap(), None);
        assert_eq!(reader.armed, None);
    }
}
