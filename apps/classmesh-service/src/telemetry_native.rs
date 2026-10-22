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

struct AuthorizedNativeStart {
    pipe: ReceiverTelemetryPipeListener,
    worker: SessionProcess,
    identity: TelemetryPipeIdentity,
}
struct NativeReport {
    identity: TelemetryPipeIdentity,
    data: [u8; ONE_REPORT_BYTES],
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
        if filled != 0 && began.is_some_and(|at| at.elapsed() > NATIVE_DIAGNOSTIC_PARTIAL_TIMEOUT) {
            return;
        }
        let received = start.pipe.read_authenticated_chunk(
            &mut frame[filled..],
            NATIVE_DIAGNOSTIC_READ_TIMEOUT,
            &start.worker,
            live,
        );
        match received {
            Ok(Some(n)) => {
                if filled == 0 {
                    began = Some(Instant::now());
                }
                filled += n;
                if filled == ONE_REPORT_BYTES {
                    // If full, DROP the entire record, not a partial frame.
                    let _ = out.try_send(NativeReport {
                        identity,
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
