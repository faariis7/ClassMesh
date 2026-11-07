//! Operator-requested metadata only; no command or credential ingress.
//! Available solely in the existing protected-policy qualification build.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::control_runtime::WorkerCapabilityState;

pub(crate) struct RuntimeProbe {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RuntimeProbe {
    pub(crate) fn start(capabilities: Arc<WorkerCapabilityState>) -> Result<Option<Self>, String> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 1 {
            return Ok(None);
        }
        if args.len() != 4 || args[1] != "--worker-ipc-observer" {
            return Err("unexpected Service qualification arguments".into());
        }
        let pid: u32 = args[2].parse().map_err(|_| "invalid observer PID")?;
        let session: u32 = args[3].parse().map_err(|_| "invalid observer session")?;
        if pid == 0 || session == 0 {
            return Err("interactive observer required".into());
        }
        let sid = classmesh_win32::session_user_sid(session).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::Builder::new().name("classmesh-runtime-probe".into()).spawn(move || {
            let service = std::process::id();
            let name = format!("ClassMesh-runtime-{service:08x}");
            while !stopped.load(Ordering::Acquire) {
                let _ = classmesh_win32::NamedPipeServer::publish_runtime_probe(
                    &name, &sid, pid, session, || {
                        // Sample AFTER attesting the observer, never queue an old report.
                        let (generation, worker, worker_session) = capabilities.runtime_report().unwrap_or_default();
                        format!("{{\"service_pid\":{service},\"generation\":{generation},\"worker_pid\":{worker},\"session\":{worker_session}}}\n").into_bytes()
                    },
                );
                thread::sleep(Duration::from_millis(25));
            }
        }).map_err(|e| e.to_string())?;
        Ok(Some(Self {
            stop,
            thread: Some(thread),
        }))
    }
}

impl Drop for RuntimeProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
