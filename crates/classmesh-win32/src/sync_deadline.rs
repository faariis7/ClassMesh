use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineError {
    Spawn,
    ThreadExited,
    Expired,
}

/// Cancel only a fresh dedicated thread, then JOIN before releasing borrowed
/// buffers/handles. Cancellation is retried to cover the pre-syscall race.
/// Like an overlapped-I/O drain, joining can exceed the logical deadline if
/// a Windows driver does not complete cancellation; never free live I/O memory.
pub(crate) fn run_with_deadline<T: Send>(
    timeout: Duration,
    operation: impl FnOnce() -> T + Send,
    mut cancel: impl FnMut(),
) -> Result<T, DeadlineError> {
    thread::scope(|scope| {
        let (tx, rx) = mpsc::sync_channel(1);
        let task = thread::Builder::new()
            .name("classmesh-worker-startup".into())
            .spawn_scoped(scope, move || {
                let _ = tx.send(operation());
            })
            .map_err(|_| DeadlineError::Spawn)?;
        let result = match rx.recv_timeout(timeout) {
            Ok(value) => Ok(value),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(DeadlineError::ThreadExited),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                loop {
                    cancel();
                    if !matches!(
                        rx.recv_timeout(Duration::from_millis(10)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ) {
                        break;
                    }
                }
                Err(DeadlineError::Expired) // Never admit a late success.
            }
        };
        if task.join().is_err() {
            return Err(DeadlineError::ThreadExited);
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn deadline_cancels_drains_and_rejects_late_success() {
        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let result = run_with_deadline(
            Duration::from_millis(20),
            move || {
                rx.recv().unwrap();
                42
            },
            || {
                let _ = tx.send(());
            },
        );
        assert!(
            result.is_err(),
            "completion after cancellation must not be admitted"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn completion_does_not_cancel_unrelated_io() {
        assert_eq!(
            run_with_deadline(Duration::from_secs(1), || 42, || panic!("early cancel")),
            Ok(42)
        );
    }
}
