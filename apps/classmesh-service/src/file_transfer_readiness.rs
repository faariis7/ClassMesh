//! Shared, one-way readiness for optional Service FileTransfer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The optional feature may only transition from ready to disabled.
/// The Service dispatch loop and future QUIC handshakes share one flag.
#[derive(Debug, Clone)]
pub(crate) struct FileTransferReadiness(Arc<AtomicBool>);

impl FileTransferReadiness {
    pub(crate) fn new(initially_ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(initially_ready)))
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn disable(&self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::FileTransferReadiness;

    #[test]
    fn disabling_unsafe_storage_reaches_existing_and_future_listener_snapshots() {
        let service = FileTransferReadiness::new(true);
        let listener = service.clone();
        assert!(listener.is_ready());
        service.disable();
        assert!(!service.is_ready());
        assert!(!listener.is_ready());
        let later_listener = service.clone();
        assert!(!later_listener.is_ready());
    }
}
