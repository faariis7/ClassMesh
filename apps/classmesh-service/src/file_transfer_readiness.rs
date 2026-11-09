//! Shared, one-way readiness for optional Service FileTransfer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// No trusted operator provisioning/opt-in source exists yet. Do not infer
// permission from private ACLs alone; keep FileTransfer production-default OFF.
pub(crate) const FILE_TRANSFER_OPERATOR_OPT_IN: bool = false;

/// The optional feature may only transition from ready to disabled.
/// The Service dispatch loop and future QUIC handshakes share one flag.
/// A fresh storage check at each new handshake also catches unsafe ACL changes
/// when no transfer dispatch has yet reached the Service main loop.
#[derive(Clone)]
pub(crate) struct FileTransferReadiness {
    ready: Arc<AtomicBool>,
    storage_verifier: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for FileTransferReadiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTransferReadiness")
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

impl FileTransferReadiness {
    #[cfg(test)]
    pub(crate) fn new(initially_ready: bool) -> Self {
        Self::with_storage_verifier(initially_ready, || true)
    }

    /// A secure directory alone is not permission to enable FileTransfer.
    /// Only an explicit, trusted operator gate may even attempt provisioning.
    /// A disabled gate must not create paths or run the storage preparer.
    pub(crate) fn with_operator_gate(
        operator_opt_in: bool,
        prepare_storage: impl FnOnce() -> bool,
        verifier: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::with_storage_verifier(operator_opt_in && prepare_storage(), verifier)
    }

    pub(crate) fn with_storage_verifier(
        initially_ready: bool,
        verifier: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(initially_ready)),
            storage_verifier: Arc::new(verifier),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub(crate) fn revalidate_for_hello(&self) -> bool {
        if !self.is_ready() {
            return false;
        }
        if !(self.storage_verifier)() {
            self.disable();
        }
        self.is_ready()
    }

    pub(crate) fn disable(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{FILE_TRANSFER_OPERATOR_OPT_IN, FileTransferReadiness};

    #[test]
    fn handshake_revalidates_storage_without_a_queued_transfer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let storage_safe = Arc::new(AtomicBool::new(true));
        let verifier_flag = Arc::clone(&storage_safe);
        let readiness = FileTransferReadiness::with_storage_verifier(true, move || {
            verifier_flag.load(Ordering::Acquire)
        });
        let listener = readiness.clone();
        assert!(listener.revalidate_for_hello());
        storage_safe.store(false, Ordering::Release);
        assert!(
            !listener.revalidate_for_hello(),
            "a new handshake must not advertise FileTransfer after an ACL change"
        );
        storage_safe.store(true, Ordering::Release);
        assert!(
            !readiness.revalidate_for_hello(),
            "a previously revoked FileTransfer instance must never re-enable itself"
        );
    }

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

    #[test]
    fn secure_storage_without_explicit_operator_opt_in_never_advertises_transfer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let provision_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&provision_called);
        const {
            assert!(!FILE_TRANSFER_OPERATOR_OPT_IN);
        }
        let readiness = FileTransferReadiness::with_operator_gate(
            FILE_TRANSFER_OPERATOR_OPT_IN,
            move || {
                called.store(true, Ordering::Release);
                true
            },
            || true,
        );
        assert!(!readiness.revalidate_for_hello());
        assert!(!readiness.is_ready());
        assert!(
            !provision_called.load(Ordering::Acquire),
            "default-OFF must not create staging directories or register sources"
        );

        let unsafe_opt_in = FileTransferReadiness::with_operator_gate(true, || false, || true);
        assert!(!unsafe_opt_in.revalidate_for_hello());
    }
}
