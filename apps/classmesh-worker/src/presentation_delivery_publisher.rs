//! In-process, fail-closed Worker playback outbox for a Service-issued receiver
//! lifetime. This library component creates NO IPC channel or privileged
//! sender, and is not connected to the production Worker loop yet.
//!
//! Only an independently authenticated Service command may activate the
//! exact receiver/Worker generation, authorized media-start request and
//! protected key grant. The request IDs are different contracts. Reporting
//! stamps the complete owner BEFORE placing an immutable snapshot in the
//! one-slot, best-effort mailbox. A later checkout cannot relabel it.
//! A real sender MUST independently recheck live Service authorization
//! immediately before I/O; this helper alone is not authentication.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryWorkerGrant;
use classmesh_control::receiver_telemetry_transport::{
    ReceiverTelemetryConcurrentError, ReceiverTelemetryConcurrentMailbox,
    ReceiverTelemetrySendLease,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

use crate::group_media_receive::WorkerGroupMediaAuthenticationStats;
use crate::presentation_decode_render::PresentationDecodeStep;
use crate::presentation_delivery_telemetry::PresentationDeliveryTelemetry;

/// An arbitrary caller must not synthesize a Worker receiver permit by
/// filling in plausible identities. Only a Service-minted grant, checked
/// against the Worker-installed key, may be converted to a permit.
///
/// ```compile_fail
/// use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
/// use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
/// use classmesh_worker::presentation_delivery_publisher::WorkerReceiverTelemetryAuthorization;
/// let forged = WorkerReceiverTelemetryAuthorization {
///     owner: ReceiverTelemetryBinding {
///         process_id: 501, session_id: 7, worker_generation: 11,
///         control_session_id: 30, request_id: 91, presentation_id: 40,
///         stream_id: 8, epoch: 2, receiver_generation: 1,
///     },
///     installed_key: PresentationKeyInstallBinding {
///         control_session_id: 30, request_id: 51,
///         presentation_id: 40, stream_id: 8, epoch: 2,
///     },
///     authorized_start_request_id: 91,
/// };
/// assert!(forged.is_valid());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerReceiverTelemetryAuthorization {
    owner: ReceiverTelemetryBinding,
    installed_key: PresentationKeyInstallBinding,
    /// Independently Service-authorized StreamOffer/start request, not key
    /// grant request. This value is not created by the Worker.
    authorized_start_request_id: u64,
}

impl WorkerReceiverTelemetryAuthorization {
    /// Non-authoritative read-only owner; a permit is NOT an OS credential.
    #[must_use]
    pub const fn owner(self) -> ReceiverTelemetryBinding {
        self.owner
    }

    #[must_use]
    pub const fn installed_key(self) -> PresentationKeyInstallBinding {
        self.installed_key
    }

    #[must_use]
    pub const fn authorized_start_request_id(self) -> u64 {
        self.authorized_start_request_id
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.owner.is_valid()
            && self.installed_key.request_id != 0
            && self.authorized_start_request_id != 0
            && self.owner.request_id == self.authorized_start_request_id
            && self.owner.control_session_id == self.installed_key.control_session_id
            && self.owner.presentation_id == self.installed_key.presentation_id
            && self.owner.stream_id == self.installed_key.stream_id
            && self.owner.epoch == self.installed_key.epoch
    }
}

impl WorkerReceiverTelemetryAuthorization {
    /// Convert a Service-minted grant into exact Worker-local key binding
    /// consistency. An arbitrary caller cannot construct
    /// ReceiverTelemetryWorkerGrant via its private fields, but this method
    /// itself does NOT authenticate the source transport or OS peer.
    #[must_use]
    pub fn from_service_grant(
        grant: ReceiverTelemetryWorkerGrant,
        installed_key: PresentationKeyInstallBinding,
    ) -> Option<Self> {
        let authorized = grant.protected_key_grant();
        if authorized.control_session_id != installed_key.control_session_id
            || authorized.key_grant_request_id != installed_key.request_id
            || authorized.presentation_id != installed_key.presentation_id
            || authorized.stream_id != installed_key.stream_id
            || authorized.epoch != installed_key.epoch
        {
            return None;
        }
        let owner = grant.receiver();
        let permit = Self {
            owner,
            installed_key,
            authorized_start_request_id: owner.request_id,
        };
        permit.is_valid().then_some(permit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationDeliveryPublisherError {
    InvalidAuthorization,
    StaleReceiverGeneration,
    InvalidLocalReport,
    Mailbox(ReceiverTelemetryConcurrentError),
}

/// Read-only, cloneable checkout side of the one-slot diagnostic outbox.
/// A low-priority sender may own this handle on a different thread without
/// locking the Worker decode/render publisher or acquiring an ability to
/// activate, offer, clear or rebind a receiver.
///
/// The atomic generation invalidates handles immediately on revocation,
/// replacement (including failed replacement), and publisher destruction,
/// even when the mailbox mutex is busy. It is NOT an authenticated Service
/// peer or an authorization token: the eventual sender must independently
/// verify its live OS peer and Service-issued receiver identity before I/O.
#[derive(Debug, Clone)]
pub struct PresentationDeliveryReadonlySender {
    mailbox: ReceiverTelemetryConcurrentMailbox,
    active_generation: Arc<AtomicU64>,
}

impl PresentationDeliveryReadonlySender {
    pub fn try_checkout_matching(
        &self,
        receiver: ReceiverTelemetryBinding,
    ) -> Result<Option<ReceiverTelemetrySendLease>, ReceiverTelemetryConcurrentError> {
        let generation = receiver.receiver_generation;
        if generation == 0 || self.active_generation.load(Ordering::Acquire) != generation {
            return Ok(None);
        }
        let lease = self.mailbox.try_checkout_matching(receiver)?;
        if self.active_generation.load(Ordering::Acquire) != generation {
            return Ok(None);
        }
        Ok(lease)
    }

    /// Check again immediately before a nonblocking write; this still does
    /// not prevent a revocation race with I/O or authenticate a remote peer.
    pub fn lease_is_current(
        &self,
        lease: &ReceiverTelemetrySendLease,
    ) -> Result<bool, ReceiverTelemetryConcurrentError> {
        let generation = lease.snapshot().binding.receiver_generation;
        if generation == 0 || self.active_generation.load(Ordering::Acquire) != generation {
            return Ok(false);
        }
        let valid = self.mailbox.try_lease_is_current(lease)?;
        Ok(valid && self.active_generation.load(Ordering::Acquire) == generation)
    }
}

/// One owner of playback counters and a constant-size outbound diagnostic
/// mailbox. It intentionally has no OS pipe or network socket to block.
#[derive(Debug, Default)]
pub struct PresentationDeliveryPublisher {
    active: Option<WorkerReceiverTelemetryAuthorization>,
    highest_receiver_generation: u64,
    tracker: PresentationDeliveryTelemetry,
    mailbox: ReceiverTelemetryConcurrentMailbox,
    active_generation: Arc<AtomicU64>,
}

impl Drop for PresentationDeliveryPublisher {
    fn drop(&mut self) {
        // A detached sender must never retain usable authority after its
        // originating publisher has been destroyed.
        self.active_generation.store(0, Ordering::Release);
    }
}

impl PresentationDeliveryPublisher {
    /// Issue a read-only, shareable handle for future low-priority diagnostic
    /// dispatch. This neither authenticates a sender nor creates an IPC path.
    #[must_use]
    pub fn readonly_sender(&self) -> PresentationDeliveryReadonlySender {
        PresentationDeliveryReadonlySender {
            mailbox: self.mailbox.clone(),
            active_generation: Arc::clone(&self.active_generation),
        }
    }

    /// Only the authorized Service-to-Worker lifecycle controller may call
    /// this after authenticated handoff. Do NOT synthesize authorizations
    /// from Worker media keys, local process state or report bytes.
    pub fn activate_from_service(
        &mut self,
        permit: WorkerReceiverTelemetryAuthorization,
    ) -> Result<(), PresentationDeliveryPublisherError> {
        if !permit.is_valid() {
            return Err(PresentationDeliveryPublisherError::InvalidAuthorization);
        }
        if self.active == Some(permit) {
            return Ok(()); // Exact duplicate activation is idempotent.
        }
        if permit.owner.receiver_generation <= self.highest_receiver_generation {
            return Err(PresentationDeliveryPublisherError::StaleReceiverGeneration);
        }

        // A valid replacement must retire local report authority immediately.
        // If try_lock is busy, no old checked-out lease passes our local
        // lease_is_current check while the caller retries activation.
        self.active_generation.store(0, Ordering::Release);
        self.active = None;
        self.tracker.reset();
        self.mailbox
            .try_activate(permit.owner)
            .map_err(PresentationDeliveryPublisherError::Mailbox)?;
        self.highest_receiver_generation = permit.owner.receiver_generation;
        self.active = Some(permit);
        self.active_generation
            .store(permit.owner.receiver_generation, Ordering::Release);
        Ok(())
    }

    #[must_use]
    pub fn current(&self) -> Option<ReceiverTelemetryBinding> {
        self.active.map(|permit| permit.owner)
    }

    /// Actual receiver decode events only count when they still belong to
    /// the Service-authorized installed key. No fabricated decoder health.
    pub fn accept_decoded(
        &mut self,
        installed_key: PresentationKeyInstallBinding,
        result: PresentationDecodeStep,
    ) -> bool {
        if !self
            .active
            .is_some_and(|permit| permit.installed_key == installed_key)
        {
            return false;
        }
        self.tracker.accept_decoded(installed_key, result);
        true
    }

    pub fn accept_decode_error(&mut self, installed_key: PresentationKeyInstallBinding) -> bool {
        if !self
            .active
            .is_some_and(|permit| permit.installed_key == installed_key)
        {
            return false;
        }
        self.tracker.accept_decode_error(installed_key);
        true
    }

    /// Generate an immutable, already-bound report at the **emission** edge.
    /// None means no receiver/no diagnostic due; Some(true) indicates the
    /// constant-space mailbox replaced an older unsent diagnostic sample.
    /// This never performs a blocking lock, pipe write or network operation.
    pub fn offer_if_due(
        &mut self,
        now: Instant,
        authenticated: WorkerGroupMediaAuthenticationStats,
        receiver_queue_drops: u64,
    ) -> Result<Option<bool>, PresentationDeliveryPublisherError> {
        let Some(permit) = self.active else {
            return Ok(None);
        };
        let Some(report) = self.tracker.report_if_due(
            now,
            permit.installed_key,
            authenticated,
            receiver_queue_drops,
        ) else {
            return Ok(None);
        };
        let snapshot = report
            .snapshot_for_authorized_start(
                permit.owner,
                permit.installed_key,
                permit.authorized_start_request_id,
            )
            .ok_or(PresentationDeliveryPublisherError::InvalidLocalReport)?;
        let replaced = self
            .mailbox
            .try_offer(snapshot)
            .map_err(PresentationDeliveryPublisherError::Mailbox)?;
        Ok(Some(replaced))
    }

    /// The only valid report to check out is for the currently active owner.
    /// A detached checkout cannot be relabelled to a different receiver.
    pub fn try_checkout(
        &self,
    ) -> Result<Option<ReceiverTelemetrySendLease>, PresentationDeliveryPublisherError> {
        let Some(permit) = self.active else {
            return Ok(None);
        };
        self.mailbox
            .try_checkout_matching(permit.owner)
            .map_err(PresentationDeliveryPublisherError::Mailbox)
    }

    /// A sender must repeat this check and also independently verify the
    /// Service-owned runtime with its authenticated peer at the transport
    /// boundary. Local validity alone cannot authorize a remote send.
    pub fn lease_is_current(
        &self,
        lease: &ReceiverTelemetrySendLease,
    ) -> Result<bool, PresentationDeliveryPublisherError> {
        if self.active.map(|permit| permit.owner) != Some(lease.snapshot().binding) {
            return Ok(false);
        }
        self.mailbox
            .try_lease_is_current(lease)
            .map_err(PresentationDeliveryPublisherError::Mailbox)
    }

    /// Exact-match revocation resets counters and disables local checkout
    /// before any nonblocking mailbox cleanup attempt. The local generation
    /// high-watermark never goes backwards, even if cleanup is contended.
    pub fn clear_if_matches(
        &mut self,
        owner: ReceiverTelemetryBinding,
    ) -> Result<bool, PresentationDeliveryPublisherError> {
        if self.active.map(|permit| permit.owner) != Some(owner) {
            return Ok(false);
        }
        self.active_generation.store(0, Ordering::Release);
        self.active = None;
        self.tracker.reset();
        self.mailbox
            .try_clear_if_matches(owner)
            .map_err(PresentationDeliveryPublisherError::Mailbox)?;
        Ok(true)
    }
}

#[cfg(test)]
mod permit_validation_tests {
    use super::*;

    #[test]
    fn inconsistent_internal_permits_cannot_activate_outbox() {
        let installed_key = PresentationKeyInstallBinding {
            control_session_id: 30,
            request_id: 51,
            presentation_id: 40,
            stream_id: 8,
            epoch: 2,
        };
        let binding = ReceiverTelemetryBinding {
            process_id: 501,
            session_id: 7,
            worker_generation: 11,
            control_session_id: 30,
            request_id: 91,
            presentation_id: 40,
            stream_id: 8,
            epoch: 2,
            receiver_generation: 1,
        };
        let valid = WorkerReceiverTelemetryAuthorization {
            owner: binding,
            installed_key,
            authorized_start_request_id: 91,
        };
        assert!(valid.is_valid());
        let mut outbox = PresentationDeliveryPublisher::default();
        outbox.activate_from_service(valid).unwrap();

        let bad_start = WorkerReceiverTelemetryAuthorization {
            authorized_start_request_id: 92,
            ..valid
        };
        assert_eq!(
            outbox.activate_from_service(bad_start),
            Err(PresentationDeliveryPublisherError::InvalidAuthorization)
        );
        let bad_key = WorkerReceiverTelemetryAuthorization {
            installed_key: PresentationKeyInstallBinding {
                epoch: 3,
                ..installed_key
            },
            ..valid
        };
        assert_eq!(
            outbox.activate_from_service(bad_key),
            Err(PresentationDeliveryPublisherError::InvalidAuthorization)
        );
        assert_eq!(outbox.current(), Some(binding));
    }
}
