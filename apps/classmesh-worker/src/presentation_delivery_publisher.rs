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

use std::time::Instant;

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_transport::{
    ReceiverTelemetryConcurrentError, ReceiverTelemetryConcurrentMailbox,
    ReceiverTelemetrySendLease,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

use crate::group_media_receive::WorkerGroupMediaAuthenticationStats;
use crate::presentation_decode_render::PresentationDecodeStep;
use crate::presentation_delivery_telemetry::PresentationDeliveryTelemetry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerReceiverTelemetryAuthorization {
    pub owner: ReceiverTelemetryBinding,
    pub installed_key: PresentationKeyInstallBinding,
    /// Independently Service-authorized StreamOffer/start request, not key
    /// grant request. This value is not created by the Worker.
    pub authorized_start_request_id: u64,
}

impl WorkerReceiverTelemetryAuthorization {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationDeliveryPublisherError {
    InvalidAuthorization,
    StaleReceiverGeneration,
    InvalidLocalReport,
    Mailbox(ReceiverTelemetryConcurrentError),
}

/// One owner of playback counters and a constant-size outbound diagnostic
/// mailbox. It intentionally has no OS pipe or network socket to block.
#[derive(Debug, Default)]
pub struct PresentationDeliveryPublisher {
    active: Option<WorkerReceiverTelemetryAuthorization>,
    highest_receiver_generation: u64,
    tracker: PresentationDeliveryTelemetry,
    mailbox: ReceiverTelemetryConcurrentMailbox,
}

impl PresentationDeliveryPublisher {
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
        self.active = None;
        self.tracker.reset();
        self.mailbox
            .try_activate(permit.owner)
            .map_err(PresentationDeliveryPublisherError::Mailbox)?;
        self.highest_receiver_generation = permit.owner.receiver_generation;
        self.active = Some(permit);
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
        self.active = None;
        self.tracker.reset();
        self.mailbox
            .try_clear_if_matches(owner)
            .map_err(PresentationDeliveryPublisherError::Mailbox)?;
        Ok(true)
    }
}
