//! Passive, atomic composition of Service-owned receiver lifetimes and
//! authenticated-worker telemetry ingress. No live IPC, transport, new
//! protocol message or adaptive-quality state exists in this module.
//!
//! Every method suffixed `verified_peer` assumes the caller **independently**
//! read the actual authenticated Windows named-pipe peer and current
//! Service-managed Worker generation. Never use Worker report bytes as proof
//! of the caller's identity. Service lifecycle mutations and ingress must be
//! serialized by their real owner; an arbitrary copy of these inputs does
//! not establish authorization or rule out external concurrent revocation.

use std::time::Instant;

use crate::receiver_telemetry::{ReceiverTelemetryBinding, ReceiverTelemetryDecision};
use crate::receiver_telemetry_ingress::{ReceiverTelemetryIngress, ReceiverTelemetryIngressError};
use crate::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryServiceLifecycle,
    ReceiverTelemetryServiceLifecycleError, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryServiceAdmissionError {
    NoActiveRuntime,
    WorkerMismatch,
    Ingress(ReceiverTelemetryIngressError),
}

/// Single in-process owner for one protected receiver-runtime slot.
/// Both admission and lifetime replacement/revocation happen here, so
/// neither can inadvertently keep an obsolete binding in use.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryServiceAdmission {
    lifecycle: ReceiverTelemetryServiceLifecycle,
    ingress: ReceiverTelemetryIngress,
}

impl ReceiverTelemetryServiceAdmission {
    /// Service-only: invoke after a correlated and authorized receiver start.
    /// Current peer must come from Windows OS IPC checks and WorkerManager,
    /// pending must come from the authorized protected media grant, and reply
    /// must be the existing authenticated start ACK from that same Worker.
    pub fn activate_after_correlated_reply(
        &mut self,
        pending: ReceiverTelemetryStart,
        current_worker: ReceiverTelemetryCurrentWorker,
        reply: ReceiverTelemetryStartAck,
    ) -> Result<ReceiverTelemetryBinding, ReceiverTelemetryServiceLifecycleError> {
        let binding =
            self.lifecycle
                .activate_after_correlated_reply(pending, current_worker, reply)?;

        // The lifecycle just constructed a valid, nonzero binding, so this
        // admission error branch is unreachable under normal contracts.
        // Fail closed and revoke the just-created lifetime if that invariant
        // should change in a future refactor.
        if self.ingress.activate_verified(binding).is_err() {
            self.lifecycle.clear_if_matches(binding);
            return Err(ReceiverTelemetryServiceLifecycleError::InvalidBinding);
        }
        Ok(binding)
    }

    #[must_use]
    pub fn current(&self) -> Option<ReceiverTelemetryBinding> {
        self.lifecycle.current()
    }

    /// Exact-match teardown clears both the current runtime and its
    /// diagnostic sample/replay state. Stale teardown cannot revoke a new
    /// runtime even when the media-key epoch was reused.
    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        if !self.lifecycle.clear_if_matches(binding) {
            return false;
        }
        self.ingress.clear_if_matches(binding);
        true
    }

    /// Admit a single bounded byte report only when the OS-verified currently
    /// running Worker is the same Worker that owns this Service runtime.
    /// The exact 9-field receiver identity is taken from the Service ledger,
    /// NEVER supplied by the payload or caller.
    pub fn observe_after_verified_peer(
        &mut self,
        current_worker: ReceiverTelemetryCurrentWorker,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryServiceAdmissionError> {
        let binding = self.verify_worker_matches_active(current_worker)?;
        self.ingress
            .observe_for_current_owner(binding, bytes, service_received_at)
            .map_err(ReceiverTelemetryServiceAdmissionError::Ingress)
    }

    /// Read-only *diagnostic* liveness, not an adaptive-quality sample.
    #[must_use]
    pub fn has_fresh_for_verified_peer(
        &self,
        current_worker: ReceiverTelemetryCurrentWorker,
        service_now: Instant,
    ) -> bool {
        self.verify_worker_matches_active(current_worker)
            .is_ok_and(|binding| {
                self.ingress
                    .has_fresh_for_current_owner(binding, service_now)
            })
    }

    fn verify_worker_matches_active(
        &self,
        current_worker: ReceiverTelemetryCurrentWorker,
    ) -> Result<ReceiverTelemetryBinding, ReceiverTelemetryServiceAdmissionError> {
        let binding = self
            .lifecycle
            .current()
            .ok_or(ReceiverTelemetryServiceAdmissionError::NoActiveRuntime)?;
        if current_worker.process_id != binding.process_id
            || current_worker.session_id != binding.session_id
            || current_worker.worker_generation != binding.worker_generation
        {
            return Err(ReceiverTelemetryServiceAdmissionError::WorkerMismatch);
        }
        Ok(binding)
    }
}
