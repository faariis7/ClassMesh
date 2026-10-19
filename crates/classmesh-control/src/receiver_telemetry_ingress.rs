//! Passive, byte-oriented receiver telemetry admission for a Service-verified Worker.
//!
//! The caller owns authentication, peer process/session verification, and exact
//! media binding activation. Parsing bytes is not proof of their origin.
//! This adds no IPC message, threads, network sender or quality promotion.
use std::time::Instant;

use crate::receiver_telemetry::{
    ReceiverTelemetryBinding, ReceiverTelemetryDecision, ReceiverTelemetryError,
    ReceiverTelemetryGate,
};
use crate::receiver_telemetry_transport::{ReceiverTelemetryWireError, decode_receiver_telemetry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryIngressError {
    Wire(ReceiverTelemetryWireError),
    Admission(ReceiverTelemetryError),
}

/// One bounded telemetry admission gate per independently verified Worker.
/// A payload must never activate itself or change the bound identity.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryIngress {
    gate: ReceiverTelemetryGate,
}

impl ReceiverTelemetryIngress {
    /// Must be called only after independent transport and lifecycle checks.
    pub fn activate_verified(
        &mut self,
        verified_binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryError> {
        self.gate.activate(verified_binding)
    }

    /// Exact binding revocation prevents a stale teardown from clearing a replacement.
    pub fn clear_if_matches(&mut self, verified_binding: ReceiverTelemetryBinding) -> bool {
        self.gate.clear_if_matches(verified_binding)
    }

    /// Parse the strictly bounded diagnostic bytes, then apply current binding,
    /// replay, interval, monotonic-clock and counter checks. Arrival time is
    /// Service-owned, never supplied by the Worker.
    pub fn observe_verified(
        &mut self,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryIngressError> {
        let snapshot =
            decode_receiver_telemetry(bytes).map_err(ReceiverTelemetryIngressError::Wire)?;
        self.gate
            .observe(snapshot, service_received_at)
            .map_err(ReceiverTelemetryIngressError::Admission)
    }

    /// Prefer this per-report guard when a Service has separately and
    /// synchronously authenticated its actual current Worker, session and
    /// receiver-runtime generation. It fails closed BEFORE parsing bytes if
    /// the formerly activated gate does not match that live authority.
    ///
    /// This comparison does not authenticate its argument, pin a concurrent
    /// process lifetime or add any transport; the Service must retain the
    /// independently verified owner across the entire receive operation.
    pub fn observe_for_current_owner(
        &mut self,
        service_current_owner: ReceiverTelemetryBinding,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryIngressError> {
        self.gate
            .verify_current_owner(service_current_owner)
            .map_err(ReceiverTelemetryIngressError::Admission)?;
        self.observe_verified(bytes, service_received_at)
    }

    /// Read-only diagnostic liveness is meaningful only for a still-current
    /// independently verified Service owner, never for a stale gate binding.
    #[must_use]
    pub fn has_fresh_for_current_owner(
        &self,
        service_current_owner: ReceiverTelemetryBinding,
        service_now: Instant,
    ) -> bool {
        self.gate
            .verify_current_owner(service_current_owner)
            .is_ok()
            && self.gate.has_fresh_report(service_now)
    }

    /// Observability only, never sufficient for promoting quality.
    #[must_use]
    pub fn has_fresh_report(&self, service_now: Instant) -> bool {
        self.gate.has_fresh_report(service_now)
    }
}
