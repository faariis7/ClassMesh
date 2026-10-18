//! A passive byte-ingress boundary for independently verified Worker telemetry.
//!
//! The caller MUST verify the Worker IPC peer, active process/session/generation,
//! presentation ownership and receive generation *before* `activate_verified`.
//! This does not authenticate bytes, install an IPC handler or authorize
//! adaptation: it only prevents decoded envelopes from selecting their owner.
use std::time::Instant;

use crate::receiver_telemetry::{
    ReceiverTelemetryBinding, ReceiverTelemetryDecision, ReceiverTelemetryError,
    ReceiverTelemetryGate,
};
use crate::receiver_telemetry_transport::{
    ReceiverTelemetryWireError, decode_receiver_telemetry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryIngressError {
    Wire(ReceiverTelemetryWireError),
    Admission(ReceiverTelemetryError),
}

#[derive(Debug, Default)]
pub struct ReceiverTelemetryIngress {
    gate: ReceiverTelemetryGate,
}

impl ReceiverTelemetryIngress {
    /// Only the authoritative Service owner may call this after independently
    /// verifying the actual Worker transport and current presentation lifecycle.
    pub fn activate_verified(
        &mut self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryError> {
        self.gate.activate(binding)
    }

    /// A stale lifecycle completion cannot clear a newer media binding.
    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        self.gate.clear_if_matches(binding)
    }

    /// Decodes a strict envelope, then checks its identity and replay/counter
    /// continuity against a Service-activated binding. `received_at` must come
    /// from the Service's monotonic clock, not from decoded Worker bytes.
    pub fn observe_verified(
        &mut self,
        bytes: &[u8],
        received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryIngressError> {
        let sample = decode_receiver_telemetry(bytes).map_err(ReceiverTelemetryIngressError::Wire)?;
        self.gate
            .observe(sample, received_at)
            .map_err(ReceiverTelemetryIngressError::Admission)
    }

    /// Read-only report liveness; does not prove stream quality or authorize a
    /// Teacher quality promotion. Must not bypass the external trust boundary.
    #[must_use]
    pub fn has_fresh_report(&self, now: Instant) -> bool {
        self.gate.has_fresh_report(now)
    }
}
