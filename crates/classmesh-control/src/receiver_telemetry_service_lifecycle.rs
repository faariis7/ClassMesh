//! Service-owned, strictly monotonic receiver-runtime generations.
//!
//! This ledger is a passive, in-process building block for eventual
//! authenticated Worker-to-Service telemetry. The caller MUST independently
//! verify the OS-observed Worker process/session, Service Worker generation,
//! matching authorized presentation start and actual receiver start result.
//! Do not populate fields from untrusted telemetry bytes or infer a running
//! Worker from this ledger alone. This module introduces no IPC or sender.

use crate::receiver_telemetry::ReceiverTelemetryBinding;

/// Fields verified by the Service after a successful protected receiver start.
/// Deliberately no caller-selected receiver generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetryStart {
    pub process_id: u32,
    pub session_id: u32,
    pub worker_generation: u64,
    pub control_session_id: u64,
    pub request_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}

impl ReceiverTelemetryStart {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.process_id != 0
            && self.session_id != 0
            && self.worker_generation != 0
            && self.control_session_id != 0
            && self.request_id != 0
            && self.presentation_id != 0
            && self.stream_id != 0
            && self.epoch != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryServiceLifecycleError {
    InvalidBinding,
    GenerationExhausted,
}

/// Single authoritative ledger for one Service-owned receive slot.
/// Generation survives revocation, so a reused media-key epoch cannot
/// accidentally resurrect reports from a previous receiver runtime.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryServiceLifecycle {
    last_issued_generation: u64,
    active: Option<ReceiverTelemetryBinding>,
}

impl ReceiverTelemetryServiceLifecycle {
    /// Call only after separately authenticating the active Worker and
    /// correlating a successful receiver start to the pending authorized
    /// media request. Even a retry using the same key gets a new generation.
    pub fn activate_after_verified_start(
        &mut self,
        start: ReceiverTelemetryStart,
    ) -> Result<ReceiverTelemetryBinding, ReceiverTelemetryServiceLifecycleError> {
        if !start.is_valid() {
            return Err(ReceiverTelemetryServiceLifecycleError::InvalidBinding);
        }
        let Some(next) = self.last_issued_generation.checked_add(1) else {
            self.active = None;
            return Err(ReceiverTelemetryServiceLifecycleError::GenerationExhausted);
        };
        let binding = ReceiverTelemetryBinding {
            process_id: start.process_id,
            session_id: start.session_id,
            worker_generation: start.worker_generation,
            control_session_id: start.control_session_id,
            request_id: start.request_id,
            presentation_id: start.presentation_id,
            stream_id: start.stream_id,
            epoch: start.epoch,
            receiver_generation: next,
        };
        self.last_issued_generation = next;
        self.active = Some(binding);
        Ok(binding)
    }

    /// Read-only snapshot; callers MUST still check the live authenticated
    /// OS peer before admitting a telemetry frame.
    #[must_use]
    pub const fn current(&self) -> Option<ReceiverTelemetryBinding> {
        self.active
    }

    /// Exact-match teardown cannot revoke the replacement lifetime.
    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        if self.active != Some(binding) {
            return false;
        }
        self.active = None;
        true
    }

    /// A comparison against a *separately verified* current peer. Merely
    /// calling this function is NOT peer authentication.
    #[must_use]
    pub fn is_current_after_verified_peer(&self, binding: ReceiverTelemetryBinding) -> bool {
        binding.is_valid() && self.active == Some(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_generation_never_wraps_and_revokes_old_owner() {
        let original = ReceiverTelemetryStart {
            process_id: 1,
            session_id: 2,
            worker_generation: 3,
            control_session_id: 4,
            request_id: 5,
            presentation_id: 6,
            stream_id: 7,
            epoch: 8,
        };
        let mut ledger = ReceiverTelemetryServiceLifecycle {
            last_issued_generation: u64::MAX - 1,
            active: None,
        };
        let max = ledger.activate_after_verified_start(original).unwrap();
        assert_eq!(max.receiver_generation, u64::MAX);
        assert_eq!(
            ledger.activate_after_verified_start(original),
            Err(ReceiverTelemetryServiceLifecycleError::GenerationExhausted)
        );
        assert!(ledger.current().is_none());
        assert!(!ledger.is_current_after_verified_peer(max));
        assert!(!ledger.clear_if_matches(max));
        assert_eq!(
            ledger.activate_after_verified_start(original),
            Err(ReceiverTelemetryServiceLifecycleError::GenerationExhausted)
        );
    }
}
