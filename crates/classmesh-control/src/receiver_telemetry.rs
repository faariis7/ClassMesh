//! Admission and continuity gate for future authenticated receiver playback reports.
//!
//! Caller must first authenticate the Worker transport, verify the process,
//! session, Worker generation, presentation ownership and current receive runtime,
//! then activate that exact binding. A report cannot authorize itself.
//! No packet-loss percentage, RTT or remote quality decision is derived here.
use std::time::{Duration, Instant};

pub const MIN_RECEIVER_TELEMETRY_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_RECEIVER_TELEMETRY_GAP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetryBinding {
    pub process_id: u32,
    pub session_id: u32,
    pub worker_generation: u64,
    pub control_session_id: u64,
    pub request_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
    /// Changes whenever the protected receiver runtime is replaced.
    pub receiver_generation: u64,
}

impl ReceiverTelemetryBinding {
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
            && self.receiver_generation != 0
    }
}

/// All counters are cumulative and have deliberately different meanings.
/// Authentication means a successful AEAD frame open, not video playback.
/// Queue drops are a receiver-runtime lifetime counter, not UDP packet loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverPlaybackCounters {
    pub authenticated_frames: u64,
    pub rejected_frames: u64,
    pub decoded_frames: u64,
    pub presented_frames: u64,
    pub present_errors: u64,
    pub decode_errors: u64,
    pub keyframe_waits: u64,
    pub queue_drops: u64,
}

impl ReceiverPlaybackCounters {
    fn delta_since(self, before: Self, elapsed: Duration) -> Option<ReceiverTelemetryInterval> {
        Some(ReceiverTelemetryInterval {
            elapsed,
            authenticated_frames: self
                .authenticated_frames
                .checked_sub(before.authenticated_frames)?,
            rejected_frames: self.rejected_frames.checked_sub(before.rejected_frames)?,
            decoded_frames: self.decoded_frames.checked_sub(before.decoded_frames)?,
            presented_frames: self.presented_frames.checked_sub(before.presented_frames)?,
            present_errors: self.present_errors.checked_sub(before.present_errors)?,
            decode_errors: self.decode_errors.checked_sub(before.decode_errors)?,
            keyframe_waits: self.keyframe_waits.checked_sub(before.keyframe_waits)?,
            queue_drops: self.queue_drops.checked_sub(before.queue_drops)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetrySnapshot {
    pub binding: ReceiverTelemetryBinding,
    pub sequence: u64,
    pub counters: ReceiverPlaybackCounters,
}

/// These are observation deltas only. This type intentionally has no packet
/// loss, RTT, bandwidth, transport-quality tier or renderer-health verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetryInterval {
    pub elapsed: Duration,
    pub authenticated_frames: u64,
    pub rejected_frames: u64,
    pub decoded_frames: u64,
    pub presented_frames: u64,
    pub present_errors: u64,
    pub decode_errors: u64,
    pub keyframe_waits: u64,
    pub queue_drops: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryDecision {
    /// First valid report, skipped sequence or expired baseline. Do not count
    /// toward consecutive fresh, healthy adaptive-quality observations.
    Baseline,
    Interval(ReceiverTelemetryInterval),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryError {
    InvalidBinding,
    NoActiveBinding,
    BindingMismatch,
    InvalidSequence,
    Replay,
    ClockRegression,
    TooFrequent,
    CounterRegression,
}

/// Constant-space, per-active-receiver admission gate. The Service must own
/// activation and clear it on pipe disconnect, revocation or media teardown.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryGate {
    active: Option<ReceiverTelemetryBinding>,
    last: Option<(ReceiverTelemetrySnapshot, Instant)>,
}

impl ReceiverTelemetryGate {
    /// Only call after checking the real, currently authenticated owner and
    /// Worker generation. Re-activating the same binding never resets replay state.
    pub fn activate(
        &mut self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryError> {
        if !binding.is_valid() {
            return Err(ReceiverTelemetryError::InvalidBinding);
        }
        if self.active != Some(binding) {
            self.active = Some(binding);
            self.last = None;
        }
        Ok(())
    }

    /// A stale clear cannot revoke the replacement presentation/epoch.
    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        if self.active != Some(binding) {
            return false;
        }
        self.active = None;
        self.last = None;
        true
    }

    /// Receive time MUST come from the Service monotonic clock, never from a
    /// Worker-controlled timestamp. Invalid observations do not advance state.
    pub fn observe(
        &mut self,
        sample: ReceiverTelemetrySnapshot,
        received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryError> {
        let Some(active) = self.active else {
            return Err(ReceiverTelemetryError::NoActiveBinding);
        };
        if sample.binding != active {
            return Err(ReceiverTelemetryError::BindingMismatch);
        }
        if sample.sequence == 0 {
            return Err(ReceiverTelemetryError::InvalidSequence);
        }
        let decision = if let Some((previous, previous_at)) = self.last {
            if sample.sequence <= previous.sequence {
                return Err(ReceiverTelemetryError::Replay);
            }
            let elapsed = received_at
                .checked_duration_since(previous_at)
                .ok_or(ReceiverTelemetryError::ClockRegression)?;
            if elapsed < MIN_RECEIVER_TELEMETRY_INTERVAL {
                return Err(ReceiverTelemetryError::TooFrequent);
            }
            let delta = sample
                .counters
                .delta_since(previous.counters, elapsed)
                .ok_or(ReceiverTelemetryError::CounterRegression)?;
            if sample.sequence != previous.sequence.saturating_add(1)
                || elapsed > MAX_RECEIVER_TELEMETRY_GAP
            {
                ReceiverTelemetryDecision::Baseline
            } else {
                ReceiverTelemetryDecision::Interval(delta)
            }
        } else {
            ReceiverTelemetryDecision::Baseline
        };
        self.last = Some((sample, received_at));
        Ok(decision)
    }
}
