//! Local, per-session playback diagnostics. No IPC or network reports are sent.
use crate::group_media_receive::WorkerGroupMediaAuthenticationStats;
#[cfg(test)]
use crate::presentation_decode_render::PresentationDecodeBatch;
use crate::presentation_decode_render::PresentationDecodeStep;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Only the single healthy receiver already verified against the active key
/// binding may supply queue counters. `None` means absent, failed or mismatched.
/// Never invent zero drops, nor prefer multicast when two paths conflict.
#[must_use]
pub const fn single_exact_receiver_queue_drops(
    multicast: Option<u64>,
    unicast: Option<u64>,
) -> Option<u64> {
    match (multicast, unicast) {
        (Some(drops), None) | (None, Some(drops)) => Some(drops),
        _ => None,
    }
}

/// Counter snapshot for the *local* Worker playback path. Decoded output is
/// distinct from frames successfully presented on screen or authenticated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationDeliveryReport {
    /// Monotonic per exact installed presentation binding; local only until IPC is qualified.
    pub sample_sequence: u64,
    pub authenticated_frames: u64,
    pub auth_rejected_frames: u64,
    pub decoded_frames: u64,
    pub presented_frames: u64,
    pub present_errors: u64,
    pub decode_errors: u64,
    pub waiting_for_keyframe: u64,
    /// Queue drops from the receiver runtime's own lifetime counter.
    pub receiver_queue_drops: u64,
}

#[derive(Debug, Default)]
pub struct PresentationDeliveryTelemetry {
    binding: Option<PresentationKeyInstallBinding>,
    last_report_at: Option<Instant>,
    report_sequence: u64,
    /// Last successfully emitted cumulative counters, in the same receiver lifetime.
    last_external: Option<(u64, u64, u64)>,
    /// Once a source counter resets under the same binding, do not issue a new
    /// sequence or pretend the measurement is continuous.
    external_counter_regression: bool,
    decoded_frames: u64,
    presented_frames: u64,
    present_errors: u64,
    decode_errors: u64,
    waiting_for_keyframe: u64,
}

impl PresentationDeliveryTelemetry {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn track_binding(&mut self, binding: PresentationKeyInstallBinding, now: Instant) {
        if self.binding != Some(binding) {
            self.reset();
            self.binding = Some(binding);
            self.last_report_at = Some(now);
        }
    }

    pub fn accept_decoded(
        &mut self,
        binding: PresentationKeyInstallBinding,
        outcome: PresentationDecodeStep,
    ) {
        self.track_binding(binding, Instant::now());
        match outcome {
            PresentationDecodeStep::Decoded(batch) => {
                self.decoded_frames = self.decoded_frames.saturating_add(batch.decoded as u64);
                self.presented_frames =
                    self.presented_frames.saturating_add(batch.presented as u64);
                self.present_errors = self
                    .present_errors
                    .saturating_add(batch.present_errors as u64);
            }
            PresentationDecodeStep::WaitingForKeyframe => {
                self.waiting_for_keyframe = self.waiting_for_keyframe.saturating_add(1);
            }
        }
    }

    pub fn accept_decode_error(&mut self, binding: PresentationKeyInstallBinding) {
        self.track_binding(binding, Instant::now());
        self.decode_errors = self.decode_errors.saturating_add(1);
    }

    pub fn report_if_due(
        &mut self,
        now: Instant,
        binding: PresentationKeyInstallBinding,
        authenticated: WorkerGroupMediaAuthenticationStats,
        receiver_queue_drops: u64,
    ) -> Option<PresentationDeliveryReport> {
        self.track_binding(binding, now);
        let last = self.last_report_at?;
        if now.checked_duration_since(last)? < REPORT_INTERVAL {
            return None;
        }
        if self.external_counter_regression {
            return None;
        }
        let external = (
            authenticated.opened_frames,
            authenticated.rejected_frames,
            receiver_queue_drops,
        );
        if self.last_external.is_some_and(|before| {
            external.0 < before.0 || external.1 < before.1 || external.2 < before.2
        }) {
            // A hidden receiver/authentication runtime replacement with the
            // same key identity cannot replay sequence 1 or forge a delta.
            // Require explicit pipeline reset or exact binding replacement.
            self.external_counter_regression = true;
            return None;
        }
        // On exhaustion, fail closed rather than emitting a replayed sequence.
        let next_sequence = self.report_sequence.checked_add(1)?;
        self.report_sequence = next_sequence;
        self.last_report_at = Some(now);
        self.last_external = Some(external);
        Some(PresentationDeliveryReport {
            sample_sequence: next_sequence,
            authenticated_frames: authenticated.opened_frames,
            auth_rejected_frames: authenticated.rejected_frames,
            decoded_frames: self.decoded_frames,
            presented_frames: self.presented_frames,
            present_errors: self.present_errors,
            decode_errors: self.decode_errors,
            waiting_for_keyframe: self.waiting_for_keyframe,
            receiver_queue_drops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(epoch: u32) -> PresentationKeyInstallBinding {
        PresentationKeyInstallBinding {
            control_session_id: 7,
            request_id: 9,
            presentation_id: 11,
            stream_id: 13,
            epoch,
        }
    }

    #[test]
    fn trusted_opens_and_decode_outputs_stay_distinct() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let at = Instant::now();
        tracker.accept_decoded(
            binding(1),
            PresentationDecodeStep::Decoded(PresentationDecodeBatch {
                decoded: 3,
                presented: 2,
                present_errors: 1,
            }),
        );
        tracker.accept_decoded(binding(1), PresentationDecodeStep::WaitingForKeyframe);
        tracker.accept_decode_error(binding(1));
        let report = tracker
            .report_if_due(
                at + Duration::from_secs(6),
                binding(1),
                WorkerGroupMediaAuthenticationStats {
                    opened_frames: 6,
                    rejected_frames: 2,
                },
                4,
            )
            .unwrap();
        assert_eq!(report.sample_sequence, 1);
        assert_eq!(report.authenticated_frames, 6);
        assert_eq!(report.auth_rejected_frames, 2);
        assert_eq!(report.decoded_frames, 3);
        assert_eq!(report.presented_frames, 2);
        assert_eq!(report.present_errors, 1);
        assert_eq!(report.waiting_for_keyframe, 1);
        assert_eq!(report.decode_errors, 1);
        assert_eq!(report.receiver_queue_drops, 4);
        assert!(
            tracker
                .report_if_due(
                    at + Duration::from_secs(7),
                    binding(1),
                    WorkerGroupMediaAuthenticationStats::default(),
                    4
                )
                .is_none()
        );
    }

    #[test]
    fn epoch_change_restarts_all_delivery_counts_and_cadence() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let at = Instant::now();
        tracker.accept_decoded(
            binding(1),
            PresentationDecodeStep::Decoded(PresentationDecodeBatch {
                decoded: 7,
                presented: 6,
                present_errors: 0,
            }),
        );
        assert!(
            tracker
                .report_if_due(
                    at + Duration::from_secs(1),
                    binding(2),
                    WorkerGroupMediaAuthenticationStats::default(),
                    0
                )
                .is_none()
        );
        let report = tracker
            .report_if_due(
                at + Duration::from_secs(7),
                binding(2),
                WorkerGroupMediaAuthenticationStats {
                    opened_frames: 2,
                    rejected_frames: 0,
                },
                0,
            )
            .unwrap();
        assert_eq!(report.sample_sequence, 1);
        assert_eq!(report.decoded_frames, 0);
        assert_eq!(report.presented_frames, 0);
        assert_eq!(report.authenticated_frames, 2);
        tracker.reset();
        assert!(
            tracker
                .report_if_due(
                    at + Duration::from_secs(30),
                    binding(3),
                    WorkerGroupMediaAuthenticationStats::default(),
                    0
                )
                .is_none()
        );
    }

    #[test]
    fn bounded_reporting_never_claims_decryption_or_presentation_on_wait() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let at = Instant::now();
        tracker.accept_decoded(binding(1), PresentationDecodeStep::WaitingForKeyframe);
        let report = tracker
            .report_if_due(
                at + Duration::from_secs(6),
                binding(1),
                WorkerGroupMediaAuthenticationStats {
                    opened_frames: 1,
                    rejected_frames: 1,
                },
                3,
            )
            .unwrap();
        assert_eq!((report.decoded_frames, report.presented_frames), (0, 0));
        assert_eq!(report.waiting_for_keyframe, 1);
    }

    #[test]
    fn telemetry_sequence_advances_only_on_due_report_and_resets_per_epoch() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let at = Instant::now();
        let auth = WorkerGroupMediaAuthenticationStats::default();
        assert!(tracker.report_if_due(at, binding(1), auth, 0).is_none());
        let first = tracker
            .report_if_due(at + Duration::from_secs(5), binding(1), auth, 0)
            .unwrap();
        assert_eq!(first.sample_sequence, 1);
        assert!(
            tracker
                .report_if_due(at + Duration::from_secs(6), binding(1), auth, 0)
                .is_none()
        );
        let second = tracker
            .report_if_due(at + Duration::from_secs(10), binding(1), auth, 0)
            .unwrap();
        assert_eq!(second.sample_sequence, 2);
        assert!(
            tracker
                .report_if_due(at + Duration::from_secs(11), binding(2), auth, 0)
                .is_none()
        );
        let replacement = tracker
            .report_if_due(at + Duration::from_secs(16), binding(2), auth, 0)
            .unwrap();
        assert_eq!(replacement.sample_sequence, 1);
        tracker.reset();
        assert!(
            tracker
                .report_if_due(at + Duration::from_secs(17), binding(2), auth, 0)
                .is_none()
        );
        assert_eq!(
            tracker
                .report_if_due(at + Duration::from_secs(22), binding(2), auth, 0)
                .unwrap()
                .sample_sequence,
            1
        );
    }

    #[test]
    fn telemetry_drops_only_come_from_exactly_one_verified_receiver() {
        assert_eq!(
            super::single_exact_receiver_queue_drops(Some(8), None),
            Some(8)
        );
        assert_eq!(
            super::single_exact_receiver_queue_drops(None, Some(13)),
            Some(13)
        );
        // No active matched runtime cannot supply an invented zero-drop report.
        assert_eq!(super::single_exact_receiver_queue_drops(None, None), None);
        // Two simultaneously matching runtimes cannot arbitrarily pick one.
        assert_eq!(
            super::single_exact_receiver_queue_drops(Some(8), Some(13)),
            None
        );
    }

    #[test]
    fn telemetry_drops_allow_zero_only_from_a_verified_receiver() {
        assert_eq!(
            super::single_exact_receiver_queue_drops(Some(0), None),
            Some(0)
        );
        assert_eq!(
            super::single_exact_receiver_queue_drops(None, Some(0)),
            Some(0)
        );
        assert_eq!(super::single_exact_receiver_queue_drops(None, None), None);
    }

    #[test]
    fn external_auth_counter_reset_latches_fail_closed_until_binding_changes() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let start = Instant::now();
        let auth = |opened_frames, rejected_frames| WorkerGroupMediaAuthenticationStats {
            opened_frames,
            rejected_frames,
        };
        assert!(tracker.report_if_due(start, binding(1), auth(0, 0), 0).is_none());
        let first = tracker
            .report_if_due(start + Duration::from_secs(5), binding(1), auth(7, 2), 4)
            .unwrap();
        assert_eq!(first.sample_sequence, 1);
        assert!(tracker
            .report_if_due(start + Duration::from_secs(10), binding(1), auth(6, 2), 5)
            .is_none());
        assert_eq!(tracker.report_sequence, 1);
        // Larger later totals cannot conceal a reset of the same lifetime counters.
        assert!(tracker
            .report_if_due(start + Duration::from_secs(15), binding(1), auth(20, 4), 8)
            .is_none());
        assert_eq!(tracker.report_sequence, 1);
        // Only an explicitly new key binding (or an existing runtime reset) can
        // establish a new sequence/baseline; no old sequence is replayed.
        assert!(tracker
            .report_if_due(start + Duration::from_secs(16), binding(2), auth(0, 0), 0)
            .is_none());
        let fresh = tracker
            .report_if_due(start + Duration::from_secs(21), binding(2), auth(1, 0), 0)
            .unwrap();
        assert_eq!(fresh.sample_sequence, 1);
    }

    #[test]
    fn rejected_auth_and_receiver_drop_counter_resets_also_fail_closed() {
        let start = Instant::now();
        for (opened, rejected, drops) in [(9, 2, 8), (9, 4, 7)] {
            let mut tracker = PresentationDeliveryTelemetry::default();
            let auth = |opened_frames, rejected_frames| WorkerGroupMediaAuthenticationStats {
                opened_frames,
                rejected_frames,
            };
            assert!(tracker.report_if_due(start, binding(1), auth(0, 0), 0).is_none());
            assert!(tracker
                .report_if_due(start + Duration::from_secs(5), binding(1), auth(8, 4), 8)
                .is_some());
            assert!(tracker
                .report_if_due(start + Duration::from_secs(10), binding(1), auth(opened, rejected), drops)
                .is_none());
            assert_eq!(tracker.report_sequence, 1);
        }
    }

    #[test]
    fn telemetry_sequence_overflow_stops_reporting_without_replaying_a_number() {
        let mut tracker = PresentationDeliveryTelemetry::default();
        let at = Instant::now();
        let auth = WorkerGroupMediaAuthenticationStats::default();
        assert!(tracker.report_if_due(at, binding(1), auth, 0).is_none());
        tracker.report_sequence = u64::MAX - 1;
        assert_eq!(
            tracker
                .report_if_due(at + Duration::from_secs(5), binding(1), auth, 0)
                .unwrap()
                .sample_sequence,
            u64::MAX
        );
        assert!(
            tracker
                .report_if_due(at + Duration::from_secs(10), binding(1), auth, 0)
                .is_none()
        );
    }
}
