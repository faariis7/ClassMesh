//! Source-bound read-only Teacher UI projection of already authenticated
//! playback reports. This is NEVER a QUIC authentication or quality sample.
use std::time::{Duration, Instant};

use classmesh_control::teacher_playback_receive::AuthenticatedTeacherControlMessage;
use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::receiver_playback_diagnostics::{
    TeacherPlaybackBinding, TeacherPlaybackCounters, TeacherPlaybackDiagnosticError,
    TeacherPlaybackDiagnosticLedger,
};

/// Hide the last report if the authenticated channel stops delivering.
/// The native sender is approximately five seconds per report.
pub const MAX_PLAYBACK_UI_AGE: Duration = Duration::from_secs(10);

/// A UI presentation boundary, NOT a network or PrincipalId verifier.
/// Call accept only after the actual authenticated QUIC connection verifies
/// the enrolled Service, exact control-session and negotiated capability.
#[derive(Debug)]
pub struct TeacherPlaybackUiProjection {
    source_id: MonitoringSourceId,
    binding: TeacherPlaybackBinding,
    ledger: TeacherPlaybackDiagnosticLedger,
    received_at: Option<Instant>,
}
impl TeacherPlaybackUiProjection {
    pub fn new(
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    ) -> Result<Self, TeacherPlaybackDiagnosticError> {
        Ok(Self {
            source_id,
            binding,
            ledger: TeacherPlaybackDiagnosticLedger::new(binding)?,
            received_at: None,
        })
    }

    #[must_use]
    pub const fn source_id(&self) -> MonitoringSourceId {
        self.source_id
    }

    #[must_use]
    pub const fn binding(&self) -> TeacherPlaybackBinding {
        self.binding
    }

    /// Only an already authenticated and enrolled QUIC receive result may
    /// enter the public Teacher projection. The explicitly mapped source
    /// must equal this projection's selected device before replay/freshness
    /// state is mutated. Other control envelopes are never playback samples.
    pub fn accept_verified_from_source(
        &mut self,
        source_id: MonitoringSourceId,
        verified: &AuthenticatedTeacherControlMessage,
        now: Instant,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
        if source_id != self.source_id {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        let envelope = verified
            .receiver_playback()
            .ok_or(TeacherPlaybackDiagnosticError::Malformed)?;
        self.accept_authenticated(envelope, true, now)
    }

    /// Internal replay and payload gate, only called directly from tests or
    /// an already verified boundary. NOT a public network authentication API.
    pub(crate) fn accept_authenticated(
        &mut self,
        envelope: &ControlEnvelope,
        capability_negotiated: bool,
        now: Instant,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
        // Check before mutating the ledger: a backward local receive clock
        // must not consume a valid sequence or replace newer counters.
        if self.received_at.is_some_and(|previous| now < previous) {
            return Err(TeacherPlaybackDiagnosticError::ClockRegression);
        }
        let accepted = self
            .ledger
            .accept_from_authenticated_control(envelope, capability_negotiated)?;
        self.received_at = Some(now);
        Ok(accepted)
    }

    /// Never surface a counter sample for a different selected device, an
    /// expired observation or a time before the authenticated reception.
    /// This never modifies network quality, transport topology or defaults.
    #[must_use]
    pub fn visible(
        &self,
        selected_source: MonitoringSourceId,
        now: Instant,
    ) -> Option<TeacherPlaybackCounters> {
        if selected_source != self.source_id
            || !self
                .received_at
                .is_some_and(|at| now >= at && now.duration_since(at) <= MAX_PLAYBACK_UI_AGE)
        {
            return None;
        }
        self.ledger.current()
    }

    /// Schedule exactly one UI repaint just after the visible report
    /// expires. egui is event-driven: hiding stale counters during normal
    /// rendering is insufficient if no new input wakes the UI. This hint
    /// never keeps a revoked, future-dated, expired or other-source report
    /// alive and never drives network quality decisions.
    #[must_use]
    pub fn repaint_after_expiry(
        &self,
        selected_source: MonitoringSourceId,
        now: Instant,
    ) -> Option<Duration> {
        self.visible(selected_source, now)?;
        let received = self.received_at?;
        let age = now.duration_since(received);
        Some(MAX_PLAYBACK_UI_AGE - age + Duration::from_millis(1))
    }

    /// A stale disconnect cannot revoke another device or control session.
    pub fn revoke(
        &mut self,
        source_id: MonitoringSourceId,
        exact_binding: TeacherPlaybackBinding,
    ) -> bool {
        if source_id != self.source_id || exact_binding != self.binding {
            return false;
        }
        let revoked = self.ledger.revoke(exact_binding);
        if revoked {
            self.received_at = None;
        }
        revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::{
        ControlEnvelope, ProtocolVersion, ReceiverPlaybackDiagnostic, control_envelope,
    };

    fn binding() -> TeacherPlaybackBinding {
        TeacherPlaybackBinding {
            control_session_id: 11,
            presentation_id: 12,
            stream_id: 13,
            epoch: 14,
        }
    }
    fn envelope() -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 11,
            sequence: 21,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 8 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(
                ReceiverPlaybackDiagnostic {
                    presentation_id: 12,
                    stream_id: 13,
                    epoch: 14,
                    receiver_generation: 15,
                    sequence: 16,
                    interval_ms: 5000,
                    authenticated_frames: 100,
                    rejected_frames: 1,
                    decoded_frames: 90,
                    presented_frames: 89,
                    present_errors: 2,
                    decode_errors: 3,
                    keyframe_waits: 4,
                    queue_drops: 5,
                },
            )),
        }
    }

    #[test]
    fn source_id_requires_verified_quic_message_not_bare_envelope() {
        use classmesh_control::teacher_playback_receive::AuthenticatedTeacherControlMessage;
        let _accept: fn(
            &mut TeacherPlaybackUiProjection,
            MonitoringSourceId,
            &AuthenticatedTeacherControlMessage,
            Instant,
        )
            -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> =
            TeacherPlaybackUiProjection::accept_verified_from_source;
    }

    #[test]
    fn schedules_expiry_repaint_only_for_visible_exact_source_and_fresh_counters() {
        let now = Instant::now();
        let mut state = TeacherPlaybackUiProjection::new(MonitoringSourceId(7), binding()).unwrap();
        assert_eq!(state.repaint_after_expiry(MonitoringSourceId(7), now), None);
        let mut initial = envelope();
        state.accept_authenticated(&initial, true, now).unwrap();
        let safety_tick = Duration::from_millis(1);
        assert_eq!(
            state.repaint_after_expiry(MonitoringSourceId(7), now),
            Some(MAX_PLAYBACK_UI_AGE + safety_tick)
        );
        assert_eq!(
            state.repaint_after_expiry(MonitoringSourceId(7), now + Duration::from_secs(4)),
            Some(Duration::from_secs(6) + safety_tick)
        );
        assert_eq!(state.repaint_after_expiry(MonitoringSourceId(8), now), None);
        assert_eq!(
            state.repaint_after_expiry(MonitoringSourceId(7), now - Duration::from_millis(1)),
            None
        );
        assert_eq!(
            state.repaint_after_expiry(
                MonitoringSourceId(7),
                now + MAX_PLAYBACK_UI_AGE + safety_tick
            ),
            None
        );
        initial.sequence += 1;
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut report)) =
            initial.payload
        {
            report.sequence += 1;
        }
        state
            .accept_authenticated(&initial, true, now + Duration::from_secs(6))
            .unwrap();
        assert_eq!(
            state.repaint_after_expiry(MonitoringSourceId(7), now + Duration::from_secs(6)),
            Some(MAX_PLAYBACK_UI_AGE + safety_tick)
        );
        assert!(state.revoke(MonitoringSourceId(7), binding()));
        assert_eq!(state.repaint_after_expiry(MonitoringSourceId(7), now), None);
    }

    #[test]
    fn source_bound_projection_shows_only_fresh_authenticated_exact_session_counters() {
        let now = Instant::now();
        let mut state = TeacherPlaybackUiProjection::new(MonitoringSourceId(7), binding()).unwrap();
        assert_eq!(state.visible(MonitoringSourceId(7), now), None);
        let sample = state.accept_authenticated(&envelope(), true, now).unwrap();
        assert_eq!(sample.presented_frames, 89);
        assert_eq!(state.visible(MonitoringSourceId(7), now), Some(sample));
        assert_eq!(state.visible(MonitoringSourceId(8), now), None);
        assert_eq!(
            state.visible(MonitoringSourceId(7), now + MAX_PLAYBACK_UI_AGE),
            Some(sample)
        );
        assert_eq!(
            state.visible(
                MonitoringSourceId(7),
                now + MAX_PLAYBACK_UI_AGE + Duration::from_nanos(1)
            ),
            None
        );
        // Windows clocks may not represent a one-nanosecond subtraction.
        // Always test an earlier representable instant and retain the
        // one-nanosecond assertion when the platform can distinguish it.
        assert_eq!(
            state.visible(MonitoringSourceId(7), now - Duration::from_millis(1)),
            None
        );
        let just_before = now - Duration::from_nanos(1);
        if just_before < now {
            assert_eq!(state.visible(MonitoringSourceId(7), just_before), None);
        }
    }

    #[test]
    fn reversed_reception_clock_cannot_replace_counters_or_advance_replay_ledger() {
        let now = Instant::now();
        let mut state = TeacherPlaybackUiProjection::new(MonitoringSourceId(7), binding()).unwrap();
        let first = state.accept_authenticated(&envelope(), true, now).unwrap();
        let mut next = envelope();
        next.sequence += 1;
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
            next.payload
        {
            payload.sequence += 1;
            payload.presented_frames += 1;
        }
        assert_eq!(
            state.accept_authenticated(&next, true, now - Duration::from_millis(1)),
            Err(TeacherPlaybackDiagnosticError::ClockRegression)
        );
        assert_eq!(state.visible(MonitoringSourceId(7), now), Some(first));
        assert_eq!(
            state.visible(
                MonitoringSourceId(7),
                now + MAX_PLAYBACK_UI_AGE + Duration::from_millis(1)
            ),
            None
        );
        // The rejected sequence must be reusable at a genuinely later
        // authenticated reception time, not consumed by the rejected report.
        let second = state
            .accept_authenticated(&next, true, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(second.sequence, first.sequence + 1);
        assert_eq!(
            state.visible(MonitoringSourceId(7), now + Duration::from_secs(1)),
            Some(second)
        );
        let sub_tick_before = now - Duration::from_nanos(1);
        if sub_tick_before < now {
            let mut third = next;
            third.sequence += 1;
            if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
                third.payload
            {
                payload.sequence += 1;
            }
            assert_eq!(
                state.accept_authenticated(&third, true, sub_tick_before),
                Err(TeacherPlaybackDiagnosticError::ClockRegression)
            );
        }
    }

    #[test]
    fn legacy_forged_replay_and_wrong_presentation_never_replace_visible_counters() {
        let now = Instant::now();
        let mut state = TeacherPlaybackUiProjection::new(MonitoringSourceId(7), binding()).unwrap();
        assert_eq!(
            state.accept_authenticated(&envelope(), false, now),
            Err(TeacherPlaybackDiagnosticError::NotNegotiated)
        );
        assert_eq!(state.visible(MonitoringSourceId(7), now), None);
        let first = state.accept_authenticated(&envelope(), true, now).unwrap();
        let mut stale = envelope();
        assert_eq!(
            state.accept_authenticated(&stale, true, now + Duration::from_secs(1)),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        stale.control_session_id = 123;
        assert_eq!(
            state.accept_authenticated(&stale, true, now + Duration::from_secs(2)),
            Err(TeacherPlaybackDiagnosticError::BindingMismatch)
        );
        let mut wrong_media = envelope();
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
            wrong_media.payload
        {
            payload.presentation_id += 1;
        }
        assert_eq!(
            state.accept_authenticated(&wrong_media, true, now + Duration::from_secs(3)),
            Err(TeacherPlaybackDiagnosticError::BindingMismatch)
        );
        assert_eq!(
            state.visible(MonitoringSourceId(7), now + Duration::from_secs(3)),
            Some(first)
        );
    }

    #[test]
    fn exact_revocation_hides_ui_without_revoking_a_new_session() {
        let now = Instant::now();
        let mut old = TeacherPlaybackUiProjection::new(MonitoringSourceId(7), binding()).unwrap();
        old.accept_authenticated(&envelope(), true, now).unwrap();
        let mut different = binding();
        different.control_session_id += 1;
        assert!(!old.revoke(MonitoringSourceId(7), different));
        assert!(old.visible(MonitoringSourceId(7), now).is_some());
        assert!(!old.revoke(MonitoringSourceId(8), binding()));
        assert!(old.revoke(MonitoringSourceId(7), binding()));
        assert_eq!(old.visible(MonitoringSourceId(7), now), None);
        assert_eq!(
            old.accept_authenticated(&envelope(), true, now),
            Err(TeacherPlaybackDiagnosticError::Inactive)
        );
    }
}
