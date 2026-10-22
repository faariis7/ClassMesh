//! Source-bound read-only Teacher UI projection of already authenticated
//! playback reports. This is NEVER a QUIC authentication or quality sample.
use std::time::{Duration, Instant};

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

    /// The live QUIC client must already have authenticated the exact Service
    /// and PrincipalId; the input boolean comes from negotiated capability 18.
    pub fn accept_authenticated(
        &mut self,
        envelope: &ControlEnvelope,
        capability_negotiated: bool,
        now: Instant,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
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
                .and_then(|at| now.checked_duration_since(at))
                .is_some_and(|age| age <= MAX_PLAYBACK_UI_AGE)
        {
            return None;
        }
        self.ledger.current()
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
        assert_eq!(
            state.visible(MonitoringSourceId(7), now - Duration::from_nanos(1)),
            None
        );
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
