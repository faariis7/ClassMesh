//! Caller-owned, authenticated Teacher playback session dispatch.
//!
//! This adapter does not create a connection, enroll a certificate, read
//! a roster, or run a second QUIC receiver. The owner supplies a trusted
//! student-to-source mapping and an already established enrolled session.
//! Other control messages remain available to the central dispatcher.

use std::time::Instant;

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_control::teacher_playback_receive::{
    AuthenticatedTeacherReceiveError, receive_authenticated_teacher_control,
};
use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_security::PrincipalId;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::receiver_playback_diagnostics::{
    TeacherPlaybackBinding, TeacherPlaybackCounters, TeacherPlaybackDiagnosticError,
};
use crate::receiver_playback_ui::TeacherPlaybackUiProjection;

/// A single outcome from the *one* owner of the multiplexed control channel.
#[derive(Debug)]
pub enum TeacherPlaybackSessionEvent {
    Playback(TeacherPlaybackCounters),
    OtherControl(ControlEnvelope),
}

#[derive(Debug)]
pub enum TeacherPlaybackSessionError {
    Retired,
    ControlSessionMismatch,
    ControlSequenceRegression,
    Receive(AuthenticatedTeacherReceiveError),
    Diagnostic(TeacherPlaybackDiagnosticError),
}

/// Owns only the optional receiver playback projection, NOT the QUIC session.
///
/// The expected student PrincipalId and MonitoringSourceId must come from
/// the same trusted enrollment/roster entry. No UI selection can establish
/// their relation. A failed peer-policy or transport check permanently
/// retires this owner; reconnect requires a newly constructed owner.
#[derive(Debug)]
pub struct TeacherPlaybackSessionOwner {
    expected_student: PrincipalId,
    source_id: MonitoringSourceId,
    binding: TeacherPlaybackBinding,
    active: bool,
    last_control_sequence: Option<u64>,
    projection: TeacherPlaybackUiProjection,
}

impl TeacherPlaybackSessionOwner {
    pub fn new(
        expected_student: PrincipalId,
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    ) -> Result<Self, TeacherPlaybackDiagnosticError> {
        Ok(Self {
            expected_student,
            source_id,
            binding,
            active: true,
            last_control_sequence: None,
            projection: TeacherPlaybackUiProjection::new(source_id, binding)?,
        })
    }

    #[must_use]
    pub fn visible(
        &self,
        selected_source: MonitoringSourceId,
        now: Instant,
    ) -> Option<TeacherPlaybackCounters> {
        if !self.active {
            return None;
        }
        self.projection.visible(selected_source, now)
    }

    /// An old session's disconnect must not retire a replacement route.
    pub fn retire_exact(
        &mut self,
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    ) -> bool {
        if !self.active || source_id != self.source_id || binding != self.binding {
            return false;
        }
        self.retire_current();
        true
    }

    fn retire_current(&mut self) {
        self.active = false;
        self.last_control_sequence = None;
        self.projection.revoke(self.source_id, self.binding);
    }

    /// Receive exactly ONE envelope through the existing authenticated QUIC
    /// client; never spawn an extra reader or drop another control command.
    ///
    /// Fresh policy and wall-clock checks happen before and after network I/O
    /// in the lower-level receiver; the monotonic time is sampled only after
    /// receiving and verifying the envelope.
    ///
    /// Failed trust, transport, or session validation retires the old
    /// projection immediately. A malformed playback report cannot overwrite
    /// the last valid counters but does not retire an otherwise valid session.
    pub async fn receive_next(
        &mut self,
        session: &mut ClientControlSession,
        authorization: &LiveAuthorizationStore,
        wall_clock_ms: impl Fn() -> u64,
        monotonic_now: impl Fn() -> Instant,
    ) -> Result<TeacherPlaybackSessionEvent, TeacherPlaybackSessionError> {
        if !self.active {
            return Err(TeacherPlaybackSessionError::Retired);
        }
        if session.established.control_session_id != self.binding.control_session_id {
            self.retire_current();
            return Err(TeacherPlaybackSessionError::ControlSessionMismatch);
        }
        let verified = match receive_authenticated_teacher_control(
            session,
            authorization,
            self.expected_student,
            wall_clock_ms,
        )
        .await
        {
            Ok(message) => message,
            Err(error) => {
                self.retire_current();
                return Err(TeacherPlaybackSessionError::Receive(error));
            }
        };
        // The single owning dispatcher must fence the outer control sequence
        // across playback AND unrelated control envelopes. The inner receiver
        // sequence is independent and cannot authorize a replayed envelope.
        let outer_sequence = verified.envelope().sequence;
        if outer_sequence == 0
            || self
                .last_control_sequence
                .is_some_and(|previous| outer_sequence <= previous)
        {
            self.retire_current();
            return Err(TeacherPlaybackSessionError::ControlSequenceRegression);
        }
        self.last_control_sequence = Some(outer_sequence);
        if verified.receiver_playback().is_none() {
            return Ok(TeacherPlaybackSessionEvent::OtherControl(
                verified.into_envelope(),
            ));
        }
        let counters = self
            .projection
            .accept_verified_from_source(self.source_id, &verified, monotonic_now())
            .map_err(TeacherPlaybackSessionError::Diagnostic)?;
        Ok(TeacherPlaybackSessionEvent::Playback(counters))
    }
}
