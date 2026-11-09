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
    AuthenticatedTeacherControlMessage, AuthenticatedTeacherReceiveError,
    TeacherControlSequenceGuard, receive_guarded_authenticated_teacher_control,
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
    /// A verified live QUIC observation plus the projection counters. Keep the
    /// privately constructed proof so the owning runtime can forward it to
    /// the native Teacher window without fabricating a trusted envelope.
    Playback {
        counters: TeacherPlaybackCounters,
        verified: AuthenticatedTeacherControlMessage,
        /// The monotonic instant sampled when the signed QUIC report was
        /// accepted, not when a potentially backlogged GUI dequeues it.
        received_at: Instant,
    },
    OtherControl(ControlEnvelope),
}

#[derive(Debug)]
pub enum TeacherPlaybackSessionError {
    Retired,
    ControlSessionMismatch,
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
    control_sequence_guard: TeacherControlSequenceGuard,
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
            control_sequence_guard: TeacherControlSequenceGuard::default(),
            projection: TeacherPlaybackUiProjection::new(source_id, binding)?,
        })
    }

    /// The trusted enrollment/roster source this authenticated QUIC owner
    /// was created for. Never source playback identity from a GUI selection.
    #[must_use]
    pub fn source_id(&self) -> MonitoringSourceId {
        self.source_id
    }

    /// Exact presentation/stream/epoch binding assigned by the roster owner.
    #[must_use]
    pub fn binding(&self) -> TeacherPlaybackBinding {
        self.binding
    }

    /// Expected enrolled StudentDevice, assigned by the trusted roster owner.
    /// An identity value is not proof of a verified TLS peer.
    #[must_use]
    pub fn expected_student(&self) -> PrincipalId {
        self.expected_student
    }

    /// A prior terminal receive error or exact session retirement forbids reuse.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
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
        self.control_sequence_guard = TeacherControlSequenceGuard::default();
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
        let verified = match receive_guarded_authenticated_teacher_control(
            session,
            authorization,
            self.expected_student,
            wall_clock_ms,
            &mut self.control_sequence_guard,
        )
        .await
        {
            Ok(message) => message,
            Err(error) => {
                self.retire_current();
                return Err(TeacherPlaybackSessionError::Receive(error));
            }
        };
        self.accept_guarded_verified(verified, monotonic_now())
    }

    /// Project an already authenticated *and replay-guarded* receive from the
    /// sole split QUIC reader. The runtime is responsible for retaining its
    /// guard for the complete Hello session; the proof type is opaque to UI.
    /// A bare ControlEnvelope cannot enter this path.
    pub(crate) fn accept_guarded_verified(
        &mut self,
        verified: AuthenticatedTeacherControlMessage,
        received_at: Instant,
    ) -> Result<TeacherPlaybackSessionEvent, TeacherPlaybackSessionError> {
        if !self.active {
            return Err(TeacherPlaybackSessionError::Retired);
        }
        if verified.envelope().control_session_id != self.binding.control_session_id {
            self.retire_current();
            return Err(TeacherPlaybackSessionError::ControlSessionMismatch);
        }
        if verified.receiver_playback().is_none() {
            return Ok(TeacherPlaybackSessionEvent::OtherControl(
                verified.into_envelope(),
            ));
        }
        let counters = self
            .projection
            .accept_verified_from_source(self.source_id, &verified, received_at)
            .map_err(TeacherPlaybackSessionError::Diagnostic)?;
        Ok(TeacherPlaybackSessionEvent::Playback {
            counters,
            verified,
            received_at,
        })
    }
}
