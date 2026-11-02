//! Opt-in *read-only* Teacher-side playback diagnostics from an enrolled
//! authenticated Service control channel. This module never authenticates
//! the network peer; the QUIC client MUST establish TLS/PrincipalId control
//! identity and negotiate optional capability 18 before calling accept.
//! The counters are not RTT, loss, latency, bandwidth or a quality vote.
use classmesh_protocol::control_wire::{ControlEnvelope, control_envelope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeacherPlaybackBinding {
    pub control_session_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}
impl TeacherPlaybackBinding {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.control_session_id != 0
            && self.presentation_id != 0
            && self.stream_id != 0
            && self.epoch != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeacherPlaybackCounters {
    pub receiver_generation: u64,
    pub sequence: u64,
    pub interval_ms: u64,
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
pub enum TeacherPlaybackDiagnosticError {
    InvalidBinding,
    Inactive,
    NotNegotiated,
    BindingMismatch,
    Malformed,
    Replay,
    ClockRegression,
}

/// Latest-only receiver counter projection. An old session or a lower
/// receiver incarnation cannot overwrite a newer observation.
/// This is NOT a transport/Teacher authentication implementation.
#[derive(Debug, Default)]
pub struct TeacherPlaybackDiagnosticLedger {
    binding: Option<TeacherPlaybackBinding>,
    current: Option<TeacherPlaybackCounters>,
    last_control_sequence: Option<u64>,
}
impl TeacherPlaybackDiagnosticLedger {
    pub fn new(binding: TeacherPlaybackBinding) -> Result<Self, TeacherPlaybackDiagnosticError> {
        if !binding.is_valid() {
            return Err(TeacherPlaybackDiagnosticError::InvalidBinding);
        }
        Ok(Self {
            binding: Some(binding),
            current: None,
            last_control_sequence: None,
        })
    }

    #[must_use]
    pub const fn current(&self) -> Option<TeacherPlaybackCounters> {
        self.current
    }

    /// Call only after the enclosing ControlEnvelope was authenticated by the
    /// exact enrolled Service QUIC connection and the receiver capability was
    /// negotiated. This method rechecks the exact live presentation binding.
    pub fn accept_from_authenticated_control(
        &mut self,
        envelope: &ControlEnvelope,
        capability_negotiated: bool,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
        let binding = self
            .binding
            .ok_or(TeacherPlaybackDiagnosticError::Inactive)?;
        if !capability_negotiated {
            return Err(TeacherPlaybackDiagnosticError::NotNegotiated);
        }
        let Some(version) = envelope.protocol_version else {
            return Err(TeacherPlaybackDiagnosticError::NotNegotiated);
        };
        if version.major != 0 || version.minor < 8 {
            return Err(TeacherPlaybackDiagnosticError::NotNegotiated);
        }
        if envelope.control_session_id != binding.control_session_id
            || envelope.sequence == 0
            || envelope.request_id != 0
        {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(payload)) =
            envelope.payload.as_ref()
        else {
            return Err(TeacherPlaybackDiagnosticError::Malformed);
        };
        if payload.presentation_id != binding.presentation_id
            || payload.stream_id != u64::from(binding.stream_id)
            || payload.epoch != binding.epoch
        {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        if payload.receiver_generation == 0
            || payload.sequence == 0
            || !(1..=30_000).contains(&payload.interval_ms)
        {
            return Err(TeacherPlaybackDiagnosticError::Malformed);
        }
        // The QUIC control envelope is independently sequenced from the
        // receiver's own report counter. Reject an old outer envelope even
        // if a replay attacker changes the inner receiver sequence.
        if self
            .last_control_sequence
            .is_some_and(|previous| envelope.sequence <= previous)
        {
            return Err(TeacherPlaybackDiagnosticError::Replay);
        }
        if self.current.is_some_and(|prev| {
            payload.receiver_generation < prev.receiver_generation
                || (payload.receiver_generation == prev.receiver_generation
                    && payload.sequence <= prev.sequence)
        }) {
            return Err(TeacherPlaybackDiagnosticError::Replay);
        }
        let next = TeacherPlaybackCounters {
            receiver_generation: payload.receiver_generation,
            sequence: payload.sequence,
            interval_ms: payload.interval_ms,
            authenticated_frames: payload.authenticated_frames,
            rejected_frames: payload.rejected_frames,
            decoded_frames: payload.decoded_frames,
            presented_frames: payload.presented_frames,
            present_errors: payload.present_errors,
            decode_errors: payload.decode_errors,
            keyframe_waits: payload.keyframe_waits,
            queue_drops: payload.queue_drops,
        };
        self.last_control_sequence = Some(envelope.sequence);
        self.current = Some(next);
        Ok(next)
    }

    /// Stale teardown is not allowed to revoke a replacement active session.
    pub fn revoke(&mut self, exact: TeacherPlaybackBinding) -> bool {
        if self.binding != Some(exact) {
            return false;
        }
        self.binding = None;
        self.current = None;
        self.last_control_sequence = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::{ProtocolVersion, ReceiverPlaybackDiagnostic};

    fn session() -> TeacherPlaybackBinding {
        TeacherPlaybackBinding {
            control_session_id: 11,
            presentation_id: 21,
            stream_id: 31,
            epoch: 41,
        }
    }

    fn wire(receiver_generation: u64, sequence: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 11,
            sequence: receiver_generation * 1_000 + sequence,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 8 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(
                ReceiverPlaybackDiagnostic {
                    presentation_id: 21,
                    stream_id: 31,
                    epoch: 41,
                    receiver_generation,
                    sequence,
                    interval_ms: 5_000,
                    authenticated_frames: 90,
                    rejected_frames: 1,
                    decoded_frames: 82,
                    presented_frames: 81,
                    present_errors: 2,
                    decode_errors: 3,
                    keyframe_waits: 4,
                    queue_drops: 5,
                },
            )),
        }
    }

    #[test]
    fn accepts_only_new_authenticated_playback_counters_for_exact_session() {
        let mut ledger = TeacherPlaybackDiagnosticLedger::new(session()).unwrap();
        assert_eq!(
            ledger
                .accept_from_authenticated_control(&wire(1, 1), true)
                .unwrap()
                .presented_frames,
            81
        );
        assert_eq!(
            ledger
                .accept_from_authenticated_control(&wire(1, 2), true)
                .unwrap()
                .receiver_generation,
            1
        );
        assert_eq!(
            ledger.accept_from_authenticated_control(&wire(1, 2), true),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        assert_eq!(
            ledger.accept_from_authenticated_control(&wire(1, 1), true),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        assert_eq!(
            ledger
                .accept_from_authenticated_control(&wire(2, 1), true)
                .unwrap()
                .receiver_generation,
            2
        );
        assert_eq!(
            ledger.accept_from_authenticated_control(&wire(1, 100), true),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
    }

    #[test]
    fn control_envelope_replay_cannot_smuggle_in_a_new_receiver_sequence() {
        let mut ledger = TeacherPlaybackDiagnosticLedger::new(session()).unwrap();
        let mut first = wire(1, 1);
        first.sequence = 50;
        let accepted = ledger
            .accept_from_authenticated_control(&first, true)
            .unwrap();

        let mut replayed_control = wire(1, 2);
        replayed_control.sequence = 50;
        assert_eq!(
            ledger.accept_from_authenticated_control(&replayed_control, true),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        replayed_control.sequence = 49;
        assert_eq!(
            ledger.accept_from_authenticated_control(&replayed_control, true),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        assert_eq!(ledger.current(), Some(accepted));

        replayed_control.sequence = 51;
        let next = ledger
            .accept_from_authenticated_control(&replayed_control, true)
            .unwrap();
        assert_eq!(next.sequence, 2);

        let mut new_receiver = wire(2, 1);
        new_receiver.sequence = 52;
        assert_eq!(
            ledger
                .accept_from_authenticated_control(&new_receiver, true)
                .unwrap()
                .receiver_generation,
            2
        );
    }

    #[test]
    fn rejects_legacy_peer_forged_session_and_wrong_media_owner() {
        let mut ledger = TeacherPlaybackDiagnosticLedger::new(session()).unwrap();
        assert_eq!(
            ledger.accept_from_authenticated_control(&wire(1, 1), false),
            Err(TeacherPlaybackDiagnosticError::NotNegotiated)
        );
        let mut wrong = wire(1, 1);
        wrong.control_session_id = 12;
        assert_eq!(
            ledger.accept_from_authenticated_control(&wrong, true),
            Err(TeacherPlaybackDiagnosticError::BindingMismatch)
        );
        wrong = wire(1, 1);
        wrong.request_id = 77;
        assert_eq!(
            ledger.accept_from_authenticated_control(&wrong, true),
            Err(TeacherPlaybackDiagnosticError::BindingMismatch)
        );
        wrong = wire(1, 1);
        wrong.protocol_version.as_mut().unwrap().minor = 7;
        assert_eq!(
            ledger.accept_from_authenticated_control(&wrong, true),
            Err(TeacherPlaybackDiagnosticError::NotNegotiated)
        );
        wrong = wire(1, 1);
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
            wrong.payload
        {
            payload.epoch = 99;
        }
        assert_eq!(
            ledger.accept_from_authenticated_control(&wrong, true),
            Err(TeacherPlaybackDiagnosticError::BindingMismatch)
        );
        assert!(
            ledger
                .accept_from_authenticated_control(&wire(1, 1), true)
                .is_ok()
        );
    }

    #[test]
    fn rejects_malformed_counters_and_revoked_presentation_without_quality_inference() {
        let mut ledger = TeacherPlaybackDiagnosticLedger::new(session()).unwrap();
        for (generation, sequence) in [(0, 1), (1, 0)] {
            assert_eq!(
                ledger.accept_from_authenticated_control(&wire(generation, sequence), true),
                Err(TeacherPlaybackDiagnosticError::Malformed)
            );
        }
        let mut invalid = wire(1, 1);
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
            invalid.payload
        {
            payload.interval_ms = 0;
        }
        assert_eq!(
            ledger.accept_from_authenticated_control(&invalid, true),
            Err(TeacherPlaybackDiagnosticError::Malformed)
        );
        ledger.revoke(session());
        assert_eq!(
            ledger.accept_from_authenticated_control(&wire(1, 1), true),
            Err(TeacherPlaybackDiagnosticError::Inactive)
        );
        assert_eq!(ledger.current(), None);
    }
}
