//! Correlate an actually received authenticated Service/Worker teacher-command
//! result.  A successful QUIC send is NOT a remote Worker acknowledgment.

use classmesh_protocol::control_wire::{
    ControlEnvelope, TeacherInteractionKind, TeacherInteractionState, control_envelope,
};
use classmesh_protocol::teacher_interaction::validate_result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherAckStatus {
    /// Worker accepted the request; this is NOT proof of screen rendering.
    Accepted,
    /// Worker returned an explicit completion result.
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherAckError {
    InvalidBinding,
    WrongSession,
    WrongRequestId,
    WrongVersion,
    InvalidSequence,
    MissingOrWrongPayload,
    InvalidResult,
    WrongKind,
    WorkerRejected,
    WorkerFailed,
}

impl std::fmt::Display for TeacherAckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Teacher↔Worker result correlation failed: {self:?}")
    }
}
impl std::error::Error for TeacherAckError {}

/// Verifies the actual authenticated Service response to one Worker-bound
/// message, not QUIC write success or a synthetic ACK. The calling QUIC
/// session already owns mTLS, replay and source authorization; this guards
/// the application request/session/kind/status correlation of its reply.
pub fn verify_teacher_message_ack(
    reply: &ControlEnvelope,
    expected_session: u64,
    expected_request_id: u64,
    expected_version: (u32, u32),
) -> Result<TeacherAckStatus, TeacherAckError> {
    if expected_session == 0 || expected_request_id == 0 {
        return Err(TeacherAckError::InvalidBinding);
    }
    if reply.control_session_id != expected_session {
        return Err(TeacherAckError::WrongSession);
    }
    if reply.request_id != expected_request_id {
        return Err(TeacherAckError::WrongRequestId);
    }
    if !reply
        .protocol_version
        .as_ref()
        .is_some_and(|version| (version.major, version.minor) == expected_version)
    {
        return Err(TeacherAckError::WrongVersion);
    }
    if reply.sequence == 0 {
        return Err(TeacherAckError::InvalidSequence);
    }
    let Some(control_envelope::Payload::TeacherInteractionResult(result)) = &reply.payload else {
        return Err(TeacherAckError::MissingOrWrongPayload);
    };
    validate_result(result).map_err(|_| TeacherAckError::InvalidResult)?;
    if result.kind != TeacherInteractionKind::Message as i32 {
        return Err(TeacherAckError::WrongKind);
    }
    match TeacherInteractionState::try_from(result.state) {
        Ok(TeacherInteractionState::Accepted) => Ok(TeacherAckStatus::Accepted),
        Ok(TeacherInteractionState::Completed) => Ok(TeacherAckStatus::Completed),
        Ok(TeacherInteractionState::Rejected) => Err(TeacherAckError::WorkerRejected),
        Ok(TeacherInteractionState::Failed) => Err(TeacherAckError::WorkerFailed),
        _ => Err(TeacherAckError::InvalidResult),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::{
        ControlEnvelope, ProtocolVersion, TeacherInteractionKind, TeacherInteractionResult,
        TeacherInteractionState, control_envelope,
    };

    fn ack(
        session: u64,
        request: u64,
        kind: TeacherInteractionKind,
        state: TeacherInteractionState,
    ) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session,
            sequence: 44,
            request_id: request,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 8 }),
            payload: Some(control_envelope::Payload::TeacherInteractionResult(
                TeacherInteractionResult {
                    kind: kind as i32,
                    state: state as i32,
                    diagnostic: String::new(),
                },
            )),
        }
    }

    #[test]
    fn real_worker_acceptance_is_reported_separately_from_completion() {
        assert_eq!(
            verify_teacher_message_ack(
                &ack(
                    7,
                    19,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Accepted
                ),
                7,
                19,
                (0, 8)
            ),
            Ok(TeacherAckStatus::Accepted)
        );
        assert_eq!(
            verify_teacher_message_ack(
                &ack(
                    7,
                    19,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                7,
                19,
                (0, 8)
            ),
            Ok(TeacherAckStatus::Completed)
        );
    }

    #[test]
    fn wrong_session_request_version_kind_or_sequence_fail_closed() {
        let baseline = ack(
            7,
            19,
            TeacherInteractionKind::Message,
            TeacherInteractionState::Accepted,
        );
        let mut invalid = baseline.clone();
        invalid.control_session_id = 8;
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
        invalid = baseline.clone();
        invalid.request_id = 20;
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
        invalid = baseline.clone();
        invalid.protocol_version.as_mut().unwrap().minor = 7;
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
        invalid = baseline.clone();
        invalid.sequence = 0;
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
        invalid = baseline.clone();
        invalid.payload = None;
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
        invalid = ack(
            7,
            19,
            TeacherInteractionKind::OpenTarget,
            TeacherInteractionState::Accepted,
        );
        assert!(verify_teacher_message_ack(&invalid, 7, 19, (0, 8)).is_err());
    }

    #[test]
    fn worker_rejection_or_failure_never_claims_success() {
        for state in [
            TeacherInteractionState::Rejected,
            TeacherInteractionState::Failed,
            TeacherInteractionState::Unspecified,
        ] {
            assert!(
                verify_teacher_message_ack(
                    &ack(7, 19, TeacherInteractionKind::Message, state),
                    7,
                    19,
                    (0, 8)
                )
                .is_err()
            );
        }
    }
}

/// An ACK-only qualification must not advertise media capabilities that it
/// cannot exercise, or require a UDP port to be available.
pub fn qualification_capabilities(
    message_only: bool,
    with_message: bool,
) -> std::collections::BTreeSet<classmesh_protocol::Capability> {
    use classmesh_protocol::Capability;
    let mut caps = std::collections::BTreeSet::new();
    if !message_only {
        caps.insert(Capability::UdpUnicast);
        caps.insert(Capability::H264HardwareDecode);
    }
    if with_message {
        caps.insert(Capability::TeacherMessage);
    }
    caps
}

#[cfg(test)]
mod qualification_capability_tests {
    use super::qualification_capabilities;
    use classmesh_protocol::Capability;
    #[test]
    fn ack_only_never_advertises_or_requires_media() {
        let caps = qualification_capabilities(true, true);
        assert_eq!(caps.len(), 1);
        assert!(caps.contains(&Capability::TeacherMessage));
        assert!(!caps.contains(&Capability::UdpUnicast));
        assert!(!caps.contains(&Capability::H264HardwareDecode));
        let media = qualification_capabilities(false, true);
        assert!(media.contains(&Capability::UdpUnicast));
        assert!(media.contains(&Capability::H264HardwareDecode));
    }
}

/// Strict delivery qualification: Worker acceptance alone does not prove completion.
/// A caller may report Accepted for diagnostics, but must not pass strict mode.
pub fn require_worker_completion(status: TeacherAckStatus) -> Result<(), &'static str> {
    match status {
        TeacherAckStatus::Completed => Ok(()),
        TeacherAckStatus::Accepted => {
            Err("Worker only accepted the message; completion not observed")
        }
    }
}

#[cfg(test)]
mod acceptance_policy_tests {
    use super::*;
    #[test]
    fn strict_completion_policy_rejects_accepted_only() {
        assert!(require_worker_completion(TeacherAckStatus::Completed).is_ok());
        assert!(require_worker_completion(TeacherAckStatus::Accepted).is_err());
    }
}
