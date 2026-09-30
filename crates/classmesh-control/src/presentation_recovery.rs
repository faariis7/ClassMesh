use classmesh_core::keyframe::KeyframeRequestCoordinator;
use classmesh_protocol::feedback::FeedbackMessage;

pub const DEFAULT_PRESENTATION_KEYFRAME_MIN_INTERVAL_US: u64 = 250_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationRecoveryError {
    InvalidStreamId,
    InvalidKeyframeInterval,
    StreamMismatch { expected: u32, received: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationRecoveryOutcome {
    NackObserved {
        frame_id: u64,
        missing_packets: usize,
    },
    KeyframeGranted {
        after_frame_id: u64,
    },
    KeyframeSuppressed {
        after_frame_id: u64,
    },
}

/// Teacher-side recovery policy for already-authenticated presentation feedback.
///
/// Callers must pass feedback only after the control/session/authorization/stream checks performed
/// by `accept_presentation_feedback`. This coordinator deliberately owns no identity, replay or
/// authorization state. It applies one stream-wide keyframe throttle so simultaneous receiver
/// requests cannot create an IDR storm.
///
/// Presentation NACKs are observed but never trigger multicast retransmission or an implicit
/// keyframe. The production multicast sender has no group retransmission cache; explicit receiver
/// keyframe requests are the only feedback event that can ask the shared encoder for an IDR here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationRecoveryCoordinator {
    stream_id: u32,
    keyframes: KeyframeRequestCoordinator,
    nack_events: u64,
}

impl PresentationRecoveryCoordinator {
    pub fn new(
        stream_id: u32,
        min_keyframe_interval_us: u64,
    ) -> Result<Self, PresentationRecoveryError> {
        if stream_id == 0 {
            return Err(PresentationRecoveryError::InvalidStreamId);
        }
        if min_keyframe_interval_us == 0 {
            return Err(PresentationRecoveryError::InvalidKeyframeInterval);
        }
        Ok(Self {
            stream_id,
            keyframes: KeyframeRequestCoordinator::new(min_keyframe_interval_us),
            nack_events: 0,
        })
    }

    pub fn for_stream(stream_id: u32) -> Result<Self, PresentationRecoveryError> {
        Self::new(stream_id, DEFAULT_PRESENTATION_KEYFRAME_MIN_INTERVAL_US)
    }

    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn nack_events(&self) -> u64 {
        self.nack_events
    }

    #[must_use]
    pub const fn granted_keyframes(&self) -> u64 {
        self.keyframes.granted_requests()
    }

    #[must_use]
    pub const fn suppressed_keyframes(&self) -> u64 {
        self.keyframes.suppressed_requests()
    }

    pub fn observe(
        &mut self,
        now_us: u64,
        feedback: &FeedbackMessage,
    ) -> Result<PresentationRecoveryOutcome, PresentationRecoveryError> {
        let received = feedback.stream_id();
        if received != self.stream_id {
            return Err(PresentationRecoveryError::StreamMismatch {
                expected: self.stream_id,
                received,
            });
        }

        match feedback {
            FeedbackMessage::Nack {
                frame_id,
                missing_packet_indices,
                ..
            } => {
                self.nack_events = self.nack_events.saturating_add(1);
                Ok(PresentationRecoveryOutcome::NackObserved {
                    frame_id: *frame_id,
                    missing_packets: missing_packet_indices.len(),
                })
            }
            FeedbackMessage::RequestKeyframe { after_frame_id, .. } => {
                if self.keyframes.request(now_us) {
                    Ok(PresentationRecoveryOutcome::KeyframeGranted {
                        after_frame_id: *after_frame_id,
                    })
                } else {
                    Ok(PresentationRecoveryOutcome::KeyframeSuppressed {
                        after_frame_id: *after_frame_id,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyframe(stream_id: u32, after_frame_id: u64) -> FeedbackMessage {
        FeedbackMessage::RequestKeyframe {
            stream_id,
            after_frame_id,
        }
    }

    #[test]
    fn constructor_requires_stream_and_real_throttle_interval() {
        assert_eq!(
            PresentationRecoveryCoordinator::for_stream(0),
            Err(PresentationRecoveryError::InvalidStreamId)
        );
        assert_eq!(
            PresentationRecoveryCoordinator::new(7, 0),
            Err(PresentationRecoveryError::InvalidKeyframeInterval)
        );
    }

    #[test]
    fn simultaneous_receiver_requests_are_globally_coalesced() {
        let mut recovery =
            PresentationRecoveryCoordinator::new(7, 250_000).expect("valid recovery coordinator");

        assert_eq!(
            recovery.observe(1_000_000, &keyframe(7, 40)),
            Ok(PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 40 })
        );
        assert_eq!(
            recovery.observe(1_010_000, &keyframe(7, 41)),
            Ok(PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 41 })
        );
        assert_eq!(
            recovery.observe(1_250_000, &keyframe(7, 42)),
            Ok(PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 42 })
        );

        assert_eq!(recovery.granted_keyframes(), 2);
        assert_eq!(recovery.suppressed_keyframes(), 1);
    }

    #[test]
    fn recovery_plans_encoder_keyframe_only_for_granted_explicit_request() {
        let mut recovery =
            PresentationRecoveryCoordinator::new(7, 250_000).expect("valid recovery coordinator");

        let granted = recovery
            .observe_and_plan(55, 1_000_000, &keyframe(7, 40))
            .expect("first request");
        assert_eq!(
            granted.outcome,
            PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 40 }
        );
        let request = granted
            .keyframe_request
            .expect("granted request must plan IDR");
        assert_eq!(request.presentation_id(), 55);
        assert_eq!(request.stream_id(), 7);
        assert_eq!(request.after_frame_id(), 40);

        let suppressed = recovery
            .observe_and_plan(55, 1_010_000, &keyframe(7, 41))
            .expect("coalesced request");
        assert_eq!(
            suppressed.outcome,
            PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 41 }
        );
        assert!(suppressed.keyframe_request.is_none());

        let nack = FeedbackMessage::Nack {
            stream_id: 7,
            frame_id: 42,
            missing_packet_indices: vec![1, 2],
        };
        let observed = recovery
            .observe_and_plan(55, 1_020_000, &nack)
            .expect("observational NACK");
        assert!(matches!(
            observed.outcome,
            PresentationRecoveryOutcome::NackObserved { .. }
        ));
        assert!(observed.keyframe_request.is_none());
    }

    #[test]
    fn multicast_nack_never_requests_a_group_retransmit_or_implicit_idr() {
        let mut recovery =
            PresentationRecoveryCoordinator::for_stream(7).expect("valid recovery coordinator");
        let nack = FeedbackMessage::Nack {
            stream_id: 7,
            frame_id: 99,
            missing_packet_indices: vec![0, 3, 5],
        };

        assert_eq!(
            recovery.observe(1_000_000, &nack),
            Ok(PresentationRecoveryOutcome::NackObserved {
                frame_id: 99,
                missing_packets: 3,
            })
        );
        assert_eq!(recovery.nack_events(), 1);
        assert_eq!(recovery.granted_keyframes(), 0);
        assert_eq!(recovery.suppressed_keyframes(), 0);
    }

    #[test]
    fn wrong_stream_fails_before_recovery_state_changes() {
        let mut recovery =
            PresentationRecoveryCoordinator::for_stream(7).expect("valid recovery coordinator");

        assert_eq!(
            recovery.observe(1_000_000, &keyframe(8, 40)),
            Err(PresentationRecoveryError::StreamMismatch {
                expected: 7,
                received: 8,
            })
        );
        assert_eq!(recovery.nack_events(), 0);
        assert_eq!(recovery.granted_keyframes(), 0);
        assert_eq!(recovery.suppressed_keyframes(), 0);
    }

    #[test]
    fn backwards_time_does_not_bypass_shared_keyframe_throttle() {
        let mut recovery =
            PresentationRecoveryCoordinator::new(7, 100).expect("valid recovery coordinator");
        assert!(matches!(
            recovery.observe(1_000, &keyframe(7, 1)),
            Ok(PresentationRecoveryOutcome::KeyframeGranted { .. })
        ));
        assert!(matches!(
            recovery.observe(900, &keyframe(7, 2)),
            Ok(PresentationRecoveryOutcome::KeyframeSuppressed { .. })
        ));
    }
}
