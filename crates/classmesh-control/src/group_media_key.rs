use std::fmt;

use classmesh_protocol::control_wire::{
    ControlEnvelope, PresentationKeyAck, PresentationKeyGrant, control_envelope,
};
use classmesh_protocol::group_media_control::{
    GroupMediaControlError, validate_key_ack, validate_key_grant,
};
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaError, GroupMediaKeyMaterial, GroupMediaReceiver,
};
use zeroize::Zeroize;

pub struct InstalledPresentationKey {
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
    receiver: GroupMediaReceiver,
}

impl fmt::Debug for InstalledPresentationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledPresentationKey")
            .field("presentation_id", &self.presentation_id)
            .field("stream_id", &self.stream_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl InstalledPresentationKey {
    #[must_use]
    pub const fn presentation_id(&self) -> u64 {
        self.presentation_id
    }

    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn epoch(&self) -> GroupMediaEpoch {
        self.epoch
    }

    pub fn open_frame(
        &mut self,
        sealed: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, GroupMediaError> {
        self.receiver.open_frame(sealed, associated_data)
    }
}

#[derive(Debug)]
pub enum PresentationKeyInstallError {
    InvalidWire(GroupMediaControlError),
    Security(GroupMediaError),
}

impl fmt::Display for PresentationKeyInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWire(error) => {
                write!(formatter, "invalid presentation key grant: {error:?}")
            }
            Self::Security(error) => write!(formatter, "presentation key install failed: {error}"),
        }
    }
}

impl std::error::Error for PresentationKeyInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::InvalidWire(_) => None,
        }
    }
}

/// Validates and installs one received v0.4 group-media key grant.
///
/// The raw protobuf key bytes are zeroized before this function returns on both
/// success and validation/security failure. On success only the derived SFrame
/// decryption/replay state remains; raw base-key bytes are not retained here.
pub fn install_received_presentation_key(
    grant: &mut PresentationKeyGrant,
) -> Result<InstalledPresentationKey, PresentationKeyInstallError> {
    if let Err(error) = validate_key_grant(grant) {
        grant.key_material.zeroize();
        return Err(PresentationKeyInstallError::InvalidWire(error));
    }

    let key_material = GroupMediaKeyMaterial::import_received_wire(&mut grant.key_material)
        .map_err(PresentationKeyInstallError::Security)?;
    let epoch = GroupMediaEpoch::new(grant.epoch).map_err(PresentationKeyInstallError::Security)?;
    let stream_id = u32::try_from(grant.stream_id).map_err(|_| {
        PresentationKeyInstallError::InvalidWire(GroupMediaControlError::StreamIdOutOfRange)
    })?;
    let receiver = GroupMediaReceiver::with_default_replay_tolerance(epoch, &key_material)
        .map_err(PresentationKeyInstallError::Security)?;

    Ok(InstalledPresentationKey {
        presentation_id: grant.presentation_id,
        stream_id,
        epoch,
        receiver,
    })
}

#[derive(Debug)]
pub enum PresentationKeyAckBuildError {
    UnexpectedPayload,
    InvalidSessionId,
    ZeroRequestId,
    ZeroSequence,
    MissingProtocolVersion,
    BindingMismatch,
    InvalidAck(GroupMediaControlError),
}

impl fmt::Display for PresentationKeyAckBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPayload => formatter.write_str("expected PresentationKeyGrant payload"),
            Self::InvalidSessionId => {
                formatter.write_str("presentation key grant control_session_id is zero")
            }
            Self::ZeroRequestId => formatter.write_str("presentation key grant request_id is zero"),
            Self::ZeroSequence => formatter.write_str("presentation key ACK sequence is zero"),
            Self::MissingProtocolVersion => {
                formatter.write_str("presentation key grant is missing protocol_version")
            }
            Self::BindingMismatch => formatter.write_str(
                "installed presentation key does not match the received grant binding",
            ),
            Self::InvalidAck(error) => {
                write!(formatter, "invalid presentation key ACK: {error:?}")
            }
        }
    }
}

impl std::error::Error for PresentationKeyAckBuildError {}

/// Builds the receiver ACK for an already-installed key grant.
///
/// The caller must perform authenticated-session, replay/sequence and presentation-ownership
/// checks before installing the grant. This helper only preserves the exact wire correlation:
/// same control session, protocol version, request ID, presentation, stream and epoch. Because
/// installation zeroizes the raw grant bytes, constructing the ACK does not require retaining
/// or re-exposing the group key.
pub fn build_presentation_key_ack(
    received: &ControlEnvelope,
    installed: &InstalledPresentationKey,
    sequence: u64,
) -> Result<ControlEnvelope, PresentationKeyAckBuildError> {
    if received.control_session_id == 0 {
        return Err(PresentationKeyAckBuildError::InvalidSessionId);
    }
    if received.request_id == 0 {
        return Err(PresentationKeyAckBuildError::ZeroRequestId);
    }
    if sequence == 0 {
        return Err(PresentationKeyAckBuildError::ZeroSequence);
    }
    let protocol_version = received
        .protocol_version
        .clone()
        .ok_or(PresentationKeyAckBuildError::MissingProtocolVersion)?;

    let Some(control_envelope::Payload::PresentationKeyGrant(grant)) = received.payload.as_ref()
    else {
        return Err(PresentationKeyAckBuildError::UnexpectedPayload);
    };

    if grant.presentation_id != installed.presentation_id()
        || grant.stream_id != u64::from(installed.stream_id())
        || grant.epoch != installed.epoch().get()
    {
        return Err(PresentationKeyAckBuildError::BindingMismatch);
    }

    let ack = PresentationKeyAck {
        presentation_id: installed.presentation_id(),
        stream_id: u64::from(installed.stream_id()),
        epoch: installed.epoch().get(),
    };
    validate_key_ack(&ack).map_err(PresentationKeyAckBuildError::InvalidAck)?;

    Ok(ControlEnvelope {
        control_session_id: received.control_session_id,
        sequence,
        protocol_version: Some(protocol_version),
        request_id: received.request_id,
        payload: Some(control_envelope::Payload::PresentationKeyAck(ack)),
    })
}

#[cfg(test)]
mod tests {
    use classmesh_security::group_media::{GROUP_MEDIA_KEY_BYTES, GroupMediaSender};

    use super::*;

    fn grant(value: u8) -> PresentationKeyGrant {
        PresentationKeyGrant {
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            key_material: vec![value; GROUP_MEDIA_KEY_BYTES],
        }
    }

    fn grant_envelope(value: u8) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence: 2,
            protocol_version: Some(classmesh_protocol::control_wire::ProtocolVersion {
                major: 0,
                minor: 4,
            }),
            request_id: 44,
            payload: Some(control_envelope::Payload::PresentationKeyGrant(grant(value))),
        }
    }

    #[test]
    fn valid_wire_grant_installs_receiver_and_zeroizes_raw_protobuf_key() {
        let mut grant = grant(0x5a);
        let installed =
            install_received_presentation_key(&mut grant).expect("grant should install");

        assert_eq!(installed.presentation_id(), 55);
        assert_eq!(installed.stream_id(), 7);
        assert_eq!(installed.epoch().get(), 3);
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
        assert!(!format!("{installed:?}").contains("5a"));
    }

    #[test]
    fn invalid_wire_grant_zeroizes_key_before_returning_error() {
        let mut grant = grant(0x6b);
        grant.stream_id = 0;

        assert!(matches!(
            install_received_presentation_key(&mut grant),
            Err(PresentationKeyInstallError::InvalidWire(
                GroupMediaControlError::InvalidStreamId
            ))
        ));
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn installed_key_builds_exact_correlated_ack_after_raw_key_zeroization() {
        let mut envelope = grant_envelope(0x44);
        let installed = match envelope.payload.as_mut() {
            Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                install_received_presentation_key(grant).expect("receiver install")
            }
            _ => panic!("expected grant"),
        };

        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            envelope.payload.as_ref()
        else {
            panic!("expected grant");
        };
        assert!(grant.key_material.iter().all(|byte| *byte == 0));

        let ack = build_presentation_key_ack(&envelope, &installed, 3).expect("correlated ACK");
        assert_eq!(ack.control_session_id, 77);
        assert_eq!(ack.sequence, 3);
        assert_eq!(ack.request_id, 44);
        assert_eq!(
            ack.protocol_version,
            Some(classmesh_protocol::control_wire::ProtocolVersion {
                major: 0,
                minor: 4,
            })
        );
        let Some(control_envelope::Payload::PresentationKeyAck(ack_payload)) = ack.payload else {
            panic!("expected ACK");
        };
        assert_eq!(ack_payload.presentation_id, 55);
        assert_eq!(ack_payload.stream_id, 7);
        assert_eq!(ack_payload.epoch, 3);
    }

    #[test]
    fn ack_builder_rejects_metadata_tamper_after_install() {
        let mut envelope = grant_envelope(0x45);
        let installed = match envelope.payload.as_mut() {
            Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                install_received_presentation_key(grant).expect("receiver install")
            }
            _ => panic!("expected grant"),
        };

        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            envelope.payload.as_mut()
        else {
            panic!("expected grant");
        };
        grant.stream_id = 8;

        assert!(matches!(
            build_presentation_key_ack(&envelope, &installed, 3),
            Err(PresentationKeyAckBuildError::BindingMismatch)
        ));
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn ack_builder_requires_nonzero_wire_correlation_fields() {
        let mut envelope = grant_envelope(0x46);
        let installed = match envelope.payload.as_mut() {
            Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                install_received_presentation_key(grant).expect("receiver install")
            }
            _ => panic!("expected grant"),
        };

        envelope.request_id = 0;
        assert!(matches!(
            build_presentation_key_ack(&envelope, &installed, 3),
            Err(PresentationKeyAckBuildError::ZeroRequestId)
        ));

        envelope.request_id = 44;
        assert!(matches!(
            build_presentation_key_ack(&envelope, &installed, 0),
            Err(PresentationKeyAckBuildError::ZeroSequence)
        ));
    }

    #[test]
    fn installed_receiver_opens_frames_for_the_exact_epoch_key() {
        let mut sender_bytes = vec![0x33; GROUP_MEDIA_KEY_BYTES];
        let sender_material =
            GroupMediaKeyMaterial::import_received_wire(&mut sender_bytes).expect("sender key");
        let epoch = GroupMediaEpoch::new(3).expect("epoch");
        let mut sender = GroupMediaSender::new(epoch, &sender_material).expect("sender");

        let mut grant = grant(0x33);
        let mut installed =
            install_received_presentation_key(&mut grant).expect("receiver install");
        let aad = b"presentation=55:stream=7:epoch=3";
        let sealed = sender
            .seal_frame(b"presentation-frame", aad)
            .expect("sealed frame");

        assert_eq!(
            installed
                .open_frame(&sealed, aad)
                .expect("installed receiver decrypts"),
            b"presentation-frame"
        );
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
    }
}
