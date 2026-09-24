use std::collections::BTreeSet;

use crate::control_wire::{PresentationKeyAck, PresentationKeyGrant};
use crate::{Capability, ProtocolVersion};

pub const PRESENTATION_GROUP_KEY_BYTES: usize = 32;
pub const GROUP_MEDIA_CONTROL_MIN_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 4 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaControlError {
    InvalidPresentationId,
    InvalidStreamId,
    StreamIdOutOfRange,
    InvalidEpoch,
    InvalidKeyLength { actual: usize },
}

#[must_use]
pub fn group_media_control_available(
    version: ProtocolVersion,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    version.major == GROUP_MEDIA_CONTROL_MIN_VERSION.major
        && version.minor >= GROUP_MEDIA_CONTROL_MIN_VERSION.minor
        && capabilities.contains(&Capability::TeacherPresentation)
        && capabilities.contains(&Capability::SframeGroupMedia)
}

pub fn validate_key_grant(grant: &PresentationKeyGrant) -> Result<(), GroupMediaControlError> {
    validate_binding(grant.presentation_id, grant.stream_id, grant.epoch)?;
    if grant.key_material.len() != PRESENTATION_GROUP_KEY_BYTES {
        return Err(GroupMediaControlError::InvalidKeyLength {
            actual: grant.key_material.len(),
        });
    }
    Ok(())
}

pub fn validate_key_ack(ack: &PresentationKeyAck) -> Result<(), GroupMediaControlError> {
    validate_binding(ack.presentation_id, ack.stream_id, ack.epoch)
}

fn validate_binding(
    presentation_id: u64,
    stream_id: u64,
    epoch: u32,
) -> Result<(), GroupMediaControlError> {
    if presentation_id == 0 {
        return Err(GroupMediaControlError::InvalidPresentationId);
    }
    if stream_id == 0 {
        return Err(GroupMediaControlError::InvalidStreamId);
    }
    if u32::try_from(stream_id).is_err() {
        return Err(GroupMediaControlError::StreamIdOutOfRange);
    }
    if epoch == 0 {
        return Err(GroupMediaControlError::InvalidEpoch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> PresentationKeyGrant {
        PresentationKeyGrant {
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            key_material: vec![9; PRESENTATION_GROUP_KEY_BYTES],
        }
    }

    #[test]
    fn contract_requires_v04_and_both_explicit_capabilities() {
        let both = BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
        ]);
        assert!(!group_media_control_available(
            ProtocolVersion { major: 0, minor: 3 },
            &both
        ));
        assert!(!group_media_control_available(
            ProtocolVersion { major: 1, minor: 4 },
            &both
        ));
        assert!(!group_media_control_available(
            GROUP_MEDIA_CONTROL_MIN_VERSION,
            &BTreeSet::from([Capability::TeacherPresentation])
        ));
        assert!(!group_media_control_available(
            GROUP_MEDIA_CONTROL_MIN_VERSION,
            &BTreeSet::from([Capability::SframeGroupMedia])
        ));
        assert!(group_media_control_available(
            GROUP_MEDIA_CONTROL_MIN_VERSION,
            &both
        ));
    }

    #[test]
    fn key_grant_requires_exact_binding_and_key_size() {
        assert_eq!(validate_key_grant(&grant()), Ok(()));

        let mut invalid = grant();
        invalid.presentation_id = 0;
        assert_eq!(
            validate_key_grant(&invalid),
            Err(GroupMediaControlError::InvalidPresentationId)
        );

        let mut invalid = grant();
        invalid.stream_id = 0;
        assert_eq!(
            validate_key_grant(&invalid),
            Err(GroupMediaControlError::InvalidStreamId)
        );

        let mut invalid = grant();
        invalid.stream_id = u64::from(u32::MAX) + 1;
        assert_eq!(
            validate_key_grant(&invalid),
            Err(GroupMediaControlError::StreamIdOutOfRange)
        );

        let mut invalid = grant();
        invalid.epoch = 0;
        assert_eq!(
            validate_key_grant(&invalid),
            Err(GroupMediaControlError::InvalidEpoch)
        );

        for size in [
            PRESENTATION_GROUP_KEY_BYTES - 1,
            PRESENTATION_GROUP_KEY_BYTES + 1,
        ] {
            let mut invalid = grant();
            invalid.key_material = vec![0; size];
            assert_eq!(
                validate_key_grant(&invalid),
                Err(GroupMediaControlError::InvalidKeyLength { actual: size })
            );
        }
    }

    #[test]
    fn key_ack_requires_exact_nonzero_binding() {
        let valid = PresentationKeyAck {
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        };
        assert_eq!(validate_key_ack(&valid), Ok(()));

        assert_eq!(
            validate_key_ack(&PresentationKeyAck {
                presentation_id: 0,
                ..valid
            }),
            Err(GroupMediaControlError::InvalidPresentationId)
        );
        assert_eq!(
            validate_key_ack(&PresentationKeyAck {
                stream_id: 0,
                ..valid
            }),
            Err(GroupMediaControlError::InvalidStreamId)
        );
        assert_eq!(
            validate_key_ack(&PresentationKeyAck { epoch: 0, ..valid }),
            Err(GroupMediaControlError::InvalidEpoch)
        );
    }
}
