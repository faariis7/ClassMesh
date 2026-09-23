use std::fmt;
use std::num::NonZeroU32;

use sframe::CipherSuite;
use sframe::error::SframeError;
use sframe::frame::validation::{ReplayAttackProtection, ReplayAttackProtectionError, Tolerance};
use sframe::frame::{EncryptedFrameView, MediaFrame, MonotonicCounter};
use sframe::key::{DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

pub const GROUP_MEDIA_KEY_BYTES: usize = 32;
pub const DEFAULT_GROUP_MEDIA_REPLAY_TOLERANCE_FRAMES: usize = 64;
pub const MAX_GROUP_MEDIA_REPLAY_TOLERANCE_FRAMES: usize = 512;
pub const MAX_GROUP_MEDIA_AAD_BYTES: usize = 256;
pub const MAX_GROUP_MEDIA_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GROUP_MEDIA_SEALED_BYTES: usize = MAX_GROUP_MEDIA_FRAME_BYTES + 64;

const GROUP_MEDIA_CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupMediaEpoch(NonZeroU32);

impl GroupMediaEpoch {
    pub fn new(value: u32) -> Result<Self, GroupMediaError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(GroupMediaError::InvalidEpoch)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[must_use]
    pub const fn sframe_key_id(self) -> u64 {
        self.get() as u64
    }
}

pub struct GroupMediaKeyMaterial([u8; GROUP_MEDIA_KEY_BYTES]);

impl GroupMediaKeyMaterial {
    #[must_use]
    pub const fn new(bytes: [u8; GROUP_MEDIA_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; GROUP_MEDIA_KEY_BYTES] {
        &self.0
    }
}

impl Drop for GroupMediaKeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaReplayError {
    UnexpectedEpoch,
    Duplicate,
    TooOld,
}

#[derive(Debug)]
pub enum GroupMediaError {
    InvalidEpoch,
    InvalidReplayTolerance,
    MissingAssociatedData,
    AadTooLarge,
    FrameTooLarge,
    SealedFrameTooLarge,
    Replay(GroupMediaReplayError),
    Crypto(SframeError),
}

impl fmt::Display for GroupMediaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEpoch => formatter.write_str("group-media epoch must be non-zero"),
            Self::InvalidReplayTolerance => {
                formatter.write_str("group-media replay tolerance is outside the bounded range")
            }
            Self::MissingAssociatedData => {
                formatter.write_str("group-media associated data is required")
            }
            Self::AadTooLarge => formatter.write_str("group-media associated data is too large"),
            Self::FrameTooLarge => formatter.write_str("group-media plaintext frame is too large"),
            Self::SealedFrameTooLarge => {
                formatter.write_str("group-media sealed frame is too large")
            }
            Self::Replay(reason) => write!(formatter, "group-media replay rejected: {reason:?}"),
            Self::Crypto(error) => write!(formatter, "group-media SFrame error: {error}"),
        }
    }
}

impl std::error::Error for GroupMediaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::InvalidEpoch
            | Self::InvalidReplayTolerance
            | Self::MissingAssociatedData
            | Self::AadTooLarge
            | Self::FrameTooLarge
            | Self::SealedFrameTooLarge
            | Self::Replay(_) => None,
        }
    }
}

pub struct GroupMediaSender {
    epoch: GroupMediaEpoch,
    key: EncryptionKey,
    counter: MonotonicCounter,
}

impl GroupMediaSender {
    pub fn new(
        epoch: GroupMediaEpoch,
        key_material: GroupMediaKeyMaterial,
    ) -> Result<Self, GroupMediaError> {
        let key = EncryptionKey::derive_from(
            GROUP_MEDIA_CIPHER_SUITE,
            epoch.sframe_key_id(),
            key_material.as_bytes(),
        )
        .map_err(GroupMediaError::from_sframe)?;

        Ok(Self {
            epoch,
            key,
            counter: MonotonicCounter::default(),
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> GroupMediaEpoch {
        self.epoch
    }

    pub fn seal_frame(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, GroupMediaError> {
        validate_plaintext_len(plaintext.len())?;
        validate_aad_len(associated_data.len())?;

        let frame = MediaFrame::try_with_meta_data(&mut self.counter, plaintext, associated_data)
            .map_err(GroupMediaError::from_sframe)?;
        let encrypted = frame
            .encrypt(&self.key)
            .map_err(GroupMediaError::from_sframe)?;

        let header = Vec::from(encrypted.header());
        let mut sealed = Vec::with_capacity(header.len() + encrypted.cipher_text().len());
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(encrypted.cipher_text());
        validate_sealed_len(sealed.len())?;
        Ok(sealed)
    }
}

pub struct GroupMediaReceiver {
    epoch: GroupMediaEpoch,
    key: DecryptionKey,
    replay: ReplayAttackProtection,
}

impl GroupMediaReceiver {
    pub fn new(
        epoch: GroupMediaEpoch,
        key_material: GroupMediaKeyMaterial,
        replay_tolerance_frames: usize,
    ) -> Result<Self, GroupMediaError> {
        if !(1..=MAX_GROUP_MEDIA_REPLAY_TOLERANCE_FRAMES).contains(&replay_tolerance_frames) {
            return Err(GroupMediaError::InvalidReplayTolerance);
        }

        let tolerance = Tolerance::try_new(replay_tolerance_frames)
            .map_err(|_| GroupMediaError::InvalidReplayTolerance)?;
        let key = DecryptionKey::derive_from(
            GROUP_MEDIA_CIPHER_SUITE,
            epoch.sframe_key_id(),
            key_material.as_bytes(),
        )
        .map_err(GroupMediaError::from_sframe)?;

        Ok(Self {
            epoch,
            key,
            replay: ReplayAttackProtection::new(epoch.sframe_key_id(), tolerance),
        })
    }

    pub fn with_default_replay_tolerance(
        epoch: GroupMediaEpoch,
        key_material: GroupMediaKeyMaterial,
    ) -> Result<Self, GroupMediaError> {
        Self::new(
            epoch,
            key_material,
            DEFAULT_GROUP_MEDIA_REPLAY_TOLERANCE_FRAMES,
        )
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
        validate_sealed_len(sealed.len())?;
        validate_aad_len(associated_data.len())?;

        let encrypted = EncryptedFrameView::try_with_meta_data(sealed, associated_data)
            .map_err(GroupMediaError::from_sframe)?;
        let plaintext = encrypted
            .validated_decrypt(&self.key, &mut self.replay)
            .map_err(GroupMediaError::from_sframe)?;
        validate_plaintext_len(plaintext.payload().len())?;
        Ok(plaintext.payload().to_vec())
    }
}

fn validate_plaintext_len(len: usize) -> Result<(), GroupMediaError> {
    if len > MAX_GROUP_MEDIA_FRAME_BYTES {
        return Err(GroupMediaError::FrameTooLarge);
    }
    Ok(())
}

fn validate_aad_len(len: usize) -> Result<(), GroupMediaError> {
    if len == 0 {
        return Err(GroupMediaError::MissingAssociatedData);
    }
    if len > MAX_GROUP_MEDIA_AAD_BYTES {
        return Err(GroupMediaError::AadTooLarge);
    }
    Ok(())
}

fn validate_sealed_len(len: usize) -> Result<(), GroupMediaError> {
    if len > MAX_GROUP_MEDIA_SEALED_BYTES {
        return Err(GroupMediaError::SealedFrameTooLarge);
    }
    Ok(())
}

impl GroupMediaError {
    fn from_sframe(error: SframeError) -> Self {
        let replay = error
            .source_as::<ReplayAttackProtectionError>()
            .map(|reason| match reason {
                ReplayAttackProtectionError::KeyIdMismatch { .. } => {
                    GroupMediaReplayError::UnexpectedEpoch
                }
                ReplayAttackProtectionError::DuplicatedFrame { .. } => {
                    GroupMediaReplayError::Duplicate
                }
                ReplayAttackProtectionError::CounterTooOld { .. } => GroupMediaReplayError::TooOld,
            });

        replay.map_or(Self::Crypto(error), Self::Replay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(value: u32) -> GroupMediaEpoch {
        GroupMediaEpoch::new(value).expect("valid epoch")
    }

    fn key(value: u8) -> GroupMediaKeyMaterial {
        GroupMediaKeyMaterial::new([value; GROUP_MEDIA_KEY_BYTES])
    }

    fn pair(epoch_value: u32, key_value: u8) -> (GroupMediaSender, GroupMediaReceiver) {
        (
            GroupMediaSender::new(epoch(epoch_value), key(key_value)).expect("sender"),
            GroupMediaReceiver::with_default_replay_tolerance(epoch(epoch_value), key(key_value))
                .expect("receiver"),
        )
    }

    #[test]
    fn epoch_zero_is_rejected() {
        assert!(matches!(
            GroupMediaEpoch::new(0),
            Err(GroupMediaError::InvalidEpoch)
        ));
    }

    #[test]
    fn frame_round_trip_authenticates_external_associated_data() {
        let (mut sender, mut receiver) = pair(1, 0x11);
        let plaintext = b"encoded presentation frame";
        let aad = b"classmesh:presentation=7:stream=9:epoch=1";

        let sealed = sender
            .seal_frame(plaintext, aad)
            .expect("frame should encrypt");
        assert_ne!(sealed, plaintext);

        let opened = receiver
            .open_frame(&sealed, aad)
            .expect("frame should decrypt");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected_without_poisoning_replay_state() {
        let (mut sender, mut receiver) = pair(2, 0x22);
        let aad = b"presentation-binding";
        let sealed = sender.seal_frame(b"frame", aad).expect("encrypted frame");

        let mut tampered = sealed.clone();
        let last = tampered.last_mut().expect("sealed frame has tag");
        *last ^= 0x80;

        assert!(matches!(
            receiver.open_frame(&tampered, aad),
            Err(GroupMediaError::Crypto(_))
        ));

        assert_eq!(
            receiver
                .open_frame(&sealed, aad)
                .expect("original frame must still be accepted"),
            b"frame"
        );

        assert!(matches!(
            receiver.open_frame(&sealed, aad),
            Err(GroupMediaError::Replay(GroupMediaReplayError::Duplicate))
        ));
    }

    #[test]
    fn tampered_associated_data_is_rejected_without_consuming_counter() {
        let (mut sender, mut receiver) = pair(3, 0x33);
        let sealed = sender
            .seal_frame(b"frame", b"correct-binding")
            .expect("encrypted frame");

        assert!(matches!(
            receiver.open_frame(&sealed, b"wrong-binding"),
            Err(GroupMediaError::Crypto(_))
        ));

        assert_eq!(
            receiver
                .open_frame(&sealed, b"correct-binding")
                .expect("valid AAD must remain acceptable"),
            b"frame"
        );
    }

    #[test]
    fn another_epoch_is_rejected_before_decryption() {
        let mut sender = GroupMediaSender::new(epoch(4), key(0x44)).expect("sender");
        let mut receiver = GroupMediaReceiver::with_default_replay_tolerance(epoch(5), key(0x55))
            .expect("receiver");
        let sealed = sender
            .seal_frame(b"frame", b"binding")
            .expect("encrypted frame");

        assert!(matches!(
            receiver.open_frame(&sealed, b"binding"),
            Err(GroupMediaError::Replay(
                GroupMediaReplayError::UnexpectedEpoch
            ))
        ));
    }

    #[test]
    fn replay_window_accepts_in_window_reordering_and_rejects_too_old_frames() {
        let mut sender = GroupMediaSender::new(epoch(6), key(0x66)).expect("sender");
        let mut receiver = GroupMediaReceiver::new(epoch(6), key(0x66), 3).expect("receiver");
        let aad = b"bounded-replay";
        let frames: Vec<Vec<u8>> = (0..5)
            .map(|value| sender.seal_frame(&[value], aad).expect("encrypted frame"))
            .collect();

        assert_eq!(
            receiver.open_frame(&frames[4], aad).expect("newest frame"),
            vec![4]
        );
        assert_eq!(
            receiver
                .open_frame(&frames[3], aad)
                .expect("in-window reordered frame"),
            vec![3]
        );
        assert!(matches!(
            receiver.open_frame(&frames[0], aad),
            Err(GroupMediaError::Replay(GroupMediaReplayError::TooOld))
        ));
    }

    #[test]
    fn replay_tolerance_is_bounded() {
        assert!(matches!(
            GroupMediaReceiver::new(epoch(1), key(1), 0),
            Err(GroupMediaError::InvalidReplayTolerance)
        ));
        assert!(matches!(
            GroupMediaReceiver::new(
                epoch(1),
                key(1),
                MAX_GROUP_MEDIA_REPLAY_TOLERANCE_FRAMES + 1
            ),
            Err(GroupMediaError::InvalidReplayTolerance)
        ));
    }

    #[test]
    fn length_limits_are_checked_without_large_allocations() {
        assert!(validate_plaintext_len(MAX_GROUP_MEDIA_FRAME_BYTES).is_ok());
        assert!(matches!(
            validate_plaintext_len(MAX_GROUP_MEDIA_FRAME_BYTES + 1),
            Err(GroupMediaError::FrameTooLarge)
        ));
        assert!(matches!(
            validate_aad_len(0),
            Err(GroupMediaError::MissingAssociatedData)
        ));
        assert!(validate_aad_len(MAX_GROUP_MEDIA_AAD_BYTES).is_ok());
        assert!(matches!(
            validate_aad_len(MAX_GROUP_MEDIA_AAD_BYTES + 1),
            Err(GroupMediaError::AadTooLarge)
        ));
        assert!(validate_sealed_len(MAX_GROUP_MEDIA_SEALED_BYTES).is_ok());
        assert!(matches!(
            validate_sealed_len(MAX_GROUP_MEDIA_SEALED_BYTES + 1),
            Err(GroupMediaError::SealedFrameTooLarge)
        ));
    }
}
