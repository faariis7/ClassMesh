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
const GROUP_MEDIA_AAD_MAGIC: &[u8; 4] = b"CMG1";
pub const GROUP_MEDIA_BOUND_AAD_BYTES: usize = 40;

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

/// Canonical non-secret metadata authenticated alongside one SFrame-protected presentation frame.
///
/// The fixed-width encoding is intentionally transport-neutral: packet sequence/index fields are
/// excluded because packetization happens after SFrame sealing. The receiver reconstructs this
/// exact binding from its authenticated presentation state plus the assembled media frame metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMediaFrameBinding {
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
    frame_id: u64,
    timestamp_us: u64,
    keyframe: bool,
}

impl GroupMediaFrameBinding {
    pub fn new(
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        frame_id: u64,
        timestamp_us: u64,
        keyframe: bool,
    ) -> Result<Self, GroupMediaError> {
        if presentation_id == 0 {
            return Err(GroupMediaError::InvalidPresentationId);
        }
        if stream_id == 0 {
            return Err(GroupMediaError::InvalidStreamId);
        }
        Ok(Self {
            presentation_id,
            stream_id,
            epoch,
            frame_id,
            timestamp_us,
            keyframe,
        })
    }

    #[must_use]
    pub const fn presentation_id(self) -> u64 {
        self.presentation_id
    }

    #[must_use]
    pub const fn stream_id(self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn epoch(self) -> GroupMediaEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn frame_id(self) -> u64 {
        self.frame_id
    }

    #[must_use]
    pub const fn timestamp_us(self) -> u64 {
        self.timestamp_us
    }

    #[must_use]
    pub const fn keyframe(self) -> bool {
        self.keyframe
    }

    fn associated_data(self) -> [u8; GROUP_MEDIA_BOUND_AAD_BYTES] {
        let mut aad = [0_u8; GROUP_MEDIA_BOUND_AAD_BYTES];
        aad[0..4].copy_from_slice(GROUP_MEDIA_AAD_MAGIC);
        aad[4..12].copy_from_slice(&self.presentation_id.to_be_bytes());
        aad[12..16].copy_from_slice(&self.stream_id.to_be_bytes());
        aad[16..20].copy_from_slice(&self.epoch.get().to_be_bytes());
        aad[20..28].copy_from_slice(&self.frame_id.to_be_bytes());
        aad[28..36].copy_from_slice(&self.timestamp_us.to_be_bytes());
        aad[36] = u8::from(self.keyframe);
        aad
    }
}

pub struct GroupMediaKeyMaterial([u8; GROUP_MEDIA_KEY_BYTES]);

impl GroupMediaKeyMaterial {
    pub fn generate() -> Result<Self, GroupMediaError> {
        let mut bytes = [0_u8; GROUP_MEDIA_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| GroupMediaError::KeyGenerationFailed)?;
        Ok(Self(bytes))
    }

    /// Imports authenticated control-wire key bytes for a receiver and zeroizes
    /// the caller-owned buffer on both success and failure.
    ///
    /// This is deliberately separate from `generate`: sender keys are created
    /// locally with the OS CSPRNG, while receivers may install exactly one
    /// authenticated 32-byte grant delivered by the control plane.
    pub fn import_received_wire(bytes: &mut [u8]) -> Result<Self, GroupMediaError> {
        if bytes.len() != GROUP_MEDIA_KEY_BYTES {
            bytes.zeroize();
            return Err(GroupMediaError::InvalidKeyMaterialLength);
        }

        let mut key = [0_u8; GROUP_MEDIA_KEY_BYTES];
        key.copy_from_slice(bytes);
        bytes.zeroize();

        let material = Self(key);
        key.zeroize();
        Ok(material)
    }

    #[cfg(test)]
    const fn from_test_bytes(bytes: [u8; GROUP_MEDIA_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; GROUP_MEDIA_KEY_BYTES] {
        &self.0
    }

    pub(crate) const fn copy_bytes(&self) -> [u8; GROUP_MEDIA_KEY_BYTES] {
        self.0
    }
}

impl Drop for GroupMediaKeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Opaque SFrame ciphertext intended for the group-media transport path.
///
/// There is deliberately no public constructor from raw H.264 bytes. Production multicast code can
/// require this type and therefore cannot accidentally accept an unprotected encoded frame.
pub struct SealedGroupMediaFrame {
    binding: GroupMediaFrameBinding,
    data: Vec<u8>,
}

impl SealedGroupMediaFrame {
    #[must_use]
    pub const fn binding(&self) -> GroupMediaFrameBinding {
        self.binding
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SealedGroupMediaFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedGroupMediaFrame")
            .field("binding", &self.binding)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
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
    InvalidPresentationId,
    InvalidStreamId,
    BindingEpochMismatch,
    InvalidReplayTolerance,
    InvalidKeyMaterialLength,
    KeyGenerationFailed,
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
            Self::InvalidPresentationId => {
                formatter.write_str("group-media presentation id must be non-zero")
            }
            Self::InvalidStreamId => formatter.write_str("group-media stream id must be non-zero"),
            Self::BindingEpochMismatch => {
                formatter.write_str("group-media frame binding epoch does not match installed key")
            }
            Self::InvalidReplayTolerance => {
                formatter.write_str("group-media replay tolerance is outside the bounded range")
            }
            Self::InvalidKeyMaterialLength => {
                formatter.write_str("group-media key material must be exactly 32 bytes")
            }
            Self::KeyGenerationFailed => formatter.write_str("group-media key generation failed"),
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
            | Self::InvalidPresentationId
            | Self::InvalidStreamId
            | Self::BindingEpochMismatch
            | Self::InvalidReplayTolerance
            | Self::InvalidKeyMaterialLength
            | Self::KeyGenerationFailed
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
        key_material: &GroupMediaKeyMaterial,
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

    pub fn seal_bound_frame(
        &mut self,
        plaintext: &[u8],
        binding: GroupMediaFrameBinding,
    ) -> Result<SealedGroupMediaFrame, GroupMediaError> {
        if binding.epoch() != self.epoch {
            return Err(GroupMediaError::BindingEpochMismatch);
        }
        let associated_data = binding.associated_data();
        let data = self.seal_frame(plaintext, &associated_data)?;
        Ok(SealedGroupMediaFrame { binding, data })
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
        key_material: &GroupMediaKeyMaterial,
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
        key_material: &GroupMediaKeyMaterial,
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

    pub fn open_bound_frame(
        &mut self,
        sealed: &[u8],
        binding: GroupMediaFrameBinding,
    ) -> Result<Vec<u8>, GroupMediaError> {
        if binding.epoch() != self.epoch {
            return Err(GroupMediaError::BindingEpochMismatch);
        }
        let associated_data = binding.associated_data();
        self.open_frame(sealed, &associated_data)
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
        GroupMediaKeyMaterial::from_test_bytes([value; GROUP_MEDIA_KEY_BYTES])
    }

    fn pair(epoch_value: u32, key_value: u8) -> (GroupMediaSender, GroupMediaReceiver) {
        let material = key(key_value);
        (
            GroupMediaSender::new(epoch(epoch_value), &material).expect("sender"),
            GroupMediaReceiver::with_default_replay_tolerance(epoch(epoch_value), &material)
                .expect("receiver"),
        )
    }

    #[test]
    fn production_generated_key_supports_authenticated_round_trip() {
        let material = GroupMediaKeyMaterial::generate().expect("generated key");
        let mut sender = GroupMediaSender::new(epoch(7), &material).expect("sender");
        let mut receiver = GroupMediaReceiver::with_default_replay_tolerance(epoch(7), &material)
            .expect("receiver");
        let aad = b"generated-key-binding";
        let sealed = sender
            .seal_frame(b"generated-key-frame", aad)
            .expect("encrypted frame");

        assert_eq!(
            receiver
                .open_frame(&sealed, aad)
                .expect("generated key should decrypt"),
            b"generated-key-frame"
        );
    }

    #[test]
    fn received_wire_key_import_zeroizes_source_and_builds_matching_receiver() {
        let mut sender_bytes = vec![0x77; GROUP_MEDIA_KEY_BYTES];
        let sender_material =
            GroupMediaKeyMaterial::import_received_wire(&mut sender_bytes).expect("sender key");
        assert!(sender_bytes.iter().all(|byte| *byte == 0));

        let mut received_bytes = vec![0x77; GROUP_MEDIA_KEY_BYTES];
        let received_material =
            GroupMediaKeyMaterial::import_received_wire(&mut received_bytes).expect("wire key");
        assert!(received_bytes.iter().all(|byte| *byte == 0));

        let mut sender = GroupMediaSender::new(epoch(8), &sender_material).expect("sender");
        let mut receiver =
            GroupMediaReceiver::with_default_replay_tolerance(epoch(8), &received_material)
                .expect("receiver");
        let sealed = sender
            .seal_frame(b"wire-key-frame", b"wire-key-binding")
            .expect("sealed frame");
        assert_eq!(
            receiver
                .open_frame(&sealed, b"wire-key-binding")
                .expect("matching imported key"),
            b"wire-key-frame"
        );
    }

    #[test]
    fn invalid_received_wire_key_length_is_rejected_and_zeroized() {
        let mut received_bytes = vec![0x44; GROUP_MEDIA_KEY_BYTES - 1];
        assert!(matches!(
            GroupMediaKeyMaterial::import_received_wire(&mut received_bytes),
            Err(GroupMediaError::InvalidKeyMaterialLength)
        ));
        assert!(received_bytes.iter().all(|byte| *byte == 0));
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
    fn bound_frame_aad_is_fixed_width_big_endian_and_versioned() {
        let binding = GroupMediaFrameBinding::new(
            0x0102_0304_0506_0708,
            0x1112_1314,
            epoch(0x2122_2324),
            0x3132_3334_3536_3738,
            0x4142_4344_4546_4748,
            true,
        )
        .expect("valid binding");
        let aad = binding.associated_data();

        assert_eq!(aad.len(), GROUP_MEDIA_BOUND_AAD_BYTES);
        assert_eq!(&aad[0..4], b"CMG1");
        assert_eq!(&aad[4..12], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&aad[12..16], &0x1112_1314_u32.to_be_bytes());
        assert_eq!(&aad[16..20], &0x2122_2324_u32.to_be_bytes());
        assert_eq!(&aad[20..28], &0x3132_3334_3536_3738_u64.to_be_bytes());
        assert_eq!(&aad[28..36], &0x4142_4344_4546_4748_u64.to_be_bytes());
        assert_eq!(aad[36], 1);
        assert_eq!(&aad[37..40], &[0, 0, 0]);
    }

    #[test]
    fn bound_frame_round_trip_authenticates_presentation_metadata() {
        let material = key(0x71);
        let epoch = epoch(7);
        let mut sender = GroupMediaSender::new(epoch, &material).expect("sender");
        let mut receiver =
            GroupMediaReceiver::with_default_replay_tolerance(epoch, &material).expect("receiver");
        let binding = GroupMediaFrameBinding::new(10, 20, epoch, 30, 40, true)
            .expect("valid binding");
        let sealed = sender
            .seal_bound_frame(b"protected presentation frame", binding)
            .expect("sealed bound frame");

        assert!(!sealed.is_empty());
        assert_eq!(sealed.binding(), binding);
        assert_eq!(
            receiver
                .open_bound_frame(sealed.as_bytes(), binding)
                .expect("matching binding opens"),
            b"protected presentation frame"
        );
    }

    #[test]
    fn wrong_bound_metadata_fails_without_consuming_replay_state() {
        let material = key(0x72);
        let epoch = epoch(8);
        let mut sender = GroupMediaSender::new(epoch, &material).expect("sender");
        let mut receiver =
            GroupMediaReceiver::with_default_replay_tolerance(epoch, &material).expect("receiver");
        let binding = GroupMediaFrameBinding::new(11, 21, epoch, 31, 41, false)
            .expect("valid binding");
        let sealed = sender
            .seal_bound_frame(b"frame", binding)
            .expect("sealed bound frame");
        let wrong = GroupMediaFrameBinding::new(12, 21, epoch, 31, 41, false)
            .expect("valid wrong binding");

        assert!(matches!(
            receiver.open_bound_frame(sealed.as_bytes(), wrong),
            Err(GroupMediaError::Crypto(_))
        ));
        assert_eq!(
            receiver
                .open_bound_frame(sealed.as_bytes(), binding)
                .expect("failed authentication must not consume replay state"),
            b"frame"
        );
    }

    #[test]
    fn bound_frame_requires_nonzero_ids_and_matching_epoch() {
        let first = epoch(9);
        let second = epoch(10);
        assert!(matches!(
            GroupMediaFrameBinding::new(0, 1, first, 1, 1, false),
            Err(GroupMediaError::InvalidPresentationId)
        ));
        assert!(matches!(
            GroupMediaFrameBinding::new(1, 0, first, 1, 1, false),
            Err(GroupMediaError::InvalidStreamId)
        ));

        let material = key(0x73);
        let mut sender = GroupMediaSender::new(first, &material).expect("sender");
        let binding = GroupMediaFrameBinding::new(1, 2, second, 3, 4, false)
            .expect("binding");
        assert!(matches!(
            sender.seal_bound_frame(b"frame", binding),
            Err(GroupMediaError::BindingEpochMismatch)
        ));
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
        let mut sender = GroupMediaSender::new(epoch(4), &key(0x44)).expect("sender");
        let mut receiver = GroupMediaReceiver::with_default_replay_tolerance(epoch(5), &key(0x55))
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
        let mut sender = GroupMediaSender::new(epoch(6), &key(0x66)).expect("sender");
        let mut receiver = GroupMediaReceiver::new(epoch(6), &key(0x66), 3).expect("receiver");
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
            GroupMediaReceiver::new(epoch(1), &key(1), 0),
            Err(GroupMediaError::InvalidReplayTolerance)
        ));
        assert!(matches!(
            GroupMediaReceiver::new(
                epoch(1),
                &key(1),
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
