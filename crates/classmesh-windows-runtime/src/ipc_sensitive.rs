use std::collections::VecDeque;
use std::fmt;

use classmesh_protocol::control_wire::{PresentationKeyAck, PresentationKeyGrant};
use classmesh_protocol::group_media_control::{
    PRESENTATION_GROUP_KEY_BYTES, validate_key_ack, validate_key_grant,
};
use zeroize::{Zeroize, Zeroizing};

use crate::ipc::{
    IPC_HEADER_LEN, IPC_VERSION_MAJOR, IPC_VERSION_MINOR, IpcFrame, IpcFrameError, IpcHeader,
    MAX_IPC_MESSAGE, MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
};

pub const PRESENTATION_KEY_INSTALL_PAYLOAD_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationKeyInstallBinding {
    pub control_session_id: u64,
    pub request_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}

pub struct SensitivePresentationKeyInstall {
    binding: PresentationKeyInstallBinding,
    key_material: Zeroizing<[u8; PRESENTATION_GROUP_KEY_BYTES]>,
}

impl fmt::Debug for SensitivePresentationKeyInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitivePresentationKeyInstall")
            .field("binding", &self.binding)
            .field("key_material_len", &PRESENTATION_GROUP_KEY_BYTES)
            .finish_non_exhaustive()
    }
}

impl SensitivePresentationKeyInstall {
    pub fn take_from_control_grant(
        control_session_id: u64,
        request_id: u64,
        grant: &mut PresentationKeyGrant,
    ) -> Result<Self, crate::ipc::IpcMessageError> {
        let result = (|| {
            if control_session_id == 0 || request_id == 0 {
                return Err(crate::ipc::IpcMessageError::InvalidPayload);
            }
            validate_key_grant(grant)
                .map_err(|_| crate::ipc::IpcMessageError::InvalidPayload)?;

            let stream_id = u32::try_from(grant.stream_id)
                .map_err(|_| crate::ipc::IpcMessageError::InvalidPayload)?;
            let mut key_material = Zeroizing::new([0_u8; PRESENTATION_GROUP_KEY_BYTES]);
            key_material.copy_from_slice(&grant.key_material);

            Ok(Self {
                binding: PresentationKeyInstallBinding {
                    control_session_id,
                    request_id,
                    presentation_id: grant.presentation_id,
                    stream_id,
                    epoch: grant.epoch,
                },
                key_material,
            })
        })();

        grant.key_material.zeroize();
        result
    }

    #[must_use]
    pub const fn binding(&self) -> PresentationKeyInstallBinding {
        self.binding
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PresentationKeyInstallBinding,
        Zeroizing<[u8; PRESENTATION_GROUP_KEY_BYTES]>,
    ) {
        (self.binding, self.key_material)
    }

    pub fn encode(self) -> Result<Zeroizing<Vec<u8>>, IpcFrameError> {
        let header = IpcHeader {
            version_major: IPC_VERSION_MAJOR,
            version_minor: IPC_VERSION_MINOR,
            message_type: MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
            payload_len: u32::try_from(PRESENTATION_KEY_INSTALL_PAYLOAD_LEN)
                .map_err(|_| IpcFrameError::PayloadTooLarge)?,
        }
        .encode()?;

        let mut output =
            Zeroizing::new(Vec::with_capacity(IPC_HEADER_LEN + PRESENTATION_KEY_INSTALL_PAYLOAD_LEN));
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.binding.control_session_id.to_be_bytes());
        output.extend_from_slice(&self.binding.request_id.to_be_bytes());
        output.extend_from_slice(&self.binding.presentation_id.to_be_bytes());
        output.extend_from_slice(&self.binding.stream_id.to_be_bytes());
        output.extend_from_slice(&self.binding.epoch.to_be_bytes());
        output.extend_from_slice(self.key_material.as_slice());
        debug_assert_eq!(
            output.len(),
            IPC_HEADER_LEN + PRESENTATION_KEY_INSTALL_PAYLOAD_LEN
        );
        Ok(output)
    }

    fn decode_payload(
        payload: Zeroizing<Vec<u8>>,
    ) -> Result<Self, IpcFrameError> {
        if payload.len() != PRESENTATION_KEY_INSTALL_PAYLOAD_LEN {
            return Err(IpcFrameError::InvalidSensitivePayload);
        }

        let control_session_id =
            u64::from_be_bytes(payload[0..8].try_into().expect("eight bytes"));
        let request_id = u64::from_be_bytes(payload[8..16].try_into().expect("eight bytes"));
        let presentation_id =
            u64::from_be_bytes(payload[16..24].try_into().expect("eight bytes"));
        let stream_id = u32::from_be_bytes(payload[24..28].try_into().expect("four bytes"));
        let epoch = u32::from_be_bytes(payload[28..32].try_into().expect("four bytes"));

        if control_session_id == 0 || request_id == 0 {
            return Err(IpcFrameError::InvalidSensitivePayload);
        }
        validate_key_ack(&PresentationKeyAck {
            presentation_id,
            stream_id: u64::from(stream_id),
            epoch,
        })
        .map_err(|_| IpcFrameError::InvalidSensitivePayload)?;

        let mut key_material = Zeroizing::new([0_u8; PRESENTATION_GROUP_KEY_BYTES]);
        key_material.copy_from_slice(&payload[32..]);

        Ok(Self {
            binding: PresentationKeyInstallBinding {
                control_session_id,
                request_id,
                presentation_id,
                stream_id,
                epoch,
            },
            key_material,
        })
    }
}

#[derive(Debug)]
pub enum DecodedIpcFrame {
    Regular(IpcFrame),
    PresentationKeyInstall(SensitivePresentationKeyInstall),
}

/// Decoder for authenticated Service -> Worker IPC paths that may carry presentation key material.
///
/// The buffer is allocated to its maximum bounded size up front so secret bytes are never moved by
/// a VecDeque reallocation. Caller-owned read buffers are zeroized immediately after copying.
/// Sensitive payload slots are zeroized before removal and all remaining buffered bytes are
/// zeroized on any parser error or decoder drop.
#[derive(Debug)]
pub struct SensitiveIpcFrameDecoder {
    buffer: VecDeque<u8>,
}

impl Default for SensitiveIpcFrameDecoder {
    fn default() -> Self {
        Self {
            buffer: VecDeque::with_capacity(MAX_IPC_MESSAGE + IPC_HEADER_LEN),
        }
    }
}

impl SensitiveIpcFrameDecoder {
    pub fn push_bytes_zeroizing(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<Vec<DecodedIpcFrame>, IpcFrameError> {
        let new_len = self.buffer.len().saturating_add(bytes.len());
        if new_len > MAX_IPC_MESSAGE + IPC_HEADER_LEN || new_len > self.buffer.capacity() {
            bytes.zeroize();
            self.zeroize_buffer();
            return Err(IpcFrameError::PayloadTooLarge);
        }

        self.buffer.extend(bytes.iter().copied());
        bytes.zeroize();
        self.decode_available()
    }

    fn decode_available(&mut self) -> Result<Vec<DecodedIpcFrame>, IpcFrameError> {
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < IPC_HEADER_LEN {
                break;
            }

            let mut header_bytes = [0_u8; IPC_HEADER_LEN];
            for (target, source) in header_bytes.iter_mut().zip(self.buffer.iter()) {
                *target = *source;
            }
            let header = match IpcHeader::decode(&header_bytes) {
                Ok(header) => header,
                Err(error) => {
                    self.zeroize_buffer();
                    return Err(error);
                }
            };
            let payload_len = match usize::try_from(header.payload_len) {
                Ok(payload_len) => payload_len,
                Err(_) => {
                    self.zeroize_buffer();
                    return Err(IpcFrameError::PayloadTooLarge);
                }
            };
            let frame_len = IPC_HEADER_LEN.saturating_add(payload_len);

            if header.message_type == MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL
                && (header.version_major != IPC_VERSION_MAJOR
                    || header.version_minor != IPC_VERSION_MINOR
                    || payload_len != PRESENTATION_KEY_INSTALL_PAYLOAD_LEN)
            {
                self.zeroize_buffer();
                return Err(IpcFrameError::InvalidSensitivePayload);
            }
            if self.buffer.len() < frame_len {
                break;
            }

            for _ in 0..IPC_HEADER_LEN {
                let _ = self.buffer.pop_front();
            }

            if header.message_type == MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL {
                let mut payload = Zeroizing::new(Vec::with_capacity(payload_len));
                for _ in 0..payload_len {
                    let mut value = *self.buffer.front().expect("frame length was checked");
                    if let Some(front) = self.buffer.front_mut() {
                        front.zeroize();
                    }
                    let _ = self.buffer.pop_front();
                    payload.push(value);
                    value.zeroize();
                }

                let sensitive = match SensitivePresentationKeyInstall::decode_payload(payload) {
                    Ok(sensitive) => sensitive,
                    Err(error) => {
                        self.zeroize_buffer();
                        return Err(error);
                    }
                };
                frames.push(DecodedIpcFrame::PresentationKeyInstall(sensitive));
            } else {
                let mut payload = Vec::with_capacity(payload_len);
                for _ in 0..payload_len {
                    payload.push(self.buffer.pop_front().expect("frame length was checked"));
                }
                frames.push(DecodedIpcFrame::Regular(IpcFrame { header, payload }));
            }
        }

        Ok(frames)
    }

    fn zeroize_buffer(&mut self) {
        for byte in &mut self.buffer {
            byte.zeroize();
        }
        self.buffer.clear();
    }

    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Drop for SensitiveIpcFrameDecoder {
    fn drop(&mut self) {
        self.zeroize_buffer();
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::control_wire::PresentationKeyGrant;

    use super::*;
    use crate::ipc::{IpcFrameDecoder, IpcMessage};

    fn grant(value: u8) -> PresentationKeyGrant {
        PresentationKeyGrant {
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            key_material: vec![value; PRESENTATION_GROUP_KEY_BYTES],
        }
    }

    fn sensitive(value: u8) -> SensitivePresentationKeyInstall {
        let mut grant = grant(value);
        let sensitive = SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant)
            .expect("valid sensitive IPC install");
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
        sensitive
    }

    #[test]
    fn control_grant_is_taken_once_and_source_is_zeroized() {
        let mut grant = grant(0x5a);
        let install =
            SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant)
                .expect("valid grant");
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
        assert_eq!(
            install.binding(),
            PresentationKeyInstallBinding {
                control_session_id: 77,
                request_id: 44,
                presentation_id: 55,
                stream_id: 7,
                epoch: 3,
            }
        );
        let debug = format!("{install:?}");
        assert!(debug.contains("key_material_len"));
        assert!(!debug.contains("[90"));
    }

    #[test]
    fn rejected_control_grant_still_zeroizes_source_key() {
        let mut grant = grant(0x6a);
        grant.stream_id = 0;
        assert_eq!(
            SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant).err(),
            Some(crate::ipc::IpcMessageError::InvalidPayload)
        );
        assert!(grant.key_material.iter().all(|byte| *byte == 0));

        let mut grant = grant(0x6b);
        assert_eq!(
            SensitivePresentationKeyInstall::take_from_control_grant(0, 44, &mut grant).err(),
            Some(crate::ipc::IpcMessageError::InvalidPayload)
        );
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn generic_decoder_rejects_sensitive_message_type() {
        let encoded = sensitive(0x44).encode().expect("sensitive frame encodes");
        let mut decoder = IpcFrameDecoder::default();
        assert_eq!(
            decoder.push_bytes(encoded.as_slice()),
            Err(IpcFrameError::SensitiveMessageRequiresZeroizingDecoder)
        );
    }

    #[test]
    fn sensitive_decoder_round_trips_fragmented_key_and_zeroizes_input_chunks() {
        let mut encoded = sensitive(0x33).encode().expect("sensitive frame encodes");
        let split = IPC_HEADER_LEN + 40;
        let (first, second) = encoded.split_at_mut(split);
        let mut decoder = SensitiveIpcFrameDecoder::default();

        assert!(decoder
            .push_bytes_zeroizing(first)
            .expect("first fragment accepted")
            .is_empty());
        assert!(first.iter().all(|byte| *byte == 0));

        let mut decoded = decoder
            .push_bytes_zeroizing(second)
            .expect("second fragment accepted");
        assert!(second.iter().all(|byte| *byte == 0));
        assert_eq!(decoded.len(), 1);

        let DecodedIpcFrame::PresentationKeyInstall(install) = decoded.remove(0) else {
            panic!("expected sensitive presentation-key install");
        };
        assert_eq!(install.binding().control_session_id, 77);
        assert_eq!(install.binding().request_id, 44);
        assert_eq!(install.binding().presentation_id, 55);
        assert_eq!(install.binding().stream_id, 7);
        assert_eq!(install.binding().epoch, 3);

        let (_, key_material) = install.into_parts();
        assert!(key_material.iter().all(|byte| *byte == 0x33));
    }

    #[test]
    fn malformed_sensitive_frame_zeroizes_caller_and_internal_buffer() {
        let header = IpcHeader {
            version_major: IPC_VERSION_MAJOR,
            version_minor: IPC_VERSION_MINOR,
            message_type: MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
            payload_len: 1,
        }
        .encode()
        .expect("header encodes");
        let mut bytes = Vec::from(header);
        bytes.push(0x5a);

        let mut decoder = SensitiveIpcFrameDecoder::default();
        assert_eq!(
            decoder.push_bytes_zeroizing(bytes.as_mut_slice()),
            Err(IpcFrameError::InvalidSensitivePayload)
        );
        assert!(bytes.iter().all(|byte| *byte == 0));
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn secure_decoder_preserves_regular_message_behavior_and_zeroizes_read_buffer() {
        let mut bytes = IpcFrame::worker_hello(42, 7)
            .encode()
            .expect("worker hello encodes");
        let mut decoder = SensitiveIpcFrameDecoder::default();
        let mut decoded = decoder
            .push_bytes_zeroizing(bytes.as_mut_slice())
            .expect("regular frame accepted");
        assert!(bytes.iter().all(|byte| *byte == 0));

        let DecodedIpcFrame::Regular(frame) = decoded.remove(0) else {
            panic!("expected regular IPC frame");
        };
        assert_eq!(
            frame.message().expect("regular message remains typed"),
            IpcMessage::WorkerHello {
                process_id: 42,
                session_id: 7,
            }
        );
    }
}
