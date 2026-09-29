use std::collections::VecDeque;

use zeroize::{Zeroize, Zeroizing};

use crate::ipc::{
    IPC_HEADER_LEN, IPC_VERSION_MAJOR, IPC_VERSION_MINOR, IpcFrame, IpcFrameError, IpcHeader,
    MAX_IPC_MESSAGE, MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
};

use super::contract::{PRESENTATION_KEY_INSTALL_PAYLOAD_LEN, SensitivePresentationKeyInstall};

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
                frames.push(DecodedIpcFrame::PresentationKeyInstall(
                    self.decode_sensitive_payload(payload_len)?,
                ));
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

    fn decode_sensitive_payload(
        &mut self,
        payload_len: usize,
    ) -> Result<SensitivePresentationKeyInstall, IpcFrameError> {
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

        match SensitivePresentationKeyInstall::decode_payload(payload) {
            Ok(sensitive) => Ok(sensitive),
            Err(error) => {
                self.zeroize_buffer();
                Err(error)
            }
        }
    }

    fn zeroize_buffer(&mut self) {
        for byte in &mut self.buffer {
            byte.zeroize();
        }
        self.buffer.clear();
    }

    #[cfg(test)]
    pub(super) fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Drop for SensitiveIpcFrameDecoder {
    fn drop(&mut self) {
        self.zeroize_buffer();
    }
}
