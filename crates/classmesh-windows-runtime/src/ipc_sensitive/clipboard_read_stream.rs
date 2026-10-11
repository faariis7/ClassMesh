//! Reserved v12 Worker->Service streaming clipboard read-success decoder.
//! Deliberately not wired into the active v11 Service IPC reader.
//! Only the specific sensitive read-success message is accepted.
use std::fmt;

use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
use zeroize::{Zeroize, Zeroizing};

use super::clipboard_read_frame::{
    CLIPBOARD_READ_SUCCESS_FUTURE_MINOR, CLIPBOARD_READ_SUCCESS_RESERVED_TYPE,
    ClipboardReadFrameError, decode_sensitive_clipboard_read_frame,
};
use super::clipboard_read_success::{
    CLIPBOARD_READ_SUCCESS_FIXED_LEN, SensitiveClipboardReadSuccess,
};
use crate::ipc::{IPC_HEADER_LEN, IPC_VERSION_MAJOR, IpcHeader};

const MAX_SENSITIVE_READ_FRAME: usize =
    IPC_HEADER_LEN + CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardStreamState {
    Collecting,
    Complete,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardStreamError {
    Finished,
    MalformedHeader,
    WrongVersion,
    WrongMessage,
    PayloadTooLarge,
    LengthMismatch,
    InvalidFrame(ClipboardReadFrameError),
}

/// Bounded single-flight parser for one sensitive response; no generic
/// plaintext IPC frame or Debug output is ever constructed.
pub struct SensitiveClipboardReadStream {
    buffer: Zeroizing<Vec<u8>>,
    state: ClipboardStreamState,
}

impl Default for SensitiveClipboardReadStream {
    fn default() -> Self {
        Self {
            buffer: Zeroizing::new(Vec::with_capacity(MAX_SENSITIVE_READ_FRAME)),
            state: ClipboardStreamState::Collecting,
        }
    }
}

impl fmt::Debug for SensitiveClipboardReadStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveClipboardReadStream")
            .field("state", &self.state)
            .field("buffered_bytes", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

impl SensitiveClipboardReadStream {
    #[must_use]
    pub const fn state(&self) -> ClipboardStreamState {
        self.state
    }

    fn reject<T>(&mut self, error: ClipboardStreamError) -> Result<T, ClipboardStreamError> {
        self.buffer.zeroize();
        self.state = ClipboardStreamState::Rejected;
        Err(error)
    }

    /// Immediately zeroizes the caller-owned input chunk, regardless of state
    /// or result. Rejects concatenated messages rather than emitting partial
    /// clipboard text or accepting generic IPC messages.
    pub fn push_bytes(
        &mut self,
        incoming: &mut [u8],
    ) -> Result<Option<SensitiveClipboardReadSuccess>, ClipboardStreamError> {
        if self.state != ClipboardStreamState::Collecting {
            incoming.zeroize();
            return Err(ClipboardStreamError::Finished);
        }

        if self.buffer.len().saturating_add(incoming.len()) > MAX_SENSITIVE_READ_FRAME {
            incoming.zeroize();
            return self.reject(ClipboardStreamError::PayloadTooLarge);
        }

        self.buffer.extend_from_slice(incoming);
        incoming.zeroize();

        if self.buffer.len() < IPC_HEADER_LEN {
            return Ok(None);
        }
        let header = match IpcHeader::decode(&self.buffer) {
            Ok(header) => header,
            Err(_) => return self.reject(ClipboardStreamError::MalformedHeader),
        };
        if header.version_major != IPC_VERSION_MAJOR
            || header.version_minor != CLIPBOARD_READ_SUCCESS_FUTURE_MINOR
        {
            return self.reject(ClipboardStreamError::WrongVersion);
        }
        if header.message_type != CLIPBOARD_READ_SUCCESS_RESERVED_TYPE {
            return self.reject(ClipboardStreamError::WrongMessage);
        }

        let Ok(payload_len) = usize::try_from(header.payload_len) else {
            return self.reject(ClipboardStreamError::PayloadTooLarge);
        };
        if payload_len > CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES {
            return self.reject(ClipboardStreamError::PayloadTooLarge);
        }
        if payload_len < CLIPBOARD_READ_SUCCESS_FIXED_LEN {
            return self.reject(ClipboardStreamError::LengthMismatch);
        }
        let total = IPC_HEADER_LEN + payload_len;
        if self.buffer.len() > total {
            return self.reject(ClipboardStreamError::LengthMismatch);
        }
        if self.buffer.len() < total {
            return Ok(None);
        }

        // Transfer the sole buffer to the typed zeroizing decoder. The old
        // allocation is wiped on both success and parser failure.
        let frame = std::mem::replace(&mut self.buffer, Zeroizing::new(Vec::new()));
        self.state = ClipboardStreamState::Complete;
        match decode_sensitive_clipboard_read_frame(frame) {
            Ok(sensitive) => Ok(Some(sensitive)),
            Err(error) => {
                self.state = ClipboardStreamState::Rejected;
                Err(ClipboardStreamError::InvalidFrame(error))
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_sensitive::{
        ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess,
        encode_sensitive_clipboard_read_frame,
    };

    fn make_frame() -> Zeroizing<Vec<u8>> {
        let secret = SensitiveClipboardReadSuccess::new(
            ClipboardReadSuccessBinding {
                worker_process_id: 42,
                worker_session_id: 7,
                worker_generation: 4,
                control_session_id: 77,
                control_sequence: 101,
                request_id: 19,
            },
            Zeroizing::new("سر تجريبي é😀".as_bytes().to_vec()),
        )
        .expect("valid test text");
        encode_sensitive_clipboard_read_frame(&secret)
    }

    #[test]
    fn fragmented_header_and_payload_roundtrip_zeroizes_input() {
        let mut stream = SensitiveClipboardReadStream::default();
        let mut frame = make_frame();
        let frame_len = frame.len();
        assert!(
            stream
                .push_bytes(&mut frame[..5])
                .expect("partial header")
                .is_none()
        );
        assert!(frame[..5].iter().all(|b| *b == 0));
        assert!(
            stream
                .push_bytes(&mut frame[5..12])
                .expect("complete header")
                .is_none()
        );
        assert!(
            stream
                .push_bytes(&mut frame[12..18])
                .expect("partial payload")
                .is_none()
        );
        assert!(!format!("{stream:?}").contains("سر تجريبي"));
        let result = stream
            .push_bytes(&mut frame[18..frame_len])
            .expect("complete payload")
            .expect("one sensitive result");
        assert_eq!(result.text(), "سر تجريبي é😀");
        assert!(frame.iter().all(|b| *b == 0));
        assert_eq!(stream.state(), ClipboardStreamState::Complete);
        let mut new_data = vec![42_u8; 4];
        assert_eq!(
            stream.push_bytes(&mut new_data).err(),
            Some(ClipboardStreamError::Finished)
        );
        assert!(new_data.iter().all(|b| *b == 0));
    }

    #[test]
    fn wrong_version_type_or_magic_is_rejected_and_clears_buffer() {
        for index in [0_usize, 5, 7] {
            let mut stream = SensitiveClipboardReadStream::default();
            let mut frame = make_frame();
            frame[index] ^= 1;
            let outcome = stream.push_bytes(&mut frame);
            assert!(outcome.is_err());
            assert!(frame.iter().all(|b| *b == 0));
            assert_eq!(stream.state(), ClipboardStreamState::Rejected);
            assert!(stream.buffer.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn excessive_declared_length_fails_immediately_at_header() {
        let mut stream = SensitiveClipboardReadStream::default();
        let mut frame = make_frame();
        frame[8..12].copy_from_slice(
            &u32::try_from(CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES + 1)
                .expect("bounded test")
                .to_be_bytes(),
        );
        let mut header = frame[..IPC_HEADER_LEN].to_vec();
        assert_eq!(
            stream.push_bytes(&mut header).err(),
            Some(ClipboardStreamError::PayloadTooLarge)
        );
        assert!(header.iter().all(|b| *b == 0));
        assert_eq!(stream.state(), ClipboardStreamState::Rejected);
    }

    #[test]
    fn rejects_bounded_overflow_and_zeroizes_even_oversized_input() {
        let mut stream = SensitiveClipboardReadStream::default();
        let mut oversize = vec![42_u8; MAX_SENSITIVE_READ_FRAME + 1];
        assert_eq!(
            stream.push_bytes(&mut oversize).err(),
            Some(ClipboardStreamError::PayloadTooLarge),
        );
        assert!(oversize.iter().all(|b| *b == 0));
        assert_eq!(stream.state(), ClipboardStreamState::Rejected);
        assert!(stream.buffer.is_empty());
    }

    #[test]
    fn invalid_short_payload_length_rejects_at_header() {
        let mut stream = SensitiveClipboardReadStream::default();
        let mut header = make_frame()[..IPC_HEADER_LEN].to_vec();
        header[8..12].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            stream.push_bytes(&mut header).err(),
            Some(ClipboardStreamError::LengthMismatch),
        );
        assert!(header.iter().all(|b| *b == 0));
        assert_eq!(stream.state(), ClipboardStreamState::Rejected);
    }

    #[test]
    fn concatenated_frames_and_trailing_bytes_rejected_without_delivery() {
        let mut data = make_frame();
        data.push(1);
        let mut stream = SensitiveClipboardReadStream::default();
        assert_eq!(
            stream.push_bytes(&mut data).err(),
            Some(ClipboardStreamError::LengthMismatch)
        );
        assert!(data.iter().all(|b| *b == 0));
        assert_eq!(stream.state(), ClipboardStreamState::Rejected);
    }

    #[test]
    fn malformed_utf8_poison_decoder_and_reject_followup() {
        let mut frame = make_frame();
        frame[IPC_HEADER_LEN + CLIPBOARD_READ_SUCCESS_FIXED_LEN] = 0xFF;
        let mut stream = SensitiveClipboardReadStream::default();
        assert!(matches!(
            stream.push_bytes(&mut frame),
            Err(ClipboardStreamError::InvalidFrame(_))
        ));
        assert!(frame.iter().all(|b| *b == 0));
        assert!(stream.buffer.is_empty());
        let mut more = [8_u8, 9];
        assert_eq!(
            stream.push_bytes(&mut more).err(),
            Some(ClipboardStreamError::Finished)
        );
        assert_eq!(more, [0_u8; 2]);
    }
}
