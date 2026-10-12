//! Pure, text-sensitive payload contract for a *future* Worker→Service
//! clipboard read-success frame. This does not register an IPC message type,
//! change the active IPC version, or access the Windows clipboard.
//!
//! All text allocations are owned by Zeroizing containers; never log raw
//! payloads or route them through generic IpcFrame/Debug decoders.
use std::fmt;

use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
use zeroize::Zeroizing;

pub const CLIPBOARD_READ_SUCCESS_FIXED_LEN: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardReadSuccessBinding {
    pub worker_process_id: u32,
    pub worker_session_id: u32,
    pub worker_generation: u64,
    pub control_session_id: u64,
    pub control_sequence: u64,
    pub request_id: u64,
}

impl ClipboardReadSuccessBinding {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.worker_process_id != 0
            && self.worker_session_id != 0
            && self.worker_generation != 0
            && self.control_session_id != 0
            && self.control_sequence != 0
            && self.request_id != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardReadSuccessError {
    InvalidBinding,
    TooLarge,
    InvalidUtf8,
    InteriorNul,
    InvalidPayload,
}

/// A decoded or outbound clipboard string tied to a specific authenticated
/// Worker and control command, with a redacted Debug and zeroizing storage.
pub struct SensitiveClipboardReadSuccess {
    binding: ClipboardReadSuccessBinding,
    // Outbound values own only UTF-8 text (offset 0). Decoded values retain
    // their *original* Zeroizing payload, including the fixed metadata prefix,
    // so no second plaintext heap buffer is allocated during decoding.
    text: Zeroizing<Vec<u8>>,
    text_start: usize,
}

impl fmt::Debug for SensitiveClipboardReadSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveClipboardReadSuccess")
            .field("binding", &self.binding)
            .field("text_bytes", &(self.text.len() - self.text_start))
            .finish_non_exhaustive()
    }
}

impl SensitiveClipboardReadSuccess {
    pub fn new(
        binding: ClipboardReadSuccessBinding,
        text: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ClipboardReadSuccessError> {
        if !binding.is_valid() {
            return Err(ClipboardReadSuccessError::InvalidBinding);
        }
        Self::validate_text(&text)?;
        Ok(Self {
            binding,
            text,
            text_start: 0,
        })
    }

    fn validate_text(text: &[u8]) -> Result<(), ClipboardReadSuccessError> {
        if text.len() > MAX_CLIPBOARD_TEXT_BYTES {
            return Err(ClipboardReadSuccessError::TooLarge);
        }
        if text.contains(&0) {
            return Err(ClipboardReadSuccessError::InteriorNul);
        }
        std::str::from_utf8(text).map_err(|_| ClipboardReadSuccessError::InvalidUtf8)?;
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> ClipboardReadSuccessBinding {
        self.binding
    }

    #[must_use]
    pub fn text(&self) -> &str {
        // This payload is validated exactly once at construction/decode.
        std::str::from_utf8(&self.text[self.text_start..]).expect("validated clipboard UTF-8")
    }

    /// Only the future sensitive IPC encoder may call this. The active generic
    /// IpcFrame decoder MUST NOT handle this text-bearing payload.
    #[must_use]
    pub fn encode_payload(&self) -> Zeroizing<Vec<u8>> {
        let text = &self.text[self.text_start..];
        let mut out = Zeroizing::new(Vec::with_capacity(
            CLIPBOARD_READ_SUCCESS_FIXED_LEN + text.len(),
        ));
        out.extend_from_slice(&self.binding.worker_process_id.to_be_bytes());
        out.extend_from_slice(&self.binding.worker_session_id.to_be_bytes());
        out.extend_from_slice(&self.binding.control_session_id.to_be_bytes());
        out.extend_from_slice(&self.binding.control_sequence.to_be_bytes());
        out.extend_from_slice(&self.binding.request_id.to_be_bytes());
        out.extend_from_slice(&self.binding.worker_generation.to_be_bytes());
        let length = u32::try_from(text.len()).expect("<=64KiB text");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&[0_u8; 4]); // Reserved: must remain zero.
        out.extend_from_slice(text);
        debug_assert_eq!(out.len(), CLIPBOARD_READ_SUCCESS_FIXED_LEN + text.len());
        out
    }

    pub fn decode_payload(payload: Zeroizing<Vec<u8>>) -> Result<Self, ClipboardReadSuccessError> {
        Self::decode_payload_with_prefix(payload, 0)
    }

    /// The dedicated v12 frame decoder has already validated its 12-byte
    /// header. Retain that entire zeroizing allocation instead of copying
    /// the text-bearing payload into a second plaintext heap buffer.
    /// Not available to the active generic v11 IPC decoder.
    pub(super) fn decode_payload_with_prefix(
        payload: Zeroizing<Vec<u8>>,
        prefix_len: usize,
    ) -> Result<Self, ClipboardReadSuccessError> {
        let Some(text_start) = prefix_len.checked_add(CLIPBOARD_READ_SUCCESS_FIXED_LEN) else {
            return Err(ClipboardReadSuccessError::InvalidPayload);
        };
        if payload.len() < text_start {
            return Err(ClipboardReadSuccessError::InvalidPayload);
        }
        if payload.len() - prefix_len > CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES
        {
            return Err(ClipboardReadSuccessError::TooLarge);
        }
        let prefix = &payload[prefix_len..];
        let binding = ClipboardReadSuccessBinding {
            worker_process_id: u32::from_be_bytes(prefix[0..4].try_into().expect("fixed size")),
            worker_session_id: u32::from_be_bytes(prefix[4..8].try_into().expect("fixed size")),
            control_session_id: u64::from_be_bytes(prefix[8..16].try_into().expect("fixed size")),
            control_sequence: u64::from_be_bytes(prefix[16..24].try_into().expect("fixed size")),
            request_id: u64::from_be_bytes(prefix[24..32].try_into().expect("fixed size")),
            worker_generation: u64::from_be_bytes(prefix[32..40].try_into().expect("fixed size")),
        };
        let text_len = u32::from_be_bytes(prefix[40..44].try_into().expect("fixed size")) as usize;
        if prefix[44..48] != [0; 4]
            || payload.len() - prefix_len != CLIPBOARD_READ_SUCCESS_FIXED_LEN + text_len
        {
            return Err(ClipboardReadSuccessError::InvalidPayload);
        }
        if !binding.is_valid() {
            return Err(ClipboardReadSuccessError::InvalidBinding);
        }
        Self::validate_text(&payload[text_start..])?;
        // Transfer the *same* zeroizing allocation into the decoded value.
        // This keeps both metadata and clipboard bytes wiped on drop and
        // avoids a temporary plaintext copy during frame reception.
        Ok(Self {
            binding,
            text: payload,
            text_start,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ClipboardReadSuccessBinding {
        ClipboardReadSuccessBinding {
            worker_process_id: 42,
            worker_session_id: 7,
            worker_generation: 4,
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
        }
    }

    #[test]
    fn bounded_unicode_text_roundtrips_with_bound_identity_and_redacted_debug() {
        let secret = "كلمة سر مُفترضة é😀";
        let result = SensitiveClipboardReadSuccess::new(
            binding(),
            Zeroizing::new(secret.as_bytes().to_vec()),
        )
        .expect("valid");
        let debug = format!("{result:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains("مُفترضة"));
        assert_eq!(result.binding(), binding());
        let encoded = result.encode_payload();
        assert_eq!(
            encoded.len(),
            CLIPBOARD_READ_SUCCESS_FIXED_LEN + secret.len()
        );
        let decoded = SensitiveClipboardReadSuccess::decode_payload(encoded).expect("roundtrip");
        assert_eq!(decoded.binding(), binding());
        assert_eq!(decoded.text(), secret);
    }

    #[test]
    fn decoding_owns_original_zeroizing_payload_without_new_plaintext_copy() {
        let secret = "حافظة خاصة 🌙 é😀";
        let original = SensitiveClipboardReadSuccess::new(
            binding(),
            Zeroizing::new(secret.as_bytes().to_vec()),
        )
        .expect("valid secret");
        let incoming = original.encode_payload();
        let original_payload_base = incoming.as_ptr();
        let original_text_address = incoming[CLIPBOARD_READ_SUCCESS_FIXED_LEN..].as_ptr();
        let decoded = SensitiveClipboardReadSuccess::decode_payload(incoming)
            .expect("valid existing payload");
        assert_eq!(decoded.binding(), binding());
        assert_eq!(decoded.text(), secret);
        assert_eq!(
            decoded.text.as_ptr(),
            original_payload_base,
            "must own original zeroizing payload"
        );
        assert_eq!(
            decoded.text().as_ptr(),
            original_text_address,
            "must not copy secret text"
        );
        assert!(!format!("{decoded:?}").contains(secret));
        let encoded_again = decoded.encode_payload();
        assert_eq!(
            &encoded_again[CLIPBOARD_READ_SUCCESS_FIXED_LEN..],
            secret.as_bytes()
        );
    }

    #[test]
    fn sensitive_frame_decode_retains_original_zeroizing_frame_allocation() {
        use crate::ipc::IPC_HEADER_LEN;
        use crate::ipc_sensitive::{
            decode_sensitive_clipboard_read_frame, encode_sensitive_clipboard_read_frame,
        };
        let secret = "حافظة المحادثة 🌙 é😀";
        let original = SensitiveClipboardReadSuccess::new(
            binding(),
            Zeroizing::new(secret.as_bytes().to_vec()),
        )
        .expect("secret");
        let frame = encode_sensitive_clipboard_read_frame(&original);
        let expected_buffer_addr = frame.as_ptr();
        let expected_text_addr =
            frame[IPC_HEADER_LEN + CLIPBOARD_READ_SUCCESS_FIXED_LEN..].as_ptr();
        let decoded = decode_sensitive_clipboard_read_frame(frame).expect("valid frame");
        assert_eq!(decoded.binding(), binding());
        assert_eq!(decoded.text(), secret);
        assert_eq!(
            decoded.text.as_ptr(),
            expected_buffer_addr,
            "sensitive frame decoding must not allocate a second plaintext buffer"
        );
        assert_eq!(decoded.text().as_ptr(), expected_text_addr);
        assert!(!format!("{decoded:?}").contains(secret));
        let encoded_again = decoded.encode_payload();
        assert_eq!(
            &encoded_again[CLIPBOARD_READ_SUCCESS_FIXED_LEN..],
            secret.as_bytes()
        );
    }

    #[test]
    fn invalid_zero_worker_and_control_identifiers_rejected() {
        let base = binding();
        let bad = [
            ClipboardReadSuccessBinding {
                worker_process_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_session_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_generation: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_session_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_sequence: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                request_id: 0,
                ..base
            },
        ];
        for candidate in bad {
            assert_eq!(
                SensitiveClipboardReadSuccess::new(candidate, Zeroizing::new(b"text".to_vec()))
                    .err(),
                Some(ClipboardReadSuccessError::InvalidBinding),
            );
        }
    }

    #[test]
    fn reject_oversize_malformed_utf8_and_nul_without_emitting_payload() {
        for (bytes, expected) in [
            (
                vec![b'x'; MAX_CLIPBOARD_TEXT_BYTES + 1],
                ClipboardReadSuccessError::TooLarge,
            ),
            (vec![0xFF, 0xFE], ClipboardReadSuccessError::InvalidUtf8),
            (
                b"valid\0trailing".to_vec(),
                ClipboardReadSuccessError::InteriorNul,
            ),
        ] {
            assert_eq!(
                SensitiveClipboardReadSuccess::new(binding(), Zeroizing::new(bytes)).err(),
                Some(expected),
            );
        }
    }

    #[test]
    fn decode_rejects_inconsistent_length_nonzero_padding_and_trailing_bytes() {
        let valid = SensitiveClipboardReadSuccess::new(binding(), Zeroizing::new(b"text".to_vec()))
            .expect("valid")
            .encode_payload();
        let mut too_short = Zeroizing::new(valid.to_vec());
        too_short[40..44].copy_from_slice(&6_u32.to_be_bytes());
        assert_eq!(
            SensitiveClipboardReadSuccess::decode_payload(too_short).err(),
            Some(ClipboardReadSuccessError::InvalidPayload)
        );
        let mut bad_padding = Zeroizing::new(valid.to_vec());
        bad_padding[44] = 1;
        assert_eq!(
            SensitiveClipboardReadSuccess::decode_payload(bad_padding).err(),
            Some(ClipboardReadSuccessError::InvalidPayload)
        );
        let mut trailing = Zeroizing::new(valid.to_vec());
        trailing.push(42);
        assert_eq!(
            SensitiveClipboardReadSuccess::decode_payload(trailing).err(),
            Some(ClipboardReadSuccessError::InvalidPayload)
        );
        assert_eq!(
            SensitiveClipboardReadSuccess::decode_payload(Zeroizing::new(vec![0; 47])).err(),
            Some(ClipboardReadSuccessError::InvalidPayload)
        );
    }

    #[test]
    fn exact_utf8_policy_boundary_and_empty_clipboard_text_are_supported() {
        let exact = SensitiveClipboardReadSuccess::new(
            binding(),
            Zeroizing::new(vec![b'a'; MAX_CLIPBOARD_TEXT_BYTES]),
        )
        .expect("exact");
        let encoded = exact.encode_payload();
        assert_eq!(
            encoded.len(),
            CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES
        );
        let decoded = SensitiveClipboardReadSuccess::decode_payload(encoded).expect("decoded");
        assert_eq!(decoded.text().len(), MAX_CLIPBOARD_TEXT_BYTES);
        let empty = SensitiveClipboardReadSuccess::new(binding(), Zeroizing::new(Vec::new()))
            .expect("empty but available text");
        assert_eq!(empty.text(), "");
    }
}
