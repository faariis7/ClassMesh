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
    text: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SensitiveClipboardReadSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveClipboardReadSuccess")
            .field("binding", &self.binding)
            .field("text_bytes", &self.text.len())
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
        if text.len() > MAX_CLIPBOARD_TEXT_BYTES {
            return Err(ClipboardReadSuccessError::TooLarge);
        }
        if text.contains(&0) {
            return Err(ClipboardReadSuccessError::InteriorNul);
        }
        std::str::from_utf8(&text).map_err(|_| ClipboardReadSuccessError::InvalidUtf8)?;
        Ok(Self { binding, text })
    }

    #[must_use]
    pub const fn binding(&self) -> ClipboardReadSuccessBinding {
        self.binding
    }

    #[must_use]
    pub fn text(&self) -> &str {
        // This payload is validated exactly once at construction/decode.
        std::str::from_utf8(&self.text).expect("validated clipboard UTF-8")
    }

    /// Only the future sensitive IPC encoder may call this. The active generic
    /// IpcFrame decoder MUST NOT handle this text-bearing payload.
    #[must_use]
    pub fn encode_payload(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            CLIPBOARD_READ_SUCCESS_FIXED_LEN + self.text.len(),
        ));
        out.extend_from_slice(&self.binding.worker_process_id.to_be_bytes());
        out.extend_from_slice(&self.binding.worker_session_id.to_be_bytes());
        out.extend_from_slice(&self.binding.control_session_id.to_be_bytes());
        out.extend_from_slice(&self.binding.control_sequence.to_be_bytes());
        out.extend_from_slice(&self.binding.request_id.to_be_bytes());
        out.extend_from_slice(&self.binding.worker_generation.to_be_bytes());
        let length = u32::try_from(self.text.len()).expect("<=64KiB text");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&[0_u8; 4]); // Reserved: must remain zero.
        out.extend_from_slice(&self.text);
        debug_assert_eq!(
            out.len(),
            CLIPBOARD_READ_SUCCESS_FIXED_LEN + self.text.len()
        );
        out
    }

    pub fn decode_payload(payload: Zeroizing<Vec<u8>>) -> Result<Self, ClipboardReadSuccessError> {
        if payload.len() < CLIPBOARD_READ_SUCCESS_FIXED_LEN {
            return Err(ClipboardReadSuccessError::InvalidPayload);
        }
        if payload.len() > CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES {
            return Err(ClipboardReadSuccessError::TooLarge);
        }
        let binding = ClipboardReadSuccessBinding {
            worker_process_id: u32::from_be_bytes(payload[0..4].try_into().expect("fixed size")),
            worker_session_id: u32::from_be_bytes(payload[4..8].try_into().expect("fixed size")),
            control_session_id: u64::from_be_bytes(payload[8..16].try_into().expect("fixed size")),
            control_sequence: u64::from_be_bytes(payload[16..24].try_into().expect("fixed size")),
            request_id: u64::from_be_bytes(payload[24..32].try_into().expect("fixed size")),
            worker_generation: u64::from_be_bytes(payload[32..40].try_into().expect("fixed size")),
        };
        let text_len = u32::from_be_bytes(payload[40..44].try_into().expect("fixed size")) as usize;
        if payload[44..48] != [0; 4] || payload.len() != CLIPBOARD_READ_SUCCESS_FIXED_LEN + text_len
        {
            return Err(ClipboardReadSuccessError::InvalidPayload);
        }
        Self::new(
            binding,
            Zeroizing::new(payload[CLIPBOARD_READ_SUCCESS_FIXED_LEN..].to_vec()),
        )
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
