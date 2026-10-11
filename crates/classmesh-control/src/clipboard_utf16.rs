//! Strict, portable CF_UNICODETEXT decoding boundary for a future interactive
//! Windows clipboard adapter. Does not access Windows/OS clipboard APIs.
//! Every caller-owned UTF-16 code unit is zeroized on success *and* failure.

use std::fmt;

use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardUtf16Error {
    MissingTerminator,
    InvalidSurrogate,
    TooLarge,
}

/// Short-lived clipboard text, zeroized on drop and redacted in diagnostics.
pub struct ClipboardUtf8Text {
    text: Zeroizing<String>,
}

impl fmt::Debug for ClipboardUtf8Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardUtf8Text")
            .field("byte_len", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl ClipboardUtf8Text {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}

/// Caller must first bound its operating-system clipboard buffer allocation.
/// Fail closed on unterminated, malformed or oversized Unicode text. No secret
/// text or source units are exposed in the error/Debug representation.
pub fn decode_clipboard_utf16_zeroizing(
    input: &mut [u16],
) -> Result<ClipboardUtf8Text, ClipboardUtf16Error> {
    let result = decode_utf16_bounded(input);
    input.zeroize();
    result
}

fn decode_utf16_bounded(input: &[u16]) -> Result<ClipboardUtf8Text, ClipboardUtf16Error> {
    // Any valid text of <=64KiB UTF-8 needs no more than 64Ki UTF-16
    // code units; reject before scanning/allocating beyond that bound.
    let Some(end) = input
        .iter()
        .take(MAX_CLIPBOARD_TEXT_BYTES + 1)
        .position(|unit| *unit == 0)
    else {
        return Err(if input.len() > MAX_CLIPBOARD_TEXT_BYTES {
            ClipboardUtf16Error::TooLarge
        } else {
            ClipboardUtf16Error::MissingTerminator
        });
    };

    let mut text = Zeroizing::new(String::new());
    for decoded in std::char::decode_utf16(input[..end].iter().copied()) {
        let value = decoded.map_err(|_| ClipboardUtf16Error::InvalidSurrogate)?;
        let length = text
            .len()
            .checked_add(value.len_utf8())
            .ok_or(ClipboardUtf16Error::TooLarge)?;
        if length > MAX_CLIPBOARD_TEXT_BYTES {
            return Err(ClipboardUtf16Error::TooLarge);
        }
        text.push(value);
    }

    Ok(ClipboardUtf8Text { text })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_clipboard_text_is_valid_and_source_zeroized() {
        let mut units = [0_u16];
        let text = decode_clipboard_utf16_zeroizing(&mut units).expect("empty string");
        assert_eq!(text.as_str(), "");
        assert!(units.iter().all(|u| *u == 0));
    }

    #[test]
    fn text_with_multibyte_and_surrogate_pair_decodes_and_redacts_debug() {
        let mut units = [0x0041, 0x00E9, 0xD83D, 0xDE00, 0];
        let text = decode_clipboard_utf16_zeroizing(&mut units).expect("unicode");
        assert_eq!(text.as_str(), "Aé😀");
        assert!(units.iter().all(|u| *u == 0));
        let log = format!("{text:?}");
        assert!(log.contains("ClipboardUtf8Text"));
        assert!(!log.contains("Aé"));
        assert!(!log.contains("😀"));
    }

    #[test]
    fn invalid_surrogate_and_missing_terminator_reject_and_zeroize() {
        let mut broken = [0xD800, 0];
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut broken).err(),
            Some(ClipboardUtf16Error::InvalidSurrogate)
        );
        assert!(broken.iter().all(|u| *u == 0));
        let mut truncated = [65_u16, 66];
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut truncated).err(),
            Some(ClipboardUtf16Error::MissingTerminator)
        );
        assert!(truncated.iter().all(|u| *u == 0));
    }

    #[test]
    fn exact_ascii_utf8_byte_limit_accepted_and_oversize_denied() {
        let mut max = vec![b'a' as u16; MAX_CLIPBOARD_TEXT_BYTES];
        max.push(0);
        let decoded = decode_clipboard_utf16_zeroizing(&mut max).expect("64KiB exact");
        assert_eq!(decoded.as_str().len(), MAX_CLIPBOARD_TEXT_BYTES);
        assert!(max.iter().all(|u| *u == 0));

        let mut over = vec![b'a' as u16; MAX_CLIPBOARD_TEXT_BYTES + 1];
        over.push(0);
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut over).err(),
            Some(ClipboardUtf16Error::TooLarge)
        );
        assert!(over.iter().all(|u| *u == 0));
    }

    #[test]
    fn multibyte_utf8_length_is_counted_in_bytes() {
        let mut exact = vec![0x00E9_u16; MAX_CLIPBOARD_TEXT_BYTES / 2];
        exact.push(0);
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut exact)
                .expect("exact multi byte")
                .as_str()
                .len(),
            MAX_CLIPBOARD_TEXT_BYTES
        );
        let mut over = vec![0x00E9_u16; MAX_CLIPBOARD_TEXT_BYTES / 2 + 1];
        over.push(0);
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut over).err(),
            Some(ClipboardUtf16Error::TooLarge)
        );
        assert!(over.iter().all(|u| *u == 0));
    }

    #[test]
    fn missing_terminator_beyond_maximum_is_bounded_and_zeroized() {
        let mut over = vec![65_u16; MAX_CLIPBOARD_TEXT_BYTES + 10];
        assert_eq!(
            decode_clipboard_utf16_zeroizing(&mut over).err(),
            Some(ClipboardUtf16Error::TooLarge)
        );
        assert!(over.iter().all(|u| *u == 0));
    }
}
