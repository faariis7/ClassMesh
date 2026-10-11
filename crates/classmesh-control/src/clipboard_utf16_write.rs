//! Strict portable CF_UNICODETEXT encoding for a future Windows Worker write.
//! No clipboard OS access is provided in this module.
use std::fmt;

use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardUtf16WriteError {
    TooLarge,
    InteriorNul,
}

/// Owned, single-terminator UTF-16 text; its allocated units are erased on drop.
pub struct ClipboardUtf16WriteBuffer {
    units: Zeroizing<Vec<u16>>,
}

impl fmt::Debug for ClipboardUtf16WriteBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardUtf16WriteBuffer")
            .field("units_len", &self.units.len())
            .finish_non_exhaustive()
    }
}

impl ClipboardUtf16WriteBuffer {
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units
    }
}

/// Encode only bounded, NUL-free UTF-8 previously authorized for clipboard
/// writes. Prevent embedded NUL truncation in CF_UNICODETEXT consumers.
pub fn encode_clipboard_write(
    text: &str,
) -> Result<ClipboardUtf16WriteBuffer, ClipboardUtf16WriteError> {
    if text.len() > MAX_CLIPBOARD_TEXT_BYTES {
        return Err(ClipboardUtf16WriteError::TooLarge);
    }
    if text.contains('\0') {
        return Err(ClipboardUtf16WriteError::InteriorNul);
    }
    // UTF-16 units never exceed the validated UTF-8 byte count.
    let mut units = Zeroizing::new(Vec::with_capacity(text.len() + 1));
    units.extend(text.encode_utf16());
    units.push(0);
    Ok(ClipboardUtf16WriteBuffer { units })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_write_has_one_terminator() {
        let encoded = encode_clipboard_write("").expect("valid clear");
        assert_eq!(encoded.as_units(), &[0]);
    }

    #[test]
    fn unicode_write_encodes_surrogates_and_redacts_debug() {
        let encoded = encode_clipboard_write("Aé😀").expect("Unicode");
        assert_eq!(encoded.as_units(), &[0x0041, 0x00E9, 0xD83D, 0xDE00, 0]);
        let debug = format!("{encoded:?}");
        assert!(debug.contains("ClipboardUtf16WriteBuffer"));
        assert!(!debug.contains("Aé"));
        assert!(!debug.contains("😀"));
    }

    #[test]
    fn exact_utf8_limit_accepted_and_over_limit_rejected() {
        let text = "a".repeat(MAX_CLIPBOARD_TEXT_BYTES);
        let encoded = encode_clipboard_write(&text).expect("exact bound");
        assert_eq!(encoded.as_units().len(), MAX_CLIPBOARD_TEXT_BYTES + 1);
        assert_eq!(encoded.as_units().last(), Some(&0));
        assert_eq!(
            encode_clipboard_write(&format!("{text}a")).err(),
            Some(ClipboardUtf16WriteError::TooLarge),
        );
    }

    #[test]
    fn rejects_embedded_nul_that_would_truncate_windows_clipboard() {
        assert_eq!(
            encode_clipboard_write("before\0after").err(),
            Some(ClipboardUtf16WriteError::InteriorNul),
        );
    }

    #[test]
    fn multi_byte_utf8_policy_is_byte_bound_not_utf16_unit_bound() {
        assert!(encode_clipboard_write(&"é".repeat(MAX_CLIPBOARD_TEXT_BYTES / 2)).is_ok());
        assert_eq!(
            encode_clipboard_write(&"é".repeat(MAX_CLIPBOARD_TEXT_BYTES / 2 + 1)).err(),
            Some(ClipboardUtf16WriteError::TooLarge),
        );
    }
}
