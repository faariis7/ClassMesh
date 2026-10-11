//! Isolated interactive Worker conversion boundary for clipboard text.
//! Native Windows reading is not wired to IPC request handling or Teacher UI.
//!
//! The caller must first have an authenticated, authorized ReadClipboard
//! request; this module does not grant authority or transmit clipboard text.
use classmesh_control::clipboard_utf16::{
    ClipboardUtf8Text, ClipboardUtf16Error, decode_clipboard_utf16_zeroizing,
};

/// Accept only a previously size-checked local UTF-16 source buffer. The
/// portable decoder wipes every source unit even when UTF-8 conversion fails.
pub fn decode_clipboard_units(units: &mut [u16]) -> Result<ClipboardUtf8Text, ClipboardUtf16Error> {
    decode_clipboard_utf16_zeroizing(units)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerClipboardReadError {
    NativeUnavailable,
    InvalidText,
}

/// Future authorized Worker read: no call site is enabled until its matching
/// zeroizing, version-gated v12 sensitive Service IPC response is integrated.
#[cfg(windows)]
pub fn read_windows_clipboard_text() -> Result<Option<ClipboardUtf8Text>, WorkerClipboardReadError>
{
    let Some(mut units) = classmesh_win32::read_clipboard_unicode()
        .map_err(|_| WorkerClipboardReadError::NativeUnavailable)?
    else {
        return Ok(None);
    };
    decode_clipboard_units(units.as_mut_units())
        .map(Some)
        .map_err(|_| WorkerClipboardReadError::InvalidText)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arabic_unicode_and_surrogate_pair_are_decoded_and_source_cleared() {
        let secret = "مرحبا 🌙 é";
        let mut units = secret.encode_utf16().chain([0]).collect::<Vec<_>>();
        let text = decode_clipboard_units(&mut units).expect("valid UTF-16");
        assert_eq!(text.as_str(), secret);
        assert!(units.iter().all(|unit| *unit == 0));
        let debug = format!("{text:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains("مرحبا"));
    }

    #[test]
    fn empty_clipboard_is_valid_without_claiming_unavailable() {
        let mut units = [0_u16];
        assert_eq!(
            decode_clipboard_units(&mut units).expect("clear").as_str(),
            ""
        );
        assert_eq!(units, [0]);
    }

    #[test]
    fn invalid_surrogate_and_missing_terminator_reject_and_zeroize() {
        let mut invalid = [0xD800_u16, 0];
        assert_eq!(
            decode_clipboard_units(&mut invalid).err(),
            Some(ClipboardUtf16Error::InvalidSurrogate)
        );
        assert_eq!(invalid, [0, 0]);
        let mut missing = [65_u16, 66_u16];
        assert_eq!(
            decode_clipboard_units(&mut missing).err(),
            Some(ClipboardUtf16Error::MissingTerminator)
        );
        assert_eq!(missing, [0, 0]);
    }

    #[test]
    fn oversized_clipboard_rejects_and_zeroizes_without_text() {
        use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
        let mut units = vec![b'a' as u16; MAX_CLIPBOARD_TEXT_BYTES + 1];
        units.push(0);
        assert_eq!(
            decode_clipboard_units(&mut units).err(),
            Some(ClipboardUtf16Error::TooLarge)
        );
        assert!(units.iter().all(|unit| *unit == 0));
    }
}
