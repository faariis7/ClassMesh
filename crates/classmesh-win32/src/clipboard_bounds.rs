//! Portable bounded copying boundary for Windows CF_UNICODETEXT clipboard
//! memory. Native Win32 calls are isolated in clipboard.rs and disabled until
//! a separately authorized Worker dispatch path is wired.
use std::fmt;

use zeroize::Zeroizing;

/// 64 KiB UTF-8 policy permits at most 64Ki UTF-16 code units plus NUL.
/// This is a conservative bound for the OS-owned allocation we will inspect.
pub const MAX_CLIPBOARD_UTF16_UNITS: usize = 64 * 1024 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardUnicodeReadError {
    Busy,
    Unavailable,
    MemoryUnavailable,
    InvalidLayout,
    TooLarge,
    MissingTerminator,
}

/// A redacted owner of the bounded local copy. Contents are erased at drop;
/// the OS-owned clipboard allocation is never modified or released by us.
pub struct ClipboardUnicodeUnits {
    units: Zeroizing<Vec<u16>>,
}

impl fmt::Debug for ClipboardUnicodeUnits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardUnicodeUnits")
            .field("units_len", &self.units.len())
            .finish_non_exhaustive()
    }
}

impl ClipboardUnicodeUnits {
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units
    }

    /// Allows a downstream validated UTF-16 decoder to zeroize the source
    /// in-place as soon as conversion completes.
    pub fn as_mut_units(&mut self) -> &mut [u16] {
        self.units.as_mut_slice()
    }

    #[cfg(test)]
    fn inner_for_test(&self) -> &Zeroizing<Vec<u16>> {
        &self.units
    }
}

/// Fail closed on OS memory larger than our policy, no terminator or zero
/// length; copy only until the first Unicode NUL, never trailing allocations.
pub fn copy_bounded_clipboard_unicode(
    input: &[u16],
) -> Result<ClipboardUnicodeUnits, ClipboardUnicodeReadError> {
    if input.len() > MAX_CLIPBOARD_UTF16_UNITS {
        return Err(ClipboardUnicodeReadError::TooLarge);
    }
    let end = input
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(ClipboardUnicodeReadError::MissingTerminator)?;
    let mut units = Zeroizing::new(Vec::with_capacity(end + 1));
    units.extend_from_slice(&input[..=end]);
    Ok(ClipboardUnicodeUnits { units })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_clipboard_and_single_terminator_are_valid() {
        let mut value = copy_bounded_clipboard_unicode(&[0]).expect("empty text");
        assert_eq!(value.as_units(), &[0]);
        assert!(value.as_mut_units().iter().all(|unit| *unit == 0));
    }

    #[test]
    fn preserves_unicode_and_stops_at_first_terminator_without_logging_text() {
        let input = [0x0645, 0x0631, 0x062D, 0x0628, 0xD83D, 0xDE00, 0, 0, 0];
        let value = copy_bounded_clipboard_unicode(&input).expect("Unicode");
        assert_eq!(value.as_units(), &input[..7]);
        assert_eq!(value.as_units().len(), 7);
        let debug = format!("{value:?}");
        assert!(debug.contains("ClipboardUnicodeUnits"));
        assert!(!debug.contains("1605"));
        assert!(!debug.contains("DE00"));
    }

    #[test]
    fn enforces_exact_unicode_unit_bound_including_terminator() {
        let mut largest = vec![b'a' as u16; MAX_CLIPBOARD_UTF16_UNITS - 1];
        largest.push(0);
        let copy = copy_bounded_clipboard_unicode(&largest).expect("at bound");
        assert_eq!(copy.as_units().len(), MAX_CLIPBOARD_UTF16_UNITS);
        largest.push(0);
        assert_eq!(
            copy_bounded_clipboard_unicode(&largest).err(),
            Some(ClipboardUnicodeReadError::TooLarge),
        );
    }

    #[test]
    fn rejects_missing_terminator_and_empty_unreadable_buffers() {
        assert_eq!(
            copy_bounded_clipboard_unicode(&[]).err(),
            Some(ClipboardUnicodeReadError::MissingTerminator),
        );
        assert_eq!(
            copy_bounded_clipboard_unicode(&[65, 66]).err(),
            Some(ClipboardUnicodeReadError::MissingTerminator),
        );
        assert_eq!(
            copy_bounded_clipboard_unicode(&vec![65; MAX_CLIPBOARD_UTF16_UNITS]).err(),
            Some(ClipboardUnicodeReadError::MissingTerminator),
        );
    }

    #[test]
    fn copy_owned_units_are_zeroized_on_drop() {
        let value = copy_bounded_clipboard_unicode(&[65, 66, 0]).expect("valid");
        fn takes_zeroizing_units(_: &zeroize::Zeroizing<Vec<u16>>) {}
        takes_zeroizing_units(value.inner_for_test());
        assert_eq!(value.as_units(), &[65, 66, 0]);
    }
}
