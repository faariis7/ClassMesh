use std::fmt::{Display, Formatter};

use crate::control_wire::{ClipboardReadResponse, ClipboardWrite};

pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardTextError {
    TooLarge { bytes: usize, maximum: usize },
    UnavailableContainsText,
}

impl Display for ClipboardTextError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnavailableContainsText => write!(
                formatter,
                "unavailable clipboard response must not contain text"
            ),
            Self::TooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "clipboard UTF-8 text is {bytes} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for ClipboardTextError {}

pub fn validate_text(text: &str) -> Result<(), ClipboardTextError> {
    let bytes = text.len();
    if bytes > MAX_CLIPBOARD_TEXT_BYTES {
        return Err(ClipboardTextError::TooLarge {
            bytes,
            maximum: MAX_CLIPBOARD_TEXT_BYTES,
        });
    }
    Ok(())
}

/// Reuse the text-only 64 KiB policy on the existing control-wire write.
pub fn validate_write(write: &ClipboardWrite) -> Result<(), ClipboardTextError> {
    validate_text(&write.text_utf8)
}

/// Fail closed when an unavailable read response also carries hidden text.
/// Request/session correlation remains the authenticated control layer's job.
pub fn validate_read_response(response: &ClipboardReadResponse) -> Result<(), ClipboardTextError> {
    if !response.available && !response.text_utf8.is_empty() {
        return Err(ClipboardTextError::UnavailableContainsText);
    }
    validate_text(&response.text_utf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_clipboard_wire_types_remain_text_only_and_bounded() {
        assert!(
            validate_write(&ClipboardWrite {
                text_utf8: String::new(),
            })
            .is_ok()
        );
        assert!(
            validate_write(&ClipboardWrite {
                text_utf8: "a".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1),
            })
            .is_err()
        );
        assert!(
            validate_read_response(&ClipboardReadResponse {
                available: false,
                text_utf8: String::new(),
            })
            .is_ok()
        );
        assert_eq!(
            validate_read_response(&ClipboardReadResponse {
                available: false,
                text_utf8: "hidden".to_owned(),
            }),
            Err(ClipboardTextError::UnavailableContainsText)
        );
        assert!(
            validate_read_response(&ClipboardReadResponse {
                available: true,
                text_utf8: "é".repeat(MAX_CLIPBOARD_TEXT_BYTES / 2),
            })
            .is_ok()
        );
        assert!(
            validate_read_response(&ClipboardReadResponse {
                available: true,
                text_utf8: "é".repeat(MAX_CLIPBOARD_TEXT_BYTES / 2 + 1),
            })
            .is_err()
        );
    }

    #[test]
    fn clipboard_text_limit_is_measured_in_utf8_bytes() {
        assert!(validate_text(&"a".repeat(MAX_CLIPBOARD_TEXT_BYTES)).is_ok());
        assert!(matches!(
            validate_text(&"a".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1)),
            Err(ClipboardTextError::TooLarge { .. })
        ));

        let two_byte = "é".repeat(MAX_CLIPBOARD_TEXT_BYTES / 2);
        assert_eq!(two_byte.len(), MAX_CLIPBOARD_TEXT_BYTES);
        assert!(validate_text(&two_byte).is_ok());

        let oversized = format!("{two_byte}é");
        assert!(matches!(
            validate_text(&oversized),
            Err(ClipboardTextError::TooLarge { .. })
        ));
    }

    #[test]
    fn empty_text_is_valid_for_explicit_clipboard_clear() {
        assert!(validate_text("").is_ok());
    }
}
