use std::fmt::{Display, Formatter};

pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardTextError {
    TooLarge { bytes: usize, maximum: usize },
}

impl Display for ClipboardTextError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
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

#[cfg(test)]
mod tests {
    use super::*;

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
