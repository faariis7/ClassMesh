//! Portable injected clipboard boundary; this module has no Windows side effects.
//! Only opaque tokens issued by authenticated privileged dispatch reach execution.
//! The Service caller remains responsible for exact session, capability, sequence,
//! bounded IPC routing and response-envelope correlation.
use crate::dispatch::{AuthorizedClipboardRead, AuthorizedClipboardWrite};
use classmesh_protocol::clipboard::{validate_read_response, validate_text};
use classmesh_protocol::control_wire::ClipboardReadResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardBackendError {
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardExecutionError {
    Unavailable,
    Failed,
    InvalidBackendText,
}

impl ClipboardExecutionError {
    #[must_use]
    pub const fn diagnostic_code(&self) -> &str {
        match self {
            Self::Unavailable => "clipboard.backend_unavailable",
            Self::Failed => "clipboard.backend_failed",
            Self::InvalidBackendText => "clipboard.backend_text_invalid",
        }
    }
}

impl From<ClipboardBackendError> for ClipboardExecutionError {
    fn from(value: ClipboardBackendError) -> Self {
        match value {
            ClipboardBackendError::Unavailable => Self::Unavailable,
            ClipboardBackendError::Failed => Self::Failed,
        }
    }
}

/// Platform adapter accepts text only. Real implementations must bound allocation.
pub trait ClipboardBackend {
    /// Some(empty) means available empty text; None means not available.
    fn read_text(&mut self) -> Result<Option<String>, ClipboardBackendError>;
    fn write_text(&mut self, text: &str) -> Result<(), ClipboardBackendError>;
}

/// The caller must bind request_id into the authenticated response envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelatedClipboardRead {
    pub request_id: u64,
    pub response: Result<ClipboardReadResponse, ClipboardExecutionError>,
}

#[must_use]
pub fn execute_clipboard_read<B: ClipboardBackend + ?Sized>(
    backend: &mut B,
    request: AuthorizedClipboardRead,
) -> CorrelatedClipboardRead {
    let response = backend
        .read_text()
        .map_err(ClipboardExecutionError::from)
        .and_then(|text| {
            let available = text.is_some();
            let reply = ClipboardReadResponse {
                available,
                text_utf8: text.unwrap_or_default(),
            };
            validate_read_response(&reply)
                .map_err(|_| ClipboardExecutionError::InvalidBackendText)?;
            Ok(reply)
        });
    CorrelatedClipboardRead {
        request_id: request.request_id(),
        response,
    }
}

pub fn execute_clipboard_write<B: ClipboardBackend + ?Sized>(
    backend: &mut B,
    command: AuthorizedClipboardWrite,
) -> Result<(), ClipboardExecutionError> {
    // Enforce the text-only wire policy again at execution.
    validate_text(command.text()).map_err(|_| ClipboardExecutionError::InvalidBackendText)?;
    backend
        .write_text(command.text())
        .map_err(ClipboardExecutionError::from)
}
