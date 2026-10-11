mod clipboard_read_frame;
mod clipboard_read_gate;
mod clipboard_read_stream;
mod clipboard_read_success;
mod contract;
mod decoder;

pub use clipboard_read_frame::{
    CLIPBOARD_READ_SUCCESS_FUTURE_MINOR, CLIPBOARD_READ_SUCCESS_RESERVED_TYPE,
    ClipboardReadFrameError, decode_sensitive_clipboard_read_frame,
    encode_sensitive_clipboard_read_frame,
};
pub use clipboard_read_gate::{
    SENSITIVE_CLIPBOARD_READ_DEADLINE_MS, SensitiveClipboardReadAcceptanceGate,
    SensitiveReadAcceptError,
};
pub use clipboard_read_stream::{
    ClipboardStreamError, ClipboardStreamState, SensitiveClipboardReadStream,
};
pub use clipboard_read_success::{
    CLIPBOARD_READ_SUCCESS_FIXED_LEN, ClipboardReadSuccessBinding, ClipboardReadSuccessError,
    SensitiveClipboardReadSuccess,
};
pub use contract::{
    PRESENTATION_KEY_INSTALL_PAYLOAD_LEN, PresentationKeyInstallBinding,
    SensitivePresentationKeyInstall,
};
pub use decoder::{DecodedIpcFrame, SensitiveIpcFrameDecoder};

#[cfg(test)]
mod tests;
