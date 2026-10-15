mod clipboard_read_frame;
mod clipboard_read_gate;
mod clipboard_read_inbound;
mod clipboard_read_stream;
mod clipboard_read_success;
mod clipboard_read_teacher;
mod clipboard_read_transport_gate;
mod contract;
mod decoder;
mod v12_challenge;

pub use clipboard_read_frame::{
    CLIPBOARD_READ_SUCCESS_FUTURE_MINOR, CLIPBOARD_READ_SUCCESS_RESERVED_TYPE,
    ClipboardReadFrameError, decode_sensitive_clipboard_read_frame,
    encode_sensitive_clipboard_read_frame,
};
pub use clipboard_read_gate::{
    SENSITIVE_CLIPBOARD_READ_DEADLINE_MS, SensitiveClipboardReadAcceptanceGate,
    SensitiveReadAcceptError,
};
pub use clipboard_read_inbound::{SensitiveClipboardReadInbox, SensitiveInboxError};
pub use clipboard_read_stream::{
    ClipboardStreamError, ClipboardStreamState, SensitiveClipboardReadStream,
};
pub use clipboard_read_success::{
    CLIPBOARD_READ_SUCCESS_FIXED_LEN, ClipboardReadSuccessBinding, ClipboardReadSuccessError,
    SensitiveClipboardReadSuccess,
};
pub use clipboard_read_teacher::{
    SensitiveTeacherClipboardError, SensitiveTeacherClipboardWire, TeacherClipboardReadContext,
    encode_sensitive_teacher_read_response,
};
pub use clipboard_read_transport_gate::{
    SensitiveClipboardTransportGate, SensitiveReadGrants, SensitiveTransportError,
};
pub use contract::{
    PRESENTATION_KEY_INSTALL_PAYLOAD_LEN, PresentationKeyInstallBinding,
    SensitivePresentationKeyInstall,
};
pub use decoder::{DecodedIpcFrame, SensitiveIpcFrameDecoder};
pub use v12_challenge::{
    SensitiveV12Challenge, SensitiveV12ChallengeError, V12LiveAuthority, compute_v12_challenge_mac,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod v12_challenge_tests;

#[cfg(test)]
mod service_owned_control_gate_tests;
