mod clipboard_read_success;
mod contract;
mod decoder;

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
