mod contract;
mod decoder;

pub use contract::{
    PRESENTATION_KEY_INSTALL_PAYLOAD_LEN, PresentationKeyInstallBinding,
    SensitivePresentationKeyInstall,
};
pub use decoder::{DecodedIpcFrame, SensitiveIpcFrameDecoder};

#[cfg(test)]
mod tests;
