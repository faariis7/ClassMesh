//! Isolated *future* v12 Worker->Service clipboard success frame codec.
//! This does not modify the active IPC minor (v11) or register message 33.
//! Callers MUST use a dedicated zeroizing streaming decoder before activation.
use zeroize::Zeroizing;

use super::clipboard_read_success::{
    CLIPBOARD_READ_SUCCESS_FIXED_LEN, ClipboardReadSuccessError, SensitiveClipboardReadSuccess,
};
use crate::ipc::{
    IPC_HEADER_LEN, IPC_VERSION_MAJOR, IPC_VERSION_MINOR, IpcHeader, MAX_IPC_MESSAGE,
};
use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;

/// Reserved for a future version-gated, sensitive Worker->Service decoder.
pub const CLIPBOARD_READ_SUCCESS_FUTURE_MINOR: u8 = 12;
pub const CLIPBOARD_READ_SUCCESS_RESERVED_TYPE: u16 = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardReadFrameError {
    MalformedHeader,
    WrongVersion,
    WrongMessage,
    LengthMismatch,
    InvalidPayload(ClipboardReadSuccessError),
}

/// Produces a zeroizing frame buffer. Never route this into the generic IPC
/// decoder or log it; it contains clipboard text.
#[must_use]
pub fn encode_sensitive_clipboard_read_frame(
    message: &SensitiveClipboardReadSuccess,
) -> Zeroizing<Vec<u8>> {
    let payload = message.encode_payload();
    let length = u32::try_from(payload.len()).expect("bounded 64KiB text + fixed metadata");
    let header = IpcHeader {
        version_major: IPC_VERSION_MAJOR,
        version_minor: CLIPBOARD_READ_SUCCESS_FUTURE_MINOR,
        message_type: CLIPBOARD_READ_SUCCESS_RESERVED_TYPE,
        payload_len: length,
    }
    .encode()
    .expect("bounded v12 sensitive frame");
    let mut frame = Zeroizing::new(Vec::with_capacity(IPC_HEADER_LEN + payload.len()));
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    frame
}

/// Consumes an owned, zeroizing full frame and validates exact header,
/// negotiated future protocol version and sensitive payload. No partial
/// streaming behavior is provided by this helper.
pub fn decode_sensitive_clipboard_read_frame(
    frame: Zeroizing<Vec<u8>>,
) -> Result<SensitiveClipboardReadSuccess, ClipboardReadFrameError> {
    if frame.len() > IPC_HEADER_LEN + CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES {
        return Err(ClipboardReadFrameError::MalformedHeader);
    }
    let header = IpcHeader::decode(&frame).map_err(|_| ClipboardReadFrameError::MalformedHeader)?;
    if header.version_major != IPC_VERSION_MAJOR
        || header.version_minor != CLIPBOARD_READ_SUCCESS_FUTURE_MINOR
        || IPC_VERSION_MINOR >= CLIPBOARD_READ_SUCCESS_FUTURE_MINOR
    {
        return Err(ClipboardReadFrameError::WrongVersion);
    }
    if header.message_type != CLIPBOARD_READ_SUCCESS_RESERVED_TYPE {
        return Err(ClipboardReadFrameError::WrongMessage);
    }
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| ClipboardReadFrameError::LengthMismatch)?;
    if !(CLIPBOARD_READ_SUCCESS_FIXED_LEN
        ..=CLIPBOARD_READ_SUCCESS_FIXED_LEN + MAX_CLIPBOARD_TEXT_BYTES)
        .contains(&payload_len)
        || payload_len > MAX_IPC_MESSAGE
        || IPC_HEADER_LEN.checked_add(payload_len) != Some(frame.len())
    {
        return Err(ClipboardReadFrameError::LengthMismatch);
    }
    SensitiveClipboardReadSuccess::decode_payload_with_prefix(frame, IPC_HEADER_LEN)
        .map_err(ClipboardReadFrameError::InvalidPayload)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_sensitive::clipboard_read_success::ClipboardReadSuccessBinding;

    fn sample() -> SensitiveClipboardReadSuccess {
        SensitiveClipboardReadSuccess::new(
            ClipboardReadSuccessBinding {
                worker_process_id: 42,
                worker_session_id: 7,
                worker_generation: 4,
                control_session_id: 77,
                control_sequence: 101,
                request_id: 19,
            },
            Zeroizing::new("مثال UTF-8 é😀".as_bytes().to_vec()),
        )
        .expect("valid sensitive text")
    }

    #[test]
    fn clipboard_success_future_minor_roundtrips_bound_text() {
        let msg = sample();
        let frame = encode_sensitive_clipboard_read_frame(&msg);
        assert_eq!(frame[4], IPC_VERSION_MAJOR);
        assert_eq!(frame[5], CLIPBOARD_READ_SUCCESS_FUTURE_MINOR);
        assert_eq!(
            u16::from_be_bytes([frame[6], frame[7]]),
            CLIPBOARD_READ_SUCCESS_RESERVED_TYPE
        );
        let decoded = decode_sensitive_clipboard_read_frame(frame).expect("roundtrip");
        assert_eq!(decoded.binding(), msg.binding());
        assert_eq!(decoded.text(), msg.text());
    }

    #[test]
    fn old_and_future_ipc_minors_fail_closed() {
        for minor in [IPC_VERSION_MINOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR + 1] {
            let mut bytes = encode_sensitive_clipboard_read_frame(&sample());
            bytes[5] = minor;
            assert!(matches!(
                decode_sensitive_clipboard_read_frame(bytes),
                Err(ClipboardReadFrameError::WrongVersion),
            ));
        }
    }

    #[test]
    fn wrong_message_major_or_magic_is_rejected() {
        let mut wrong_type = encode_sensitive_clipboard_read_frame(&sample());
        wrong_type[6..8].copy_from_slice(&32_u16.to_be_bytes());
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(wrong_type),
            Err(ClipboardReadFrameError::WrongMessage),
        ));

        let mut wrong_major = encode_sensitive_clipboard_read_frame(&sample());
        wrong_major[4] = 1;
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(wrong_major),
            Err(ClipboardReadFrameError::WrongVersion),
        ));

        let mut wrong_magic = encode_sensitive_clipboard_read_frame(&sample());
        wrong_magic[0] = 0;
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(wrong_magic),
            Err(ClipboardReadFrameError::MalformedHeader),
        ));
    }

    #[test]
    fn exact_length_mismatch_or_truncated_header_reject() {
        let mut truncated = encode_sensitive_clipboard_read_frame(&sample());
        truncated.truncate(11);
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(truncated),
            Err(ClipboardReadFrameError::MalformedHeader),
        ));

        let mut extra = encode_sensitive_clipboard_read_frame(&sample());
        extra.push(0);
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(extra),
            Err(ClipboardReadFrameError::LengthMismatch),
        ));

        let mut short = encode_sensitive_clipboard_read_frame(&sample());
        let declared = u32::from_be_bytes(short[8..12].try_into().expect("four bytes"));
        short[8..12].copy_from_slice(&(declared + 1).to_be_bytes());
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(short),
            Err(ClipboardReadFrameError::LengthMismatch),
        ));
    }

    #[test]
    fn invalid_payload_is_rejected_without_debugging_secret() {
        let mut bytes = encode_sensitive_clipboard_read_frame(&sample());
        bytes[IPC_HEADER_LEN + CLIPBOARD_READ_SUCCESS_FIXED_LEN] = 0xFF;
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(bytes),
            Err(ClipboardReadFrameError::InvalidPayload(
                ClipboardReadSuccessError::InvalidUtf8
            )),
        ));

        let mut oversized = Zeroizing::new(vec![0_u8; IPC_HEADER_LEN + MAX_IPC_MESSAGE + 1]);
        oversized[0..4].copy_from_slice(&crate::ipc::IPC_MAGIC.to_be_bytes());
        assert!(matches!(
            decode_sensitive_clipboard_read_frame(oversized),
            Err(ClipboardReadFrameError::MalformedHeader),
        ));
    }
}
