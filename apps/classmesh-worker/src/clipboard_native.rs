//! Isolated interactive Worker conversion boundary for clipboard text.
//! Native Windows reading is not wired to IPC request handling or Teacher UI.
//!
//! The caller must first have an authenticated, authorized ReadClipboard
//! request; this module does not grant authority or transmit clipboard text.
use classmesh_control::clipboard_utf16::{
    ClipboardUtf8Text, ClipboardUtf16Error, decode_clipboard_utf16_zeroizing,
};
use classmesh_windows_runtime::ipc_sensitive::{
    ClipboardReadSuccessBinding, ClipboardReadSuccessError, SensitiveClipboardReadSuccess,
    encode_sensitive_clipboard_read_frame,
};

/// Accept only a previously size-checked local UTF-16 source buffer. The
/// portable decoder wipes every source unit even when UTF-8 conversion fails.
pub fn decode_clipboard_units(units: &mut [u16]) -> Result<ClipboardUtf8Text, ClipboardUtf16Error> {
    decode_clipboard_utf16_zeroizing(units)
}

/// Pure conversion: no clipboard OS read, pipe send or network completion.
/// Source UTF-16 and outgoing UTF-8 each have a zeroizing owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerClipboardReadConversionError {
    InvalidUnicode,
    InvalidPayload(ClipboardReadSuccessError),
}

pub fn convert_units_to_sensitive_read_success(
    units: &mut [u16],
    binding: ClipboardReadSuccessBinding,
) -> Result<SensitiveClipboardReadSuccess, WorkerClipboardReadConversionError> {
    let text = decode_clipboard_units(units)
        .map_err(|_| WorkerClipboardReadConversionError::InvalidUnicode)?;
    SensitiveClipboardReadSuccess::new(binding, text.into_zeroizing_bytes())
        .map_err(WorkerClipboardReadConversionError::InvalidPayload)
}

/// Strictly isolated future-v12 sender. The caller must supply a binding
/// taken from the current authenticated pending Worker request, and must only
/// provide a trusted sensitive-pipe writer once v12 is negotiated. This helper
/// does not open a pipe or activate Worker clipboard events.
#[derive(Debug, PartialEq, Eq)]
pub enum WorkerClipboardFrameSendError<E> {
    BindingMismatch,
    WriteFailed(E),
}

pub fn send_sensitive_read_frame<E>(
    message: SensitiveClipboardReadSuccess,
    expected: ClipboardReadSuccessBinding,
    write_all: impl FnOnce(&[u8]) -> Result<(), E>,
) -> Result<(), WorkerClipboardFrameSendError<E>> {
    if !expected.is_valid() || message.binding() != expected {
        return Err(WorkerClipboardFrameSendError::BindingMismatch);
    }
    // Both the source message and the wire allocation wipe themselves on drop.
    let wire = encode_sensitive_clipboard_read_frame(&message);
    write_all(&wire).map_err(WorkerClipboardFrameSendError::WriteFailed)
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
    fn isolated_worker_sender_to_service_inbox_roundtrips_unicode_and_wipes_every_chunk() {
        use classmesh_windows_runtime::ipc_sensitive::SensitiveClipboardReadInbox;
        let secret = "حافظة آمنة 🌙 é😀";
        let mut units = secret.encode_utf16().chain([0]).collect::<Vec<_>>();
        let message = convert_units_to_sensitive_read_success(&mut units, binding())
            .expect("worker-bound zeroizing Unicode");
        let mut wire = Vec::new();
        send_sensitive_read_frame(message, binding(), |bytes| {
            wire.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .expect("injected future sensitive writer");
        assert!(units.iter().all(|unit| *unit == 0));
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100)
            .expect("future Service pending exact Worker");
        assert!(
            inbox
                .push_chunk(&mut wire[..5], 101)
                .expect("part one")
                .is_none()
        );
        assert!(
            inbox
                .push_chunk(&mut wire[5..12], 102)
                .expect("header")
                .is_none()
        );
        let decoded = inbox
            .push_chunk(&mut wire[12..], 103)
            .expect("current Worker read result")
            .expect("complete");
        assert_eq!(decoded.binding(), binding());
        assert_eq!(decoded.text(), secret);
        assert!(wire.iter().all(|byte| *byte == 0));
        assert!(!format!("{decoded:?}").contains(secret));
    }

    #[test]
    fn isolated_worker_sender_to_service_inbox_rejects_replaced_worker_and_replay() {
        use classmesh_windows_runtime::ipc_sensitive::{
            SensitiveClipboardReadInbox, SensitiveInboxError, SensitiveReadAcceptError,
        };
        let replaced_worker =
            classmesh_windows_runtime::ipc_sensitive::ClipboardReadSuccessBinding {
                worker_generation: binding().worker_generation + 1,
                ..binding()
            };
        let mut units = [65_u16, 0_u16];
        let message = convert_units_to_sensitive_read_success(&mut units, replaced_worker)
            .expect("valid but outdated Worker");
        let mut wire = Vec::new();
        send_sensitive_read_frame(message, replaced_worker, |bytes| {
            wire.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .expect("injected test writer");
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("current Worker");
        assert_eq!(
            inbox.push_chunk(&mut wire, 101).err(),
            Some(SensitiveInboxError::Acceptance(
                SensitiveReadAcceptError::Mismatch
            )),
        );
        assert!(wire.iter().all(|byte| *byte == 0));
        let mut new_attempt = [1_u8; 12];
        assert_eq!(
            inbox.push_chunk(&mut new_attempt, 102).err(),
            Some(SensitiveInboxError::Finished),
        );
        assert_eq!(new_attempt, [0; 12]);
    }

    #[test]
    fn isolated_worker_sender_to_service_inbox_honors_idle_deadline_and_cancel() {
        use classmesh_windows_runtime::ipc_sensitive::{
            SENSITIVE_CLIPBOARD_READ_DEADLINE_MS, SensitiveClipboardReadInbox, SensitiveInboxError,
        };
        let mut units = [0_u16];
        let message = convert_units_to_sensitive_read_success(&mut units, binding())
            .expect("empty valid UTF-16");
        let mut wire = Vec::new();
        send_sensitive_read_frame(message, binding(), |bytes| {
            wire.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .expect("injected test writer");
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("pending");
        assert!(
            inbox
                .push_chunk(&mut wire[..8], 101)
                .expect("partial")
                .is_none()
        );
        let deadline = 100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS;
        assert!(inbox.expire(deadline));
        assert_eq!(
            inbox.push_chunk(&mut wire[8..], deadline + 1).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert!(wire.iter().all(|byte| *byte == 0));

        let mut fresh = SensitiveClipboardReadInbox::new(binding(), 100).expect("fresh");
        assert!(fresh.cancel());
        let mut late = [7_u8; 12];
        assert_eq!(
            fresh.push_chunk(&mut late, 101).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert_eq!(late, [0; 12]);
    }

    #[test]
    fn sensitive_sender_encodes_exact_bound_unicode_and_no_plaintext_debug() {
        use classmesh_windows_runtime::ipc_sensitive::SensitiveClipboardReadStream;
        let secret = "مرحبا 🌙";
        let mut units = secret.encode_utf16().chain([0]).collect::<Vec<_>>();
        let result = convert_units_to_sensitive_read_success(&mut units, binding())
            .expect("authorized result");
        let mut sent = Vec::new();
        assert_eq!(
            send_sensitive_read_frame(result, binding(), |wire| {
                sent.extend_from_slice(wire);
                Ok::<(), &'static str>(())
            }),
            Ok(())
        );
        assert!(units.iter().all(|value| *value == 0));
        let mut stream = SensitiveClipboardReadStream::default();
        let decoded = stream
            .push_bytes(&mut sent)
            .expect("future versioned frame")
            .expect("exact sensitive response");
        assert!(sent.iter().all(|value| *value == 0));
        assert_eq!(decoded.binding(), binding());
        assert_eq!(decoded.text(), secret);
        assert!(!format!("{decoded:?}").contains(secret));
    }

    #[test]
    fn replaced_worker_generation_never_invokes_sensitive_writer() {
        let mut units = [65_u16, 0];
        let result =
            convert_units_to_sensitive_read_success(&mut units, binding()).expect("bounded text");
        let stale = ClipboardReadSuccessBinding {
            worker_generation: binding().worker_generation + 1,
            ..binding()
        };
        let mut called = false;
        assert_eq!(
            send_sensitive_read_frame(result, stale, |_wire| {
                called = true;
                Ok::<(), &'static str>(())
            }),
            Err(WorkerClipboardFrameSendError::BindingMismatch)
        );
        assert!(!called);
    }

    #[test]
    fn writer_failure_is_reported_without_duplicating_secret() {
        let mut units = [65_u16, 0];
        let result =
            convert_units_to_sensitive_read_success(&mut units, binding()).expect("bounded text");
        assert_eq!(
            send_sensitive_read_frame(result, binding(), |_wire| Err("pipe closed")),
            Err(WorkerClipboardFrameSendError::WriteFailed("pipe closed"))
        );
    }

    fn binding() -> classmesh_windows_runtime::ipc_sensitive::ClipboardReadSuccessBinding {
        classmesh_windows_runtime::ipc_sensitive::ClipboardReadSuccessBinding {
            worker_process_id: 42,
            worker_session_id: 7,
            worker_generation: 4,
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
        }
    }

    #[test]
    fn authorized_unicode_result_is_zeroizing_and_worker_bound() {
        let secret = "مرحبا 😀";
        let mut units = secret.encode_utf16().chain([0]).collect::<Vec<_>>();
        let result = convert_units_to_sensitive_read_success(&mut units, binding()).expect("valid");
        assert!(units.iter().all(|unit| *unit == 0));
        assert_eq!(result.binding(), binding());
        assert_eq!(result.text(), secret);
        let log = format!("{result:?}");
        assert!(!log.contains(secret));
        assert!(!log.contains("مرحبا"));
    }

    #[test]
    fn invalid_identity_is_rejected_and_unicode_units_wiped() {
        let mut units = [65_u16, 0];
        let bad = classmesh_windows_runtime::ipc_sensitive::ClipboardReadSuccessBinding {
            worker_generation: 0,
            ..binding()
        };
        assert!(matches!(
            convert_units_to_sensitive_read_success(&mut units, bad),
            Err(WorkerClipboardReadConversionError::InvalidPayload(_))
        ));
        assert_eq!(units, [0, 0]);
    }

    #[test]
    fn malformed_utf16_rejected_before_creating_sensitive_result() {
        let mut units = [0xD800_u16, 0];
        assert!(matches!(
            convert_units_to_sensitive_read_success(&mut units, binding()),
            Err(WorkerClipboardReadConversionError::InvalidUnicode)
        ));
        assert_eq!(units, [0, 0]);
    }

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
