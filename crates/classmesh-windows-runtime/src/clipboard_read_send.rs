//! Text-free Service -> Worker clipboard-read IPC send boundary.
//!
//! The caller must have already authenticated the control envelope, negotiated
//! ClipboardText, passed ReadClipboard permission and replay checks, and bound
//! the request to the active Worker. This helper DOES NOT perform authorization.
//! It transmits only fixed-size correlation metadata, never clipboard contents.
use crate::ipc::{IpcFrame, IpcFrameError, IpcMessageError, ServiceClipboardReadRequest};

#[derive(Debug, PartialEq, Eq)]
pub enum ClipboardReadSendError<E> {
    StaleWorker,
    InvalidRequest(IpcMessageError),
    InvalidFrame(IpcFrameError),
    WriteFailed(E),
}

/// Reject obsolete Worker incarnations *before* invoking the pipe writer.
/// The caller owns the authenticated named pipe and must fail closed when
/// no live Worker is available. This sends no actual clipboard text.
pub fn send_read_metadata<E>(
    request: ServiceClipboardReadRequest,
    active_worker_generation: u64,
    write_all: impl FnOnce(&[u8]) -> Result<(), E>,
) -> Result<(), ClipboardReadSendError<E>> {
    if !request.targets_active_worker_generation(active_worker_generation) {
        return Err(ClipboardReadSendError::StaleWorker);
    }
    let frame = IpcFrame::service_clipboard_read_request(request)
        .map_err(ClipboardReadSendError::InvalidRequest)?;
    let wire = frame
        .encode()
        .map_err(ClipboardReadSendError::InvalidFrame)?;
    write_all(&wire).map_err(ClipboardReadSendError::WriteFailed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcFrameDecoder, IpcMessage};

    fn request() -> ServiceClipboardReadRequest {
        ServiceClipboardReadRequest {
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
            worker_generation: 4,
        }
    }

    #[test]
    fn guarded_read_sender_transports_exact_metadata_without_clipboard_text() {
        let mut captured = Vec::new();
        assert_eq!(
            send_read_metadata(request(), 4, |frame: &[u8]| {
                captured.extend_from_slice(frame);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert_eq!(captured.len(), 44); // 12-byte IPC header + 32 metadata.
        let frames = IpcFrameDecoder::default()
            .push_bytes(&captured)
            .expect("valid bounded frame");
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].message(),
            Ok(IpcMessage::ServiceClipboardReadRequest(request()))
        );
    }

    #[test]
    fn stale_worker_generation_never_reaches_pipe() {
        for generation in [0, 3, 5] {
            let mut sent = false;
            let actual = send_read_metadata(request(), generation, |_bytes| {
                sent = true;
                Ok::<_, ()>(())
            });
            assert_eq!(actual, Err(ClipboardReadSendError::StaleWorker));
            assert!(!sent);
        }
    }

    #[test]
    fn invalid_correlation_never_reaches_pipe() {
        let invalid = ServiceClipboardReadRequest {
            request_id: 0,
            ..request()
        };
        let mut sent = false;
        let actual = send_read_metadata(invalid, 4, |_bytes| {
            sent = true;
            Ok::<_, ()>(())
        });
        assert_eq!(
            actual,
            Err(ClipboardReadSendError::InvalidRequest(
                IpcMessageError::InvalidPayload
            ))
        );
        assert!(!sent);
    }

    #[test]
    fn worker_pipe_write_error_is_not_reported_as_success() {
        assert_eq!(
            send_read_metadata(request(), 4, |_bytes| Err("pipe.closed")),
            Err(ClipboardReadSendError::WriteFailed("pipe.closed"))
        );
    }
}
