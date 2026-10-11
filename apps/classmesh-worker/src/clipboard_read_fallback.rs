//! Explicit fail-closed Worker behavior while real interactive clipboard
//! access and zeroizing success-response transport are not implemented.
//! This function does not inspect clipboard state or hold user text.

use classmesh_windows_runtime::ipc::{
    ClipboardReadFailureReason, IpcFrame, IpcMessageError, ServiceClipboardReadRequest,
    WorkerClipboardReadFailure,
};

/// Return only a bounded, authenticated-pipe reply identifying the failed read.
/// An actual read-success must never be represented by this metadata-only frame.
pub fn unavailable_clipboard_read(
    request: ServiceClipboardReadRequest,
    process_id: u32,
    session_id: u32,
) -> Result<WorkerClipboardReadFailure, IpcMessageError> {
    let reply = WorkerClipboardReadFailure {
        process_id,
        session_id,
        control_session_id: request.control_session_id,
        control_sequence: request.control_sequence,
        request_id: request.request_id,
        worker_generation: request.worker_generation,
        reason: ClipboardReadFailureReason::Unavailable,
    };
    IpcFrame::worker_clipboard_read_failure(reply)?;
    Ok(reply)
}
#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_windows_runtime::ipc::{
        ClipboardReadFailureReason, IpcFrame, IpcMessage, IpcMessageError,
        ServiceClipboardReadRequest,
    };

    fn request() -> ServiceClipboardReadRequest {
        ServiceClipboardReadRequest {
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
            worker_generation: 4,
        }
    }

    #[test]
    fn fail_closed_without_touching_clipboard_or_minting_available_text() {
        let reply = unavailable_clipboard_read(request(), 42, 7).expect("valid identity");
        assert_eq!(reply.process_id, 42);
        assert_eq!(reply.session_id, 7);
        assert_eq!(reply.control_session_id, 77);
        assert_eq!(reply.control_sequence, 101);
        assert_eq!(reply.request_id, 19);
        assert_eq!(reply.worker_generation, 4);
        assert_eq!(reply.reason, ClipboardReadFailureReason::Unavailable);
        let frame = IpcFrame::worker_clipboard_read_failure(reply).expect("valid result");
        assert_eq!(
            frame.message(),
            Ok(IpcMessage::WorkerClipboardReadFailure(reply))
        );
        assert_eq!(frame.payload.len(), 48);
    }

    #[test]
    fn fail_closed_rejects_zero_worker_and_request_bindings() {
        assert_eq!(
            unavailable_clipboard_read(request(), 0, 7),
            Err(IpcMessageError::InvalidPayload)
        );
        assert_eq!(
            unavailable_clipboard_read(request(), 42, 0),
            Err(IpcMessageError::InvalidPayload)
        );
        assert_eq!(
            unavailable_clipboard_read(
                ServiceClipboardReadRequest {
                    control_sequence: 0,
                    ..request()
                },
                42,
                7
            ),
            Err(IpcMessageError::InvalidPayload)
        );
    }
}
