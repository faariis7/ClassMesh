//! Inactive future-v12 Worker clipboard read entry seam.
//!
//! The live v11 Worker event deliberately remains failure-only. This boundary
//! composes existing zeroizing native decoding and sensitive frame sending,
//! but only after the caller supplies a trusted authenticated v12 session,
//! explicit capability/permission grants and the current Worker identity.
//! It has no production call site and is not an authorization mint.
use crate::clipboard_native::{
    WorkerClipboardFrameSendError, WorkerClipboardReadError, send_sensitive_read_frame,
};
use classmesh_control::clipboard_utf16::ClipboardUtf8Text;
use classmesh_windows_runtime::ipc::{
    HandshakeState, IPC_VERSION_MAJOR, IpcHandshake, ServiceClipboardReadRequest,
};
use classmesh_windows_runtime::ipc_sensitive::{
    CLIPBOARD_READ_SUCCESS_FUTURE_MINOR, ClipboardReadSuccessBinding, ClipboardReadSuccessError,
    SensitiveClipboardReadSuccess,
};

pub struct AuthorizedWorkerReadContext<'a> {
    pub handshake: &'a IpcHandshake,
    pub ipc_version: (u8, u8),
    /// These flags must come from Service's authenticated control checks;
    /// they must never be inferred from request metadata alone.
    pub clipboard_capability: bool,
    pub read_permission: bool,
    pub request: ServiceClipboardReadRequest,
    pub worker_pid: u32,
    pub worker_session: u32,
    pub worker_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedWorkerReadOutcome {
    SensitiveSent,
    Unavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GuardedWorkerReadError<E> {
    NotAuthenticated,
    WrongVersion,
    NotAuthorized,
    InvalidBinding,
    Native(WorkerClipboardReadError),
    InvalidPayload(ClipboardReadSuccessError),
    Send(WorkerClipboardFrameSendError<E>),
}

/// Never invoke either callback on untrusted, v11, revoked or stale request.
/// Unlike the production v11 path, the *future* versioned route may return a
/// success frame, but only through the existing zeroizing v12 sender.
pub fn run_guarded_worker_clipboard_read<E>(
    context: AuthorizedWorkerReadContext<'_>,
    read_clipboard: impl FnOnce() -> Result<Option<ClipboardUtf8Text>, WorkerClipboardReadError>,
    write_all: impl FnOnce(&[u8]) -> Result<(), E>,
) -> Result<GuardedWorkerReadOutcome, GuardedWorkerReadError<E>> {
    if context.handshake.state() != HandshakeState::Authenticated {
        return Err(GuardedWorkerReadError::NotAuthenticated);
    }
    if context.ipc_version != (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR) {
        return Err(GuardedWorkerReadError::WrongVersion);
    }
    if !context.clipboard_capability || !context.read_permission {
        return Err(GuardedWorkerReadError::NotAuthorized);
    }
    let request = context.request;
    if context.worker_pid == 0
        || context.worker_session == 0
        || !request.targets_active_worker_generation(context.worker_generation)
        || request.control_session_id == 0
        || request.control_sequence == 0
        || request.request_id == 0
    {
        return Err(GuardedWorkerReadError::InvalidBinding);
    }
    let binding = ClipboardReadSuccessBinding {
        worker_process_id: context.worker_pid,
        worker_session_id: context.worker_session,
        worker_generation: context.worker_generation,
        control_session_id: request.control_session_id,
        control_sequence: request.control_sequence,
        request_id: request.request_id,
    };
    let Some(text) = read_clipboard().map_err(GuardedWorkerReadError::Native)? else {
        return Ok(GuardedWorkerReadOutcome::Unavailable);
    };
    let message = SensitiveClipboardReadSuccess::new(binding, text.into_zeroizing_bytes())
        .map_err(GuardedWorkerReadError::InvalidPayload)?;
    send_sensitive_read_frame(message, binding, write_all).map_err(GuardedWorkerReadError::Send)?;
    Ok(GuardedWorkerReadOutcome::SensitiveSent)
}
// Inactive future-v12 Worker authorization and read/write composition tests.
// Production Worker events still use the v11 failure-only response.
#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_control::clipboard_utf16::decode_clipboard_utf16_zeroizing;
    use classmesh_windows_runtime::ipc::{HandshakeEvent, IPC_VERSION_MINOR, IpcHandshake};
    use classmesh_windows_runtime::ipc_sensitive::{
        CLIPBOARD_READ_SUCCESS_FUTURE_MINOR, SensitiveClipboardReadStream,
    };

    fn auth() -> IpcHandshake {
        let mut h = IpcHandshake::default();
        h.on_event(HandshakeEvent::PeerHelloValid);
        h.on_event(HandshakeEvent::ChallengeResponseValid);
        h
    }

    fn request() -> ServiceClipboardReadRequest {
        ServiceClipboardReadRequest {
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
            worker_generation: 4,
        }
    }

    fn context<'a>(h: &'a IpcHandshake) -> AuthorizedWorkerReadContext<'a> {
        AuthorizedWorkerReadContext {
            handshake: h,
            ipc_version: (0, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            clipboard_capability: true,
            read_permission: true,
            request: request(),
            worker_pid: 42,
            worker_session: 7,
            worker_generation: 4,
        }
    }

    fn clipboard(text: &str) -> ClipboardUtf8Text {
        let mut units = text.encode_utf16().chain([0]).collect::<Vec<_>>();
        let value = decode_clipboard_utf16_zeroizing(&mut units).expect("test Unicode");
        assert!(units.iter().all(|x| *x == 0));
        value
    }

    #[test]
    fn v11_untrusted_or_unauthorized_never_invokes_clipboard_or_writer() {
        let trusted = auth();
        let unauthenticated = IpcHandshake::default();
        let contexts = [
            context(&unauthenticated),
            AuthorizedWorkerReadContext {
                ipc_version: (0, IPC_VERSION_MINOR),
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                ipc_version: (0, 13),
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                clipboard_capability: false,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                read_permission: false,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                worker_generation: 5,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                worker_pid: 0,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                worker_session: 0,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                request: ServiceClipboardReadRequest {
                    request_id: 0,
                    ..request()
                },
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                request: ServiceClipboardReadRequest {
                    control_sequence: 0,
                    ..request()
                },
                ..context(&trusted)
            },
        ];
        for ctx in contexts {
            let mut read = false;
            let mut wrote = false;
            assert!(
                run_guarded_worker_clipboard_read(
                    ctx,
                    || {
                        read = true;
                        Ok(Some(clipboard("hidden")))
                    },
                    |_bytes| {
                        wrote = true;
                        Ok::<(), ()>(())
                    }
                )
                .is_err()
            );
            assert!(!read);
            assert!(!wrote);
        }
    }

    #[test]
    fn approved_unicode_read_sends_one_zeroizing_v12_frame() {
        let trusted = auth();
        let secret = "مرحبا 🌙 é😀";
        let mut wire = Vec::new();
        let result = run_guarded_worker_clipboard_read(
            context(&trusted),
            || Ok(Some(clipboard(secret))),
            |bytes| {
                wire.extend_from_slice(bytes);
                Ok::<(), ()>(())
            },
        );
        assert_eq!(result, Ok(GuardedWorkerReadOutcome::SensitiveSent));
        let mut stream = SensitiveClipboardReadStream::default();
        let received = stream
            .push_bytes(&mut wire)
            .expect("future v12 only")
            .expect("complete");
        assert_eq!(received.text(), secret);
        assert_eq!(received.binding().worker_generation, 4);
        assert_eq!(received.binding().request_id, 19);
        assert!(wire.iter().all(|x| *x == 0));
    }

    #[test]
    fn missing_clipboard_text_never_sends_success() {
        let trusted = auth();
        let mut called = false;
        assert_eq!(
            run_guarded_worker_clipboard_read(
                context(&trusted),
                || Ok(None),
                |_bytes| {
                    called = true;
                    Ok::<(), ()>(())
                }
            ),
            Ok(GuardedWorkerReadOutcome::Unavailable)
        );
        assert!(!called);
    }

    #[test]
    fn native_error_does_not_write_secret_and_write_error_propagates() {
        let trusted = auth();
        let mut wrote = false;
        assert_eq!(
            run_guarded_worker_clipboard_read(
                context(&trusted),
                || Err(WorkerClipboardReadError::NativeUnavailable),
                |_bytes| {
                    wrote = true;
                    Ok::<(), &'static str>(())
                },
            ),
            Err(GuardedWorkerReadError::Native(
                WorkerClipboardReadError::NativeUnavailable
            ))
        );
        assert!(!wrote);
        assert_eq!(
            run_guarded_worker_clipboard_read(
                context(&trusted),
                || Ok(Some(clipboard("private"))),
                |_bytes| Err("pipe closed"),
            ),
            Err(GuardedWorkerReadError::Send(
                WorkerClipboardFrameSendError::WriteFailed("pipe closed")
            ))
        );
    }

    #[test]
    fn invalid_unicode_identity_or_request_cannot_mint_success() {
        let trusted = auth();
        let mut ctx = context(&trusted);
        ctx.request.worker_generation = 0;
        let mut read = false;
        assert!(matches!(
            run_guarded_worker_clipboard_read(
                ctx,
                || {
                    read = true;
                    Ok(Some(clipboard("x")))
                },
                |_bytes| Ok::<(), ()>(())
            ),
            Err(GuardedWorkerReadError::InvalidBinding)
        ));
        assert!(!read);
    }
}
