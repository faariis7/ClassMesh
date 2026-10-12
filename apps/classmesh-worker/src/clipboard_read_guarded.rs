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

/// Construct once from the already-authenticated live Worker/control session.
/// Never recreate this from a repeated or untrusted request's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerReadScope {
    pub worker_pid: u32,
    pub worker_session: u32,
    pub worker_generation: u64,
    pub control_session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerReadReplayError {
    InvalidScope,
    BindingMismatch,
    NonMonotonic,
}

/// Retains the most recently consumed control sequence, including failures.
/// Scope rotation requires the trusted lifecycle owner to construct a new
/// guard only after a separately authenticated session/Worker transition.
#[derive(Debug)]
pub struct WorkerReadSequenceGuard {
    scope: WorkerReadScope,
    last_sequence: u64,
}

impl WorkerReadSequenceGuard {
    pub fn new(scope: WorkerReadScope) -> Result<Self, WorkerReadReplayError> {
        if scope.worker_pid == 0
            || scope.worker_session == 0
            || scope.worker_generation == 0
            || scope.control_session_id == 0
        {
            return Err(WorkerReadReplayError::InvalidScope);
        }
        Ok(Self {
            scope,
            last_sequence: 0,
        })
    }

    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    fn reserve(
        &mut self,
        context: &AuthorizedWorkerReadContext<'_>,
    ) -> Result<(), WorkerReadReplayError> {
        let request = context.request;
        if context.worker_pid != self.scope.worker_pid
            || context.worker_session != self.scope.worker_session
            || context.worker_generation != self.scope.worker_generation
            || request.worker_generation != self.scope.worker_generation
            || request.control_session_id != self.scope.control_session_id
            || request.request_id == 0
            || request.control_sequence == 0
        {
            return Err(WorkerReadReplayError::BindingMismatch);
        }
        if request.control_sequence <= self.last_sequence {
            return Err(WorkerReadReplayError::NonMonotonic);
        }
        self.last_sequence = request.control_sequence;
        Ok(())
    }
}

/// The intended future-v12 entry point: reject unauthenticated commands
/// without consuming the sequence. Once authorized, consume sequence before
/// native clipboard read; failures and disconnects must not allow re-reading.
pub fn run_guarded_worker_clipboard_read_once<E>(
    guard: &mut WorkerReadSequenceGuard,
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
    guard
        .reserve(&context)
        .map_err(GuardedWorkerReadError::Replay)?;
    run_guarded_worker_clipboard_read(context, read_clipboard, write_all)
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
    Replay(WorkerReadReplayError),
    Native(WorkerClipboardReadError),
    InvalidPayload(ClipboardReadSuccessError),
    Send(WorkerClipboardFrameSendError<E>),
}

/// Never invoke either callback on untrusted, v11, revoked or stale request.
/// Unlike the production v11 path, the *future* versioned route may return a
/// success frame, but only through the existing zeroizing v12 sender.
fn run_guarded_worker_clipboard_read<E>(
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

    fn scope() -> WorkerReadScope {
        WorkerReadScope {
            worker_pid: 42,
            worker_session: 7,
            worker_generation: 4,
            control_session_id: 77,
        }
    }

    #[test]
    fn replayed_worker_read_never_rereads_clipboard() {
        let trusted = auth();
        let mut replay = WorkerReadSequenceGuard::new(scope()).expect("trusted scope");
        let mut reads = 0;
        let first = run_guarded_worker_clipboard_read_once(
            &mut replay,
            context(&trusted),
            || {
                reads += 1;
                Err(WorkerClipboardReadError::NativeUnavailable)
            },
            |_frame| Ok::<(), ()>(()),
        );
        assert_eq!(
            first,
            Err(GuardedWorkerReadError::Native(
                WorkerClipboardReadError::NativeUnavailable
            ))
        );
        assert_eq!(reads, 1);
        let duplicate = run_guarded_worker_clipboard_read_once(
            &mut replay,
            context(&trusted),
            || {
                reads += 1;
                Ok(Some(clipboard("must not be read")))
            },
            |_frame| Ok::<(), ()>(()),
        );
        assert_eq!(
            duplicate,
            Err(GuardedWorkerReadError::Replay(
                WorkerReadReplayError::NonMonotonic
            ))
        );
        assert_eq!(reads, 1);
        let stale = AuthorizedWorkerReadContext {
            request: ServiceClipboardReadRequest {
                control_sequence: 100,
                ..request()
            },
            ..context(&trusted)
        };
        assert_eq!(
            run_guarded_worker_clipboard_read_once(
                &mut replay,
                stale,
                || {
                    reads += 1;
                    Ok(Some(clipboard("no")))
                },
                |_frame| Ok::<(), ()>(()),
            ),
            Err(GuardedWorkerReadError::Replay(
                WorkerReadReplayError::NonMonotonic
            ))
        );
        assert_eq!(reads, 1);
    }

    #[test]
    fn rejected_v11_grant_does_not_consume_future_authorized_sequence() {
        let trusted = auth();
        let mut replay = WorkerReadSequenceGuard::new(scope()).unwrap();
        let unauthorized = AuthorizedWorkerReadContext {
            clipboard_capability: false,
            ..context(&trusted)
        };
        let mut reads = 0;
        assert_eq!(
            run_guarded_worker_clipboard_read_once(
                &mut replay,
                unauthorized,
                || {
                    reads += 1;
                    Ok(Some(clipboard("no")))
                },
                |_frame| Ok::<(), ()>(()),
            ),
            Err(GuardedWorkerReadError::NotAuthorized)
        );
        assert_eq!(reads, 0);
        let v11 = AuthorizedWorkerReadContext {
            ipc_version: (0, IPC_VERSION_MINOR),
            ..context(&trusted)
        };
        assert_eq!(
            run_guarded_worker_clipboard_read_once(
                &mut replay,
                v11,
                || {
                    reads += 1;
                    Ok(Some(clipboard("no")))
                },
                |_frame| Ok::<(), ()>(()),
            ),
            Err(GuardedWorkerReadError::WrongVersion)
        );
        let accepted = run_guarded_worker_clipboard_read_once(
            &mut replay,
            context(&trusted),
            || {
                reads += 1;
                Ok(None)
            },
            |_frame| Ok::<(), ()>(()),
        );
        assert_eq!(accepted, Ok(GuardedWorkerReadOutcome::Unavailable));
        assert_eq!(reads, 1);
    }

    #[test]
    fn stale_generation_session_and_worker_are_not_replay_guard_resets() {
        let trusted = auth();
        let mut replay = WorkerReadSequenceGuard::new(scope()).unwrap();
        for ctx in [
            AuthorizedWorkerReadContext {
                worker_pid: 43,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                worker_session: 8,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                worker_generation: 5,
                ..context(&trusted)
            },
            AuthorizedWorkerReadContext {
                request: ServiceClipboardReadRequest {
                    control_session_id: 78,
                    ..request()
                },
                ..context(&trusted)
            },
        ] {
            let mut invoked = false;
            assert_eq!(
                run_guarded_worker_clipboard_read_once(
                    &mut replay,
                    ctx,
                    || {
                        invoked = true;
                        Ok(Some(clipboard("no")))
                    },
                    |_frame| Ok::<(), ()>(()),
                ),
                Err(GuardedWorkerReadError::Replay(
                    WorkerReadReplayError::BindingMismatch
                ))
            );
            assert!(!invoked);
        }
        assert_eq!(replay.last_sequence(), 0);
        assert!(
            WorkerReadSequenceGuard::new(WorkerReadScope {
                worker_pid: 0,
                ..scope()
            })
            .is_err()
        );
    }

    #[test]
    fn increasing_sequences_send_unicode_once_even_after_writer_failure() {
        let trusted = auth();
        let mut replay = WorkerReadSequenceGuard::new(scope()).unwrap();
        assert_eq!(
            run_guarded_worker_clipboard_read_once(
                &mut replay,
                context(&trusted),
                || Ok(Some(clipboard("private"))),
                |_frame| Err("disconnected")
            ),
            Err(GuardedWorkerReadError::Send(
                WorkerClipboardFrameSendError::WriteFailed("disconnected")
            ))
        );
        assert_eq!(replay.last_sequence(), 101);
        let later = AuthorizedWorkerReadContext {
            request: ServiceClipboardReadRequest {
                control_sequence: 102,
                request_id: 20,
                ..request()
            },
            ..context(&trusted)
        };
        let mut wire = Vec::new();
        assert_eq!(
            run_guarded_worker_clipboard_read_once(
                &mut replay,
                later,
                || Ok(Some(clipboard("مرحبا 🌙"))),
                |frame| {
                    wire.extend_from_slice(frame);
                    Ok::<(), ()>(())
                },
            ),
            Ok(GuardedWorkerReadOutcome::SensitiveSent)
        );
        assert_eq!(replay.last_sequence(), 102);
        let mut stream = SensitiveClipboardReadStream::default();
        let result = stream.push_bytes(&mut wire).unwrap().unwrap();
        assert_eq!(result.text(), "مرحبا 🌙");
        assert_eq!(result.binding().control_sequence, 102);
        assert!(wire.iter().all(|b| *b == 0));
    }
}
