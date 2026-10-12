//! Inactive future-v12 Service clipboard sensitive ingress guard.
//!
//! This wrapper does NOT authenticate the pipe or negotiate IPC v12. The
//! caller must supply the trusted, already-verified handshake, version and
//! six-field identity from the current control and Worker session. Production
//! v11 must continue using its existing failure-only path.
use zeroize::Zeroize;

use super::clipboard_read_frame::CLIPBOARD_READ_SUCCESS_FUTURE_MINOR;
use super::clipboard_read_gate::SensitiveReadAcceptError;
use super::clipboard_read_inbound::{SensitiveClipboardReadInbox, SensitiveInboxError};
use super::clipboard_read_success::{ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess};
use crate::ipc::{HandshakeState, IPC_VERSION_MAJOR, IpcHandshake};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveTransportError {
    NotAuthenticated,
    WrongVersion,
    NotAuthorized,
    BindingMismatch,
    InvalidPending(SensitiveReadAcceptError),
    WorkerChanged,
    Inbox(SensitiveInboxError),
}

/// Trusted current Service authorization and capability for a sensitive read.
/// The caller must source these from a verified session/policy (never metadata
/// from the Worker or untrusted clipboard request). Recheck each fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveReadGrants {
    pub clipboard_capability: bool,
    pub read_permission: bool,
}

impl SensitiveReadGrants {
    #[must_use]
    pub const fn allows_read(self) -> bool {
        self.clipboard_capability && self.read_permission
    }
}

/// An authenticated, version-bound, one-shot *testable ingress seam*.
/// There is no production Service/Worker pipe hookup or clipboard access here.
#[derive(Debug)]
pub struct SensitiveClipboardTransportGate {
    expected: ClipboardReadSuccessBinding,
    inbox: SensitiveClipboardReadInbox,
}

impl SensitiveClipboardTransportGate {
    pub fn new(
        handshake: &IpcHandshake,
        version: (u8, u8),
        expected: ClipboardReadSuccessBinding,
        active: ClipboardReadSuccessBinding,
        now_ms: u64,
        grants: SensitiveReadGrants,
    ) -> Result<Self, SensitiveTransportError> {
        if handshake.state() != HandshakeState::Authenticated {
            return Err(SensitiveTransportError::NotAuthenticated);
        }
        if version != (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR) {
            return Err(SensitiveTransportError::WrongVersion);
        }
        if !grants.allows_read() {
            return Err(SensitiveTransportError::NotAuthorized);
        }
        if !expected.is_valid() || !active.is_valid() || expected != active {
            return Err(SensitiveTransportError::BindingMismatch);
        }
        let inbox = SensitiveClipboardReadInbox::new(expected, now_ms)
            .map_err(SensitiveTransportError::InvalidPending)?;
        Ok(Self { expected, inbox })
    }

    /// On an authenticated pipe read, the caller must supply the current
    /// binding; replaced Workers or control sessions poison this pending
    /// operation and wipe the incoming fragment immediately.
    pub fn push_chunk(
        &mut self,
        handshake: &IpcHandshake,
        version: (u8, u8),
        current: ClipboardReadSuccessBinding,
        incoming: &mut [u8],
        now_ms: u64,
        grants: SensitiveReadGrants,
    ) -> Result<Option<SensitiveClipboardReadSuccess>, SensitiveTransportError> {
        if handshake.state() != HandshakeState::Authenticated {
            incoming.zeroize();
            self.inbox.cancel();
            return Err(SensitiveTransportError::NotAuthenticated);
        }
        if version != (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR) {
            incoming.zeroize();
            self.inbox.cancel();
            return Err(SensitiveTransportError::WrongVersion);
        }
        if !grants.allows_read() {
            incoming.zeroize();
            self.inbox.cancel();
            return Err(SensitiveTransportError::NotAuthorized);
        }
        if current != self.expected || !current.is_valid() {
            incoming.zeroize();
            self.inbox.cancel();
            return Err(SensitiveTransportError::WorkerChanged);
        }
        self.inbox
            .push_chunk(incoming, now_ms)
            .map_err(SensitiveTransportError::Inbox)
    }

    /// Call on control authorization revocation, IPC disconnect or Worker stop.
    pub fn cancel(&mut self) -> bool {
        self.inbox.cancel()
    }

    /// Call on each Service lifecycle tick, even if no new bytes are received.
    pub fn expire(&mut self, now_ms: u64) -> bool {
        self.inbox.expire(now_ms)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{HandshakeEvent, IPC_VERSION_MINOR, IpcHandshake};
    use crate::ipc_sensitive::{
        ClipboardReadSuccessBinding, SENSITIVE_CLIPBOARD_READ_DEADLINE_MS,
        SensitiveClipboardReadSuccess, encode_sensitive_clipboard_read_frame,
    };
    use zeroize::Zeroizing;

    fn binding() -> ClipboardReadSuccessBinding {
        ClipboardReadSuccessBinding {
            worker_process_id: 42,
            worker_session_id: 7,
            worker_generation: 4,
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
        }
    }

    fn authenticated() -> IpcHandshake {
        let mut handshake = IpcHandshake::default();
        handshake.on_event(HandshakeEvent::PeerHelloValid);
        handshake.on_event(HandshakeEvent::ChallengeResponseValid);
        handshake
    }

    fn grants() -> SensitiveReadGrants {
        SensitiveReadGrants {
            clipboard_capability: true,
            read_permission: true,
        }
    }

    fn bytes(identity: ClipboardReadSuccessBinding) -> Zeroizing<Vec<u8>> {
        let text = SensitiveClipboardReadSuccess::new(
            identity,
            Zeroizing::new("حافظة 🌙 é😀".as_bytes().to_vec()),
        )
        .expect("valid Unicode text");
        encode_sensitive_clipboard_read_frame(&text)
    }

    #[test]
    fn missing_capability_or_permission_cannot_create_sensitive_ingress() {
        for denied in [
            SensitiveReadGrants {
                clipboard_capability: false,
                read_permission: true,
            },
            SensitiveReadGrants {
                clipboard_capability: true,
                read_permission: false,
            },
        ] {
            assert_eq!(
                SensitiveClipboardTransportGate::new(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    binding(),
                    100,
                    denied,
                )
                .err(),
                Some(SensitiveTransportError::NotAuthorized)
            );
        }
    }

    #[test]
    fn revoked_grant_mid_secret_frame_zeroizes_and_poison_closes_ingress() {
        let authorized = SensitiveReadGrants {
            clipboard_capability: true,
            read_permission: true,
        };
        let mut guard = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            authorized,
        )
        .expect("authorized v12 ingress");
        let mut wire = bytes(binding());
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[..20],
                    101,
                    authorized,
                )
                .expect("accepted bounded header")
                .is_none()
        );
        let denied = SensitiveReadGrants {
            clipboard_capability: true,
            read_permission: false,
        };
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[20..],
                    102,
                    denied,
                )
                .err(),
            Some(SensitiveTransportError::NotAuthorized)
        );
        assert!(wire.iter().all(|byte| *byte == 0));
        let mut late = [0x5a; 8];
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut late,
                    103,
                    authorized,
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            ))
        );
        assert_eq!(late, [0; 8]);
    }

    #[test]
    fn active_v11_and_untrusted_handshakes_cannot_open_sensitive_ingress() {
        let auth = authenticated();
        for minor in [IPC_VERSION_MINOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR + 1] {
            assert_eq!(
                SensitiveClipboardTransportGate::new(
                    &auth,
                    (IPC_VERSION_MAJOR, minor),
                    binding(),
                    binding(),
                    100,
                    grants(),
                )
                .err(),
                Some(SensitiveTransportError::WrongVersion)
            );
        }
        let not_authenticated = IpcHandshake::default();
        assert_eq!(
            SensitiveClipboardTransportGate::new(
                &not_authenticated,
                (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                binding(),
                binding(),
                100,
                grants(),
            )
            .err(),
            Some(SensitiveTransportError::NotAuthenticated)
        );
        let mut rejected = IpcHandshake::default();
        rejected.on_event(HandshakeEvent::PeerHelloInvalid);
        assert_eq!(
            SensitiveClipboardTransportGate::new(
                &rejected,
                (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                binding(),
                binding(),
                100,
                grants(),
            )
            .err(),
            Some(SensitiveTransportError::NotAuthenticated)
        );
    }

    #[test]
    fn mismatched_or_zero_worker_binding_cannot_open_sensitive_ingress() {
        let auth = authenticated();
        for active in [
            ClipboardReadSuccessBinding {
                worker_process_id: 43,
                ..binding()
            },
            ClipboardReadSuccessBinding {
                worker_session_id: 8,
                ..binding()
            },
            ClipboardReadSuccessBinding {
                worker_generation: 5,
                ..binding()
            },
            ClipboardReadSuccessBinding {
                control_sequence: 102,
                ..binding()
            },
            ClipboardReadSuccessBinding {
                request_id: 0,
                ..binding()
            },
        ] {
            assert_eq!(
                SensitiveClipboardTransportGate::new(
                    &auth,
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    active,
                    100,
                    grants(),
                )
                .err(),
                Some(SensitiveTransportError::BindingMismatch)
            );
        }
    }

    #[test]
    fn authenticated_v12_one_shot_accepts_exact_identity_and_wipes_fragments() {
        let mut guard = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("version and authenticated identity");
        let mut wire = bytes(binding());
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[..7],
                    101,
                    grants(),
                )
                .expect("partial header")
                .is_none()
        );
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[7..12],
                    102,
                    grants(),
                )
                .expect("header")
                .is_none()
        );
        let result = guard
            .push_chunk(
                &authenticated(),
                (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                binding(),
                &mut wire[12..],
                103,
                grants(),
            )
            .expect("correlated response")
            .expect("completed");
        assert_eq!(result.binding(), binding());
        assert_eq!(result.text(), "حافظة 🌙 é😀");
        assert!(wire.iter().all(|byte| *byte == 0));
        assert!(!format!("{guard:?}").contains("حافظة"));
        let mut replay = [88_u8; 5];
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut replay,
                    104,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            )),
        );
        assert_eq!(replay, [0; 5]);
    }

    #[test]
    fn replaced_worker_mid_frame_cancels_and_wipes_late_secret() {
        let mut guard = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("safe start");
        let mut wire = bytes(binding());
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[..16],
                    101,
                    grants(),
                )
                .expect("fragment")
                .is_none()
        );
        let stale = ClipboardReadSuccessBinding {
            worker_generation: 5,
            ..binding()
        };
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    stale,
                    &mut wire[16..],
                    102,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::WorkerChanged)
        );
        assert!(wire.iter().all(|byte| *byte == 0));
        let mut late = [77_u8; 6];
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut late,
                    103,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            ))
        );
        assert_eq!(late, [0; 6]);
    }

    #[test]
    fn mid_stream_revocation_or_protocol_downgrade_wipes_and_poison_pending() {
        let mut guard = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("authorized session");
        let mut frame = bytes(binding());
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut frame[..9],
                    101,
                    grants(),
                )
                .expect("first fragment")
                .is_none()
        );
        let unauthenticated = IpcHandshake::default();
        assert_eq!(
            guard
                .push_chunk(
                    &unauthenticated,
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut frame[9..],
                    102,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::NotAuthenticated)
        );
        assert!(frame.iter().all(|byte| *byte == 0));

        let mut downgraded = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("versioned session");
        let mut secret = bytes(binding());
        assert_eq!(
            downgraded
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, IPC_VERSION_MINOR),
                    binding(),
                    &mut secret,
                    101,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::WrongVersion)
        );
        assert!(secret.iter().all(|byte| *byte == 0));
        let mut late = [42_u8; 4];
        assert_eq!(
            downgraded
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut late,
                    102,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            ))
        );
        assert_eq!(late, [0_u8; 4]);
    }

    #[test]
    fn idle_expiration_and_cancellation_fail_closed() {
        let mut guard = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("safe start");
        let mut wire = bytes(binding());
        assert!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[..9],
                    101,
                    grants(),
                )
                .expect("partial")
                .is_none()
        );
        assert!(guard.expire(100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS));
        assert_eq!(
            guard
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut wire[9..],
                    9999,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            ))
        );
        assert!(wire.iter().all(|byte| *byte == 0));
        let mut other = SensitiveClipboardTransportGate::new(
            &authenticated(),
            (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            binding(),
            binding(),
            100,
            grants(),
        )
        .expect("start");
        assert!(other.cancel());
        assert!(!other.cancel());
        let mut chunk = [7_u8; 12];
        assert_eq!(
            other
                .push_chunk(
                    &authenticated(),
                    (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
                    binding(),
                    &mut chunk,
                    101,
                    grants(),
                )
                .err(),
            Some(SensitiveTransportError::Inbox(
                SensitiveInboxError::Finished
            ))
        );
        assert_eq!(chunk, [0; 12]);
    }
}
