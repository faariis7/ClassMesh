//! Inactive, sensitive Service -> Teacher clipboard read-success encoding seam.
//!
//! Requires separately authenticated v12 Service/Worker IPC and a validated,
//! authorized, one-shot Worker result. No production QUIC writer is connected.
//! Temporary protobuf plaintext is erased on drop; output bytes have an
//! owned zeroizing buffer and a redacted Debug implementation.
use std::fmt;

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_protocol::control_wire::{
    ClipboardReadResponse, ControlEnvelope, ProtocolVersion as WireProtocolVersion,
    control_envelope,
};
use prost::Message;
use zeroize::{Zeroize, Zeroizing};

use super::clipboard_read_frame::CLIPBOARD_READ_SUCCESS_FUTURE_MINOR;
use super::clipboard_read_success::{ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess};
use crate::ipc::{HandshakeState, IPC_VERSION_MAJOR, IpcHandshake};

pub struct TeacherClipboardReadContext<'a> {
    pub handshake: &'a IpcHandshake,
    /// Trusted IPC version from the authenticated Worker/Service peer.
    pub ipc_version: (u8, u8),
    /// These grants must come from the Service's verified authority, not the
    /// untrusted clipboard request or Worker result.
    pub clipboard_capability: bool,
    pub read_permission: bool,
    /// Exact current identity captured at the authorized in-flight read.
    pub expected: ClipboardReadSuccessBinding,
    pub outbound_control_sequence: u64,
    pub control_wire_version: (u16, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveTeacherClipboardError {
    NotAuthenticated,
    WrongVersion,
    NotAuthorized,
    BindingMismatch,
    InvalidSequence,
    InvalidControlVersion,
    EncodeFailed,
}

/// Secret-bearing protobuf bytes; Debug never renders the contents.
/// The allocation is wiped on drop, including failed/abandoned writes.
pub struct SensitiveTeacherClipboardWire {
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SensitiveTeacherClipboardWire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveTeacherClipboardWire")
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl SensitiveTeacherClipboardWire {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The only plaintext String created for the protobuf is owned by this
/// RAII guard; it is erased on normal return, failures and unwinding.
struct ProtectedControlEnvelope(ControlEnvelope);

impl Drop for ProtectedControlEnvelope {
    fn drop(&mut self) {
        if let Some(control_envelope::Payload::ClipboardReadResponse(reply)) =
            self.0.payload.as_mut()
        {
            reply.text_utf8.zeroize();
        }
    }
}

/// Transform *one* previously accepted future-v12 result into the existing
/// versioned control-wire message. This is not a permission mint or network
/// send; it must only be called after trusted Worker identity correlation.
pub fn encode_sensitive_teacher_read_response(
    context: TeacherClipboardReadContext<'_>,
    result: SensitiveClipboardReadSuccess,
) -> Result<SensitiveTeacherClipboardWire, SensitiveTeacherClipboardError> {
    if context.handshake.state() != HandshakeState::Authenticated {
        return Err(SensitiveTeacherClipboardError::NotAuthenticated);
    }
    if context.ipc_version != (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR) {
        return Err(SensitiveTeacherClipboardError::WrongVersion);
    }
    if !context.clipboard_capability || !context.read_permission {
        return Err(SensitiveTeacherClipboardError::NotAuthorized);
    }
    if !context.expected.is_valid() || result.binding() != context.expected {
        return Err(SensitiveTeacherClipboardError::BindingMismatch);
    }
    if context.outbound_control_sequence == 0 {
        return Err(SensitiveTeacherClipboardError::InvalidSequence);
    }
    if context.control_wire_version.0 != PROTOCOL_VERSION.major
        || context.control_wire_version.1 > PROTOCOL_VERSION.minor
    {
        return Err(SensitiveTeacherClipboardError::InvalidControlVersion);
    }

    let guarded = ProtectedControlEnvelope(ControlEnvelope {
        control_session_id: context.expected.control_session_id,
        sequence: context.outbound_control_sequence,
        protocol_version: Some(WireProtocolVersion {
            major: u32::from(context.control_wire_version.0),
            minor: u32::from(context.control_wire_version.1),
        }),
        request_id: context.expected.request_id,
        payload: Some(control_envelope::Payload::ClipboardReadResponse(
            ClipboardReadResponse {
                available: true,
                text_utf8: result.text().to_owned(),
            },
        )),
    });
    let mut wire = Zeroizing::new(Vec::with_capacity(guarded.0.encoded_len()));
    guarded
        .0
        .encode(&mut *wire)
        .map_err(|_| SensitiveTeacherClipboardError::EncodeFailed)?;
    Ok(SensitiveTeacherClipboardWire { bytes: wire })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{HandshakeEvent, IPC_VERSION_MINOR};
    use classmesh_protocol::control_wire::{ControlEnvelope, control_envelope};
    use prost::Message;
    use zeroize::Zeroizing;

    fn auth() -> IpcHandshake {
        let mut h = IpcHandshake::default();
        h.on_event(HandshakeEvent::PeerHelloValid);
        h.on_event(HandshakeEvent::ChallengeResponseValid);
        h
    }

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

    fn message(secret: &str) -> SensitiveClipboardReadSuccess {
        SensitiveClipboardReadSuccess::new(binding(), Zeroizing::new(secret.as_bytes().to_vec()))
            .expect("valid UTF-8")
    }

    fn context<'a>(h: &'a IpcHandshake) -> TeacherClipboardReadContext<'a> {
        TeacherClipboardReadContext {
            handshake: h,
            ipc_version: (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
            clipboard_capability: true,
            read_permission: true,
            expected: binding(),
            outbound_control_sequence: 6,
            control_wire_version: (0, 8),
        }
    }

    #[test]
    fn authorized_v12_success_yields_bounded_teacher_response_with_redacted_owner() {
        let handshake = auth();
        let secret = "سر الحافظة 🌙 é😀";
        let frame = encode_sensitive_teacher_read_response(context(&handshake), message(secret))
            .expect("authorized");
        assert!(!format!("{frame:?}").contains(secret));
        let parsed = ControlEnvelope::decode(frame.as_bytes()).expect("protobuf");
        assert_eq!(parsed.control_session_id, binding().control_session_id);
        assert_eq!(parsed.sequence, 6);
        assert_eq!(parsed.request_id, binding().request_id);
        match parsed.payload.expect("payload") {
            control_envelope::Payload::ClipboardReadResponse(r) => {
                assert!(r.available);
                assert_eq!(r.text_utf8, secret);
            }
            _ => panic!("unexpected response"),
        }
        assert_eq!(parsed.protocol_version.expect("wire version").minor, 8);
    }

    #[test]
    fn empty_but_available_text_is_distinct_from_failure_only() {
        let handshake = auth();
        let output = encode_sensitive_teacher_read_response(context(&handshake), message(""))
            .expect("empty valid");
        let envelope = ControlEnvelope::decode(output.as_bytes()).expect("wire");
        match envelope.payload.expect("typed") {
            control_envelope::Payload::ClipboardReadResponse(r) => {
                assert!(r.available);
                assert!(r.text_utf8.is_empty());
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn rejects_unauthenticated_v11_and_permission_revocation_without_output() {
        let unauth = IpcHandshake::default();
        assert!(matches!(
            encode_sensitive_teacher_read_response(context(&unauth), message("private")),
            Err(SensitiveTeacherClipboardError::NotAuthenticated)
        ));
        let auth = auth();
        let mut old = context(&auth);
        old.ipc_version = (IPC_VERSION_MAJOR, IPC_VERSION_MINOR);
        assert!(matches!(
            encode_sensitive_teacher_read_response(old, message("private")),
            Err(SensitiveTeacherClipboardError::WrongVersion)
        ));
        let mut revoked = context(&auth);
        revoked.read_permission = false;
        assert!(matches!(
            encode_sensitive_teacher_read_response(revoked, message("private")),
            Err(SensitiveTeacherClipboardError::NotAuthorized)
        ));
        let mut absent = context(&auth);
        absent.clipboard_capability = false;
        assert!(matches!(
            encode_sensitive_teacher_read_response(absent, message("private")),
            Err(SensitiveTeacherClipboardError::NotAuthorized)
        ));
    }

    #[test]
    fn rejects_pre_clipboard_control_wire_minor_without_generating_secret_response() {
        let auth = auth();
        for older_minor in [0, 2] {
            let mut downgraded = context(&auth);
            downgraded.control_wire_version = (0, older_minor);
            assert!(matches!(
                encode_sensitive_teacher_read_response(downgraded, message("private")),
                Err(SensitiveTeacherClipboardError::InvalidControlVersion)
            ));
        }

        let mut first_clipboard_minor = context(&auth);
        first_clipboard_minor.control_wire_version = (0, 3);
        let response =
            encode_sensitive_teacher_read_response(first_clipboard_minor, message("مرحبا"))
                .expect("clipboard contract available since v0.3");
        let parsed = ControlEnvelope::decode(response.as_bytes()).expect("valid control wire");
        assert_eq!(parsed.protocol_version.expect("version").minor, 3);
    }

    #[test]
    fn rejects_changed_worker_control_binding_and_invalid_outbound_sequence() {
        let auth = auth();
        let mut stale = context(&auth);
        stale.expected.worker_generation += 1;
        assert!(matches!(
            encode_sensitive_teacher_read_response(stale, message("hidden")),
            Err(SensitiveTeacherClipboardError::BindingMismatch)
        ));
        let mut no_sequence = context(&auth);
        no_sequence.outbound_control_sequence = 0;
        assert!(matches!(
            encode_sensitive_teacher_read_response(no_sequence, message("hidden")),
            Err(SensitiveTeacherClipboardError::InvalidSequence)
        ));
        let mut bogus_wire = context(&auth);
        bogus_wire.control_wire_version = (10, 99);
        assert!(matches!(
            encode_sensitive_teacher_read_response(bogus_wire, message("hidden")),
            Err(SensitiveTeacherClipboardError::InvalidControlVersion)
        ));
    }
}
