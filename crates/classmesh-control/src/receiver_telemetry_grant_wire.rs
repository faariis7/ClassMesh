//! Fixed-width, non-secret grant *payload* for a FUTURE negotiated transport.
//!
//! No IPC message type, minor version, privilege, sender or receive path is
//! registered here. In particular Phase12 reserves IPC v12 / type 33 for a
//! separate sensitive clipboard channel. A decoded payload is **untrusted**
//! and MUST NOT activate any Worker receiver/publisher without independent
//! authenticated Service-origin and current OS peer/generation checks.
//! This codec intentionally has no cryptographic authenticity mechanism.

use crate::receiver_telemetry::ReceiverTelemetryBinding;
use crate::receiver_telemetry_service_lifecycle::ReceiverTelemetryCurrentWorker;
use crate::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryWorkerGrant,
};

const MAGIC: [u8; 4] = *b"CMRG";
const WIRE_VERSION: u8 = 1;
/// Eight-byte envelope, 56-byte receiver identity and 32-byte key-grant
/// identity, with no variable-length allocations or extension fields.
pub const GRANT_WIRE_LEN: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverGrantWireError {
    InvalidLength,
    BadMagic,
    UnsupportedVersion,
    NonzeroReserved,
    InvalidBinding,
    MismatchedGrant,
}

/// Parsing this struct is NEVER authorization. Only the Service-owned
/// lifecycle can mint a `ReceiverTelemetryWorkerGrant` with private fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedReceiverTelemetryGrant {
    receiver: ReceiverTelemetryBinding,
    protected_key_grant: ReceiverTelemetryAuthorizedKey,
}

impl UntrustedReceiverTelemetryGrant {
    #[must_use]
    pub const fn receiver(self) -> ReceiverTelemetryBinding {
        self.receiver
    }

    #[must_use]
    pub const fn protected_key_grant(self) -> ReceiverTelemetryAuthorizedKey {
        self.protected_key_grant
    }

    /// Local consistency ONLY, not transport authentication or an
    /// authorization permit. The caller must independently verify that this
    /// came from the currently authenticated Service and that these local
    /// Worker/installed-key/start values are genuinely current.
    #[must_use]
    pub fn matches_verified_local_state(
        self,
        current_worker: ReceiverTelemetryCurrentWorker,
        installed_key: ReceiverTelemetryAuthorizedKey,
        accepted_start_request_id: u64,
    ) -> bool {
        current_worker.process_id != 0
            && current_worker.session_id != 0
            && current_worker.worker_generation != 0
            && accepted_start_request_id != 0
            && installed_key.is_valid()
            && self.receiver.process_id == current_worker.process_id
            && self.receiver.session_id == current_worker.session_id
            && self.receiver.worker_generation == current_worker.worker_generation
            && self.receiver.request_id == accepted_start_request_id
            && self.protected_key_grant == installed_key
    }
}

/// Serialize an already Service-minted grant into a fixed-size payload.
/// Transport framing, peer authentication and replay prevention MUST be
/// supplied separately; no active IPC version is registered by this codec.
#[must_use]
pub fn encode_service_worker_grant(grant: ReceiverTelemetryWorkerGrant) -> [u8; GRANT_WIRE_LEN] {
    let receiver = grant.receiver();
    let key = grant.protected_key_grant();
    let mut bytes = [0_u8; GRANT_WIRE_LEN];
    bytes[..4].copy_from_slice(&MAGIC);
    bytes[4] = WIRE_VERSION;
    // Bytes 5..8 stay zero (reserved for future use).
    let mut cursor = 8;
    write_u32(&mut bytes, &mut cursor, receiver.process_id);
    write_u32(&mut bytes, &mut cursor, receiver.session_id);
    write_u64(&mut bytes, &mut cursor, receiver.worker_generation);
    write_u64(&mut bytes, &mut cursor, receiver.control_session_id);
    write_u64(&mut bytes, &mut cursor, receiver.request_id);
    write_u64(&mut bytes, &mut cursor, receiver.presentation_id);
    write_u32(&mut bytes, &mut cursor, receiver.stream_id);
    write_u32(&mut bytes, &mut cursor, receiver.epoch);
    write_u64(&mut bytes, &mut cursor, receiver.receiver_generation);
    write_u64(&mut bytes, &mut cursor, key.control_session_id);
    write_u64(&mut bytes, &mut cursor, key.key_grant_request_id);
    write_u64(&mut bytes, &mut cursor, key.presentation_id);
    write_u32(&mut bytes, &mut cursor, key.stream_id);
    write_u32(&mut bytes, &mut cursor, key.epoch);
    debug_assert_eq!(cursor, GRANT_WIRE_LEN);
    bytes
}

/// Strict, allocation-free decode of an *untrusted* payload. This returns
/// neither a credential nor the private Service-minted grant type.
pub fn decode_untrusted_worker_grant(
    bytes: &[u8],
) -> Result<UntrustedReceiverTelemetryGrant, ReceiverGrantWireError> {
    if bytes.len() != GRANT_WIRE_LEN {
        return Err(ReceiverGrantWireError::InvalidLength);
    }
    if bytes[..4] != MAGIC {
        return Err(ReceiverGrantWireError::BadMagic);
    }
    if bytes[4] != WIRE_VERSION {
        return Err(ReceiverGrantWireError::UnsupportedVersion);
    }
    if bytes[5..8].iter().any(|byte| *byte != 0) {
        return Err(ReceiverGrantWireError::NonzeroReserved);
    }

    let mut cursor = 8;
    let receiver = ReceiverTelemetryBinding {
        process_id: read_u32(bytes, &mut cursor),
        session_id: read_u32(bytes, &mut cursor),
        worker_generation: read_u64(bytes, &mut cursor),
        control_session_id: read_u64(bytes, &mut cursor),
        request_id: read_u64(bytes, &mut cursor),
        presentation_id: read_u64(bytes, &mut cursor),
        stream_id: read_u32(bytes, &mut cursor),
        epoch: read_u32(bytes, &mut cursor),
        receiver_generation: read_u64(bytes, &mut cursor),
    };
    let protected_key_grant = ReceiverTelemetryAuthorizedKey {
        control_session_id: read_u64(bytes, &mut cursor),
        key_grant_request_id: read_u64(bytes, &mut cursor),
        presentation_id: read_u64(bytes, &mut cursor),
        stream_id: read_u32(bytes, &mut cursor),
        epoch: read_u32(bytes, &mut cursor),
    };
    debug_assert_eq!(cursor, GRANT_WIRE_LEN);

    if !receiver.is_valid() || !protected_key_grant.is_valid() {
        return Err(ReceiverGrantWireError::InvalidBinding);
    }
    if receiver.control_session_id != protected_key_grant.control_session_id
        || receiver.presentation_id != protected_key_grant.presentation_id
        || receiver.stream_id != protected_key_grant.stream_id
        || receiver.epoch != protected_key_grant.epoch
    {
        return Err(ReceiverGrantWireError::MismatchedGrant);
    }
    Ok(UntrustedReceiverTelemetryGrant {
        receiver,
        protected_key_grant,
    })
}

fn write_u32(bytes: &mut [u8; GRANT_WIRE_LEN], cursor: &mut usize, value: u32) {
    bytes[*cursor..*cursor + 4].copy_from_slice(&value.to_be_bytes());
    *cursor += 4;
}

fn write_u64(bytes: &mut [u8; GRANT_WIRE_LEN], cursor: &mut usize, value: u64) {
    bytes[*cursor..*cursor + 8].copy_from_slice(&value.to_be_bytes());
    *cursor += 8;
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    let value = u32::from_be_bytes(
        bytes[*cursor..*cursor + 4]
            .try_into()
            .expect("fixed-width grant payload checked"),
    );
    *cursor += 4;
    value
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let value = u64::from_be_bytes(
        bytes[*cursor..*cursor + 8]
            .try_into()
            .expect("fixed-width grant payload checked"),
    );
    *cursor += 8;
    value
}
