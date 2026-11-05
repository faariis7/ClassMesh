//! Bounded, canonical representation of a non-secret Phase12F audit *INTENT*.
//!
//! Encoding is NOT a signature, authenticity check, durable audit event or
//! policy commit. No untrusted bytes can authorize an administrative action.
//! The independently authenticated durable commit path must validate
//! current policy/actor, publish and record an immutable audit atomically.
use serde::{Deserialize, Serialize};

use crate::{
    PrincipalId, classroom_policy_change_stage::ClassroomAuditIntent,
    classroom_policy_preview::ClassroomPermission,
};

pub const MAX_AUDIT_INTENT_BYTES: usize = 512;
const AUDIT_INTENT_VERSION: u8 = 1;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditIntentEncodingError {
    Oversize,
    Malformed,
    UnsupportedVersion,
    InvalidIntent,
    NonCanonical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassroomAuditIntentRecord {
    actor: PrincipalId,
    target: PrincipalId,
    permission: ClassroomPermission,
    previous_grant: bool,
    new_grant: bool,
    request_id: u64,
    expected_policy_generation: u64,
    checked_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAuditIntent {
    version: u8,
    actor: String,
    target: String,
    permission: String,
    previous_grant: bool,
    new_grant: bool,
    request_id: u64,
    expected_policy_generation: u64,
    checked_at_unix_ms: u64,
}

fn encode_id(id: PrincipalId) -> String {
    let mut out = String::with_capacity(64);
    for b in id.0 {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

fn hex_digit(b: u8) -> Result<u8, AuditIntentEncodingError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(AuditIntentEncodingError::InvalidIntent),
    }
}

fn decode_id(value: &str) -> Result<PrincipalId, AuditIntentEncodingError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(AuditIntentEncodingError::InvalidIntent);
    }
    let mut result = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        result[i] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(PrincipalId(result))
}

fn permission_tag(p: ClassroomPermission) -> &'static str {
    match p {
        ClassroomPermission::ViewMonitoring => "view_monitoring",
        ClassroomPermission::ViewInteractive => "view_interactive",
        ClassroomPermission::StartPresentation => "start_presentation",
        ClassroomPermission::ReceivePresentation => "receive_presentation",
    }
}

fn parse_permission(value: &str) -> Result<ClassroomPermission, AuditIntentEncodingError> {
    match value {
        "view_monitoring" => Ok(ClassroomPermission::ViewMonitoring),
        "view_interactive" => Ok(ClassroomPermission::ViewInteractive),
        "start_presentation" => Ok(ClassroomPermission::StartPresentation),
        "receive_presentation" => Ok(ClassroomPermission::ReceivePresentation),
        _ => Err(AuditIntentEncodingError::InvalidIntent),
    }
}

impl ClassroomAuditIntentRecord {
    pub fn from_intent(intent: &ClassroomAuditIntent) -> Result<Self, AuditIntentEncodingError> {
        let record = Self {
            actor: intent.actor(),
            target: intent.target(),
            permission: intent.permission(),
            previous_grant: intent.previous_grant(),
            new_grant: intent.new_grant(),
            request_id: intent.request_id(),
            expected_policy_generation: intent.expected_policy_generation(),
            checked_at_unix_ms: intent.checked_at_unix_ms(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), AuditIntentEncodingError> {
        if self.actor == self.target
            || self.previous_grant == self.new_grant
            || self.request_id == 0
            || self.expected_policy_generation == 0
            || self.expected_policy_generation == u64::MAX
            || self.checked_at_unix_ms == 0
        {
            return Err(AuditIntentEncodingError::InvalidIntent);
        }
        Ok(())
    }

    fn to_wire(&self) -> WireAuditIntent {
        WireAuditIntent {
            version: AUDIT_INTENT_VERSION,
            actor: encode_id(self.actor),
            target: encode_id(self.target),
            permission: permission_tag(self.permission).to_owned(),
            previous_grant: self.previous_grant,
            new_grant: self.new_grant,
            request_id: self.request_id,
            expected_policy_generation: self.expected_policy_generation,
            checked_at_unix_ms: self.checked_at_unix_ms,
        }
    }

    /// Canonical byte representation ONLY; no commit, I/O or attestation.
    pub fn encode(&self) -> Result<Vec<u8>, AuditIntentEncodingError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(&self.to_wire()).map_err(|_| AuditIntentEncodingError::Malformed)?;
        if bytes.len() > MAX_AUDIT_INTENT_BYTES {
            return Err(AuditIntentEncodingError::Oversize);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AuditIntentEncodingError> {
        if bytes.len() > MAX_AUDIT_INTENT_BYTES {
            return Err(AuditIntentEncodingError::Oversize);
        }
        let wire: WireAuditIntent =
            serde_json::from_slice(bytes).map_err(|_| AuditIntentEncodingError::Malformed)?;
        if wire.version != AUDIT_INTENT_VERSION {
            return Err(AuditIntentEncodingError::UnsupportedVersion);
        }
        let record = Self {
            actor: decode_id(&wire.actor)?,
            target: decode_id(&wire.target)?,
            permission: parse_permission(&wire.permission)?,
            previous_grant: wire.previous_grant,
            new_grant: wire.new_grant,
            request_id: wire.request_id,
            expected_policy_generation: wire.expected_policy_generation,
            checked_at_unix_ms: wire.checked_at_unix_ms,
        };
        record.validate()?;
        // Reject noncanonical representations: whitespace, order, duplicate
        // encodings, etc. Serialization is deterministic but NOT cryptographic.
        if record.encode()?.as_slice() != bytes {
            return Err(AuditIntentEncodingError::NonCanonical);
        }
        Ok(record)
    }

    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    #[must_use]
    pub const fn target(&self) -> PrincipalId {
        self.target
    }
    #[must_use]
    pub const fn permission(&self) -> ClassroomPermission {
        self.permission
    }
    #[must_use]
    pub const fn previous_grant(&self) -> bool {
        self.previous_grant
    }
    #[must_use]
    pub const fn new_grant(&self) -> bool {
        self.new_grant
    }
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    #[must_use]
    pub const fn expected_policy_generation(&self) -> u64 {
        self.expected_policy_generation
    }
    #[must_use]
    pub const fn checked_at_unix_ms(&self) -> u64 {
        self.checked_at_unix_ms
    }
}
