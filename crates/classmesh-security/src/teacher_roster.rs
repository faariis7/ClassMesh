//! Version-1 ClassMesh Teacher roster. The caller must authenticate policy provenance.
use crate::{PrincipalId, policy_epoch::verify_startup_policy_epoch};
use coset::{Header, ProtectedHeader, SignatureContext, sig_structure_data};
use minicbor::{Decoder, Encoder, data::Tag};
use ring::{digest, signature};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_DEVICES: usize = 256;
pub const MAX_KEYS: usize = 8;
pub const MAX_PAYLOAD_BYTES: usize = 12 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_FRESHNESS_MS: u64 = 60 * 60 * 1000;
const MAX_IDENTIFIER: usize = 48;
const DOMAIN: &[u8] = b"ClassMesh/TeacherRoster/v1";
const SIGN1: Tag = Tag::new(18);
const ES256: i8 = -7;
const ROLE_TEACHER: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterDevice {
    pub principal: PrincipalId,
    pub source: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterClaims {
    pub issuer: String,
    pub key_id: String,
    pub organization: String,
    pub teacher: PrincipalId,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub epoch: u64,
    pub devices: Vec<RosterDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterKey {
    pub id: String,
    pub sec1: Vec<u8>,
    pub revoked: bool,
}

pub struct RosterPolicy<'a> {
    pub issuer: &'a str,
    pub organization: &'a str,
    pub keys: &'a [RosterKey],
    pub epoch: u64,
    pub payload_sha256: [u8; 32],
    pub refreshed_at_ms: u64,
    pub max_age_ms: u64,
    pub max_lifetime_ms: u64,
    pub revoked: &'a [PrincipalId],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterError {
    Encoding,
    Size,
    Claims,
    Algorithm,
    Issuer,
    Key,
    Signature,
    Organization,
    Teacher,
    Validity,
    Epoch,
    Conflict,
    Revoked,
    Freshness,
}

impl fmt::Display for RosterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Teacher roster rejected ({self:?})")
    }
}

impl std::error::Error for RosterError {}

impl From<minicbor::decode::Error> for RosterError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::Encoding
    }
}

#[derive(Debug)]
pub struct VerifiedTeacherRoster {
    claims: RosterClaims,
    valid_until_ms: u64,
}

impl VerifiedTeacherRoster {
    pub fn devices(&self) -> &[RosterDevice] {
        &self.claims.devices
    }

    pub fn device(&self, principal: PrincipalId) -> Option<RosterDevice> {
        let index = self
            .claims
            .devices
            .binary_search_by_key(&principal, |entry| entry.principal)
            .ok()?;
        Some(self.claims.devices[index])
    }

    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
}

/// Canonical bytes for an external signer. Contains no key and grants no authority.
pub struct UnsignedRoster {
    protected: Vec<u8>,
    payload: Vec<u8>,
}

impl UnsignedRoster {
    pub fn new(claims: &RosterClaims) -> Result<Self, RosterError> {
        validate_claims(claims)?;
        let payload = encode_claims(claims);
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(RosterError::Size);
        }
        Ok(Self {
            protected: protected_header(&claims.key_id),
            payload,
        })
    }

    pub fn signing_data(&self) -> Vec<u8> {
        signing_data(&self.protected, &self.payload)
    }

    pub fn payload_sha256(&self) -> [u8; 32] {
        sha256(&self.payload)
    }

    pub fn attach_signature(&self, signature: &[u8]) -> Result<Vec<u8>, RosterError> {
        if signature.len() != 64 {
            return Err(RosterError::Signature);
        }
        Ok(encode_envelope(&self.protected, &self.payload, signature))
    }
}

/// Parse metadata for operator inspection only. Any party can create these bytes.
pub fn inspect_roster(bytes: &[u8]) -> Result<RosterClaims, RosterError> {
    Ok(decode_envelope(bytes)?.claims)
}

pub fn verify_teacher_roster(
    bytes: &[u8],
    policy: &RosterPolicy<'_>,
    expected_teacher: PrincipalId,
    now_ms: u64,
) -> Result<VerifiedTeacherRoster, RosterError> {
    let envelope = decode_envelope(bytes)?;
    let claims = envelope.claims;
    if claims.issuer != policy.issuer {
        return Err(RosterError::Issuer);
    }
    if policy.keys.is_empty() || policy.keys.len() > MAX_KEYS {
        return Err(RosterError::Key);
    }
    let mut matching = policy.keys.iter().filter(|key| key.id == claims.key_id);
    let key = matching.next().ok_or(RosterError::Key)?;
    if matching.next().is_some() || key.sec1.len() != 65 || key.sec1[0] != 4 {
        return Err(RosterError::Key);
    }
    if key.revoked {
        return Err(RosterError::Revoked);
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &key.sec1)
        .verify(
            &signing_data(envelope.protected, envelope.payload),
            envelope.signature,
        )
        .map_err(|_| RosterError::Signature)?;
    if claims.organization != policy.organization {
        return Err(RosterError::Organization);
    }
    if claims.teacher != expected_teacher {
        return Err(RosterError::Teacher);
    }
    if policy.revoked.contains(&claims.teacher)
        || claims
            .devices
            .iter()
            .any(|device| policy.revoked.contains(&device.principal))
    {
        return Err(RosterError::Revoked);
    }
    verify_startup_policy_epoch(policy.epoch, claims.epoch).map_err(|_| RosterError::Epoch)?;
    if policy.payload_sha256 != sha256(envelope.payload) {
        return Err(RosterError::Conflict);
    }
    if !(1..=MAX_LIFETIME_MS).contains(&policy.max_lifetime_ms)
        || claims.expires_at_ms - claims.issued_at_ms > policy.max_lifetime_ms
        || now_ms < claims.not_before_ms
        || now_ms >= claims.expires_at_ms
    {
        return Err(RosterError::Validity);
    }
    let freshness_limit = policy
        .refreshed_at_ms
        .checked_add(policy.max_age_ms)
        .ok_or(RosterError::Freshness)?;
    if policy.refreshed_at_ms == 0
        || claims.issued_at_ms > policy.refreshed_at_ms
        || !(1..=MAX_FRESHNESS_MS).contains(&policy.max_age_ms)
        || now_ms < policy.refreshed_at_ms
        || now_ms >= freshness_limit
    {
        return Err(RosterError::Freshness);
    }
    let valid_until_ms = claims.expires_at_ms.min(freshness_limit);
    Ok(VerifiedTeacherRoster {
        claims,
        valid_until_ms,
    })
}

struct Envelope<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
    claims: RosterClaims,
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope<'_>, RosterError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(RosterError::Size);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.tag()? != SIGN1 || decoder.array()? != Some(4) {
        return Err(RosterError::Encoding);
    }
    let protected = decoder.bytes()?;
    if protected.len() > MAX_IDENTIFIER + 8 || decoder.map()? != Some(0) {
        return Err(RosterError::Encoding);
    }
    let payload = decoder.bytes()?;
    let signature = decoder.bytes()?;
    if payload.len() > MAX_PAYLOAD_BYTES || signature.len() != 64 {
        return Err(RosterError::Size);
    }
    if decoder.position() != bytes.len() || encode_envelope(protected, payload, signature) != bytes
    {
        return Err(RosterError::Encoding);
    }

    let mut header = Decoder::new(protected);
    if header.map()? != Some(2) || header.u8()? != 1 {
        return Err(RosterError::Encoding);
    }
    if header.i8()? != ES256 {
        return Err(RosterError::Algorithm);
    }
    if header.u8()? != 4 {
        return Err(RosterError::Encoding);
    }
    let kid = header.bytes()?;
    let key_id = std::str::from_utf8(kid).map_err(|_| RosterError::Encoding)?;
    if !identifier(key_id) || protected_header(key_id) != protected {
        return Err(RosterError::Encoding);
    }
    let claims = decode_claims(payload)?;
    if claims.key_id != key_id {
        return Err(RosterError::Key);
    }
    Ok(Envelope {
        protected,
        payload,
        signature,
        claims,
    })
}

fn decode_claims(payload: &[u8]) -> Result<RosterClaims, RosterError> {
    let mut decoder = Decoder::new(payload);
    if decoder.array()? != Some(11) || decoder.u8()? != 1 {
        return Err(RosterError::Encoding);
    }
    let issuer = decode_id(&mut decoder)?;
    let key_id = decode_id(&mut decoder)?;
    let organization = decode_id(&mut decoder)?;
    let teacher = decode_principal(&mut decoder)?;
    if decoder.u8()? != ROLE_TEACHER {
        return Err(RosterError::Teacher);
    }
    let issued_at_ms = decoder.u64()?;
    let not_before_ms = decoder.u64()?;
    let expires_at_ms = decoder.u64()?;
    let epoch = decoder.u64()?;
    let count = decoder.array()?.ok_or(RosterError::Encoding)?;
    if count == 0 || count > MAX_DEVICES as u64 {
        return Err(RosterError::Size);
    }
    let mut devices = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if decoder.array()? != Some(2) {
            return Err(RosterError::Encoding);
        }
        devices.push(RosterDevice {
            principal: decode_principal(&mut decoder)?,
            source: decoder.u64()?,
        });
    }
    let claims = RosterClaims {
        issuer,
        key_id,
        organization,
        teacher,
        issued_at_ms,
        not_before_ms,
        expires_at_ms,
        epoch,
        devices,
    };
    validate_claims(&claims)?;
    if decoder.position() != payload.len() || encode_claims(&claims) != payload {
        return Err(RosterError::Encoding);
    }
    Ok(claims)
}

fn decode_id(decoder: &mut Decoder<'_>) -> Result<String, RosterError> {
    let id = decoder.str()?;
    if !identifier(id) {
        return Err(RosterError::Claims);
    }
    Ok(id.to_owned())
}

fn decode_principal(decoder: &mut Decoder<'_>) -> Result<PrincipalId, RosterError> {
    let bytes = decoder
        .bytes()?
        .try_into()
        .map_err(|_| RosterError::Encoding)?;
    Ok(PrincipalId(bytes))
}

fn identifier(value: &str) -> bool {
    (1..=MAX_IDENTIFIER).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_claims(claims: &RosterClaims) -> Result<(), RosterError> {
    if !identifier(&claims.issuer)
        || !identifier(&claims.key_id)
        || !identifier(&claims.organization)
        || claims.teacher.0 == [0; 32]
        || claims.epoch == 0
        || claims.issued_at_ms == 0
        || claims.issued_at_ms > claims.not_before_ms
        || claims.not_before_ms >= claims.expires_at_ms
        || claims.expires_at_ms - claims.issued_at_ms > MAX_LIFETIME_MS
    {
        return Err(RosterError::Claims);
    }
    if claims.devices.is_empty() || claims.devices.len() > MAX_DEVICES {
        return Err(RosterError::Size);
    }
    let mut sources = BTreeSet::new();
    if claims
        .devices
        .windows(2)
        .any(|pair| pair[0].principal >= pair[1].principal)
        || claims.devices.iter().any(|device| {
            device.principal == claims.teacher
                || device.principal.0 == [0; 32]
                || device.source == 0
                || !sources.insert(device.source)
        })
    {
        return Err(RosterError::Claims);
    }
    Ok(())
}

fn encode_claims(claims: &RosterClaims) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(11)
        .unwrap()
        .u8(1)
        .unwrap()
        .str(&claims.issuer)
        .unwrap()
        .str(&claims.key_id)
        .unwrap()
        .str(&claims.organization)
        .unwrap()
        .bytes(&claims.teacher.0)
        .unwrap()
        .u8(ROLE_TEACHER)
        .unwrap()
        .u64(claims.issued_at_ms)
        .unwrap()
        .u64(claims.not_before_ms)
        .unwrap()
        .u64(claims.expires_at_ms)
        .unwrap()
        .u64(claims.epoch)
        .unwrap()
        .array(claims.devices.len() as u64)
        .unwrap();
    for device in &claims.devices {
        encoder
            .array(2)
            .unwrap()
            .bytes(&device.principal.0)
            .unwrap()
            .u64(device.source)
            .unwrap();
    }
    encoder.into_writer()
}

fn protected_header(kid: &str) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .i8(ES256)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(kid.as_bytes())
        .unwrap();
    encoder.into_writer()
}

fn encode_envelope(protected: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .tag(SIGN1)
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature)
        .unwrap();
    encoder.into_writer()
}

fn signing_data(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    sig_structure_data(
        SignatureContext::CoseSign1,
        ProtectedHeader {
            original_data: Some(protected.to_vec()),
            header: Header::default(),
        },
        None,
        DOMAIN,
        payload,
    )
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 width")
}
