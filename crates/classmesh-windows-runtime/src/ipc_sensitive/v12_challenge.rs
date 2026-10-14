//! Inactive future-v12 Service-issued request proof (NOT a wire transport).
//!
//! An OS-attested, live Worker pipe peer and a trusted Service-owned control
//! and grants accessor are still required. The Service must securely provision
//! a fresh, unpredictable per-request key to the launched Worker OUTSIDE legacy
//! v11 IPC before this proof can become part of a real v12 handshake.
//! Never transmit this key over v11, log it, or treat the public nonce as auth.
use std::fmt;

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use super::clipboard_read_frame::CLIPBOARD_READ_SUCCESS_FUTURE_MINOR;
use super::clipboard_read_success::ClipboardReadSuccessBinding;
use super::clipboard_read_transport_gate::SensitiveReadGrants;
use crate::ipc::IPC_VERSION_MAJOR;

const V12_VERSION: (u8, u8) = (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR);
const DEADLINE_MS: u64 = 2_500;
const TRANSCRIPT_DOMAIN: &[u8] = b"ClassMesh.v12.ClipboardRead.ServiceChallenge.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveV12ChallengeError {
    InvalidBinding,
    InvalidKey,
    ClockOverflow,
    EntropyUnavailable,
    AlreadyUsed,
    WrongVersion,
    ClockRegression,
    Expired,
    CurrentAuthorityUnavailable,
    NotAuthorized,
    BindingChanged,
    InvalidProof,
}

/// Must be read from current, trusted Service policy, never Worker metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V12LiveAuthority {
    pub binding: ClipboardReadSuccessBinding,
    pub grants: SensitiveReadGrants,
}

/// Private, single-use future-v12 proof guard. Successful verification alone
/// does NOT grant permission to receive secret payloads or bypass later checks.
pub struct SensitiveV12Challenge {
    expected: ClipboardReadSuccessBinding,
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 32],
    started_at_ms: u64,
    expires_at_ms: u64,
    pending: bool,
}

impl fmt::Debug for SensitiveV12Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveV12Challenge")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl SensitiveV12Challenge {
    /// `key` MUST be a fresh CSPRNG-generated 256-bit per-request secret
    /// provisioned only through a future trusted Worker bootstrap; this module
    /// intentionally does not supply such a bootstrap or any production I/O.
    pub fn issue(
        key: Zeroizing<[u8; 32]>,
        expected: ClipboardReadSuccessBinding,
        now_ms: u64,
    ) -> Result<Self, SensitiveV12ChallengeError> {
        if !expected.is_valid() {
            return Err(SensitiveV12ChallengeError::InvalidBinding);
        }
        if key.iter().all(|value| *value == 0) {
            return Err(SensitiveV12ChallengeError::InvalidKey);
        }
        let expires_at_ms = now_ms
            .checked_add(DEADLINE_MS)
            .ok_or(SensitiveV12ChallengeError::ClockOverflow)?;
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SensitiveV12ChallengeError::EntropyUnavailable)?;
        Ok(Self {
            expected,
            key,
            nonce,
            started_at_ms: now_ms,
            expires_at_ms,
            pending: true,
        })
    }

    /// A public nonce may be sent only over the future v12 channel AFTER the
    /// OS peer is bound. It is never itself proof of Worker authorization.
    #[must_use]
    pub fn nonce(&self) -> Option<[u8; 32]> {
        self.pending.then_some(self.nonce)
    }

    /// Consume exactly one proof attempt. Any error poisons the challenge,
    /// clears the stored key/nonce and requires an entirely new Service request.
    ///
    /// `current_authority` MUST sample live Service policy at verification,
    /// not a stale snapshot from before the Windows ConnectNamedPipe wait.
    pub fn verify(
        &mut self,
        response_mac: &[u8; 32],
        negotiated_version: (u8, u8),
        now_ms: u64,
        current_authority: impl FnOnce() -> Option<V12LiveAuthority>,
    ) -> Result<(), SensitiveV12ChallengeError> {
        if !self.pending {
            return Err(SensitiveV12ChallengeError::AlreadyUsed);
        }
        self.pending = false;
        let result = self.verify_once(response_mac, negotiated_version, now_ms, current_authority);
        self.key.zeroize();
        self.nonce.zeroize();
        result
    }

    fn verify_once(
        &self,
        response_mac: &[u8; 32],
        version: (u8, u8),
        now_ms: u64,
        current_authority: impl FnOnce() -> Option<V12LiveAuthority>,
    ) -> Result<(), SensitiveV12ChallengeError> {
        if version != V12_VERSION {
            return Err(SensitiveV12ChallengeError::WrongVersion);
        }
        if now_ms < self.started_at_ms {
            return Err(SensitiveV12ChallengeError::ClockRegression);
        }
        if now_ms >= self.expires_at_ms {
            return Err(SensitiveV12ChallengeError::Expired);
        }
        let current =
            current_authority().ok_or(SensitiveV12ChallengeError::CurrentAuthorityUnavailable)?;
        if !current.grants.allows_read() {
            return Err(SensitiveV12ChallengeError::NotAuthorized);
        }
        if !current.binding.is_valid() || current.binding != self.expected {
            return Err(SensitiveV12ChallengeError::BindingChanged);
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key[..]);
        let transcript = transcript(&self.nonce, version, self.expected);
        hmac::verify(&key, &transcript, response_mac)
            .map_err(|_| SensitiveV12ChallengeError::InvalidProof)
    }

    /// Explicit control/session revocation. Drop also clears owned key bytes.
    pub fn cancel(&mut self) -> bool {
        let was_pending = std::mem::replace(&mut self.pending, false);
        self.key.zeroize();
        self.nonce.zeroize();
        was_pending
    }
}

/// Worker-only future-v12 response primitive. Its key must come from the
/// trusted Service bootstrap, never from the challenge or an IPC v11 message.
/// Uses maintained `ring` HMAC-SHA256 rather than custom MAC cryptography.
#[must_use]
pub fn compute_v12_challenge_mac(
    key: &[u8; 32],
    nonce: &[u8; 32],
    version: (u8, u8),
    binding: ClipboardReadSuccessBinding,
) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let proof = hmac::sign(&key, &transcript(nonce, version, binding));
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(proof.as_ref());
    bytes
}

fn transcript(
    nonce: &[u8; 32],
    version: (u8, u8),
    binding: ClipboardReadSuccessBinding,
) -> Vec<u8> {
    let mut result = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 2 + 40 + nonce.len());
    result.extend_from_slice(TRANSCRIPT_DOMAIN);
    result.extend_from_slice(&[version.0, version.1]);
    result.extend_from_slice(&binding.worker_process_id.to_le_bytes());
    result.extend_from_slice(&binding.worker_session_id.to_le_bytes());
    result.extend_from_slice(&binding.worker_generation.to_le_bytes());
    result.extend_from_slice(&binding.control_session_id.to_le_bytes());
    result.extend_from_slice(&binding.control_sequence.to_le_bytes());
    result.extend_from_slice(&binding.request_id.to_le_bytes());
    result.extend_from_slice(nonce);
    result
}