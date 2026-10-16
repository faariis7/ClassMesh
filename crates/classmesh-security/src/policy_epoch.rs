//! Pure monotonic policy-epoch decision; NOT a protected persistence anchor.
//! A caller must first authenticate an independently protected durable anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEpochError {
    MissingOrInvalidAnchor,
    InvalidCandidate,
    NotNewer { trusted: u64, candidate: u64 },
    Exhausted,
    StartupEpochMismatch { trusted: u64, candidate: u64 },
}

/// Require a nonzero strictly increasing policy generation after reading a
/// *trusted* durable anchor. Never interpret this as a signature or ACL check.
pub fn verify_next_policy_epoch(trusted: u64, candidate: u64) -> Result<(), PolicyEpochError> {
    if trusted == 0 {
        return Err(PolicyEpochError::MissingOrInvalidAnchor);
    }
    if candidate == 0 {
        return Err(PolicyEpochError::InvalidCandidate);
    }
    if trusted == u64::MAX {
        return Err(PolicyEpochError::Exhausted);
    }
    if candidate <= trusted {
        return Err(PolicyEpochError::NotNewer { trusted, candidate });
    }
    Ok(())
}

/// Startup admission for a separately authenticated durable anchor and an
/// already authenticated policy. Equality is mandatory: a newer candidate
/// cannot silently advance trust at restart, and an older one is a rollback.
/// This does NOT authenticate either input or open any files.
pub fn verify_startup_policy_epoch(trusted: u64, candidate: u64) -> Result<(), PolicyEpochError> {
    if trusted == 0 {
        return Err(PolicyEpochError::MissingOrInvalidAnchor);
    }
    if candidate == 0 {
        return Err(PolicyEpochError::InvalidCandidate);
    }
    if trusted != candidate {
        return Err(PolicyEpochError::StartupEpochMismatch { trusted, candidate });
    }
    Ok(())
}

/// Proof of successful invocation of the caller-supplied durable commit hook.
/// Not proof of OS ACL, filesystem durability, or independently trusted origin:
/// only a future authenticated anchor implementation can supply those.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedPolicyEpoch {
    epoch: u64,
}

impl CommittedPolicyEpoch {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EpochTransitionError<E> {
    Invalid(PolicyEpochError),
    Commit(E),
}

/// Validate the proposed generation before touching storage. Return a receipt
/// ONLY if the supplied *trusted durable* commit succeeds. A publisher must
/// never install policy before this returns Ok; if a crash happens after the
/// commit but before policy publication, startup equality rejects stale data.
///
/// The callback is an interface contract, NOT a trusted writer: callers must
/// separately prove protected persistence, atomicity and fsync semantics.
pub fn commit_policy_epoch<E>(
    trusted: u64,
    candidate: u64,
    durable_commit: impl FnOnce(u64) -> Result<(), E>,
) -> Result<CommittedPolicyEpoch, EpochTransitionError<E>> {
    verify_next_policy_epoch(trusted, candidate).map_err(EpochTransitionError::Invalid)?;
    durable_commit(candidate).map_err(EpochTransitionError::Commit)?;
    Ok(CommittedPolicyEpoch { epoch: candidate })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictly_advancing_epoch_only() {
        assert_eq!(verify_next_policy_epoch(4, 5), Ok(()));
        assert_eq!(
            verify_next_policy_epoch(4, 4),
            Err(PolicyEpochError::NotNewer {
                trusted: 4,
                candidate: 4
            })
        );
        assert_eq!(
            verify_next_policy_epoch(4, 3),
            Err(PolicyEpochError::NotNewer {
                trusted: 4,
                candidate: 3
            })
        );
    }

    #[test]
    fn invalid_anchor_zero_candidate_and_overflow_are_fail_closed() {
        assert_eq!(
            verify_next_policy_epoch(0, 1),
            Err(PolicyEpochError::MissingOrInvalidAnchor)
        );
        assert_eq!(
            verify_next_policy_epoch(1, 0),
            Err(PolicyEpochError::InvalidCandidate)
        );
        assert_eq!(
            verify_next_policy_epoch(u64::MAX, u64::MAX),
            Err(PolicyEpochError::Exhausted)
        );
    }
}

#[cfg(test)]
mod transition_contract_tests {
    use super::*;

    #[test]
    fn startup_requires_exact_trusted_epoch_even_if_candidate_is_newer() {
        assert_eq!(verify_startup_policy_epoch(7, 7), Ok(()));
        assert!(verify_startup_policy_epoch(7, 8).is_err());
        assert!(verify_startup_policy_epoch(7, 6).is_err());
        assert!(verify_startup_policy_epoch(0, 7).is_err());
        assert!(verify_startup_policy_epoch(7, 0).is_err());
    }

    #[test]
    fn update_commits_trusted_epoch_before_issuing_receipt() {
        let mut committed = 7_u64;
        let receipt = commit_policy_epoch(7, 9, |candidate| {
            committed = candidate;
            Ok::<(), &'static str>(())
        })
        .unwrap();
        assert_eq!(committed, 9);
        assert_eq!(receipt.epoch(), 9);
    }

    #[test]
    fn failed_durable_commit_never_issues_receipt() {
        let mut attempts = 0;
        let result = commit_policy_epoch(7, 8, |_| {
            attempts += 1;
            Err::<(), _>("disk sync failed")
        });
        assert!(matches!(
            result,
            Err(EpochTransitionError::Commit("disk sync failed"))
        ));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn invalid_transitions_do_not_touch_trusted_storage() {
        for (trusted, candidate) in [(0, 1), (1, 0), (7, 7), (7, 6), (u64::MAX, u64::MAX)] {
            let mut writes = 0;
            let result = commit_policy_epoch(trusted, candidate, |_| {
                writes += 1;
                Ok::<(), ()>(())
            });
            assert!(matches!(result, Err(EpochTransitionError::Invalid(_))));
            assert_eq!(writes, 0);
        }
    }

    #[test]
    fn crash_after_durable_commit_before_policy_publish_fails_closed_on_restart() {
        // The external policy file still contains 7 when the independently
        // protected durable anchor has already advanced to 8.
        let mut anchor = 7;
        let receipt = commit_policy_epoch(anchor, 8, |next| {
            anchor = next;
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(receipt.epoch(), 8);
        assert!(verify_startup_policy_epoch(anchor, 7).is_err());
        assert_eq!(verify_startup_policy_epoch(anchor, 8), Ok(()));
    }
}

const POLICY_EPOCH_CHECKPOINT_MAGIC: &[u8; 8] = b"CMPECH01";
const POLICY_EPOCH_CHECKPOINT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEpochCheckpointError {
    InvalidFormat,
    InvalidEpoch,
    Unreadable,
}

/// Canonical fixed-width checkpoint bytes for a future protected epoch store.
/// These bytes are NOT authenticated or tamper-resistant by themselves.
pub fn encode_policy_epoch_checkpoint(
    epoch: u64,
) -> Result<[u8; POLICY_EPOCH_CHECKPOINT_LEN], PolicyEpochCheckpointError> {
    if epoch == 0 {
        return Err(PolicyEpochCheckpointError::InvalidEpoch);
    }
    let mut bytes = [0_u8; POLICY_EPOCH_CHECKPOINT_LEN];
    bytes[..8].copy_from_slice(POLICY_EPOCH_CHECKPOINT_MAGIC);
    bytes[8..].copy_from_slice(&epoch.to_le_bytes());
    Ok(bytes)
}

/// Read exactly one checkpoint from a caller-supplied, already-authenticated
/// open HANDLE/reader. Never silently accept trailing data or a torn record.
/// The caller must independently attest trusted origin and durable storage.
pub fn parse_policy_epoch_checkpoint(
    mut source: impl std::io::Read,
) -> Result<u64, PolicyEpochCheckpointError> {
    let mut bytes = [0_u8; POLICY_EPOCH_CHECKPOINT_LEN];
    source
        .read_exact(&mut bytes)
        .map_err(|_| PolicyEpochCheckpointError::Unreadable)?;
    if &bytes[..8] != POLICY_EPOCH_CHECKPOINT_MAGIC {
        return Err(PolicyEpochCheckpointError::InvalidFormat);
    }
    let mut extra = [0_u8; 1];
    if source
        .read(&mut extra)
        .map_err(|_| PolicyEpochCheckpointError::Unreadable)?
        != 0
    {
        return Err(PolicyEpochCheckpointError::InvalidFormat);
    }
    let epoch = u64::from_le_bytes(bytes[8..].try_into().expect("fixed width"));
    if epoch == 0 {
        return Err(PolicyEpochCheckpointError::InvalidEpoch);
    }
    Ok(epoch)
}

#[cfg(test)]
mod checkpoint_contract_tests {
    use super::*;

    #[test]
    fn checkpoint_roundtrip_accepts_only_nonzero_epoch() {
        for epoch in [1, 7, u64::MAX] {
            let encoded = encode_policy_epoch_checkpoint(epoch).unwrap();
            assert_eq!(encoded.len(), 16);
            assert_eq!(parse_policy_epoch_checkpoint(encoded.as_slice()), Ok(epoch));
        }
        assert!(encode_policy_epoch_checkpoint(0).is_err());
    }

    #[test]
    fn malformed_truncated_and_trailing_checkpoints_fail_closed() {
        let valid = encode_policy_epoch_checkpoint(42).unwrap();
        for len in 0..valid.len() {
            assert!(parse_policy_epoch_checkpoint(&valid[..len]).is_err());
        }
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(parse_policy_epoch_checkpoint(trailing.as_slice()).is_err());
        let mut wrong_magic = valid;
        wrong_magic[0] ^= 1;
        assert!(parse_policy_epoch_checkpoint(wrong_magic.as_slice()).is_err());
        let mut zero = valid;
        zero[8..].fill(0);
        assert!(parse_policy_epoch_checkpoint(zero.as_slice()).is_err());
    }

    #[test]
    fn decoder_accepts_short_reads_without_ever_accepting_short_file() {
        struct Bytewise<'a>(&'a [u8]);
        impl std::io::Read for Bytewise<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() || output.is_empty() {
                    return Ok(0);
                }
                output[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let valid = encode_policy_epoch_checkpoint(21).unwrap();
        assert_eq!(parse_policy_epoch_checkpoint(Bytewise(&valid)), Ok(21));
        assert!(parse_policy_epoch_checkpoint(Bytewise(&valid[..15])).is_err());
    }
}

/// V2 binds the *exact* policy bytes to a separately protected epoch anchor.
/// SHA-256 is unkeyed: this is not authentication unless the checkpoint's
/// provenance is independently established by the caller.
const BOUND_POLICY_CHECKPOINT_MAGIC: &[u8; 8] = b"CMPBND02";
const BOUND_POLICY_CHECKPOINT_LEN: usize = 48;
const MAX_BOUND_POLICY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundPolicyError {
    InvalidEpoch,
    InvalidCheckpoint,
    InvalidPolicy,
    DigestMismatch,
    Unreadable,
}

/// The exact byte buffer which passed the checkpoint digest check.
/// Not an authorization capability: caller must attest both open HANDLEs and
/// parse these same bytes without reopening or rereading a pathname.
#[derive(Debug)]
pub struct VerifiedPolicyBytes {
    epoch: u64,
    bytes: Vec<u8>,
}

impl VerifiedPolicyBytes {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn policy_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub fn encode_bound_policy_checkpoint(
    epoch: u64,
    policy_bytes: &[u8],
) -> Result<[u8; BOUND_POLICY_CHECKPOINT_LEN], BoundPolicyError> {
    if epoch == 0 {
        return Err(BoundPolicyError::InvalidEpoch);
    }
    if policy_bytes.is_empty() || policy_bytes.len() > MAX_BOUND_POLICY_BYTES {
        return Err(BoundPolicyError::InvalidPolicy);
    }
    let mut record = [0_u8; BOUND_POLICY_CHECKPOINT_LEN];
    record[..8].copy_from_slice(BOUND_POLICY_CHECKPOINT_MAGIC);
    record[8..16].copy_from_slice(&epoch.to_le_bytes());
    record[16..]
        .copy_from_slice(ring::digest::digest(&ring::digest::SHA256, policy_bytes).as_ref());
    Ok(record)
}

/// Bounded exact-record reader + exact-policy-byte digest binding.
/// Rejects the legacy 16-byte V1 checkpoint, never falls back to backups,
/// and does not open paths. Both readers must already be OS-attested.
pub fn verify_bound_policy_checkpoint(
    mut checkpoint: impl std::io::Read,
    policy: impl std::io::Read,
    maximum_policy_bytes: usize,
) -> Result<VerifiedPolicyBytes, BoundPolicyError> {
    use std::io::Read;
    let mut record = [0_u8; BOUND_POLICY_CHECKPOINT_LEN];
    checkpoint
        .read_exact(&mut record)
        .map_err(|_| BoundPolicyError::Unreadable)?;
    let mut extra = [0_u8; 1];
    if checkpoint
        .read(&mut extra)
        .map_err(|_| BoundPolicyError::Unreadable)?
        != 0
    {
        return Err(BoundPolicyError::InvalidCheckpoint);
    }
    if &record[..8] != BOUND_POLICY_CHECKPOINT_MAGIC {
        return Err(BoundPolicyError::InvalidCheckpoint);
    }
    let epoch = u64::from_le_bytes(record[8..16].try_into().expect("fixed-width epoch"));
    if epoch == 0 {
        return Err(BoundPolicyError::InvalidEpoch);
    }
    let bound = maximum_policy_bytes.min(MAX_BOUND_POLICY_BYTES);
    let mut bytes = Vec::new();
    policy
        .take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BoundPolicyError::Unreadable)?;
    if bytes.is_empty() || bytes.len() > bound {
        return Err(BoundPolicyError::InvalidPolicy);
    }
    let actual = ring::digest::digest(&ring::digest::SHA256, &bytes);
    // Digest is unkeyed and not a secret; fixed-width XOR aggregation avoids
    // leaking the first mismatching byte and does not use deprecated APIs.
    let mismatch = record[16..]
        .iter()
        .zip(actual.as_ref().iter())
        .fold(0_u8, |acc, (expected, observed)| {
            acc | (expected ^ observed)
        });
    if mismatch != 0 {
        return Err(BoundPolicyError::DigestMismatch);
    }
    Ok(VerifiedPolicyBytes { epoch, bytes })
}

#[cfg(test)]
mod bound_checkpoint_contract_tests {
    use super::*;

    #[test]
    fn bound_checkpoint_accepts_only_original_policy_bytes() {
        let original = br#"{"version":1,"principals":[]}"#;
        let checkpoint = encode_bound_policy_checkpoint(17, original).unwrap();
        assert_eq!(checkpoint.len(), 48);
        let verified =
            verify_bound_policy_checkpoint(checkpoint.as_slice(), original.as_slice(), 1024)
                .unwrap();
        assert_eq!(verified.epoch(), 17);
        assert_eq!(verified.policy_bytes(), original);
        let modified = br#"{"version":1,"principals":[1]}"#;
        assert!(
            verify_bound_policy_checkpoint(checkpoint.as_slice(), modified.as_slice(), 1024)
                .is_err()
        );
    }

    #[test]
    fn rejects_unbound_v1_truncation_trailing_zero_epoch_and_oversize() {
        let original = b"authorized";
        let valid = encode_bound_policy_checkpoint(19, original).unwrap();
        let v1 = encode_policy_epoch_checkpoint(19).unwrap();
        assert!(verify_bound_policy_checkpoint(v1.as_slice(), original.as_slice(), 1024).is_err());
        for len in 0..valid.len() {
            assert!(
                verify_bound_policy_checkpoint(&valid[..len], original.as_slice(), 1024).is_err()
            );
        }
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(
            verify_bound_policy_checkpoint(trailing.as_slice(), original.as_slice(), 1024).is_err()
        );
        let mut zero = valid;
        zero[8..16].fill(0);
        assert!(
            verify_bound_policy_checkpoint(zero.as_slice(), original.as_slice(), 1024).is_err()
        );
        assert!(verify_bound_policy_checkpoint(valid.as_slice(), original.as_slice(), 5).is_err());
        assert!(encode_bound_policy_checkpoint(0, original).is_err());
    }

    #[test]
    fn readers_with_partial_reads_are_supported() {
        struct Bytewise<'a>(&'a [u8]);
        impl std::io::Read for Bytewise<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() || output.is_empty() {
                    return Ok(0);
                }
                output[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let original = b"policy contents";
        let valid = encode_bound_policy_checkpoint(20, original).unwrap();
        let verified =
            verify_bound_policy_checkpoint(Bytewise(&valid), Bytewise(original), 64).unwrap();
        assert_eq!(verified.policy_bytes(), original);
    }
}

/// Receipt for the *ordering* of a versioned immutable policy blob and its
/// checkpoint. This does not authenticate either callback or establish disk
/// durability; the caller must independently attest and implement both.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedBoundPolicy {
    epoch: u64,
}

impl CommittedBoundPolicy {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BoundInstallError<E> {
    InvalidEpoch(PolicyEpochError),
    InvalidPolicy(BoundPolicyError),
    Stage(E),
    Commit(E),
}

/// Experimental crash-consistent *ordering* contract for an immutable,
/// versioned policy store. Caller must:
/// 1. Stage a NEW immutable blob, flush its file and containing directory,
///    and refuse overwrite/reuse with different bytes; never replace current.
/// 2. Atomically and durably commit an independently trusted checkpoint
///    pointing at those exact staged bytes, with anti-rollback protection.
/// 3. Publish only after this method returns Ok.
/// Startup must load the exact blob selected by the trusted checkpoint, never
/// fallback to a different version or unverified backup. Orphan staged blobs
/// may be cleaned ONLY after independent trust and recovery qualification.
/// No Windows filesystem implementation or Service wiring is provided here.
pub fn stage_then_commit_bound_policy<E>(
    trusted_epoch: u64,
    candidate_epoch: u64,
    candidate_policy: &[u8],
    stage_immutable_and_flush: impl FnOnce(u64, &[u8]) -> Result<(), E>,
    commit_trusted_checkpoint: impl FnOnce(&[u8; BOUND_POLICY_CHECKPOINT_LEN]) -> Result<(), E>,
) -> Result<CommittedBoundPolicy, BoundInstallError<E>> {
    verify_next_policy_epoch(trusted_epoch, candidate_epoch)
        .map_err(BoundInstallError::InvalidEpoch)?;
    let checkpoint = encode_bound_policy_checkpoint(candidate_epoch, candidate_policy)
        .map_err(BoundInstallError::InvalidPolicy)?;
    stage_immutable_and_flush(candidate_epoch, candidate_policy).map_err(BoundInstallError::Stage)?;
    commit_trusted_checkpoint(&checkpoint).map_err(BoundInstallError::Commit)?;
    Ok(CommittedBoundPolicy {
        epoch: candidate_epoch,
    })
}

#[cfg(test)]
mod immutable_policy_install_tests {
    use super::*;
    use std::collections::BTreeMap;

    const OLD: &[u8] = br#"{"version":1,"principals":[]}"#;
    const NEW: &[u8] = br#"{"version":1,"principals":[1]}"#;

    struct InMemoryDurableStore {
        checkpoint: [u8; BOUND_POLICY_CHECKPOINT_LEN],
        blobs: BTreeMap<u64, Vec<u8>>,
    }

    impl InMemoryDurableStore {
        fn initial() -> Self {
            Self {
                checkpoint: encode_bound_policy_checkpoint(4, OLD).unwrap(),
                blobs: BTreeMap::from([(4, OLD.to_vec())]),
            }
        }

        fn startup(&self) -> Result<VerifiedPolicyBytes, BoundPolicyError> {
            let epoch = u64::from_le_bytes(self.checkpoint[8..16].try_into().unwrap());
            let blob = self.blobs.get(&epoch).ok_or(BoundPolicyError::InvalidPolicy)?;
            verify_bound_policy_checkpoint(self.checkpoint.as_slice(), blob.as_slice(), 1024)
        }

        fn stage(&mut self, epoch: u64, bytes: &[u8]) -> Result<(), &'static str> {
            if self.blobs.contains_key(&epoch) {
                return Err("immutable blob already exists");
            }
            self.blobs.insert(epoch, bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn crash_after_stage_before_anchor_commit_loads_only_old_policy() {
        let mut store = InMemoryDurableStore::initial();
        store.stage(5, NEW).unwrap(); // simulated crash: no anchor commit
        assert_eq!(store.startup().unwrap().policy_bytes(), OLD);
        assert_eq!(store.startup().unwrap().epoch(), 4);
    }

    #[test]
    fn crash_after_anchor_commit_before_publication_loads_new_policy() {
        let mut store = InMemoryDurableStore::initial();
        store.stage(5, NEW).unwrap();
        store.checkpoint = encode_bound_policy_checkpoint(5, NEW).unwrap();
        // simulated crash before in-process publication
        assert_eq!(store.startup().unwrap().policy_bytes(), NEW);
        assert_eq!(store.startup().unwrap().epoch(), 5);
    }

    #[test]
    fn invalid_candidates_never_touch_storage() {
        for (trusted, next, policy) in [(0, 5, NEW), (4, 4, NEW), (4, 3, NEW), (4, 5, b"".as_slice())] {
            let touched = std::cell::Cell::new(0);
            let result = stage_then_commit_bound_policy(
                trusted, next, policy,
                |_, _| { touched.set(touched.get() + 1); Ok::<(), ()>(()) },
                |_| { touched.set(touched.get() + 1); Ok::<(), ()>(()) },
            );
            assert!(result.is_err());
            assert_eq!(touched.get(), 0);
        }
    }

    #[test]
    fn staging_failure_never_commits_and_commit_failure_never_returns_receipt() {
        let mut committed = false;
        let result = stage_then_commit_bound_policy(4, 5, NEW, |_, _| Err("stage failed"), |_| {
            committed = true;
            Ok(())
        });
        assert_eq!(result, Err(BoundInstallError::Stage("stage failed")));
        assert!(!committed);
        let result = stage_then_commit_bound_policy(4, 5, NEW, |_, _| Ok(()), |_| Err("commit failed"));
        assert_eq!(result, Err(BoundInstallError::Commit("commit failed")));
    }

    #[test]
    fn successful_install_orders_stage_before_anchor_and_receipt() {
        use std::cell::RefCell;
        let events = RefCell::new(Vec::new());
        let receipt = stage_then_commit_bound_policy(4, 5, NEW, |epoch, bytes| {
            assert_eq!(epoch, 5);
            assert_eq!(bytes, NEW);
            events.borrow_mut().push("stage");
            Ok::<(), ()>(())
        }, |record| {
            assert_eq!(record, &encode_bound_policy_checkpoint(5, NEW).unwrap());
            events.borrow_mut().push("commit");
            Ok::<(), ()>(())
        }).unwrap();
        assert_eq!(receipt.epoch(), 5);
        assert_eq!(events.into_inner(), ["stage", "commit"]);
    }

    #[test]
    fn missing_or_mutated_committed_blob_fails_closed_without_old_version_fallback() {
        let mut store = InMemoryDurableStore::initial();
        store.stage(5, NEW).unwrap();
        store.checkpoint = encode_bound_policy_checkpoint(5, NEW).unwrap();
        store.blobs.remove(&5);
        assert!(store.startup().is_err());
        store.blobs.insert(5, OLD.to_vec());
        assert!(store.startup().is_err());
        assert_eq!(store.blobs.get(&4).unwrap(), OLD);
        assert!(store.stage(4, NEW).is_err());
    }
}
