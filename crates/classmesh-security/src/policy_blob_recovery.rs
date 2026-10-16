//! Isolated recovery of the *one* immutable blob named by a qualified V2
//! checkpoint. No path traversal, fallback, or Service production integration.

use std::fs::File;
use std::io::{self, Read};

use crate::policy_epoch::{
    BOUND_POLICY_CHECKPOINT_LEN, BOUND_POLICY_CHECKPOINT_MAGIC, BoundPolicyError,\n    VerifiedPolicyBytes, verify_bound_policy_checkpoint,
};

const V2_RECORD_LEN: usize = 48;
const V2_MAGIC: &[u8; 8] = b"CMPBND02";

/// Recover exactly the policy selected by an independently authenticated V2
/// checkpoint. The opener MUST return an OS-qualified retained File HANDLE for
/// that epoch; this helper does not authenticate the checkpoint, file, owner,
/// ACL, ancestor directories, or monotonic durable epoch. A path-based opener
/// without independent Windows HANDLE attestation is NOT a trusted opener.
///
/// Checkpoint framing is validated before any opener call. The returned File
/// is read once and SHA-256 verified against the checkpoint's exact bytes;
/// missing, modified or unreadable blobs fail closed with NO backup fallback.
/// No in-process policy is published by this helper.
pub fn recover_committed_policy_from_qualified_handle(
    mut qualified_checkpoint: impl Read,
    open_qualified_blob: impl FnOnce(u64) -> io::Result<File>,
    maximum_policy_bytes: usize,
) -> Result<VerifiedPolicyBytes, BoundPolicyError> {
    if maximum_policy_bytes == 0 {
        return Err(BoundPolicyError::InvalidPolicy);
    }
    let mut record = [0_u8; BOUND_POLICY_CHECKPOINT_LEN];
    qualified_checkpoint
        .read_exact(&mut record)
        .map_err(|_| BoundPolicyError::Unreadable)?;
    let mut extra = [0_u8; 1];
    if qualified_checkpoint
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
    let file = open_qualified_blob(epoch).map_err(|_| BoundPolicyError::Unreadable)?;
    verify_bound_policy_checkpoint(record.as_slice(), file, maximum_policy_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_blob_stage::{policy_blob_filename, stage_new_policy_blob};
    use crate::policy_epoch::encode_bound_policy_checkpoint;
    use std::cell::Cell;
    use std::fs;
    use std::path::Path;

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "classmesh-recovery-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_epoch(dir: &Path, epoch: u64) -> io::Result<File> {
        File::open(dir.join(policy_blob_filename(epoch)?))
    }

    #[test]
    fn recovery_opens_only_checkpoint_selected_epoch_and_exact_bytes() {
        let dir = scratch();
        let old = stage_new_policy_blob(&dir, 17, b"old").unwrap();
        let new = stage_new_policy_blob(&dir, 18, b"new policy").unwrap();
        let record = encode_bound_policy_checkpoint(18, b"new policy").unwrap();
        let opened = Cell::new(0);
        let verified = recover_committed_policy_from_qualified_handle(
            record.as_slice(),
            |epoch| {
                opened.set(opened.get() + 1);
                assert_eq!(epoch, 18);
                open_epoch(&dir, epoch)
            },
            1024,
        )
        .unwrap();
        assert_eq!(opened.get(), 1);
        assert_eq!(verified.epoch(), 18);
        assert_eq!(verified.policy_bytes(), b"new policy");
        drop((old, new));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crash_after_staging_before_checkpoint_commit_keeps_old_selection() {
        let dir = scratch();
        let old = stage_new_policy_blob(&dir, 19, b"old").unwrap();
        let new = stage_new_policy_blob(&dir, 20, b"uncommitted").unwrap();
        let trusted_record = encode_bound_policy_checkpoint(19, b"old").unwrap();
        let verified = recover_committed_policy_from_qualified_handle(
            trusted_record.as_slice(),
            |epoch| open_epoch(&dir, epoch),
            1024,
        )
        .unwrap();
        assert_eq!(verified.epoch(), 19);
        assert_eq!(verified.policy_bytes(), b"old");
        drop((old, new));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crash_after_checkpoint_commit_recovers_new_without_publication() {
        let dir = scratch();
        let old = stage_new_policy_blob(&dir, 21, b"old").unwrap();
        let new = stage_new_policy_blob(&dir, 22, b"committed").unwrap();
        let record = encode_bound_policy_checkpoint(22, b"committed").unwrap();
        let verified = recover_committed_policy_from_qualified_handle(
            record.as_slice(),
            |epoch| open_epoch(&dir, epoch),
            1024,
        )
        .unwrap();
        assert_eq!(verified.policy_bytes(), b"committed");
        drop((old, new));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_committed_blob_does_not_fall_back_to_older_blob() {
        let dir = scratch();
        let old = stage_new_policy_blob(&dir, 23, b"old").unwrap();
        let record = encode_bound_policy_checkpoint(24, b"missing").unwrap();
        let opened = Cell::new(0);
        let result = recover_committed_policy_from_qualified_handle(
            record.as_slice(),
            |epoch| {
                opened.set(opened.get() + 1);
                assert_eq!(epoch, 24);
                open_epoch(&dir, epoch)
            },
            1024,
        );
        assert_eq!(result.unwrap_err(), BoundPolicyError::Unreadable);
        assert_eq!(opened.get(), 1);
        drop(old);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_and_wrong_blob_and_size_limit_fail_closed() {
        let dir = scratch();
        let staged = stage_new_policy_blob(&dir, 25, b"tampered").unwrap();
        let original_record = encode_bound_policy_checkpoint(25, b"original").unwrap();
        assert_eq!(
            recover_committed_policy_from_qualified_handle(
                original_record.as_slice(),
                |epoch| open_epoch(&dir, epoch),
                1024,
            )
            .unwrap_err(),
            BoundPolicyError::DigestMismatch
        );
        let actual_record = encode_bound_policy_checkpoint(25, b"tampered").unwrap();
        assert_eq!(
            recover_committed_policy_from_qualified_handle(
                actual_record.as_slice(),
                |epoch| open_epoch(&dir, epoch),
                4,
            )
            .unwrap_err(),
            BoundPolicyError::InvalidPolicy
        );
        drop(staged);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_checkpoint_framing_never_opens_any_blob() {
        let valid = encode_bound_policy_checkpoint(26, b"candidate").unwrap();
        let mut bad_magic = valid.to_vec();
        bad_magic[0] = 0;
        let mut zero_epoch = valid.to_vec();
        zero_epoch[8..16].fill(0);
        let mut trailing = valid.to_vec();
        trailing.push(0);
        for invalid in [bad_magic, zero_epoch, trailing, valid[..47].to_vec()] {
            let opened = Cell::new(0);
            let result = recover_committed_policy_from_qualified_handle(
                invalid.as_slice(),
                |_| {
                    opened.set(opened.get() + 1);
                    Err(io::Error::new(io::ErrorKind::NotFound, "unexpected open"))
                },
                1024,
            );
            assert!(result.is_err());
            assert_eq!(opened.get(), 0);
        }
        let opened = Cell::new(0);
        assert_eq!(
            recover_committed_policy_from_qualified_handle(
                valid.as_slice(),
                |_| {
                    opened.set(opened.get() + 1);
                    Err(io::Error::new(io::ErrorKind::NotFound, "unexpected open"))
                },
                0,
            )
            .unwrap_err(),
            BoundPolicyError::InvalidPolicy
        );
        assert_eq!(opened.get(), 0);
    }
}
