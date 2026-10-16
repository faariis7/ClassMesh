//! Experimental create-only blob staging; NOT a trusted Windows store.


use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_STAGED_POLICY_BYTES: usize = 4 * 1024 * 1024;

/// A create-only staged candidate. This is NOT an OS-immutable file, a trusted
/// checkpoint, or proof that its directory metadata has been durably flushed.
/// The directory must be independently authenticated and protected from all
/// untrusted mutation BEFORE any caller can rely on the blob's provenance.
#[derive(Debug)]
pub struct StagedPolicyBlob {
    epoch: u64,
    path: PathBuf,
    handle: File,
    expected_digest: [u8; 32],
}

impl StagedPolicyBlob {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read back from the SAME retained file handle; no pathname reopen.
    /// The returned bytes must still be authenticated by a trusted checkpoint
    /// before they may be used as an authorization policy.
    pub fn verify_open_handle(&mut self) -> io::Result<Vec<u8>> {
        self.handle.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.handle)
            .take((MAX_STAGED_POLICY_BYTES as u64) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > MAX_STAGED_POLICY_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "staged policy size changed"));
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let mismatch = self
            .expected_digest
            .iter()
            .zip(digest.as_ref().iter())
            .fold(0_u8, |acc, (expected, actual)| acc | (expected ^ actual));
        if mismatch != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "staged policy bytes changed"));
        }
        Ok(bytes)
    }
}

/// Deterministic, filename-only key; no user-controlled path segments.
pub fn policy_blob_filename(epoch: u64) -> io::Result<String> {
    if epoch == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero policy epoch"));
    }
    Ok(format!("policy-{epoch:016x}.json"))
}

/// Experimental create-only stage. Refuses preexisting targets, including
/// symlinks; writes and syncs the file and verifies from its retained handle.
/// It does NOT sync parent-directory metadata or implement Windows ACL / owner
/// checks, trusted ancestor pinning, cross-process exclusion or durable anchor.
/// An error after create_new may leave an orphan; NEVER automatically reuse it.
pub fn stage_new_policy_blob(
    trusted_directory: &Path,
    epoch: u64,
    policy_bytes: &[u8],
) -> io::Result<StagedPolicyBlob> {
    let filename = policy_blob_filename(epoch)?;
    if policy_bytes.is_empty() || policy_bytes.len() > MAX_STAGED_POLICY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid policy byte count"));
    }
    let path = trusted_directory.join(filename);
    let mut handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    // A failed write/sync leaves a quarantined orphan, not a silently reusable
    // file or a commit receipt. No overwrite/rename/fallback occurs here.
    handle.write_all(policy_bytes)?;
    handle.sync_all()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, policy_bytes);
    let mut expected_digest = [0_u8; 32];
    expected_digest.copy_from_slice(digest.as_ref());
    let mut staged = StagedPolicyBlob {
        epoch,
        path,
        handle,
        expected_digest,
    };
    staged.verify_open_handle()?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "classmesh-blob-stage-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn creates_exact_blob_and_refuses_same_epoch_overwrite() {
        let dir = scratch();
        let mut staged = stage_new_policy_blob(&dir, 41, b"new policy").unwrap();
        assert_eq!(staged.epoch(), 41);
        assert_eq!(fs::read(staged.path()).unwrap(), b"new policy");
        assert_eq!(staged.verify_open_handle().unwrap(), b"new policy");
        assert_eq!(stage_new_policy_blob(&dir, 41, b"other").unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(staged.path()).unwrap(), b"new policy");
        drop(staged);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_inputs_have_no_side_effects() {
        let dir = scratch();
        let oversized = vec![0; 4 * 1024 * 1024 + 1];
        for (epoch, data) in [(0, b"valid".as_slice()), (3, b"".as_slice()), (3, oversized.as_slice())] {
            assert!(stage_new_policy_blob(&dir, epoch, data).is_err());
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn precreated_target_is_never_overwritten() {
        let dir = scratch();
        let target = dir.join(policy_blob_filename(42).unwrap());
        fs::write(&target, b"attacker content").unwrap();
        assert_eq!(stage_new_policy_blob(&dir, 42, b"safe").unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(target).unwrap(), b"attacker content");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_staged_bytes_are_rejected_from_retained_handle() {
        let dir = scratch();
        let mut staged = stage_new_policy_blob(&dir, 44, b"original").unwrap();
        staged.handle.seek(SeekFrom::Start(0)).unwrap();
        staged.handle.write_all(b"modified").unwrap();
        staged.handle.sync_all().unwrap();
        assert_eq!(staged.verify_open_handle().unwrap_err().kind(), io::ErrorKind::InvalidData);
        drop(staged);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hardlink_precreation_cannot_redirect_create_new() {
        let dir = scratch();
        let original = dir.join("preexisting.txt");
        fs::write(&original, b"untrusted").unwrap();
        let target = dir.join(policy_blob_filename(45).unwrap());
        fs::hard_link(&original, &target).unwrap();
        assert_eq!(stage_new_policy_blob(&dir, 45, b"policy").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&original).unwrap(), b"untrusted");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn partial_staging_crash_orphan_is_not_reused() {
        let dir = scratch();
        let target = dir.join(policy_blob_filename(43).unwrap());
        fs::write(&target, b"torn").unwrap();
        assert_eq!(stage_new_policy_blob(&dir, 43, b"complete").unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(target).unwrap(), b"torn");
        fs::remove_dir_all(dir).unwrap();
    }
}
