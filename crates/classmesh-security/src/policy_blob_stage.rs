//! Experimental create-only blob staging; NOT a trusted Windows store.

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
        for (epoch, data) in [(0, b"valid".as_slice()), (3, b"".as_slice()), (3, &vec![0; 4 * 1024 * 1024 + 1])] {
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
    fn partial_staging_crash_orphan_is_not_reused() {
        let dir = scratch();
        let target = dir.join(policy_blob_filename(43).unwrap());
        fs::write(&target, b"torn").unwrap();
        assert_eq!(stage_new_policy_blob(&dir, 43, b"complete").unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(target).unwrap(), b"torn");
        fs::remove_dir_all(dir).unwrap();
    }
}
