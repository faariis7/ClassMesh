//! Opt-in trusted-Windows policy installation and startup boundary.
//!
//! Default builds do not enable this API. The supported lifecycle is stop,
//! install, restart: a stable exclusive lock is retained for the Service lifetime.
//! Administrators/kernel and whole-disk restoration are outside this threat model.
//! File and Registry commits are ordered, not one atomic transaction. Missing
//! committed data always denies startup. Power-loss qualification remains open.
use crate::{
    nt_relative_directory::{
        create_relative_protected_directory, create_relative_protected_file,
        open_relative_exclusive_file, open_relative_protected_node,
    },
    registry_epoch::RegistryAnchor,
};
use classmesh_security::{
    AuthorizationStore, persistence::DurableAuthorizationState,
    policy_epoch::encode_bound_policy_checkpoint,
};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

const INSTALLED_SCOPE: &str = "ClassMesh-Policy-v2";
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const LOCK_NAME: &str = "authority.lock";

/// Keep alive until every runtime using the extracted policy has stopped/joined.
/// No raw handles, paths or clone operation escape this lease.
#[must_use = "retain the session until its authorization runtime has stopped"]
pub struct TrustedPolicySession {
    authorization: Option<AuthorizationStore>,
    epoch: u64,
    _lock: File,
    _directories: Vec<File>,
}
impl TrustedPolicySession {
    /// Open only the fixed installed namespace, discovered from Windows itself.
    /// Missing/invalid state never creates a lock or consults legacy backups.
    pub fn open_installed() -> io::Result<Self> {
        open_at(INSTALLED_SCOPE)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Transfer the parsed store once, retaining the exclusive lifetime lease.
    pub fn take_authorization(&mut self) -> io::Result<AuthorizationStore> {
        self.authorization.take().ok_or_else(denied)
    }
}

/// Explicit installer operation; creates a NEW installation, never adopts or
/// repairs existing objects. Failures may leave an orphan requiring inspection.
pub fn provision_installed(epoch: u64, bytes: &[u8]) -> io::Result<()> {
    provision_at(INSTALLED_SCOPE, epoch, bytes)
}
/// Service must first stop. Refuse active runtime, stale epoch and existing blob.
/// An error after commit can leave the newer epoch durable but unacknowledged;
/// recovery must reopen the anchor, never retry with the old expected record.
pub fn install_policy(epoch: u64, bytes: &[u8]) -> io::Result<()> {
    install_at(INSTALLED_SCOPE, epoch, bytes)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "trusted policy state rejected",
    )
}
fn validate(epoch: u64, bytes: &[u8]) -> io::Result<[u8; 48]> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(denied());
    }
    let record = encode_bound_policy_checkpoint(epoch, bytes).map_err(|_| denied())?;
    DurableAuthorizationState::parse_bound_primary_from_readers(record.as_slice(), bytes, epoch)
        .map_err(|_| denied())?;
    Ok(record)
}
fn state(directories: &[File]) -> io::Result<&File> {
    directories.last().ok_or_else(denied)
}
fn pin(scope: &str, create: bool) -> io::Result<Vec<File>> {
    // Caller-independent fixed production scope; private tests use unique siblings.
    if scope != INSTALLED_SCOPE && !(cfg!(test) && scope.starts_with("ClassMesh-anchor-probe-")) {
        return Err(denied());
    }
    let mut directories = crate::system_volume::pin_system_program_data()?;
    let app = if create {
        create_relative_protected_directory(state(&directories)?, scope)?
    } else {
        open_relative_protected_node(state(&directories)?, scope, true)?
    };
    let child = if create {
        create_relative_protected_directory(&app, "state")?
    } else {
        open_relative_protected_node(&app, "state", true)?
    };
    directories.push(app);
    directories.push(child);
    Ok(directories)
}
fn stage(parent: &File, epoch: u64, bytes: &[u8], record: &[u8; 48]) -> io::Result<File> {
    let name = classmesh_security::policy_blob_stage::policy_blob_filename(epoch)?;
    let mut file = create_relative_protected_file(parent, &name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    // Exact bounded readback and parsing from the ORIGINAL exclusive writer.
    DurableAuthorizationState::parse_bound_primary_from_readers(
        record.as_slice(),
        Read::by_ref(&mut file).take((MAX_POLICY_BYTES + 1) as u64),
        epoch,
    )
    .map_err(|_| denied())?;
    Ok(file)
}
fn provision_at(scope: &str, epoch: u64, bytes: &[u8]) -> io::Result<()> {
    let record = validate(epoch, bytes)?;
    let directories = pin(scope, true)?;
    let mut lock = create_relative_protected_file(state(&directories)?, LOCK_NAME)?;
    lock.write_all(b"ClassMesh policy authority v2\n")?;
    lock.sync_all()?;
    let _blob = stage(state(&directories)?, epoch, bytes, &record)?;
    // The exclusive original blob and authority handles remain alive through
    // Registry creation, commit, flush and exact readback.
    let _anchor = RegistryAnchor::create(scope, &record)?;
    Ok(())
}
fn install_at(scope: &str, epoch: u64, bytes: &[u8]) -> io::Result<()> {
    let record = validate(epoch, bytes)?;
    let directories = pin(scope, false)?;
    let _lock = open_relative_exclusive_file(state(&directories)?, LOCK_NAME)?;
    let anchor = RegistryAnchor::open(scope)?;
    let previous = anchor.read()?;
    let old_epoch = u64::from_le_bytes(previous[8..16].try_into().expect("validated record"));
    if epoch <= old_epoch {
        return Err(denied());
    }
    let _blob = stage(state(&directories)?, epoch, bytes, &record)?;
    anchor.advance(&previous, &record)
}
pub(crate) fn parse_registry_policy(
    parent: &File,
    anchor: &RegistryAnchor,
) -> io::Result<(u64, AuthorizationStore)> {
    anchor.with_record(|record| {
        let epoch = u64::from_le_bytes(record[8..16].try_into().expect("validated record"));
        let name = classmesh_security::policy_blob_stage::policy_blob_filename(epoch)?;
        let policy = open_relative_protected_node(parent, &name, false)?;
        let authorization = DurableAuthorizationState::parse_bound_primary_from_readers(
            record.as_slice(),
            policy.take((MAX_POLICY_BYTES + 1) as u64),
            epoch,
        )
        .map_err(|_| denied())?;
        Ok((epoch, authorization))
    })
}
fn open_at(scope: &str) -> io::Result<TrustedPolicySession> {
    let directories = pin(scope, false)?;
    let lock = open_relative_exclusive_file(state(&directories)?, LOCK_NAME)?;
    let anchor = RegistryAnchor::open(scope)?;
    let (epoch, authorization) = parse_registry_policy(state(&directories)?, &anchor)?;
    Ok(TrustedPolicySession {
        authorization: Some(authorization),
        epoch,
        _lock: lock,
        _directories: directories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const VALID: &[u8] = br#"{"version":1,"principals":[]}"#;

    #[test]
    fn native_install_orders_blob_before_anchor_and_excludes_active_runtime() {
        let scope = format!("ClassMesh-anchor-probe-install-{}", std::process::id());
        provision_at(&scope, 1, VALID).expect("native protected provision");
        let root = crate::program_data_known_folder::resolve_os_program_data_path()
            .unwrap()
            .join(&scope);
        let state = root.join("state");
        assert!(provision_at(&scope, 1, VALID).is_err());
        let session = open_at(&scope).expect("trusted startup");
        assert_eq!(session.epoch(), 1);
        assert!(
            open_at(&scope).is_err(),
            "one Service/install owner across processes"
        );
        assert!(std::fs::rename(state.join(LOCK_NAME), state.join("renamed.lock")).is_err());
        assert!(std::fs::rename(&state, root.join("renamed-state")).is_err());
        worker(&scope, "compete");
        assert!(install_at(&scope, 2, VALID).is_err());
        assert!(!state.join("policy-0000000000000002.json").exists());
        drop(session);
        let mut session = open_at(&scope).unwrap();
        let _authorization = session.take_authorization().unwrap();
        assert!(session.take_authorization().is_err());
        assert!(
            install_at(&scope, 2, VALID).is_err(),
            "extracting store retains lease"
        );
        assert!(
            std::panic::catch_unwind(move || {
                let _held = session;
                panic!("lease unwind");
            })
            .is_err()
        );
        assert!(install_at(&scope, 2, b"not JSON").is_err());
        assert!(!state.join("policy-0000000000000002.json").exists());
        install_at(&scope, 2, VALID).unwrap();
        assert!(install_at(&scope, 1, VALID).is_err());
        assert!(install_at(&scope, 2, VALID).is_err());
        assert_eq!(open_at(&scope).unwrap().epoch(), 2);
        // A partial orphan from an interrupted stage cannot be adopted or overwritten.
        let orphan = state.join("policy-0000000000000003.json");
        std::fs::write(&orphan, b"torn").unwrap();
        assert!(install_at(&scope, 3, VALID).is_err());
        assert_eq!(std::fs::read(&orphan).unwrap(), b"torn");
        assert_eq!(open_at(&scope).unwrap().epoch(), 2);
        install_at(&scope, 4, VALID).unwrap();
        assert_eq!(open_at(&scope).unwrap().epoch(), 4);
        let current = state.join("policy-0000000000000004.json");
        std::fs::write(&current, [VALID, b" "].concat()).unwrap();
        assert!(
            open_at(&scope).is_err(),
            "same-epoch byte substitution fails"
        );
        std::fs::remove_file(&current).unwrap();
        assert!(open_at(&scope).is_err(), "never recover an older blob");
        {
            let dirs = pin(&scope, false).unwrap();
            let record = validate(4, VALID).unwrap();
            let _restored = stage(super::state(&dirs).unwrap(), 4, VALID, &record).unwrap();
        }
        let lock = state.join(LOCK_NAME);
        let alias = state.join("lock-alias");
        std::fs::hard_link(&lock, &alias).unwrap();
        assert!(open_at(&scope).is_err(), "hardlinked authority rejected");
        std::fs::remove_file(alias).unwrap();
        assert_eq!(open_at(&scope).unwrap().epoch(), 4);
        std::fs::remove_file(lock).unwrap();
        assert!(open_at(&scope).is_err());
        assert!(install_at(&scope, 5, VALID).is_err());
        assert!(
            !state.join(LOCK_NAME).exists(),
            "missing lock is never recreated"
        );
        crate::registry_epoch::remove_fixture(&scope);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn worker(scope: &str, mode: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trusted_policy::tests::native_install_process_worker",
                "--nocapture",
            ])
            .env("CLASSMESH_INSTALL_SCOPE", scope)
            .env("CLASSMESH_INSTALL_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn native_install_recovers_process_crash_without_adopting_orphans() {
        let scope = format!(
            "ClassMesh-anchor-probe-install-crash-{}",
            std::process::id()
        );
        provision_at(&scope, 1, VALID).unwrap();
        worker(&scope, "staged-exit");
        assert_eq!(open_at(&scope).unwrap().epoch(), 1);
        assert!(
            install_at(&scope, 2, VALID).is_err(),
            "staged orphan cannot be adopted"
        );
        worker(&scope, "committed-exit");
        assert_eq!(open_at(&scope).unwrap().epoch(), 3);
        assert!(install_at(&scope, 2, VALID).is_err());
        let root = crate::program_data_known_folder::resolve_os_program_data_path()
            .unwrap()
            .join(&scope);
        crate::registry_epoch::remove_fixture(&scope);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn native_install_process_worker() {
        let Ok(scope) = std::env::var("CLASSMESH_INSTALL_SCOPE") else {
            return;
        };
        assert!(
            [
                "ClassMesh-anchor-probe-install-",
                "ClassMesh-anchor-probe-install-crash-"
            ]
            .iter()
            .any(|prefix| scope
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.parse::<u32>().is_ok())),
            "worker accepts only disposable install fixture names"
        );
        let mode = std::env::var("CLASSMESH_INSTALL_MODE").unwrap();
        match mode.as_str() {
            "compete" => {
                assert!(open_at(&scope).is_err());
                assert!(install_at(&scope, 2, VALID).is_err());
            }
            "staged-exit" => {
                let dirs = pin(&scope, false).unwrap();
                let _lock = open_relative_exclusive_file(state(&dirs).unwrap(), LOCK_NAME).unwrap();
                let record = validate(2, VALID).unwrap();
                let _blob = stage(state(&dirs).unwrap(), 2, VALID, &record).unwrap();
                std::process::exit(0); // No Rust destructors, OS releases all handles.
            }
            "committed-exit" => {
                install_at(&scope, 3, VALID).unwrap();
                std::process::exit(0);
            }
            _ => panic!("unknown private fixture mode"),
        }
    }
}
