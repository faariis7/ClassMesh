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
    AuthorizationStore, CredentialFingerprint, PrincipalId, persistence::DurableAuthorizationState,
    policy_epoch::encode_bound_policy_checkpoint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

const INSTALLED_SCOPE: &str = "ClassMesh-Policy-v2";
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const LOCK_NAME: &str = "authority.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedControlConfig {
    pub bind_address: SocketAddr,
    pub multicast_interface: Option<Ipv4Addr>,
}

#[derive(Deserialize, Serialize)]
struct PersistedControlConfig {
    version: u32,
    bind_address: String,
    multicast_interface: Option<String>,
}

/// The single bounded v1 parser used before protected provisioning and after
/// trusted HANDLE acquisition. The caller must establish the reader's origin.
pub fn parse_control_config(reader: impl Read) -> io::Result<TrustedControlConfig> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(denied());
    }
    let persisted: PersistedControlConfig = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if persisted.version != 1 {
        return Err(denied());
    }
    let bind_address = persisted
        .bind_address
        .parse::<SocketAddr>()
        .map_err(|_| denied())?;
    if bind_address.port() == 0 {
        return Err(denied());
    }
    let multicast_interface = persisted
        .multicast_interface
        .map(|value| value.parse::<Ipv4Addr>().map_err(|_| denied()))
        .transpose()?;
    Ok(TrustedControlConfig {
        bind_address,
        multicast_interface,
    })
}

fn encode_control_config(config: TrustedControlConfig) -> io::Result<Vec<u8>> {
    let persisted = PersistedControlConfig {
        version: 1,
        bind_address: config.bind_address.to_string(),
        multicast_interface: config.multicast_interface.map(|value| value.to_string()),
    };
    let bytes = serde_json::to_vec(&persisted)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(denied());
    }
    Ok(bytes)
}

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
    /// Read the fixed primary machine identity in the existing protected
    /// ClassMesh/state tree. The opaque reader and all ancestors remain pinned
    /// through parsing; a missing primary never consults its backup.
    pub fn read_machine_identity<T>(
        &self,
        parse: impl FnOnce(&mut dyn Read) -> T,
    ) -> io::Result<T> {
        let index = self._directories.len().checked_sub(3).ok_or_else(denied)?;
        let program_data = self._directories.get(index).ok_or_else(denied)?;
        read_trusted_primary(
            program_data,
            "ClassMesh",
            "state",
            "machine-identity.json",
            MAX_IDENTITY_BYTES as u64,
            parse,
        )
    }
    /// Read only the fixed protected ClassMesh/config primary through the same
    /// trusted ProgramData HANDLE. No environment path or backup fallback.
    pub fn read_control_config<T>(&self, parse: impl FnOnce(&mut dyn Read) -> T) -> io::Result<T> {
        let index = self._directories.len().checked_sub(3).ok_or_else(denied)?;
        let program_data = self._directories.get(index).ok_or_else(denied)?;
        read_trusted_primary(
            program_data,
            "ClassMesh",
            "config",
            "control-runtime.json",
            MAX_CONFIG_BYTES as u64,
            parse,
        )
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
/// Fresh-install-only identity/config seed under fixed protected `ClassMesh`.
/// It refuses an existing root and never migrates or adopts legacy state.
/// A crash may leave a partial root that must be inspected before retrying.
pub fn provision_startup_inputs(identity: &[u8], config: &[u8]) -> io::Result<()> {
    provision_inputs_at("ClassMesh", identity, config)
}
/// Provision all required inputs of a fresh opt-in Service installation. No
/// filesystem or Registry creation occurs before the candidate policy, machine
/// credential, non-exportable CNG key and config agree. A crash after the first
/// create can leave an orphan; startup remains fail-closed and never repairs it.
pub fn provision_fresh_install(
    epoch: u64,
    policy: &[u8],
    identity: &[u8],
    config: &[u8],
) -> io::Result<()> {
    provision_fresh_at(
        INSTALLED_SCOPE,
        "ClassMesh",
        epoch,
        policy,
        identity,
        config,
    )
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
fn startup_scope_allowed(scope: &str) -> bool {
    scope == "ClassMesh"
        || (cfg!(test)
            && scope
                .strip_prefix("ClassMesh-anchor-probe-provision-")
                .is_some_and(|suffix| suffix.parse::<u32>().is_ok()))
}

fn stage_startup_input(
    parent: &File,
    leaf: &str,
    bytes: &[u8],
    maximum: usize,
) -> io::Result<File> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(denied());
    }
    let mut file = create_relative_protected_file(parent, leaf)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let mut readback = Vec::new();
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut readback)?;
    if readback != bytes {
        return Err(denied());
    }
    Ok(file)
}

fn provision_inputs_at(scope: &str, identity: &[u8], config: &[u8]) -> io::Result<()> {
    if !startup_scope_allowed(scope) {
        return Err(denied());
    }
    let identity_bundle =
        classmesh_identity_win::DurableMachineIdentity::parse_from_reader(identity)
            .map_err(|_| denied())?;
    let identity_bytes =
        classmesh_identity_win::DurableMachineIdentity::encode_canonical(&identity_bundle)
            .map_err(|_| denied())?;
    let config_bytes = encode_control_config(parse_control_config(config)?)?;
    // All validation precedes any filesystem side effect. Every creation is
    // relative to its retained OS-rooted parent and refuses preexisting state.
    let roots = crate::system_volume::pin_system_program_data()?;
    let program_data = roots.last().ok_or_else(denied)?;
    let app = create_relative_protected_directory(program_data, scope)?;
    let state = create_relative_protected_directory(&app, "state")?;
    let config_dir = create_relative_protected_directory(&app, "config")?;
    let _identity = stage_startup_input(
        &state,
        "machine-identity.json",
        &identity_bytes,
        MAX_IDENTITY_BYTES,
    )?;
    let _config = stage_startup_input(
        &config_dir,
        "control-runtime.json",
        &config_bytes,
        MAX_CONFIG_BYTES,
    )?;
    Ok(())
}
fn preflight_fresh_install(
    epoch: u64,
    policy: &[u8],
    identity: &[u8],
    config: &[u8],
) -> io::Result<()> {
    let record = validate(epoch, policy)?;
    let authorization = DurableAuthorizationState::parse_bound_primary_from_readers(
        record.as_slice(),
        policy,
        epoch,
    )
    .map_err(|_| denied())?;
    let identity = classmesh_identity_win::DurableMachineIdentity::parse_from_reader(identity)
        .map_err(|_| denied())?;
    parse_control_config(config)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| denied())?;
    let now_ms = u64::try_from(now.as_millis()).map_err(|_| denied())?;
    if identity.not_after_unix_ms <= now_ms {
        return Err(denied());
    }
    let leaf = identity.certificate_chain_der.first().ok_or_else(denied)?;
    let fingerprint = CredentialFingerprint(Sha256::digest(leaf).into());
    if authorization.principal_for_credential(fingerprint, now_ms)
        != Some(PrincipalId(identity.principal_id))
    {
        return Err(denied());
    }
    let key =
        classmesh_identity_win::CngMachineKey::open(identity.cng_key_name).map_err(|_| denied())?;
    if key.export_policy().map_err(|_| denied())? != 0 {
        return Err(denied());
    }
    let chain = identity
        .certificate_chain_der
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    classmesh_identity_win::cng_server_cert_resolver(chain, key).map_err(|_| denied())?;
    Ok(())
}
fn provision_fresh_at(
    policy_scope: &str,
    startup_scope: &str,
    epoch: u64,
    policy: &[u8],
    identity: &[u8],
    config: &[u8],
) -> io::Result<()> {
    if (policy_scope != INSTALLED_SCOPE && !cfg!(test)) || !startup_scope_allowed(startup_scope) {
        return Err(denied());
    }
    preflight_fresh_install(epoch, policy, identity, config)?;
    // Startup inputs precede the policy commit. The latter is the activation
    // boundary, and any partial prior step leaves only an inert orphan.
    provision_inputs_at(startup_scope, identity, config)?;
    provision_at(policy_scope, epoch, policy)
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
fn read_trusted_primary<T>(
    program_data: &File,
    scope: &str,
    directory: &str,
    leaf: &str,
    maximum: u64,
    parse: impl FnOnce(&mut dyn Read) -> T,
) -> io::Result<T> {
    let fixture = [
        "ClassMesh-anchor-probe-identity-",
        "ClassMesh-anchor-probe-provision-",
    ]
    .into_iter()
    .any(|prefix| {
        scope
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.parse::<u32>().is_ok())
    });
    if scope != "ClassMesh" && !(cfg!(test) && fixture) {
        return Err(denied());
    }
    let app = open_relative_protected_node(program_data, scope, true)?;
    let child = open_relative_protected_node(&app, directory, true)?;
    let primary = open_relative_protected_node(&child, leaf, false)?;
    let mut bounded = primary.take(maximum + 1);
    Ok(parse(&mut bounded))
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
    #[test]
    fn rooted_identity_keeps_handles_through_canonical_parser_and_has_no_backup_fallback() {
        let scope = format!("ClassMesh-anchor-probe-identity-{}", std::process::id());
        provision_at(&scope, 1, VALID).unwrap();
        let dirs = pin(&scope, false).unwrap();
        let roots = crate::system_volume::pin_system_program_data().unwrap();
        let parent = roots.last().unwrap();
        let state_handle = super::state(&dirs).unwrap();
        let bytes = format!(r#"{{"version":1,"principal_id":[{}],"cng_key_name":"ClassMesh-test","certificate_chain_der":[[48,1,0]],"trust_roots_der":[[48,1,1]],"not_after_unix_ms":999999}}"#, ["7"; 32].join(",")).into_bytes();
        let root = crate::program_data_known_folder::resolve_os_program_data_path()
            .unwrap()
            .join(&scope);
        let identity = root.join("state").join("machine-identity.json");
        let mut original =
            create_relative_protected_file(state_handle, "machine-identity.json").unwrap();
        original.write_all(&bytes).unwrap();
        original.sync_all().unwrap();
        drop(original);
        let app = &dirs[dirs.len() - 2];
        let config_directory = create_relative_protected_directory(app, "config").unwrap();
        let config_bytes =
            br#"{"version":1,"bind_address":"127.0.0.1:52000","multicast_interface":null}"#;
        let mut config_file =
            create_relative_protected_file(&config_directory, "control-runtime.json").unwrap();
        config_file.write_all(config_bytes).unwrap();
        config_file.sync_all().unwrap();
        drop(config_file);
        drop(config_directory);
        drop(dirs);
        let config_read = read_trusted_primary(
            parent,
            &scope,
            "config",
            "control-runtime.json",
            64 * 1024,
            |reader| {
                let config_path = root.join("config").join("control-runtime.json");
                assert!(std::fs::write(config_path, b"replacement").is_err());
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                bytes
            },
        )
        .unwrap();
        assert_eq!(config_read, config_bytes);
        let parsed = read_trusted_primary(
            parent,
            &scope,
            "state",
            "machine-identity.json",
            1024 * 1024,
            |reader| {
                assert!(std::fs::write(&identity, b"changed roots").is_err());
                assert!(std::fs::rename(&identity, identity.with_extension("moved")).is_err());
                classmesh_identity_win::DurableMachineIdentity::parse_from_reader(reader)
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.principal_id, [7; 32]);
        assert_eq!(parsed.trust_roots_der, vec![vec![48, 1, 1]]);
        std::fs::write(&identity, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(
            read_trusted_primary(
                parent,
                &scope,
                "state",
                "machine-identity.json",
                1024 * 1024,
                |reader| {
                    classmesh_identity_win::DurableMachineIdentity::parse_from_reader(reader)
                }
            )
            .unwrap()
            .is_err()
        );
        std::fs::write(&identity, &bytes).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                let _ = read_trusted_primary(
                    parent,
                    &scope,
                    "state",
                    "machine-identity.json",
                    1024 * 1024,
                    |_| panic!("identity read unwind"),
                );
            })
            .is_err()
        );
        let config_path = root.join("config").join("control-runtime.json");
        std::fs::write(&config_path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert_eq!(
            read_trusted_primary(
                parent,
                &scope,
                "config",
                "control-runtime.json",
                64 * 1024,
                |reader| {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).unwrap();
                    bytes.len()
                }
            )
            .unwrap(),
            64 * 1024 + 1
        );
        std::fs::remove_file(&config_path).unwrap();
        assert!(
            read_trusted_primary(
                parent,
                &scope,
                "config",
                "control-runtime.json",
                64 * 1024,
                |_| ()
            )
            .is_err()
        );
        let backup = identity.with_extension("json.bak");
        std::fs::rename(&identity, &backup).unwrap();
        assert!(
            read_trusted_primary(
                parent,
                &scope,
                "state",
                "machine-identity.json",
                1024 * 1024,
                |_| ()
            )
            .is_err(),
            "trusted identity never uses .bak"
        );
        std::fs::rename(&backup, &identity).unwrap();
        let alias = identity.with_extension("hardlink");
        std::fs::hard_link(&identity, &alias).unwrap();
        assert!(
            read_trusted_primary(
                parent,
                &scope,
                "state",
                "machine-identity.json",
                1024 * 1024,
                |_| ()
            )
            .is_err()
        );
        drop(roots);
        crate::registry_epoch::remove_fixture(&scope);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protected_startup_provision_validates_before_create_and_never_adopts_existing_root() {
        let scope = format!("ClassMesh-anchor-probe-provision-{}", std::process::id());
        let root = crate::program_data_known_folder::resolve_os_program_data_path()
            .unwrap()
            .join(&scope);
        let identity = format!(r#"{{"version":1,"principal_id":[{}],"cng_key_name":"ClassMesh-test","certificate_chain_der":[[48,1,0]],"trust_roots_der":[[48,1,1]],"not_after_unix_ms":999999,"private_key":"MUST_NOT_STORE"}}"#, ["7"; 32].join(",")).into_bytes();
        let config = br#"{"version":1,"bind_address":"127.0.0.1:52000","multicast_interface":null,"unrecognized_secret":"MUST_NOT_STORE"}"#;
        assert!(provision_inputs_at(&scope, b"invalid identity", config).is_err());
        assert!(
            !root.exists(),
            "invalid identity has no filesystem side effect"
        );
        assert!(provision_inputs_at(&scope, &identity, b"invalid config").is_err());
        assert!(
            !root.exists(),
            "invalid config has no filesystem side effect"
        );
        provision_inputs_at(&scope, &identity, config).unwrap();
        assert!(provision_inputs_at(&scope, &identity, config).is_err());
        assert!(
            !String::from_utf8_lossy(
                &std::fs::read(root.join("state").join("machine-identity.json")).unwrap()
            )
            .contains("MUST_NOT_STORE"),
            "a tolerated extra input field must not become persisted key material"
        );
        assert!(
            !String::from_utf8_lossy(
                &std::fs::read(root.join("config").join("control-runtime.json")).unwrap()
            )
            .contains("MUST_NOT_STORE")
        );
        let roots = crate::system_volume::pin_system_program_data().unwrap();
        let parent = roots.last().unwrap();
        let decoded = read_trusted_primary(
            parent,
            &scope,
            "state",
            "machine-identity.json",
            1024 * 1024,
            |reader| classmesh_identity_win::DurableMachineIdentity::parse_from_reader(reader),
        )
        .unwrap()
        .unwrap();
        assert_eq!(decoded.principal_id, [7; 32]);
        let installed_config = read_trusted_primary(
            parent,
            &scope,
            "config",
            "control-runtime.json",
            64 * 1024,
            |reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                bytes
            },
        )
        .unwrap();
        assert_eq!(
            parse_control_config(installed_config.as_slice()).unwrap(),
            parse_control_config(config.as_slice()).unwrap()
        );
        drop(roots);
        std::fs::remove_dir_all(&root).unwrap();

        // A process exit after creating only the protected root is an orphan,
        // not a reason to adopt or silently repair it on a later call.
        let roots = crate::system_volume::pin_system_program_data().unwrap();
        let partial = create_relative_protected_directory(roots.last().unwrap(), &scope).unwrap();
        drop(partial);
        drop(roots);
        assert!(provision_inputs_at(&scope, &identity, config).is_err());
        assert!(!root.join("state").exists());
        assert!(!root.join("config").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fresh_install_preflight_rejects_invalid_inputs_without_creating_either_scope() {
        let suffix = std::process::id().wrapping_add(1_000_000);
        let policy_scope = format!("ClassMesh-anchor-probe-fresh-{suffix}");
        let startup_scope = format!("ClassMesh-anchor-probe-provision-{suffix}");
        let program_data =
            crate::program_data_known_folder::resolve_os_program_data_path().unwrap();
        let policy_root = program_data.join(&policy_scope);
        let startup_root = program_data.join(&startup_scope);
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                br#"{"version":1,"principals":[]}"#,
                b"invalid identity",
                br#"{"version":1,"bind_address":"127.0.0.1:5151","multicast_interface":null}"#,
            )
            .is_err()
        );
        assert!(!policy_root.exists());
        assert!(!startup_root.exists());
    }

    #[test]
    fn fresh_install_binds_policy_identity_key_and_config_before_commit() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyUsagePurpose,
        };
        struct KeyCleanup(String);
        impl Drop for KeyCleanup {
            fn drop(&mut self) {
                if let Ok(key) = classmesh_identity_win::CngMachineKey::open(self.0.clone()) {
                    let _ = key.delete();
                }
            }
        }
        let suffix = std::process::id().wrapping_add(2_000_000);
        let policy_scope = format!("ClassMesh-anchor-probe-fresh-valid-{suffix}");
        let startup_scope = format!("ClassMesh-anchor-probe-provision-{suffix}");
        let program_data =
            crate::program_data_known_folder::resolve_os_program_data_path().unwrap();
        let policy_root = program_data.join(&policy_scope);
        let startup_root = program_data.join(&startup_scope);
        let key_name = format!("ClassMesh-fresh-test-{suffix}");
        let _cleanup = KeyCleanup(key_name.clone());
        let key = classmesh_identity_win::CngMachineKey::create(key_name.clone()).unwrap();
        let adapter = classmesh_identity_win::CngRcgenSigningKey::new(key).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.serial_number = Some(1_u64.into());
        params
            .distinguished_name
            .push(DnType::CommonName, "ClassMesh Fresh Install Test");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let leaf = CertifiedIssuer::self_signed(params, adapter)
            .unwrap()
            .der()
            .to_vec();
        let fingerprint: [u8; 32] = Sha256::digest(&leaf).into();
        let principal = [7_u8; 32];
        let policy = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "principals": [{"id": principal, "kind": 4, "enabled": true,
                "permissions": [], "credentials": [{"fingerprint": fingerprint,
                    "state": 1, "issued_at_unix_ms": 0,
                    "expires_at_unix_ms": null, "revoked_at_unix_ms": null}]}]
        }))
        .unwrap();
        let identity = serde_json::to_vec(&serde_json::json!({
            "version": 1, "principal_id": principal, "cng_key_name": key_name,
            "certificate_chain_der": [leaf], "trust_roots_der": [],
            "not_after_unix_ms": u64::MAX
        }))
        .unwrap();
        let config = br#"{"version":1,"bind_address":"127.0.0.1:5151","multicast_interface":null}"#;
        let mut wrong_policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        wrong_policy["principals"][0]["enabled"] = false.into();
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                &serde_json::to_vec(&wrong_policy).unwrap(),
                &identity,
                config
            )
            .is_err()
        );
        let mut wrong_identity: serde_json::Value = serde_json::from_slice(&identity).unwrap();
        wrong_identity["cng_key_name"] = "ClassMesh-missing-key".into();
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                &policy,
                &serde_json::to_vec(&wrong_identity).unwrap(),
                config
            )
            .is_err()
        );
        let other_key_name = format!("ClassMesh-fresh-other-test-{suffix}");
        let _other_cleanup = KeyCleanup(other_key_name.clone());
        classmesh_identity_win::CngMachineKey::create(other_key_name.clone()).unwrap();
        wrong_identity["cng_key_name"] = other_key_name.into();
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                &policy,
                &serde_json::to_vec(&wrong_identity).unwrap(),
                config
            )
            .is_err(),
            "existing CNG key with a different public key must fail preflight"
        );
        wrong_identity["cng_key_name"] = key_name.into();
        wrong_identity["not_after_unix_ms"] = 1.into();
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                &policy,
                &serde_json::to_vec(&wrong_identity).unwrap(),
                config
            )
            .is_err()
        );
        assert!(
            provision_fresh_at(
                &policy_scope,
                &startup_scope,
                1,
                &policy,
                &identity,
                b"bad config"
            )
            .is_err()
        );
        assert!(!policy_root.exists());
        assert!(!startup_root.exists());
        provision_fresh_at(&policy_scope, &startup_scope, 1, &policy, &identity, config).unwrap();
        assert!(policy_root.exists());
        assert!(startup_root.join("state/machine-identity.json").exists());
        assert_eq!(open_at(&policy_scope).unwrap().epoch(), 1);
        assert!(
            provision_fresh_at(&policy_scope, &startup_scope, 1, &policy, &identity, config)
                .is_err()
        );
        crate::registry_epoch::remove_fixture(&policy_scope);
        std::fs::remove_dir_all(policy_root).unwrap();
        std::fs::remove_dir_all(startup_root).unwrap();
    }
}
