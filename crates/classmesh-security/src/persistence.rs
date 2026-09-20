use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    AuthorizationStore, AuthorizationStoreError, CredentialFingerprint, CredentialRecord,
    CredentialState, Permission, Principal, PrincipalId, PrincipalKind,
};

const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PRINCIPALS: usize = 10_000;
const MAX_CREDENTIALS_PER_PRINCIPAL: usize = 16;
const MAX_PERMISSIONS_PER_PRINCIPAL: usize = 32;

#[derive(Debug)]
pub enum PersistenceError {
    Io(std::io::Error),
    Json(serde_json::Error),
    StateTooLarge {
        bytes: usize,
        maximum: usize,
    },
    UnsupportedVersion(u32),
    TooManyPrincipals(usize),
    TooManyCredentials {
        principal: PrincipalId,
        count: usize,
    },
    TooManyPermissions {
        principal: PrincipalId,
        count: usize,
    },
    DuplicatePrincipal(PrincipalId),
    DuplicateCredential(CredentialFingerprint),
    InvalidPrincipalKind(u8),
    InvalidPermission(u8),
    InvalidCredentialState(u8),
    InvalidCredentialTime(CredentialFingerprint),
    Authorization(AuthorizationStoreError),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "security state I/O failed: {error}"),
            Self::Json(error) => write!(f, "security state JSON failed: {error}"),
            Self::StateTooLarge { bytes, maximum } => {
                write!(f, "security state is {bytes} bytes; maximum is {maximum}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported security state version {version}")
            }
            Self::TooManyPrincipals(count) => {
                write!(f, "security state has too many principals: {count}")
            }
            Self::TooManyCredentials { principal, count } => write!(
                f,
                "principal {:?} has too many persisted credentials: {count}",
                principal
            ),
            Self::TooManyPermissions { principal, count } => write!(
                f,
                "principal {:?} has too many persisted permissions: {count}",
                principal
            ),
            Self::DuplicatePrincipal(principal) => {
                write!(f, "duplicate persisted principal {:?}", principal)
            }
            Self::DuplicateCredential(fingerprint) => {
                write!(f, "duplicate persisted credential {:?}", fingerprint)
            }
            Self::InvalidPrincipalKind(value) => {
                write!(f, "invalid persisted principal kind {value}")
            }
            Self::InvalidPermission(value) => write!(f, "invalid persisted permission {value}"),
            Self::InvalidCredentialState(value) => {
                write!(f, "invalid persisted credential state {value}")
            }
            Self::InvalidCredentialTime(fingerprint) => {
                write!(
                    f,
                    "invalid persisted credential times for {:?}",
                    fingerprint
                )
            }
            Self::Authorization(error) => {
                write!(
                    f,
                    "persisted authorization state violates invariants: {error:?}"
                )
            }
        }
    }
}

impl std::error::Error for PersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PersistenceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PersistenceError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<AuthorizationStoreError> for PersistenceError {
    fn from(value: AuthorizationStoreError) -> Self {
        Self::Authorization(value)
    }
}

#[derive(Debug, Clone)]
pub struct DurableAuthorizationState {
    path: PathBuf,
}

impl DurableAuthorizationState {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<AuthorizationStore>, PersistenceError> {
        let backup = sibling_with_suffix(&self.path, ".bak");
        let source = if self.path.exists() {
            self.path.as_path()
        } else if backup.exists() {
            backup.as_path()
        } else {
            return Ok(None);
        };

        let metadata = fs::metadata(source)?;
        let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if declared > MAX_STATE_BYTES {
            return Err(PersistenceError::StateTooLarge {
                bytes: declared,
                maximum: MAX_STATE_BYTES,
            });
        }

        let file = File::open(source)?;
        let mut bytes = Vec::with_capacity(declared.min(MAX_STATE_BYTES));
        file.take(u64::try_from(MAX_STATE_BYTES + 1).expect("state bound fits u64"))
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(PersistenceError::StateTooLarge {
                bytes: bytes.len(),
                maximum: MAX_STATE_BYTES,
            });
        }

        let persisted: PersistedState = serde_json::from_slice(&bytes)?;
        Ok(Some(persisted.into_store()?))
    }

    pub fn save(&self, store: &AuthorizationStore) -> Result<(), PersistenceError> {
        let persisted = PersistedState::from_store(store);
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(PersistenceError::StateTooLarge {
                bytes: bytes.len(),
                maximum: MAX_STATE_BYTES,
            });
        }

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let temporary = sibling_with_suffix(&self.path, ".tmp");
        let backup = sibling_with_suffix(&self.path, ".bak");
        let _ = fs::remove_file(&temporary);

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);

        let _ = fs::remove_file(&backup);
        if self.path.exists() {
            fs::rename(&self.path, &backup)?;
        }

        if let Err(error) = fs::rename(&temporary, &self.path) {
            if backup.exists() && !self.path.exists() {
                let _ = fs::rename(&backup, &self.path);
            }
            return Err(PersistenceError::Io(error));
        }

        let _ = fs::remove_file(&backup);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    principals: Vec<PersistedPrincipal>,
}

impl PersistedState {
    fn from_store(store: &AuthorizationStore) -> Self {
        let principals = store
            .principals
            .values()
            .map(PersistedPrincipal::from_principal)
            .collect();
        Self {
            version: STATE_VERSION,
            principals,
        }
    }

    fn into_store(self) -> Result<AuthorizationStore, PersistenceError> {
        if self.version != STATE_VERSION {
            return Err(PersistenceError::UnsupportedVersion(self.version));
        }
        if self.principals.len() > MAX_PRINCIPALS {
            return Err(PersistenceError::TooManyPrincipals(self.principals.len()));
        }

        let mut seen = BTreeSet::new();
        let mut store = AuthorizationStore::default();
        for principal in self.principals {
            let id = PrincipalId(principal.id);
            if !seen.insert(id) {
                return Err(PersistenceError::DuplicatePrincipal(id));
            }
            store.upsert(principal.into_principal()?)?;
        }
        Ok(store)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPrincipal {
    id: [u8; 32],
    kind: u8,
    enabled: bool,
    permissions: Vec<u8>,
    credentials: Vec<PersistedCredential>,
}

impl PersistedPrincipal {
    fn from_principal(principal: &Principal) -> Self {
        Self {
            id: principal.id.0,
            kind: principal_kind_to_u8(principal.kind),
            enabled: principal.enabled,
            permissions: principal
                .permissions
                .iter()
                .copied()
                .map(permission_to_u8)
                .collect(),
            credentials: principal
                .credentials
                .values()
                .map(PersistedCredential::from_record)
                .collect(),
        }
    }

    fn into_principal(self) -> Result<Principal, PersistenceError> {
        let principal_id = PrincipalId(self.id);
        if self.permissions.len() > MAX_PERMISSIONS_PER_PRINCIPAL {
            return Err(PersistenceError::TooManyPermissions {
                principal: principal_id,
                count: self.permissions.len(),
            });
        }
        if self.credentials.len() > MAX_CREDENTIALS_PER_PRINCIPAL {
            return Err(PersistenceError::TooManyCredentials {
                principal: principal_id,
                count: self.credentials.len(),
            });
        }

        let mut permissions = BTreeSet::new();
        for permission in self.permissions {
            permissions.insert(permission_from_u8(permission)?);
        }

        let mut credentials = BTreeMap::new();
        for credential in self.credentials {
            let record = credential.into_record()?;
            let fingerprint = record.fingerprint;
            if credentials.insert(fingerprint, record).is_some() {
                return Err(PersistenceError::DuplicateCredential(fingerprint));
            }
        }

        Ok(Principal {
            id: principal_id,
            kind: principal_kind_from_u8(self.kind)?,
            enabled: self.enabled,
            permissions,
            credentials,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedCredential {
    fingerprint: [u8; 32],
    state: u8,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: Option<u64>,
    revoked_at_unix_ms: Option<u64>,
}

impl PersistedCredential {
    fn from_record(record: &CredentialRecord) -> Self {
        Self {
            fingerprint: record.fingerprint.0,
            state: credential_state_to_u8(record.state),
            issued_at_unix_ms: record.issued_at_unix_ms,
            expires_at_unix_ms: record.expires_at_unix_ms,
            revoked_at_unix_ms: record.revoked_at_unix_ms,
        }
    }

    fn into_record(self) -> Result<CredentialRecord, PersistenceError> {
        let fingerprint = CredentialFingerprint(self.fingerprint);
        if self
            .expires_at_unix_ms
            .is_some_and(|expires| expires <= self.issued_at_unix_ms)
            || self
                .revoked_at_unix_ms
                .is_some_and(|revoked| revoked < self.issued_at_unix_ms)
        {
            return Err(PersistenceError::InvalidCredentialTime(fingerprint));
        }

        let state = credential_state_from_u8(self.state)?;
        if (state == CredentialState::Revoked) != self.revoked_at_unix_ms.is_some() {
            return Err(PersistenceError::InvalidCredentialTime(fingerprint));
        }

        Ok(CredentialRecord {
            fingerprint,
            state,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            revoked_at_unix_ms: self.revoked_at_unix_ms,
        })
    }
}

fn principal_kind_to_u8(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Teacher => 1,
        PrincipalKind::StudentDevice => 2,
        PrincipalKind::Administrator => 3,
        PrincipalKind::Service => 4,
        PrincipalKind::SessionWorker => 5,
    }
}

fn principal_kind_from_u8(value: u8) -> Result<PrincipalKind, PersistenceError> {
    match value {
        1 => Ok(PrincipalKind::Teacher),
        2 => Ok(PrincipalKind::StudentDevice),
        3 => Ok(PrincipalKind::Administrator),
        4 => Ok(PrincipalKind::Service),
        5 => Ok(PrincipalKind::SessionWorker),
        _ => Err(PersistenceError::InvalidPrincipalKind(value)),
    }
}

fn permission_to_u8(permission: Permission) -> u8 {
    match permission {
        Permission::ViewMonitoring => 1,
        Permission::ViewInteractive => 2,
        Permission::ControlInput => 3,
        Permission::StartPresentation => 4,
        Permission::ReceivePresentation => 5,
        Permission::SendFile => 6,
        Permission::ReceiveFile => 7,
        Permission::LockDevice => 8,
        Permission::RestartDevice => 9,
        Permission::ShutdownDevice => 10,
        Permission::ManageEnrollment => 11,
        Permission::ManagePolicy => 12,
        Permission::ReadClipboard => 13,
        Permission::WriteClipboard => 14,
    }
}

fn permission_from_u8(value: u8) -> Result<Permission, PersistenceError> {
    match value {
        1 => Ok(Permission::ViewMonitoring),
        2 => Ok(Permission::ViewInteractive),
        3 => Ok(Permission::ControlInput),
        4 => Ok(Permission::StartPresentation),
        5 => Ok(Permission::ReceivePresentation),
        6 => Ok(Permission::SendFile),
        7 => Ok(Permission::ReceiveFile),
        8 => Ok(Permission::LockDevice),
        9 => Ok(Permission::RestartDevice),
        10 => Ok(Permission::ShutdownDevice),
        11 => Ok(Permission::ManageEnrollment),
        12 => Ok(Permission::ManagePolicy),
        13 => Ok(Permission::ReadClipboard),
        14 => Ok(Permission::WriteClipboard),
        _ => Err(PersistenceError::InvalidPermission(value)),
    }
}

fn credential_state_to_u8(state: CredentialState) -> u8 {
    match state {
        CredentialState::Active => 1,
        CredentialState::Retiring => 2,
        CredentialState::Revoked => 3,
    }
}

fn credential_state_from_u8(value: u8) -> Result<CredentialState, PersistenceError> {
    match value {
        1 => Ok(CredentialState::Active),
        2 => Ok(CredentialState::Retiring),
        3 => Ok(CredentialState::Revoked),
        _ => Err(PersistenceError::InvalidCredentialState(value)),
    }
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "authorization-state".into(), |name| name.to_os_string());
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn fingerprint(value: u8) -> CredentialFingerprint {
        CredentialFingerprint([value; 32])
    }

    fn test_store() -> AuthorizationStore {
        let old = fingerprint(10);
        let new = fingerprint(11);
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::ViewMonitoring);
        permissions.insert(Permission::ControlInput);

        let mut credentials = BTreeMap::new();
        let mut old_record = CredentialRecord::active(old, 10);
        old_record.state = CredentialState::Retiring;
        old_record.expires_at_unix_ms = Some(40);
        credentials.insert(old, old_record);
        credentials.insert(new, CredentialRecord::active(new, 20));

        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: id(7),
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions,
                credentials,
            })
            .expect("test principal should register");
        store
    }

    fn test_path() -> PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "classmesh-security-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test directory");
        directory.join("authorization.json")
    }

    #[test]
    fn durable_state_round_trips_authorization_and_rotation() {
        let path = test_path();
        let durable = DurableAuthorizationState::new(&path);
        let store = test_store();

        durable.save(&store).expect("state should save");
        let loaded = durable
            .load()
            .expect("state should load")
            .expect("state should exist");

        assert_eq!(
            loaded.principal_for_credential(fingerprint(10), 39),
            Some(id(7))
        );
        assert_eq!(loaded.principal_for_credential(fingerprint(10), 40), None);
        assert!(loaded.authorize_credential(fingerprint(11), Permission::ControlInput, 40));

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn load_recovers_backup_if_commit_was_interrupted() {
        let path = test_path();
        let durable = DurableAuthorizationState::new(&path);
        durable.save(&test_store()).expect("state should save");

        let backup = sibling_with_suffix(&path, ".bak");
        fs::rename(&path, &backup).expect("simulate interrupted replace");

        let loaded = durable
            .load()
            .expect("backup should load")
            .expect("backup should exist");
        assert_eq!(
            loaded.principal_for_credential(fingerprint(11), 30),
            Some(id(7))
        );

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn corrupted_or_oversized_state_fails_closed() {
        let path = test_path();
        fs::write(&path, br#"{"version":999,"principals":[]}"#).expect("write state");
        let durable = DurableAuthorizationState::new(&path);
        assert!(matches!(
            durable.load(),
            Err(PersistenceError::UnsupportedVersion(999))
        ));

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }
}
