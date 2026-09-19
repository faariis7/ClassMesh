use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const MAX_KEY_NAME_BYTES: usize = 512;
const MAX_CERTIFICATE_CHAIN_ENTRIES: usize = 8;
const MAX_TRUST_ROOTS: usize = 16;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_SET_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentityBundle {
    pub principal_id: [u8; 32],
    pub cng_key_name: String,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub trust_roots_der: Vec<Vec<u8>>,
    pub not_after_unix_ms: u64,
}

#[derive(Debug)]
pub enum MachineIdentityStateError {
    Io(std::io::Error),
    Json(serde_json::Error),
    UnsupportedVersion(u32),
    StateTooLarge { bytes: usize, maximum: usize },
    EmptyKeyName,
    KeyNameTooLong { bytes: usize, maximum: usize },
    InvalidKeyName,
    EmptyCertificateChain,
    MissingExpiry,
    TooManyCertificates { count: usize, maximum: usize },
    TooManyTrustRoots { count: usize, maximum: usize },
    CertificateTooLarge { bytes: usize, maximum: usize },
    CertificateSetTooLarge { bytes: usize, maximum: usize },
}

impl std::fmt::Display for MachineIdentityStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "machine identity state I/O failed: {error}"),
            Self::Json(error) => write!(f, "machine identity state JSON failed: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported machine identity state version {version}")
            }
            Self::StateTooLarge { bytes, maximum } => {
                write!(
                    f,
                    "machine identity state is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::EmptyKeyName => write!(f, "CNG machine key name must not be empty"),
            Self::KeyNameTooLong { bytes, maximum } => {
                write!(
                    f,
                    "CNG machine key name is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidKeyName => write!(f, "CNG machine key name contains a NUL"),
            Self::EmptyCertificateChain => write!(f, "machine certificate chain must not be empty"),
            Self::MissingExpiry => write!(f, "machine certificate expiry must be non-zero"),
            Self::TooManyCertificates { count, maximum } => {
                write!(
                    f,
                    "machine certificate chain has {count} entries; maximum is {maximum}"
                )
            }
            Self::TooManyTrustRoots { count, maximum } => {
                write!(
                    f,
                    "machine trust store has {count} roots; maximum is {maximum}"
                )
            }
            Self::CertificateTooLarge { bytes, maximum } => {
                write!(f, "certificate is {bytes} bytes; maximum is {maximum}")
            }
            Self::CertificateSetTooLarge { bytes, maximum } => {
                write!(
                    f,
                    "certificate material is {bytes} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for MachineIdentityStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for MachineIdentityStateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for MachineIdentityStateError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone)]
pub struct DurableMachineIdentity {
    path: PathBuf,
}

impl DurableMachineIdentity {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<MachineIdentityBundle>, MachineIdentityStateError> {
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
            return Err(MachineIdentityStateError::StateTooLarge {
                bytes: declared,
                maximum: MAX_STATE_BYTES,
            });
        }

        let file = File::open(source)?;
        let mut bytes = Vec::with_capacity(declared.min(MAX_STATE_BYTES));
        file.take(u64::try_from(MAX_STATE_BYTES + 1).expect("state bound fits u64"))
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(MachineIdentityStateError::StateTooLarge {
                bytes: bytes.len(),
                maximum: MAX_STATE_BYTES,
            });
        }

        PersistedMachineIdentity::decode(&bytes)
    }

    pub fn save(&self, bundle: &MachineIdentityBundle) -> Result<(), MachineIdentityStateError> {
        validate_bundle(bundle)?;
        let persisted = PersistedMachineIdentity::from_bundle(bundle);
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(MachineIdentityStateError::StateTooLarge {
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
            return Err(MachineIdentityStateError::Io(error));
        }
        let _ = fs::remove_file(&backup);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedMachineIdentity {
    version: u32,
    principal_id: [u8; 32],
    cng_key_name: String,
    certificate_chain_der: Vec<Vec<u8>>,
    trust_roots_der: Vec<Vec<u8>>,
    not_after_unix_ms: u64,
}

impl PersistedMachineIdentity {
    fn from_bundle(bundle: &MachineIdentityBundle) -> Self {
        Self {
            version: STATE_VERSION,
            principal_id: bundle.principal_id,
            cng_key_name: bundle.cng_key_name.clone(),
            certificate_chain_der: bundle.certificate_chain_der.clone(),
            trust_roots_der: bundle.trust_roots_der.clone(),
            not_after_unix_ms: bundle.not_after_unix_ms,
        }
    }

    fn decode(bytes: &[u8]) -> Result<Option<MachineIdentityBundle>, MachineIdentityStateError> {
        let persisted: Self = serde_json::from_slice(bytes)?;
        if persisted.version != STATE_VERSION {
            return Err(MachineIdentityStateError::UnsupportedVersion(
                persisted.version,
            ));
        }
        let bundle = MachineIdentityBundle {
            principal_id: persisted.principal_id,
            cng_key_name: persisted.cng_key_name,
            certificate_chain_der: persisted.certificate_chain_der,
            trust_roots_der: persisted.trust_roots_der,
            not_after_unix_ms: persisted.not_after_unix_ms,
        };
        validate_bundle(&bundle)?;
        Ok(Some(bundle))
    }
}

fn validate_bundle(bundle: &MachineIdentityBundle) -> Result<(), MachineIdentityStateError> {
    if bundle.cng_key_name.is_empty() {
        return Err(MachineIdentityStateError::EmptyKeyName);
    }
    if bundle.cng_key_name.len() > MAX_KEY_NAME_BYTES {
        return Err(MachineIdentityStateError::KeyNameTooLong {
            bytes: bundle.cng_key_name.len(),
            maximum: MAX_KEY_NAME_BYTES,
        });
    }
    if bundle.cng_key_name.encode_utf16().any(|unit| unit == 0) {
        return Err(MachineIdentityStateError::InvalidKeyName);
    }
    if bundle.certificate_chain_der.is_empty() {
        return Err(MachineIdentityStateError::EmptyCertificateChain);
    }
    if bundle.not_after_unix_ms == 0 {
        return Err(MachineIdentityStateError::MissingExpiry);
    }
    if bundle.certificate_chain_der.len() > MAX_CERTIFICATE_CHAIN_ENTRIES {
        return Err(MachineIdentityStateError::TooManyCertificates {
            count: bundle.certificate_chain_der.len(),
            maximum: MAX_CERTIFICATE_CHAIN_ENTRIES,
        });
    }
    if bundle.trust_roots_der.len() > MAX_TRUST_ROOTS {
        return Err(MachineIdentityStateError::TooManyTrustRoots {
            count: bundle.trust_roots_der.len(),
            maximum: MAX_TRUST_ROOTS,
        });
    }

    let mut total = 0usize;
    for certificate in bundle
        .certificate_chain_der
        .iter()
        .chain(bundle.trust_roots_der.iter())
    {
        if certificate.len() > MAX_CERTIFICATE_DER_BYTES {
            return Err(MachineIdentityStateError::CertificateTooLarge {
                bytes: certificate.len(),
                maximum: MAX_CERTIFICATE_DER_BYTES,
            });
        }
        total = total.saturating_add(certificate.len());
        if total > MAX_CERTIFICATE_SET_BYTES {
            return Err(MachineIdentityStateError::CertificateSetTooLarge {
                bytes: total,
                maximum: MAX_CERTIFICATE_SET_BYTES,
            });
        }
    }
    Ok(())
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "machine-identity".into(), |name| name.to_os_string());
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn bundle() -> MachineIdentityBundle {
        MachineIdentityBundle {
            principal_id: [7; 32],
            cng_key_name: "ClassMesh-Machine-7".to_owned(),
            certificate_chain_der: vec![vec![0x30, 0x01, 0x00]],
            trust_roots_der: vec![vec![0x30, 0x01, 0x01]],
            not_after_unix_ms: 999_999,
        }
    }

    fn test_path() -> PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "classmesh-machine-identity-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test directory");
        directory.join("identity.json")
    }

    #[test]
    fn durable_machine_identity_round_trips_without_private_key_material() {
        let path = test_path();
        let durable = DurableMachineIdentity::new(&path);
        let expected = bundle();

        durable.save(&expected).expect("identity should save");
        let loaded = durable
            .load()
            .expect("identity should load")
            .expect("identity should exist");
        assert_eq!(loaded, expected);

        let serialized = fs::read_to_string(&path).expect("state file");
        assert!(serialized.contains("ClassMesh-Machine-7"));
        assert!(!serialized.contains("private_key"));
        assert!(!serialized.contains("pkcs8"));

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn invalid_or_unbounded_material_fails_closed() {
        let mut invalid = bundle();
        invalid.cng_key_name.clear();
        assert!(matches!(
            validate_bundle(&invalid),
            Err(MachineIdentityStateError::EmptyKeyName)
        ));

        let mut oversized = bundle();
        oversized.certificate_chain_der = vec![vec![0; MAX_CERTIFICATE_DER_BYTES + 1]];
        assert!(matches!(
            validate_bundle(&oversized),
            Err(MachineIdentityStateError::CertificateTooLarge { .. })
        ));
    }

    #[test]
    fn backup_is_loaded_when_primary_is_absent_after_interrupted_replace() {
        let path = test_path();
        let durable = DurableMachineIdentity::new(&path);
        durable.save(&bundle()).expect("identity should save");

        let backup = sibling_with_suffix(&path, ".bak");
        fs::rename(&path, &backup).expect("simulate interrupted replace");
        assert_eq!(durable.load().expect("backup should load"), Some(bundle()));

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }
}
