//! Read-only CNG public-key binding qualification. This is NOT a trust decision.
use crate::{CngKeyError, CngMachineKey, DurableMachineIdentity, MachineIdentityStateError};
use std::path::Path;

#[derive(Debug)]
pub enum BindingQualificationError {
    Identity(MachineIdentityStateError),
    Cng(CngKeyError),
    PublicKeyMismatch,
}

/// The expected SEC1 uncompressed P-256 public key MUST come from an independently
/// authenticated certificate/provenance verifier. Never derive it from CLI flags
/// or untrusted JSON. This API does not authenticate the supplied expectation.
pub fn qualify_existing_key_binding(
    primary_path: &Path,
    expected_authenticated_sec1: &[u8],
) -> Result<(), BindingQualificationError> {
    let identity = DurableMachineIdentity::new(primary_path)
        .load_primary_only()
        .map_err(BindingQualificationError::Identity)?;
    let key = CngMachineKey::open_existing_non_exportable(identity.cng_key_name)
        .map_err(BindingQualificationError::Cng)?;
    let actual = key.public_key_sec1().map_err(BindingQualificationError::Cng)?;
    if actual.as_slice() != expected_authenticated_sec1 {
        return Err(BindingQualificationError::PublicKeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MachineIdentityBundle;
    use std::fs;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn missing_primary_rejects_even_if_backup_exists() {
        let dir = std::env::temp_dir().join(format!("teacher-binding-{}-{}", process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap();
        let primary = dir.join("machine-identity.json");
        let bundle = MachineIdentityBundle {
            principal_id: [1; 32], cng_key_name: "unprovisioned".into(),
            certificate_chain_der: vec![vec![1]], trust_roots_der: vec![],
            not_after_unix_ms: 1,
        };
        let durable = DurableMachineIdentity::new(&primary);
        durable.save(&bundle).unwrap();
        fs::rename(&primary, dir.join("machine-identity.json.bak")).unwrap();
        assert!(matches!(qualify_existing_key_binding(&primary, &[4; 65]),
            Err(BindingQualificationError::Identity(MachineIdentityStateError::Io(_)))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_key_requires_exact_public_key_binding() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("ClassMesh-binding-test-{}-{nonce}", process::id());
        let key = CngMachineKey::create(name.clone()).unwrap();
        let dir = std::env::temp_dir().join(format!("teacher-binding-key-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        let primary = dir.join("machine-identity.json");
        DurableMachineIdentity::new(&primary).save(&MachineIdentityBundle {
            principal_id: [2; 32], cng_key_name: name,
            certificate_chain_der: vec![vec![1]], trust_roots_der: vec![],
            not_after_unix_ms: 1,
        }).unwrap();
        let actual = key.public_key_sec1().unwrap();
        assert!(qualify_existing_key_binding(&primary, &actual).is_ok());
        let mut wrong = actual;
        wrong[1] ^= 1;
        assert!(matches!(qualify_existing_key_binding(&primary, &wrong),
            Err(BindingQualificationError::PublicKeyMismatch)));
        key.delete().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
