//! Read-only, non-authoritative Teacher enrollment diagnostics.
//! Run: cargo run -p classmesh-identity-win --example teacher_identity_readiness
//! This never enables Teacher startup, provisions CNG keys, or validates a CA/roster.
use classmesh_identity_win::{DurableMachineIdentity, MachineIdentityBundle};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
enum Finding {
    MissingPrimary,
    UnreadablePrimary,
    Expired,
    MissingTrustRoots,
    UnverifiedProvenance,
}

fn inspect_loaded(bundle: &MachineIdentityBundle, now_ms: u64) -> Finding {
    if bundle.not_after_unix_ms <= now_ms {
        Finding::Expired
    } else if bundle.trust_roots_der.is_empty() {
        Finding::MissingTrustRoots
    } else {
        // Embedded roots and certificates are NOT proof of authorized enrollment.
        Finding::UnverifiedProvenance
    }
}

fn inspect_primary(path: &std::path::Path, now_ms: u64) -> Finding {
    match DurableMachineIdentity::new(path).load_primary_only() {
        Ok(bundle) => inspect_loaded(&bundle, now_ms),
        Err(classmesh_identity_win::MachineIdentityStateError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Finding::MissingPrimary
        }
        Err(_) => Finding::UnreadablePrimary,
    }
}

fn main() {
    let path = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("ClassMesh")
        .join("state")
        .join("machine-identity.json");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64;
    let finding = inspect_primary(&path, now_ms);
    println!("Teacher protected startup: BLOCKED (diagnostic only)");
    println!("Primary identity diagnostic: {finding:?}");
    println!(
        "Not verified: source provenance, approved CA, CNG key binding, signed StudentDevice roster, Teacher permission, trusted session/peer."
    );
    // Exit code intentionally non-zero even for syntactically valid identity.
    std::process::exit(3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(expiry: u64, roots: Vec<Vec<u8>>) -> MachineIdentityBundle {
        MachineIdentityBundle {
            principal_id: [9; 32],
            cng_key_name: "test-only-not-a-trusted-key".into(),
            certificate_chain_der: vec![vec![0x30]],
            trust_roots_der: roots,
            not_after_unix_ms: expiry,
        }
    }

    #[test]
    fn stale_identity_is_not_qualified() {
        assert_eq!(
            inspect_loaded(&fixture(99, vec![vec![0x30]]), 100),
            Finding::Expired
        );
    }

    #[test]
    fn embedded_roots_never_imply_approved_provenance() {
        assert_eq!(
            inspect_loaded(&fixture(200, vec![vec![0x30]]), 100),
            Finding::UnverifiedProvenance
        );
        assert_eq!(
            inspect_loaded(&fixture(200, vec![]), 100),
            Finding::MissingTrustRoots
        );
    }

    #[test]
    fn backup_cannot_rescue_missing_primary() {
        let dir = std::env::temp_dir().join(format!(
            "classmesh-readiness-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let primary = dir.join("machine-identity.json");
        let bytes =
            DurableMachineIdentity::encode_canonical(&fixture(200, vec![vec![0x30]])).unwrap();
        fs::write(dir.join("machine-identity.json.bak"), bytes).unwrap();
        assert_eq!(inspect_primary(&primary, 100), Finding::MissingPrimary);
        fs::remove_dir_all(dir).unwrap();
    }
}
