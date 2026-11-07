//! Explicitly disposable CA bootstrap. Never changes a Windows certificate store.
#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-lab-ca requires Windows CNG");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("lab CA failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows_app {
    use std::error::Error;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use classmesh_identity_win::{CngMachineKey, CngRcgenSigningKey, cng_server_cert_resolver};
    use classmesh_lab::lab_ca::LabSession;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest, Sha256};

    type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
    const MAGIC: &[u8; 8] = b"CMLABCA1";
    const RECEIPT_BYTES: usize = 136;
    const USAGE: &str = "classmesh-lab-ca bootstrap|inspect|cleanup --lab-only [--session <32 lowercase hex digits>]\nBootstrap defaults to a random session. Other operations require its printed session.\nOnly a new ClassMesh-LabCA-<session> child of TEMP and a same-named CNG key are used.\nNo certificate-store import, production trust, or Service installation.";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn regular(path: &Path, directory: bool) -> Result {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_attributes() & 0x400 != 0
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
        {
            return Err("refusing reparse point or unexpected file kind".into());
        }
        Ok(())
    }
    fn bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
        regular(path, false)?;
        let file = fs::File::open(path)?;
        let size = usize::try_from(file.metadata()?.len())?;
        if size == 0 || size > max {
            return Err("invalid lab file size".into());
        }
        let mut bytes = Vec::new();
        file.take(u64::try_from(max + 1)?).read_to_end(&mut bytes)?;
        if bytes.len() != size {
            return Err("lab file changed while reading".into());
        }
        Ok(bytes)
    }
    fn create_file(path: &Path, data: &[u8], files: &mut Vec<std::path::PathBuf>) -> Result {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        files.push(path.to_owned());
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }
    fn digest(session: &LabSession, payload: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ClassMesh disposable lab ownership v1\0");
        hash.update(session.directory.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(payload);
        hash.finalize().into()
    }
    fn bootstrap(session: &LabSession) -> Result {
        // Reject collision before creating anything. CNG create itself also has
        // no overwrite flag; an inaccessible existing key is never adopted.
        if session.directory.symlink_metadata().is_ok()
            || CngMachineKey::open(session.key_name.clone()).is_ok()
        {
            return Err("lab files or key already exist".into());
        }
        fs::create_dir(&session.directory)?;
        let mut owned_key = None;
        let mut files = Vec::new();
        let result = (|| -> Result {
            let key = CngMachineKey::create(session.key_name.clone())?;
            owned_key = Some(key.clone());
            if key.export_policy()? != 0 {
                return Err("lab CNG key is exportable".into());
            }
            let signing = CngRcgenSigningKey::new(key.clone())?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            params.distinguished_name.push(
                DnType::CommonName,
                format!("ClassMesh TEST ONLY Lab CA {}", session.id),
            );
            let now = SystemTime::now();
            params.not_before = (now - Duration::from_secs(60)).into();
            params.not_after = (now + Duration::from_secs(48 * 3600)).into();
            let certificate = params.self_signed(&signing)?.der().to_vec();
            cng_server_cert_resolver(vec![CertificateDer::from(certificate.clone())], key.clone())?;
            let mut receipt = MAGIC.to_vec();
            receipt.extend_from_slice(&Sha256::digest(key.public_key_blob()?));
            receipt.extend_from_slice(&Sha256::digest(&certificate));
            receipt.extend_from_slice(&key.sign_sha256_digest(&digest(session, &receipt))?);
            if receipt.len() != RECEIPT_BYTES {
                return Err("unexpected P-256 receipt signature".into());
            }
            create_file(&session.directory.join("ca.der"), &certificate, &mut files)?;
            create_file(
                &session.directory.join("ownership.bin"),
                &receipt,
                &mut files,
            )?;
            Ok(())
        })();
        if result.is_err() {
            // Only creations successfully acquired by this invocation are owned.
            for file in files {
                let _ = fs::remove_file(file);
            }
            if let Some(key) = owned_key {
                let _ = key.delete();
            }
            let _ = fs::remove_dir(&session.directory);
        }
        result
    }
    fn inspect(session: &LabSession) -> Result<CngMachineKey> {
        regular(&session.directory, true)?;
        for item in fs::read_dir(&session.directory)? {
            let name = item?.file_name();
            if name != "ca.der" && name != "ownership.bin" {
                return Err("unowned file in lab directory; cleanup refused".into());
            }
        }
        let receipt = bounded(&session.directory.join("ownership.bin"), RECEIPT_BYTES)?;
        let certificate = bounded(&session.directory.join("ca.der"), 65536)?;
        if receipt.len() != RECEIPT_BYTES || &receipt[..8] != MAGIC {
            return Err("invalid ownership receipt".into());
        }
        let key = CngMachineKey::open(session.key_name.clone())?;
        let public: [u8; 32] = Sha256::digest(key.public_key_blob()?).into();
        let cert: [u8; 32] = Sha256::digest(&certificate).into();
        if receipt[8..40] != public
            || receipt[40..72] != cert
            || key.export_policy()? != 0
            || !key.verify_sha256_digest(&digest(session, &receipt[..72]), &receipt[72..])?
        {
            return Err("ownership/key/certificate verification failed; cleanup refused".into());
        }
        cng_server_cert_resolver(vec![CertificateDer::from(certificate)], key.clone())?;
        Ok(key)
    }
    pub fn run() -> Result {
        let mut args = std::env::args().skip(1);
        let operation = args.next().ok_or(USAGE)?;
        if operation == "--help" || operation == "-h" {
            println!("{USAGE}");
            return Ok(());
        }
        let mut lab_only = false;
        let mut id = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--lab-only" => lab_only = true,
                "--session" => {
                    if id.is_some() {
                        return Err("duplicate session".into());
                    }
                    id = Some(args.next().ok_or("missing session")?);
                }
                _ => return Err(USAGE.into()),
            }
        }
        if !lab_only {
            return Err("explicit --lab-only required".into());
        }
        if !["bootstrap", "inspect", "cleanup"].contains(&operation.as_str()) {
            return Err(USAGE.into());
        }
        let id = match id {
            Some(id) => id,
            None if operation == "bootstrap" => {
                let mut data = [0; 16];
                getrandom::fill(&mut data).map_err(|e| e.to_string())?;
                hex(&data)
            }
            None => return Err("session is required".into()),
        };
        let temp = fs::canonicalize(std::env::temp_dir())?;
        regular(&temp, true)?;
        let session = LabSession::new(&temp, &id)?;
        match operation.as_str() {
            "bootstrap" => bootstrap(&session)?,
            "inspect" => {
                inspect(&session)?;
            }
            "cleanup" => {
                // Validate every resource before any deletion. No recursive
                // deletion, arbitrary path/key input or certificate-store APIs.
                inspect(&session)?.delete()?;
                fs::remove_file(session.directory.join("ownership.bin"))?;
                fs::remove_file(session.directory.join("ca.der"))?;
                fs::remove_dir(&session.directory)?;
            }
            _ => unreachable!(),
        }
        println!(
            "operation={operation}\nsession={}\nca_key_name={}\nca_certificate={}\ncng_export_policy=0\nprivate_key_exported=false\ntrusted_root_store_changed=false",
            session.id,
            session.key_name,
            session.directory.join("ca.der").display()
        );
        Ok(())
    }
}
