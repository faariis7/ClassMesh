//! Stage a new StudentDevice authorization and loopback-only control config.
//! This NEVER installs into ProgramData or registers a Windows Service.
#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-student-authorization-init is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use classmesh_control::enrollment::{
        ENROLLMENT_MIN_VERSION, validate_enrollment_request, validate_enrollment_result_binding,
    };
    use classmesh_control::enrollment_result::approved_credential_from_result;
    use classmesh_identity_win::{CngMachineKey, cng_server_cert_resolver};
    use classmesh_lab::enrollment_certificate_validation::validate_signed_result;
    use classmesh_lab::enrollment_cli_role::EnrollmentCliRole;
    use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult, PrincipalRole};
    use classmesh_security::persistence::DurableAuthorizationState;
    use classmesh_security::{AuthorizationStore, Principal, PrincipalKind};
    use prost::Message;
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest, Sha256};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
    const MAX_ENROLLMENT_BYTES: usize = 512 * 1024;

    struct Config {
        request: PathBuf,
        result: PathBuf,
        output_dir: PathBuf,
        trust_roots: Vec<PathBuf>,
        bind_address: SocketAddr,
    }

    fn require_loopback_bind(text: &str) -> Result<SocketAddr, &'static str> {
        let address = text
            .parse::<SocketAddr>()
            .map_err(|_| "invalid bind address")?;
        if address.port() == 0 || !address.ip().is_loopback() {
            return Err("bind address must be loopback with a nonzero port");
        }
        Ok(address)
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            let mut args = std::env::args().skip(1);
            let (mut request, mut result, mut output_dir) = (None, None, None);
            let mut trust_roots = Vec::new();
            let mut bind_address =
                require_loopback_bind("127.0.0.1:5151").expect("constant bind address is valid");
            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--request" => request = Some(PathBuf::from(value()?)),
                    "--result" => result = Some(PathBuf::from(value()?)),
                    "--trust-root" => trust_roots.push(PathBuf::from(value()?)),
                    "--output-dir" => output_dir = Some(PathBuf::from(value()?)),
                    "--bind-address" => {
                        bind_address = require_loopback_bind(&value()?).map_err(str::to_owned)?
                    }
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n{}", Self::usage())),
                }
            }
            if trust_roots.is_empty() || trust_roots.len() > 16 {
                return Err("1..=16 explicit --trust-root values required".into());
            }
            Ok(Self {
                trust_roots,
                request: request.ok_or("--request is required")?,
                result: result.ok_or("--result is required")?,
                output_dir: output_dir.ok_or("--output-dir is required")?,
                bind_address,
            })
        }

        fn usage() -> &'static str {
            "Usage: classmesh-student-authorization-init --request <StudentDevice-request.pb> \
             --result <approved.pb> --trust-root <operator-ca.der> --output-dir <new direct child of %TEMP%> \
             [--bind-address 127.0.0.1:5151]\n\
             Creates only a new temporary staging tree; NEVER installs it into ProgramData."
        }
    }

    fn read_bounded(path: &Path, label: &str) -> AppResult<Vec<u8>> {
        let file = File::open(path)?;
        let size = usize::try_from(file.metadata()?.len()).unwrap_or(usize::MAX);
        if size == 0 || size > MAX_ENROLLMENT_BYTES {
            return Err(format!("{label} size is invalid: {size}").into());
        }
        let mut data = Vec::with_capacity(size);
        file.take(u64::try_from(MAX_ENROLLMENT_BYTES + 1)?)
            .read_to_end(&mut data)?;
        if data.len() != size || data.len() > MAX_ENROLLMENT_BYTES {
            return Err(format!("{label} changed during reading").into());
        }
        Ok(data)
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            value.push(char::from(DIGITS[usize::from(byte >> 4)]));
            value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        value
    }

    pub fn run() -> AppResult {
        let config = match Config::parse() {
            Ok(config) => config,
            Err(message) => {
                eprintln!("{message}");
                if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
                    return Ok(());
                }
                return Err("invalid arguments".into());
            }
        };

        // The binary is a disposable staging tool, NOT a production installer.
        // Require an exact new child of this account's temporary directory.
        let temp_root = fs::canonicalize(std::env::temp_dir())?;
        let parent = config
            .output_dir
            .parent()
            .ok_or("output directory has no parent")?;
        if fs::canonicalize(parent)? != temp_root || config.output_dir.exists() {
            return Err("output must be a NEW direct child of the current user's TEMP".into());
        }

        let request = EnrollmentRequest::decode(
            read_bounded(&config.request, "enrollment request")?.as_slice(),
        )?;
        validate_enrollment_request(ENROLLMENT_MIN_VERSION, &request)
            .map_err(|e| format!("invalid enrollment request: {e:?}"))?;
        if request.role != PrincipalRole::StudentDevice as i32 {
            return Err("only an explicit StudentDevice enrollment request is allowed".into());
        }

        let principal_id: [u8; 32] = request.principal_id.as_slice().try_into()?;
        let csr_digest: [u8; 32] = Sha256::digest(&request.pkcs10_csr_der).into();
        let result =
            EnrollmentResult::decode(read_bounded(&config.result, "approved result")?.as_slice())?;
        validate_enrollment_result_binding(
            ENROLLMENT_MIN_VERSION,
            &principal_id,
            &csr_digest,
            &result,
        )
        .map_err(|e| format!("enrollment result binding rejected: {e:?}"))?;

        let now_unix_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let approved = approved_credential_from_result(&result, now_unix_ms)
            .map_err(|e| format!("approved credential rejected: {e:?}"))?;
        let leaf = approved
            .certificate_chain_der
            .first()
            .ok_or("approved certificate chain is empty")?;
        let fingerprint: [u8; 32] = Sha256::digest(leaf).into();
        if approved.credential.fingerprint.0 != fingerprint {
            return Err("credential fingerprint does not match leaf certificate".into());
        }

        let mut roots = Vec::new();
        for path in &config.trust_roots {
            roots.push(read_bounded(path, "operator trust root")?);
        }
        validate_signed_result(
            &request,
            &result,
            &roots,
            now_unix_ms,
            EnrollmentCliRole::StudentDevice,
        )?;

        // Independently verify matching non-exportable CNG machine signing key.
        let key_name = format!("ClassMesh-StudentDevice-{}", hex(&principal_id));
        let key = CngMachineKey::open(key_name)?;
        if key.export_policy()? != 0 {
            return Err("machine key is exportable".into());
        }
        let chain = approved
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        cng_server_cert_resolver(chain, key)
            .map_err(|e| format!("device leaf certificate does not match CNG key: {e}"))?;

        let mut credentials = BTreeMap::new();
        credentials.insert(approved.credential.fingerprint, approved.credential);
        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: approved.principal_id,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::new(), // never grant a device Teacher powers
                credentials,
            })
            .map_err(|e| format!("device authorization rejected: {e:?}"))?;

        // Fail on pre-existing directory; create nothing in ProgramData.
        fs::create_dir(&config.output_dir)?;
        let state = config.output_dir.join("state");
        let config_dir = config.output_dir.join("config");
        fs::create_dir(&state)?;
        fs::create_dir(&config_dir)?;
        let authorization = state.join("authorization.json");
        DurableAuthorizationState::new(&authorization).save(&store)?;
        let config_path = config_dir.join("control-runtime.json");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&config_path)?;
        writeln!(
            file,
            "{{\"version\":1,\"bind_address\":\"{}\",\"multicast_interface\":null}}",
            config.bind_address
        )?;
        file.sync_all()?;

        println!("student_authorization=staged");
        println!("principal_id={}", hex(&principal_id));
        println!("device_credential_fingerprint={}", hex(&fingerprint));
        println!("authorization={}", authorization.display());
        println!("config={}", config_path.display());
        println!("programdata_changed=false");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::require_loopback_bind;

        #[test]
        fn lab_control_listener_accepts_only_loopback_nonzero_ports() {
            assert_eq!(
                require_loopback_bind("127.0.0.1:5151").unwrap().port(),
                5151
            );
            assert_eq!(require_loopback_bind("[::1]:52100").unwrap().port(), 52100);
            for unsafe_address in [
                "0.0.0.0:5151",
                "192.0.2.1:5151",
                "127.0.0.1:0",
                "[::]:5151",
                "[2001:db8::1]:5151",
                "localhost:5151",
            ] {
                assert!(require_loopback_bind(unsafe_address).is_err());
            }
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("student authorization staging failed: {error}");
        std::process::exit(1);
    }
}
