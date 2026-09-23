#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-enrollment-install is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use classmesh_control::enrollment::{
        ENROLLMENT_MIN_VERSION, validate_enrollment_request, validate_enrollment_result_binding,
    };
    use classmesh_control::enrollment_result::approved_credential_from_result;
    use classmesh_identity_win::{
        CngMachineKey, DurableMachineIdentity, MachineIdentityBundle, cng_client_cert_resolver,
    };
    use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult, PrincipalRole};
    use prost::Message;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest, Sha256};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    const MAX_PROTOBUF_BYTES: usize = 512 * 1024;
    const MAX_TRUST_ROOT_BYTES: usize = 64 * 1024;
    const MAX_TRUST_ROOTS: usize = 16;

    #[derive(Debug)]
    struct Config {
        request: PathBuf,
        result: PathBuf,
        trust_roots: Vec<PathBuf>,
        identity_output: PathBuf,
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            let mut args = std::env::args().skip(1);
            let mut request = None;
            let mut result = None;
            let mut trust_roots = Vec::new();
            let mut identity_output = None;

            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--request" => request = Some(PathBuf::from(value()?)),
                    "--result" => result = Some(PathBuf::from(value()?)),
                    "--trust-root" => trust_roots.push(PathBuf::from(value()?)),
                    "--identity-output" => identity_output = Some(PathBuf::from(value()?)),
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
                }
            }

            if trust_roots.is_empty() {
                return Err(format!(
                    "at least one --trust-root is required\n\n{}",
                    Self::usage()
                ));
            }
            if trust_roots.len() > MAX_TRUST_ROOTS {
                return Err(format!(
                    "too many --trust-root values: {}; maximum is {MAX_TRUST_ROOTS}",
                    trust_roots.len()
                ));
            }

            Ok(Self {
                request: request
                    .ok_or_else(|| format!("--request is required\n\n{}", Self::usage()))?,
                result: result
                    .ok_or_else(|| format!("--result is required\n\n{}", Self::usage()))?,
                trust_roots,
                identity_output: identity_output
                    .ok_or_else(|| format!("--identity-output is required\n\n{}", Self::usage()))?,
            })
        }

        fn usage() -> &'static str {
            "ClassMesh approved Teacher enrollment installer\n\n\
Required:\n\
  --request <teacher-request.pb>\n\
  --result <approved-result.pb>\n\
  --trust-root <server-root.der>   repeat for each trusted server root\n\
  --identity-output <machine-identity.json>\n\n\
The installer validates request/result binding, certificate fingerprint, protected CNG\n\
key matching/export policy, bounded trust roots, and refuses to overwrite identity state."
        }
    }

    fn read_bounded(path: &PathBuf, maximum: usize, label: &str) -> AppResult<Vec<u8>> {
        let metadata = fs::metadata(path)?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if length == 0 {
            return Err(format!("{label} is empty: {}", path.display()).into());
        }
        if length > maximum {
            return Err(format!(
                "{label} is {length} bytes; maximum is {maximum}: {}",
                path.display()
            )
            .into());
        }
        Ok(fs::read(path)?)
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn unix_time_ms() -> AppResult<u64> {
        Ok(
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
                .map_err(|_| "system time does not fit u64 milliseconds")?,
        )
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

        if config.identity_output.exists() {
            return Err(format!(
                "refusing to overwrite existing machine identity: {}",
                config.identity_output.display()
            )
            .into());
        }

        let request_bytes =
            read_bounded(&config.request, MAX_PROTOBUF_BYTES, "enrollment request")?;
        let request = EnrollmentRequest::decode(request_bytes.as_slice())?;
        validate_enrollment_request(ENROLLMENT_MIN_VERSION, &request)
            .map_err(|error| format!("enrollment request rejected: {error:?}"))?;
        if request.role != PrincipalRole::Teacher as i32 {
            return Err("enrollment request is not for a Teacher principal".into());
        }
        let principal_id: [u8; 32] = request
            .principal_id
            .as_slice()
            .try_into()
            .map_err(|_| "validated PrincipalId length changed unexpectedly")?;
        let csr_sha256: [u8; 32] = Sha256::digest(&request.pkcs10_csr_der).into();

        let result_bytes = read_bounded(&config.result, MAX_PROTOBUF_BYTES, "enrollment result")?;
        let result = EnrollmentResult::decode(result_bytes.as_slice())?;
        validate_enrollment_result_binding(
            ENROLLMENT_MIN_VERSION,
            &principal_id,
            &csr_sha256,
            &result,
        )
        .map_err(|error| format!("enrollment result binding rejected: {error:?}"))?;

        let now_unix_ms = unix_time_ms()?;
        let approved = approved_credential_from_result(&result, now_unix_ms)
            .map_err(|error| format!("enrollment result rejected: {error:?}"))?;
        if approved.principal_id.0 != principal_id {
            return Err("approved credential PrincipalId changed after validation".into());
        }

        let leaf = approved
            .certificate_chain_der
            .first()
            .ok_or("approved certificate chain is empty")?;
        let actual_fingerprint: [u8; 32] = Sha256::digest(leaf).into();
        if approved.credential.fingerprint.0 != actual_fingerprint {
            return Err("approved credential fingerprint does not match leaf certificate".into());
        }

        let principal_hex = hex(&principal_id);
        let key_name = format!("ClassMesh-Teacher-{principal_hex}");
        let key = CngMachineKey::open(key_name.clone())?;
        if key.export_policy()? != 0 {
            return Err("Teacher CNG key is exportable; refusing identity installation".into());
        }
        let certificate_chain = approved
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        cng_client_cert_resolver(certificate_chain, key).map_err(|error| {
            format!("approved certificate does not match protected key: {error}")
        })?;

        let mut trust_roots_der = Vec::with_capacity(config.trust_roots.len());
        let mut root_store = RootCertStore::empty();
        for path in &config.trust_roots {
            let root = read_bounded(path, MAX_TRUST_ROOT_BYTES, "trust root")?;
            root_store
                .add(CertificateDer::from(root.clone()))
                .map_err(|error| format!("invalid trust root {}: {error}", path.display()))?;
            trust_roots_der.push(root);
        }
        if root_store.is_empty() {
            return Err("no valid server trust roots were supplied".into());
        }

        let bundle = MachineIdentityBundle {
            principal_id,
            cng_key_name: key_name.clone(),
            certificate_chain_der: approved.certificate_chain_der,
            trust_roots_der,
            not_after_unix_ms: result.not_after_unix_ms,
        };
        DurableMachineIdentity::new(&config.identity_output).save(&bundle)?;

        println!("enrollment_identity=installed");
        println!("principal_id={principal_hex}");
        println!("cng_key_name={key_name}");
        println!("cng_export_policy=0");
        println!("identity={}", config.identity_output.display());
        println!("certificate_not_after_unix_ms={}", result.not_after_unix_ms);
        println!("private_key_exported=false");
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("enrollment install failed: {error}");
        std::process::exit(1);
    }
}
