#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-enrollment-request is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    use classmesh_control::enrollment::{
        ENROLLMENT_MIN_VERSION, validate_enrollment_request,
    };
    use classmesh_identity_win::{CngMachineKey, CngRcgenSigningKey};
    use classmesh_protocol::control_wire::{EnrollmentRequest, PrincipalRole};
    use prost::Message;
    use rcgen::{CertificateParams, DnType};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Debug)]
    struct Config {
        display_name: String,
        output: PathBuf,
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            let mut args = std::env::args().skip(1);
            let mut display_name = None;
            let mut output = None;

            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--display-name" => display_name = Some(value()?),
                    "--output" => output = Some(PathBuf::from(value()?)),
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
                }
            }

            Ok(Self {
                display_name: display_name
                    .ok_or_else(|| format!("--display-name is required\n\n{}", Self::usage()))?,
                output: output
                    .ok_or_else(|| format!("--output is required\n\n{}", Self::usage()))?,
            })
        }

        fn usage() -> &'static str {
            "ClassMesh protected Teacher enrollment request\n\n\
Required:\n\
  --display-name <name>     bounded Teacher display name\n\
  --output <request.pb>     new protobuf EnrollmentRequest file\n\n\
The private key is created as a non-exportable machine-scoped CNG P-256 key.\n\
Only the signed PKCS#10 request and non-secret enrollment metadata leave this PC."
        }
    }

    struct KeyCleanup {
        name: String,
        armed: bool,
    }

    impl KeyCleanup {
        fn new(name: String) -> Self {
            Self { name, armed: true }
        }

        fn disarm(&mut self) {
            self.armed = false;
        }
    }

    impl Drop for KeyCleanup {
        fn drop(&mut self) {
            if self.armed
                && let Ok(key) = CngMachineKey::open(self.name.clone())
            {
                let _ = key.delete();
            }
        }
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

        if config.output.exists() {
            return Err(format!(
                "refusing to overwrite existing enrollment request: {}",
                config.output.display()
            )
            .into());
        }

        let mut principal_id = [0_u8; 32];
        let mut client_nonce = [0_u8; 32];
        getrandom::fill(&mut principal_id)?;
        getrandom::fill(&mut client_nonce)?;

        let principal_hex = hex(&principal_id);
        let key_name = format!("ClassMesh-Teacher-{principal_hex}");
        let key = CngMachineKey::create(key_name.clone())?;
        let mut cleanup = KeyCleanup::new(key_name.clone());

        if key.export_policy()? != 0 {
            return Err("new ClassMesh CNG key is exportable; refusing enrollment request".into());
        }

        let signing_key = CngRcgenSigningKey::new(key)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(
            DnType::CommonName,
            format!("ClassMesh Teacher {}", config.display_name.trim()),
        );
        let csr_der = params.serialize_request(&signing_key)?.der().to_vec();

        let request = EnrollmentRequest {
            principal_id: principal_id.to_vec(),
            role: PrincipalRole::Teacher as i32,
            pkcs10_csr_der: csr_der,
            client_nonce: client_nonce.to_vec(),
            display_name: config.display_name,
        };
        validate_enrollment_request(ENROLLMENT_MIN_VERSION, &request)
            .map_err(|error| format!("generated enrollment request rejected: {error:?}"))?;

        if let Some(parent) = config.output.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = request.encode_to_vec();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&config.output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;

        cleanup.disarm();
        println!("enrollment_request=created");
        println!("principal_id={principal_hex}");
        println!("cng_key_name={key_name}");
        println!("cng_export_policy=0");
        println!("request={}", config.output.display());
        println!("private_key_exported=false");
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("enrollment request failed: {error}");
        std::process::exit(1);
    }
}
