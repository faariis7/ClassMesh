#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-student-authorize-teacher is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use classmesh_control::enrollment_result::approved_credential_from_result;
    use classmesh_protocol::control_wire::EnrollmentResult;
    use classmesh_security::persistence::DurableAuthorizationState;
    use classmesh_security::{Permission, Principal, PrincipalKind};
    use prost::Message;
    use sha2::{Digest, Sha256};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    const MAX_RESULT_BYTES: usize = 512 * 1024;

    #[derive(Debug)]
    struct Config {
        result: PathBuf,
        authorization: PathBuf,
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            let mut args = std::env::args().skip(1);
            let mut result = None;
            let mut authorization = None;

            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--result" => result = Some(PathBuf::from(value()?)),
                    "--authorization" => authorization = Some(PathBuf::from(value()?)),
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
                }
            }

            Ok(Self {
                result: result
                    .ok_or_else(|| format!("--result is required\n\n{}", Self::usage()))?,
                authorization: authorization
                    .ok_or_else(|| format!("--authorization is required\n\n{}", Self::usage()))?,
            })
        }

        fn usage() -> &'static str {
            "ClassMesh Phase 6F Student Teacher authorization\n\n\
Required:\n\
  --result <teacher-approved.pb>\n\
  --authorization <Student authorization.json>\n\n\
Adds exactly one previously-absent Teacher principal with only ViewInteractive and\n\
ControlInput permissions. Existing principals are never replaced by this qualification tool."
        }
    }

    fn read_result(path: &PathBuf) -> AppResult<Vec<u8>> {
        let metadata = fs::metadata(path)?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_RESULT_BYTES {
            return Err(format!(
                "enrollment result size {length} is outside 1..={MAX_RESULT_BYTES}: {}",
                path.display()
            )
            .into());
        }
        Ok(fs::read(path)?)
    }

    fn unix_time_ms() -> AppResult<u64> {
        Ok(
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
                .map_err(|_| "system time does not fit u64 milliseconds")?,
        )
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

        let result_bytes = read_result(&config.result)?;
        let result = EnrollmentResult::decode(result_bytes.as_slice())?;
        let now_unix_ms = unix_time_ms()?;
        let approved = approved_credential_from_result(&result, now_unix_ms)
            .map_err(|error| format!("Teacher enrollment result rejected: {error:?}"))?;

        let leaf = approved
            .certificate_chain_der
            .first()
            .ok_or("approved Teacher certificate chain is empty")?;
        let actual_fingerprint: [u8; 32] = Sha256::digest(leaf).into();
        if approved.credential.fingerprint.0 != actual_fingerprint {
            return Err("Teacher result fingerprint does not match leaf certificate".into());
        }

        let durable = DurableAuthorizationState::new(&config.authorization);
        let mut store = durable
            .load()
            .map_err(|error| format!("Student authorization state rejected: {error}"))?
            .ok_or_else(|| {
                format!(
                    "Student authorization state is missing at {}",
                    config.authorization.display()
                )
            })?;

        if store.principal(approved.principal_id).is_some() {
            return Err(
                "Teacher PrincipalId already exists; refusing to replace existing authorization"
                    .into(),
            );
        }

        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::ViewInteractive);
        permissions.insert(Permission::ControlInput);
        let fingerprint = approved.credential.fingerprint;
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, approved.credential);
        store
            .upsert(Principal {
                id: approved.principal_id,
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions,
                credentials,
            })
            .map_err(|error| format!("Teacher authorization rejected: {error:?}"))?;

        durable
            .save(&store)
            .map_err(|error| format!("Student authorization state update failed: {error}"))?;

        println!("teacher_authorization=installed");
        println!("principal_id={}", hex(&approved.principal_id.0));
        println!("credential_fingerprint_sha256={}", hex(&fingerprint.0));
        println!("permissions=ViewInteractive,ControlInput");
        println!("authorization={}", config.authorization.display());
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("Student Teacher authorization failed: {error}");
        std::process::exit(1);
    }
}
