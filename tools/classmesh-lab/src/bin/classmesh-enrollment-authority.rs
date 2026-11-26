#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-enrollment-authority is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::error::Error;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use classmesh_control::enrollment::{ENROLLMENT_MIN_VERSION, validate_enrollment_request};
    use classmesh_control::issuance::{
        CertificateIssuancePolicy, CertificateValidity, EnrollmentApproval,
    };
    use classmesh_control::x509_issuance::{EnrollmentCertificateRequest, issue_certificate};
    use classmesh_identity_win::{CngMachineKey, CngRcgenSigningKey};
    use classmesh_lab::enrollment_cli_role::EnrollmentCliRole;
    use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult, PrincipalRole};
    use classmesh_security::PrincipalId;
    use prost::Message;
    use rcgen::Issuer;
    use rustls::pki_types::{CertificateDer, ServerName};
    use sha2::{Digest, Sha256};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    const MAX_REQUEST_BYTES: usize = 512 * 1024;
    const MAX_CA_CERT_BYTES: usize = 64 * 1024;
    const DEFAULT_LIFETIME_HOURS: u64 = 24;
    const MAX_LIFETIME_HOURS: u64 = 24 * 7;

    #[derive(Debug)]
    struct Config {
        role: EnrollmentCliRole,
        request: PathBuf,
        ca_cert: PathBuf,
        ca_key_name: String,
        output: PathBuf,
        lifetime_hours: u64,
        student_server_name: Option<ServerName<'static>>,
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            Self::parse_args(std::env::args().skip(1))
        }

        fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
            let mut role = EnrollmentCliRole::Teacher;
            let mut request = None;
            let mut ca_cert = None;
            let mut ca_key_name = None;
            let mut output = None;
            let mut lifetime_hours = DEFAULT_LIFETIME_HOURS;
            let mut student_server_name = None;

            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--role" => role = EnrollmentCliRole::parse(&value()?)?,
                    "--request" => request = Some(PathBuf::from(value()?)),
                    "--ca-cert" => ca_cert = Some(PathBuf::from(value()?)),
                    "--ca-key-name" => ca_key_name = Some(value()?),
                    "--output" => output = Some(PathBuf::from(value()?)),
                    "--student-server-name" => {
                        if student_server_name.is_some() {
                            return Err("--student-server-name must appear once".to_owned());
                        }
                        student_server_name =
                            Some(ServerName::try_from(value()?).map_err(|_| {
                                "--student-server-name must be a valid DNS name or IP address"
                                    .to_owned()
                            })?);
                    }
                    "--lifetime-hours" => {
                        lifetime_hours = value()?
                            .parse()
                            .map_err(|_| "--lifetime-hours must be an integer".to_owned())?;
                    }
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
                }
            }

            if lifetime_hours == 0 || lifetime_hours > MAX_LIFETIME_HOURS {
                return Err(format!("--lifetime-hours must be 1..={MAX_LIFETIME_HOURS}"));
            }
            if student_server_name.is_some() && !matches!(role, EnrollmentCliRole::StudentDevice) {
                return Err("--student-server-name requires --role student-device".to_owned());
            }

            Ok(Self {
                role,
                request: request
                    .ok_or_else(|| format!("--request is required\n\n{}", Self::usage()))?,
                ca_cert: ca_cert
                    .ok_or_else(|| format!("--ca-cert is required\n\n{}", Self::usage()))?,
                ca_key_name: ca_key_name
                    .ok_or_else(|| format!("--ca-key-name is required\n\n{}", Self::usage()))?,
                output: output
                    .ok_or_else(|| format!("--output is required\n\n{}", Self::usage()))?,
                lifetime_hours,
                student_server_name,
            })
        }

        fn usage() -> &'static str {
            "ClassMesh offline enrollment authority (--role teacher|student-device; default teacher)\n\n\
Required:\n\
  --request <teacher-request.pb>\n\
  --ca-cert <authority-ca.der>\n\
  --ca-key-name <machine CNG key name>\n\
  --output <approved-result.pb>\n\n\
Optional:\n\
  --lifetime-hours <1..168>   default: 24\n  --student-server-name <DNS-or-IP>   operator-approved endpoint for Student Live Mode\n\n\
The CA private key must already exist as a non-exportable machine-scoped CNG key.\n\
The selected role must explicitly match the request. Default role: Teacher."
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

        if config.output.exists() {
            return Err(format!(
                "refusing to overwrite existing enrollment result: {}",
                config.output.display()
            )
            .into());
        }

        let request_bytes = read_bounded(&config.request, MAX_REQUEST_BYTES, "enrollment request")?;
        let request = EnrollmentRequest::decode(request_bytes.as_slice())?;
        validate_enrollment_request(ENROLLMENT_MIN_VERSION, &request)
            .map_err(|error| format!("enrollment request rejected: {error:?}"))?;
        let expected = match config.role {
            EnrollmentCliRole::Teacher => PrincipalRole::Teacher as i32,
            EnrollmentCliRole::StudentDevice => PrincipalRole::StudentDevice as i32,
        };
        if request.role != expected {
            return Err("enrollment request role does not match operator-approved role".into());
        }

        let principal_id = PrincipalId(
            request
                .principal_id
                .as_slice()
                .try_into()
                .map_err(|_| "validated PrincipalId length changed unexpectedly")?,
        );
        let csr_sha256: [u8; 32] = Sha256::digest(&request.pkcs10_csr_der).into();

        let ca_cert_der =
            read_bounded(&config.ca_cert, MAX_CA_CERT_BYTES, "authority certificate")?;
        let ca_key = CngMachineKey::open(config.ca_key_name.clone())?;
        if ca_key.export_policy()? != 0 {
            return Err("authority CNG key is exportable; refusing certificate issuance".into());
        }
        let ca_signing_key = CngRcgenSigningKey::new(ca_key)?;
        let ca_der = CertificateDer::from(ca_cert_der.clone());
        let issuer = Issuer::from_ca_cert_der(&ca_der, ca_signing_key)
            .map_err(|error| format!("authority certificate/key rejected: {error}"))?;

        let now_unix_ms = unix_time_ms()?;
        let lifetime_ms = config
            .lifetime_hours
            .checked_mul(60 * 60 * 1000)
            .ok_or("certificate lifetime overflow")?;
        let not_after_unix_ms = now_unix_ms
            .checked_add(lifetime_ms)
            .ok_or("certificate expiry overflow")?;
        let approval = EnrollmentApproval {
            principal_id,
            csr_sha256,
        };
        let issued = issue_certificate(
            CertificateIssuancePolicy {
                maximum_lifetime_ms: MAX_LIFETIME_HOURS * 60 * 60 * 1000,
                allowed_clock_skew_ms: 60_000,
            },
            now_unix_ms,
            EnrollmentCertificateRequest {
                principal_id,
                csr_der: &request.pkcs10_csr_der,
                approval,
                approved_server_name: config.student_server_name.clone(),
            },
            CertificateValidity {
                not_before_unix_ms: now_unix_ms,
                not_after_unix_ms,
            },
            &issuer,
        )
        .map_err(|error| format!("certificate issuance failed: {error:?}"))?;

        let mut enrollment_id = [0_u8; 16];
        getrandom::fill(&mut enrollment_id)
            .map_err(|error| format!("failed to generate enrollment ID randomness: {error}"))?;
        let result = EnrollmentResult {
            enrollment_id: enrollment_id.to_vec(),
            status: 2,
            certificate_chain_der: vec![issued.certificate_der.as_ref().to_vec(), ca_cert_der],
            credential_fingerprint_sha256: issued.credential_fingerprint_sha256.to_vec(),
            not_after_unix_ms: issued.not_after_unix_ms,
            diagnostic: "approved".to_owned(),
            principal_id: principal_id.0.to_vec(),
            csr_sha256: issued.csr_sha256.to_vec(),
        };

        let bytes = result.encode_to_vec();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&config.output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;

        println!("enrollment_result=approved");
        println!("enrollment_role={}", config.role.common_name_label());
        if let Some(server_name) = config.student_server_name {
            println!("student_server_name={}", server_name.to_str());
        }
        println!("principal_id={}", hex(&principal_id.0));
        println!(
            "credential_fingerprint_sha256={}",
            hex(&issued.credential_fingerprint_sha256)
        );
        println!("not_after_unix_ms={}", issued.not_after_unix_ms);
        println!("result={}", config.output.display());
        println!("authority_private_key_exported=false");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::Config;

        fn parse(extra: &[&str]) -> Result<Config, String> {
            Config::parse_args(
                [
                    "--request",
                    "request.pb",
                    "--ca-cert",
                    "ca.der",
                    "--ca-key-name",
                    "Lab CA",
                    "--output",
                    "issued.pb",
                ]
                .into_iter()
                .chain(extra.iter().copied())
                .map(str::to_owned),
            )
        }

        #[test]
        fn student_server_name_requires_explicit_student_role_and_valid_endpoint() {
            for endpoint in ["student.classmesh", "127.0.0.1", "::1"] {
                let config = parse(&[
                    "--role",
                    "student-device",
                    "--student-server-name",
                    endpoint,
                ])
                .expect("approved Student endpoint");
                assert_eq!(config.student_server_name.unwrap().to_str(), endpoint);
                assert!(parse(&["--student-server-name", endpoint]).is_err());
            }
            for bad in [
                "*.classmesh",
                "student.classmesh:4433",
                "https://student.classmesh",
            ] {
                assert!(
                    parse(&["--role", "student-device", "--student-server-name", bad]).is_err()
                );
            }
            assert!(
                parse(&[
                    "--role",
                    "student-device",
                    "--student-server-name",
                    "student.classmesh",
                    "--student-server-name",
                    "other.classmesh",
                ])
                .is_err()
            );
            assert!(
                parse(&[])
                    .expect("Teacher CLI")
                    .student_server_name
                    .is_none()
            );
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("enrollment authority failed: {error}");
        std::process::exit(1);
    }
}
