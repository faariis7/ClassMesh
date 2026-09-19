use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult};
use classmesh_protocol::ProtocolVersion;

pub const ENROLLMENT_MIN_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 2 };
pub const PRINCIPAL_ID_BYTES: usize = 32;
pub const ENROLLMENT_NONCE_BYTES: usize = 32;
pub const SHA256_BYTES: usize = 32;
pub const MAX_ENROLLMENT_CSR_BYTES: usize = 64 * 1024;
pub const MAX_DISPLAY_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentValidationError {
    UnsupportedProtocolVersion {
        negotiated: ProtocolVersion,
        minimum: ProtocolVersion,
    },
    InvalidPrincipalIdLength {
        length: usize,
    },
    InvalidClientNonceLength {
        length: usize,
    },
    EmptyCsr,
    CsrTooLarge {
        length: usize,
        maximum: usize,
    },
    EmptyDisplayName,
    DisplayNameTooLong {
        length: usize,
        maximum: usize,
    },
    UnsupportedRole {
        value: i32,
    },
    InvalidCsrSha256Length {
        length: usize,
    },
    PrincipalBindingMismatch,
    CsrBindingMismatch,
}

pub fn validate_enrollment_request(
    negotiated_version: ProtocolVersion,
    request: &EnrollmentRequest,
) -> Result<(), EnrollmentValidationError> {
    validate_enrollment_version(negotiated_version)?;

    if request.principal_id.len() != PRINCIPAL_ID_BYTES {
        return Err(EnrollmentValidationError::InvalidPrincipalIdLength {
            length: request.principal_id.len(),
        });
    }
    if request.client_nonce.len() != ENROLLMENT_NONCE_BYTES {
        return Err(EnrollmentValidationError::InvalidClientNonceLength {
            length: request.client_nonce.len(),
        });
    }
    if request.pkcs10_csr_der.is_empty() {
        return Err(EnrollmentValidationError::EmptyCsr);
    }
    if request.pkcs10_csr_der.len() > MAX_ENROLLMENT_CSR_BYTES {
        return Err(EnrollmentValidationError::CsrTooLarge {
            length: request.pkcs10_csr_der.len(),
            maximum: MAX_ENROLLMENT_CSR_BYTES,
        });
    }

    let display_name_len = request.display_name.len();
    if request.display_name.trim().is_empty() {
        return Err(EnrollmentValidationError::EmptyDisplayName);
    }
    if display_name_len > MAX_DISPLAY_NAME_BYTES {
        return Err(EnrollmentValidationError::DisplayNameTooLong {
            length: display_name_len,
            maximum: MAX_DISPLAY_NAME_BYTES,
        });
    }

    if !matches!(request.role, 1..=3) {
        return Err(EnrollmentValidationError::UnsupportedRole {
            value: request.role,
        });
    }

    Ok(())
}

pub fn validate_enrollment_result_binding(
    negotiated_version: ProtocolVersion,
    expected_principal_id: &[u8; PRINCIPAL_ID_BYTES],
    expected_csr_sha256: &[u8; SHA256_BYTES],
    result: &EnrollmentResult,
) -> Result<(), EnrollmentValidationError> {
    validate_enrollment_version(negotiated_version)?;

    if result.principal_id.len() != PRINCIPAL_ID_BYTES {
        return Err(EnrollmentValidationError::InvalidPrincipalIdLength {
            length: result.principal_id.len(),
        });
    }
    if result.csr_sha256.len() != SHA256_BYTES {
        return Err(EnrollmentValidationError::InvalidCsrSha256Length {
            length: result.csr_sha256.len(),
        });
    }

    if result.principal_id.as_slice() != expected_principal_id {
        return Err(EnrollmentValidationError::PrincipalBindingMismatch);
    }
    if result.csr_sha256.as_slice() != expected_csr_sha256 {
        return Err(EnrollmentValidationError::CsrBindingMismatch);
    }

    Ok(())
}

fn validate_enrollment_version(
    negotiated_version: ProtocolVersion,
) -> Result<(), EnrollmentValidationError> {
    if negotiated_version.major != ENROLLMENT_MIN_VERSION.major
        || negotiated_version.minor < ENROLLMENT_MIN_VERSION.minor
    {
        return Err(EnrollmentValidationError::UnsupportedProtocolVersion {
            negotiated: negotiated_version,
            minimum: ENROLLMENT_MIN_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> EnrollmentRequest {
        EnrollmentRequest {
            principal_id: vec![7; PRINCIPAL_ID_BYTES],
            role: 2,
            pkcs10_csr_der: vec![0x30, 0x01, 0x00],
            client_nonce: vec![9; ENROLLMENT_NONCE_BYTES],
            display_name: "student-07".to_owned(),
        }
    }

    #[test]
    fn version_01_rejects_enrollment_payloads_explicitly() {
        assert_eq!(
            validate_enrollment_request(ProtocolVersion { major: 0, minor: 1 }, &valid_request()),
            Err(EnrollmentValidationError::UnsupportedProtocolVersion {
                negotiated: ProtocolVersion { major: 0, minor: 1 },
                minimum: ENROLLMENT_MIN_VERSION,
            })
        );
    }

    #[test]
    fn malformed_identity_nonce_and_csr_are_rejected() {
        let version = ENROLLMENT_MIN_VERSION;

        let mut request = valid_request();
        request.principal_id.pop();
        assert!(matches!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::InvalidPrincipalIdLength { .. })
        ));

        let mut request = valid_request();
        request.client_nonce.clear();
        assert!(matches!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::InvalidClientNonceLength { .. })
        ));

        let mut request = valid_request();
        request.pkcs10_csr_der.clear();
        assert_eq!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::EmptyCsr)
        );

        let mut request = valid_request();
        request.pkcs10_csr_der = vec![0; MAX_ENROLLMENT_CSR_BYTES + 1];
        assert!(matches!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::CsrTooLarge { .. })
        ));
    }

    #[test]
    fn display_name_and_role_are_bounded() {
        let version = ENROLLMENT_MIN_VERSION;

        let mut request = valid_request();
        request.display_name = " ".to_owned();
        assert_eq!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::EmptyDisplayName)
        );

        let mut request = valid_request();
        request.display_name = "x".repeat(MAX_DISPLAY_NAME_BYTES + 1);
        assert!(matches!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::DisplayNameTooLong { .. })
        ));

        let mut request = valid_request();
        request.role = 0;
        assert_eq!(
            validate_enrollment_request(version, &request),
            Err(EnrollmentValidationError::UnsupportedRole { value: 0 })
        );
    }

    #[test]
    fn valid_v02_request_is_accepted() {
        validate_enrollment_request(ENROLLMENT_MIN_VERSION, &valid_request())
            .expect("valid v0.2 enrollment request should pass validation");
    }

    #[test]
    fn result_must_bind_to_expected_principal_and_csr() {
        let principal_id = [7_u8; PRINCIPAL_ID_BYTES];
        let csr_sha256 = [8_u8; SHA256_BYTES];
        let result = EnrollmentResult {
            enrollment_id: vec![1; 16],
            status: 2,
            certificate_chain_der: Vec::new(),
            credential_fingerprint_sha256: Vec::new(),
            not_after_unix_ms: 0,
            diagnostic: String::new(),
            principal_id: principal_id.to_vec(),
            csr_sha256: csr_sha256.to_vec(),
        };

        validate_enrollment_result_binding(
            ENROLLMENT_MIN_VERSION,
            &principal_id,
            &csr_sha256,
            &result,
        )
        .expect("matching result binding should pass");

        let wrong_principal = [6_u8; PRINCIPAL_ID_BYTES];
        assert_eq!(
            validate_enrollment_result_binding(
                ENROLLMENT_MIN_VERSION,
                &wrong_principal,
                &csr_sha256,
                &result,
            ),
            Err(EnrollmentValidationError::PrincipalBindingMismatch)
        );

        let wrong_csr = [5_u8; SHA256_BYTES];
        assert_eq!(
            validate_enrollment_result_binding(
                ENROLLMENT_MIN_VERSION,
                &principal_id,
                &wrong_csr,
                &result,
            ),
            Err(EnrollmentValidationError::CsrBindingMismatch)
        );
    }
}
