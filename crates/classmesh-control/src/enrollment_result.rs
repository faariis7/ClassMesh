use classmesh_protocol::control_wire::EnrollmentResult;
use classmesh_security::{CredentialFingerprint, CredentialRecord, PrincipalId};

use crate::enrollment::{PRINCIPAL_ID_BYTES, SHA256_BYTES};

pub const MAX_CERTIFICATE_CHAIN_ENTRIES: usize = 8;
pub const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
pub const MAX_CERTIFICATE_CHAIN_DER_BYTES: usize = 256 * 1024;

const STATUS_APPROVED: i32 = 2;
const STATUS_REJECTED: i32 = 3;
const STATUS_REVOKED: i32 = 4;
const STATUS_EXPIRED: i32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedEnrollmentCredential {
    pub principal_id: PrincipalId,
    pub csr_sha256: [u8; SHA256_BYTES],
    pub credential: CredentialRecord,
    pub certificate_chain_der: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentCredentialError {
    InvalidResult(EnrollmentResultError),
    ResultNotApproved,
    CredentialAlreadyExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentResultError {
    InvalidPrincipalIdLength { length: usize },
    InvalidCsrSha256Length { length: usize },
    UnsupportedTerminalStatus { value: i32 },
    ApprovedResultMissingCertificateChain,
    ApprovedResultInvalidCredentialFingerprintLength { length: usize },
    ApprovedResultMissingExpiry,
    NonApprovedResultCarriesCredential,
    CertificateChainTooLong { length: usize, maximum: usize },
    CertificateTooLarge { length: usize, maximum: usize },
    CertificateChainTooLarge { length: usize, maximum: usize },
}

/// Validates status-dependent enrollment result shape before any certificate is
/// persisted or used for mTLS. Cryptographic certificate/CSR verification is a
/// separate authority/client step; this function only enforces bounded wire
/// invariants and prevents rejected/revoked results from smuggling credentials.
pub fn validate_enrollment_result(result: &EnrollmentResult) -> Result<(), EnrollmentResultError> {
    if result.principal_id.len() != PRINCIPAL_ID_BYTES {
        return Err(EnrollmentResultError::InvalidPrincipalIdLength {
            length: result.principal_id.len(),
        });
    }
    if result.csr_sha256.len() != SHA256_BYTES {
        return Err(EnrollmentResultError::InvalidCsrSha256Length {
            length: result.csr_sha256.len(),
        });
    }

    match result.status {
        STATUS_APPROVED => validate_approved_result(result),
        STATUS_REJECTED | STATUS_REVOKED | STATUS_EXPIRED => {
            if !result.certificate_chain_der.is_empty()
                || !result.credential_fingerprint_sha256.is_empty()
                || result.not_after_unix_ms != 0
            {
                return Err(EnrollmentResultError::NonApprovedResultCarriesCredential);
            }
            Ok(())
        }
        value => Err(EnrollmentResultError::UnsupportedTerminalStatus { value }),
    }
}

pub fn approved_credential_from_result(
    result: &EnrollmentResult,
    now_unix_ms: u64,
) -> Result<ApprovedEnrollmentCredential, EnrollmentCredentialError> {
    validate_enrollment_result(result).map_err(EnrollmentCredentialError::InvalidResult)?;
    if result.status != STATUS_APPROVED {
        return Err(EnrollmentCredentialError::ResultNotApproved);
    }
    if result.not_after_unix_ms <= now_unix_ms {
        return Err(EnrollmentCredentialError::CredentialAlreadyExpired);
    }

    let principal_id = PrincipalId(
        result
            .principal_id
            .as_slice()
            .try_into()
            .expect("validated principal ID length"),
    );
    let csr_sha256 = result
        .csr_sha256
        .as_slice()
        .try_into()
        .expect("validated CSR SHA-256 length");
    let fingerprint = CredentialFingerprint(
        result
            .credential_fingerprint_sha256
            .as_slice()
            .try_into()
            .expect("validated credential fingerprint length"),
    );
    let mut credential = CredentialRecord::active(fingerprint, now_unix_ms);
    credential.expires_at_unix_ms = Some(result.not_after_unix_ms);

    Ok(ApprovedEnrollmentCredential {
        principal_id,
        csr_sha256,
        credential,
        certificate_chain_der: result.certificate_chain_der.clone(),
    })
}

fn validate_approved_result(result: &EnrollmentResult) -> Result<(), EnrollmentResultError> {
    if result.certificate_chain_der.is_empty() {
        return Err(EnrollmentResultError::ApprovedResultMissingCertificateChain);
    }
    if result.credential_fingerprint_sha256.len() != SHA256_BYTES {
        return Err(
            EnrollmentResultError::ApprovedResultInvalidCredentialFingerprintLength {
                length: result.credential_fingerprint_sha256.len(),
            },
        );
    }
    if result.not_after_unix_ms == 0 {
        return Err(EnrollmentResultError::ApprovedResultMissingExpiry);
    }
    if result.certificate_chain_der.len() > MAX_CERTIFICATE_CHAIN_ENTRIES {
        return Err(EnrollmentResultError::CertificateChainTooLong {
            length: result.certificate_chain_der.len(),
            maximum: MAX_CERTIFICATE_CHAIN_ENTRIES,
        });
    }

    let mut total = 0usize;
    for certificate in &result.certificate_chain_der {
        if certificate.len() > MAX_CERTIFICATE_DER_BYTES {
            return Err(EnrollmentResultError::CertificateTooLarge {
                length: certificate.len(),
                maximum: MAX_CERTIFICATE_DER_BYTES,
            });
        }
        total = total.saturating_add(certificate.len());
        if total > MAX_CERTIFICATE_CHAIN_DER_BYTES {
            return Err(EnrollmentResultError::CertificateChainTooLarge {
                length: total,
                maximum: MAX_CERTIFICATE_CHAIN_DER_BYTES,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: i32) -> EnrollmentResult {
        EnrollmentResult {
            enrollment_id: vec![1; 16],
            status,
            certificate_chain_der: Vec::new(),
            credential_fingerprint_sha256: Vec::new(),
            not_after_unix_ms: 0,
            diagnostic: String::new(),
            principal_id: vec![7; PRINCIPAL_ID_BYTES],
            csr_sha256: vec![8; SHA256_BYTES],
        }
    }

    #[test]
    fn approved_result_requires_bounded_credential_material() {
        let mut approved = result(STATUS_APPROVED);
        assert_eq!(
            validate_enrollment_result(&approved),
            Err(EnrollmentResultError::ApprovedResultMissingCertificateChain)
        );

        approved.certificate_chain_der.push(vec![0x30, 0x01, 0x00]);
        approved.credential_fingerprint_sha256 = vec![9; SHA256_BYTES];
        approved.not_after_unix_ms = 123;
        validate_enrollment_result(&approved).expect("bounded approved result should validate");

        approved.certificate_chain_der = vec![vec![0; 1]; MAX_CERTIFICATE_CHAIN_ENTRIES + 1];
        assert!(matches!(
            validate_enrollment_result(&approved),
            Err(EnrollmentResultError::CertificateChainTooLong { .. })
        ));
    }

    #[test]
    fn approved_result_maps_to_bounded_credential_record() {
        let mut approved = result(STATUS_APPROVED);
        approved.certificate_chain_der.push(vec![0x30, 0x01, 0x00]);
        approved.credential_fingerprint_sha256 = vec![9; SHA256_BYTES];
        approved.not_after_unix_ms = 500;

        let material =
            approved_credential_from_result(&approved, 100).expect("approved credential material");
        assert_eq!(material.principal_id, PrincipalId([7; PRINCIPAL_ID_BYTES]));
        assert_eq!(material.csr_sha256, [8; SHA256_BYTES]);
        assert_eq!(
            material.credential.fingerprint,
            CredentialFingerprint([9; SHA256_BYTES])
        );
        assert_eq!(material.credential.issued_at_unix_ms, 100);
        assert_eq!(material.credential.expires_at_unix_ms, Some(500));
        assert_eq!(
            material.certificate_chain_der,
            approved.certificate_chain_der
        );

        assert_eq!(
            approved_credential_from_result(&approved, 500),
            Err(EnrollmentCredentialError::CredentialAlreadyExpired)
        );
    }

    #[test]
    fn non_approved_terminal_result_cannot_carry_credentials() {
        for status in [STATUS_REJECTED, STATUS_REVOKED, STATUS_EXPIRED] {
            validate_enrollment_result(&result(status))
                .expect("credential-free terminal result should validate");

            let mut smuggled = result(status);
            smuggled.certificate_chain_der.push(vec![1]);
            assert_eq!(
                validate_enrollment_result(&smuggled),
                Err(EnrollmentResultError::NonApprovedResultCarriesCredential)
            );
        }
    }

    #[test]
    fn pending_and_unspecified_are_not_terminal_results() {
        assert_eq!(
            validate_enrollment_result(&result(0)),
            Err(EnrollmentResultError::UnsupportedTerminalStatus { value: 0 })
        );
        assert_eq!(
            validate_enrollment_result(&result(1)),
            Err(EnrollmentResultError::UnsupportedTerminalStatus { value: 1 })
        );
    }

    #[test]
    fn identity_and_csr_binding_fields_are_always_required() {
        let mut approved = result(STATUS_APPROVED);
        approved.certificate_chain_der.push(vec![1]);
        approved.credential_fingerprint_sha256 = vec![2; SHA256_BYTES];
        approved.not_after_unix_ms = 123;

        approved.principal_id.pop();
        assert!(matches!(
            validate_enrollment_result(&approved),
            Err(EnrollmentResultError::InvalidPrincipalIdLength { .. })
        ));

        approved.principal_id = vec![7; PRINCIPAL_ID_BYTES];
        approved.csr_sha256.clear();
        assert!(matches!(
            validate_enrollment_result(&approved),
            Err(EnrollmentResultError::InvalidCsrSha256Length { .. })
        ));
    }
}
