use classmesh_security::PrincipalId;

use crate::enrollment::{MAX_ENROLLMENT_CSR_BYTES, PRINCIPAL_ID_BYTES, SHA256_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentApproval {
    pub principal_id: PrincipalId,
    pub csr_sha256: [u8; SHA256_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateValidity {
    pub not_before_unix_ms: u64,
    pub not_after_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateIssuancePolicy {
    pub maximum_lifetime_ms: u64,
    pub allowed_clock_skew_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIssuanceError {
    EmptyCsr,
    CsrTooLarge { length: usize, maximum: usize },
    PrincipalBindingMismatch,
    CsrBindingMismatch,
    InvalidValidityWindow,
    NotBeforeTooFarInFuture,
    LifetimeTooLong,
}

impl CertificateIssuancePolicy {
    pub fn validate(
        self,
        now_unix_ms: u64,
        principal_id: PrincipalId,
        csr_der: &[u8],
        csr_sha256: [u8; SHA256_BYTES],
        approval: EnrollmentApproval,
        validity: CertificateValidity,
    ) -> Result<(), CertificateIssuanceError> {
        if csr_der.is_empty() {
            return Err(CertificateIssuanceError::EmptyCsr);
        }
        if csr_der.len() > MAX_ENROLLMENT_CSR_BYTES {
            return Err(CertificateIssuanceError::CsrTooLarge {
                length: csr_der.len(),
                maximum: MAX_ENROLLMENT_CSR_BYTES,
            });
        }
        if approval.principal_id != principal_id {
            return Err(CertificateIssuanceError::PrincipalBindingMismatch);
        }
        if approval.csr_sha256 != csr_sha256 {
            return Err(CertificateIssuanceError::CsrBindingMismatch);
        }
        if validity.not_after_unix_ms <= validity.not_before_unix_ms {
            return Err(CertificateIssuanceError::InvalidValidityWindow);
        }

        let latest_not_before = now_unix_ms.saturating_add(self.allowed_clock_skew_ms);
        if validity.not_before_unix_ms > latest_not_before {
            return Err(CertificateIssuanceError::NotBeforeTooFarInFuture);
        }

        let lifetime = validity
            .not_after_unix_ms
            .saturating_sub(validity.not_before_unix_ms);
        if lifetime > self.maximum_lifetime_ms {
            return Err(CertificateIssuanceError::LifetimeTooLong);
        }

        Ok(())
    }
}

const _: usize = PRINCIPAL_ID_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; PRINCIPAL_ID_BYTES])
    }

    fn policy() -> CertificateIssuancePolicy {
        CertificateIssuancePolicy {
            maximum_lifetime_ms: 86_400_000,
            allowed_clock_skew_ms: 60_000,
        }
    }

    fn approval() -> EnrollmentApproval {
        EnrollmentApproval {
            principal_id: principal(7),
            csr_sha256: [8; SHA256_BYTES],
        }
    }

    fn validity() -> CertificateValidity {
        CertificateValidity {
            not_before_unix_ms: 1_000_000,
            not_after_unix_ms: 1_000_000 + 3_600_000,
        }
    }

    #[test]
    fn issuance_requires_exact_approved_principal_and_csr() {
        policy()
            .validate(
                1_000_000,
                principal(7),
                &[0x30, 0x01, 0x00],
                [8; SHA256_BYTES],
                approval(),
                validity(),
            )
            .expect("approved principal and CSR should pass issuance policy");

        assert_eq!(
            policy().validate(
                1_000_000,
                principal(9),
                &[0x30, 0x01, 0x00],
                [8; SHA256_BYTES],
                approval(),
                validity(),
            ),
            Err(CertificateIssuanceError::PrincipalBindingMismatch)
        );
        assert_eq!(
            policy().validate(
                1_000_000,
                principal(7),
                &[0x30, 0x01, 0x00],
                [9; SHA256_BYTES],
                approval(),
                validity(),
            ),
            Err(CertificateIssuanceError::CsrBindingMismatch)
        );
    }

    #[test]
    fn issuance_rejects_unbounded_or_invalid_validity() {
        let mut invalid = validity();
        invalid.not_after_unix_ms = invalid.not_before_unix_ms;
        assert_eq!(
            policy().validate(
                1_000_000,
                principal(7),
                &[1],
                [8; SHA256_BYTES],
                approval(),
                invalid,
            ),
            Err(CertificateIssuanceError::InvalidValidityWindow)
        );

        let too_long = CertificateValidity {
            not_before_unix_ms: 1_000_000,
            not_after_unix_ms: 1_000_000 + 86_400_001,
        };
        assert_eq!(
            policy().validate(
                1_000_000,
                principal(7),
                &[1],
                [8; SHA256_BYTES],
                approval(),
                too_long,
            ),
            Err(CertificateIssuanceError::LifetimeTooLong)
        );

        let future = CertificateValidity {
            not_before_unix_ms: 1_060_001,
            not_after_unix_ms: 1_060_002,
        };
        assert_eq!(
            policy().validate(
                1_000_000,
                principal(7),
                &[1],
                [8; SHA256_BYTES],
                approval(),
                future,
            ),
            Err(CertificateIssuanceError::NotBeforeTooFarInFuture)
        );
    }

    #[test]
    fn issuance_rejects_empty_or_oversized_csr() {
        assert_eq!(
            policy().validate(
                1_000_000,
                principal(7),
                &[],
                [8; SHA256_BYTES],
                approval(),
                validity(),
            ),
            Err(CertificateIssuanceError::EmptyCsr)
        );

        let oversized = vec![0; MAX_ENROLLMENT_CSR_BYTES + 1];
        assert!(matches!(
            policy().validate(
                1_000_000,
                principal(7),
                &oversized,
                [8; SHA256_BYTES],
                approval(),
                validity(),
            ),
            Err(CertificateIssuanceError::CsrTooLarge { .. })
        ));
    }
}
