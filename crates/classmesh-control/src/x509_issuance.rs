use std::time::{Duration, SystemTime};

use classmesh_security::PrincipalId;
use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    SigningKey,
};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};
use sha2::{Digest, Sha256};

use crate::enrollment::SHA256_BYTES;
use crate::issuance::{
    CertificateIssuanceError, CertificateIssuancePolicy, CertificateValidity, EnrollmentApproval,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub principal_id: PrincipalId,
    pub csr_sha256: [u8; SHA256_BYTES],
    pub certificate_der: CertificateDer<'static>,
    pub credential_fingerprint_sha256: [u8; SHA256_BYTES],
    pub not_before_unix_ms: u64,
    pub not_after_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X509IssuanceError {
    Policy(CertificateIssuanceError),
    InvalidCsr,
    InvalidTimestamp,
    SigningFailed(String),
}

/// Issues a ClassMesh end-entity certificate from an already approved PKCS#10 CSR.
///
/// The issuance policy first binds the exact CSR bytes to the approved stable
/// PrincipalId and verifies PKCS#10 proof-of-possession. The authority then
/// overrides security-sensitive certificate properties instead of trusting CSR
/// requests for CA/basic-constraints or key-usage privileges.
pub fn issue_certificate<S: SigningKey>(
    policy: CertificateIssuancePolicy,
    now_unix_ms: u64,
    principal_id: PrincipalId,
    csr_der: &[u8],
    approval: EnrollmentApproval,
    validity: CertificateValidity,
    issuer: &Issuer<'_, S>,
) -> Result<IssuedCertificate, X509IssuanceError> {
    policy
        .validate(now_unix_ms, principal_id, csr_der, approval, validity)
        .map_err(X509IssuanceError::Policy)?;

    let csr_der = CertificateSigningRequestDer::from(csr_der);
    let mut request =
        CertificateSigningRequestParams::from_der(&csr_der).map_err(|_| X509IssuanceError::InvalidCsr)?;

    request.params.not_before = unix_ms_to_system_time(validity.not_before_unix_ms)?
        .into();
    request.params.not_after = unix_ms_to_system_time(validity.not_after_unix_ms)?
        .into();
    request.params.is_ca = IsCa::NoCa;
    request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    request.params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    request.params.use_authority_key_identifier_extension = true;

    let certificate = request
        .signed_by(issuer)
        .map_err(|error| X509IssuanceError::SigningFailed(error.to_string()))?;
    let certificate_der = certificate.der().clone();
    let credential_fingerprint_sha256 = Sha256::digest(certificate_der.as_ref()).into();

    Ok(IssuedCertificate {
        principal_id,
        csr_sha256: approval.csr_sha256,
        certificate_der,
        credential_fingerprint_sha256,
        not_before_unix_ms: validity.not_before_unix_ms,
        not_after_unix_ms: validity.not_after_unix_ms,
    })
}

fn unix_ms_to_system_time(unix_ms: u64) -> Result<SystemTime, X509IssuanceError> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(unix_ms))
        .ok_or(X509IssuanceError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, KeyPair,
    };

    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn policy() -> CertificateIssuancePolicy {
        CertificateIssuancePolicy {
            maximum_lifetime_ms: 86_400_000,
            allowed_clock_skew_ms: 60_000,
        }
    }

    fn authority() -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ClassMesh Test Authority");
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed test CA")
    }

    fn csr() -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec!["student.classmesh".to_owned()])
            .expect("leaf params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params
            .serialize_request(&key)
            .expect("CSR")
            .der()
            .to_vec()
    }

    fn approval(csr: &[u8]) -> EnrollmentApproval {
        EnrollmentApproval {
            principal_id: principal(7),
            csr_sha256: Sha256::digest(csr).into(),
        }
    }

    #[test]
    fn issues_bound_end_entity_certificate_and_fingerprint() {
        let csr = csr();
        let validity = CertificateValidity {
            not_before_unix_ms: 1_000_000,
            not_after_unix_ms: 4_600_000,
        };
        let issued = issue_certificate(
            policy(),
            1_000_000,
            principal(7),
            &csr,
            approval(&csr),
            validity,
            &authority(),
        )
        .expect("certificate should issue");

        assert_eq!(issued.principal_id, principal(7));
        assert_eq!(issued.csr_sha256, Sha256::digest(&csr).into());
        assert!(!issued.certificate_der.is_empty());
        assert_eq!(
            issued.credential_fingerprint_sha256,
            Sha256::digest(issued.certificate_der.as_ref()).into()
        );
        assert_eq!(issued.not_after_unix_ms, validity.not_after_unix_ms);
    }

    #[test]
    fn issuance_rejects_wrong_principal_before_signing() {
        let csr = csr();
        let validity = CertificateValidity {
            not_before_unix_ms: 1_000_000,
            not_after_unix_ms: 4_600_000,
        };

        assert_eq!(
            issue_certificate(
                policy(),
                1_000_000,
                principal(8),
                &csr,
                approval(&csr),
                validity,
                &authority(),
            ),
            Err(X509IssuanceError::Policy(
                CertificateIssuanceError::PrincipalBindingMismatch
            ))
        );
    }
}
