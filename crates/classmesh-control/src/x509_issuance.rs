use std::time::{Duration, SystemTime};

use classmesh_security::PrincipalId;
use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    SanType, SigningKey,
};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, ServerName};
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
    InvalidServerName,
    InvalidTimestamp,
    SigningFailed(String),
}

pub struct EnrollmentCertificateRequest<'a> {
    pub principal_id: PrincipalId,
    pub csr_der: &'a [u8],
    pub approval: EnrollmentApproval,
    pub approved_server_name: Option<ServerName<'a>>,
}

/// Issues a ClassMesh end-entity certificate from an already approved PKCS#10 CSR.
///
/// The issuance policy first binds the exact CSR bytes to the approved stable
/// PrincipalId and verifies PKCS#10 proof-of-possession. The authority then
/// overrides security-sensitive certificate properties instead of trusting CSR
/// requests for CA/basic-constraints, key-usage privileges or server identities.
pub fn issue_certificate<S: SigningKey>(
    policy: CertificateIssuancePolicy,
    now_unix_ms: u64,
    enrollment: EnrollmentCertificateRequest<'_>,
    validity: CertificateValidity,
    issuer: &Issuer<'_, S>,
) -> Result<IssuedCertificate, X509IssuanceError> {
    let EnrollmentCertificateRequest {
        principal_id,
        csr_der,
        approval,
        approved_server_name,
    } = enrollment;
    policy
        .validate(now_unix_ms, principal_id, csr_der, approval, validity)
        .map_err(X509IssuanceError::Policy)?;

    let csr_der = CertificateSigningRequestDer::from(csr_der);
    let mut request = CertificateSigningRequestParams::from_der(&csr_der)
        .map_err(|_| X509IssuanceError::InvalidCsr)?;

    request.params.subject_alt_names = match approved_server_name {
        Some(ServerName::DnsName(name)) => vec![SanType::DnsName(
            name.as_ref()
                .trim_end_matches('.')
                .try_into()
                .map_err(|_| X509IssuanceError::InvalidServerName)?,
        )],
        Some(ServerName::IpAddress(address)) => vec![SanType::IpAddress(address.into())],
        Some(_) => return Err(X509IssuanceError::InvalidServerName),
        None => Vec::new(),
    };
    request.params.not_before = unix_ms_to_system_time(validity.not_before_unix_ms)?.into();
    request.params.not_after = unix_ms_to_system_time(validity.not_after_unix_ms)?.into();
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
    use std::sync::Arc;

    use quinn::Endpoint;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, KeyPair};
    use rustls::RootCertStore;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::server::WebPkiClientVerifier;
    use rustls::sign::{CertifiedKey, SingleCertAndKey};

    use super::*;
    use crate::quic::{accept, connect, enrolled_client_config, enrolled_server_config};

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
        let params =
            CertificateParams::new(vec!["student.classmesh".to_owned()]).expect("leaf params");
        params.serialize_request(&key).expect("CSR").der().to_vec()
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
            EnrollmentCertificateRequest {
                principal_id: principal(7),
                csr_der: &csr,
                approval: approval(&csr),
                approved_server_name: None,
            },
            validity,
            &authority(),
        )
        .expect("certificate should issue");

        assert_eq!(issued.principal_id, principal(7));
        let expected_csr_sha256: [u8; SHA256_BYTES] = Sha256::digest(&csr).into();
        assert_eq!(issued.csr_sha256, expected_csr_sha256);
        assert!(!issued.certificate_der.is_empty());
        let expected_fingerprint: [u8; SHA256_BYTES] =
            Sha256::digest(issued.certificate_der.as_ref()).into();
        assert_eq!(issued.credential_fingerprint_sha256, expected_fingerprint);
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
                EnrollmentCertificateRequest {
                    principal_id: principal(8),
                    csr_der: &csr,
                    approval: approval(&csr),
                    approved_server_name: None,
                },
                validity,
                &authority(),
            ),
            Err(X509IssuanceError::Policy(
                CertificateIssuanceError::PrincipalBindingMismatch
            ))
        );
    }

    #[tokio::test]
    async fn student_enrollment_supports_authority_approved_quic_server_names() {
        let issuer = authority();
        let mut roots = RootCertStore::empty();
        roots.add(issuer.der().clone()).expect("enrollment root");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
                .build()
                .expect("enrolled Teacher verifier");
        let now = u64::try_from(
            SystemTime::UNIX_EPOCH
                .elapsed()
                .expect("test time")
                .as_millis(),
        )
        .expect("test Unix time");
        let validity = CertificateValidity {
            not_before_unix_ms: now,
            not_after_unix_ms: now + 3_600_000,
        };
        let teacher_key = KeyPair::generate().expect("Teacher key");
        let teacher_csr = CertificateParams::new(Vec::<String>::new())
            .expect("Teacher CSR params")
            .serialize_request(&teacher_key)
            .expect("Teacher CSR");
        let teacher_csr = teacher_csr.der().as_ref();
        let teacher_cert = issue_certificate(
            policy(),
            now,
            EnrollmentCertificateRequest {
                principal_id: principal(7),
                csr_der: teacher_csr,
                approval: approval(teacher_csr),
                approved_server_name: None,
            },
            validity,
            &issuer,
        )
        .expect("Teacher enrollment");
        let teacher_signer = CertifiedKey::from_der(
            vec![teacher_cert.certificate_der],
            PrivatePkcs8KeyDer::from(teacher_key.serialize_der()).into(),
            &provider,
        )
        .expect("Teacher signer");
        let listen = "127.0.0.1:0".parse().expect("loopback address");
        let mut teacher = Endpoint::client(listen).expect("Teacher QUIC endpoint");
        teacher.set_default_client_config(
            enrolled_client_config(roots, Arc::new(SingleCertAndKey::from(teacher_signer)))
                .expect("enrolled Teacher TLS config"),
        );

        for (approved_name, requested_names) in [
            ("student.classmesh", Vec::new()),
            ("127.0.0.1", vec!["unapproved.classmesh".to_owned()]),
        ] {
            let student_key = KeyPair::generate().expect("Student key");
            let student_csr = CertificateParams::new(requested_names)
                .expect("Student CSR params")
                .serialize_request(&student_key)
                .expect("Student CSR");
            let student_csr = student_csr.der().as_ref();
            let student_approval = EnrollmentApproval {
                principal_id: principal(8),
                csr_sha256: Sha256::digest(student_csr).into(),
            };
            let student_cert = issue_certificate(
                policy(),
                now,
                EnrollmentCertificateRequest {
                    principal_id: principal(8),
                    csr_der: student_csr,
                    approval: student_approval,
                    approved_server_name: Some(
                        ServerName::try_from(approved_name).expect("approved Student name"),
                    ),
                },
                validity,
                &issuer,
            )
            .expect("Student enrollment");
            let student = Endpoint::server(
                enrolled_server_config(
                    vec![student_cert.certificate_der],
                    PrivatePkcs8KeyDer::from(student_key.serialize_der()).into(),
                    client_verifier.clone(),
                )
                .expect("enrolled Student TLS config"),
                listen,
            )
            .expect("Student QUIC endpoint");
            let address = student.local_addr().expect("Student address");
            let (teacher_peer, student_peer) =
                tokio::join!(connect(&teacher, address, approved_name), accept(&student));
            assert!(
                teacher_peer.is_ok(),
                "Teacher rejected the enrolled Student at {approved_name}: {:?}",
                teacher_peer.err()
            );
            let student_peer = student_peer.expect("Student accepts the enrolled Teacher");
            assert!(student_peer.peer_identity().is_some());
            student_peer.close(0_u32.into(), b"enrollment verified");

            let (teacher_peer, student_peer) = tokio::join!(
                connect(&teacher, address, "unapproved.classmesh"),
                accept(&student)
            );
            let rejected = teacher_peer.expect_err("unapproved name must fail TLS");
            assert!(
                rejected
                    .to_string()
                    .contains("certificate not valid for name"),
                "{rejected}"
            );
            assert!(student_peer.is_err());
        }
    }
}
