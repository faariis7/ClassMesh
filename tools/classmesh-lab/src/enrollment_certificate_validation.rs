//! Offline enrollment validation against operator-supplied roots, never result-supplied trust.
//! This validates staging material, not DNS peer identity, revocation or production installation.
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult};
use rcgen::{CertificateSigningRequestParams, PublicKeyData};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, UnixTime};

use crate::enrollment_cli_role::EnrollmentCliRole;

type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn validate_signed_result(
    request: &EnrollmentRequest,
    result: &EnrollmentResult,
    roots: &[Vec<u8>],
    now_unix_ms: u64,
    role: EnrollmentCliRole,
) -> AppResult {
    let leaf = result
        .certificate_chain_der
        .first()
        .ok_or("missing leaf certificate")?;
    let (trailing, parsed) =
        x509_parser::parse_x509_certificate(leaf).map_err(|_| "invalid leaf certificate")?;
    if !trailing.is_empty() || parsed.basic_constraints()?.is_some_and(|e| e.value.ca) {
        return Err("expected exactly one end-entity certificate".into());
    }
    let expiry = u64::try_from(parsed.validity().not_after.timestamp())?;
    if result.not_after_unix_ms / 1000 != expiry {
        return Err("result expiry does not match signed leaf expiry".into());
    }
    let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
        request.pkcs10_csr_der.as_slice(),
    ))
    .map_err(|e| format!("invalid CSR proof of possession: {e}"))?;
    if csr.public_key.der_bytes() != parsed.public_key().subject_public_key.data.as_ref() {
        return Err("certificate public key does not match the approved CSR".into());
    }
    let mut store = RootCertStore::empty();
    if roots.is_empty() || roots.len() > 16 {
        return Err("explicit bounded trust roots required".into());
    }
    for root in roots {
        if root.is_empty() || root.len() > 65536 {
            return Err("invalid trust-root size".into());
        }
        store.add(CertificateDer::from(root.clone()))?;
    }
    let chain: Vec<_> = result
        .certificate_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let now = UnixTime::since_unix_epoch(Duration::from_millis(now_unix_ms));
    match role {
        EnrollmentCliRole::Teacher => {
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider)
                .build()?
                .verify_client_cert(&chain[0], &chain[1..], now)?;
        }
        EnrollmentCliRole::StudentDevice => {
            let certificate = rustls::server::ParsedCertificate::try_from(&chain[0])?;
            rustls::client::verify_server_cert_signed_by_trust_anchor(
                &certificate,
                &store,
                &chain[1..],
                now,
                provider.signature_verification_algorithms.all,
            )?;
        }
    }
    Ok(())
}
