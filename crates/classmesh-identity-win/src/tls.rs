use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use p256::ecdsa::Signature;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, alg_id::ECDSA_P256};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::cng::{CngKeyError, CngMachineKey};

const SHA256_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct CngRustlsSigningKey {
    key: CngMachineKey,
    public_key_spki: SubjectPublicKeyInfoDer<'static>,
}

#[derive(Debug, Clone)]
struct CngRustlsSigner {
    key: CngMachineKey,
}

#[derive(Debug)]
pub enum CngTlsError {
    Key(CngKeyError),
    Rustls(Error),
}

impl Display for CngTlsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(error) => write!(formatter, "CNG key error: {error}"),
            Self::Rustls(error) => write!(formatter, "rustls key error: {error}"),
        }
    }
}

impl StdError for CngTlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::Rustls(error) => Some(error),
        }
    }
}

impl From<CngKeyError> for CngTlsError {
    fn from(error: CngKeyError) -> Self {
        Self::Key(error)
    }
}

impl From<Error> for CngTlsError {
    fn from(error: Error) -> Self {
        Self::Rustls(error)
    }
}

impl CngRustlsSigningKey {
    pub fn new(key: CngMachineKey) -> Result<Self, CngKeyError> {
        let public_key_sec1 = key.public_key_sec1()?;
        let public_key_spki = public_key_to_spki(&ECDSA_P256, &public_key_sec1);
        Ok(Self {
            key,
            public_key_spki,
        })
    }
}

impl SigningKey for CngRustlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(CngRustlsSigner {
                    key: self.key.clone(),
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.public_key_spki.clone())
    }
}

impl Signer for CngRustlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest: [u8; SHA256_BYTES] = Sha256::digest(message).into();
        let raw_signature = self
            .key
            .sign_sha256_digest(&digest)
            .map_err(|error| Error::General(format!("CNG TLS signing failed: {error}")))?;
        let signature = Signature::from_slice(&raw_signature)
            .map_err(|_| Error::General("CNG returned an invalid P-256 signature".to_owned()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn cng_certified_key(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: CngMachineKey,
) -> Result<CertifiedKey, CngTlsError> {
    let signing_key = Arc::new(CngRustlsSigningKey::new(key)?);
    let certified_key = CertifiedKey::new(certificate_chain, signing_key);
    certified_key.keys_match()?;
    Ok(certified_key)
}

pub fn cng_client_cert_resolver(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: CngMachineKey,
) -> Result<Arc<dyn ResolvesClientCert>, CngTlsError> {
    Ok(Arc::new(SingleCertAndKey::from(cng_certified_key(
        certificate_chain,
        key,
    )?)))
}

pub fn cng_server_cert_resolver(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: CngMachineKey,
) -> Result<Arc<dyn ResolvesServerCert>, CngTlsError> {
    Ok(Arc::new(SingleCertAndKey::from(cng_certified_key(
        certificate_chain,
        key,
    )?)))
}

#[cfg(test)]
mod tests {
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyUsagePurpose,
    };

    use crate::CngRcgenSigningKey;

    use super::*;

    fn unique_key_name(label: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        format!("ClassMesh-TLS-{label}-{}-{nonce}", process::id())
    }

    struct TestKeyCleanup {
        name: String,
    }

    impl TestKeyCleanup {
        fn new(name: String) -> Self {
            Self { name }
        }
    }

    impl Drop for TestKeyCleanup {
        fn drop(&mut self) {
            if let Ok(key) = CngMachineKey::open(self.name.clone()) {
                let _ = key.delete();
            }
        }
    }

    fn self_signed_certificate(key: CngMachineKey) -> CertificateDer<'static> {
        let adapter = CngRcgenSigningKey::new(key).expect("rcgen adapter");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "ClassMesh TLS Test");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        CertifiedIssuer::self_signed(params, adapter)
            .expect("CNG key should self-sign")
            .der()
            .clone()
    }

    #[test]
    fn rustls_signer_selects_only_p256_sha256_and_signs_without_export() {
        let name = unique_key_name("sign");
        let _cleanup = TestKeyCleanup::new(name.clone());
        let key = CngMachineKey::create(name).expect("machine key");
        let verifier = key.clone();
        assert_eq!(verifier.export_policy().expect("export policy"), 0);

        let signing_key = CngRustlsSigningKey::new(key).expect("rustls signing key");
        assert!(
            signing_key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        let signer = signing_key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("P-256 SHA-256 should be supported");

        let message = b"ClassMesh TLS CertificateVerify";
        let signature_der = signer.sign(message).expect("TLS signature");
        let signature = Signature::from_der(&signature_der).expect("DER ECDSA signature");
        let digest: [u8; SHA256_BYTES] = Sha256::digest(message).into();
        assert!(
            verifier
                .verify_sha256_digest(&digest, signature.to_bytes().as_ref())
                .expect("CNG verification")
        );
        assert_eq!(verifier.export_policy().expect("export policy"), 0);
    }

    #[test]
    fn server_resolver_requires_certificate_to_match_protected_key() {
        let name = unique_key_name("server-match");
        let other_name = unique_key_name("server-mismatch");
        let _cleanup = TestKeyCleanup::new(name.clone());
        let _other_cleanup = TestKeyCleanup::new(other_name.clone());
        let key = CngMachineKey::create(name).expect("machine key");
        let other = CngMachineKey::create(other_name).expect("other machine key");
        let certificate = self_signed_certificate(key.clone());

        cng_server_cert_resolver(vec![certificate.clone()], key)
            .expect("matching server certificate and CNG key should resolve");
        assert!(cng_server_cert_resolver(vec![certificate], other).is_err());
    }

    #[test]
    fn client_resolver_requires_certificate_to_match_protected_key() {
        let name = unique_key_name("match");
        let other_name = unique_key_name("mismatch");
        let _cleanup = TestKeyCleanup::new(name.clone());
        let _other_cleanup = TestKeyCleanup::new(other_name.clone());
        let key = CngMachineKey::create(name).expect("machine key");
        let other = CngMachineKey::create(other_name).expect("other machine key");
        let certificate = self_signed_certificate(key.clone());

        cng_client_cert_resolver(vec![certificate.clone()], key)
            .expect("matching certificate and CNG key should resolve");
        assert!(cng_client_cert_resolver(vec![certificate], other).is_err());
    }
}
