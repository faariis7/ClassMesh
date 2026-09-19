use rcgen::CertificateSigningRequestParams;
use rustls::pki_types::CertificateSigningRequestDer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrVerificationError {
    MalformedOrInvalidSignature,
}

/// Parses a PKCS#10 request and verifies its proof-of-possession signature.
///
/// Successful verification proves that the request is structurally supported by the
/// maintained parser and that the request signature matches its embedded public key.
/// Enrollment policy remains responsible for binding the exact DER bytes to the
/// approved stable principal.
pub fn verify_pkcs10_csr(csr_der: &[u8]) -> Result<(), CsrVerificationError> {
    let csr = CertificateSigningRequestDer::from(csr_der);
    CertificateSigningRequestParams::from_der(&csr)
        .map(|_| ())
        .map_err(|_| CsrVerificationError::MalformedOrInvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    #[test]
    fn valid_signed_pkcs10_request_is_accepted() {
        let key = KeyPair::generate().expect("test key");
        let request = CertificateParams::new(Vec::<String>::new())
            .expect("params")
            .serialize_request(&key)
            .expect("CSR");

        verify_pkcs10_csr(request.der()).expect("valid signed CSR");
    }

    #[test]
    fn malformed_and_tampered_requests_are_rejected() {
        assert_eq!(
            verify_pkcs10_csr(&[0x30, 0x01, 0x00]),
            Err(CsrVerificationError::MalformedOrInvalidSignature)
        );

        let key = KeyPair::generate().expect("test key");
        let request = CertificateParams::new(Vec::<String>::new())
            .expect("params")
            .serialize_request(&key)
            .expect("CSR");
        let mut tampered = request.der().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert_eq!(
            verify_pkcs10_csr(&tampered),
            Err(CsrVerificationError::MalformedOrInvalidSignature)
        );
    }
}
