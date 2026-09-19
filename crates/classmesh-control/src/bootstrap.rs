use classmesh_security::PrincipalId;

pub const SHA256_BYTES: usize = 32;
pub const BOOTSTRAP_NONCE_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapAuthority {
    pub certificate_fingerprint_sha256: [u8; SHA256_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapChallenge {
    pub principal_id: PrincipalId,
    pub client_nonce: [u8; BOOTSTRAP_NONCE_BYTES],
    pub authority_fingerprint_sha256: [u8; SHA256_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapTrustError {
    AuthorityMismatch,
    PrincipalMismatch,
    NonceMismatch,
}

impl BootstrapAuthority {
    pub fn validate_challenge(
        self,
        expected_principal: PrincipalId,
        expected_nonce: [u8; BOOTSTRAP_NONCE_BYTES],
        challenge: BootstrapChallenge,
    ) -> Result<(), BootstrapTrustError> {
        if challenge.authority_fingerprint_sha256 != self.certificate_fingerprint_sha256 {
            return Err(BootstrapTrustError::AuthorityMismatch);
        }
        if challenge.principal_id != expected_principal {
            return Err(BootstrapTrustError::PrincipalMismatch);
        }
        if challenge.client_nonce != expected_nonce {
            return Err(BootstrapTrustError::NonceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    #[test]
    fn bootstrap_requires_explicit_authority_pin_and_request_binding() {
        let authority = BootstrapAuthority {
            certificate_fingerprint_sha256: [1; SHA256_BYTES],
        };
        let challenge = BootstrapChallenge {
            principal_id: id(7),
            client_nonce: [2; BOOTSTRAP_NONCE_BYTES],
            authority_fingerprint_sha256: [1; SHA256_BYTES],
        };

        authority
            .validate_challenge(id(7), [2; BOOTSTRAP_NONCE_BYTES], challenge)
            .expect("pinned authority and request binding should pass");

        assert_eq!(
            authority.validate_challenge(
                id(7),
                [2; BOOTSTRAP_NONCE_BYTES],
                BootstrapChallenge {
                    authority_fingerprint_sha256: [9; SHA256_BYTES],
                    ..challenge
                },
            ),
            Err(BootstrapTrustError::AuthorityMismatch)
        );
        assert_eq!(
            authority.validate_challenge(id(8), [2; BOOTSTRAP_NONCE_BYTES], challenge),
            Err(BootstrapTrustError::PrincipalMismatch)
        );
        assert_eq!(
            authority.validate_challenge(id(7), [3; BOOTSTRAP_NONCE_BYTES], challenge),
            Err(BootstrapTrustError::NonceMismatch)
        );
    }
}
