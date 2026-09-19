use classmesh_security::{AuthorizationStore, CredentialFingerprint, PrincipalId};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityError {
    MissingPeerIdentity,
    UnexpectedPeerIdentityType,
    EmptyCertificateChain,
    UnknownOrInactiveCredential,
}

/// Resolves a TLS-verified leaf certificate to the stable ClassMesh principal.
///
/// The certificate fingerprint is only a lookup credential. It never becomes the
/// principal identity itself, and the authorization store applies credential
/// revocation, expiry, future-issued, and principal-enabled checks.
pub fn principal_for_verified_certificate_chain(
    authorization: &AuthorizationStore,
    certificate_chain: &[CertificateDer<'_>],
    now_unix_ms: u64,
) -> Result<PrincipalId, PeerIdentityError> {
    let leaf = certificate_chain
        .first()
        .ok_or(PeerIdentityError::EmptyCertificateChain)?;
    let fingerprint = CredentialFingerprint(Sha256::digest(leaf.as_ref()).into());

    authorization
        .principal_for_credential(fingerprint, now_unix_ms)
        .ok_or(PeerIdentityError::UnknownOrInactiveCredential)
}

/// Resolves the peer certificate exposed by Quinn after the TLS handshake.
///
/// This function does not replace certificate-chain verification. It must only be
/// used on a connection established with the enrolled mTLS configuration.
pub fn authenticated_peer_principal(
    connection: &Connection,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
) -> Result<PrincipalId, PeerIdentityError> {
    let identity = connection
        .peer_identity()
        .ok_or(PeerIdentityError::MissingPeerIdentity)?;
    let certificate_chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| PeerIdentityError::UnexpectedPeerIdentityType)?;

    principal_for_verified_certificate_chain(authorization, &certificate_chain, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use classmesh_security::{
        CredentialRecord, CredentialState, Permission, Principal, PrincipalKind,
    };

    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn store_with_certificate(certificate: &CertificateDer<'_>) -> AuthorizationStore {
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));

        let record = Principal {
            id: principal(7),
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::from([Permission::ReceivePresentation]),
            credentials,
        };
        let mut store = AuthorizationStore::default();
        store.upsert(record).expect("principal should register");
        store
    }

    #[test]
    fn verified_leaf_fingerprint_resolves_to_stable_principal() {
        let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        let store = store_with_certificate(&certificate);

        assert_eq!(
            principal_for_verified_certificate_chain(&store, &[certificate], 150),
            Ok(principal(7))
        );
    }

    #[test]
    fn inactive_unknown_and_empty_credentials_are_rejected() {
        let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(
            fingerprint,
            CredentialRecord {
                fingerprint,
                state: CredentialState::Revoked,
                issued_at_unix_ms: 100,
                expires_at_unix_ms: None,
                revoked_at_unix_ms: Some(120),
            },
        );
        let record = Principal {
            id: principal(7),
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::new(),
            credentials,
        };
        let mut store = AuthorizationStore::default();
        store.upsert(record).expect("principal should register");

        assert_eq!(
            principal_for_verified_certificate_chain(&store, &[certificate], 150),
            Err(PeerIdentityError::UnknownOrInactiveCredential)
        );
        assert_eq!(
            principal_for_verified_certificate_chain(&store, &[], 150),
            Err(PeerIdentityError::EmptyCertificateChain)
        );
    }

    #[test]
    fn future_issued_credential_does_not_resolve() {
        let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x02]);
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 200));
        let record = Principal {
            id: principal(8),
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::new(),
            credentials,
        };
        let mut store = AuthorizationStore::default();
        store.upsert(record).expect("principal should register");

        assert_eq!(
            principal_for_verified_certificate_chain(&store, &[certificate], 199),
            Err(PeerIdentityError::UnknownOrInactiveCredential)
        );
    }
}
