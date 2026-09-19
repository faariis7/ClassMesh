use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, Permission, PrincipalId,
};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPeerIdentity {
    pub principal_id: PrincipalId,
    pub credential_fingerprint: CredentialFingerprint,
}

impl AuthenticatedPeerIdentity {
    #[must_use]
    pub fn is_currently_authenticated(
        self,
        authorization: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> bool {
        authorization.principal_for_credential(self.credential_fingerprint, now_unix_ms)
            == Some(self.principal_id)
    }

    #[must_use]
    pub fn authorize(
        self,
        authorization: &AuthorizationStore,
        permission: Permission,
        now_unix_ms: u64,
    ) -> bool {
        self.is_currently_authenticated(authorization, now_unix_ms)
            && authorization.authorize(self.principal_id, permission)
    }
}

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
pub fn identity_for_verified_certificate_chain(
    authorization: &AuthorizationStore,
    certificate_chain: &[CertificateDer<'_>],
    now_unix_ms: u64,
) -> Result<AuthenticatedPeerIdentity, PeerIdentityError> {
    let leaf = certificate_chain
        .first()
        .ok_or(PeerIdentityError::EmptyCertificateChain)?;
    let credential_fingerprint = CredentialFingerprint(Sha256::digest(leaf.as_ref()).into());
    let principal_id = authorization
        .principal_for_credential(credential_fingerprint, now_unix_ms)
        .ok_or(PeerIdentityError::UnknownOrInactiveCredential)?;

    Ok(AuthenticatedPeerIdentity {
        principal_id,
        credential_fingerprint,
    })
}

pub fn principal_for_verified_certificate_chain(
    authorization: &AuthorizationStore,
    certificate_chain: &[CertificateDer<'_>],
    now_unix_ms: u64,
) -> Result<PrincipalId, PeerIdentityError> {
    identity_for_verified_certificate_chain(authorization, certificate_chain, now_unix_ms)
        .map(|identity| identity.principal_id)
}

/// Resolves the peer certificate exposed by Quinn after the TLS handshake.
///
/// This function does not replace certificate-chain verification. It must only be
/// used on a connection established with the enrolled mTLS configuration.
pub fn authenticated_peer_identity(
    connection: &Connection,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
) -> Result<AuthenticatedPeerIdentity, PeerIdentityError> {
    let identity = connection
        .peer_identity()
        .ok_or(PeerIdentityError::MissingPeerIdentity)?;
    let certificate_chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| PeerIdentityError::UnexpectedPeerIdentityType)?;

    identity_for_verified_certificate_chain(authorization, &certificate_chain, now_unix_ms)
}

pub fn authenticated_peer_principal(
    connection: &Connection,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
) -> Result<PrincipalId, PeerIdentityError> {
    authenticated_peer_identity(connection, authorization, now_unix_ms)
        .map(|identity| identity.principal_id)
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
    fn authenticated_identity_rechecks_revocation_before_authorization() {
        let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x03]);
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        let mut record = Principal {
            id: principal(9),
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions: BTreeSet::from([Permission::ViewMonitoring]),
            credentials,
        };
        let mut store = AuthorizationStore::default();
        store.upsert(record.clone()).expect("principal should register");

        let identity =
            identity_for_verified_certificate_chain(&store, &[certificate], 150)
                .expect("credential should authenticate");
        assert!(identity.authorize(&store, Permission::ViewMonitoring, 150));

        record
            .revoke_credential(fingerprint, 160)
            .expect("credential should revoke");
        store.upsert(record).expect("revocation should update");

        assert!(!identity.is_currently_authenticated(&store, 160));
        assert!(!identity.authorize(&store, Permission::ViewMonitoring, 160));
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
