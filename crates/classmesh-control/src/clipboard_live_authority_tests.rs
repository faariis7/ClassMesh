//! Future-v12 control-only: real authorization store + enrolled identity,
//! intentionally no worker, clipboard, payload or production Service hookup.
use crate::NegotiatedHello;
use crate::authorization::AuthenticatedControlGuard;
use crate::clipboard_live_authority::{ClipboardAuthorityError, ClipboardAuthorityLease};
use crate::dispatch::{PrivilegedControlCommand, dispatch_privileged_command};
use crate::handshake::{EstablishedAuthenticatedPeer, EstablishedControlSession};
use crate::peer_identity::identity_for_verified_certificate_chain;
use classmesh_protocol::control_wire::{
    ClipboardReadRequest, ControlEnvelope, ProtocolVersion as WireVersion, control_envelope,
};
use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const VERSION: ProtocolVersion = ProtocolVersion {
    major: 0,
    minor: 11,
};
const START_MS: u64 = 150;

struct Fixture {
    store: AuthorizationStore,
    session: EstablishedControlSession,
    peer: EstablishedAuthenticatedPeer,
    guard: AuthenticatedControlGuard,
    envelope: ControlEnvelope,
    credential: CredentialFingerprint,
    principal: PrincipalId,
}
fn fixture() -> Fixture {
    // The test fixture intentionally uses a synthetic leaf certificate;
    // the production server_hello_enrolled TLS path verifies real mTLS.
    let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x09]);
    let credential = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
    let principal = PrincipalId([7; 32]);
    let mut credentials = BTreeMap::new();
    credentials.insert(credential, CredentialRecord::active(credential, 100));
    let mut store = AuthorizationStore::default();
    store
        .upsert(Principal {
            id: principal,
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions: BTreeSet::from([Permission::ReadClipboard]),
            credentials,
        })
        .unwrap();
    let identity =
        identity_for_verified_certificate_chain(&store, &[certificate], START_MS).unwrap();
    let peer = EstablishedAuthenticatedPeer {
        identity,
        control_session_id: 77,
    };
    let session = EstablishedControlSession {
        control_session_id: 77,
        negotiated: NegotiatedHello {
            principal_id: principal,
            role: ControlRole::Teacher,
            version: VERSION,
            capabilities: BTreeSet::from([Capability::ClipboardText]),
        },
    };
    let guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
    let envelope = ControlEnvelope {
        control_session_id: 77,
        sequence: 2,
        request_id: 91,
        protocol_version: Some(WireVersion {
            major: 0,
            minor: 11,
        }),
        payload: Some(control_envelope::Payload::ClipboardReadRequest(
            ClipboardReadRequest {},
        )),
    };
    Fixture {
        store,
        session,
        peer,
        guard,
        envelope,
        credential,
        principal,
    }
}
fn issue(f: &mut Fixture) -> ClipboardAuthorityLease {
    let PrivilegedControlCommand::ClipboardReadRequest(token) =
        dispatch_privileged_command(&mut f.guard, &f.store, &f.envelope, START_MS).unwrap()
    else {
        panic!("authorized read token required")
    };
    ClipboardAuthorityLease::issue(
        token,
        &f.guard,
        &f.envelope,
        &f.session,
        f.peer,
        &f.store,
        START_MS,
    )
    .unwrap()
}
fn check(
    lease: &mut ClipboardAuthorityLease,
    f: &Fixture,
    time: u64,
) -> Result<(), ClipboardAuthorityError> {
    lease.recheck(
        Some(&f.store),
        Some(&f.session),
        Some(f.peer),
        Some(&f.guard),
        Some((77, 2, 91)),
        time,
    )
}
#[test]
fn actual_dispatch_token_and_live_store_allow_only_one_final_result() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert_eq!(check(&mut lease, &f, 151), Ok(()));
    assert_eq!(
        lease.finish(
            Some(&f.store),
            Some(&f.session),
            Some(f.peer),
            Some(&f.guard),
            Some((77, 2, 91)),
            152
        ),
        Ok(())
    );
    assert_eq!(
        check(&mut lease, &f, 153),
        Err(ClipboardAuthorityError::AlreadyUsed)
    );
}
#[test]
fn removing_read_permission_from_real_store_revokes_midflight() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    let mut principal = f.store.principal(f.principal).unwrap().clone();
    principal.permissions.remove(&Permission::ReadClipboard);
    f.store.upsert(principal).unwrap();
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::NotAuthorized)
    );
    assert_eq!(
        check(&mut lease, &f, 152),
        Err(ClipboardAuthorityError::AlreadyUsed)
    );
}
#[test]
fn disabling_principal_or_revoking_real_credential_denies() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert!(f.store.disable(f.principal));
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::NotAuthorized)
    );
    let mut f = fixture();
    let mut lease = issue(&mut f);
    let mut principal = f.store.principal(f.principal).unwrap().clone();
    principal
        .credentials
        .get_mut(&f.credential)
        .unwrap()
        .revoke(151);
    f.store.upsert(principal).unwrap();
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::NotAuthorized)
    );
}
#[test]
fn credential_expiry_is_rechecked_not_cached_from_initial_dispatch() {
    let mut f = fixture();
    let mut principal = f.store.principal(f.principal).unwrap().clone();
    principal
        .credentials
        .get_mut(&f.credential)
        .unwrap()
        .expires_at_unix_ms = Some(160);
    f.store.upsert(principal).unwrap();
    let mut lease = issue(&mut f);
    assert_eq!(check(&mut lease, &f, 159), Ok(()));
    assert_eq!(
        check(&mut lease, &f, 160),
        Err(ClipboardAuthorityError::NotAuthorized)
    );
}
#[test]
fn missing_capability_or_replaced_control_session_fail_closed() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    f.session.negotiated.capabilities.clear();
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::CapabilityGone)
    );
    let mut f = fixture();
    let mut lease = issue(&mut f);
    f.session.control_session_id = 78;
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::SessionChanged)
    );
    let mut f = fixture();
    let mut lease = issue(&mut f);
    f.peer.control_session_id = 78;
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::SessionChanged)
    );
}
#[test]
fn unavailable_store_or_replaced_peer_poison_existing_lease() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert_eq!(
        lease.recheck(
            None,
            Some(&f.session),
            Some(f.peer),
            Some(&f.guard),
            Some((77, 2, 91)),
            151
        ),
        Err(ClipboardAuthorityError::AuthorityUnavailable)
    );
    assert_eq!(
        check(&mut lease, &f, 152),
        Err(ClipboardAuthorityError::AlreadyUsed)
    );
    let mut f = fixture();
    let mut lease = issue(&mut f);
    f.peer.identity = fixture().peer.identity; // same identity is harmless
    assert!(check(&mut lease, &f, 151).is_ok());
    f.guard = AuthenticatedControlGuard::new(f.peer.identity, 78, VERSION, 2);
    assert_eq!(
        check(&mut lease, &f, 152),
        Err(ClipboardAuthorityError::SessionChanged)
    );
}
#[test]
fn unauthorized_creation_or_invalid_request_cannot_issue() {
    let mut f = fixture();
    f.session.negotiated.capabilities.clear();
    let PrivilegedControlCommand::ClipboardReadRequest(token) =
        dispatch_privileged_command(&mut f.guard, &f.store, &f.envelope, START_MS).unwrap()
    else {
        panic!("expected dispatch token")
    };
    assert_eq!(
        ClipboardAuthorityLease::issue(
            token,
            &f.guard,
            &f.envelope,
            &f.session,
            f.peer,
            &f.store,
            START_MS
        )
        .err(),
        Some(ClipboardAuthorityError::CapabilityGone)
    );
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert_eq!(
        check(&mut lease, &f, 149),
        Err(ClipboardAuthorityError::ClockRegression)
    );
}

#[test]
fn switching_current_pending_request_cannot_reuse_lease() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert_eq!(
        lease.recheck(
            Some(&f.store),
            Some(&f.session),
            Some(f.peer),
            Some(&f.guard),
            Some((77, 2, 999)),
            151
        ),
        Err(ClipboardAuthorityError::PendingRequestChanged)
    );
    assert_eq!(
        check(&mut lease, &f, 152),
        Err(ClipboardAuthorityError::AlreadyUsed)
    );
}

#[test]
fn removing_enrolled_teacher_role_fails_closed() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    let mut principal = f.store.principal(f.principal).unwrap().clone();
    principal.kind = PrincipalKind::StudentDevice;
    f.store.upsert(principal).unwrap();
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::NotAuthorized)
    );
    assert!(!lease.is_pending());
}
#[test]
fn wrong_pending_session_or_sequence_is_never_authorized() {
    for pending in [
        Some((78, 2, 91)),
        Some((77, 3, 91)),
        Some((77, 2, 92)),
        None,
    ] {
        let mut f = fixture();
        let mut lease = issue(&mut f);
        assert_eq!(
            lease.recheck(
                Some(&f.store),
                Some(&f.session),
                Some(f.peer),
                Some(&f.guard),
                pending,
                151
            ),
            Err(ClipboardAuthorityError::PendingRequestChanged)
        );
        assert_eq!(
            check(&mut lease, &f, 152),
            Err(ClipboardAuthorityError::AlreadyUsed)
        );
    }
}
#[test]
fn control_lease_does_not_survive_monotonic_deadline_or_cancel() {
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert_eq!(
        check(&mut lease, &f, START_MS + 2500),
        Err(ClipboardAuthorityError::Expired)
    );
    assert!(!lease.is_pending());
    let mut f = fixture();
    let mut lease = issue(&mut f);
    assert!(lease.cancel());
    assert!(!lease.cancel());
    assert_eq!(
        check(&mut lease, &f, 151),
        Err(ClipboardAuthorityError::AlreadyUsed)
    );
}
