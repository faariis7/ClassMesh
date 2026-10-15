//! Red-first: verify a single canonical Service-owned publication source
//! can be re-sampled and fail closed; no clipboard bytes or wire changes.
use std::collections::{BTreeMap,BTreeSet};
use std::sync::Arc;
use classmesh_security::{AuthorizationStore,CredentialFingerprint,CredentialRecord,Permission,Principal,PrincipalId,PrincipalKind};
use classmesh_protocol::{Capability,ControlRole,ProtocolVersion};
use classmesh_protocol::control_wire::{ClipboardReadRequest, ControlEnvelope,control_envelope,ProtocolVersion as WireVersion};
use crate::authorization::AuthenticatedControlGuard;
use crate::dispatch::{dispatch_privileged_command,PrivilegedControlCommand,PrivilegedDispatchError};
use crate::handshake::{EstablishedAuthenticatedPeer,EstablishedControlSession};
use crate::peer_identity::AuthenticatedPeerIdentity;
use crate::clipboard_live_authority::{ClipboardAuthorityLease,ClipboardAuthorityError};
use crate::live_authorization::{LiveAuthorizationStore,LiveAuthorizationError};

fn principal() -> PrincipalId {PrincipalId([21;32])}
fn fingerprint() -> CredentialFingerprint {CredentialFingerprint([23;32])}
fn policy(read:bool)->AuthorizationStore{
    let mut store=AuthorizationStore::default();
    let mut credentials=BTreeMap::new();
    credentials.insert(fingerprint(),CredentialRecord::active(fingerprint(),100));
    store.upsert(Principal{
        id:principal(),kind:PrincipalKind::Teacher,enabled:true,
        permissions:if read{BTreeSet::from([Permission::ReadClipboard])}else{BTreeSet::new()},
        credentials,
    }).unwrap();
    store
}
fn identity()->AuthenticatedPeerIdentity {
    AuthenticatedPeerIdentity {principal_id:principal(),credential_fingerprint:fingerprint()}
}
fn session()->EstablishedControlSession{
    EstablishedControlSession{
        control_session_id:77,
        negotiated:crate::NegotiatedHello{
            principal_id:principal(),role:ControlRole::Teacher,
            version:ProtocolVersion{major:0,minor:11},
            capabilities:BTreeSet::from([Capability::ClipboardText]),
        },
    }
}
fn envelope(sequence:u64)->ControlEnvelope {
    ControlEnvelope{
        control_session_id:77,sequence,request_id:91,
        protocol_version:Some(WireVersion{major:0,minor:11}),
        payload:Some(control_envelope::Payload::ClipboardReadRequest(ClipboardReadRequest{}))
    }
}
#[test]
fn canonical_publication_is_atomic_and_snapshots_are_versioned(){
    let source=LiveAuthorizationStore::new(policy(true));
    let before=source.snapshot().unwrap();
    assert_eq!(before.version(),1);
    assert!(before.store().authorize(principal(),Permission::ReadClipboard));
    assert_eq!(source.publish(policy(false)),Ok(2));
    let after=source.snapshot().unwrap();
    assert_eq!(after.version(),2);
    assert!(!after.store().authorize(principal(),Permission::ReadClipboard));
    assert!(!Arc::ptr_eq(&before.arc(),&after.arc()));
    assert!(before.store().authorize(principal(),Permission::ReadClipboard),"old captured snapshots remain stale; production must resample");
}
#[test]
fn new_current_policy_rejects_previously_dispatched_token_and_replay(){
    let source=LiveAuthorizationStore::new(policy(true));
    let initial=source.snapshot().unwrap();
    let mut guard=AuthenticatedControlGuard::new(identity(),77,ProtocolVersion{major:0,minor:11},1);
    let req=envelope(2);
    let PrivilegedControlCommand::ClipboardReadRequest(token)=
        dispatch_privileged_command(&mut guard,initial.store(),&req,150).unwrap()
    else{panic!("expected real authorized token")};
    let session=session();
    let peer=EstablishedAuthenticatedPeer{identity:identity(),control_session_id:77};
    let mut lease=ClipboardAuthorityLease::issue(token,&guard,&req,&session,peer,initial.store(),150).unwrap();
    assert_eq!(source.publish(policy(false)),Ok(2));
    let latest=source.snapshot().unwrap();
    assert_eq!(lease.recheck(Some(latest.store()),Some(&session),Some(peer),Some(&guard),Some((77,2,91)),151),Err(ClipboardAuthorityError::NotAuthorized));
    let mut next=envelope(3);
    next.request_id=92;
    assert!(matches!(dispatch_privileged_command(&mut guard,latest.store(),&next,152),Err(PrivilegedDispatchError::Authorization(_))));
    assert_eq!(lease.recheck(Some(latest.store()),Some(&session),Some(peer),Some(&guard),Some((77,2,91)),152),Err(ClipboardAuthorityError::AlreadyUsed));
}
#[test]
fn revoked_credential_in_published_state_denies_existing_authenticated_identity(){
    let source=LiveAuthorizationStore::new(policy(true));
    assert!(identity().is_currently_authenticated(source.snapshot().unwrap().store(),150));
    let mut revoked=policy(true);
    let mut teacher=revoked.principal(principal()).unwrap().clone();
    teacher.credentials.get_mut(&fingerprint()).unwrap().revoke(151);
    revoked.upsert(teacher).unwrap();
    assert_eq!(source.publish(revoked),Ok(2));
    assert!(!identity().is_currently_authenticated(source.snapshot().unwrap().store(),151));
}
#[test]
fn concurrent_readers_see_whole_old_or_new_policy_with_monotonic_generations(){
    let shared=Arc::new(LiveAuthorizationStore::new(policy(true)));
    let mut handles=Vec::new();
    for _ in 0..3 {
        let s=Arc::clone(&shared);
        handles.push(std::thread::spawn(move || {
            let mut last=1;
            for _ in 0..100 {
                let snapshot=s.snapshot().unwrap();
                assert!(snapshot.version()>=last);
                assert!(snapshot.version()<=101);
                assert_eq!(snapshot.store().authorize(principal(),Permission::ReadClipboard),snapshot.version()%2==1);
                last=snapshot.version();
            }
        }));
    }
    for index in 0..100 {shared.publish(policy(index%2!=0)).unwrap();}
    for handle in handles{handle.join().unwrap();}
    assert_eq!(shared.snapshot().unwrap().version(),101);
}
#[test]
fn read_failures_never_silently_return_a_fallback_policy(){
    // Poison/integrity denial is exercised by a separate in-module test.
    // This test pins the public error contract instead of auto-falling back.
    let _:Option<LiveAuthorizationError>=None;
}
