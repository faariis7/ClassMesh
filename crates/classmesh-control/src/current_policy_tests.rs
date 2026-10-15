//! TDD RED for canonical, locked, revisioned Service policy source.
use std::collections::{BTreeMap,BTreeSet};
use std::panic::{catch_unwind,AssertUnwindSafe};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission,
    Principal,PrincipalId,PrincipalKind,
};
use crate::current_policy::{CurrentAuthorizationPolicy,CurrentPolicyError};

fn pid()->PrincipalId { PrincipalId([7;32]) }
fn fp()->CredentialFingerprint { CredentialFingerprint([9;32]) }
fn make_policy(read:bool)->AuthorizationStore {
    let mut store=AuthorizationStore::default();
    let mut credentials=BTreeMap::new();
    credentials.insert(fp(),CredentialRecord::active(fp(),100));
    let mut permissions=BTreeSet::new();
    if read { permissions.insert(Permission::ReadClipboard); }
    store.upsert(Principal {
        id:pid(),kind:PrincipalKind::Teacher,enabled:true,permissions,credentials
    }).unwrap();
    store
}
fn is_allowed(store:&AuthorizationStore)->bool {
    store.principal_for_credential(fp(),150)==Some(pid())
        && store.authorize_credential(fp(),Permission::ReadClipboard,150)
}

#[test]
fn actual_policy_change_is_visible_to_new_reads_with_strict_revision() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    assert_eq!(policy.inspect(|store,rev|(rev,is_allowed(store))),Ok((1,true)));
    assert_eq!(policy.publish(1,make_policy(false)),Ok(2));
    assert_eq!(policy.inspect(|store,rev|(rev,is_allowed(store))),Ok((2,false)));
}

#[test]
fn stale_publisher_cannot_resurrect_revoked_permission() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    assert_eq!(policy.publish(1,make_policy(false)),Ok(2));
    assert_eq!(policy.publish(1,make_policy(true)),Err(CurrentPolicyError::StaleRevision));
    assert_eq!(policy.inspect(|store,rev|(rev,is_allowed(store))),Ok((2,false)));
}

#[test]
fn credential_revocation_and_principal_disable_use_real_security_store() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    let mut revoked=make_policy(true);
    let mut teacher=revoked.principal(pid()).unwrap().clone();
    teacher.credentials.get_mut(&fp()).unwrap().revoke(150);
    revoked.upsert(teacher).unwrap();
    assert_eq!(policy.publish(1,revoked),Ok(2));
    assert_eq!(policy.inspect(|store,_|is_allowed(store)),Ok(false));

    let mut disabled=make_policy(true);
    assert!(disabled.disable(pid()));
    assert_eq!(policy.publish(2,disabled),Ok(3));
    assert_eq!(policy.inspect(|store,rev|(rev,is_allowed(store))),Ok((3,false)));
}

#[test]
fn panicking_current_policy_inspector_poisoned_lock_fails_closed() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _=policy.inspect(|_store,_rev|panic!("simulated abort during policy validation"));
    })).is_err());
    assert_eq!(policy.inspect(|store,_|is_allowed(store)),Err(CurrentPolicyError::Unavailable));
    assert_eq!(policy.publish(1,make_policy(true)),Err(CurrentPolicyError::Unavailable));
}

#[test]
fn panicking_service_writer_does_not_silently_recover_poisoned_source() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _=policy.update_if_current(1,|_store|panic!("simulated trusted reload failed"));
    })).is_err());
    assert_eq!(policy.inspect(|store,_|is_allowed(store)),Err(CurrentPolicyError::Unavailable));
}

#[test]
fn active_permission_update_is_atomic_with_revision_and_safely_fails_stale_writer() {
    let policy=CurrentAuthorizationPolicy::new(make_policy(true));
    assert_eq!(policy.update_if_current(1,|store|{
        let mut teacher=store.principal(pid()).unwrap().clone();
        teacher.permissions.remove(&Permission::ReadClipboard);
        store.upsert(teacher).unwrap();
    }),Ok(2));
    assert_eq!(policy.inspect(|store,rev|(rev,is_allowed(store))),Ok((2,false)));
    assert_eq!(policy.update_if_current(1,|_|{}),Err(CurrentPolicyError::StaleRevision));
}

#[test]
fn in_flight_authorized_teacher_read_is_revoked_from_same_policy_source() {
    use classmesh_protocol::{Capability,ControlRole,ProtocolVersion};
    use classmesh_protocol::control_wire::{
        ClipboardReadRequest,ControlEnvelope,control_envelope,ProtocolVersion as WireVersion,
    };
    use crate::authorization::AuthenticatedControlGuard;
    use crate::dispatch::{dispatch_privileged_command,PrivilegedControlCommand};
    use crate::clipboard_live_authority::{ClipboardAuthorityLease,ClipboardAuthorityError};
    use crate::handshake::{EstablishedControlSession,EstablishedAuthenticatedPeer};
    use crate::peer_identity::identity_for_verified_certificate_chain;
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest,Sha256};

    let certificate=CertificateDer::from(vec![0x30,0x03,0x02,0x01,0x09]);
    let credential=CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
    let mut store=AuthorizationStore::default();
    let mut credentials=BTreeMap::new();
    credentials.insert(credential,CredentialRecord::active(credential,100));
    store.upsert(Principal{id:pid(),kind:PrincipalKind::Teacher,enabled:true,
        permissions:BTreeSet::from([Permission::ReadClipboard]),credentials}).unwrap();
    let identity=identity_for_verified_certificate_chain(&store,&[certificate],150).unwrap();
    let version=ProtocolVersion{major:0,minor:11};
    let peer=EstablishedAuthenticatedPeer{identity,control_session_id:77};
    let session=EstablishedControlSession{control_session_id:77,
        negotiated:crate::NegotiatedHello{principal_id:pid(),role:ControlRole::Teacher,version,
            capabilities:BTreeSet::from([Capability::ClipboardText])}};
    let mut guard=AuthenticatedControlGuard::new(identity,77,version,1);
    let envelope=ControlEnvelope{control_session_id:77,sequence:2,request_id:91,
        protocol_version:Some(WireVersion{major:0,minor:11}),
        payload:Some(control_envelope::Payload::ClipboardReadRequest(ClipboardReadRequest{}))};
    let policy=CurrentAuthorizationPolicy::new(store);
    let mut lease=policy.inspect(|current,_|{
        let PrivilegedControlCommand::ClipboardReadRequest(token)=
            dispatch_privileged_command(&mut guard,current,&envelope,150).unwrap()
        else { panic!("real authenticated read token required") };
        ClipboardAuthorityLease::issue(token,&guard,&envelope,&session,peer,current,150).unwrap()
    }).unwrap();
    assert_eq!(policy.inspect(|current,_|lease.recheck(Some(current),Some(&session),Some(peer),
        Some(&guard),Some((77,2,91)),151)),Ok(Ok(())));
    assert_eq!(policy.update_if_current(1,|current|{
        let mut teacher=current.principal(pid()).unwrap().clone();
        teacher.permissions.remove(&Permission::ReadClipboard);
        current.upsert(teacher).unwrap();
    }),Ok(2));
    assert_eq!(policy.inspect(|current,_|lease.recheck(Some(current),Some(&session),Some(peer),
        Some(&guard),Some((77,2,91)),152)),Ok(Err(ClipboardAuthorityError::NotAuthorized)));
    assert!(!lease.is_pending());
}
