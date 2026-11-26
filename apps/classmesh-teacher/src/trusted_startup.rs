//! Connect the installed, read-only Teacher policy to the existing native GUI.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use classmesh_control::{
    ControlHello,
    client_session::{ClientControlSession, connect_client_session_with_retries},
    live_authorization::LiveAuthorizationStore,
    quic::{DEFAULT_IO_TIMEOUT, DEFAULT_RECONNECT_POLICY, enrolled_client_config},
};
use classmesh_identity_win::{CngMachineKey, DurableMachineIdentity, cng_client_cert_resolver};
use classmesh_protocol::{Capability, ControlRole, PROTOCOL_VERSION};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, CredentialState, Principal,
    PrincipalId, PrincipalKind,
    teacher_roster::{MAX_DEVICES, RosterKey, RosterPolicy, verify_teacher_roster},
};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;
use classmesh_win32::teacher_policy::{InstalledTeacherPolicy, MAX_POLICY_BYTES};
use quinn::Endpoint;
use rustls::{
    RootCertStore,
    client::ResolvesClientCert,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::connected_command::{TeacherControlRoute, verify_current_student};

type StartupResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    version: u32,
    issuer: String,
    organization: String,
    keys: Vec<VerificationKey>,
    roster: Vec<u8>,
    roster_payload_sha256: [u8; 32],
    refreshed_at_ms: u64,
    max_age_ms: u64,
    max_lifetime_ms: u64,
    revoked_principals: Vec<[u8; 32]>,
    teacher_principal: [u8; 32],
    teacher_leaf_sha256: [u8; 32],
    teacher_enrollment_ca_der: Vec<u8>,
    machine_identity: Vec<u8>,
    student: StudentTarget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKey {
    id: String,
    sec1: Vec<u8>,
    revoked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StudentTarget {
    principal: [u8; 32],
    leaf_sha256: [u8; 32],
    address: SocketAddr,
    server_name: String,
}

struct ValidatedPolicy {
    teacher: PrincipalId,
    student: PrincipalId,
    source: MonitoringSourceId,
    target: StudentTarget,
    authorization: LiveAuthorizationStore,
    resolver: Arc<dyn ResolvesClientCert>,
    roots: RootCertStore,
    deadline_ms: u64,
}

fn validate_policy(bytes: &[u8], epoch: u64, now: u64) -> StartupResult<ValidatedPolicy> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err("protected Teacher policy exceeds its byte limit".into());
    }
    let config: PolicyDocument = serde_json::from_slice(bytes)?;
    if config.version != 1
        || config.revoked_principals.len() > MAX_DEVICES + 1
        || config.student.address.port() == 0
        || config.student.address.ip().is_unspecified()
        || config.student.address.ip().is_multicast()
        || config.student.server_name.len() > 253
        || ServerName::try_from(config.student.server_name.as_str()).is_err()
        || config.student.leaf_sha256 == [0; 32]
        || config.teacher_enrollment_ca_der.len() > 64 * 1024
    {
        return Err("invalid Teacher policy version, target, root, or revocation bounds".into());
    }
    let teacher = PrincipalId(config.teacher_principal);
    let student = PrincipalId(config.student.principal);
    let keys = config
        .keys
        .into_iter()
        .map(|key| RosterKey {
            id: key.id,
            sec1: key.sec1,
            revoked: key.revoked,
        })
        .collect::<Vec<_>>();
    let revoked: Vec<_> = config
        .revoked_principals
        .into_iter()
        .map(PrincipalId)
        .collect();
    let roster = verify_teacher_roster(
        &config.roster,
        &RosterPolicy {
            issuer: &config.issuer,
            organization: &config.organization,
            keys: &keys,
            epoch,
            payload_sha256: config.roster_payload_sha256,
            refreshed_at_ms: config.refreshed_at_ms,
            max_age_ms: config.max_age_ms,
            max_lifetime_ms: config.max_lifetime_ms,
            revoked: &revoked,
        },
        teacher,
        now,
    )?;
    let target = roster
        .device(student)
        .ok_or("protected Student target absent from signed roster")?;
    let identity = DurableMachineIdentity::parse_from_reader(config.machine_identity.as_slice())?;
    let expected_key = format!("ClassMesh-Teacher-{}", hex_principal(teacher));
    let chain: Vec<_> = identity
        .certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or("empty Teacher certificate chain")?;
    let teacher_expiry = certificate_expiry(leaf)?;
    let fingerprint: [u8; 32] = Sha256::digest(leaf).into();
    if identity.principal_id != teacher.0
        || identity.cng_key_name != expected_key
        || identity.not_after_unix_ms <= now
        || config.teacher_leaf_sha256 != fingerprint
        || identity.not_after_unix_ms / 1000 != teacher_expiry / 1000
    {
        return Err(
            "enrolled Teacher principal, role key name, leaf pin or expiry mismatch".into(),
        );
    }

    let mut issuer = RootCertStore::empty();
    issuer.add(CertificateDer::from(config.teacher_enrollment_ca_der))?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(issuer),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    verifier.verify_client_cert(
        leaf,
        intermediates,
        UnixTime::since_unix_epoch(Duration::from_millis(now)),
    )?;

    let key = CngMachineKey::open_existing_non_exportable(identity.cng_key_name)?;
    let resolver = cng_client_cert_resolver(chain, key)?;
    let mut roots = RootCertStore::empty();
    for root in identity.trust_roots_der {
        roots.add(CertificateDer::from(root))?;
    }
    if roots.is_empty() {
        return Err("enrolled Student TLS roots missing".into());
    }

    let deadline_ms = roster
        .valid_until_ms()
        .min(identity.not_after_unix_ms)
        .min(teacher_expiry);
    let fingerprint = CredentialFingerprint(config.student.leaf_sha256);
    let mut authorization = AuthorizationStore::default();
    authorization
        .upsert(Principal {
            id: student,
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::new(),
            credentials: BTreeMap::from([(
                fingerprint,
                CredentialRecord {
                    fingerprint,
                    state: CredentialState::Active,
                    issued_at_unix_ms: 0,
                    expires_at_unix_ms: Some(deadline_ms),
                    revoked_at_unix_ms: None,
                },
            )]),
        })
        .map_err(|e| io::Error::other(format!("invalid Student authorization: {e:?}")))?;

    Ok(ValidatedPolicy {
        teacher,
        student,
        source: MonitoringSourceId(target.source),
        target: config.student,
        authorization: LiveAuthorizationStore::new(authorization),
        resolver,
        roots,
        deadline_ms,
    })
}

/// Read-only exact candidate preflight used by the separate administrator tool.
/// This API returns no authority or trusted runtime object.
pub fn verify_teacher_policy_candidate(bytes: &[u8], epoch: u64) -> StartupResult<()> {
    validate_policy(bytes, epoch, unix_ms()?).map(|_| ())
}

pub(crate) struct PreparedTeacher {
    pub(crate) runtime: tokio::runtime::Runtime,
    pub(crate) endpoint: Endpoint,
    pub(crate) session: ClientControlSession,
    pub(crate) route: TeacherControlRoute,
    pub(crate) authorization: LiveAuthorizationStore,
    pub(crate) display_name: String,
    pub(crate) clock: Box<dyn Fn() -> u64 + Send>,
}

pub(crate) fn prepare_installed_teacher() -> StartupResult<PreparedTeacher> {
    let policy = InstalledTeacherPolicy::open().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("installed Teacher policy unavailable: {e}"),
        )
    })?;
    let wall_start = unix_ms()?;
    let started = Instant::now();
    let validated = validate_policy(policy.bytes(), policy.epoch(), wall_start)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (endpoint, session) = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), connect_teacher(&validated)).await?
    })?;
    let chain = session
        .connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or("Student TLS peer certificate missing")?;
    let student_leaf = chain.first().ok_or("Student TLS peer chain empty")?;
    let deadline = validated.deadline_ms.min(certificate_expiry(student_leaf)?);
    let clock = Box::new(move || {
        let time = monotonic_wall_time(wall_start, started.elapsed(), unix_ms().ok());
        if time >= deadline || !policy.still_current().unwrap_or(false) {
            return u64::MAX;
        }
        time
    });
    let now = clock();
    if now == u64::MAX {
        return Err("protected Teacher policy changed or expired during connection".into());
    }
    verify_current_student(
        validated.student,
        &session.connection,
        &validated.authorization,
        now,
    )
    .map_err(|e| io::Error::other(format!("Student identity rejected: {e:?}")))?;
    let route = TeacherControlRoute::new(
        validated.student,
        validated.source,
        session.established.control_session_id,
    )
    .map_err(|e| io::Error::other(format!("Teacher session route rejected: {e:?}")))?;
    Ok(PreparedTeacher {
        runtime,
        endpoint,
        session,
        route,
        authorization: validated.authorization,
        display_name: validated.target.server_name,
        clock,
    })
}

async fn connect_teacher(
    policy: &ValidatedPolicy,
) -> StartupResult<(Endpoint, ClientControlSession)> {
    let ip = match policy.target.address.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let mut endpoint = Endpoint::client(SocketAddr::new(ip, 0))?;
    endpoint.set_default_client_config(enrolled_client_config(
        policy.roots.clone(),
        policy.resolver.clone(),
    )?);
    let hello = ControlHello {
        principal_id: policy.teacher,
        role: ControlRole::Teacher,
        version: PROTOCOL_VERSION,
        capabilities: BTreeSet::from([Capability::TeacherMessage]),
        hostname: "ClassMesh Teacher".into(),
        app_version: env!("CARGO_PKG_VERSION").into(),
    };
    let session = connect_client_session_with_retries(
        &endpoint,
        policy.target.address,
        &policy.target.server_name,
        &hello,
        DEFAULT_IO_TIMEOUT,
        DEFAULT_RECONNECT_POLICY,
    )
    .await?;
    Ok((endpoint, session))
}

fn certificate_expiry(leaf: &CertificateDer<'_>) -> StartupResult<u64> {
    let (trailing, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| "invalid enrolled leaf DER")?;
    if !trailing.is_empty() || parsed.basic_constraints()?.is_some_and(|ext| ext.value.ca) {
        return Err("enrolled identity must be an end-entity certificate".into());
    }
    let expiry = u64::try_from(parsed.validity().not_after.timestamp())?;
    expiry
        .checked_mul(1000)
        .ok_or_else(|| "enrolled certificate expiry overflow".into())
}

fn hex_principal(principal: PrincipalId) -> String {
    principal.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_ms() -> StartupResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn monotonic_wall_time(wall_start: u64, elapsed: Duration, wall_now: Option<u64>) -> u64 {
    let elapsed = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    wall_now.map_or(u64::MAX, |now| now.max(wall_start.saturating_add(elapsed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_floor_cannot_move_backwards_with_wall_clock() {
        assert_eq!(
            monotonic_wall_time(1000, Duration::from_millis(70), Some(950)),
            1070
        );
        assert_eq!(
            monotonic_wall_time(1000, Duration::from_millis(70), Some(1500)),
            1500
        );
        assert_eq!(monotonic_wall_time(1000, Duration::ZERO, None), u64::MAX);
    }

    #[tokio::test]
    async fn signed_policy_and_cng_teacher_reach_enrolled_quic_hello() {
        use classmesh_control::{
            handshake::{ServerHelloConfig, server_hello_enrolled},
            quic::{ControlChannel, accept, enrolled_server_config},
        };
        use classmesh_identity_win::{CngRcgenSigningKey, MachineIdentityBundle};
        use classmesh_security::teacher_roster::{RosterClaims, RosterDevice, UnsignedRoster};
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose,
        };
        use ring::{
            rand::{SecureRandom, SystemRandom},
            signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
        };
        use rustls::pki_types::PrivatePkcs8KeyDer;

        struct OwnedKey(CngMachineKey);
        impl Drop for OwnedKey {
            fn drop(&mut self) {
                self.0
                    .clone()
                    .delete()
                    .expect("remove only the fixture-owned CNG key");
            }
        }

        let rng = SystemRandom::new();
        let mut teacher_bytes = [0; 32];
        rng.fill(&mut teacher_bytes).unwrap();
        let teacher = PrincipalId(teacher_bytes);
        let student = PrincipalId([8; 32]);
        let key_name = format!("ClassMesh-Teacher-{}", hex_principal(teacher));
        let owned = OwnedKey(CngMachineKey::create(&key_name).unwrap());
        assert_eq!(owned.0.export_policy().unwrap(), 0);
        let teacher_key = CngRcgenSigningKey::new(owned.0.clone()).unwrap();
        let mut authority = CertificateParams::default();
        authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        authority
            .distinguished_name
            .push(DnType::CommonName, "ClassMesh test issuer");
        authority.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let authority =
            CertifiedIssuer::self_signed(authority, KeyPair::generate().unwrap()).unwrap();
        let ca = authority.der().to_vec();
        let mut teacher_cert = CertificateParams::default();
        teacher_cert
            .distinguished_name
            .push(DnType::CommonName, "ClassMesh test Teacher");
        teacher_cert.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let teacher_cert = teacher_cert.signed_by(&teacher_key, &authority).unwrap();
        let leaf = teacher_cert.der().to_vec();
        let identity = DurableMachineIdentity::encode_canonical(&MachineIdentityBundle {
            principal_id: teacher_bytes,
            cng_key_name: key_name,
            certificate_chain_der: vec![leaf.clone(), ca.clone()],
            trust_roots_der: vec![ca.clone()],
            not_after_unix_ms: certificate_expiry(teacher_cert.der()).unwrap(),
        })
        .unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_cert = CertificateParams::new(vec!["classmesh.local".into()]).unwrap();
        server_cert.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_cert.signed_by(&server_key, &authority).unwrap();
        let mut server_roots = RootCertStore::empty();
        server_roots.add(CertificateDer::from(ca.clone())).unwrap();
        let config = enrolled_server_config(
            vec![server_cert.der().clone(), CertificateDer::from(ca.clone())],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(server_roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap(),
        )
        .unwrap();
        let server = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let now = unix_ms().unwrap();
        let grant_fingerprint = CredentialFingerprint(Sha256::digest(&leaf).into());
        let task = tokio::spawn(async move {
            let mut teacher_store = AuthorizationStore::default();
            teacher_store
                .upsert(Principal {
                    id: teacher,
                    kind: PrincipalKind::Teacher,
                    enabled: true,
                    permissions: BTreeSet::new(),
                    credentials: BTreeMap::from([(
                        grant_fingerprint,
                        CredentialRecord::active(grant_fingerprint, now),
                    )]),
                })
                .unwrap();
            let connection = accept(&server).await.unwrap();
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .unwrap();
            let (_, proof) = server_hello_enrolled(
                &connection,
                &mut channel,
                &ServerHelloConfig {
                    local_version: PROTOCOL_VERSION,
                    local_capabilities: BTreeSet::from([Capability::TeacherMessage]),
                    control_session_id: 51,
                },
                &teacher_store,
                now,
            )
            .await
            .unwrap();
            assert_eq!(proof.identity.principal_id(), teacher);
            (server, connection, channel)
        });

        let unsigned = UnsignedRoster::new(&RosterClaims {
            issuer: "fixture-issuer".into(),
            key_id: "fixture-key".into(),
            organization: "fixture-org".into(),
            teacher,
            issued_at_ms: now,
            not_before_ms: now,
            expires_at_ms: now + 60_000,
            epoch: 3,
            devices: vec![RosterDevice {
                principal: student,
                source: 9,
            }],
        })
        .unwrap();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_ref(), &rng).unwrap();
        let envelope = unsigned
            .attach_signature(key.sign(&rng, &unsigned.signing_data()).unwrap().as_ref())
            .unwrap();
        let snapshot = serde_json::json!({
            "version": 1, "issuer": "fixture-issuer", "organization": "fixture-org",
            "keys": [{ "id": "fixture-key", "sec1": key.public_key().as_ref(), "revoked": false }],
            "roster": envelope, "roster_payload_sha256": unsigned.payload_sha256(),
            "refreshed_at_ms": now, "max_age_ms": 60_000, "max_lifetime_ms": 60_000,
            "revoked_principals": [], "teacher_principal": teacher.0,
            "teacher_leaf_sha256": Sha256::digest(&leaf).to_vec(),
            "teacher_enrollment_ca_der": ca, "machine_identity": identity,
            "student": { "principal": student.0, "leaf_sha256": Sha256::digest(server_cert.der()).to_vec(),
                "address": address, "server_name": "classmesh.local" },
        });
        let validated = validate_policy(&serde_json::to_vec(&snapshot).unwrap(), 3, now).unwrap();
        let (_endpoint, session) =
            tokio::time::timeout(Duration::from_secs(10), connect_teacher(&validated))
                .await
                .unwrap()
                .unwrap();
        let _server_session = task.await.unwrap();
        assert_eq!(session.established.control_session_id, 51);
        assert_eq!(validated.source, MonitoringSourceId(9));
        assert!(
            verify_current_student(student, &session.connection, &validated.authorization, now)
                .is_ok()
        );
        assert!(
            verify_current_student(teacher, &session.connection, &validated.authorization, now)
                .is_err()
        );
        assert!(
            verify_current_student(
                student,
                &session.connection,
                &validated.authorization,
                now + 60_000
            )
            .is_err()
        );
        session.connection.close(0u32.into(), b"test completed");
    }
}
