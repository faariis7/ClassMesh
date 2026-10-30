//! Actual QUIC -> verified Teacher session -> disk, with no premature success.
use classmesh_control::{
    ControlHello,
    client_session::connect_client_session_with_retries,
    handshake::{ServerHelloConfig, server_hello},
    live_authorization::LiveAuthorizationStore,
    quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    },
    teacher_file_pull_receive::TeacherFilePullInbox,
};
use classmesh_core::recovery::RecoveryPolicy;
use classmesh_protocol::{
    Capability, ControlRole, ProtocolVersion,
    control_wire::{
        ControlEnvelope, FileDestinationPolicy, FileTransferChunk, FileTransferFinish,
        FileTransferOffer, FileTransferState, ProtocolVersion as WireVersion, control_envelope,
    },
};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
};
use classmesh_teacher::file_inbox::TeacherFileInbox;
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };
const STUDENT: PrincipalId = PrincipalId([7; 32]);
const ID: [u8; 16] = [9; 16];
type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

fn frame(sequence: u64, payload: control_envelope::Payload) -> ControlEnvelope {
    ControlEnvelope {
        control_session_id: 77,
        sequence,
        request_id: 11,
        protocol_version: Some(WireVersion { major: 0, minor: 8 }),
        payload: Some(payload),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_quic_to_teacher_app_inbox_publishes_only_after_verified_finish() -> TestResult
{
    let root = std::env::temp_dir().join(format!(
        "classmesh-teacher-quic-inbox-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let data = b"actual classroom bytes".to_vec();
    let path = root.join(format!("{}.bin", "09".repeat(16)));
    let partial = root.join(format!("{}.part", "09".repeat(16)));
    let cert = generate_simple_self_signed(vec!["classmesh.local".into()])?;
    let certificate = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server = Endpoint::server(
        server_config_with_certificate(vec![certificate.clone()], key.into())?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )?;
    let address = server.local_addr()?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    endpoint.set_default_client_config(client_config_with_roots(roots)?);

    let remote_path = path.clone();
    let remote_partial = partial.clone();
    let remote_bytes = data.clone();
    let server_task = tokio::spawn(async move {
        let connection = accept(&server).await.map_err(|e| e.to_string())?;
        let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        server_hello(
            &mut channel,
            &ServerHelloConfig {
                local_version: VERSION,
                local_capabilities: BTreeSet::from([Capability::FileTransfer]),
                control_session_id: 77,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let offer = FileTransferOffer {
            transfer_id: ID.to_vec(),
            filename: "lesson.pdf".into(),
            total_size: remote_bytes.len() as u64,
            sha256: Sha256::digest(&remote_bytes).to_vec(),
            destination: FileDestinationPolicy::AppInbox as i32,
        };
        channel
            .send(&frame(
                2,
                control_envelope::Payload::FileTransferOffer(offer),
            ))
            .await
            .map_err(|e| e.to_string())?;
        let status = channel.receive().await.map_err(|e| e.to_string())?;
        assert!(
            matches!(status.payload,Some(control_envelope::Payload::FileTransferStatus(s))
            if s.state==FileTransferState::Accepted as i32)
        );
        assert!(!remote_path.exists());
        assert!(remote_partial.exists());
        channel
            .send(&frame(
                3,
                control_envelope::Payload::FileTransferChunk(FileTransferChunk {
                    transfer_id: ID.to_vec(),
                    offset: 0,
                    content: remote_bytes.clone(),
                }),
            ))
            .await
            .map_err(|e| e.to_string())?;
        let status = channel.receive().await.map_err(|e| e.to_string())?;
        assert!(
            matches!(status.payload,Some(control_envelope::Payload::FileTransferStatus(s))
            if s.state==FileTransferState::Progress as i32 && s.next_offset==remote_bytes.len() as u64)
        );
        assert!(!remote_path.exists());
        channel
            .send(&frame(
                4,
                control_envelope::Payload::FileTransferFinish(FileTransferFinish {
                    transfer_id: ID.to_vec(),
                }),
            ))
            .await
            .map_err(|e| e.to_string())?;
        let status = channel.receive().await.map_err(|e| e.to_string())?;
        assert!(
            matches!(status.payload,Some(control_envelope::Payload::FileTransferStatus(s))
            if s.state==FileTransferState::Completed as i32 && s.next_offset==remote_bytes.len() as u64)
        );
        assert_eq!(
            fs::read(&remote_path).map_err(|e| e.to_string())?,
            remote_bytes
        );
        assert!(!remote_partial.exists());
        Ok::<_, String>(())
    });

    let mut client = connect_client_session_with_retries(
        &endpoint,
        address,
        "classmesh.local",
        &ControlHello {
            principal_id: PrincipalId([8; 32]),
            role: ControlRole::Teacher,
            version: VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
            hostname: "teacher".into(),
            app_version: "0.0.1".into(),
        },
        DEFAULT_IO_TIMEOUT,
        RecoveryPolicy {
            max_attempts: 1,
            base_backoff_ms: 1,
            max_backoff_ms: 1,
        },
    )
    .await?;
    let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
    let mut credentials = BTreeMap::new();
    credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
    let mut store = AuthorizationStore::default();
    store
        .upsert(Principal {
            id: STUDENT,
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::from([Permission::ReceivePresentation]),
            credentials,
        })
        .map_err(|e| format!("{e:?}"))?;
    let live = LiveAuthorizationStore::new(store);
    let sink = TeacherFileInbox::new(&root).expect("precreated Teacher inbox");
    let mut inbox = TeacherFilePullInbox::new(&client, STUDENT, 11, ID, 1, sink)?;
    let mut outbound = 1;
    for wanted in [
        FileTransferState::Accepted,
        FileTransferState::Progress,
        FileTransferState::Completed,
    ] {
        let status = inbox
            .receive_and_reply(&mut client, &live, &mut outbound, || 150)
            .await?;
        assert_eq!(status.state, wanted as i32);
    }
    server_task.await??;
    assert_eq!(outbound, 4);
    assert_eq!(fs::read(&path)?, data);
    fs::remove_dir_all(&root)?;
    Ok(())
}
