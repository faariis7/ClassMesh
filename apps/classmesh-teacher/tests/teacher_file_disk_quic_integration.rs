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
    teacher_file_pull_receive::TeacherFilePullReceiveError,
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
use classmesh_teacher::file_pull_runtime::{
    TeacherFilePullRuntimeError, VerifiedSelectedStudent, run_authenticated_teacher_file_pull,
};
use classmesh_teacher::ui_file_transfer::{TeacherFilePullContext, prepare_file_pull_action};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;
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
    sync::Arc,
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

async fn run_teacher_disk_transfer_case(revoke_teacher_after_accept: bool) -> TestResult {
    // Canonicalize the temporary ancestor: on macOS /var can be a symlink.
    let root = std::env::temp_dir().canonicalize()?.join(format!(
        "classmesh-teacher-quic-inbox-{}-{}",
        std::process::id(),
        if revoke_teacher_after_accept {
            "revoked"
        } else {
            "valid"
        }
    ));
    fs::create_dir(&root)?;
    // The app refuses a pre-existing shared-readable AppInbox; this fixture
    // must explicitly provision the same owner-only boundary as production.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
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
    // The test authority is handed to the peer only for a trusted revocation
    // after its authenticated stream has actually consumed Accepted.
    let (revoke_source_tx, revoke_source_rx) =
        tokio::sync::oneshot::channel::<(Arc<LiveAuthorizationStore>, AuthorizationStore)>();
    // Keep the authenticated server connection alive until the Teacher has
    // actually observed the revoked permission and finished its fail-closed
    // receive path. Otherwise dropping this task can race the QUIC frame and
    // replace the intended revocation error with a transport-close error.
    let (teacher_finished_tx, teacher_finished_rx) = tokio::sync::oneshot::channel::<()>();
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
        let request = channel.receive().await.map_err(|e| e.to_string())?;
        assert_eq!(request.request_id, 11);
        assert_eq!(request.control_session_id, 77);
        assert!(matches!(
            request.payload,
            Some(control_envelope::Payload::FileTransferPullRequest(ref pull))
                if pull.transfer_id == ID.to_vec()
                    && pull.source_id == [8; 16].to_vec()
        ));
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
        // The Teacher revokes immediately after processing Accepted and
        // closes QUIC. Its Accepted status can be lost in transit before the
        // Student's receive completes; the Teacher-side status assertion
        // below remains authoritative for this test.
        let status = match channel.receive().await {
            Ok(status) => status,
            Err(_) if revoke_teacher_after_accept => return Ok::<_, String>(()),
            Err(error) => return Err(error.to_string()),
        };
        assert!(
            matches!(status.payload,Some(control_envelope::Payload::FileTransferStatus(s))
            if s.state==FileTransferState::Accepted as i32)
        );
        assert!(!remote_path.exists());
        // The peer consumed Accepted; a local on_status callback alone does
        // not guarantee that its asynchronous QUIC write arrived at the peer.
        // Revoke before the next authenticated Chunk is sent.
        if revoke_teacher_after_accept {
            let (trusted_live, revoked_policy) = revoke_source_rx
                .await
                .map_err(|_| "missing trusted revocation test authority".to_string())?;
            trusted_live
                .publish_if_version(1, revoked_policy)
                .map_err(|error| format!("trusted test revocation failed: {error:?}"))?;
        }
        // After the Accepted reply the Teacher may immediately revoke the
        // transfer and remove the .part before this server checks the path.
        if !revoke_teacher_after_accept {
            assert!(remote_partial.exists());
        }
        let chunk_send = channel
            .send(&frame(
                3,
                control_envelope::Payload::FileTransferChunk(FileTransferChunk {
                    transfer_id: ID.to_vec(),
                    offset: 0,
                    content: remote_bytes.clone(),
                }),
            ))
            .await;
        if revoke_teacher_after_accept {
            // The packet has been submitted, but keep the QUIC connection
            // owned by this task until the Teacher's receive path returns.
            // No Progress or Completed acknowledgement is expected.
            let _ = teacher_finished_rx.await;
            return Ok::<_, String>(());
        }
        chunk_send.map_err(|e| e.to_string())?;
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
    // A verified Student alone is insufficient: the current Teacher must
    // also hold live ReceiveFile permission for this actual QUIC flow.
    store
        .upsert(Principal {
            id: PrincipalId([8; 32]),
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions: BTreeSet::from([Permission::ReceiveFile]),
            credentials: BTreeMap::new(),
        })
        .map_err(|e| format!("{e:?}"))?;
    let mut revoked = store.clone();
    revoked
        .upsert(Principal {
            id: PrincipalId([8; 32]),
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions: BTreeSet::new(),
            credentials: BTreeMap::new(),
        })
        .map_err(|e| format!("{e:?}"))?;
    let live = Arc::new(LiveAuthorizationStore::new(store));
    if revoke_teacher_after_accept {
        revoke_source_tx
            .send((Arc::clone(&live), revoked))
            .expect("revocation peer owns the live Teacher authority");
    }
    let context = TeacherFilePullContext {
        source_id: MonitoringSourceId(7),
        control_session_id: 77,
        version: VERSION,
        capabilities: BTreeSet::from([Capability::FileTransfer]),
    };
    let action = prepare_file_pull_action(
        MonitoringSourceId(7),
        ID,
        [8; 16],
        Some(MonitoringSourceId(7)),
        Some(&context),
    )
    .map_err(|error| format!("{error:?}"))?;
    // The owning Teacher dispatcher must derive this from its live,
    // authenticated monitoring-source registry, never from the GUI action.
    let verified_selection = VerifiedSelectedStudent {
        source_id: MonitoringSourceId(7),
        control_session_id: 77,
        principal_id: STUDENT,
    };
    let mut outbound = 1;
    // The GUI selection must be validated again at dispatch, even after
    // the action was originally prepared for a real authenticated session.
    assert!(matches!(
        run_authenticated_teacher_file_pull(
            &action,
            Some(MonitoringSourceId(8)),
            &context,
            &mut client,
            &live,
            verified_selection,
            STUDENT,
            1,
            &mut outbound,
            11,
            TeacherFileInbox::new(&root).expect("precreated inbox"),
            || 150,
            |_| {},
        )
        .await,
        Err(TeacherFilePullRuntimeError::Ui(_))
    ));
    assert_eq!(outbound, 1);
    assert_eq!(fs::read_dir(&root)?.count(), 0);

    // The GUI's once-valid selection and context cannot authorize an
    // unrelated live control session or a revoked negotiated capability.
    client.established.control_session_id = 78;
    assert!(matches!(
        run_authenticated_teacher_file_pull(
            &action,
            Some(MonitoringSourceId(7)),
            &context,
            &mut client,
            &live,
            verified_selection,
            STUDENT,
            1,
            &mut outbound,
            11,
            TeacherFileInbox::new(&root).expect("precreated inbox"),
            || 150,
            |_| {},
        )
        .await,
        Err(TeacherFilePullRuntimeError::StaleControlSession)
    ));
    client.established.control_session_id = 77;
    client.established.negotiated.capabilities.clear();
    assert!(matches!(
        run_authenticated_teacher_file_pull(
            &action,
            Some(MonitoringSourceId(7)),
            &context,
            &mut client,
            &live,
            verified_selection,
            STUDENT,
            1,
            &mut outbound,
            11,
            TeacherFileInbox::new(&root).expect("precreated inbox"),
            || 150,
            |_| {},
        )
        .await,
        Err(TeacherFilePullRuntimeError::CapabilityChanged)
    ));
    client
        .established
        .negotiated
        .capabilities
        .insert(Capability::FileTransfer);
    assert_eq!(outbound, 1);
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    // A stale/cross-device source->principal mapping must not send a pull,
    // even when the QUIC peer itself is a valid enrolled Student.
    assert!(matches!(
        run_authenticated_teacher_file_pull(
            &action,
            Some(MonitoringSourceId(7)),
            &context,
            &mut client,
            &live,
            VerifiedSelectedStudent {
                principal_id: PrincipalId([6; 32]),
                ..verified_selection
            },
            STUDENT,
            1,
            &mut outbound,
            11,
            TeacherFileInbox::new(&root).expect("precreated inbox"),
            || 150,
            |_| {},
        )
        .await,
        Err(TeacherFilePullRuntimeError::SelectionIdentityChanged)
    ));
    assert_eq!(outbound, 1);
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    for stale_binding in [
        VerifiedSelectedStudent {
            source_id: MonitoringSourceId(8),
            ..verified_selection
        },
        VerifiedSelectedStudent {
            control_session_id: 78,
            ..verified_selection
        },
    ] {
        assert!(matches!(
            run_authenticated_teacher_file_pull(
                &action,
                Some(MonitoringSourceId(7)),
                &context,
                &mut client,
                &live,
                stale_binding,
                STUDENT,
                1,
                &mut outbound,
                11,
                TeacherFileInbox::new(&root).expect("precreated inbox"),
                || 150,
                |_| {},
            )
            .await,
            Err(TeacherFilePullRuntimeError::SelectionIdentityChanged)
        ));
        assert_eq!(outbound, 1);
        assert_eq!(fs::read_dir(&root)?.count(), 0);
    }
    let sink = TeacherFileInbox::new(&root).expect("precreated Teacher inbox");
    let mut statuses = Vec::new();
    let result = run_authenticated_teacher_file_pull(
        &action,
        Some(MonitoringSourceId(7)),
        &context,
        &mut client,
        &live,
        verified_selection,
        STUDENT,
        1,
        &mut outbound,
        11,
        sink,
        || 150,
        |status| {
            statuses.push(status.state);
        },
    )
    .await;
    if revoke_teacher_after_accept {
        // Release the server connection even if the assertion below fails,
        // avoiding a stranded background task while preserving the error.
        let _ = teacher_finished_tx.send(());
        assert!(matches!(
            result,
            Err(TeacherFilePullRuntimeError::Receive(
                TeacherFilePullReceiveError::TeacherPermissionRevoked
            ))
        ));
        assert_eq!(statuses, vec![FileTransferState::Accepted as i32]);
        assert!(
            !path.exists(),
            "revoked Teacher may not publish a final file"
        );
        assert!(
            !partial.exists(),
            "revoked Teacher must clean the partial file"
        );
        server_task.await??;
        fs::remove_dir_all(&root)?;
        return Ok(());
    }
    let outcome = result?;
    assert_eq!(
        statuses,
        vec![
            FileTransferState::Accepted as i32,
            FileTransferState::Progress as i32,
            FileTransferState::Completed as i32,
        ]
    );
    // The inbox pins a canonical root to avoid mutable ancestor aliases.
    assert_eq!(
        outcome.completed_path,
        fs::canonicalize(&root)?.join(path.file_name().unwrap())
    );
    assert_eq!(outcome.total_size, data.len() as u64);
    assert_eq!(outcome.last_inbound_sequence, 4);
    server_task.await??;
    // Outbound stream includes the authenticated PullRequest plus three status acknowledgements.
    assert_eq!(outbound, 5);
    assert_eq!(fs::read(&path)?, data);
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_quic_to_teacher_app_inbox_publishes_only_after_verified_finish() -> TestResult
{
    run_teacher_disk_transfer_case(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn teacher_role_revocation_during_transfer_aborts_partial_without_completed_ack() -> TestResult
{
    run_teacher_disk_transfer_case(true).await
}
