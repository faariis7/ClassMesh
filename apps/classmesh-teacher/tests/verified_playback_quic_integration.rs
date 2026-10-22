//! Integration gate: only the verified live QUIC adapter can feed Teacher UI.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use classmesh_control::ControlHello;
use classmesh_control::client_session::{
    ClientControlSession, connect_client_session_with_retries,
};
use classmesh_control::handshake::{ServerHelloConfig, server_hello};
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_control::quic::{
    ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
    server_config_with_certificate,
};
use classmesh_control::teacher_playback_receive::receive_authenticated_teacher_control;
use classmesh_core::recovery::RecoveryPolicy;
use classmesh_protocol::control_wire::{
    ControlEnvelope, ProtocolVersion as WireVersion, ReceiverPlaybackDiagnostic, control_envelope,
};
use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
};
use classmesh_teacher::receiver_playback_diagnostics::{
    TeacherPlaybackBinding, TeacherPlaybackDiagnosticError,
};
use classmesh_teacher::receiver_playback_ui::{MAX_PLAYBACK_UI_AGE, TeacherPlaybackUiProjection};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;
use quinn::{Connection, Endpoint};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };
const STUDENT: PrincipalId = PrincipalId([7; 32]);
const CONTROL_SESSION: u64 = 55;
const SOURCE: MonitoringSourceId = MonitoringSourceId(7);

struct Pair {
    _client_endpoint: Endpoint,
    _server_endpoint: Endpoint,
    _server_connection: Connection,
    server_channel: ControlChannel,
    client: ClientControlSession,
    live_auth: LiveAuthorizationStore,
}

async fn pair() -> Result<Pair, Box<dyn Error + Send + Sync>> {
    let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
    let cert = CertificateDer::from(certified.cert);
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let server = Endpoint::server(
        server_config_with_certificate(vec![cert.clone()], key.into())?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )?;
    let addr = server.local_addr()?;
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone())?;
    let mut client_endpoint =
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    client_endpoint.set_default_client_config(client_config_with_roots(roots)?);
    let capabilities = BTreeSet::from([Capability::ReceiverPlaybackDiagnostics]);
    let negotiated = capabilities.clone();
    let server_task = tokio::spawn(async move {
        let conn = accept(&server).await.map_err(|e| e.to_string())?;
        let mut ch = ControlChannel::accept(&conn, DEFAULT_IO_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        server_hello(
            &mut ch,
            &ServerHelloConfig {
                local_version: VERSION,
                local_capabilities: negotiated,
                control_session_id: CONTROL_SESSION,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok::<_, String>((server, conn, ch))
    });
    let client = connect_client_session_with_retries(
        &client_endpoint,
        addr,
        "classmesh.local",
        &ControlHello {
            principal_id: PrincipalId([8; 32]),
            role: ControlRole::Teacher,
            version: VERSION,
            capabilities,
            hostname: "teacher-projection-test".to_owned(),
            app_version: "0.0.1".to_owned(),
        },
        DEFAULT_IO_TIMEOUT,
        RecoveryPolicy {
            max_attempts: 1,
            base_backoff_ms: 1,
            max_backoff_ms: 1,
        },
    )
    .await?;
    let (server_endpoint, server_connection, server_channel) = server_task.await??;
    let fp = CredentialFingerprint(Sha256::digest(cert.as_ref()).into());
    let mut credentials = BTreeMap::new();
    credentials.insert(fp, CredentialRecord::active(fp, 100));
    let mut store = AuthorizationStore::default();
    store
        .upsert(Principal {
            id: STUDENT,
            kind: PrincipalKind::StudentDevice,
            enabled: true,
            permissions: BTreeSet::from([Permission::ReceivePresentation]),
            credentials,
        })
        .map_err(|error| format!("test store: {error:?}"))?;
    Ok(Pair {
        _client_endpoint: client_endpoint,
        _server_endpoint: server_endpoint,
        _server_connection: server_connection,
        server_channel,
        client,
        live_auth: LiveAuthorizationStore::new(store),
    })
}

fn binding() -> TeacherPlaybackBinding {
    TeacherPlaybackBinding {
        control_session_id: CONTROL_SESSION,
        presentation_id: 21,
        stream_id: 31,
        epoch: 41,
    }
}

fn report() -> ControlEnvelope {
    ControlEnvelope {
        control_session_id: CONTROL_SESSION,
        sequence: 2,
        request_id: 0,
        protocol_version: Some(WireVersion { major: 0, minor: 8 }),
        payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(
            ReceiverPlaybackDiagnostic {
                presentation_id: 21,
                stream_id: 31,
                epoch: 41,
                receiver_generation: 3,
                sequence: 1,
                interval_ms: 5_000,
                authenticated_frames: 100,
                rejected_frames: 1,
                decoded_frames: 90,
                presented_frames: 89,
                present_errors: 2,
                decode_errors: 3,
                keyframe_waits: 4,
                queue_drops: 5,
            },
        )),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_quic_source_binding_replay_and_freshness_reach_teacher_projection() -> TestResult
{
    let mut pair = pair().await?;
    pair.server_channel.send(&report()).await?;
    let verified =
        receive_authenticated_teacher_control(&mut pair.client, &pair.live_auth, STUDENT, || 150)
            .await?;
    let now = Instant::now();
    let mut ui =
        TeacherPlaybackUiProjection::new(SOURCE, binding()).map_err(|e| format!("{e:?}"))?;

    // Source mismatch must not consume the sequence or update any counters.
    assert_eq!(
        ui.accept_verified_from_source(MonitoringSourceId(8), &verified, now),
        Err(TeacherPlaybackDiagnosticError::BindingMismatch)
    );
    assert_eq!(ui.visible(SOURCE, now), None);
    let current = ui
        .accept_verified_from_source(SOURCE, &verified, now)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(current.presented_frames, 89);
    assert_eq!(ui.visible(SOURCE, now), Some(current));
    assert_eq!(ui.visible(MonitoringSourceId(8), now), None);
    assert_eq!(
        ui.accept_verified_from_source(SOURCE, &verified, now + Duration::from_secs(1)),
        Err(TeacherPlaybackDiagnosticError::Replay)
    );
    assert_eq!(
        ui.visible(SOURCE, now + MAX_PLAYBACK_UI_AGE + Duration::from_millis(1)),
        None
    );
    assert!(!ui.revoke(MonitoringSourceId(8), binding()));
    assert!(ui.revoke(SOURCE, binding()));
    assert_eq!(ui.visible(SOURCE, now), None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_playback_control_message_is_not_injected_into_teacher_counters() -> TestResult {
    let mut pair = pair().await?;
    let mut other = report();
    other.payload = None;
    pair.server_channel.send(&other).await?;
    let verified =
        receive_authenticated_teacher_control(&mut pair.client, &pair.live_auth, STUDENT, || 150)
            .await?;
    let now = Instant::now();
    let mut ui =
        TeacherPlaybackUiProjection::new(SOURCE, binding()).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        ui.accept_verified_from_source(SOURCE, &verified, now),
        Err(TeacherPlaybackDiagnosticError::Malformed)
    );
    assert_eq!(ui.visible(SOURCE, now), None);
    assert_eq!(verified.into_envelope().control_session_id, CONTROL_SESSION);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_wrong_epoch_never_replaces_valid_teacher_report() -> TestResult {
    let mut pair = pair().await?;
    pair.server_channel.send(&report()).await?;
    let first =
        receive_authenticated_teacher_control(&mut pair.client, &pair.live_auth, STUDENT, || 150)
            .await?;
    let now = Instant::now();
    let mut ui =
        TeacherPlaybackUiProjection::new(SOURCE, binding()).map_err(|e| format!("{e:?}"))?;
    let before = ui
        .accept_verified_from_source(SOURCE, &first, now)
        .map_err(|e| format!("{e:?}"))?;

    let mut bad = report();
    bad.sequence += 1;
    if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut body)) = bad.payload {
        body.epoch += 1;
        body.sequence += 1;
    }
    pair.server_channel.send(&bad).await?;
    let verified =
        receive_authenticated_teacher_control(&mut pair.client, &pair.live_auth, STUDENT, || 150)
            .await?;
    assert_eq!(
        ui.accept_verified_from_source(SOURCE, &verified, now + Duration::from_secs(1)),
        Err(TeacherPlaybackDiagnosticError::BindingMismatch)
    );
    assert_eq!(
        ui.visible(SOURCE, now + Duration::from_secs(1)),
        Some(before)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_owner_dispatches_non_playback_without_dropping_next_verified_report() -> TestResult
{
    use classmesh_teacher::receiver_playback_session::{
        TeacherPlaybackSessionEvent, TeacherPlaybackSessionOwner,
    };
    let mut pair = pair().await?;
    let now = Instant::now();
    let mut owner = TeacherPlaybackSessionOwner::new(STUDENT, SOURCE, binding())
        .map_err(|error| format!("{error:?}"))?;

    let mut other = report();
    other.payload = None;
    other.sequence = 1;
    pair.server_channel.send(&other).await?;
    let event = owner
        .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
        .await
        .map_err(|error| format!("{error:?}"))?;
    match event {
        TeacherPlaybackSessionEvent::OtherControl(envelope) => {
            assert_eq!(envelope.control_session_id, CONTROL_SESSION);
            assert!(envelope.payload.is_none());
        }
        TeacherPlaybackSessionEvent::Playback(_) => panic!("nonplayback message was misclassified"),
    }
    assert_eq!(owner.visible(SOURCE, now), None);

    pair.server_channel.send(&report()).await?;
    let event = owner
        .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
        .await
        .map_err(|error| format!("{error:?}"))?;
    match event {
        TeacherPlaybackSessionEvent::Playback(counters) => {
            assert_eq!(counters.presented_frames, 89);
        }
        TeacherPlaybackSessionEvent::OtherControl(_) => {
            panic!("playback report was not dispatched")
        }
    }
    assert!(owner.visible(SOURCE, now).is_some());
    assert_eq!(owner.visible(MonitoringSourceId(8), now), None);

    assert!(!owner.retire_exact(MonitoringSourceId(8), binding()));
    assert!(owner.visible(SOURCE, now).is_some());
    assert!(owner.retire_exact(SOURCE, binding()));
    assert_eq!(owner.visible(SOURCE, now), None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_revocation_retires_live_teacher_owner_and_hides_stale_playback() -> TestResult {
    use classmesh_teacher::receiver_playback_session::{
        TeacherPlaybackSessionError, TeacherPlaybackSessionOwner,
    };
    let mut pair = pair().await?;
    let now = Instant::now();
    let mut owner = TeacherPlaybackSessionOwner::new(STUDENT, SOURCE, binding())
        .map_err(|error| format!("{error:?}"))?;

    pair.server_channel.send(&report()).await?;
    owner
        .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
        .await
        .map_err(|error| format!("{error:?}"))?;
    assert!(owner.visible(SOURCE, now).is_some());

    let version = pair
        .live_auth
        .snapshot()
        .map_err(|error| format!("{error:?}"))?
        .version();
    pair.live_auth
        .publish_if_version(version, AuthorizationStore::default())
        .map_err(|error| format!("{error:?}"))?;

    assert!(matches!(
        owner
            .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
            .await,
        Err(TeacherPlaybackSessionError::Receive(_))
    ));
    assert_eq!(owner.visible(SOURCE, now), None);
    assert!(matches!(
        owner
            .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
            .await,
        Err(TeacherPlaybackSessionError::Retired)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_control_session_retires_owner_before_consuming_control_channel() -> TestResult {
    use classmesh_teacher::receiver_playback_session::{
        TeacherPlaybackSessionError, TeacherPlaybackSessionOwner,
    };
    let mut pair = pair().await?;
    let now = Instant::now();
    let mut wrong = binding();
    wrong.control_session_id += 1;
    let mut owner = TeacherPlaybackSessionOwner::new(STUDENT, SOURCE, wrong)
        .map_err(|error| format!("{error:?}"))?;
    pair.server_channel.send(&report()).await?;

    assert!(matches!(
        owner
            .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
            .await,
        Err(TeacherPlaybackSessionError::ControlSessionMismatch)
    ));
    assert_eq!(owner.visible(SOURCE, now), None);
    // Rejected route never drained the correctly bound control channel.
    assert!(
        receive_authenticated_teacher_control(&mut pair.client, &pair.live_auth, STUDENT, || 150)
            .await?
            .receiver_playback()
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_epoch_does_not_destroy_last_valid_owner_projection() -> TestResult {
    use classmesh_teacher::receiver_playback_session::{
        TeacherPlaybackSessionError, TeacherPlaybackSessionOwner,
    };
    let mut pair = pair().await?;
    let now = Instant::now();
    let mut owner = TeacherPlaybackSessionOwner::new(STUDENT, SOURCE, binding())
        .map_err(|error| format!("{error:?}"))?;
    pair.server_channel.send(&report()).await?;
    owner
        .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
        .await
        .map_err(|error| format!("{error:?}"))?;
    let valid = owner.visible(SOURCE, now);

    let mut bad = report();
    bad.sequence += 1;
    if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut payload)) =
        bad.payload
    {
        payload.epoch += 1;
        payload.sequence += 1;
    }
    pair.server_channel.send(&bad).await?;
    assert!(matches!(
        owner
            .receive_next(
                &mut pair.client,
                &pair.live_auth,
                || 150,
                || now + Duration::from_secs(1)
            )
            .await,
        Err(TeacherPlaybackSessionError::Diagnostic(
            TeacherPlaybackDiagnosticError::BindingMismatch
        ))
    ));
    assert_eq!(owner.visible(SOURCE, now + Duration::from_secs(1)), valid);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_outer_control_sequence_forces_retirement_even_when_message_type_changes() -> TestResult
{
    use classmesh_teacher::receiver_playback_session::{
        TeacherPlaybackSessionError, TeacherPlaybackSessionOwner,
    };
    let mut pair = pair().await?;
    let now = Instant::now();
    let mut owner = TeacherPlaybackSessionOwner::new(STUDENT, SOURCE, binding())
        .map_err(|error| format!("{error:?}"))?;

    pair.server_channel.send(&report()).await?;
    owner
        .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
        .await
        .map_err(|error| format!("{error:?}"))?;
    assert!(owner.visible(SOURCE, now).is_some());

    let mut replayed = report();
    replayed.payload = None;
    // The unrelated control message repeats the preceding playback's
    // outer sequence. A single owning dispatcher must reject this globally.
    pair.server_channel.send(&replayed).await?;
    assert!(matches!(
        owner
            .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
            .await,
        Err(TeacherPlaybackSessionError::ControlSequenceRegression)
    ));
    assert_eq!(owner.visible(SOURCE, now), None);
    assert!(matches!(
        owner
            .receive_next(&mut pair.client, &pair.live_auth, || 150, || now)
            .await,
        Err(TeacherPlaybackSessionError::Retired)
    ));
    Ok(())
}
