#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::control_envelope;
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::group_media_coordinator::{
        GroupMediaCoordinator, GroupMediaReceiverInstallState, MAX_GROUP_MEDIA_RECEIVERS,
    };
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
        PrincipalId, PrincipalKind,
    };
    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    use crate::ControlHello;
    use crate::client_session::{ClientControlSession, connect_client_session_with_retries};
    use crate::group_media_session::PresentationKeyGrantRequest;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 4 };

    struct SessionPair {
        _client_endpoint: Endpoint,
        _server_endpoint: Endpoint,
        _server_connection: Connection,
        server_channel: ControlChannel,
        client: ClientControlSession,
        certificate: CertificateDer<'static>,
    }

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
        ])
    }

    fn teacher_hello() -> ControlHello {
        ControlHello {
            principal_id: principal(8),
            role: ControlRole::Teacher,
            version: VERSION,
            capabilities: capabilities(),
            hostname: "teacher-test".to_owned(),
            app_version: "0.0.1".to_owned(),
        }
    }

    async fn session_pair(control_session_id: u64) -> TestResult<SessionPair> {
        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone())?;
        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client_endpoint.set_default_client_config(client_config_with_roots(roots)?);

        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|error| error.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: capabilities(),
                    control_session_id,
                },
            )
            .await
            .map_err(|error| error.to_string())?;

            Ok::<_, String>((server, connection, channel))
        });

        let client = connect_client_session_with_retries(
            &client_endpoint,
            server_address,
            "classmesh.local",
            &teacher_hello(),
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
            },
        )
        .await?;

        let (server_endpoint, server_connection, server_channel) =
            server_task.await.map_err(|error| error.to_string())??;

        Ok(SessionPair {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            _server_connection: server_connection,
            server_channel,
            client,
            certificate,
        })
    }

    fn authorization(
        receiver: PrincipalId,
        certificates: &[CertificateDer<'static>],
    ) -> AuthorizationStore {
        let mut credentials = BTreeMap::new();
        for certificate in certificates {
            let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
            credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        }

        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: receiver,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceivePresentation]),
                credentials,
            })
            .expect("student receiver principal");
        store
    }

    fn coordinator(
        authorization: &AuthorizationStore,
        receiver: PrincipalId,
    ) -> GroupMediaCoordinator {
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(authorization, receiver)
            .expect("receiver should register");
        coordinator.begin_epoch().expect("epoch should start");
        coordinator
    }

    #[test]
    fn delivery_manager_rejects_invalid_receiver_limits() {
        assert!(matches!(
            TeacherGroupMediaDeliveryManager::with_limit(0),
            Err(TeacherGroupMediaDeliveryError::InvalidReceiverLimit)
        ));
        assert!(matches!(
            TeacherGroupMediaDeliveryManager::with_limit(MAX_GROUP_MEDIA_RECEIVERS + 1),
            Err(TeacherGroupMediaDeliveryError::InvalidReceiverLimit)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_receiver_has_one_pending_ack_and_send_uses_registered_connection() -> TestResult {
        let receiver = principal(7);
        let mut pair = session_pair(77).await?;
        let authorization = authorization(receiver, &[pair.certificate.clone()]);
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;
        assert_eq!(delivery.receiver_count(), 1);

        let epoch = delivery
            .send_key(
                receiver,
                &mut pair.client,
                &mut coordinator,
                &authorization,
                PresentationKeyGrantRequest::new(55, 7, 44, 2),
                150,
            )
            .await?;
        assert!(delivery.has_pending_ack(receiver));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::KeyIssued(epoch))
        );

        let mut received = pair.server_channel.receive().await?;
        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            received.payload.as_mut()
        else {
            return Err("expected PresentationKeyGrant".into());
        };
        assert_eq!(grant.presentation_id, 55);
        assert_eq!(grant.stream_id, 7);
        assert_eq!(grant.epoch, epoch.get());
        assert_eq!(grant.key_material.len(), 32);
        grant.key_material.zeroize();

        assert!(matches!(
            delivery
                .send_key(
                    receiver,
                    &mut pair.client,
                    &mut coordinator,
                    &authorization,
                    PresentationKeyGrantRequest::new(55, 7, 45, 3),
                    150,
                )
                .await,
            Err(TeacherGroupMediaDeliveryError::PendingAckExists)
        ));

        assert!(delivery.remove_receiver(receiver));
        assert_eq!(delivery.receiver_count(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_student_and_control_session_on_another_connection_is_rejected() -> TestResult {
        let receiver = principal(7);
        let first = session_pair(77).await?;
        let mut second = session_pair(77).await?;
        let authorization = authorization(
            receiver,
            &[first.certificate.clone(), second.certificate.clone()],
        );
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&first.client, receiver, &authorization, 150)?;

        assert!(matches!(
            delivery
                .send_key(
                    receiver,
                    &mut second.client,
                    &mut coordinator,
                    &authorization,
                    PresentationKeyGrantRequest::new(55, 7, 44, 2),
                    150,
                )
                .await,
            Err(TeacherGroupMediaDeliveryError::SessionBindingMismatch)
        ));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
        assert!(!delivery.has_pending_ack(receiver));
        Ok(())
    }
}
