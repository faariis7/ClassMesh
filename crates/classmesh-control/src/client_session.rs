use std::net::SocketAddr;
use std::time::Duration;

use classmesh_core::recovery::RecoveryPolicy;
use quinn::{Connection, Endpoint};
use tokio::time::sleep;

use crate::ControlHello;
use crate::handshake::{EstablishedControlSession, HandshakeError, client_hello};
use crate::quic::{
    ControlChannel, ControlReceiveHalf, ControlSendHalf, ControlTransportError, connect,
    validate_reconnect_policy,
};

#[derive(Debug)]
pub struct ClientControlSession {
    pub connection: Connection,
    pub channel: ControlChannel,
    pub established: EstablishedControlSession,
}

/// Two *halves of the same already authenticated QUIC stream*; this is not
/// another connection or a second network reader. The single receive owner
/// can keep a frame read in flight while the send owner handles a UI command.
/// Dropping a partially read receive future is unsafe; retain the reader task
/// until it completes or retire this entire session and reconnect afresh.
#[derive(Debug)]
pub struct SplitClientControlSession {
    pub connection: Connection,
    pub sender: ControlSendHalf,
    pub receiver: ControlReceiveHalf,
    pub established: EstablishedControlSession,
}

impl ClientControlSession {
    #[must_use]
    pub fn into_split(self) -> SplitClientControlSession {
        let (sender, receiver) = self.channel.into_split();
        SplitClientControlSession {
            connection: self.connection,
            sender,
            receiver,
            established: self.established,
        }
    }
}

/// Establishes a fresh control transport + stream + Hello session with bounded retries.
///
/// Retries are limited to transport failures. Authentication, authorization and protocol
/// rejection are terminal so ClassMesh does not hammer a peer with requests that cannot
/// succeed without configuration or administrative change.
///
/// Reusing the caller's configured QUIC endpoint also reuses its enrolled mTLS identity,
/// so reconnecting does not require re-enrollment.
pub async fn connect_client_session_with_retries(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    hello: &ControlHello,
    io_timeout: Duration,
    policy: RecoveryPolicy,
) -> Result<ClientControlSession, HandshakeError> {
    validate_reconnect_policy(policy).map_err(HandshakeError::Transport)?;
    ControlChannel::validate_io_timeout(io_timeout).map_err(HandshakeError::Transport)?;

    let mut last_transport_error = None;

    for attempt in 1..=policy.max_attempts {
        match establish_once(endpoint, remote, server_name, hello, io_timeout).await {
            Ok(session) => return Ok(session),
            Err(error @ HandshakeError::Transport(_)) => {
                last_transport_error = Some(error);
            }
            Err(error) => return Err(error),
        }

        if attempt < policy.max_attempts {
            sleep(Duration::from_millis(policy.backoff_ms(attempt))).await;
        }
    }

    Err(last_transport_error.unwrap_or_else(|| {
        HandshakeError::Transport(ControlTransportError::Configuration(
            "control session reconnect policy produced no attempts".to_owned(),
        ))
    }))
}

async fn establish_once(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    hello: &ControlHello,
    io_timeout: Duration,
) -> Result<ClientControlSession, HandshakeError> {
    let connection = connect(endpoint, remote, server_name).await?;
    let mut channel = match ControlChannel::open(&connection, io_timeout).await {
        Ok(channel) => channel,
        Err(error) => {
            connection.close(0_u32.into(), b"control stream establishment failed");
            return Err(error.into());
        }
    };

    let established = match client_hello(&mut channel, hello).await {
        Ok(established) => established,
        Err(error) => {
            connection.close(0_u32.into(), b"control hello failed");
            return Err(error);
        }
    };

    Ok(ClientControlSession {
        connection,
        channel,
        established,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr};

    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::PrincipalId;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::quic::{
        DEFAULT_IO_TIMEOUT, accept, client_config_with_roots, server_config_with_certificate,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn hello() -> ControlHello {
        ControlHello {
            principal_id: PrincipalId([7; 32]),
            role: ControlRole::StudentDevice,
            version: ProtocolVersion { major: 0, minor: 2 },
            capabilities: BTreeSet::from([Capability::UdpUnicast]),
            hostname: "student-07".to_owned(),
            app_version: "0.0.1".to_owned(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_reestablishes_fresh_control_session_after_transport_drop() -> TestResult {
        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(client_config_with_roots(roots)?);

        let server_task = tokio::spawn(async move {
            let first = accept(&server).await.map_err(|error| error.to_string())?;
            let _first_channel = ControlChannel::accept(&first, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            first.close(0_u32.into(), b"simulate dropped control session");

            let second = accept(&server).await.map_err(|error| error.to_string())?;
            let mut second_channel = ControlChannel::accept(&second, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            let established = server_hello(
                &mut second_channel,
                &ServerHelloConfig {
                    local_version: ProtocolVersion { major: 0, minor: 2 },
                    local_capabilities: BTreeSet::from([Capability::UdpUnicast]),
                    control_session_id: 88,
                },
            )
            .await
            .map_err(|error| error.to_string())?;

            Ok::<(Endpoint, Connection, EstablishedControlSession), String>((
                server,
                second,
                established,
            ))
        });

        let session = connect_client_session_with_retries(
            &client,
            server_address,
            "classmesh.local",
            &hello(),
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 2,
                base_backoff_ms: 1,
                max_backoff_ms: 2,
            },
        )
        .await?;

        assert_eq!(session.established.control_session_id, 88);

        session
            .connection
            .close(0_u32.into(), b"reconnect test complete");
        let (server, server_connection, server_session) =
            server_task.await.map_err(|error| error.to_string())??;
        assert_eq!(server_session.control_session_id, 88);
        server_connection.close(0_u32.into(), b"reconnect test complete");
        server.close(0_u32.into(), b"reconnect test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn split_authenticated_session_writes_while_one_inbound_reader_waits() -> TestResult {
        use classmesh_protocol::control_wire::{
            ControlEnvelope, Heartbeat, ProtocolVersion as WireVersion, control_envelope,
        };
        use tokio::time::timeout;

        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;
        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(client_config_with_roots(roots)?);

        let request = ControlEnvelope {
            control_session_id: 55,
            sequence: 2,
            request_id: 2,
            protocol_version: Some(WireVersion { major: 0, minor: 2 }),
            payload: Some(control_envelope::Payload::Heartbeat(Heartbeat {
                monotonic_time_us: 100,
                control_session_id: 55,
                media: 1,
            })),
        };
        let response = ControlEnvelope {
            sequence: 3,
            request_id: 3,
            ..request.clone()
        };
        let expected_request = request.clone();
        let expected_response = response.clone();
        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|e| e.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: ProtocolVersion { major: 0, minor: 2 },
                    local_capabilities: BTreeSet::from([Capability::UdpUnicast]),
                    control_session_id: 55,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            let observed = channel.receive().await.map_err(|e| e.to_string())?;
            assert_eq!(observed, expected_request);
            channel.send(&response).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((server, connection))
        });

        let established = connect_client_session_with_retries(
            &client,
            server_address,
            "classmesh.local",
            &hello(),
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
            },
        )
        .await?;
        let mut split = established.into_split();
        assert_eq!(split.established.control_session_id, 55);
        // Retain the actual in-flight receive future. Never cancel/drop a
        // partially consumed length-prefix or body merely to send a command.
        let read = split.receiver.receive();
        tokio::pin!(read);
        assert!(timeout(Duration::from_millis(25), &mut read).await.is_err());
        timeout(Duration::from_secs(3), split.sender.send(&request)).await??;
        assert_eq!(
            timeout(Duration::from_secs(3), &mut read).await??,
            expected_response
        );
        let (server, server_connection) = server_task.await??;
        split.connection.close(0_u32.into(), b"test complete");
        server_connection.close(0_u32.into(), b"test complete");
        server.close(0_u32.into(), b"test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_does_not_retry_terminal_protocol_rejection() -> TestResult {
        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(client_config_with_roots(roots)?);

        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|error| error.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            let result = server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: ProtocolVersion { major: 9, minor: 0 },
                    local_capabilities: BTreeSet::new(),
                    control_session_id: 99,
                },
            )
            .await;
            assert!(result.is_err());
            Ok::<(Endpoint, Connection), String>((server, connection))
        });

        let result = connect_client_session_with_retries(
            &client,
            server_address,
            "classmesh.local",
            &hello(),
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 3,
                base_backoff_ms: 1,
                max_backoff_ms: 2,
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(HandshakeError::Rejected { .. }) | Err(HandshakeError::Negotiation(_))
        ));

        let (server, connection) = server_task.await.map_err(|error| error.to_string())??;
        connection.close(0_u32.into(), b"terminal rejection test complete");
        server.close(0_u32.into(), b"terminal rejection test complete");
        client.wait_idle().await;
        Ok(())
    }
}
