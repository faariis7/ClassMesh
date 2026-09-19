use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use classmesh_core::recovery::RecoveryPolicy;
use classmesh_protocol::control_wire::ControlEnvelope;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use tokio::time::{sleep, timeout};

use crate::framing::{CONTROL_LENGTH_PREFIX_BYTES, FrameError, declared_payload_len, encode_frame};

pub const CONTROL_ALPN: &[u8] = b"classmesh-control/1";
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_QUIC_KEEPALIVE: Duration = Duration::from_secs(4);
pub const MAX_CONTROL_BIDI_STREAMS: u32 = 4;
pub const DEFAULT_RECONNECT_POLICY: RecoveryPolicy = RecoveryPolicy {
    max_attempts: 8,
    base_backoff_ms: 200,
    max_backoff_ms: 5_000,
};

#[derive(Debug)]
pub enum ControlTransportError {
    Frame(FrameError),
    Timeout { operation: &'static str },
    Configuration(String),
    Transport(String),
    EndpointClosed,
}

impl Display for ControlTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => Display::fmt(error, formatter),
            Self::Timeout { operation } => write!(formatter, "{operation} timed out"),
            Self::Configuration(error) => {
                write!(formatter, "control transport configuration: {error}")
            }
            Self::Transport(error) => write!(formatter, "control transport: {error}"),
            Self::EndpointClosed => write!(formatter, "control QUIC endpoint closed"),
        }
    }
}

impl Error for ControlTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FrameError> for ControlTransportError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

#[must_use]
pub fn control_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(MAX_CONTROL_BIDI_STREAMS.into());
    config.max_concurrent_uni_streams(0_u8.into());
    config.keep_alive_interval(Some(DEFAULT_QUIC_KEEPALIVE));

    let idle_timeout = IdleTimeout::try_from(DEFAULT_QUIC_IDLE_TIMEOUT)
        .expect("ClassMesh idle timeout is representable as a QUIC varint");
    config.max_idle_timeout(Some(idle_timeout));
    config
}

/// Creates the Phase 5 pre-enrollment server TLS configuration.
///
/// Client certificate authentication is intentionally added in Phase 5C after
/// the persistent identity/enrollment store exists. This configuration still
/// authenticates the server certificate and explicitly disables QUIC 0-RTT.
pub fn server_config_with_certificate(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, ControlTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(control_transport_config()));
    Ok(config)
}

/// Creates the Phase 5 pre-enrollment client TLS configuration.
///
/// The roots store must contain the authority/certificate trusted for the
/// target ClassMesh control endpoint. Client identity is introduced in Phase 5C.
pub fn client_config_with_roots(
    roots: RootCertStore,
) -> Result<ClientConfig, ControlTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.enable_early_data = false;

    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(control_transport_config()));
    Ok(config)
}

/// Creates an enrolled server configuration that requires a verified client certificate.
///
/// The caller supplies the verifier so ClassMesh can enforce its own trust/revocation
/// policy without weakening rustls certificate validation. Administrative 0-RTT remains
/// disabled.
pub fn enrolled_server_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
) -> Result<ServerConfig, ControlTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(control_transport_config()));
    Ok(config)
}

/// Creates an enrolled client configuration with a resolver-backed client credential.
///
/// Using a resolver keeps protected-key implementations (for example Windows CNG) behind
/// rustls' signing abstraction rather than requiring PKCS#8/SEC1 private-key export.
pub fn enrolled_client_config(
    roots: RootCertStore,
    client_cert_resolver: Arc<dyn ResolvesClientCert>,
) -> Result<ClientConfig, ControlTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?
        .with_root_certificates(roots)
        .with_client_cert_resolver(client_cert_resolver);
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.enable_early_data = false;

    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|error| ControlTransportError::Configuration(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(control_transport_config()));
    Ok(config)
}

pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> Result<Connection, ControlTransportError> {
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(|error| ControlTransportError::Transport(error.to_string()))?;

    timeout(DEFAULT_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| ControlTransportError::Timeout {
            operation: "QUIC connect",
        })?
        .map_err(|error| ControlTransportError::Transport(error.to_string()))
}

fn validate_reconnect_policy(policy: RecoveryPolicy) -> Result<(), ControlTransportError> {
    if policy.max_attempts == 0 {
        return Err(ControlTransportError::Configuration(
            "reconnect policy must allow at least one attempt".to_owned(),
        ));
    }
    if policy.base_backoff_ms == 0 {
        return Err(ControlTransportError::Configuration(
            "reconnect base backoff must be greater than zero".to_owned(),
        ));
    }
    if policy.max_backoff_ms == 0 {
        return Err(ControlTransportError::Configuration(
            "reconnect maximum backoff must be greater than zero".to_owned(),
        ));
    }
    if policy.base_backoff_ms > policy.max_backoff_ms {
        return Err(ControlTransportError::Configuration(
            "reconnect base backoff must not exceed maximum backoff".to_owned(),
        ));
    }
    Ok(())
}

pub async fn connect_with_retries(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    policy: RecoveryPolicy,
) -> Result<Connection, ControlTransportError> {
    validate_reconnect_policy(policy)?;

    let mut last_error = None;
    for attempt in 1..=policy.max_attempts {
        match connect(endpoint, remote, server_name).await {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = Some(error),
        }

        if attempt < policy.max_attempts {
            sleep(Duration::from_millis(policy.backoff_ms(attempt))).await;
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ControlTransportError::Configuration("reconnect policy produced no attempts".to_owned())
    }))
}

pub async fn accept(endpoint: &Endpoint) -> Result<Connection, ControlTransportError> {
    let incoming = timeout(DEFAULT_CONNECT_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| ControlTransportError::Timeout {
            operation: "QUIC accept",
        })?
        .ok_or(ControlTransportError::EndpointClosed)?;

    timeout(DEFAULT_CONNECT_TIMEOUT, incoming)
        .await
        .map_err(|_| ControlTransportError::Timeout {
            operation: "QUIC handshake",
        })?
        .map_err(|error| ControlTransportError::Transport(error.to_string()))
}

#[derive(Debug)]
pub struct ControlChannel {
    send: SendStream,
    recv: RecvStream,
    io_timeout: Duration,
}

impl ControlChannel {
    fn validate_io_timeout(io_timeout: Duration) -> Result<(), ControlTransportError> {
        if io_timeout.is_zero() {
            return Err(ControlTransportError::Configuration(
                "control I/O timeout must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn open(
        connection: &Connection,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        Self::validate_io_timeout(io_timeout)?;
        let (send, recv) = timeout(io_timeout, connection.open_bi())
            .await
            .map_err(|_| ControlTransportError::Timeout {
                operation: "open control stream",
            })?
            .map_err(|error| ControlTransportError::Transport(error.to_string()))?;

        Ok(Self {
            send,
            recv,
            io_timeout,
        })
    }

    pub async fn accept(
        connection: &Connection,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        Self::validate_io_timeout(io_timeout)?;
        let (send, recv) = timeout(io_timeout, connection.accept_bi())
            .await
            .map_err(|_| ControlTransportError::Timeout {
                operation: "accept control stream",
            })?
            .map_err(|error| ControlTransportError::Transport(error.to_string()))?;

        Ok(Self {
            send,
            recv,
            io_timeout,
        })
    }

    pub async fn send(&mut self, envelope: &ControlEnvelope) -> Result<(), ControlTransportError> {
        let frame = encode_frame(envelope)?;
        timeout(self.io_timeout, self.send.write_all(&frame))
            .await
            .map_err(|_| ControlTransportError::Timeout {
                operation: "write control frame",
            })?
            .map_err(|error| ControlTransportError::Transport(error.to_string()))
    }

    pub async fn receive(&mut self) -> Result<ControlEnvelope, ControlTransportError> {
        let mut prefix = [0_u8; CONTROL_LENGTH_PREFIX_BYTES];
        timeout(self.io_timeout, self.recv.read_exact(&mut prefix))
            .await
            .map_err(|_| ControlTransportError::Timeout {
                operation: "read control frame length",
            })?
            .map_err(|error| ControlTransportError::Transport(error.to_string()))?;

        let length = declared_payload_len(prefix)?;
        let mut payload = vec![0_u8; length];
        timeout(self.io_timeout, self.recv.read_exact(&mut payload))
            .await
            .map_err(|_| ControlTransportError::Timeout {
                operation: "read control frame payload",
            })?
            .map_err(|error| ControlTransportError::Transport(error.to_string()))?;

        let mut frame = Vec::with_capacity(CONTROL_LENGTH_PREFIX_BYTES + payload.len());
        frame.extend_from_slice(&prefix);
        frame.extend_from_slice(&payload);
        crate::framing::decode_frame(&frame).map_err(Into::into)
    }

    pub fn finish(&mut self) -> Result<(), ControlTransportError> {
        self.send
            .finish()
            .map_err(|error| ControlTransportError::Transport(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr};

    use classmesh_protocol::control_wire::{
        ControlEnvelope, Heartbeat, HeartbeatAck, ProtocolVersion as WireProtocolVersion,
        control_envelope,
    };
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Principal, PrincipalId,
        PrincipalKind,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::server::WebPkiClientVerifier;
    use rustls::sign::{CertifiedKey, SingleCertAndKey};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::ControlHello;
    use crate::handshake::{
        HandshakeError, ServerHelloConfig, client_hello, server_hello, server_hello_enrolled,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn heartbeat() -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence: 1,
            protocol_version: Some(WireProtocolVersion { major: 0, minor: 1 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::Heartbeat(Heartbeat {
                monotonic_time_us: 500,
                control_session_id: 77,
                media: 3,
            })),
        }
    }

    fn heartbeat_ack() -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence: 1,
            protocol_version: Some(WireProtocolVersion { major: 0, minor: 1 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::HeartbeatAck(HeartbeatAck {
                heartbeat_sequence: 1,
                monotonic_time_us: 700,
            })),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reliable_quic_channel_round_trips_control_envelopes() -> TestResult {
        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

        let server_config =
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?;
        let server = Endpoint::server(
            server_config,
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

            let established = server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: ProtocolVersion { major: 0, minor: 1 },
                    local_capabilities: [Capability::UdpUnicast].into_iter().collect(),
                    control_session_id: 77,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            assert_eq!(established.control_session_id, 77);

            let received = channel.receive().await.map_err(|error| error.to_string())?;
            assert_eq!(received.control_session_id, 77);
            assert!(matches!(
                received.payload,
                Some(control_envelope::Payload::Heartbeat(_))
            ));

            channel
                .send(&heartbeat_ack())
                .await
                .map_err(|error| error.to_string())?;
            channel.finish().map_err(|error| error.to_string())?;

            // Keep both the endpoint and connection alive in the task result until
            // the client has consumed the final control frame. Dropping the final
            // QUIC handles here can race the peer and surface as "connection lost".
            Ok::<(Endpoint, Connection), String>((server, connection))
        });

        let connection = connect(&client, server_address, "classmesh.local").await?;
        let mut channel = ControlChannel::open(&connection, DEFAULT_IO_TIMEOUT).await?;
        let hello = ControlHello {
            principal_id: PrincipalId([7; 32]),
            role: ControlRole::StudentDevice,
            version: ProtocolVersion { major: 0, minor: 1 },
            capabilities: BTreeSet::from([Capability::UdpUnicast, Capability::QuicDatagram]),
            hostname: "student-07".to_owned(),
            app_version: "0.0.1".to_owned(),
        };
        let established = client_hello(&mut channel, &hello).await?;
        assert_eq!(established.control_session_id, 77);
        assert_eq!(
            established.negotiated.capabilities,
            BTreeSet::from([Capability::UdpUnicast])
        );

        channel.send(&heartbeat()).await?;

        let received = channel.receive().await?;
        assert!(matches!(
            received.payload,
            Some(control_envelope::Payload::HeartbeatAck(_))
        ));
        channel.finish()?;

        connection.close(0_u32.into(), b"test complete");
        let (server, server_connection) =
            server_task.await.map_err(|error| error.to_string())??;
        server_connection.close(0_u32.into(), b"test complete");
        server.close(0_u32.into(), b"test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_hello_rejects_claimed_principal_mismatch() -> TestResult {
        let server_identity = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let server_certificate = CertificateDer::from(server_identity.cert);
        let server_private_key =
            PrivatePkcs8KeyDer::from(server_identity.signing_key.serialize_der());

        let client_identity = generate_simple_self_signed(vec!["student.classmesh".to_owned()])?;
        let client_certificate = CertificateDer::from(client_identity.cert);
        let client_private_key =
            PrivatePkcs8KeyDer::from(client_identity.signing_key.serialize_der());

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_certificate.clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                .build()
                .map_err(|error| error.to_string())?;

        let server = Endpoint::server(
            enrolled_server_config(
                vec![server_certificate.clone()],
                server_private_key.into(),
                verifier,
            )?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let fingerprint = CredentialFingerprint(Sha256::digest(client_certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        let mut authorization = AuthorizationStore::default();
        authorization
            .upsert(Principal {
                id: PrincipalId([7; 32]),
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::new(),
                credentials,
            })
            .expect("test principal should register");

        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_certificate)?;
        let provider = rustls::crypto::ring::default_provider();
        let certified_key = CertifiedKey::from_der(
            vec![client_certificate],
            client_private_key.into(),
            &provider,
        )?;
        let resolver = Arc::new(SingleCertAndKey::from(certified_key));
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(enrolled_client_config(server_roots, resolver)?);

        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|error| error.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            let result = server_hello_enrolled(
                &connection,
                &mut channel,
                &ServerHelloConfig {
                    local_version: ProtocolVersion { major: 0, minor: 2 },
                    local_capabilities: BTreeSet::new(),
                    control_session_id: 77,
                },
                &authorization,
                150,
            )
            .await;
            assert!(matches!(
                result,
                Err(HandshakeError::IdentityMismatch { .. })
            ));
            channel.finish().map_err(|error| error.to_string())?;
            Ok::<(Endpoint, Connection), String>((server, connection))
        });

        let connection = connect(&client, server_address, "classmesh.local").await?;
        let mut channel = ControlChannel::open(&connection, DEFAULT_IO_TIMEOUT).await?;
        let hello = ControlHello {
            principal_id: PrincipalId([8; 32]),
            role: ControlRole::StudentDevice,
            version: ProtocolVersion { major: 0, minor: 2 },
            capabilities: BTreeSet::new(),
            hostname: "spoofed-student".to_owned(),
            app_version: "0.0.1".to_owned(),
        };
        assert!(matches!(
            client_hello(&mut channel, &hello).await,
            Err(HandshakeError::Rejected { reason: 4, .. })
        ));

        connection.close(0_u32.into(), b"identity mismatch test complete");
        let (server, server_connection) =
            server_task.await.map_err(|error| error.to_string())??;
        server_connection.close(0_u32.into(), b"identity mismatch test complete");
        server.close(0_u32.into(), b"identity mismatch test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_quic_accepts_verified_client_certificate() -> TestResult {
        let server_identity = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let server_certificate = CertificateDer::from(server_identity.cert);
        let server_private_key =
            PrivatePkcs8KeyDer::from(server_identity.signing_key.serialize_der());

        let client_identity = generate_simple_self_signed(vec!["student.classmesh".to_owned()])?;
        let client_certificate = CertificateDer::from(client_identity.cert);
        let client_private_key =
            PrivatePkcs8KeyDer::from(client_identity.signing_key.serialize_der());

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_certificate.clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                .build()
                .map_err(|error| error.to_string())?;

        let server = Endpoint::server(
            enrolled_server_config(
                vec![server_certificate.clone()],
                server_private_key.into(),
                verifier,
            )?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_certificate)?;

        let provider = rustls::crypto::ring::default_provider();
        let certified_key = CertifiedKey::from_der(
            vec![client_certificate],
            client_private_key.into(),
            &provider,
        )?;
        let resolver = Arc::new(SingleCertAndKey::from(certified_key));

        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(enrolled_client_config(server_roots, resolver)?);

        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|error| error.to_string())?;
            connection.close(0_u32.into(), b"mTLS test complete");
            Ok::<Endpoint, String>(server)
        });

        let connection = connect(&client, server_address, "classmesh.local").await?;
        connection.close(0_u32.into(), b"mTLS test complete");
        let server = server_task.await.map_err(|error| error.to_string())??;
        server.close(0_u32.into(), b"mTLS test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_quic_rejects_client_without_certificate() -> TestResult {
        let server_identity = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let server_certificate = CertificateDer::from(server_identity.cert);
        let server_private_key =
            PrivatePkcs8KeyDer::from(server_identity.signing_key.serialize_der());

        let trusted_client = generate_simple_self_signed(vec!["trusted.classmesh".to_owned()])?;
        let trusted_client_certificate = CertificateDer::from(trusted_client.cert);
        let mut client_roots = RootCertStore::empty();
        client_roots.add(trusted_client_certificate)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                .build()
                .map_err(|error| error.to_string())?;

        let server = Endpoint::server(
            enrolled_server_config(
                vec![server_certificate.clone()],
                server_private_key.into(),
                verifier,
            )?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_certificate)?;
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(client_config_with_roots(server_roots)?);

        let server_task = tokio::spawn(async move { accept(&server).await.is_err() });
        let client_result = connect(&client, server_address, "classmesh.local").await;
        assert!(server_task.await?);
        if let Ok(connection) = client_result {
            connection.close(0_u32.into(), b"server rejected missing client identity");
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_quic_rejects_untrusted_client_certificate() -> TestResult {
        let server_identity = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let server_certificate = CertificateDer::from(server_identity.cert);
        let server_private_key =
            PrivatePkcs8KeyDer::from(server_identity.signing_key.serialize_der());

        let trusted_client = generate_simple_self_signed(vec!["trusted.classmesh".to_owned()])?;
        let trusted_client_certificate = CertificateDer::from(trusted_client.cert);
        let untrusted_client = generate_simple_self_signed(vec!["untrusted.classmesh".to_owned()])?;
        let untrusted_client_certificate = CertificateDer::from(untrusted_client.cert);
        let untrusted_client_private_key =
            PrivatePkcs8KeyDer::from(untrusted_client.signing_key.serialize_der());

        let mut client_roots = RootCertStore::empty();
        client_roots.add(trusted_client_certificate)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                .build()
                .map_err(|error| error.to_string())?;

        let server = Endpoint::server(
            enrolled_server_config(
                vec![server_certificate.clone()],
                server_private_key.into(),
                verifier,
            )?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;

        let mut server_roots = RootCertStore::empty();
        server_roots.add(server_certificate)?;
        let provider = rustls::crypto::ring::default_provider();
        let certified_key = CertifiedKey::from_der(
            vec![untrusted_client_certificate],
            untrusted_client_private_key.into(),
            &provider,
        )?;
        let resolver = Arc::new(SingleCertAndKey::from(certified_key));
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(enrolled_client_config(server_roots, resolver)?);

        let server_task = tokio::spawn(async move { accept(&server).await.is_err() });
        let client_result = connect(&client, server_address, "classmesh.local").await;
        assert!(server_task.await?);
        if let Ok(connection) = client_result {
            connection.close(0_u32.into(), b"server rejected untrusted client identity");
        }
        Ok(())
    }

    #[test]
    fn reconnect_policy_rejects_zero_or_inverted_backoff() {
        for policy in [
            RecoveryPolicy {
                max_attempts: 0,
                base_backoff_ms: 200,
                max_backoff_ms: 5_000,
            },
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 0,
                max_backoff_ms: 5_000,
            },
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 200,
                max_backoff_ms: 0,
            },
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 5_001,
                max_backoff_ms: 5_000,
            },
        ] {
            assert!(matches!(
                validate_reconnect_policy(policy),
                Err(ControlTransportError::Configuration(_))
            ));
        }

        assert!(validate_reconnect_policy(DEFAULT_RECONNECT_POLICY).is_ok());
    }

    #[test]
    fn control_channel_rejects_zero_io_timeout() {
        assert!(matches!(
            ControlChannel::validate_io_timeout(Duration::ZERO),
            Err(ControlTransportError::Configuration(_))
        ));
        assert!(ControlChannel::validate_io_timeout(Duration::from_millis(1)).is_ok());
        assert!(ControlChannel::validate_io_timeout(DEFAULT_IO_TIMEOUT).is_ok());
    }

    #[test]
    fn transport_defaults_build_with_bounded_reconnect() {
        let _config = control_transport_config();
        assert_eq!(DEFAULT_RECONNECT_POLICY.backoff_ms(1), 200);
        assert_eq!(DEFAULT_RECONNECT_POLICY.backoff_ms(8), 5_000);
    }
}
