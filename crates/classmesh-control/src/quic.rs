use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use classmesh_protocol::control_wire::ControlEnvelope;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;

use crate::framing::{
    CONTROL_LENGTH_PREFIX_BYTES, FrameError, declared_payload_len, encode_frame,
};

pub const CONTROL_ALPN: &[u8] = b"classmesh-control/1";
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_QUIC_KEEPALIVE: Duration = Duration::from_secs(4);
pub const MAX_CONTROL_BIDI_STREAMS: u32 = 4;

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
    let mut tls = rustls::ServerConfig::builder()
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
    let mut tls = rustls::ClientConfig::builder()
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
    pub async fn open(
        connection: &Connection,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
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

    pub async fn send(
        &mut self,
        envelope: &ControlEnvelope,
    ) -> Result<(), ControlTransportError> {
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
    use std::net::{IpAddr, Ipv4Addr};

    use classmesh_protocol::control_wire::{
        ControlEnvelope, Heartbeat, HeartbeatAck, ProtocolVersion, control_envelope,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn heartbeat() -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence: 1,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 1 }),
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
            protocol_version: Some(ProtocolVersion { major: 0, minor: 1 }),
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
            let connection = accept(&server)
                .await
                .map_err(|error| error.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;

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
            Ok::<(), String>(())
        });

        let connection = connect(&client, server_address, "classmesh.local").await?;
        let mut channel = ControlChannel::open(&connection, DEFAULT_IO_TIMEOUT).await?;
        channel.send(&heartbeat()).await?;

        let received = channel.receive().await?;
        assert!(matches!(
            received.payload,
            Some(control_envelope::Payload::HeartbeatAck(_))
        ));
        channel.finish()?;

        server_task.await.map_err(|error| error.to_string())??;
        connection.close(0_u32.into(), b"test complete");
        client.wait_idle().await;
        Ok(())
    }

    #[test]
    fn transport_defaults_are_bounded() {
        assert!(DEFAULT_IO_TIMEOUT <= DEFAULT_QUIC_IDLE_TIMEOUT);
        assert!(MAX_CONTROL_BIDI_STREAMS <= 8);
        assert!(!CONTROL_ALPN.is_empty());
    }
}
