use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::time::{MissedTickBehavior, timeout};

const DATA_MAGIC: [u8; 4] = *b"CMB1";
const ACK_MAGIC: [u8; 4] = *b"CMA1";
const HEADER_LEN: usize = 20;
const DEFAULT_SECONDS: u64 = 30;
const DEFAULT_PPS: u64 = 500;
const DEFAULT_PAYLOAD_BYTES: usize = 1_000;
const DEFAULT_CERT_PATH: &str = "classmesh-quic-cert.der";
const QUIC_DATAGRAM_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const LATENCY_WINDOW: usize = 60_000;
const ACK_DRAIN_GRACE: Duration = Duration::from_millis(750);

type AnyError = Box<dyn Error + Send + Sync + 'static>;
type AnyResult<T> = Result<T, AnyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkTransport {
    Udp,
    Quic,
}

#[derive(Debug, Default)]
struct ServerStats {
    received: u64,
    received_bytes: u64,
    invalid: u64,
    acknowledgements: u64,
    acknowledgement_errors: u64,
}

#[derive(Debug)]
struct ClientStats {
    attempted: u64,
    accepted: u64,
    accepted_bytes: u64,
    send_errors: u64,
    acknowledgements: u64,
    invalid_acknowledgements: u64,
    latency: LatencyTracker,
}

impl Default for ClientStats {
    fn default() -> Self {
        Self {
            attempted: 0,
            accepted: 0,
            accepted_bytes: 0,
            send_errors: 0,
            acknowledgements: 0,
            invalid_acknowledgements: 0,
            latency: LatencyTracker::new(LATENCY_WINDOW),
        }
    }
}

#[derive(Debug)]
struct LatencyTracker {
    capacity: usize,
    recent_us: VecDeque<u64>,
    samples: u64,
    total_us: u128,
    min_us: u64,
    max_us: u64,
}

impl LatencyTracker {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            recent_us: VecDeque::with_capacity(capacity.max(1)),
            samples: 0,
            total_us: 0,
            min_us: u64::MAX,
            max_us: 0,
        }
    }

    fn observe(&mut self, value_us: u64) {
        self.samples = self.samples.saturating_add(1);
        self.total_us = self.total_us.saturating_add(u128::from(value_us));
        self.min_us = self.min_us.min(value_us);
        self.max_us = self.max_us.max(value_us);
        if self.recent_us.len() == self.capacity {
            self.recent_us.pop_front();
        }
        self.recent_us.push_back(value_us);
    }

    fn average_ms(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        self.total_us as f64 / self.samples as f64 / 1_000.0
    }

    fn percentile_ms(&self, percentile: u32) -> f64 {
        if self.recent_us.is_empty() {
            return 0.0;
        }
        let mut samples: Vec<u64> = self.recent_us.iter().copied().collect();
        samples.sort_unstable();
        let last = samples.len().saturating_sub(1);
        let numerator = last.saturating_mul(percentile.min(100) as usize);
        let index = numerator.div_ceil(100).min(last);
        samples[index] as f64 / 1_000.0
    }

    fn min_ms(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.min_us as f64 / 1_000.0
        }
    }

    fn max_ms(&self) -> f64 {
        self.max_us as f64 / 1_000.0
    }
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).ok_or(usage())?;
    let transport = parse_transport(&args)?;

    match role {
        "server" => run_server(&args, transport).await,
        "client" => run_client(&args, transport).await,
        _ => Err(usage().into()),
    }
}

async fn run_server(args: &[String], transport: BenchmarkTransport) -> AnyResult<()> {
    let listen = parse_socket_arg(args, "--listen", None)?.ok_or("--listen is required")?;
    let seconds = parse_u64_arg(args, "--seconds", DEFAULT_SECONDS, 1, 86_400)?;
    eprintln!(
        "ClassMesh transport benchmark server: transport={transport:?}, listen={listen}, duration={seconds}s"
    );

    match transport {
        BenchmarkTransport::Udp => run_udp_server(listen, seconds).await,
        BenchmarkTransport::Quic => {
            let cert_path = parse_string_arg(args, "--cert-out", DEFAULT_CERT_PATH)?;
            run_quic_server(listen, seconds, &cert_path).await
        }
    }
}

async fn run_client(args: &[String], transport: BenchmarkTransport) -> AnyResult<()> {
    let connect = parse_socket_arg(args, "--connect", None)?.ok_or("--connect is required")?;
    let seconds = parse_u64_arg(args, "--seconds", DEFAULT_SECONDS, 1, 86_400)?;
    let packets_per_second = parse_u64_arg(args, "--pps", DEFAULT_PPS, 1, 100_000)?;
    let payload_bytes = parse_usize_arg(
        args,
        "--payload-bytes",
        DEFAULT_PAYLOAD_BYTES,
        HEADER_LEN,
        60_000,
    )?;
    eprintln!(
        "ClassMesh transport benchmark client: transport={transport:?}, connect={connect}, duration={seconds}s, pps={packets_per_second}, payload={payload_bytes} bytes"
    );

    match transport {
        BenchmarkTransport::Udp => {
            run_udp_client(connect, seconds, packets_per_second, payload_bytes).await
        }
        BenchmarkTransport::Quic => {
            let cert_path = parse_string_arg(args, "--cert", DEFAULT_CERT_PATH)?;
            run_quic_client(
                connect,
                seconds,
                packets_per_second,
                payload_bytes,
                &cert_path,
            )
            .await
        }
    }
}

async fn run_udp_server(listen: SocketAddr, seconds: u64) -> AnyResult<()> {
    let socket = UdpSocket::bind(listen).await?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut buffer = vec![0_u8; 65_535];
    let mut stats = ServerStats::default();
    let mut next_report = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        match timeout(Duration::from_millis(100), socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, peer))) => {
                if let Some(ack) = prepare_server_ack(&buffer[..len], &mut stats) {
                    let result = socket.send_to(&ack, peer).await.map(|_| ());
                    record_server_ack_result(result, &mut stats);
                }
            }
            Ok(Err(error)) => return Err(format!("UDP receive failed: {error}").into()),
            Err(_) => {}
        }
        if Instant::now() >= next_report {
            report_server(&stats);
            next_report = Instant::now() + Duration::from_secs(1);
        }
    }

    report_server(&stats);
    Ok(())
}

async fn run_quic_server(listen: SocketAddr, seconds: u64, cert_path: &str) -> AnyResult<()> {
    let certified = rcgen::generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
    let cert_der = CertificateDer::from(certified.cert);
    fs::write(cert_path, cert_der.as_ref())?;
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key.into())?;
    server_config.transport_config(Arc::new(quic_transport_config()));
    let endpoint = Endpoint::server(server_config, listen)?;
    eprintln!(
        "QUIC benchmark certificate written to {cert_path}; copy this DER file to the client machine"
    );

    let incoming = timeout(Duration::from_secs(30), endpoint.accept())
        .await
        .map_err(|_| "timed out waiting for QUIC client")?
        .ok_or("QUIC endpoint closed before a client connected")?;
    let connection = incoming.await?;
    eprintln!(
        "QUIC client connected: peer={}, max_datagram_size={:?}",
        connection.remote_address(),
        connection.max_datagram_size()
    );

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut stats = ServerStats::default();
    let mut next_report = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        match timeout(Duration::from_millis(100), connection.read_datagram()).await {
            Ok(Ok(data)) => {
                if let Some(ack) = prepare_server_ack(&data, &mut stats) {
                    let result = connection
                        .send_datagram(Bytes::from(ack))
                        .map_err(std::io::Error::other);
                    record_server_ack_result(result, &mut stats);
                }
            }
            Ok(Err(error)) => {
                eprintln!("QUIC connection ended while receiving benchmark datagrams: {error}");
                break;
            }
            Err(_) => {}
        }
        if Instant::now() >= next_report {
            report_server(&stats);
            let path = connection.stats().path;
            eprintln!(
                "QUIC path: rtt_ms={:.2} min_rtt_ms={:.2} cwnd={} lost_packets={} lost_bytes={} congestion_events={} mtu={}",
                path.rtt.as_secs_f64() * 1_000.0,
                connection.min_rtt().as_secs_f64() * 1_000.0,
                path.cwnd,
                path.lost_packets,
                path.lost_bytes,
                path.congestion_events,
                path.current_mtu
            );
            next_report = Instant::now() + Duration::from_secs(1);
        }
    }

    report_server(&stats);
    connection.close(VarInt::from_u32(0), b"benchmark complete");
    endpoint.wait_idle().await;
    Ok(())
}

fn prepare_server_ack(data: &[u8], stats: &mut ServerStats) -> Option<Vec<u8>> {
    stats.received = stats.received.saturating_add(1);
    stats.received_bytes = stats
        .received_bytes
        .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    let Some((sequence, sent_us)) = parse_packet(data, DATA_MAGIC) else {
        stats.invalid = stats.invalid.saturating_add(1);
        return None;
    };
    Some(build_packet(ACK_MAGIC, sequence, sent_us, HEADER_LEN))
}

fn record_server_ack_result<E: std::fmt::Display>(
    result: Result<(), E>,
    stats: &mut ServerStats,
) {
    match result {
        Ok(()) => stats.acknowledgements = stats.acknowledgements.saturating_add(1),
        Err(error) => {
            stats.acknowledgement_errors = stats.acknowledgement_errors.saturating_add(1);
            eprintln!("benchmark acknowledgement send failed: {error}");
        }
    }
}

async fn run_udp_client(
    remote: SocketAddr,
    seconds: u64,
    packets_per_second: u64,
    payload_bytes: usize,
) -> AnyResult<()> {
    let socket = UdpSocket::bind(any_address_for(remote.ip())).await?;
    socket.connect(remote).await?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut stats = ClientStats::default();
    let mut sequence = 0_u64;
    let mut buffer = [0_u8; 256];
    let mut ticker = benchmark_ticker(packets_per_second);
    let mut next_report = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        tokio::select! {
            _ = ticker.tick() => {
                let packet = build_packet(DATA_MAGIC, sequence, elapsed_us(started), payload_bytes);
                stats.attempted = stats.attempted.saturating_add(1);
                match socket.send(&packet).await {
                    Ok(sent) => {
                        stats.accepted = stats.accepted.saturating_add(1);
                        stats.accepted_bytes = stats.accepted_bytes.saturating_add(u64::try_from(sent).unwrap_or(u64::MAX));
                    }
                    Err(error) => {
                        stats.send_errors = stats.send_errors.saturating_add(1);
                        eprintln!("UDP benchmark send failed: {error}");
                    }
                }
                sequence = sequence.wrapping_add(1);
            }
            received = socket.recv(&mut buffer) => {
                let len = received?;
                observe_ack(&buffer[..len], started, &mut stats);
            }
        }
        if Instant::now() >= next_report {
            report_client(&stats);
            next_report = Instant::now() + Duration::from_secs(1);
        }
    }

    drain_udp_acks(&socket, &mut buffer, started, &mut stats).await?;
    report_client(&stats);
    Ok(())
}

async fn run_quic_client(
    remote: SocketAddr,
    seconds: u64,
    packets_per_second: u64,
    payload_bytes: usize,
    cert_path: &str,
) -> AnyResult<()> {
    let cert = fs::read(cert_path)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    client_config.transport_config(Arc::new(quic_transport_config()));
    let mut endpoint = Endpoint::client(any_address_for(remote.ip()))?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint.connect(remote, "classmesh.local")?.await?;
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or("peer did not negotiate QUIC application datagrams")?;
    if payload_bytes > max_datagram_size {
        return Err(format!(
            "requested payload {payload_bytes} exceeds negotiated QUIC datagram limit {max_datagram_size}"
        )
        .into());
    }
    eprintln!(
        "QUIC connected: peer={}, max_datagram_size={}, initial_rtt_ms={:.2}",
        connection.remote_address(),
        max_datagram_size,
        connection.rtt().as_secs_f64() * 1_000.0
    );

    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut stats = ClientStats::default();
    let mut sequence = 0_u64;
    let mut ticker = benchmark_ticker(packets_per_second);
    let mut next_report = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        tokio::select! {
            _ = ticker.tick() => {
                let packet = build_packet(DATA_MAGIC, sequence, elapsed_us(started), payload_bytes);
                stats.attempted = stats.attempted.saturating_add(1);
                match connection.send_datagram(Bytes::from(packet)) {
                    Ok(()) => {
                        stats.accepted = stats.accepted.saturating_add(1);
                        stats.accepted_bytes = stats.accepted_bytes.saturating_add(u64::try_from(payload_bytes).unwrap_or(u64::MAX));
                    }
                    Err(error) => {
                        stats.send_errors = stats.send_errors.saturating_add(1);
                        eprintln!("QUIC benchmark send rejected: {error}");
                    }
                }
                sequence = sequence.wrapping_add(1);
            }
            received = connection.read_datagram() => {
                match received {
                    Ok(data) => observe_ack(&data, started, &mut stats),
                    Err(error) => {
                        eprintln!("QUIC benchmark receive ended: {error}");
                        break;
                    }
                }
            }
        }
        if Instant::now() >= next_report {
            report_client(&stats);
            let path = connection.stats().path;
            eprintln!(
                "QUIC path: rtt_ms={:.2} min_rtt_ms={:.2} cwnd={} lost_packets={} lost_bytes={} congestion_events={} mtu={} send_buffer_space={}",
                path.rtt.as_secs_f64() * 1_000.0,
                connection.min_rtt().as_secs_f64() * 1_000.0,
                path.cwnd,
                path.lost_packets,
                path.lost_bytes,
                path.congestion_events,
                path.current_mtu,
                connection.datagram_send_buffer_space()
            );
            next_report = Instant::now() + Duration::from_secs(1);
        }
    }

    drain_quic_acks(&connection, started, &mut stats).await;
    report_client(&stats);
    let connection_stats = connection.stats();
    eprintln!(
        "QUIC final: udp_tx_datagrams={} udp_tx_bytes={} udp_rx_datagrams={} udp_rx_bytes={} path_sent_packets={} path_lost_packets={} path_lost_bytes={} congestion_events={} final_rtt_ms={:.2} mtu={}",
        connection_stats.udp_tx.datagrams,
        connection_stats.udp_tx.bytes,
        connection_stats.udp_rx.datagrams,
        connection_stats.udp_rx.bytes,
        connection_stats.path.sent_packets,
        connection_stats.path.lost_packets,
        connection_stats.path.lost_bytes,
        connection_stats.path.congestion_events,
        connection_stats.path.rtt.as_secs_f64() * 1_000.0,
        connection_stats.path.current_mtu
    );
    connection.close(VarInt::from_u32(0), b"benchmark complete");
    endpoint.wait_idle().await;
    Ok(())
}

async fn drain_udp_acks(
    socket: &UdpSocket,
    buffer: &mut [u8],
    started: Instant,
    stats: &mut ClientStats,
) -> AnyResult<()> {
    let deadline = Instant::now() + ACK_DRAIN_GRACE;
    while Instant::now() < deadline {
        match timeout(Duration::from_millis(25), socket.recv(buffer)).await {
            Ok(Ok(len)) => observe_ack(&buffer[..len], started, stats),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {}
        }
    }
    Ok(())
}

async fn drain_quic_acks(
    connection: &quinn::Connection,
    started: Instant,
    stats: &mut ClientStats,
) {
    let deadline = Instant::now() + ACK_DRAIN_GRACE;
    while Instant::now() < deadline {
        match timeout(Duration::from_millis(25), connection.read_datagram()).await {
            Ok(Ok(data)) => observe_ack(&data, started, stats),
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
}

fn observe_ack(data: &[u8], started: Instant, stats: &mut ClientStats) {
    let Some((_sequence, sent_us)) = parse_packet(data, ACK_MAGIC) else {
        stats.invalid_acknowledgements = stats.invalid_acknowledgements.saturating_add(1);
        return;
    };
    stats.acknowledgements = stats.acknowledgements.saturating_add(1);
    let now_us = elapsed_us(started);
    if now_us >= sent_us {
        stats.latency.observe(now_us - sent_us);
    }
}

fn report_server(stats: &ServerStats) {
    eprintln!(
        "server stats: received={} bytes={} invalid={} acknowledgements={} acknowledgement_errors={}",
        stats.received,
        stats.received_bytes,
        stats.invalid,
        stats.acknowledgements,
        stats.acknowledgement_errors
    );
}

fn report_client(stats: &ClientStats) {
    let missing = stats.accepted.saturating_sub(stats.acknowledgements);
    let effective_loss_percent = if stats.accepted == 0 {
        0.0
    } else {
        missing as f64 * 100.0 / stats.accepted as f64
    };
    eprintln!(
        "client stats: attempted={} accepted={} bytes={} send_errors={} acks={} pending_or_lost={} effective_loss={:.2}% invalid_acks={} rtt_samples={} rtt_min_ms={:.2} rtt_avg_ms={:.2} rtt_p50_ms={:.2} rtt_p95_ms={:.2} rtt_p99_ms={:.2} rtt_max_ms={:.2}",
        stats.attempted,
        stats.accepted,
        stats.accepted_bytes,
        stats.send_errors,
        stats.acknowledgements,
        missing,
        effective_loss_percent,
        stats.invalid_acknowledgements,
        stats.latency.samples,
        stats.latency.min_ms(),
        stats.latency.average_ms(),
        stats.latency.percentile_ms(50),
        stats.latency.percentile_ms(95),
        stats.latency.percentile_ms(99),
        stats.latency.max_ms()
    );
}

fn quic_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(0_u8.into());
    config.max_concurrent_uni_streams(0_u8.into());
    config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER_BYTES));
    config.datagram_send_buffer_size(QUIC_DATAGRAM_BUFFER_BYTES);
    config.keep_alive_interval(Some(Duration::from_secs(5)));
    config
}

fn benchmark_ticker(packets_per_second: u64) -> tokio::time::Interval {
    let nanos = (1_000_000_000_u64 / packets_per_second.max(1)).max(1);
    let mut ticker = tokio::time::interval(Duration::from_nanos(nanos));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker
}

fn build_packet(magic: [u8; 4], sequence: u64, sent_us: u64, size: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; size.max(HEADER_LEN)];
    packet[0..4].copy_from_slice(&magic);
    packet[4..12].copy_from_slice(&sequence.to_be_bytes());
    packet[12..20].copy_from_slice(&sent_us.to_be_bytes());
    for (offset, byte) in packet[HEADER_LEN..].iter_mut().enumerate() {
        *byte = sequence.wrapping_add(offset as u64) as u8;
    }
    packet
}

fn parse_packet(data: &[u8], magic: [u8; 4]) -> Option<(u64, u64)> {
    if data.len() < HEADER_LEN || data[0..4] != magic {
        return None;
    }
    let sequence = u64::from_be_bytes(data[4..12].try_into().ok()?);
    let sent_us = u64::from_be_bytes(data[12..20].try_into().ok()?);
    Some((sequence, sent_us))
}

fn parse_transport(args: &[String]) -> AnyResult<BenchmarkTransport> {
    let value = parse_optional_arg(args, "--transport")?.unwrap_or_else(|| "udp".to_owned());
    match value.as_str() {
        "udp" => Ok(BenchmarkTransport::Udp),
        "quic" => Ok(BenchmarkTransport::Quic),
        _ => Err("--transport must be udp or quic".into()),
    }
}

fn parse_socket_arg(
    args: &[String],
    name: &str,
    default: Option<&str>,
) -> AnyResult<Option<SocketAddr>> {
    let value = parse_optional_arg(args, name)?.or_else(|| default.map(str::to_owned));
    value.map(|raw| raw.parse().map_err(Into::into)).transpose()
}

fn parse_string_arg(args: &[String], name: &str, default: &str) -> AnyResult<String> {
    Ok(parse_optional_arg(args, name)?.unwrap_or_else(|| default.to_owned()))
}

fn parse_u64_arg(args: &[String], name: &str, default: u64, min: u64, max: u64) -> AnyResult<u64> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(default);
    };
    let value = raw.parse::<u64>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}

fn parse_usize_arg(
    args: &[String],
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> AnyResult<usize> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(default);
    };
    let value = raw.parse::<usize>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}

fn parse_optional_arg(args: &[String], name: &str) -> AnyResult<Option<String>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    Ok(Some(value.clone()))
}

fn any_address_for(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn usage() -> &'static str {
    "usage: classmesh-transport-benchmark <server|client> --transport <udp|quic> --listen <ip:port> | --connect <ip:port> [--seconds N] [--pps N] [--payload-bytes N] [--cert-out FILE] [--cert FILE]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_packet_round_trips_header() {
        let packet = build_packet(DATA_MAGIC, 77, 123_456, 1_000);
        assert_eq!(packet.len(), 1_000);
        assert_eq!(parse_packet(&packet, DATA_MAGIC), Some((77, 123_456)));
        assert_eq!(parse_packet(&packet, ACK_MAGIC), None);
    }

    #[test]
    fn latency_tracker_is_bounded_and_reports_percentiles() {
        let mut tracker = LatencyTracker::new(3);
        tracker.observe(1_000);
        tracker.observe(2_000);
        tracker.observe(3_000);
        tracker.observe(4_000);
        assert_eq!(tracker.samples, 4);
        assert_eq!(tracker.recent_us.len(), 3);
        assert_eq!(tracker.min_ms(), 1.0);
        assert_eq!(tracker.max_ms(), 4.0);
        assert_eq!(tracker.percentile_ms(50), 3.0);
        assert_eq!(tracker.percentile_ms(100), 4.0);
    }

    #[test]
    fn parser_defaults_to_udp() {
        let args = vec!["bench".to_owned(), "client".to_owned()];
        assert_eq!(parse_transport(&args).unwrap(), BenchmarkTransport::Udp);
    }
}
