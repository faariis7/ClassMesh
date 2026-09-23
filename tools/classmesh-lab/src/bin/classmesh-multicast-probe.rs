use std::error::Error;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use classmesh_network::MediaPacket;
use classmesh_network::multicast::{
    MulticastMembership, MulticastMembershipRegistry, MulticastProbeObservation,
    MulticastProbeOutcome, evaluate_multicast_probe,
};
use classmesh_network::udp::{DatagramError, UdpMediaSocket};
use classmesh_protocol::media::{MediaFlags, MediaPacketHeader};

const PROBE_TAG: &[u8; 8] = b"CMPROBE1";
const TOKEN_BYTES: usize = 16;
const PROBE_STREAM_ID: u32 = 0xffff_ff01;
const DEFAULT_COUNT: usize = 8;
const MAX_COUNT: usize = 100;
const DEFAULT_INTERVAL_MS: u64 = 100;
const MAX_INTERVAL_MS: u64 = 5_000;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MIN_TIMEOUT_MS: u64 = 250;
const MAX_TIMEOUT_MS: u64 = 60_000;
const IO_SLICE_MS: u64 = 200;
const WRITE_TIMEOUT_MS: u64 = 1_000;

type AnyError = Box<dyn Error + Send + Sync + 'static>;
type AnyResult<T> = Result<T, AnyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeToken([u8; TOKEN_BYTES]);

impl ProbeToken {
    fn generate() -> AnyResult<Self> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|error| format!("secure probe token generation failed: {error}"))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for ProbeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ProbeToken {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != TOKEN_BYTES * 2 {
            return Err("probe token must be exactly 32 hexadecimal characters");
        }
        let mut bytes = [0_u8; TOKEN_BYTES];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            let high = hex_nibble(value.as_bytes()[offset])?;
            let low = hex_nibble(value.as_bytes()[offset + 1])?;
            *output = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("probe token contains a non-hexadecimal character"),
    }
}

fn main() -> AnyResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let Some(command) = args.get(1).map(String::as_str) else {
        return Err(usage().into());
    };
    if matches!(command, "--help" | "-h" | "help") {
        println!("{}", usage());
        return Ok(());
    }

    match command {
        "token" => {
            println!("{}", ProbeToken::generate()?);
            Ok(())
        }
        "send" => run_sender(&args),
        "receive" => run_receiver(&args),
        _ => Err(usage().into()),
    }
}

fn run_sender(args: &[String]) -> AnyResult<()> {
    let group = parse_ipv4_required(args, "--group")?;
    let interface = parse_ipv4_required(args, "--interface")?;
    let port = parse_port_required(args)?;
    let token = parse_token_required(args)?;
    let count = parse_usize_arg(args, "--count", DEFAULT_COUNT, 1, MAX_COUNT)?;
    let interval_ms = parse_u64_arg(
        args,
        "--interval-ms",
        DEFAULT_INTERVAL_MS,
        1,
        MAX_INTERVAL_MS,
    )?;
    let membership = MulticastMembership::new(group, interface)
        .map_err(|error| format!("invalid multicast membership: {error:?}"))?;

    let socket = UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(interface, 0)))?;
    socket.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)))?;
    socket.set_multicast_ttl_v4(1)?;
    let destination = SocketAddr::V4(SocketAddrV4::new(membership.group(), port));

    let mut sent = 0_usize;
    for index in 0..count {
        let sequence = u32::try_from(index + 1).expect("probe count is bounded to u32");
        let packet = probe_packet(token, sequence);
        socket.send_packet_to(&packet, destination)?;
        sent = sent.saturating_add(1);
        if index + 1 < count {
            thread::sleep(Duration::from_millis(interval_ms));
        }
    }

    println!("classmesh_phase7_multicast_probe=1");
    println!("role=send");
    println!("interface={interface}");
    println!("group={group}");
    println!("port={port}");
    println!("sent={sent}");
    println!("ttl=1");
    println!("result=sent");
    Ok(())
}

fn run_receiver(args: &[String]) -> AnyResult<()> {
    let group = parse_ipv4_required(args, "--group")?;
    let interface = parse_ipv4_required(args, "--interface")?;
    let port = parse_port_required(args)?;
    let token = parse_token_required(args)?;
    let timeout_ms = parse_u64_arg(
        args,
        "--timeout-ms",
        DEFAULT_TIMEOUT_MS,
        MIN_TIMEOUT_MS,
        MAX_TIMEOUT_MS,
    )?;
    let membership = MulticastMembership::new(group, interface)
        .map_err(|error| format!("invalid multicast membership: {error:?}"))?;

    let socket = UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        port,
    )))?;
    socket.set_read_timeout(Some(Duration::from_millis(IO_SLICE_MS)))?;

    let mut registry = MulticastMembershipRegistry::default();
    let mut observation = MulticastProbeObservation {
        joined: false,
        probe_datagram_observed: false,
        left_cleanly: true,
    };
    let mut invalid_datagrams = 0_u64;
    let mut matching_source = None;

    match socket.join_multicast_v4(membership.group(), membership.interface()) {
        Ok(()) => {
            observation.joined = true;
            if let Err(error) = registry.join(membership) {
                let _ = socket.leave_multicast_v4(membership.group(), membership.interface());
                return Err(format!("multicast membership tracking failed: {error:?}").into());
            }
        }
        Err(error) => {
            eprintln!("ClassMesh multicast join failed: {error}");
        }
    }

    if observation.joined {
        let started = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        while started.elapsed() < timeout {
            match socket.receive_packet() {
                Ok((packet, source)) if probe_packet_matches(&packet, token) => {
                    observation.probe_datagram_observed = true;
                    matching_source = Some(source);
                    break;
                }
                Ok(_) => {
                    invalid_datagrams = invalid_datagrams.saturating_add(1);
                }
                Err(DatagramError::Io(error))
                    if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
                {
                }
                Err(error) => {
                    invalid_datagrams = invalid_datagrams.saturating_add(1);
                    eprintln!("ClassMesh multicast probe ignored datagram error: {error}");
                }
            }
        }
    }

    for active in registry.take_all() {
        if let Err(error) = socket.leave_multicast_v4(active.group(), active.interface()) {
            observation.left_cleanly = false;
            eprintln!("ClassMesh multicast leave failed: {error}");
        }
    }

    let outcome = evaluate_multicast_probe(observation);
    println!("classmesh_phase7_multicast_probe=1");
    println!("role=receive");
    println!("interface={interface}");
    println!("group={group}");
    println!("port={port}");
    println!("joined={}", observation.joined);
    println!(
        "probe_datagram_observed={}",
        observation.probe_datagram_observed
    );
    println!("left_cleanly={}", observation.left_cleanly);
    println!("invalid_datagrams={invalid_datagrams}");
    if let Some(source) = matching_source {
        println!("matching_source={source}");
    }
    match outcome {
        MulticastProbeOutcome::Available => {
            println!("result=available");
            Ok(())
        }
        MulticastProbeOutcome::Unavailable(reason) => {
            println!("result=unavailable");
            println!("reason={reason:?}");
            Err(format!("multicast probe unavailable: {reason:?}").into())
        }
    }
}

fn probe_packet(token: ProbeToken, sequence: u32) -> MediaPacket {
    let mut payload = Vec::with_capacity(PROBE_TAG.len() + TOKEN_BYTES);
    payload.extend_from_slice(PROBE_TAG);
    payload.extend_from_slice(&token.0);
    let payload_len = u16::try_from(payload.len()).expect("probe payload fits media header");
    MediaPacket {
        header: MediaPacketHeader {
            protocol_major: 0,
            protocol_minor: 1,
            flags: MediaFlags::FRAME_START | MediaFlags::FRAME_END,
            stream_id: PROBE_STREAM_ID,
            frame_id: u64::from(sequence),
            sequence,
            packet_index: 0,
            packet_count: 1,
            timestamp_us: 0,
            payload_len,
        },
        payload,
    }
}

fn probe_packet_matches(packet: &MediaPacket, token: ProbeToken) -> bool {
    packet.header.protocol_major == 0
        && packet.header.protocol_minor == 1
        && packet.header.stream_id == PROBE_STREAM_ID
        && packet.header.packet_index == 0
        && packet.header.packet_count == 1
        && packet.payload.len() == PROBE_TAG.len() + TOKEN_BYTES
        && packet.payload.starts_with(PROBE_TAG)
        && packet.payload[PROBE_TAG.len()..] == token.0
}

fn parse_token_required(args: &[String]) -> AnyResult<ProbeToken> {
    let raw = required_arg(args, "--token")?;
    raw.parse::<ProbeToken>()
        .map_err(|error| format!("invalid --token: {error}").into())
}

fn parse_ipv4_required(args: &[String], name: &str) -> AnyResult<Ipv4Addr> {
    let raw = required_arg(args, name)?;
    raw.parse::<Ipv4Addr>()
        .map_err(|_| format!("{name} must be an IPv4 address").into())
}

fn parse_port_required(args: &[String]) -> AnyResult<u16> {
    let raw = required_arg(args, "--port")?;
    let port = raw
        .parse::<u16>()
        .map_err(|_| "--port must be an integer from 1 to 65535")?;
    if port == 0 {
        return Err("--port must be non-zero".into());
    }
    Ok(port)
}

fn required_arg<'a>(args: &'a [String], name: &str) -> AnyResult<&'a str> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing required {name}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} requires a value").into())
}

fn parse_u64_arg(
    args: &[String],
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> AnyResult<u64> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(default);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}").into());
    }
    Ok(value)
}

fn parse_usize_arg(
    args: &[String],
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> AnyResult<usize> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(default);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}").into());
    }
    Ok(value)
}

const fn usage() -> &'static str {
    "ClassMesh Phase 7 multicast probe\n\
\n\
Usage:\n\
  classmesh-multicast-probe token\n\
  classmesh-multicast-probe receive --group <239.x.x.x> --interface <IPv4> --port <1-65535> --token <32-hex> [--timeout-ms 5000]\n\
  classmesh-multicast-probe send --group <239.x.x.x> --interface <IPv4> --port <1-65535> --token <32-hex> [--count 8] [--interval-ms 100]\n\
\n\
This tool sends diagnostic CMV1 probe packets only. It does not qualify production media security, classroom scale, or a default transport."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_is_exact_and_case_insensitive() {
        let lower = "00112233445566778899aabbccddeeff";
        let token = lower.parse::<ProbeToken>().expect("valid token");
        assert_eq!(token.to_string(), lower);
        assert_eq!(
            "00112233445566778899AABBCCDDEEFF"
                .parse::<ProbeToken>()
                .expect("uppercase token"),
            token
        );
    }

    #[test]
    fn token_parser_rejects_bad_length_and_non_hex() {
        assert!("00".parse::<ProbeToken>().is_err());
        assert!("00112233445566778899aabbccddeefg"
            .parse::<ProbeToken>()
            .is_err());
    }

    #[test]
    fn probe_packet_requires_exact_tag_token_and_stream() {
        let token = "00112233445566778899aabbccddeeff"
            .parse::<ProbeToken>()
            .expect("token");
        let packet = probe_packet(token, 7);
        assert!(probe_packet_matches(&packet, token));

        let other = "ffeeddccbbaa99887766554433221100"
            .parse::<ProbeToken>()
            .expect("other token");
        assert!(!probe_packet_matches(&packet, other));

        let mut wrong_stream = packet.clone();
        wrong_stream.header.stream_id = 1;
        assert!(!probe_packet_matches(&wrong_stream, token));
    }

    #[test]
    fn bounded_numeric_arguments_reject_out_of_range_values() {
        let args = vec![
            "probe".to_owned(),
            "send".to_owned(),
            "--count".to_owned(),
            "101".to_owned(),
        ];
        assert!(parse_usize_arg(&args, "--count", DEFAULT_COUNT, 1, MAX_COUNT).is_err());

        let args = vec![
            "probe".to_owned(),
            "receive".to_owned(),
            "--timeout-ms".to_owned(),
            "100".to_owned(),
        ];
        assert!(parse_u64_arg(
            &args,
            "--timeout-ms",
            DEFAULT_TIMEOUT_MS,
            MIN_TIMEOUT_MS,
            MAX_TIMEOUT_MS
        )
        .is_err());
    }
}
