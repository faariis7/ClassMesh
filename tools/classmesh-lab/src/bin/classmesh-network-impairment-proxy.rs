use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use classmesh_network::impairment::{ImpairmentConfig, ImpairmentDecision, ImpairmentEngine};
use classmesh_network::udp::{MAX_MEDIA_DATAGRAM, decode_datagram};

const DEFAULT_LISTEN: &str = "0.0.0.0:57010";
const DEFAULT_SECONDS: u64 = 60;
const DEFAULT_QUEUE_CAPACITY: usize = 4_096;
const MAX_RECEIVES_PER_TICK: usize = 256;

#[derive(Debug)]
struct ScheduledDatagram {
    due_us: u64,
    order: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
struct BoundedScheduler {
    capacity: usize,
    next_order: u64,
    queued: Vec<ScheduledDatagram>,
    queue_drops: u64,
    peak_depth: usize,
}

impl BoundedScheduler {
    fn new(capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("queue capacity must be greater than zero");
        }
        Ok(Self {
            capacity,
            next_order: 0,
            queued: Vec::with_capacity(capacity.min(4_096)),
            queue_drops: 0,
            peak_depth: 0,
        })
    }

    fn push(&mut self, due_us: u64, data: Vec<u8>) -> bool {
        if self.queued.len() >= self.capacity {
            self.queue_drops = self.queue_drops.saturating_add(1);
            return false;
        }

        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        self.queued.push(ScheduledDatagram {
            due_us,
            order,
            data,
        });
        self.queued
            .sort_unstable_by_key(|packet| (packet.due_us, packet.order));
        self.peak_depth = self.peak_depth.max(self.queued.len());
        true
    }

    fn pop_due(&mut self, now_us: u64) -> Option<ScheduledDatagram> {
        if self.queued.first().is_some_and(|packet| packet.due_us <= now_us) {
            Some(self.queued.remove(0))
        } else {
            None
        }
    }

    fn len(&self) -> usize {
        self.queued.len()
    }
}

#[derive(Debug, Default)]
struct ProxyStats {
    received: u64,
    forwarded: u64,
    forwarded_bytes: u64,
    invalid_datagrams: u64,
    send_errors: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", Some(DEFAULT_LISTEN))?
        .expect("default listen address exists");
    let destination = parse_socket_arg(&args, "--to", None)?
        .ok_or("--to <receiver-ip:port> is required")?;
    let seconds = parse_u64_arg(&args, "--seconds", DEFAULT_SECONDS, 1, 86_400)?;
    let queue_capacity = parse_usize_arg(
        &args,
        "--queue-capacity",
        DEFAULT_QUEUE_CAPACITY,
        1,
        65_536,
    )?;
    let loss_basis_points = parse_u16_arg(&args, "--loss-bp", 0, 0, 10_000)?;
    let reorder_basis_points = parse_u16_arg(&args, "--reorder-bp", 0, 0, 10_000)?;
    let jitter_ms = parse_u64_arg(&args, "--jitter-ms", 0, 0, 60_000)?;
    let reorder_delay_ms = parse_u64_arg(&args, "--reorder-delay-ms", 0, 0, 60_000)?;
    let seed = parse_u64_arg(&args, "--seed", 1, 0, u64::MAX)?;

    let config = ImpairmentConfig {
        loss_basis_points,
        reorder_basis_points,
        jitter_max_us: jitter_ms.saturating_mul(1_000),
        reorder_extra_delay_us: reorder_delay_ms.saturating_mul(1_000),
        seed,
    };
    let mut engine = ImpairmentEngine::new(config)?;
    let mut scheduler = BoundedScheduler::new(queue_capacity)?;

    let receive_socket = UdpSocket::bind(listen)?;
    receive_socket.set_nonblocking(true)?;
    let send_socket = UdpSocket::bind(any_address_for(destination.ip()))?;
    send_socket.set_nonblocking(true)?;

    let bound = receive_socket.local_addr()?;
    eprintln!(
        "ClassMesh network impairment proxy: listen={bound} -> {destination}, loss={:.2}%, reorder={:.2}%, jitter={}ms, reorder_delay={}ms, queue_capacity={}, seed={}, duration={}s",
        f64::from(loss_basis_points) / 100.0,
        f64::from(reorder_basis_points) / 100.0,
        jitter_ms,
        reorder_delay_ms,
        queue_capacity,
        seed,
        seconds
    );
    eprintln!("Only valid ClassMesh media datagrams are forwarded; feedback should bypass this proxy.");

    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started);
    let mut next_report = started;
    let mut stats = ProxyStats::default();
    let mut buffer = [0_u8; MAX_MEDIA_DATAGRAM];

    while Instant::now() < deadline || scheduler.len() > 0 {
        if Instant::now() < deadline {
            for _ in 0..MAX_RECEIVES_PER_TICK {
                match receive_socket.recv_from(&mut buffer) {
                    Ok((len, _source)) => {
                        stats.received = stats.received.saturating_add(1);
                        let datagram = &buffer[..len];
                        if decode_datagram(datagram).is_err() {
                            stats.invalid_datagrams = stats.invalid_datagrams.saturating_add(1);
                            continue;
                        }

                        let now_us = elapsed_us(started);
                        match engine.plan(now_us) {
                            ImpairmentDecision::Drop => {}
                            ImpairmentDecision::DeliverAt { due_us, .. } => {
                                let _ = scheduler.push(due_us, datagram.to_vec());
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(format!("impairment proxy receive failed: {error}").into()),
                }
            }
        }

        let now_us = elapsed_us(started);
        while let Some(packet) = scheduler.pop_due(now_us) {
            match send_socket.send_to(&packet.data, destination) {
                Ok(sent) => {
                    stats.forwarded = stats.forwarded.saturating_add(1);
                    stats.forwarded_bytes = stats
                        .forwarded_bytes
                        .saturating_add(u64::try_from(sent).unwrap_or(u64::MAX));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    stats.send_errors = stats.send_errors.saturating_add(1);
                }
                Err(error) => {
                    stats.send_errors = stats.send_errors.saturating_add(1);
                    eprintln!("impairment proxy send failed: {error}");
                }
            }
        }

        if Instant::now() >= next_report {
            report(&stats, &engine, &scheduler);
            next_report = Instant::now()
                .checked_add(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    report(&stats, &engine, &scheduler);
    eprintln!("ClassMesh network impairment proxy complete");
    Ok(())
}

fn report(stats: &ProxyStats, engine: &ImpairmentEngine, scheduler: &BoundedScheduler) {
    eprintln!(
        "impairment stats: received={} forwarded={} bytes={} impairment_drops={} reordered={} queue_drops={} invalid={} send_errors={} queue_depth={} peak_queue_depth={}",
        stats.received,
        stats.forwarded,
        stats.forwarded_bytes,
        engine.packets_dropped(),
        engine.packets_reordered(),
        scheduler.queue_drops,
        stats.invalid_datagrams,
        stats.send_errors,
        scheduler.len(),
        scheduler.peak_depth
    );
}

fn any_address_for(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn parse_socket_arg(
    args: &[String],
    name: &str,
    default: Option<&str>,
) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
    let value = parse_optional_arg(args, name)?.or_else(|| default.map(str::to_owned));
    value.map(|raw| raw.parse().map_err(Into::into)).transpose()
}

fn parse_u16_arg(
    args: &[String],
    name: &str,
    default: u16,
    min: u16,
    max: u16,
) -> Result<u16, Box<dyn std::error::Error>> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(default);
    };
    let value = raw.parse::<u16>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}

fn parse_u64_arg(
    args: &[String],
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
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
) -> Result<usize, Box<dyn std::error::Error>> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(default);
    };
    let value = raw.parse::<usize>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}

fn parse_optional_arg(
    args: &[String],
    name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    Ok(Some(value.clone()))
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_releases_by_due_time_and_preserves_ties() {
        let mut scheduler = BoundedScheduler::new(4).unwrap();
        assert!(scheduler.push(30, vec![3]));
        assert!(scheduler.push(10, vec![1]));
        assert!(scheduler.push(10, vec![2]));

        assert!(scheduler.pop_due(9).is_none());
        assert_eq!(scheduler.pop_due(10).unwrap().data, vec![1]);
        assert_eq!(scheduler.pop_due(10).unwrap().data, vec![2]);
        assert_eq!(scheduler.pop_due(30).unwrap().data, vec![3]);
    }

    #[test]
    fn scheduler_drops_new_packets_when_bounded_queue_is_full() {
        let mut scheduler = BoundedScheduler::new(2).unwrap();
        assert!(scheduler.push(100, vec![1]));
        assert!(scheduler.push(200, vec![2]));
        assert!(!scheduler.push(50, vec![3]));
        assert_eq!(scheduler.queue_drops, 1);
        assert_eq!(scheduler.peak_depth, 2);
    }

    #[test]
    fn basis_point_arguments_are_bounded() {
        let args = vec![
            "proxy".to_owned(),
            "--loss-bp".to_owned(),
            "500".to_owned(),
        ];
        assert_eq!(parse_u16_arg(&args, "--loss-bp", 0, 0, 10_000).unwrap(), 500);

        let invalid = vec![
            "proxy".to_owned(),
            "--loss-bp".to_owned(),
            "10001".to_owned(),
        ];
        assert!(parse_u16_arg(&invalid, "--loss-bp", 0, 0, 10_000).is_err());
    }
}
