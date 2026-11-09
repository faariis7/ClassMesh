//! An intentionally loopback-only diagnostic. Records do not represent a
//! Teacher capture, Service enrollment, authorized stream, or GUI presentation.
use std::error::Error;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use classmesh_lab::recorded_media::{MAX_INPUT_BYTES, parse_access_units, validate_params};
use classmesh_network::transport::{UdpFrameSender, UdpSenderConfig};
use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::{Codec, EncodedFrameMeta};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 || args[1] != "--input" || args[3] != "--udp-to" || args[5] != "--fps" {
        return Err("usage: classmesh-recorded-media-udp --input <AUD-delimited.h264> --udp-to 127.0.0.1:<port> --fps <1..60>".into());
    }
    let target: SocketAddr = args[4].parse()?;
    let fps: u8 = args[6].parse()?;
    validate_params(target, fps)?;
    if !matches!(target.ip(), IpAddr::V4(_)) {
        return Err("diagnostic requires IPv4 loopback only".into());
    }
    let filename = Path::new(&args[2]);
    if std::fs::metadata(filename)?.len() > u64::try_from(MAX_INPUT_BYTES)? {
        return Err("recorded media input exceeds bounded size".into());
    }
    // Do not trust mutable file size metadata across the open: bound the
    // *actual read* as well, so a raced file replacement cannot allocate an
    // unbounded buffer or feed unchecked bytes into the network sender.
    let mut bytes = Vec::new();
    std::fs::File::open(filename)?
        .take(u64::try_from(MAX_INPUT_BYTES)? + 1)
        .read_to_end(&mut bytes)?;
    let access_units = parse_access_units(&bytes)?;
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut sender = UdpFrameSender::bind(local, UdpSenderConfig::presentation(1, target))
        .map_err(|err| format!("failed to create diagnostic sender: {err:?}"))?;
    eprintln!(
        "LAB_ONLY_RECORDED_H264: localhost media transport. NO Teacher capture, authenticated Service/Worker, hardware decode, or rendered frames"
    );
    let started = Instant::now();
    let mut idr_count = 0;
    for (index, au) in access_units.iter().enumerate() {
        let frame_id = u64::try_from(index + 1)?;
        let timestamp_us = u64::try_from(index)?.saturating_mul(1_000_000) / u64::from(fps);
        let due = started + Duration::from_micros(timestamp_us);
        if let Some(delay) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(delay);
        }
        idr_count += u64::from(au.keyframe);
        let frame = SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id,
                timestamp_us,
                keyframe: au.keyframe,
            },
            Codec::H264,
            au.data.to_vec(),
        );
        sender
            .send_frame(timestamp_us, &frame)
            .map_err(|err| format!("diagnostic UDP send failed: {err:?}"))?;
    }
    let stats = sender.stats();
    eprintln!(
        "LAB_TRANSPORT_SENT frames={} idr={} datagrams={} bytes={} input_bytes={} fps={fps}",
        stats.frames_sent,
        idr_count,
        stats.packets_sent,
        stats.payload_bytes_sent,
        bytes.len()
    );
    Ok(())
}
