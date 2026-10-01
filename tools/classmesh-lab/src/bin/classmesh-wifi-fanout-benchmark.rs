use std::env;
use std::process::ExitCode;

use classmesh_lab::wifi_direct_fanout::{DirectFanoutBenchmarkConfig, run_direct_fanout_benchmark};
use classmesh_lab::wifi_fanout_benchmark::{
    WIFI_FANOUT_EVIDENCE_VERSION, WIFI_FANOUT_SCALE_POINTS, WifiFanoutBenchmarkPlan,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error={error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut receivers = 5_usize;
    let mut frames = 120_u64;
    let mut payload_bytes = 1_200_usize;
    let mut queue_capacity = 4_usize;
    let mut weak_index = 1_usize;
    let mut weak_drain_every = 8_u64;

    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--receivers" => receivers = parse_next(&mut args, "--receivers")?,
            "--frames" => frames = parse_next(&mut args, "--frames")?,
            "--payload-bytes" => payload_bytes = parse_next(&mut args, "--payload-bytes")?,
            "--queue-capacity" => queue_capacity = parse_next(&mut args, "--queue-capacity")?,
            "--weak-index" => weak_index = parse_next(&mut args, "--weak-index")?,
            "--weak-drain-every" => {
                weak_drain_every = parse_next(&mut args, "--weak-drain-every")?;
            }
            unknown => return Err(format!("unknown argument {unknown:?}; use --help")),
        }
    }

    if !WIFI_FANOUT_SCALE_POINTS.contains(&receivers) {
        return Err(format!(
            "--receivers must be one of 5, 10, 20, 30; got {receivers}"
        ));
    }
    if weak_index == 0 || weak_index > receivers {
        return Err(format!(
            "--weak-index must be in 1..={receivers}; got {weak_index}"
        ));
    }

    let receiver_ids: Vec<String> = (1..=receivers)
        .map(|index| format!("student-{index:02}"))
        .collect();
    let weak_receiver = receiver_ids[weak_index - 1].clone();
    let plan = WifiFanoutBenchmarkPlan {
        schema_version: WIFI_FANOUT_EVIDENCE_VERSION,
        run_id: format!("synthetic-direct-{receivers}"),
        strategy_label: "direct-unicast".to_owned(),
        receiver_ids,
        duration_seconds: duration_seconds_for_frames(frames),
        weak_receiver_probe: Some(weak_receiver),
    };

    let report = run_direct_fanout_benchmark(
        &plan,
        DirectFanoutBenchmarkConfig {
            frame_count: frames,
            payload_bytes,
            queue_capacity,
            weak_drain_every,
        },
    )
    .map_err(|error| error.to_string())?;

    println!("mode=synthetic-direct-fanout");
    println!("physical_wifi=false");
    println!("strategy_selection=false");
    println!("receivers={}", report.receivers.len());
    println!("frames_published={}", report.frames_published);
    println!("payload_bytes_per_frame={}", report.payload_bytes_per_frame);
    println!(
        "shared_allocation_mismatches={}",
        report.shared_allocation_mismatches
    );
    for receiver in report.receivers {
        println!(
            "receiver={} delivered={} queue_dropped={} max_queued={} queued_at_end={}",
            receiver.receiver_id,
            receiver.delivered,
            receiver.queue_dropped,
            receiver.max_queued,
            receiver.queued_at_end
        );
    }

    Ok(())
}

fn duration_seconds_for_frames(frames: u64) -> u32 {
    let seconds = frames.saturating_add(29) / 30;
    u32::try_from(seconds.clamp(1, u64::from(u32::MAX))).unwrap_or(u32::MAX)
}

fn parse_next<T>(args: &mut impl Iterator<Item = String>, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = args
        .next()
        .ok_or_else(|| format!("{name} requires a value"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {name}: {value:?}"))
}

fn print_help() {
    println!(
        "ClassMesh synthetic direct Wi-Fi fanout baseline

Usage:
  classmesh-wifi-fanout-benchmark [options]

Options:
  --receivers <5|10|20|30>    Receiver count (default: 5)
  --frames <count>             Synthetic frames (default: 120)
  --payload-bytes <bytes>      H.264 payload bytes/frame (default: 1200)
  --queue-capacity <count>     Per-receiver bounded queue (default: 4)
  --weak-index <1..N>          Receiver intentionally drained slowly (default: 1)
  --weak-drain-every <frames>  Drain weak receiver every N frames (default: 8)
  --help                       Show this help

This is a deterministic synthetic fanout/isolation benchmark.
It is NOT physical Wi-Fi evidence and does NOT select UDP, QUIC, WebRTC, or SFU."
    );
}
