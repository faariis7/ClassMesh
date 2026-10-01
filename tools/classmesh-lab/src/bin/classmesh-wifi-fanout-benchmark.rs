use std::env;
use std::process::ExitCode;

use classmesh_lab::wifi_direct_fanout::{DirectFanoutBenchmarkConfig, run_direct_fanout_benchmark};
use classmesh_lab::wifi_fanout_benchmark::{
    WIFI_FANOUT_EVIDENCE_VERSION, WIFI_FANOUT_SCALE_POINTS, WifiFanoutBenchmarkPlan,
};
use classmesh_lab::wifi_relay_fanout::run_relay_fanout_benchmark;

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
    let mut strategy = "direct-unicast".to_owned();
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
            "--strategy" => strategy = parse_next(&mut args, "--strategy")?,
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

    if !matches!(strategy.as_str(), "direct-unicast" | "relay") {
        return Err(format!(
            "--strategy must be direct-unicast or relay; got {strategy:?}"
        ));
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
        run_id: format!("synthetic-{}-{receivers}", strategy.replace('-', "_")),
        strategy_label: strategy.clone(),
        receiver_ids,
        duration_seconds: duration_seconds_for_frames(frames),
        weak_receiver_probe: Some(weak_receiver),
    };
    let config = DirectFanoutBenchmarkConfig {
        frame_count: frames,
        payload_bytes,
        queue_capacity,
        weak_drain_every,
    };

    match strategy.as_str() {
        "direct-unicast" => {
            let report =
                run_direct_fanout_benchmark(&plan, config).map_err(|error| error.to_string())?;
            println!("mode=synthetic-direct-fanout");
            println!("physical_wifi=false");
            println!("strategy_selection=false");
            println!("receivers={}", report.receivers.len());
            println!(
                "teacher_uplink_replication_factor={}",
                report.receivers.len()
            );
            println!("frames_published={}", report.frames_published);
            println!("payload_bytes_per_frame={}", report.payload_bytes_per_frame);
            println!(
                "shared_allocation_mismatches={}",
                report.shared_allocation_mismatches
            );
            print_receivers(report.receivers);
        }
        "relay" => {
            let report =
                run_relay_fanout_benchmark(&plan, config).map_err(|error| error.to_string())?;
            println!("mode=synthetic-relay-fanout");
            println!("physical_wifi=false");
            println!("strategy_selection=false");
            println!("receivers={}", report.receivers.len());
            println!("teacher_uplink_replication_factor=1");
            println!("teacher_frames_to_relay={}", report.teacher_frames_to_relay);
            println!("teacher_payload_bytes={}", report.teacher_payload_bytes);
            println!("relay_frames_published={}", report.relay_frames_published);
            println!("payload_bytes_per_frame={}", report.payload_bytes_per_frame);
            println!(
                "shared_allocation_mismatches={}",
                report.shared_allocation_mismatches
            );
            print_receivers(report.receivers);
        }
        _ => unreachable!("strategy validated above"),
    }

    Ok(())
}

fn print_receivers(receivers: Vec<classmesh_lab::wifi_direct_fanout::DirectFanoutReceiverReport>) {
    for receiver in receivers {
        println!(
            "receiver={} delivered={} queue_dropped={} max_queued={} queued_at_end={}",
            receiver.receiver_id,
            receiver.delivered,
            receiver.queue_dropped,
            receiver.max_queued,
            receiver.queued_at_end
        );
    }
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
        "ClassMesh synthetic Wi-Fi fanout benchmark

Usage:
  classmesh-wifi-fanout-benchmark [options]

Options:
  --strategy <direct-unicast|relay>  Synthetic topology (default: direct-unicast)
  --receivers <5|10|20|30>           Receiver count (default: 5)
  --frames <count>                    Synthetic frames (default: 120)
  --payload-bytes <bytes>             H.264 payload bytes/frame (default: 1200)
  --queue-capacity <count>            Per-receiver bounded queue (default: 4)
  --weak-index <1..N>                 Receiver intentionally drained slowly (default: 1)
  --weak-drain-every <frames>         Drain weak receiver every N frames (default: 8)
  --help                              Show this help

Both strategies are deterministic software baselines.
relay models Teacher -> one relay -> bounded per-receiver relay fanout.
Neither mode is physical Wi-Fi evidence or a real SFU/WebRTC implementation,
and neither selects the final Wi-Fi strategy."
    );
}
