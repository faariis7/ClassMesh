use std::env;
use std::process::ExitCode;

use classmesh_lab::adaptive_controller_benchmark::{
    ADAPTIVE_SCALE_POINTS, AdaptiveControllerBenchmarkConfig, run_adaptive_controller_benchmark,
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
    let mut config = AdaptiveControllerBenchmarkConfig::default();
    let mut args = env::args().skip(1);

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--receivers" => config.receivers = parse_next(&mut args, "--receivers")?,
            "--rounds" => config.rounds = parse_next(&mut args, "--rounds")?,
            unknown => return Err(format!("unknown argument {unknown:?}; use --help")),
        }
    }

    if !ADAPTIVE_SCALE_POINTS.contains(&config.receivers) {
        return Err(format!(
            "--receivers must be one of 5, 10, 20, 30; got {}",
            config.receivers
        ));
    }

    let report = run_adaptive_controller_benchmark(config)
        .map_err(|error| format!("adaptive benchmark failed: {error:?}"))?;

    println!("mode=synthetic-adaptive-controller");
    println!("physical_qualification=false");
    println!("production_default_selected=false");
    println!("receivers={}", report.receivers);
    println!("rounds={}", report.rounds);
    println!(
        "healthy_high_after_weak_degrade={}",
        report.healthy_high_after_weak_degrade
    );
    println!("weak_degraded_tier={:?}", report.weak_degraded_tier);
    println!("weak_recovered_tier={:?}", report.weak_recovered_tier);
    println!(
        "noisy_receiver_tier_changes={}",
        report.noisy_receiver_tier_changes
    );
    println!("max_routed_receivers={}", report.max_routed_receivers);
    println!(
        "unresolved_transport_blocked={}",
        report.unresolved_transport_blocked
    );
    println!(
        "qualified_switch_required_hysteresis={}",
        report.qualified_switch_required_hysteresis
    );
    println!(
        "unresolved_rendition_blocked={}",
        report.unresolved_rendition_blocked
    );
    println!(
        "reliable_fallback_eligible_without_default_selection={}",
        report.reliable_fallback_eligible_without_default_selection
    );
    println!("synthetic_invariants_passed=true");
    Ok(())
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
        "ClassMesh synthetic adaptive-controller qualification benchmark

Usage:
  classmesh-adaptive-controller-benchmark [options]

Options:
  --receivers <5|10|20|30>   Receiver count (default: 30)
  --rounds <count>            Alternating noisy-sample rounds (default: 30)
  --help                      Show this help

This is deterministic software evidence only. It exercises the production
per-receiver quality/cohort, transport-topology gate/hysteresis, and
rendition/SFU eligibility contracts. It never establishes physical qualification
and never selects a production transport, topology, relay, or rendition default."
    );
}
