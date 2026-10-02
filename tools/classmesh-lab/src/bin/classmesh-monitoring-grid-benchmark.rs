use std::env;
use std::process::ExitCode;

use classmesh_lab::monitoring_grid_benchmark::{
    MONITORING_GRID_SCALE_POINTS, MonitoringGridBenchmarkConfig, run_monitoring_grid_benchmark,
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
    let mut config = MonitoringGridBenchmarkConfig::default();
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--sources" => config.sources = parse_next(&mut args, "--sources")?,
            "--rounds" => config.rounds = parse_next(&mut args, "--rounds")?,
            "--scheduler-budget" => {
                config.scheduler_budget = parse_next(&mut args, "--scheduler-budget")?;
            }
            "--drain-budget" => config.drain_budget = parse_next(&mut args, "--drain-budget")?,
            unknown => return Err(format!("unknown argument {unknown:?}; use --help")),
        }
    }

    if !MONITORING_GRID_SCALE_POINTS.contains(&config.sources) {
        return Err(format!(
            "--sources must be one of 5, 10, 20, 30; got {}",
            config.sources
        ));
    }

    let report = run_monitoring_grid_benchmark(config).map_err(|error| error.to_string())?;
    println!("mode=synthetic-monitoring-grid");
    println!("physical_classroom=false");
    println!("physical_qualification=false");
    println!("sources={}", report.sources);
    println!("rounds={}", report.rounds);
    println!(
        "profile={}x{}@{}",
        report.profile_width, report.profile_height, report.profile_fps
    );
    println!("scheduler_budget={}", report.scheduler_budget);
    println!("drain_budget={}", report.drain_budget);
    println!("max_scheduler_actions={}", report.max_scheduler_actions);
    println!("max_drain_updates={}", report.max_drain_updates);
    println!("peak_pending_sources={}", report.peak_pending_sources);
    println!("superseded_updates={}", report.superseded_updates);
    println!("rejected_updates={}", report.rejected_updates);
    println!("promotion_actions={}", report.promotion_actions);
    println!("observed_sources={}", report.observed_sources);
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
        "ClassMesh synthetic monitoring-grid benchmark

Usage:
  classmesh-monitoring-grid-benchmark [options]

Options:
  --sources <5|10|20|30>      Monitoring sources (default: 30)
  --rounds <count>             Synthetic scheduling rounds (default: 30)
  --scheduler-budget <count>   Max scheduler actions/poll (default: 4)
  --drain-budget <count>       Max fan-in updates/drain (default: 8)
  --help                       Show this help

This is a deterministic software invariant check only.
It is not physical classroom performance evidence and cannot complete Phase 9F by itself."
    );
}
