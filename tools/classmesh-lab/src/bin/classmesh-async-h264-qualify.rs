use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

#[path = "async_h264/fixture.rs"]
mod fixture;
#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "async_h264/windows_lab.rs"]
mod windows_lab;

const USAGE: &str = "classmesh-async-h264-qualify --inventory\n\
                    classmesh-async-h264-qualify --inspect FIRST.h264 SECOND.h264\n\
                    classmesh-async-h264-qualify --run FIRST.h264 SECOND.h264 [--present]";

#[derive(Debug)]
struct Failure {
    stage: &'static str,
    detail: String,
    hresult: Option<String>,
}

impl Failure {
    fn new(stage: &'static str, detail: impl ToString) -> Self {
        Self {
            stage,
            detail: detail.to_string(),
            hresult: None,
        }
    }
}

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let mut report = json!({
        "schema": 1,
        "status": "failed",
        "os": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "physical_qualification": null,
        "completed_stages": [],
        "presentation": "not_requested",
    });
    let result = dispatch(&args, &mut report);
    let exit = match result {
        Ok(status) => {
            report["status"] = json!(status);
            ExitCode::SUCCESS
        }
        Err(failure) => {
            report["failure"] = json!({
                "stage": failure.stage, "detail": failure.detail, "hresult": failure.hresult,
            });
            ExitCode::FAILURE
        }
    };
    println!("{report:#}");
    exit
}

fn dispatch(args: &[std::ffi::OsString], report: &mut Value) -> Result<&'static str, Failure> {
    let mode = args.first().and_then(|value| value.to_str());
    match (mode, args) {
        (Some("--inventory"), [_]) => {
            report["mode"] = json!("inventory");
            run_windows(None, false, report)?;
            Ok("inventory_complete")
        }
        (Some("--inspect" | "--run"), [mode, first, second, options @ ..]) => {
            let inspect = mode == "--inspect";
            let present = options == [OsStr::new("--present")];
            if !(options.is_empty() || present && !inspect) {
                return Err(Failure::new("arguments", USAGE));
            }
            report["mode"] = json!(if inspect { "inspect" } else { "run" });
            if present {
                report["presentation"] = json!("pending");
            }
            let first = fixture::load(Path::new(first), "first_fixture")?;
            report["first_fixture"] = first.describe();
            complete(report, "first_fixture");
            let second = fixture::load(Path::new(second), "second_fixture")?;
            report["second_fixture"] = second.describe();
            complete(report, "second_fixture");
            if inspect {
                return Ok("fixtures_inspected");
            }
            run_windows(Some([&first, &second]), present, report)?;
            Ok("hardware_checks_passed")
        }
        _ => Err(Failure::new("arguments", USAGE)),
    }
}

fn complete(report: &mut Value, stage: &'static str) {
    eprintln!("completed_stage={stage}");
    report["completed_stages"]
        .as_array_mut()
        .expect("report stages array")
        .push(json!(stage));
}

fn run_windows(
    fixtures: Option<[&fixture::Fixture; 2]>,
    present: bool,
    report: &mut Value,
) -> Result<(), Failure> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    return windows_lab::run(fixtures, present, report);
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (fixtures, present, report);
        Err(Failure::new(
            "platform",
            "Media Foundation qualification requires Windows x64",
        ))
    }
}
