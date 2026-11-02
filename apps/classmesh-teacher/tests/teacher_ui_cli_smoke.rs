//! Exercise the actual Teacher UI executable, not only its argument parser.
//! These probes must terminate without opening an interactive window.

use std::ffi::OsStr;
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn run_bounded(args: &[&OsStr]) -> (ExitStatus, String, String) {
    let executable = env!("CARGO_BIN_EXE_classmesh-teacher-ui");
    let mut child = Command::new(executable)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Teacher UI executable should start");

    let deadline = Instant::now() + Duration::from_secs(4);
    let status = loop {
        if let Some(status) = child.try_wait().expect("check Teacher UI process") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("terminate unexpected interactive UI");
            let _ = child.wait();
            panic!("Teacher UI did not exit promptly for diagnostic CLI arguments");
        }
        thread::sleep(Duration::from_millis(50));
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .expect("captured stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("captured stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    (status, stdout, stderr)
}

#[test]
fn help_flags_exit_successfully_without_launching_gui() {
    for flag in ["--help", "-h"] {
        let (status, stdout, stderr) = run_bounded(&[OsStr::new(flag)]);
        assert_eq!(status.code(), Some(0), "{flag}: {stderr}");
        assert!(
            stdout.contains("Usage: classmesh-teacher-ui"),
            "{flag}: {stdout}"
        );
    }
}

#[test]
fn version_flags_print_package_version_without_launching_gui() {
    for flag in ["--version", "-V"] {
        let (status, stdout, stderr) = run_bounded(&[OsStr::new(flag)]);
        assert_eq!(status.code(), Some(0), "{flag}: {stderr}");
        assert!(
            stdout.contains(&format!(
                "classmesh-teacher-ui {}",
                env!("CARGO_PKG_VERSION")
            )),
            "{flag}: {stdout}"
        );
    }
}

#[test]
fn unsupported_and_multiple_flags_fail_closed_without_launching_gui() {
    for flags in [vec!["--unknown"], vec!["--help", "--version"], vec!["--"]] {
        let args: Vec<&OsStr> = flags.iter().map(OsStr::new).collect();
        let (status, _stdout, stderr) = run_bounded(&args);
        assert_eq!(status.code(), Some(2), "{flags:?}: {stderr}");
        assert!(
            stderr.contains("Teacher UI argument"),
            "{flags:?}: {stderr}"
        );
    }
}

#[cfg(not(windows))]
#[test]
fn bare_invocation_on_unsupported_platform_is_a_failure() {
    let (status, _stdout, stderr) = run_bounded(&[]);
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Windows only"), "{stderr}");
}
