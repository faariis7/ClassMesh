use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchAction {
    Ui,
    Offline,
    Help,
    Version,
}

/// Never start the interactive Teacher window for an unrecognized installer
/// or support-tool argument: a stray flag must fail closed, not block a script.
fn parse_launch_action(args: &[OsString]) -> Result<LaunchAction, &'static str> {
    match args {
        [] => Ok(LaunchAction::Ui),
        [flag] => match flag.to_str() {
            Some("--offline") => Ok(LaunchAction::Offline),
            Some("--help" | "-h") => Ok(LaunchAction::Help),
            Some("--version" | "-V") => Ok(LaunchAction::Version),
            _ => Err("unsupported Teacher UI argument"),
        },
        _ => Err("expected at most one Teacher UI argument"),
    }
}

fn requested_action() -> LaunchAction {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    parse_launch_action(&args).unwrap_or_else(|error| {
        eprintln!("{error}; run classmesh-teacher-ui --help for usage");
        std::process::exit(2);
    })
}

fn print_help() {
    println!("Usage: classmesh-teacher-ui [--offline | --help | --version]");
    println!("Without provisioned Teacher identity, startup fails closed.");
    println!("--offline explicitly starts the disconnected diagnostic console.");
}

fn print_version() {
    println!("classmesh-teacher-ui {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    match requested_action() {
        LaunchAction::Ui => {
            eprintln!(
                "Teacher identity not provisioned; refusing live startup (use --offline for diagnostics)"
            );
            std::process::exit(3);
        }
        LaunchAction::Offline => classmesh_teacher::ui_egui::run_teacher_ui(),
        LaunchAction::Help => {
            print_help();
            Ok(())
        }
        LaunchAction::Version => {
            print_version();
            Ok(())
        }
    }
}

#[cfg(not(windows))]
fn main() {
    match requested_action() {
        LaunchAction::Ui | LaunchAction::Offline => {
            eprintln!("classmesh-teacher-ui is available on Windows only");
            std::process::exit(1);
        }
        LaunchAction::Help => print_help(),
        LaunchAction::Version => print_version(),
    }
}

#[cfg(test)]
mod tests {
    use super::{LaunchAction, parse_launch_action};
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn no_arguments_launches_ui() {
        assert_eq!(parse_launch_action(&args(&[])), Ok(LaunchAction::Ui));
    }

    #[test]
    fn offline_diagnostics_require_explicit_opt_in() {
        assert_eq!(
            parse_launch_action(&args(&["--offline"])),
            Ok(LaunchAction::Offline)
        );
        assert_eq!(parse_launch_action(&args(&[])), Ok(LaunchAction::Ui));
    }

    #[test]
    fn supported_diagnostic_flags_do_not_launch_ui() {
        assert_eq!(
            parse_launch_action(&args(&["--help"])),
            Ok(LaunchAction::Help)
        );
        assert_eq!(parse_launch_action(&args(&["-h"])), Ok(LaunchAction::Help));
        assert_eq!(
            parse_launch_action(&args(&["--version"])),
            Ok(LaunchAction::Version)
        );
        assert_eq!(
            parse_launch_action(&args(&["-V"])),
            Ok(LaunchAction::Version)
        );
    }

    #[test]
    fn unsupported_and_multiple_flags_fail_closed() {
        assert!(parse_launch_action(&args(&["--unknown"])).is_err());
        assert!(parse_launch_action(&args(&["--help", "--version"])).is_err());
        assert!(parse_launch_action(&args(&["--"])).is_err());
    }
}
