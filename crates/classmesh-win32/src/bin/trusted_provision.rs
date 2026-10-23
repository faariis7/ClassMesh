//! Explicit installer for the opt-in trusted Service policy path.
//! Inputs are operator-selected; this command does not generate or export keys.
#[cfg(windows)]
fn main() {
    use std::{
        fs::File,
        io::{self, Read},
    };

    fn bounded(path: &str, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input size rejected",
            ));
        }
        Ok(bytes)
    }
    fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        let mode = args.get(1).map(String::as_str);
        if !matches!(
            (mode, args.len()),
            (Some("--fresh"), 6) | (Some("--update"), 4)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: classmesh-trusted-provision --fresh <epoch> <policy.json> <identity.json> <control-runtime.json> | --update <epoch> <policy.json>",
            ));
        }
        let epoch = args[2].parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "epoch must be a positive integer",
            )
        })?;
        let policy = bounded(&args[3], 4 * 1024 * 1024)?;
        if mode == Some("--fresh") {
            let identity = bounded(&args[4], 1024 * 1024)?;
            let config = bounded(&args[5], 64 * 1024)?;
            classmesh_win32::trusted_policy::provision_fresh_install(
                epoch, &policy, &identity, &config,
            )?;
            println!("Trusted fresh installation committed at epoch {epoch}.");
        } else {
            // The trusted API requires the Service's lifetime lease to be
            // released first and rejects stale/repeated epochs and blob reuse.
            classmesh_win32::trusted_policy::install_policy(epoch, &policy)?;
            println!("Trusted policy update committed at epoch {epoch}.");
        }
        Ok(())
    }
    if let Err(error) = run() {
        eprintln!("Trusted policy installation rejected: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-trusted-provision requires Windows");
    std::process::exit(1);
}
