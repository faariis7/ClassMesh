//! Explicit protected Teacher policy preflight and administrator publication.
const USAGE: &str = "classmesh-teacher-policy <plan|create|advance> EPOCH POLICY_JSON
classmesh-teacher-policy revoke EPOCH
plan verifies the candidate and CNG binding without publishing.
create is a fresh administrator-only write. advance and revoke require a higher epoch.
Run either write only during an explicitly approved protected provisioning window.";

#[cfg(windows)]
fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use classmesh_teacher::trusted_startup::verify_teacher_policy_candidate;
    use classmesh_win32::teacher_policy::{
        MAX_POLICY_BYTES, publish_teacher_policy, revoke_teacher_policy,
    };
    use std::{fs::File, io::Read};

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    if let [mode, epoch] = args.as_slice()
        && mode == "revoke"
    {
        let epoch: u64 = epoch.to_str().ok_or("invalid policy epoch")?.parse()?;
        revoke_teacher_policy(epoch)?;
        println!("protected_teacher_policy=disabled epoch={epoch}");
        return Ok(());
    }
    let [mode, epoch, path] = args.as_slice() else {
        return Err(USAGE.into());
    };
    let mode = mode.to_str().ok_or(USAGE)?;
    if !matches!(mode, "plan" | "create" | "advance") {
        return Err(USAGE.into());
    }
    let epoch: u64 = epoch.to_str().ok_or("invalid policy epoch")?.parse()?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    verify_teacher_policy_candidate(&bytes, epoch)?;
    if mode == "plan" {
        println!("candidate=verified epoch={epoch} writes=none");
    } else {
        publish_teacher_policy(epoch, &bytes, mode == "create")?;
        println!("protected_teacher_policy=published epoch={epoch}");
    }
    Ok(())
}

fn main() {
    #[cfg(windows)]
    if let Err(error) = run() {
        eprintln!("Teacher policy: {error}");
        std::process::exit(1);
    }

    #[cfg(not(windows))]
    {
        eprintln!("{USAGE}\nProtected Teacher policy publication requires Windows.");
        std::process::exit(1);
    }
}
