//! Independent OS Windows-volume authority experiment; never production admission.
use std::{fs::File, io};

use crate::nt_relative_directory::{
    open_native_readonly_directory, open_relative_readonly_directory, query_object_link,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified system volume authority",
    )
}

fn system_windows_path() -> io::Result<String> {
    let mut buffer = vec![0u16; 32768];
    // Safety: initialized writable buffer; API capacity is in UTF-16 units.
    let count = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize >= buffer.len() {
        return Err(denied());
    }
    String::from_utf16(&buffer[..count as usize]).map_err(|_| denied())
}

/// Supported profile: an OS-reported local-drive Windows directory and the
/// default immediate ProgramData child on that drive. Redirection is rejected,
/// not silently treated as a second authority. No environment is consulted.
fn selected_components<'a>(windows: &'a str, program_data: &str) -> io::Result<(u8, Vec<&'a str>)> {
    let bytes = windows.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return Err(denied());
    }
    let components: Vec<_> = windows[3..].split('\\').collect();
    if !components
        .iter()
        .all(|c| crate::policy_file_origin::safe_child_leaf(c))
    {
        return Err(denied());
    }
    let expected = format!("{}:\\ProgramData", char::from(bytes[0]));
    if !program_data.eq_ignore_ascii_case(&expected) {
        return Err(denied());
    }
    Ok((bytes[0].to_ascii_uppercase(), components))
}

fn qualified_device_root(system: &str, global: &str, components: &[&str]) -> io::Result<String> {
    // Deliberately support only direct local hard-disk volume devices. Reject
    // redirectors, nested object links, SUBST/subdirectories and mount aliases.
    let number = global
        .strip_prefix(r"\Device\HarddiskVolume")
        .ok_or_else(denied)?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(denied());
    }
    let expected = format!("{}\\{}", global, components.join("\\"));
    if !system.eq_ignore_ascii_case(&expected) {
        return Err(denied());
    }
    Ok(format!("{global}\\"))
}

struct SystemVolumeCandidate {
    windows_path: String,
    directories: Vec<File>,
}

fn pin_system_windows_volume() -> io::Result<SystemVolumeCandidate> {
    let windows = system_windows_path()?;
    let drive = *windows.as_bytes().first().ok_or_else(denied)?;
    let (drive, components) =
        selected_components(&windows, &format!("{}:\\ProgramData", char::from(drive)))?;
    // The kernel's SystemRoot object-manager link is independent of the Known
    // Folder, environment and logon-local DOS device mappings. Resolve the link
    // as data, then open a direct device root with reparse refusal still enabled.
    let system_target = query_object_link(r"\SystemRoot")?;
    // Current Windows may use this one fixed kernel link. Resolve it explicitly
    // once; never recursively follow arbitrary alias chains or filesystem links.
    let system_target = if let Some(suffix) = system_target.strip_prefix(r"\Device\BootDevice\") {
        format!("{}\\{}", query_object_link(r"\Device\BootDevice")?, suffix)
    } else {
        system_target
    };
    let global_target = query_object_link(&format!("\\GLOBAL??\\{}:", char::from(drive)))?;
    let root_name = qualified_device_root(&system_target, &global_target, &components)?;
    let root = open_native_readonly_directory(None, &root_name)?;
    crate::shared_ancestor_acl::attest_shared_ancestor_acl(&root)?;
    let mut held = vec![root];
    for component in components {
        let child = open_relative_readonly_directory(held.last().ok_or_else(denied)?, component)?;
        crate::shared_ancestor_acl::attest_shared_ancestor_acl(&child)?;
        held.push(child);
    }
    Ok(SystemVolumeCandidate {
        windows_path: windows,
        directories: held,
    })
}

pub(crate) fn pin_system_program_data() -> io::Result<Vec<File>> {
    let pinned = pin_system_windows_volume()?;
    let known = crate::program_data_known_folder::resolve_os_program_data_path()?;
    selected_components(&pinned.windows_path, known.to_str().ok_or_else(denied)?)?;
    let mut held = pinned.directories;
    // Windows and ProgramData are independently rooted at the SAME retained
    // volume handle. Never reopen either ancestry using a mutable DOS path.
    let program_data = open_relative_readonly_directory(&held[0], "ProgramData")?;
    crate::shared_ancestor_acl::attest_shared_ancestor_acl(&program_data)?;
    held.push(program_data);
    Ok(held)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_authority_walk_reaches_real_programdata() {
        let held = pin_system_program_data().expect("independent OS volume authority");
        assert!(held.len() >= 3, "retain volume, Windows and ProgramData");
        let known = crate::program_data_known_folder::pin_os_program_data_candidate().unwrap();
        assert!(
            crate::nt_relative_directory::same_native_file_identity(held.last().unwrap(), &known)
                .unwrap()
        );
    }
    #[test]
    fn rejects_disagreement_between_kernel_root_and_global_drive() {
        for (system, global) in [
            (
                r"\Device\HarddiskVolume4\Windows",
                r"\Device\HarddiskVolume3",
            ),
            (r"\Device\HarddiskVolume3\decoy", r"\Device\HarddiskVolume3"),
            (
                r"\Device\HarddiskVolume3\Windows",
                r"\Device\HarddiskVolume3\decoy",
            ),
            (r"\Device\Mup\server\Windows", r"\Device\Mup\server"),
            (r"\??\C:\Windows", r"\??\C:"),
        ] {
            assert!(qualified_device_root(system, global, &["Windows"]).is_err());
        }
        assert_eq!(
            qualified_device_root(
                r"\Device\HarddiskVolume3\WINDOWS",
                r"\Device\HarddiskVolume3",
                &["Windows"]
            )
            .unwrap(),
            "\\Device\\HarddiskVolume3\\"
        );
    }

    #[test]
    fn refuses_redirected_known_folder_instead_of_trusting_its_volume() {
        for known in [
            r"D:\ProgramData",
            r"C:\redirect\ProgramData",
            r"\\server\share\ProgramData",
            r"C:\Windows\..\ProgramData",
        ] {
            assert!(selected_components(r"C:\Windows", known).is_err());
        }
        for windows in [
            r"C:Windows",
            r"\\server\share\Windows",
            r"C:\decoy\..\Windows",
            r"C:\Windows:stream",
        ] {
            assert!(selected_components(windows, r"C:\ProgramData").is_err());
        }
    }

    #[test]
    fn environment_cannot_choose_windows_volume() {
        // A child process avoids racing other tests through global environment.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "system_volume::tests::independent_windows_volume_is_pinned",
                "--nocapture",
            ])
            .env("SystemRoot", r"Z:\attacker")
            .env("windir", r"Z:\attacker")
            .env("SystemDrive", "Z:")
            .env("ProgramData", r"Z:\attacker\ProgramData")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn independent_windows_volume_is_pinned() {
        let held = pin_system_windows_volume()
            .expect("independent Windows root")
            .directories;
        assert!(held.len() >= 2);
        assert!(held.iter().all(|file| file.metadata().unwrap().is_dir()));
        assert!(
            !crate::nt_relative_directory::same_native_file_identity(
                &held[0],
                held.last().unwrap()
            )
            .unwrap()
        );
    }
}
