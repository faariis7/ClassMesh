//! Experimental shared-ancestor descriptor qualification; not production authority.
//! This snapshot alone does not revoke preexisting HANDLE rights.
#[cfg(test)]
use std::os::windows::fs::OpenOptionsExt;
use std::{fs::File, io};

fn trusted(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}

fn permission_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified shared-ancestor owner or ACL",
    )
}

pub(crate) fn attest_shared_ancestor_acl(file: &File) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(permission_denied());
    }
    let descriptor = crate::file_security_descriptor::read_allowed_descriptor(file)?;
    if !trusted(&descriptor.owner) {
        return Err(permission_denied());
    }
    let mut system = false;
    let mut administrators = false;
    for entry in descriptor.entries {
        if entry.flags & !0x1f != 0 {
            return Err(permission_denied());
        }
        let sid = entry.sid;
        // Inherit-only permissions do not apply to THIS retained directory.
        // Every child must be separately attested; private children use D:P.
        if entry.flags & 0x08 != 0 {
            continue;
        }
        use windows_sys::Win32::Security::{GENERIC_MAPPING, MapGenericMask};
        let mapping = GENERIC_MAPPING {
            GenericRead: 0x00120089,
            GenericWrite: 0x00120116,
            GenericExecute: 0x001200a0,
            GenericAll: 0x001f01ff,
        };
        let mut mask = entry.mask;
        // Safety: initialized writable mask and live immutable file mapping.
        unsafe { MapGenericMask(&raw mut mask, &mapping) };
        if mask & !0x001f01ff != 0 {
            return Err(permission_denied());
        }
        // Directory add-child/EA/attribute writes cannot grant trust in children.
        // No DELETE_CHILD, DELETE, WRITE_DAC or WRITE_OWNER for unknown principals.
        if !trusted(&sid) && mask & !0x001201bf != 0 {
            return Err(permission_denied());
        }
        if mask & 0x00020001 == 0x00020001 {
            system |= sid == "S-1-5-18";
            administrators |= sid == "S-1-5-32-544";
        }
    }
    if !system || !administrators {
        return Err(permission_denied());
    }
    Ok(())
}

#[test]
fn os_shared_ancestor_descriptors_are_supported_without_system_acl_changes() {
    for path in [r"C:\", r"C:\Windows", r"C:\ProgramData"] {
        let file = std::fs::OpenOptions::new()
            .access_mode(0x00020080)
            .share_mode(7)
            .custom_flags(0x02200000)
            .open(path)
            .unwrap();
        attest_shared_ancestor_acl(&file).expect("supported OS ancestor descriptor");
    }
}

#[test]
fn shared_ancestor_rejects_untrusted_destructive_and_security_rights() {
    let fixture =
        std::env::temp_dir().join(format!("classmesh-ancestor-acl-{}", std::process::id()));
    std::fs::create_dir(&fixture).unwrap();
    let acl = |args: &[&str]| {
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&fixture)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    };
    acl(&["/reset"]);
    acl(&[
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
    ]);
    acl(&["/setowner", "*S-1-5-32-544"]);
    let file = std::fs::OpenOptions::new()
        .access_mode(0x00020080)
        .share_mode(7)
        .custom_flags(0x02200000)
        .open(&fixture)
        .unwrap();
    // ProgramData-like add-child and attribute rights are deliberately different
    // from private policy directories, whose strict predicate remains unchanged.
    acl(&["/grant:r", "*S-1-5-32-545:(RD,WD,AD,REA,WEA,X,RA,WA,RC,S)"]);
    attest_shared_ancestor_acl(&file).unwrap();
    for right in [
        "*S-1-5-32-545:(DC)",
        "*S-1-5-32-545:(D)",
        "*S-1-5-32-545:(WDAC)",
        "*S-1-5-32-545:(WO)",
        "*S-1-5-32-545:F",
    ] {
        acl(&["/grant:r", right]);
        assert!(attest_shared_ancestor_acl(&file).is_err(), "deny {right}");
    }
    acl(&["/grant:r", "*S-1-5-32-545:R"]);
    acl(&["/setowner", "*S-1-5-32-545"]);
    assert!(attest_shared_ancestor_acl(&file).is_err());
    drop(file);
    std::fs::remove_dir(&fixture).unwrap();
}
