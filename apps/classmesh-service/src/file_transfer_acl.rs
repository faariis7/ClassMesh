//! Fail-closed Windows Outbox directory ACL gate. This checks the Service's
//! own ClassMesh directory chain; it never rewrites machine policy or ACLs.
#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;
const TOKEN_QUERY: u32 = 8;
const TOKEN_USER: u32 = 1;
// ProgramData permits ordinary Users to create subdirectories. Only deny
// rights that could replace/remove the already protected ClassMesh directory
// or rewrite its parent's ACL. Do not apply the stricter child-directory mask
// to this OS-managed anchor, or standard Service installs would be disabled.
const DESTRUCTIVE_PARENT_RIGHTS: u32 = 0x1000_0000 // GENERIC_ALL
    | 0x0200_0000 // MAXIMUM_ALLOWED (ambiguous)
    | 0x0100_0000 // ACCESS_SYSTEM_SECURITY
    | 0x000d_0040; // DELETE, WRITE_DAC, WRITE_OWNER, DELETE_CHILD
const WRITABLE_RIGHTS: u32 = 0x4000_0000 // GENERIC_WRITE
    | 0x1000_0000 // GENERIC_ALL
    | 0x0200_0000 // MAXIMUM_ALLOWED (ambiguous: fail closed)
    | 0x000d_0000 // DELETE, WRITE_DAC, WRITE_OWNER (not READ_CONTROL)
    | 0x0000_0156; // FILE_WRITE_DATA/APPEND/EA/ATTRIBUTES/DELETE_CHILD

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn GetNamedSecurityInfoW(
        name: *mut u16,
        object_type: u32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: *const c_void) -> u32;
    fn CreateWellKnownSid(
        kind: u32,
        domain: *const c_void,
        sid: *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn LocalFree(pointer: *mut c_void) -> *mut c_void;
}

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn well_known_sid(kind: u32) -> io::Result<Vec<u8>> {
    let mut sid = vec![0_u8; 68];
    let mut size = sid.len() as u32;
    // SAFETY: buffer is writable for size bytes; null domain uses the local authority.
    if unsafe { CreateWellKnownSid(kind, ptr::null(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    sid.truncate(size as usize);
    Ok(sid)
}

fn process_user_sid() -> io::Result<Vec<u8>> {
    let mut token = ptr::null_mut();
    // SAFETY: the pseudo-process handle is valid for the current process.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u8; 512];
    let mut returned = 0_u32;
    // SAFETY: TOKEN_USER is returned into the live buffer, and token is closed below.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: token was obtained by OpenProcessToken.
    unsafe { CloseHandle(token) };
    if ok == 0 || returned < std::mem::size_of::<usize>() as u32 {
        return Err(error);
    }
    // TOKEN_USER starts with SID_AND_ATTRIBUTES whose first field is PSID.
    // SAFETY: pointer-sized field is inside the returned buffer.
    let sid_ptr = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<*const u8>()) };
    if sid_ptr.is_null() {
        return Err(denied("service token has no user SID"));
    }
    copy_sid_within_token(&buffer, returned as usize, sid_ptr)
}

fn copy_sid_within_token(
    buffer: &[u8],
    returned: usize,
    sid_ptr: *const u8,
) -> io::Result<Vec<u8>> {
    let lower = buffer.as_ptr() as usize;
    let upper = lower
        .checked_add(returned)
        .filter(|_| returned <= buffer.len())
        .ok_or_else(|| denied("invalid token data length"))?;
    let begin = sid_ptr as usize;
    if begin < lower || begin.checked_add(8).is_none_or(|end| end > upper) {
        return Err(denied(
            "token SID header is outside the returned token data",
        ));
    }
    // SAFETY: the eight-byte SID header is inside the returned token buffer.
    let count = unsafe { *sid_ptr.add(1) } as usize;
    let size = 8 + count * 4;
    if count > 15 || begin.checked_add(size).is_none_or(|end| end > upper) {
        return Err(denied("token SID is outside the returned token data"));
    }
    // SAFETY: the entire SID lies within the returned TOKEN_USER allocation.
    Ok(unsafe { std::slice::from_raw_parts(sid_ptr, size) }.to_vec())
}

/// ACCESS_ALLOWED_ACE layout is 8-byte header/mask followed by a SID.
/// Validate the exact variable-length SID within AceSize before comparing bytes.
fn allow_ace_sid(ace: &[u8]) -> io::Result<&[u8]> {
    if ace.len() < 16 {
        return Err(denied("Outbox DACL contains a truncated allow ACE"));
    }
    let subauthorities = usize::from(ace[9]);
    if ace[8] != 1 || subauthorities > 15 || 16 + subauthorities * 4 != ace.len() {
        return Err(denied("Outbox allow ACE contains an invalid SID"));
    }
    Ok(&ace[8..])
}

// A Windows SID has a canonical byte representation: revision, subauthority
// count, identifier authority and exactly that many LE subauthorities.
// Compare validated slices instead of passing pointers to EqualSid.
fn sid_matches(sid: &[u8], expected: &[u8]) -> bool {
    sid == expected
}

/// Parse the API-owned ACL only after the entire ACL is bounded by its
/// descriptor. This avoids GetAce-returned raw pointers and validates the
/// complete ACE header, length, SID and ACE count before any comparison.
#[cfg(test)]
fn verify_acl_bytes(acl: &[u8], system: &[u8], admins: &[u8], service: &[u8]) -> io::Result<()> {
    verify_acl_bytes_with_policy(acl, system, admins, service, WRITABLE_RIGHTS, false)
}

fn verify_acl_bytes_with_policy(
    acl: &[u8],
    system: &[u8],
    admins: &[u8],
    service: &[u8],
    forbidden_rights: u32,
    skip_inherit_only: bool,
) -> io::Result<()> {
    if acl.len() < 8 {
        return Err(denied("Outbox DACL header is truncated"));
    }
    let declared = u16::from_le_bytes([acl[2], acl[3]]) as usize;
    if declared != acl.len() {
        return Err(denied("Outbox DACL size is inconsistent"));
    }
    let count = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    let mut offset = 8_usize;
    for _ in 0..count {
        let header = acl
            .get(offset..offset.saturating_add(4))
            .ok_or_else(|| denied("Outbox DACL ACE header is truncated"))?;
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        if length < 4 {
            return Err(denied("Outbox DACL ACE length is invalid"));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| denied("Outbox DACL ACE length overflow"))?;
        let ace = acl
            .get(offset..end)
            .ok_or_else(|| denied("Outbox DACL ACE exceeds its ACL"))?;
        match ace[0] {
            0 => {
                let sid = allow_ace_sid(ace)?;
                let mask = u32::from_le_bytes(ace[4..8].try_into().expect("ACE mask"));
                // CREATOR OWNER on ProgramData is inherit-only: it does not
                // grant access to the parent itself. Child ACLs are checked
                // separately with the strict write/delete policy.
                if skip_inherit_only && ace[1] & 0x08 != 0 {
                    offset = end;
                    continue;
                }
                if mask & forbidden_rights != 0
                    && !sid_matches(sid, system)
                    && !sid_matches(sid, admins)
                    && !sid_matches(sid, service)
                {
                    return Err(denied(
                        "FileTransfer directory grants write/delete to another principal",
                    ));
                }
            }
            1 | 2 | 3 | 7 | 8 | 17 => {} // deny, audit, and mandatory-label ACEs
            _ => return Err(denied("FileTransfer directory has an unsupported ACE type")),
        }
        offset = end;
    }
    Ok(())
}

fn verify_one_directory(
    path: &Path,
    system: &[u8],
    admins: &[u8],
    service: &[u8],
    forbidden_rights: u32,
    skip_inherit_only: bool,
) -> io::Result<()> {
    let mut name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: GetNamedSecurityInfoW allocates descriptor, freed by LocalFree below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // Scope descriptor cleanup even on a denied ACL.
    let result = (|| {
        if descriptor.is_null() || owner.is_null() || dacl.is_null() {
            return Err(denied("Outbox directory has no owner or has a null DACL"));
        }
        // Validate every ACL/ACE pointer against the API-owned descriptor before
        // reading headers. GetAce success alone does not prove bounds to Rust.
        // SAFETY: descriptor was returned by successful GetNamedSecurityInfoW.
        let descriptor_size = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        let descriptor_begin = descriptor as usize;
        let descriptor_end = descriptor_begin
            .checked_add(descriptor_size)
            .ok_or_else(|| denied("invalid security descriptor length"))?;
        let owner_begin = owner as usize;
        if owner_begin < descriptor_begin
            || owner_begin
                .checked_add(8)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox owner SID header is outside its descriptor"));
        }
        // SAFETY: owner SID header is inside the returned descriptor.
        let owner_subauthorities = unsafe { *((owner as *const u8).add(1)) } as usize;
        if owner_subauthorities > 15
            || owner_begin
                .checked_add(8 + owner_subauthorities * 4)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox owner SID exceeds its descriptor"));
        }
        // SAFETY: the complete SID was bounded by the returned descriptor.
        let owner_sid =
            unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), 8 + owner_subauthorities * 4) };
        if owner_sid[0] != 1
            || (!sid_matches(owner_sid, system)
                && !sid_matches(owner_sid, admins)
                && !sid_matches(owner_sid, service))
        {
            return Err(denied(
                "FileTransfer directory is owned by an untrusted principal",
            ));
        }
        let dacl_begin = dacl as usize;
        if dacl_begin < descriptor_begin
            || dacl_begin
                .checked_add(8)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox DACL header is outside its descriptor"));
        }
        // SAFETY: the DACL header is inside the API-owned descriptor.
        let acl_size =
            unsafe { ptr::read_unaligned((dacl as *const u8).add(2).cast::<u16>()) } as usize;
        if acl_size < 8
            || dacl_begin
                .checked_add(acl_size)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox DACL size exceeds its descriptor"));
        }
        // SAFETY: every byte in the ACL slice lies inside the API-owned
        // descriptor. All ACE offsets and SIDs are checked in safe Rust.
        let acl = unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), acl_size) };
        verify_acl_bytes_with_policy(
            acl,
            system,
            admins,
            service,
            forbidden_rights,
            skip_inherit_only,
        )?;
        Ok(())
    })();
    // SAFETY: descriptor is allocated by GetNamedSecurityInfoW.
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor) };
    }
    result
}

// Check the same owner/DACL policy before creation (on existing ancestors)
// and after creation (on every component). The preflight prevents writes
// through a *known* writable legacy ancestor; it is not atomic against
// concurrent directory substitution.
fn verify_storage_directory_chain(root: &Path, allow_missing_children: bool) -> io::Result<()> {
    let state = root
        .parent()
        .ok_or_else(|| denied("missing Outbox state parent"))?;
    let classmesh = state
        .parent()
        .ok_or_else(|| denied("missing ClassMesh parent"))?;
    let anchor = classmesh
        .parent()
        .ok_or_else(|| denied("missing ProgramData trust anchor"))?;
    let system = well_known_sid(22)?; // WinLocalSystemSid
    let admins = well_known_sid(26)?; // WinBuiltinAdministratorsSid
    let service = process_user_sid()?;
    for (path, forbidden_rights, skip_inherit_only) in [
        (anchor, DESTRUCTIVE_PARENT_RIGHTS, true),
        (classmesh, WRITABLE_RIGHTS, false),
        (state, WRITABLE_RIGHTS, false),
        (root, WRITABLE_RIGHTS, false),
    ] {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error)
                if allow_missing_children
                    && path != anchor
                    && error.kind() == io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(denied("FileTransfer directory is not a real directory"));
        }
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(denied("FileTransfer directory is a reparse point"));
        }
        verify_one_directory(
            path,
            &system,
            &admins,
            &service,
            forbidden_rights,
            skip_inherit_only,
        )?;
    }
    Ok(())
}

/// Refuse to use a transfer directory if ClassMesh, state or that directory
/// has an untrusted owner or writable ACE. ProgramData is the OS-managed trust anchor.
/// This is deliberately verification-only: an administrator must provision ACLs.
pub(crate) fn verify_private_outbox(root: &Path) -> io::Result<()> {
    verify_storage_directory_chain(root, false)
}

/// Both staging roots are pathname-based trust boundaries: the receiver
/// writes and renames files in Inbox, and the source opens registered Outbox
/// files. Check the full directory chain for *each* root, not just Outbox.
pub(crate) fn verify_private_file_transfer_storage(inbox: &Path, outbox: &Path) -> io::Result<()> {
    verify_private_outbox(inbox)?;
    verify_private_outbox(outbox)
}

/// Refuse an existing junction/symlink anywhere in the creation chain
/// *before* create_dir_all. Otherwise mkdir follows a pre-existing malicious
/// ClassMesh/state junction and creates files outside the intended tree before
/// the post-creation ACL gate can reject it. This is only a preflight: an
/// attacker racing path replacement still requires a handle-relative creation
/// design and an independently secured ancestor. Never call it an atomic gate.
fn preflight_existing_storage_chain(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(denied(
            "FileTransfer storage path must be absolute and normalized",
        ));
    }
    // The core enrolled Service loads its machine identity from an existing
    // ClassMesh/state tree before reaching this optional FileTransfer gate.
    // Never let FileTransfer create that trust root beneath ProgramData: Users
    // may have FILE_ADD_SUBDIRECTORY there and can race a missing root name.
    // Only the final inbox/outbox child may be created under a provisioned,
    // independently verified state directory.
    let state = path
        .parent()
        .ok_or_else(|| denied("missing FileTransfer state directory"))?;
    match std::fs::symlink_metadata(state) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(denied(
                "FileTransfer requires a provisioned ClassMesh state root",
            ));
        }
        Err(error) => return Err(error),
    }
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.file_attributes() & 0x400 != 0
                {
                    return Err(denied(
                        "FileTransfer storage creation traverses a reparse point or non-directory",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    // Reject a pre-existing untrusted owner/ACL before create_dir_all can
    // write through that directory. Missing children are checked again after
    // creation by verify_private_file_transfer_storage.
    verify_storage_directory_chain(path, true)
}

/// File transfer is optional. An unsafe legacy ProgramData tree must not
/// terminate an otherwise healthy Service, but no source or inbox is usable
/// until this gate passes. Never rewrite an untrusted directory's ACL here.
pub(crate) fn prepare_optional_file_transfer_storage(inbox: &Path, outbox: &Path) -> bool {
    let result = preflight_existing_storage_chain(inbox)
        .and_then(|()| preflight_existing_storage_chain(outbox))
        .and_then(|()| std::fs::create_dir_all(inbox))
        .and_then(|()| std::fs::create_dir_all(outbox))
        .and_then(|()| verify_private_file_transfer_storage(inbox, outbox));
    if let Err(error) = result {
        eprintln!("ClassMesh FileTransfer disabled: unsafe or unavailable storage: {error}");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn malformed_allow_ace_sid_fails_closed_before_equal_sid() {
        let mut ace = [0_u8; 16];
        ace[0] = 0; // ACCESS_ALLOWED_ACE_TYPE
        ace[2..4].copy_from_slice(&16_u16.to_le_bytes());
        ace[8] = 1; // SID revision
        ace[9] = 2; // declares 2 subauthorities beyond AceSize
        assert!(allow_ace_sid(&ace).is_err());
        ace[9] = 0;
        assert!(allow_ace_sid(&ace).is_ok());
        assert!(allow_ace_sid(&ace[..15]).is_err());
        // An ACCESS_ALLOWED_ACE has no trailing payload after its SID.
        // Accepting excess bytes obscures the exact SID/ACE ownership boundary.
        let mut trailing = [0_u8; 20];
        trailing[8] = 1;
        trailing[9] = 0;
        assert!(
            allow_ace_sid(&trailing).is_err(),
            "trailing ACE bytes must fail closed"
        );
    }

    #[test]
    fn malformed_acl_ace_count_and_length_fail_closed() {
        let sid = [1_u8, 0, 0, 0, 0, 0, 0, 5];
        let mut acl = [0_u8; 8];
        acl[2..4].copy_from_slice(&8_u16.to_le_bytes());
        acl[4..6].copy_from_slice(&1_u16.to_le_bytes());
        assert!(verify_acl_bytes(&acl, &sid, &sid, &sid).is_err());
        let mut truncated = [0_u8; 12];
        truncated[2..4].copy_from_slice(&12_u16.to_le_bytes());
        truncated[4..6].copy_from_slice(&1_u16.to_le_bytes());
        truncated[8..10].copy_from_slice(&[0, 0]);
        truncated[10..12].copy_from_slice(&16_u16.to_le_bytes());
        assert!(verify_acl_bytes(&truncated, &sid, &sid, &sid).is_err());
    }

    #[test]
    fn token_sid_bounds_reject_truncated_header_without_dereferencing() {
        let buffer = [0_u8; 16];
        let truncated = unsafe { buffer.as_ptr().add(buffer.len() - 1) };
        assert!(copy_sid_within_token(&buffer, buffer.len(), truncated).is_err());
        assert!(copy_sid_within_token(&buffer, buffer.len() + 1, buffer.as_ptr()).is_err());
    }

    #[test]
    fn preexisting_classmesh_junction_cannot_create_inbox_outside_storage() {
        // An attacker-controlled ancestor can redirect create_dir_all before
        // the post-creation ACL check. Do not mutate the junction target.
        let sandbox = std::env::temp_dir().join(format!(
            "classmesh-acl-precreate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let anchor = sandbox.join("anchor");
        let outside = sandbox.join("outside");
        std::fs::create_dir_all(&anchor).expect("fixture anchor");
        std::fs::create_dir_all(&outside).expect("fixture target");
        let classmesh = anchor.join("ClassMesh");
        let junction = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&classmesh)
            .arg(&outside)
            .output()
            .expect("create fixture junction");
        assert!(
            junction.status.success(),
            "junction fixture failed: {junction:?}"
        );
        let inbox = classmesh.join("state").join("file-inbox");
        let outbox = classmesh.join("state").join("file-outbox");
        let allowed = prepare_optional_file_transfer_storage(&inbox, &outbox);
        let target_mutated = outside.join("state").exists();
        std::fs::remove_dir(&classmesh).expect("remove only fixture junction");
        std::fs::remove_dir_all(&sandbox).expect("cleanup disposable fixture");
        assert!(!allowed, "junction must disable FileTransfer");
        assert!(
            !target_mutated,
            "unsafe junction target must not be mutated before ACL verification"
        );
    }

    #[test]
    fn inherited_builtin_users_modify_blocks_outbox() {
        let root = std::env::temp_dir().join(format!("classmesh-acl-{}", std::process::id()));
        let classmesh = root.join("ClassMesh");
        let state = classmesh.join("state");
        let outbox = state.join("file-outbox");
        std::fs::create_dir_all(&outbox).expect("create fixture");
        // Remove inherited ACEs only on disposable fixture directories and
        // explicitly grant the current service/test identity. Without this
        // grant a non-admin fixture owner may lose directory traversal.
        let identity = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ])
            .output()
            .expect("read current test SID");
        assert!(identity.status.success(), "test SID unavailable");
        let sid = String::from_utf8(identity.stdout).expect("SID text");
        let grant = format!("*{}:(OI)(CI)F", sid.trim());
        for path in [&outbox, &state, &classmesh, &root] {
            for args in [
                vec!["/inheritance:r".to_owned()],
                vec!["/grant".to_owned(), grant.clone()],
            ] {
                let result = Command::new("icacls")
                    .arg(path)
                    .args(&args)
                    .output()
                    .expect("icacls available");
                assert!(
                    result.status.success(),
                    "fixture ACL setup failed: {:?}",
                    result
                );
            }
        }
        assert!(
            verify_private_outbox(&outbox).is_ok(),
            "private Outbox must be accepted: {:?}",
            verify_private_outbox(&outbox)
        );
        let inbox = state.join("file-inbox");
        assert!(
            prepare_optional_file_transfer_storage(&inbox, &outbox),
            "private Inbox and Outbox permit the optional transfer feature"
        );
        // An attacker-writable inbox is just as unsafe as an Outbox:
        // the receiver writes .part and renames .bin using that pathname.
        let inbox_grant = Command::new("icacls")
            .arg(&inbox)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .output()
            .expect("icacls available");
        assert!(
            inbox_grant.status.success(),
            "inbox grant failed: {inbox_grant:?}"
        );
        assert!(
            verify_private_outbox(&outbox).is_ok(),
            "the Outbox remains private for this negative regression"
        );
        assert!(
            !prepare_optional_file_transfer_storage(&inbox, &outbox),
            "writable inbox must disable optional FileTransfer even with a protected Outbox"
        );
        let inbox_remove = Command::new("icacls")
            .arg(&inbox)
            .args(["/remove:g", "*S-1-5-32-545"])
            .output()
            .expect("icacls available");
        assert!(
            inbox_remove.status.success(),
            "inbox grant cleanup failed: {inbox_remove:?}"
        );
        assert!(
            prepare_optional_file_transfer_storage(&inbox, &outbox),
            "restored private inbox and outbox must allow optional FileTransfer"
        );
        // A substituted Inbox junction must not redirect the receiver's
        // pathname-based .part creation or .bin publication.
        let saved_inbox = state.join("file-inbox-private-original");
        std::fs::rename(&inbox, &saved_inbox).expect("rename test-owned inbox");
        let junction = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&inbox)
            .arg(&saved_inbox)
            .output()
            .expect("create disposable inbox junction");
        assert!(
            junction.status.success(),
            "junction fixture failed: {junction:?}"
        );
        assert!(
            !prepare_optional_file_transfer_storage(&inbox, &outbox),
            "reparse-substituted Inbox must disable FileTransfer"
        );
        std::fs::remove_dir(&inbox).expect("unlink test-owned junction, not target");
        std::fs::rename(&saved_inbox, &inbox).expect("restore test-owned inbox");
        assert!(
            prepare_optional_file_transfer_storage(&inbox, &outbox),
            "restored real Inbox directory must be accepted"
        );
        let output = Command::new("icacls")
            .arg(&classmesh)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .output()
            .expect("icacls available");
        assert!(
            output.status.success(),
            "fixture ACL grant failed: {:?}",
            output
        );
        assert!(
            verify_private_outbox(&outbox).is_err(),
            "Users Modify must fail closed"
        );
        // A legacy writable ClassMesh ancestor must be rejected *before*
        // creating a previously missing state/inbox/outbox directory.
        let untrusted_new_state = classmesh.join("state-untrusted-precreate");
        let untrusted_inbox = untrusted_new_state.join("file-inbox");
        let untrusted_outbox = untrusted_new_state.join("file-outbox");
        assert!(!prepare_optional_file_transfer_storage(
            &untrusted_inbox,
            &untrusted_outbox
        ));
        let untrusted_created = untrusted_new_state.exists();
        if untrusted_created {
            std::fs::remove_dir_all(&untrusted_new_state)
                .expect("cleanup test-created untrusted state");
        }
        assert!(
            !untrusted_created,
            "unsafe writable ClassMesh ancestor must not be mutated before ACL verification"
        );
        assert!(
            !prepare_optional_file_transfer_storage(&state.join("file-inbox"), &outbox),
            "unsafe legacy ACL must disable transfer without stopping the control Service"
        );
        let restore_classmesh = Command::new("icacls")
            .arg(&classmesh)
            .args(["/remove:g", "*S-1-5-32-545"])
            .output()
            .expect("icacls available");
        assert!(
            restore_classmesh.status.success(),
            "restore failed: {restore_classmesh:?}"
        );
        assert!(
            verify_private_outbox(&outbox).is_ok(),
            "private children are safe"
        );
        let normal_parent_grant = Command::new("icacls")
            .arg(&root)
            .args(["/grant", "*S-1-5-32-545:(CI)W"])
            .output()
            .expect("icacls available");
        assert!(
            normal_parent_grant.status.success(),
            "normal parent grant failed: {normal_parent_grant:?}"
        );
        assert!(
            verify_private_outbox(&outbox).is_ok(),
            "ordinary ProgramData-style Users Write must not disable the Service"
        );
        // The OS-managed parent may permit Users to create directories.
        // If ClassMesh itself is absent, mkdir races an untrusted principal
        // that can precreate or substitute that name before the ACL postcheck.
        // A valid enrolled Service already requires a provisioned state tree.
        let missing_classmesh = root.join("unprovisioned-classmesh");
        let missing_inbox = missing_classmesh.join("state").join("file-inbox");
        let missing_outbox = missing_classmesh.join("state").join("file-outbox");
        let unprovisioned_allowed =
            prepare_optional_file_transfer_storage(&missing_inbox, &missing_outbox);
        let created_before_rejection = missing_classmesh.exists();
        if created_before_rejection {
            std::fs::remove_dir_all(&missing_classmesh)
                .expect("cleanup untrusted precreate fixture");
        }
        assert!(
            !unprovisioned_allowed,
            "unprovisioned root must fail closed"
        );
        assert!(
            !created_before_rejection,
            "must not mkdir an unprovisioned ClassMesh root under a user-creatable parent"
        );
        // A parent with DELETE_CHILD can swap ClassMesh even if all three
        // inner directories have private ACLs. The ProgramData anchor must
        // reject this destructive permission without rejecting ordinary
        // inherited create-subdirectory grants.
        let parent_grant = Command::new("icacls")
            .arg(&root)
            .args(["/grant", "*S-1-5-32-545:(DC)"])
            .output()
            .expect("icacls available");
        assert!(
            parent_grant.status.success(),
            "parent grant failed: {parent_grant:?}"
        );
        assert!(
            verify_private_outbox(&outbox).is_err(),
            "untrusted DELETE_CHILD on the parent must block FileTransfer"
        );
        // Restore inheritance before deleting the disposable fixture.
        for path in [&root, &classmesh, &state, &outbox, &inbox] {
            let _ = Command::new("icacls")
                .arg(path)
                .args(["/inheritance:e"])
                .output();
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
