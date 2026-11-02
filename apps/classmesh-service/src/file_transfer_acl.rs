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
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn GetSecurityDescriptorLength(descriptor: *const c_void) -> u32;
    fn EqualSid(a: *const c_void, b: *const c_void) -> i32;
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
/// Validate variable-length SID within AceSize before any EqualSid call.
fn allow_ace_sid(ace: &[u8]) -> io::Result<*const c_void> {
    if ace.len() < 16 {
        return Err(denied("Outbox DACL contains a truncated allow ACE"));
    }
    let subauthorities = usize::from(ace[9]);
    if ace[8] != 1 || subauthorities > 15 || 16 + subauthorities * 4 > ace.len() {
        return Err(denied("Outbox allow ACE contains an invalid SID"));
    }
    Ok(ace[8..].as_ptr().cast())
}

fn equal_sid(a: *const c_void, b: &[u8]) -> bool {
    // SAFETY: caller supplies a SID from Windows security APIs; b is a valid SID.
    unsafe { EqualSid(a, b.as_ptr().cast()) != 0 }
}

fn verify_one_directory(
    path: &Path,
    system: &[u8],
    admins: &[u8],
    service: &[u8],
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
        if !equal_sid(owner, system) && !equal_sid(owner, admins) && !equal_sid(owner, service) {
            return Err(denied("Outbox ancestor is owned by an untrusted principal"));
        }
        let dacl_begin = dacl as usize;
        if dacl_begin < descriptor_begin
            || dacl_begin
                .checked_add(8)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox DACL header is outside its descriptor"));
        }
        // SAFETY: the DACL header is within the descriptor allocation.
        let acl_size =
            unsafe { ptr::read_unaligned((dacl as *const u8).add(2).cast::<u16>()) } as usize;
        if acl_size < 8
            || dacl_begin
                .checked_add(acl_size)
                .is_none_or(|end| end > descriptor_end)
        {
            return Err(denied("Outbox DACL size exceeds its descriptor"));
        }
        let acl_end = dacl_begin + acl_size;
        // SAFETY: validated ACL header bounds.
        let count = unsafe { ptr::read_unaligned((dacl as *const u8).add(4).cast::<u16>()) };
        for i in 0..u32::from(count) {
            let mut ace = ptr::null_mut();
            // SAFETY: i is within the ACL's reported ACE count.
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 || ace.is_null() {
                return Err(denied("Outbox DACL contains an invalid ACE"));
            }
            let ace_begin = ace as usize;
            if ace_begin < dacl_begin + 8
                || ace_begin.checked_add(4).is_none_or(|end| end > acl_end)
            {
                return Err(denied("Outbox ACE header is outside its ACL"));
            }
            // SAFETY: ACE header bounds were checked against the API-owned ACL.
            let kind = unsafe { *(ace as *const u8) };
            let length = unsafe { ptr::read_unaligned((ace as *const u8).add(2).cast::<u16>()) };
            if length < 4
                || ace_begin
                    .checked_add(length as usize)
                    .is_none_or(|end| end > acl_end)
            {
                return Err(denied("Outbox ACE exceeds its ACL"));
            }
            match kind {
                0 => {
                    // SAFETY: ACE pointer and AceSize were checked against the
                    // API-owned ACL allocation before forming this byte slice.
                    let bytes =
                        unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), length as usize) };
                    let sid = allow_ace_sid(bytes)?;
                    let mask = u32::from_le_bytes(bytes[4..8].try_into().expect("ACE mask"));
                    if mask & WRITABLE_RIGHTS != 0
                        && !equal_sid(sid, system)
                        && !equal_sid(sid, admins)
                        && !equal_sid(sid, service)
                    {
                        return Err(denied(
                            "Outbox ancestor grants write/delete to another principal",
                        ));
                    }
                }
                1 | 2 | 3 | 7 | 8 | 17 => {} // deny, audit, and mandatory-label ACEs
                _ => return Err(denied("Outbox ancestor has an unsupported ACE type")),
            }
        }
        Ok(())
    })();
    // SAFETY: descriptor is allocated by GetNamedSecurityInfoW.
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor) };
    }
    result
}

/// Refuse to serve Outbox data if ClassMesh, state or Outbox itself has an
/// untrusted owner or writable ACE. ProgramData is the OS-managed trust anchor.
/// This is deliberately verification-only: an administrator must provision ACLs.
pub(crate) fn verify_private_outbox(root: &Path) -> io::Result<()> {
    let state = root
        .parent()
        .ok_or_else(|| denied("missing Outbox state parent"))?;
    let classmesh = state
        .parent()
        .ok_or_else(|| denied("missing ClassMesh parent"))?;
    let system = well_known_sid(22)?; // WinLocalSystemSid
    let admins = well_known_sid(26)?; // WinBuiltinAdministratorsSid
    let service = process_user_sid()?;
    for path in [classmesh, state, root] {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(denied("Outbox ancestor is not a real directory"));
        }
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(denied("Outbox ancestor is a reparse point"));
        }
        verify_one_directory(path, &system, &admins, &service)?;
    }
    Ok(())
}

/// File transfer is optional. An unsafe legacy ProgramData tree must not
/// terminate an otherwise healthy Service, but no source or inbox is usable
/// until this gate passes. Never rewrite an untrusted directory's ACL here.
pub(crate) fn prepare_optional_file_transfer_storage(inbox: &Path, outbox: &Path) -> bool {
    let result = std::fs::create_dir_all(inbox)
        .and_then(|()| std::fs::create_dir_all(outbox))
        .and_then(|()| verify_private_outbox(outbox));
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
    }

    #[test]
    fn token_sid_bounds_reject_truncated_header_without_dereferencing() {
        let buffer = [0_u8; 16];
        let truncated = unsafe { buffer.as_ptr().add(buffer.len() - 1) };
        assert!(copy_sid_within_token(&buffer, buffer.len(), truncated).is_err());
        assert!(copy_sid_within_token(&buffer, buffer.len() + 1, buffer.as_ptr()).is_err());
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
        for path in [&outbox, &state, &classmesh] {
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
        assert!(
            prepare_optional_file_transfer_storage(&state.join("file-inbox"), &outbox),
            "a privately provisioned Outbox permits the optional transfer feature"
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
        assert!(
            !prepare_optional_file_transfer_storage(&state.join("file-inbox"), &outbox),
            "unsafe legacy ACL must disable transfer without stopping the control Service"
        );
        // Restore inheritance before deleting the disposable fixture.
        for path in [&classmesh, &state, &outbox] {
            let _ = Command::new("icacls")
                .arg(path)
                .args(["/inheritance:e"])
                .output();
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
