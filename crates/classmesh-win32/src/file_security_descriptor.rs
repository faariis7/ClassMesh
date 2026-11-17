//! Bounded same-HANDLE descriptor acquisition; callers choose acceptance rules.
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::os::windows::io::AsRawHandle;
use std::{fs::File, io};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSidLengthRequired,
    IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID,
};
use windows_sys::Win32::System::Memory::LocalSize;

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safety: GetSecurityInfo allocates this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The caller must retain the Windows buffer containing the SID and supply
/// the number of bytes available from this address within the enclosing structure.
unsafe fn sid_string(sid: PSID, available: usize) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    const SID_HEADER_SIZE: usize = offset_of!(SID, SubAuthority);
    if sid.is_null() || !sid.cast::<u32>().is_aligned() || available < SID_HEADER_SIZE {
        return Err(permission_denied());
    }
    // Safety: the fixed SID prefix fits; the count is a single byte in that prefix.
    let count = unsafe {
        sid.cast::<u8>()
            .add(offset_of!(SID, SubAuthorityCount))
            .read()
    };
    // Safety: only the copied count is passed. GetLengthSid would require a valid SID.
    let length = unsafe { GetSidLengthRequired(count) } as usize;
    if length > available {
        return Err(permission_denied());
    }
    // Safety: the complete SID representation fits in its enclosing buffer.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(permission_denied());
    }
    let mut allocated: *mut u16 = std::ptr::null_mut();
    // Safety: the live SID is bounded and has passed IsValidSid.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut allocated) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if allocated.is_null() {
        return Err(permission_denied());
    }
    let text = (|| {
        let mut length = 0usize;
        // Safety: ConvertSidToStringSidW allocated a NUL-terminated SID string.
        while length < 128 && unsafe { *allocated.add(length) } != 0 {
            length += 1;
        }
        if length == 128 {
            return Err(permission_denied());
        }
        // Safety: all characters are within the measured allocation.
        String::from_utf16(unsafe { std::slice::from_raw_parts(allocated, length) })
            .map_err(|_| permission_denied())
    })();
    // Safety: matches the allocation from ConvertSidToStringSidW.
    unsafe { LocalFree(allocated.cast()) };
    text
}

pub(crate) struct AllowedEntry {
    pub(crate) flags: u8,
    pub(crate) mask: u32,
    pub(crate) sid: String,
}

pub(crate) struct DescriptorSnapshot {
    pub(crate) owner: String,
    pub(crate) entries: Vec<AllowedEntry>,
}

fn permission_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "policy leaf owner or ACL is not a protected SYSTEM/Administrators descriptor",
    )
}

pub(crate) fn read_allowed_descriptor(file: &File) -> io::Result<DescriptorSnapshot> {
    read_allowed_object_descriptor(
        file.as_raw_handle(),
        windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
    )
}

/// # Safety
/// The caller must retain a valid registry key with READ_CONTROL for this call.
#[cfg(any(test, feature = "experimental-trusted-policy"))]
pub(crate) unsafe fn read_allowed_registry_descriptor(
    key: windows_sys::Win32::System::Registry::HKEY,
) -> io::Result<DescriptorSnapshot> {
    read_allowed_object_descriptor(
        key,
        windows_sys::Win32::Security::Authorization::SE_REGISTRY_KEY,
    )
}

fn read_allowed_object_descriptor(
    handle: windows_sys::Win32::Foundation::HANDLE,
    object_type: windows_sys::Win32::Security::Authorization::SE_OBJECT_TYPE,
) -> io::Result<DescriptorSnapshot> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = Descriptor(std::ptr::null_mut());
    // Safety: the wrapper retains a valid object through all checks; output pointers are
    // writable; GetSecurityInfo returns descriptor-owned owner and DACL pointers.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            object_type,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.0.is_null() || owner.is_null() || dacl.is_null() {
        return Err(permission_denied());
    }
    // Safety: GetSecurityInfo returns a live LocalFree-owned allocation.
    let descriptor_size = unsafe { LocalSize(descriptor.0) };
    if descriptor_size == 0 {
        return Err(permission_denied());
    }
    // Safety: the Windows outputs belong to the retained descriptor, whose
    // allocation size was just measured.
    unsafe { read_snapshot(&descriptor, descriptor_size, owner, dacl) }
}

fn bytes_remaining(start: *const c_void, length: usize, address: *const c_void) -> usize {
    address
        .addr()
        .checked_sub(start.addr())
        .and_then(|offset| length.checked_sub(offset))
        .unwrap_or(0)
}

/// The descriptor must own the Windows-returned owner and DACL pointers for
/// the duration of this call. The supplied size must fit its allocation.
unsafe fn read_snapshot(
    descriptor: &Descriptor,
    descriptor_size: usize,
    owner: PSID,
    dacl: *mut ACL,
) -> io::Result<DescriptorSnapshot> {
    let dacl_available = bytes_remaining(descriptor.0, descriptor_size, dacl.cast());
    if dacl.is_null() || !dacl.cast::<u32>().is_aligned() || dacl_available < size_of::<ACL>() {
        return Err(permission_denied());
    }
    // Safety: the aligned ACL header fits in the descriptor.
    let acl = unsafe { dacl.read() };
    let acl_size = usize::from(acl.AclSize);
    if !(size_of::<ACL>()..=dacl_available).contains(&acl_size) {
        return Err(permission_denied());
    }
    // Safety: the entire ACL range declared in its header fits in the allocation.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(permission_denied());
    }
    let count = acl.AceCount;
    if !(2..=32).contains(&count) {
        return Err(permission_denied());
    }
    let owner_available = bytes_remaining(descriptor.0, descriptor_size, owner);
    // Safety: the owner is backed by the retained descriptor and the bound
    // limits reads to the bytes available at the reported owner address.
    let owner_sid = unsafe { sid_string(owner, owner_available) }?;
    let ace_start = dacl.cast::<u8>().wrapping_add(size_of::<ACL>()).cast();
    let ace_capacity = acl_size - size_of::<ACL>();
    let mut entries = Vec::with_capacity(usize::from(count));
    for idx in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        // Safety: IsValidAcl accepted this bounded ACL, and idx is below AceCount.
        if unsafe { GetAce(dacl, idx, &raw mut ace) } == 0 || ace.is_null() {
            return Err(permission_denied());
        }
        let ace_available = bytes_remaining(ace_start, ace_capacity, ace);
        // Safety: GetAce returned an address in the live ACL; read_allowed_entry
        // checks its alignment and available range before reading.
        entries.push(unsafe { read_allowed_entry(ace, ace_available) }?);
    }
    Ok(DescriptorSnapshot {
        owner: owner_sid,
        entries,
    })
}

/// The caller must retain the Windows ACL and supply the number of bytes
/// available at this ACE address within the ACL's ACE area.
unsafe fn read_allowed_entry(ace: *mut c_void, available: usize) -> io::Result<AllowedEntry> {
    if ace.is_null() || !ace.cast::<u32>().is_aligned() || available < size_of::<ACE_HEADER>() {
        return Err(permission_denied());
    }
    // Safety: the aligned ACE header fits in the ACL's ACE area.
    let header = unsafe { ace.cast::<ACE_HEADER>().read() };
    let ace_size = usize::from(header.AceSize);
    if header.AceType != 0 || !(size_of::<ACCESS_ALLOWED_ACE>()..=available).contains(&ace_size) {
        return Err(permission_denied());
    }
    // Safety: the aligned allowed ACE prefix fits inside the verified ACE range.
    let allowed = unsafe { ace.cast::<ACCESS_ALLOWED_ACE>().read() };
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_ptr = ace.cast::<u8>().wrapping_add(sid_offset).cast();
    // Safety: the embedded SID is backed by the live ACL and bounded by this
    // ACE's end, even when the ACL contains more ACEs.
    let sid = unsafe { sid_string(sid_ptr, ace_size - sid_offset) }?;
    Ok(AllowedEntry {
        flags: header.AceFlags,
        mask: allowed.Mask,
        sid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        ACL_SIZE_INFORMATION, AclSizeInformation, GetAclInformation, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner,
    };

    fn fixture(sddl: &str) -> (Descriptor, usize, PSID, *mut ACL) {
        let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = Descriptor(std::ptr::null_mut());
        let mut size = 0;
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        // Safety: NUL-terminated SDDL, owned allocation and writable output slots.
        unsafe {
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut descriptor.0,
                    &raw mut size,
                ),
                0
            );
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.0, &raw mut owner, &raw mut defaulted),
                0
            );
            assert_ne!(
                GetSecurityDescriptorDacl(
                    descriptor.0,
                    &raw mut present,
                    &raw mut dacl,
                    &raw mut defaulted,
                ),
                0
            );
        }
        assert_ne!(present, 0);
        assert!(!owner.is_null());
        assert!(!dacl.is_null());
        (descriptor, size as usize, owner, dacl)
    }

    const ALLOW_DESCRIPTOR: &str = "O:SYD:P(A;;FR;;;SY)(A;;FA;;;BA)";
    const SYSTEM_SID_SIZE: usize = offset_of!(SID, SubAuthority) + size_of::<u32>();

    #[test]
    fn descriptor_rejects_dacl_outside_available_range() {
        let (descriptor, size, owner, dacl) = fixture(ALLOW_DESCRIPTOR);
        // Safety: all pointers come from the live fixture and size is its reported length.
        let snapshot = unsafe { read_snapshot(&descriptor, size, owner, dacl) }.unwrap();
        assert_eq!(snapshot.owner, "S-1-5-18");
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].sid, "S-1-5-18");
        assert_eq!(snapshot.entries[1].sid, "S-1-5-32-544");

        let dacl_offset = dacl.addr() - descriptor.0.addr();
        let mut info = ACL_SIZE_INFORMATION::default();
        // Safety: dacl comes from the live fixture and the output struct is writable.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut info).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        let dacl_size = (info.AclBytesInUse + info.AclBytesFree) as usize;
        // Shorten the permitted range only. The native allocation stays intact.
        for available in [size_of::<ACL>() - 1, dacl_size - 1] {
            // Safety: same fixture and pointers; the supplied range is smaller.
            let error = unsafe { read_snapshot(&descriptor, dacl_offset + available, owner, dacl) }
                .err()
                .expect("DACL must fit inside the descriptor range");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn allowed_entry_rejects_ace_outside_available_range() {
        let (_descriptor, _, _, dacl) = fixture(ALLOW_DESCRIPTOR);
        let mut ace = std::ptr::null_mut();
        // Safety: dacl is part of the live, valid Windows-generated fixture.
        assert_ne!(unsafe { GetAce(dacl, 0, &raw mut ace) }, 0);
        assert!(!ace.is_null());
        // The fixture's first ACE is a basic allow ACE for SYSTEM.
        let ace_size = offset_of!(ACCESS_ALLOWED_ACE, SidStart) + SYSTEM_SID_SIZE;
        // Safety: the complete Windows-generated ACE fits in the live fixture.
        assert_eq!(
            unsafe { read_allowed_entry(ace, ace_size) }.unwrap().sid,
            "S-1-5-18"
        );
        for available in [size_of::<ACE_HEADER>() - 1, ace_size - 1] {
            // Safety: the ACE stays live and the supplied range is smaller.
            let error = unsafe { read_allowed_entry(ace, available) }
                .err()
                .expect("ACE must fit inside the ACL range");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn sid_rejects_prefix_and_subauthorities_outside_available_range() {
        let (_descriptor, _, owner, _) = fixture(ALLOW_DESCRIPTOR);
        let sid_header = offset_of!(SID, SubAuthority);
        // Safety: the fixture owner is SYSTEM, whose SID contains one subauthority.
        assert_eq!(
            unsafe { sid_string(owner, SYSTEM_SID_SIZE) }.unwrap(),
            "S-1-5-18"
        );
        for available in [sid_header - 1, sid_header] {
            // Safety: the SID stays live, but the supplied range is smaller.
            assert_eq!(
                unsafe { sid_string(owner, available) }.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn descriptor_still_rejects_non_allow_aces() {
        let (descriptor, size, owner, dacl) =
            fixture("O:SYD:P(D;;FR;;;WD)(A;;FR;;;SY)(A;;FA;;;BA)");
        // Safety: all pointers come from the live fixture and size is its reported length.
        let error = unsafe { read_snapshot(&descriptor, size, owner, dacl) }
            .err()
            .expect("deny ACE must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
