//! Bounded same-HANDLE descriptor acquisition; callers choose acceptance rules.
use std::os::windows::io::AsRawHandle;
use std::{fs::File, io};

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
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
        IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // Safety: GetSecurityInfo allocates this descriptor with LocalAlloc.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn sid_string(sid: PSID) -> io::Result<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        if sid.is_null() {
            return Err(permission_denied());
        }
        let mut allocated: *mut u16 = std::ptr::null_mut();
        // Safety: owner/ACE SID comes from a live GetSecurityInfo descriptor.
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

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = Descriptor(std::ptr::null_mut());
    // Safety: the File is open and held through all checks; output pointers are
    // writable; GetSecurityInfo returns descriptor-owned owner and DACL pointers.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
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
    let owner_sid = sid_string(owner)?;

    // Safety: ACL and ACE addresses are inside the descriptor allocated by
    // GetSecurityInfo, kept live by Descriptor until this method returns.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(permission_denied());
    }
    // Safety: non-null ACL pointer validated by IsValidAcl.
    let count = unsafe { (*dacl).AceCount };
    if !(2..=32).contains(&count) {
        return Err(permission_denied());
    }
    let mut entries = Vec::with_capacity(usize::from(count));
    for idx in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // Safety: GetAce validates index and returns an ACL-owned ACE pointer.
        if unsafe { GetAce(dacl, idx, &raw mut ace) } == 0 || ace.is_null() {
            return Err(permission_denied());
        }
        // Safety: GetAce returns at least an in-bounds ACE_HEADER. Check size
        // BEFORE treating its memory as an ACCESS_ALLOWED_ACE.
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        if header.AceType != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(permission_denied());
        }
        // Safety: ACE size and type checked above. SidStart is the SID embedded
        // in the allowed ACE, not a separate pathname lookup.
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let sid_ptr = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        let ace_bytes = usize::from(header.AceSize);
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        // A SID needs at least its 8-byte fixed header. Validate that it fits
        // wholly INSIDE this ACE before parsing any variable subauthority data.
        if ace_bytes.saturating_sub(sid_offset) < 8 {
            return Err(permission_denied());
        }
        // Safety: GetAce supplied an in-bounds ACE, and at least the SID header
        // fits. GetLengthSid only reads that header's SubAuthorityCount.
        let length = unsafe { GetLengthSid(sid_ptr) };
        if length < 8 || usize::try_from(length).unwrap_or(usize::MAX) > ace_bytes - sid_offset {
            return Err(permission_denied());
        }
        // Safety: the full SID now fits in the ACE allocation.
        if unsafe { IsValidSid(sid_ptr) } == 0 {
            return Err(permission_denied());
        }
        entries.push(AllowedEntry {
            flags: header.AceFlags,
            mask: allowed.Mask,
            sid: sid_string(sid_ptr)?,
        });
    }
    Ok(DescriptorSnapshot {
        owner: owner_sid,
        entries,
    })
}
