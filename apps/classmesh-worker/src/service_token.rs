//! Fail-closed OS token check for the kernel-reported primary pipe server PID.
//! A LocalSystem SID is necessary, not sufficient: SCM registration, service
//! binary identity and signed policy authorization remain separate gates.
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle is exclusively owned by this scope.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub(crate) fn require_local_system(pid: u32) -> io::Result<()> {
    if pid == 0 || pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid pipe server PID",
        ));
    }
    // SAFETY: read-only query of the kernel process object.
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut raw_token = null_mut();
    // SAFETY: process handle is live and raw_token is writable.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(raw_token);
    let mut required = 0u32;
    // SAFETY: size query intentionally passes no buffer.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
    if (required as usize) < size_of::<TOKEN_USER>() || required > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TokenUser length",
        ));
    }
    let mut aligned = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned buffer is at least required bytes and remains alive for SID comparison.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            aligned.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query populated aligned TOKEN_USER storage.
    let user = unsafe { &*(aligned.as_ptr().cast::<TOKEN_USER>()) };
    let mut system_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = system_sid.len() as u32;
    // SAFETY: fixed owned output buffer and documented well-known SID.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both SIDs originate from Windows APIs and their buffers are alive.
    if unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server is not LocalSystem",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reject_foreign_interactive_user_process() {
        // A real OS process token, not a mocked SID: the child inherits the
        // interactive test runner identity and must not impersonate Service.
        // Avoid running this assertion under LocalSystem CI agents.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "ping -n 8 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn non-service child");
        let result = super::require_local_system(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            result.expect_err("interactive child must not be trusted as Service").kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn reject_current_process_and_zero_pid() {
        assert!(super::require_local_system(0).is_err());
        assert!(super::require_local_system(std::process::id()).is_err());
    }
}
