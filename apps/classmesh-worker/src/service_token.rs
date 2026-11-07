//! Fail-closed OS token check for the kernel-reported primary pipe server PID.
//! A LocalSystem SID is necessary, not sufficient: SCM registration, service
//! binary identity and signed policy authorization remain separate gates.
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};

#[derive(Debug)]
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle is exclusively owned by this scope.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug)]
pub(crate) struct ServiceProcess(Handle);

impl ServiceProcess {
    pub(crate) fn require_running(&self) -> io::Result<()> {
        // Retain this exact process object for the IPC lifetime. A new OpenProcess
        // by numeric PID on each tick could authenticate a reused PID after exit.
        match unsafe { WaitForSingleObject(self.0.0, 0) } {
            WAIT_TIMEOUT => Ok(()),
            windows_sys::Win32::Foundation::WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe server process exited",
            )),
        }
    }
}

pub(crate) fn require_local_system(pid: u32) -> io::Result<ServiceProcess> {
    if pid == 0 || pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid pipe server PID",
        ));
    }
    // SAFETY: read-only query of the kernel process object.
    let process = Handle(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    });
    if process.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    // A terminated process may return STILL_ACTIVE (259) as its actual exit
    // code. Query the process object's signaled state instead of interpreting
    // its exit code as proof of liveness; zero timeout never blocks Worker.
    // SAFETY: process is a valid owned process handle, queried without waiting.
    let process = ServiceProcess(process);
    process.require_running()?;
    let mut raw_token = null_mut();
    // SAFETY: process handle is live and raw_token is writable.
    if unsafe { OpenProcessToken(process.0.0, TOKEN_QUERY, &mut raw_token) } == 0 {
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
    process.require_running()?;
    Ok(process)
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_process_handle_detects_exit() {
        let mut child = std::process::Command::new("ping.exe")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Exercise the same rights and retained-object wait as production;
        // this is liveness coverage, not a fabricated LocalSystem credential.
        let handle = super::Handle(unsafe {
            super::OpenProcess(
                super::PROCESS_QUERY_LIMITED_INFORMATION | super::PROCESS_SYNCHRONIZE,
                0,
                child.id(),
            )
        });
        assert!(!handle.0.is_null());
        let process = super::ServiceProcess(handle);
        let live = process.require_running();
        let _ = child.kill();
        let _ = child.wait();
        live.expect("retained native process is alive");
        assert!(process.require_running().is_err());
    }

    #[test]
    fn reject_foreign_interactive_user_process() {
        // A real OS process token, not a mocked SID: the child inherits the
        // interactive test runner identity and must not impersonate Service.
        // Avoid running this assertion under LocalSystem CI agents.
        let mut child = std::process::Command::new("ping.exe")
            .args(["-n", "8", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn non-service child");
        let result = super::require_local_system(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            result
                .expect_err("interactive child must not be trusted as Service")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn live_process_reaches_token_authentication() {
        // A negative-only suite also passes when *every* live Service is
        // rejected before the SID check. Exercise the actual OpenProcess /
        // wait path with a live child and require rejection at TokenUser.
        let mut child = std::process::Command::new("ping.exe")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn live native peer");
        let result = super::require_local_system(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            result.expect_err("non-SYSTEM peer").to_string(),
            "pipe server is not LocalSystem",
            "a live process must reach the real token SID check"
        );
    }

    #[test]
    fn reject_exited_process_pid() {
        // A PID from a terminated process must not authorize an IPC peer.
        // Even if Windows temporarily retains the process object, its user
        // token is not LocalSystem on an interactive CI runner.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn short-lived process");
        let pid = child.id();
        assert!(child.wait().expect("wait for child exit").success());
        // Keep the child handle alive: Windows retains the exited process
        // object and its token, so an open PID is not proof of liveness.
        assert_eq!(
            super::require_local_system(pid)
                .expect_err("exited process must not authorize IPC")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn reject_exited_process_with_still_active_exit_code() {
        // Windows allows exit code 259, which GetExitCodeProcess reports as
        // STILL_ACTIVE even after termination. The process must be rejected.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "exit 259"])
            .spawn()
            .expect("spawn process with ambiguous exit code");
        let pid = child.id();
        let _ = child.wait().expect("wait for child exit");
        assert_eq!(
            super::require_local_system(pid)
                .expect_err("terminated process with exit code 259 must be rejected")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn reject_current_process_and_zero_pid() {
        assert!(super::require_local_system(0).is_err());
        assert!(super::require_local_system(std::process::id()).is_err());
    }
}
