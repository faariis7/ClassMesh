//! Fail-closed OS token check for the kernel-reported primary pipe server PID.
//! A LocalSystem SID is necessary, not sufficient: SCM registration, service
//! binary identity and signed policy authorization remain separate gates.
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;
use std::time::Duration;

use classmesh_win32::NamedPipeClient;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_USER,
    TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{GetProcessId, WaitForSingleObject};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle is exclusively owned by this scope.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub(crate) struct VerifiedService {
    process: Handle,
    token: Handle,
    pid: u32,
}

impl VerifiedService {
    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn authenticate(pipe: &NamedPipeClient) -> io::Result<Self> {
        let pid = observed_service_pid(pipe)?;
        let [process, token] = pipe.read_service_identity(Duration::from_secs(5))?;
        // Reject invalid and pseudo handles before assuming ownership. Only
        // the SYSTEM-owned primary endpoint can send this fixed bootstrap.
        if process == token
            || [process, token]
                .iter()
                .any(|&raw| !(4..=isize::MAX as u64).contains(&raw))
        {
            return Err(denied("invalid Service proof handles"));
        }
        let service = Self {
            process: Handle(process as usize as HANDLE),
            token: Handle(token as usize as HANDLE),
            pid,
        };
        service.recheck(pipe)?;
        Ok(service)
    }

    pub(crate) fn recheck(&self, pipe: &NamedPipeClient) -> io::Result<()> {
        if observed_service_pid(pipe)? != self.pid {
            return Err(denied("Worker IPC server process changed during handshake"));
        }
        // SAFETY: the owned, query-only process handle is valid for this call.
        if unsafe { GetProcessId(self.process.0) } != self.pid {
            return Err(denied(
                "Service proof does not match the kernel pipe server PID",
            ));
        }
        require_live(&self.process)?;
        require_local_system_token(&self.token)
    }
}

fn observed_service_pid(pipe: &NamedPipeClient) -> io::Result<u32> {
    verify_service_session(pipe.server_session_id().map_err(io::Error::other)?)?;
    let pid = pipe.server_process_id().map_err(io::Error::other)?;
    if pid == 0 || pid == std::process::id() {
        return Err(denied("invalid pipe server PID"));
    }
    Ok(pid)
}

fn verify_service_session(session: u32) -> io::Result<()> {
    if session != 0 {
        return Err(denied(
            "Worker IPC server is not running in Windows Session 0",
        ));
    }
    Ok(())
}

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn require_live(process: &Handle) -> io::Result<()> {
    // A terminated process may return STILL_ACTIVE (259) as its actual exit
    // code. Query the process object's signaled state instead of interpreting
    // its exit code as proof of liveness; zero timeout never blocks Worker.
    // SAFETY: process is a valid owned process handle, queried without waiting.
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
        return Err(denied(
            "pipe server process exited or liveness is unverified",
        ));
    }
    Ok(())
}

fn require_local_system_token(token: &Handle) -> io::Result<()> {
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
        return Err(denied("pipe server is not LocalSystem"));
    }
    Ok(())
}

#[cfg(test)]
fn require_local_system(pid: u32) -> io::Result<()> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    if pid == 0 || pid == std::process::id() {
        return Err(denied("invalid pipe server PID"));
    }
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
    require_live(&process)?;
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    require_local_system_token(&Handle(token))
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_only_session_zero_for_the_pipe_server() {
        assert!(super::verify_service_session(0).is_ok());
        assert!(super::verify_service_session(1).is_err());
        assert!(super::verify_service_session(u32::MAX).is_err());
    }

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
        let error = result.expect_err("interactive child must not be trusted as Service");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "pipe server is not LocalSystem");
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
