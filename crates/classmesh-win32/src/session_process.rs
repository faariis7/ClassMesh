use std::ffi::OsString;
use std::fmt;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION,
    STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchError {
    pub stage: &'static str,
    pub win32_error: u32,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed with Win32 error {}",
            self.stage, self.win32_error
        )
    }
}

impl std::error::Error for LaunchError {}

#[derive(Debug)]
pub struct SessionProcess {
    process: HANDLE,
    process_id: u32,
    session_id: u32,
}

// A process HANDLE may be waited on/closed from another service thread. Ownership remains unique
// to this wrapper and all operations are synchronized by the Windows kernel object itself.
unsafe impl Send for SessionProcess {}

impl SessionProcess {
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Accept an OS-reported pipe peer only while the exact launched Worker
    /// process HANDLE is still active. The handle is not reconstructed from PID.
    pub fn matches_live_pipe_peer(
        &self,
        peer: &crate::named_pipe::PipePeer,
    ) -> Result<bool, LaunchError> {
        if self.process_id != peer.process_id() || self.session_id != peer.session_id() {
            return Ok(false);
        }
        self.is_running()
    }

    pub fn is_running(&self) -> Result<bool, LaunchError> {
        // SAFETY: `self.process` is an owned, live process handle until Drop.
        match unsafe { WaitForSingleObject(self.process, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(last_error("WaitForSingleObject")),
        }
    }

    pub fn terminate(&mut self, exit_code: u32) -> Result<(), LaunchError> {
        if !self.is_running()? {
            return Ok(());
        }
        // SAFETY: the handle is owned by this wrapper and has process termination rights because
        // it was returned directly by CreateProcessAsUserW.
        if unsafe { TerminateProcess(self.process, exit_code) } == 0 {
            return Err(last_error("TerminateProcess"));
        }
        Ok(())
    }
}

impl Drop for SessionProcess {
    fn drop(&mut self) {
        if !self.process.is_null() {
            // SAFETY: process handle ownership is unique to this wrapper.
            unsafe {
                CloseHandle(self.process);
            }
            self.process = null_mut();
        }
    }
}

pub fn session_user_sid(session_id: u32) -> Result<Vec<u8>, LaunchError> {
    let mut user_token: HANDLE = null_mut();
    // SAFETY: WTSQueryUserToken writes one HANDLE to the provided valid pointer. The caller is the
    // LocalSystem service; lack of the required privilege is returned as a normal Win32 error.
    if unsafe { WTSQueryUserToken(session_id, &mut user_token) } == 0 {
        return Err(last_error("WTSQueryUserToken"));
    }
    let token_guard = HandleGuard(user_token);

    let mut required = 0_u32;
    // SAFETY: the first query intentionally passes no output buffer so Windows reports the size.
    unsafe {
        GetTokenInformation(token_guard.0, TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(last_error("GetTokenInformation(TokenUser,size)"));
    }

    let word = size_of::<usize>();
    let words = usize::try_from(required)
        .unwrap_or(usize::MAX)
        .saturating_add(word - 1)
        / word;
    let mut buffer = vec![0_usize; words];
    // SAFETY: buffer is aligned storage of at least required bytes and remains alive while
    // TOKEN_USER and its SID pointer are inspected.
    if unsafe {
        GetTokenInformation(
            token_guard.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_error("GetTokenInformation(TokenUser)"));
    }

    // SAFETY: successful TokenUser query populated a TOKEN_USER at the start of the aligned buffer.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    // SAFETY: the SID pointer belongs to the live TokenUser buffer.
    if unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(LaunchError {
            stage: "IsValidSid(TokenUser)",
            win32_error: 0,
        });
    }
    // SAFETY: the SID was validated above.
    let sid_len = unsafe { GetLengthSid(token_user.User.Sid) };
    let mut sid = vec![0_u8; usize::try_from(sid_len).expect("SID length fits usize")];
    // SAFETY: destination has exactly sid_len writable bytes; source is a validated SID.
    if unsafe { CopySid(sid_len, sid.as_mut_ptr().cast(), token_user.User.Sid) } == 0 {
        return Err(last_error("CopySid(TokenUser)"));
    }
    Ok(sid)
}

pub fn launch_worker_in_session(
    session_id: u32,
    executable: &Path,
    extra_args: &[OsString],
) -> Result<SessionProcess, LaunchError> {
    let mut user_token: HANDLE = null_mut();
    // SAFETY: WTSQueryUserToken writes one HANDLE to the provided valid pointer. The caller is the
    // LocalSystem service; lack of the required privilege is returned as a normal Win32 error.
    if unsafe { WTSQueryUserToken(session_id, &mut user_token) } == 0 {
        return Err(last_error("WTSQueryUserToken"));
    }
    let token_guard = HandleGuard(user_token);

    let mut application = wide_null(executable.as_os_str());
    let mut command_line = quoted_command_line(executable, session_id, extra_args);
    let mut desktop = wide_null(std::ffi::OsStr::new("winsta0\\default"));
    let current_directory = executable.parent().map(|path| wide_null(path.as_os_str()));

    // SAFETY: Win32 startup/process structures are plain-old-data and zero is their documented
    // initialization state when `cb` is subsequently set.
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).expect("STARTUPINFOW fits in u32");
    startup.lpDesktop = desktop.as_mut_ptr();
    // SAFETY: same POD initialization rule as STARTUPINFOW.
    let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };

    let current_directory_ptr = current_directory
        .as_ref()
        .map_or(null(), |directory| directory.as_ptr());

    // Passing a null environment intentionally asks Windows to inherit the service environment for
    // the first prototype. A user-profile environment block is the next hardening step; the Worker
    // must not depend on USERPROFILE/AppData until that is wired in.
    let creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    // SAFETY: all pointers reference mutable/null-terminated buffers that outlive this call. The
    // token and output structures are valid. Handles returned in PROCESS_INFORMATION are owned here.
    let created = unsafe {
        CreateProcessAsUserW(
            token_guard.0,
            application.as_mut_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            creation_flags,
            null(),
            current_directory_ptr,
            &startup,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(last_error("CreateProcessAsUserW"));
    }

    if !process_info.hThread.is_null() {
        // SAFETY: this thread handle was just returned by CreateProcessAsUserW and is no longer
        // needed after process creation.
        unsafe {
            CloseHandle(process_info.hThread);
        }
    }

    Ok(SessionProcess {
        process: process_info.hProcess,
        process_id: process_info.dwProcessId,
        session_id,
    })
}

fn quoted_command_line(executable: &Path, session_id: u32, extra_args: &[OsString]) -> Vec<u16> {
    let mut command = OsString::from("\"");
    command.push(executable.as_os_str());
    command.push("\" --session ");
    command.push(session_id.to_string());
    for argument in extra_args {
        command.push(" ");
        command.push(quote_argument(argument));
    }
    wide_null(&command)
}

fn quote_argument(argument: &OsString) -> OsString {
    let text = argument.to_string_lossy();
    if !text.contains([' ', '\t', '"']) {
        return argument.clone();
    }
    // Service-provided arguments are currently identifiers/pipe names, not arbitrary shell text.
    // Escape quotes and wrap the complete value so CreateProcess' command-line parser preserves it.
    OsString::from(format!("\"{}\"", text.replace('"', "\\\"")))
}

fn wide_null(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(stage: &'static str) -> LaunchError {
    // SAFETY: GetLastError has no preconditions and is read immediately after the failing API.
    let win32_error = unsafe { GetLastError() };
    LaunchError { stage, win32_error }
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership of the WTS token handle is unique to this guard.
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::ffi::OsStringExt;

    use super::*;

    #[test]
    fn alive_session_process_accepts_only_exact_os_pipe_peer_identity() {
        use crate::named_pipe::PipePeer;
        use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let current = unsafe { GetCurrentProcess() };
        let mut owned = null_mut();
        // SAFETY: DuplicateHandle creates an owned process handle for this test,
        // so SessionProcess may safely CloseHandle it on drop.
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    current,
                    current,
                    &mut owned,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let process = SessionProcess {
            process: owned,
            process_id: std::process::id(),
            session_id: 37,
        };
        assert!(
            process
                .matches_live_pipe_peer(&PipePeer::synthetic_for_test(std::process::id(), 37))
                .expect("valid current process handle")
        );
        assert!(
            !process
                .matches_live_pipe_peer(&PipePeer::synthetic_for_test(std::process::id() + 1, 37))
                .expect("wrong PID is rejected")
        );
        assert!(
            !process
                .matches_live_pipe_peer(&PipePeer::synthetic_for_test(std::process::id(), 38))
                .expect("wrong session is rejected")
        );
    }

    #[test]
    fn signaled_worker_wait_handle_is_not_an_admissible_live_process() {
        use crate::named_pipe::PipePeer;
        use windows_sys::Win32::System::Threading::CreateEventW;

        // Only in a unit test, a signaled event acts as a deterministic exited
        // waitable HANDLE; in production this field is from CreateProcessAsUserW.
        let signaled = unsafe { CreateEventW(null(), 1, 1, null()) };
        assert!(!signaled.is_null());
        let process = SessionProcess {
            process: signaled,
            process_id: std::process::id(),
            session_id: 37,
        };
        assert!(
            !process
                .matches_live_pipe_peer(&PipePeer::synthetic_for_test(std::process::id(), 37))
                .expect("signaled waitable handle must fail closed")
        );
    }

    #[test]
    fn sensitive_peer_requires_live_process_and_exact_current_control() {
        use crate::named_pipe::PipePeer;
        use crate::sensitive_pipe_listener::SensitivePipeListener;
        use crate::sensitive_pipe_name::{SensitivePipeAdmission, SensitivePipeNameBinding};
        use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

        let handle = unsafe { GetCurrentProcess() };
        let mut duplicate = null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    handle,
                    handle,
                    handle,
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let worker = SessionProcess {
            process: duplicate,
            process_id: std::process::id(),
            session_id: 37,
        };
        let current = SensitivePipeNameBinding {
            service_process_id: std::process::id(),
            worker_session_id: 37,
            worker_generation: 7,
            control_session_id: 11,
            control_sequence: 12,
            request_id: 13,
        };
        let admission = SensitivePipeAdmission::register(
            current,
            current,
            std::process::id(),
            std::process::id(),
        )
        .expect("valid Service-controlled admission");
        let peer = PipePeer::synthetic_for_test(std::process::id(), 37);
        assert!(
            SensitivePipeListener::verify_bound_worker(&admission, current, &worker, &peer,)
                .is_ok()
        );
        let changed = SensitivePipeNameBinding {
            request_id: current.request_id + 1,
            ..current
        };
        assert_eq!(
            SensitivePipeListener::verify_bound_worker(&admission, changed, &worker, &peer)
                .expect_err("stale control request must be denied")
                .stage,
            "SensitivePipePeerBinding"
        );
        let other = PipePeer::synthetic_for_test(std::process::id() + 1, 37);
        assert_eq!(
            SensitivePipeListener::verify_bound_worker(&admission, current, &worker, &other)
                .expect_err("wrong OS process must be denied")
                .stage,
            "SensitivePipePeerBinding"
        );
        let other_session = PipePeer::synthetic_for_test(std::process::id(), 38);
        assert_eq!(
            SensitivePipeListener::verify_bound_worker(
                &admission,
                current,
                &worker,
                &other_session,
            )
            .expect_err("wrong Windows session must be denied")
            .stage,
            "SensitivePipePeerBinding"
        );

        let signaled = unsafe { CreateEventW(null(), 1, 1, null()) };
        assert!(!signaled.is_null());
        let exited_worker = SessionProcess {
            process: signaled,
            process_id: std::process::id(),
            session_id: 37,
        };
        assert_eq!(
            SensitivePipeListener::verify_bound_worker(&admission, current, &exited_worker, &peer,)
                .expect_err("exited Worker is never admitted")
                .stage,
            "SensitiveWorkerNotRunning"
        );
    }

    #[test]
    fn actual_native_pipe_client_binds_to_the_live_worker_and_current_request() {
        use crate::sensitive_pipe_listener::SensitivePipeListener;
        use crate::sensitive_pipe_name::{SensitivePipeAdmission, SensitivePipeNameBinding};
        use windows_sys::Win32::Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_WRITE,
            INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinAuthenticatedUserSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let session = crate::current_session_id().expect("own Windows session");
        if session == 0 {
            // Session 0 is deliberately invalid for a Teacher/Worker request;
            // the native test is exercised in an interactive VM session.
            return;
        }
        let native_process = unsafe { GetCurrentProcess() };
        let mut owned = null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    native_process,
                    native_process,
                    native_process,
                    &mut owned,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let launched = SessionProcess {
            process: owned,
            process_id: std::process::id(),
            session_id: session,
        };
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
        let binding = SensitivePipeNameBinding {
            service_process_id: std::process::id(),
            worker_session_id: session,
            worker_generation: 19,
            control_session_id: 23,
            control_sequence: 27,
            request_id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        let admission = SensitivePipeAdmission::register(
            binding,
            binding,
            launched.process_id(),
            std::process::id(),
        )
        .expect("trusted current control request");

        let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = sid.len() as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinAuthenticatedUserSid,
                    null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut len,
                )
            },
            0
        );
        sid.truncate(len as usize);
        let mut listener =
            SensitivePipeListener::create(&admission, &sid).expect("temporary local-only pipe");
        let path = format!(r"\\.\pipe\{}", listener.pipe_name());

        let client = std::thread::spawn(move || {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            std::thread::sleep(std::time::Duration::from_millis(20));
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE, "native client connects");
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert_ne!(unsafe { CloseHandle(handle) }, 0);
        });

        let peer = listener
            .wait_for_bound_worker(
                std::time::Duration::from_secs(2),
                &admission,
                || Some(binding),
                &launched,
            )
            .expect("native OS peer matches live process and exact control");
        assert_eq!(peer.process_id(), launched.process_id());
        assert_eq!(peer.session_id(), launched.session_id());
        client.join().expect("native pipe client");
    }

    #[test]
    fn native_v12_peer_rejects_control_revoked_while_waiting() {
        use crate::sensitive_pipe_listener::SensitivePipeListener;
        use crate::sensitive_pipe_name::{SensitivePipeAdmission, SensitivePipeNameBinding};
        use windows_sys::Win32::Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_WRITE,
            INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinAuthenticatedUserSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let session = crate::current_session_id().expect("own Windows session");
        if session == 0 {
            // Session 0 is deliberately invalid for a Teacher/Worker request;
            // the native test is exercised in an interactive VM session.
            return;
        }
        let native_process = unsafe { GetCurrentProcess() };
        let mut owned = null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    native_process,
                    native_process,
                    native_process,
                    &mut owned,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let launched = SessionProcess {
            process: owned,
            process_id: std::process::id(),
            session_id: session,
        };
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
        let binding = SensitivePipeNameBinding {
            service_process_id: std::process::id(),
            worker_session_id: session,
            worker_generation: 19,
            control_session_id: 23,
            control_sequence: 27,
            request_id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        let admission = SensitivePipeAdmission::register(
            binding,
            binding,
            launched.process_id(),
            std::process::id(),
        )
        .expect("trusted current control request");

        let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = sid.len() as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinAuthenticatedUserSid,
                    null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut len,
                )
            },
            0
        );
        sid.truncate(len as usize);
        let mut listener =
            SensitivePipeListener::create(&admission, &sid).expect("temporary local-only pipe");
        let path = format!(r"\\.\pipe\{}", listener.pipe_name());

        let client = std::thread::spawn(move || {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            std::thread::sleep(std::time::Duration::from_millis(20));
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE, "native client connects");
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert_ne!(unsafe { CloseHandle(handle) }, 0);
        });

        let mut reads = 0;
        let rejected = listener
            .wait_for_bound_worker(
                std::time::Duration::from_secs(2),
                &admission,
                || {
                    reads += 1;
                    (reads == 1).then_some(binding)
                },
                &launched,
            )
            .expect_err("revoked control must be refused after native connection");
        assert_eq!(rejected.stage, "SensitiveCurrentControlUnavailable");
        assert_eq!(reads, 2, "control must be sampled on both sides of connect");
        client.join().expect("native pipe client");
    }

    #[test]
    fn worker_command_line_contains_session_and_quotes_path() {
        let path = Path::new(r"C:\Program Files\ClassMesh\classmesh-worker.exe");
        let command = quoted_command_line(path, 17, &[OsString::from("pipe name")]);
        let decoded = OsString::from_wide(&command[..command.len() - 1]);
        let text = decoded.to_string_lossy();
        assert!(
            text.starts_with(r#""C:\Program Files\ClassMesh\classmesh-worker.exe" --session 17"#)
        );
        assert!(text.ends_with(r#""pipe name""#));
    }
}
