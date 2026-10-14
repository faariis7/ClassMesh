//! Inert native Windows server identity probe for a future independent v12
//! outbound channel. Public pipe names only; NO key or clipboard content.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE, OPEN_EXISTING,
    PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: locally owned handle, not an inherited capability.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wide_null(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

#[test]
fn child_observes_true_outbound_named_pipe_server_identity() {
    if std::env::var_os("CLASSMESH_INERT_OUTBOUND_PEER_CHILD").is_none() {
        return;
    }
    let full_name =
        std::env::var("CLASSMESH_INERT_OUTBOUND_TEST_NAME").expect("test-only public pipe path");
    let expected_pid: u32 = std::env::var("CLASSMESH_INERT_OUTBOUND_EXPECTED_PID")
        .expect("test-only expected parent process id")
        .parse()
        .expect("numeric PID");
    let path = wide_null(OsStr::new(&full_name));

    // SAFETY: a previously created local test server pipe with the expected
    // allowed current-user security descriptor; no secret is read.
    let client = OwnedHandle(unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_NONE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    });
    assert_ne!(client.0, INVALID_HANDLE_VALUE, "client opens local pipe");
    let mut server_pid = 0_u32;
    let mut server_session = 0_u32;
    // SAFETY: a genuine connected Windows named-pipe client HANDLE and valid
    // single-u32 out pointers.
    assert_ne!(
        unsafe { GetNamedPipeServerProcessId(client.0, &mut server_pid) },
        0
    );
    assert_ne!(
        unsafe { GetNamedPipeServerSessionId(client.0, &mut server_session) },
        0
    );
    assert_eq!(
        server_pid, expected_pid,
        "native server PID mismatch must fail closed"
    );

    let mut session_by_pid = 0_u32;
    // SAFETY: compare independently OS-returned PID-to-session to the pipe
    // session, never to a ClientHello-asserted identity.
    assert_ne!(
        unsafe { ProcessIdToSessionId(server_pid, &mut session_by_pid) },
        0,
    );
    assert_eq!(server_session, session_by_pid, "OS session mismatch");
}

fn run_inert_server_identity_case(wrong_expected_pid: bool) -> (bool, String) {
    let nonce = NEXT_PIPE.fetch_add(1, Ordering::Relaxed);
    let full_name = format!(
        r"\\.\pipe\ClassMesh-Inert-Outbound-ServerPeer-{}-{nonce}",
        std::process::id()
    );
    let wide_name = wide_null(OsStr::new(&full_name));
    // SAFETY: isolated test-only server instance. This probe does not call
    // WriteFile, send a key, or exercise production Service ACL policy.
    let server = OwnedHandle(unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64,
            64,
            1_000,
            null(),
        )
    });
    assert_ne!(
        server.0, INVALID_HANDLE_VALUE,
        "create one local inert server"
    );
    let actual_pid = std::process::id();
    let expected = if wrong_expected_pid {
        actual_pid.checked_add(1).unwrap_or(1)
    } else {
        actual_pid
    };
    let test_binary = std::env::current_exe().expect("test executable");
    let child = Command::new(test_binary)
        .args([
            "--exact",
            "child_observes_true_outbound_named_pipe_server_identity",
        ])
        .env("CLASSMESH_INERT_OUTBOUND_PEER_CHILD", "1")
        .env("CLASSMESH_INERT_OUTBOUND_TEST_NAME", full_name)
        .env(
            "CLASSMESH_INERT_OUTBOUND_EXPECTED_PID",
            expected.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual same-session test client");
    let mut child = ChildGuard(child);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(exit) = child.0.try_wait().expect("poll child status") {
            let mut stderr = String::new();
            use std::io::Read;
            child
                .0
                .stderr
                .take()
                .expect("stderr capture")
                .read_to_string(&mut stderr)
                .expect("read child diagnostics");
            return (exit.success(), stderr);
        }
        assert!(
            Instant::now() < end,
            "no-client test must not block indefinitely"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn native_test_client_reads_actual_server_process_and_session() {
    let (success, stderr) = run_inert_server_identity_case(false);
    assert!(
        success,
        "native OS-reported server identity failed: {stderr}"
    );
}

#[test]
fn native_test_client_rejects_wrong_expected_server_process() {
    let (success, stderr) = run_inert_server_identity_case(true);
    assert!(!success, "wrong expected server PID must not be accepted");
    assert!(
        stderr.contains("native server PID mismatch must fail closed"),
        "failure must be identity mismatch, not unrelated client error: {stderr}"
    );
}
