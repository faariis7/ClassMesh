//! Inert native Windows server identity probe for a future independent v12
//! outbound channel. Public pipe names only; NO key or clipboard content.
#![cfg(windows)]

use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetTokenInformation, IsValidSid, SECURITY_MAX_SID_SIZE,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE, OPEN_EXISTING,
    PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum SidExpectation {
    CurrentUser,
    CorruptCurrentUser,
    LocalSystem,
}

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

/// Test-only OS token identity probe: the SID is never printed or used as a
/// production trust decision; native cross-session LocalSystem is untested.
fn user_sid_of_native_process(process_id: u32) -> Vec<u8> {
    // SAFETY: asks Windows for a process query HANDLE, never creates one
    // based solely on a caller-asserted authorization principal.
    let process =
        OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) });
    assert!(
        !process.0.is_null(),
        "OS server process query handle unavailable"
    );
    let mut token_handle = null_mut();
    // SAFETY: process is a locally owned kernel HANDLE and output is writable.
    assert_ne!(
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token_handle) },
        0,
        "query native server process token",
    );
    let token = OwnedHandle(token_handle);
    let mut required = 0_u32;
    // SAFETY: initial size-only query deliberately has no buffer.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
    assert!(
        (required as usize) >= size_of::<TOKEN_USER>() && required <= 4096,
        "invalid or unbounded Windows TokenUser size",
    );
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: aligned word buffer contains at least required bytes; token is owned.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        },
        0,
        "query exact native TokenUser",
    );
    // SAFETY: successful TokenUser query returned a TOKEN_USER in aligned storage.
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    // SAFETY: user SID is a kernel-populated field within live token-info storage.
    assert_ne!(unsafe { IsValidSid(user.User.Sid) }, 0, "OS SID invalid");
    let len = unsafe { GetLengthSid(user.User.Sid) } as usize;
    assert!((8..=4096).contains(&len), "OS SID has invalid bounds");
    // SAFETY: validated SID lies within the returned TokenUser allocation.
    unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), len) }.to_vec()
}

/// A Windows-generated well-known SID, not a caller-supplied principal claim.
fn local_system_sid() -> Vec<u8> {
    let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = u32::try_from(sid.len()).expect("bounded Win32 SID size");
    // SAFETY: owned fixed-size buffer, documented well-known SID type.
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        },
        0,
        "native LocalSystem SID must be available",
    );
    sid.truncate(size as usize);
    sid
}

// Windows standard process SYNCHRONIZE access mask for a non-blocking
// WaitForSingleObject liveness check (PROCESS_QUERY_LIMITED_INFORMATION alone
// does not grant SYNCHRONIZE). No rights to write or terminate a process.
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;

/// Test-only process lifetime checkpoint. A returned OS PID alone is not a
/// stable identity: pin the actual process object, verify it is still alive,
/// and bind the kernel-reported creation FILETIME to the test parent.
fn pinned_native_process_creation_time(process_id: u32) -> u64 {
    // SAFETY: OS returns a process HANDLE with minimal query + wait rights.
    let process = OwnedHandle(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            process_id,
        )
    });
    assert!(
        !process.0.is_null(),
        "live native server process handle required"
    );
    // SAFETY: verify process identity through the real owned HANDLE, not the
    // untrusted child-declared expected PID. Zero timeout never blocks.
    assert_eq!(
        unsafe { GetProcessId(process.0) },
        process_id,
        "pinned OS server process PID mismatch must fail closed",
    );
    assert_eq!(
        unsafe { WaitForSingleObject(process.0, 0) },
        WAIT_TIMEOUT,
        "native server process must still be alive",
    );
    let empty_time = || FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut creation = empty_time();
    let mut exit = empty_time();
    let mut kernel = empty_time();
    let mut user = empty_time();
    // SAFETY: live owned process HANDLE and four writable Win32 FILETIME
    // outputs. Creation time is public test metadata, never an auth secret.
    assert_ne!(
        unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) },
        0,
        "OS server process creation time unavailable",
    );
    let created = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    assert_ne!(created, 0, "server process creation time must be nonzero");
    created
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
    if let Ok(expected_birth) = std::env::var("CLASSMESH_INERT_OUTBOUND_EXPECTED_BIRTH") {
        let expected: u64 = expected_birth
            .parse()
            .expect("test-only numeric server creation time");
        let actual = pinned_native_process_creation_time(server_pid);
        assert!(
            actual == expected,
            "native server process creation time mismatch must fail closed",
        );
    }
    if std::env::var_os("CLASSMESH_INERT_OUTBOUND_CHECK_TOKEN_SID").is_some() {
        let observed = user_sid_of_native_process(server_pid);
        let mut expected =
            if std::env::var_os("CLASSMESH_INERT_OUTBOUND_REQUIRE_SYSTEM_SID").is_some() {
                local_system_sid()
            } else {
                user_sid_of_native_process(std::process::id())
            };
        if std::env::var_os("CLASSMESH_INERT_OUTBOUND_WRONG_TOKEN_SID").is_some() {
            *expected.last_mut().expect("native SID is nonempty") ^= 1;
        }
        // Do not use assert_eq!: it would dump OS account SID bytes in logs.
        assert!(
            observed == expected,
            "native server token SID mismatch must fail closed"
        );
    }
}

fn run_inert_server_identity_case(
    wrong_expected_pid: bool,
    sid_expectation: Option<SidExpectation>,
    wrong_expected_birth: Option<bool>,
) -> (bool, String) {
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
    let mut child_command = Command::new(test_binary);
    child_command
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
        .env_remove("CLASSMESH_INERT_OUTBOUND_CHECK_TOKEN_SID")
        .env_remove("CLASSMESH_INERT_OUTBOUND_WRONG_TOKEN_SID")
        .env_remove("CLASSMESH_INERT_OUTBOUND_REQUIRE_SYSTEM_SID")
        .env_remove("CLASSMESH_INERT_OUTBOUND_EXPECTED_BIRTH");
    if let Some(wrong) = wrong_expected_birth {
        let actual_birth = pinned_native_process_creation_time(actual_pid);
        let claimed_birth = if wrong {
            actual_birth.checked_add(1).unwrap_or(1)
        } else {
            actual_birth
        };
        child_command.env(
            "CLASSMESH_INERT_OUTBOUND_EXPECTED_BIRTH",
            claimed_birth.to_string(),
        );
    }
    if let Some(sid_mode) = sid_expectation {
        child_command.env("CLASSMESH_INERT_OUTBOUND_CHECK_TOKEN_SID", "1");
        match sid_mode {
            SidExpectation::CurrentUser => {}
            SidExpectation::CorruptCurrentUser => {
                child_command.env("CLASSMESH_INERT_OUTBOUND_WRONG_TOKEN_SID", "1");
            }
            SidExpectation::LocalSystem => {
                child_command.env("CLASSMESH_INERT_OUTBOUND_REQUIRE_SYSTEM_SID", "1");
            }
        }
    }
    let child = child_command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual same-session test client");
    let mut child = ChildGuard(child);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(exit) = child.0.try_wait().expect("poll child status") {
            // The libtest harness reports a caught assertion failure on
            // stdout, not necessarily stderr. Capture both streams so the
            // negative case must fail specifically on OS PID mismatch.
            use std::io::Read;
            let mut diagnostics = String::new();
            child
                .0
                .stdout
                .take()
                .expect("stdout capture")
                .take(16 * 1024)
                .read_to_string(&mut diagnostics)
                .expect("read bounded child stdout");
            child
                .0
                .stderr
                .take()
                .expect("stderr capture")
                .take(16 * 1024)
                .read_to_string(&mut diagnostics)
                .expect("read bounded child stderr");
            return (exit.success(), diagnostics);
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
    let (success, stderr) = run_inert_server_identity_case(false, None, None);
    assert!(
        success,
        "native OS-reported server identity failed: {stderr}"
    );
}

#[test]
fn native_test_client_rejects_wrong_expected_server_process() {
    let (success, stderr) = run_inert_server_identity_case(true, None, None);
    assert!(!success, "wrong expected server PID must not be accepted");
    assert!(
        stderr.contains("native server PID mismatch must fail closed"),
        "failure must be identity mismatch, not unrelated client error: {stderr}"
    );
}

#[test]
fn native_child_accepts_actual_outbound_server_token_user_sid() {
    let (success, diagnostics) =
        run_inert_server_identity_case(false, Some(SidExpectation::CurrentUser), None);
    assert!(
        success,
        "real native server token user SID should match the same-user test child: {diagnostics}"
    );
}

#[test]
fn native_child_rejects_deliberately_wrong_expected_server_token_user_sid() {
    let (success, diagnostics) =
        run_inert_server_identity_case(false, Some(SidExpectation::CorruptCurrentUser), None);
    assert!(!success, "wrong expected server token SID must be denied");
    assert!(
        diagnostics.contains("native server token SID mismatch must fail closed"),
        "must fail at SID comparison, not at unrelated pipe error: {diagnostics}"
    );
}

#[test]
fn normal_user_outbound_server_cannot_impersonate_required_local_system_identity() {
    // Fail explicitly rather than misreport this negative if test process
    // itself happens to be running as LocalSystem on a different runner.
    assert!(
        user_sid_of_native_process(std::process::id()) != local_system_sid(),
        "negative test requires a real non-LocalSystem Windows user",
    );
    let (success, diagnostics) =
        run_inert_server_identity_case(false, Some(SidExpectation::LocalSystem), None);
    assert!(
        !success,
        "ordinary hosted test user must not be admitted as LocalSystem Service"
    );
    assert!(
        diagnostics.contains("native server token SID mismatch must fail closed"),
        "native token identity gate must deny specifically, not unrelated I/O: {diagnostics}"
    );
}

#[test]
fn native_client_binds_live_server_process_creation_time() {
    let (success, diagnostics) = run_inert_server_lifetime_case(false);
    assert!(
        success,
        "actual live server process binding failed: {diagnostics}"
    );
}

#[test]
fn native_client_rejects_changed_server_process_creation_time() {
    let (success, diagnostics) = run_inert_server_lifetime_case(true);
    assert!(
        !success,
        "wrong native server process birth time must be denied"
    );
    assert!(
        diagnostics.contains("native server process creation time mismatch must fail closed"),
        "denial must be a process lifetime mismatch, not unrelated I/O: {diagnostics}"
    );
}

fn run_inert_server_lifetime_case(wrong_expected_birth: bool) -> (bool, String) {
    run_inert_server_identity_case(false, None, Some(wrong_expected_birth))
}
