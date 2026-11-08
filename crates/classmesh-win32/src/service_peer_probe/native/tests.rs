//! Real same-account Windows mechanisms, not cross-account SYSTEM evidence.
use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_child() -> ChildGuard {
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "service_peer_probe::native::tests::owned_recipient_child",
                "--nocapture",
            ])
            .env("CLASSMESH_PROCESS_LEASE_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn wait_child(child: &mut ChildGuard) -> std::process::ExitStatus {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < until,
            "owned fixture child exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn owned_recipient_child() {
    if std::env::var_os("CLASSMESH_PROCESS_LEASE_CHILD").is_none() {
        return;
    }
    // Inert private fixture stdin, NEVER a product bootstrap/authority channel.
    // No caller can use this test as an authentication result.
    let mut line = String::new();
    BufReader::new(std::io::stdin())
        .take(128)
        .read_line(&mut line)
        .unwrap();
    assert!(line.ends_with('\n'), "incomplete bounded fixture transfer");
    let v: Vec<u64> = line
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(v.len(), 3);
    assert!(v[0] > 0 && v[0] < isize::MAX as u64);
    // SAFETY: parent created this owned handle in this exact child; no other
    // fixture thread consumes it. Child termination closes it on parse failure.
    let owned = unsafe { OwnedHandle::from_raw_handle(v[0] as usize as _) };
    let process = ObservedProcess::from_readonly_handle(owned).unwrap();
    assert_eq!(process.identity().pid, v[1] as u32);
    assert_eq!(process.identity().created, v[2]);
    assert_eq!(
        process.granted_access().unwrap(),
        super::super::READ_ONLY_PROCESS_RIGHTS
    );
    assert!(!process.inheritable().unwrap());
    assert!(process.is_alive().unwrap());
}

#[test]
fn minimum_right_process_copy_reaches_only_owned_child_without_inheritance() {
    let source = ObservedProcess::open(std::process::id()).unwrap();
    let mut child = spawn_child();
    // Independently inspect both OS tokens before the PRIVATE same-account
    // mechanism probe. No SID is supplied by a pipe or command-line claim.
    assert!(same_account(source.handle.as_handle(), child.0.as_handle()).unwrap());
    let identity = source.identity();
    let mut remote: HANDLE = std::ptr::null_mut();
    // SAFETY: retained real source/child process objects; explicit minimum mask,
    // noninheritable, no SAME_ACCESS and no token transfer. This helper exists
    // only inside cfg(test), not in the library's external API.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source.handle.as_raw_handle(),
                child.0.as_raw_handle(),
                &mut remote,
                super::super::READ_ONLY_PROCESS_RIGHTS,
                0,
                0,
            )
        },
        0
    );
    assert!(same_account(source.handle.as_handle(), child.0.as_handle()).unwrap());
    writeln!(
        child.0.stdin.take().unwrap(),
        "{} {} {}",
        remote as usize,
        identity.pid,
        identity.created
    )
    .unwrap();
    assert!(wait_child(&mut child).success());
    // Never try to close the target's numeric value remotely: it may be reused.
    assert!(source.is_alive().unwrap());
}

#[test]
fn rejects_nonprocess_and_excessive_rights_without_exposing_them() {
    // SAFETY: creates a nonsecret owned event, which is not a process object.
    let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    assert!(!raw.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert!(ObservedProcess::from_readonly_handle(event).is_err());
    let child = spawn_child();
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicate an owned fixture child handle including terminate right
    // into this parent solely to prove rejection, never into a Worker.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.0.as_raw_handle(),
                GetCurrentProcess(),
                &mut raw,
                super::super::READ_ONLY_PROCESS_RIGHTS | 1,
                0,
                0,
            )
        },
        0
    );
    let excessive = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert!(ObservedProcess::from_readonly_handle(excessive).is_err());
    let mut raw: HANDLE = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.0.as_raw_handle(),
                GetCurrentProcess(),
                &mut raw,
                super::super::READ_ONLY_PROCESS_RIGHTS,
                1,
                0,
            )
        },
        0
    );
    let inheritable = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert!(ObservedProcess::from_readonly_handle(inheritable).is_err());
}

#[test]
fn substituted_live_process_copy_fails_recipient_identity_check() {
    let mut child = spawn_child();
    let intended = ObservedProcess::open(std::process::id())
        .unwrap()
        .identity();
    let mut remote: HANDLE = std::ptr::null_mut();
    // The recipient gets its own process object, NOT the expected parent.
    // It must reject even though the object is live and rights are minimal.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.0.as_raw_handle(),
                child.0.as_raw_handle(),
                &mut remote,
                super::super::READ_ONLY_PROCESS_RIGHTS,
                0,
                0,
            )
        },
        0
    );
    writeln!(
        child.0.stdin.take().unwrap(),
        "{} {} {}",
        remote as usize,
        intended.pid,
        intended.created
    )
    .unwrap();
    assert!(
        !wait_child(&mut child).success(),
        "substitution must fail in real child"
    );
}

#[test]
fn retained_process_observes_owned_child_death_without_pid_reopen() {
    let mut child = spawn_child();
    let process = ObservedProcess::open(child.0.id()).unwrap();
    let original = process.identity();
    assert!(process.is_alive().unwrap());
    // Parent owns the child; killing is fixture cleanup, not a delegated right.
    child.0.kill().unwrap();
    wait_child(&mut child);
    assert!(!process.is_alive().unwrap());
    assert_eq!(process.identity(), original);
}

#[test]
fn actual_pipe_owner_is_observed_and_closed_pipe_is_rejected() {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, OPEN_EXISTING, PIPE_ACCESS_OUTBOUND,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, DisconnectNamedPipe, PIPE_REJECT_REMOTE_CLIENTS,
    };
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        r"\\.\pipe\ClassMesh-peer-probe-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_OUTBOUND,
            PIPE_REJECT_REMOTE_CLIENTS,
            1,
            128,
            128,
            100,
            std::ptr::null(),
        )
    };
    assert_ne!(raw, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
    let server = unsafe { OwnedHandle::from_raw_handle(raw) };
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(raw, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
    let client = unsafe { OwnedHandle::from_raw_handle(raw) };
    let peer = observe_pipe_server(client.as_handle()).unwrap();
    assert_eq!(peer.pid, std::process::id());
    assert_eq!(peer.session, crate::current_session_id().unwrap());
    // A same-account fixture must never pass the actual fixed SCM candidate
    // collector, even if its executable hash matches a caller's lab sample.
    let image = std::env::current_exe().unwrap();
    let digest = ImageSample::open(&image).unwrap().sha256();
    assert!(observe_candidate(client.as_handle(), &image, digest).is_err());
    assert_ne!(unsafe { DisconnectNamedPipe(server.as_raw_handle()) }, 0);
    assert!(observe_pipe_server(client.as_handle()).is_err());
}

#[test]
fn image_hash_comes_from_retained_file_and_does_not_create_signer_authority() {
    let path =
        std::env::temp_dir().join(format!("classmesh-peer-image-{}.bin", std::process::id()));
    std::fs::write(&path, b"abc").unwrap();
    {
        let mut image = ImageSample::open(&path).unwrap();
        assert_eq!(
            image.sha256(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert!(std::fs::write(&path, b"changed").is_err());
        image.recheck().unwrap();
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn scm_absence_is_an_error_without_registration_or_fallback() {
    assert!(ServiceReader::open("ClassMesh-peer-probe-never-installed-713").is_err());
}

#[test]
fn image_sample_rejects_relative_network_and_device_names_before_open() {
    for path in [
        r"relative.exe",
        r"\\host\share\image.exe",
        r"\\?\C:\image.exe",
        r"\\.\NUL",
        r"C:\image.exe:stream",
        r"C:\folder\..\image.exe",
    ] {
        assert_eq!(
            ImageSample::open(Path::new(path)).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
