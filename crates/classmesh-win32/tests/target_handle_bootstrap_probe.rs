//! Windows-only, inert process HANDLE duplication qualification.
//! Same-session process mechanics only, not Session-0 LocalSystem to Worker.
#![cfg(windows)]

use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject,
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns the local Windows HANDLE.
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

#[test]
fn inert_target_process_waits_only_when_spawned_for_probe() {
    if std::env::var_os("CLASSMESH_INERT_HANDLE_PROBE_CHILD").is_some() {
        std::thread::sleep(Duration::from_secs(8));
    }
}

#[test]
fn source_event_can_be_duplicated_into_exact_child_then_reclaimed() {
    let exe = std::env::current_exe().expect("current native test binary");
    let child = Command::new(exe)
        .args([
            "--exact",
            "inert_target_process_waits_only_when_spawned_for_probe",
        ])
        .env("CLASSMESH_INERT_HANDLE_PROBE_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch inert separate Windows test process");
    let child = ChildGuard(child);

    // SAFETY: valid arguments create an owned, nonsensitive manual-reset event.
    let source = OwnedHandle(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) });
    assert!(!source.0.is_null(), "must own a real inert source object");
    assert_eq!(unsafe { WaitForSingleObject(source.0, 0) }, WAIT_TIMEOUT);

    let mut denied: HANDLE = null_mut();
    let invalid = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source.0,
            null_mut(),
            &mut denied,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_eq!(invalid, 0, "null target process may never receive a handle");
    assert!(denied.is_null());

    let target_process = child.0.as_raw_handle() as HANDLE;
    let mut remote: HANDLE = null_mut();
    // SAFETY: ChildGuard retains the real OS-created child process handle.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source.0,
                target_process,
                &mut remote,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "OS must duplicate only into the explicitly targeted child",
    );
    assert!(!remote.is_null());

    // Never disclose the target HANDLE value in logs, IPC, or artifacts.
    // SAFETY: this round-trip targets the exact same child process handle.
    // DUPLICATE_CLOSE_SOURCE removes the child copy on success.
    let mut reclaimed: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                target_process,
                remote,
                GetCurrentProcess(),
                &mut reclaimed,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        },
        0,
        "OS must return the inert object and close its child-side handle",
    );
    let reclaimed = OwnedHandle(reclaimed);
    assert!(!reclaimed.0.is_null());
    assert_eq!(unsafe { WaitForSingleObject(reclaimed.0, 0) }, WAIT_TIMEOUT);
    assert_ne!(unsafe { SetEvent(source.0) }, 0);
    assert_eq!(
        unsafe { WaitForSingleObject(reclaimed.0, 0) },
        WAIT_OBJECT_0
    );
}
