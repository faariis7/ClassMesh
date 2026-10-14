//! Test-only, same-session proof of an unnamed pagefile-backed section
//! duplicated into an exact separately launched Windows process.
//! NEVER use the test's stdin HANDLE-number exchange as production bootstrap.
#![cfg(windows)]

use std::io::{BufRead, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const INERT_PUBLIC_MARKER: &[u8; 16] = b"CM-INERT-KEY-000";

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: exclusively owned local HANDLE.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedView(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            // SAFETY: this view is uniquely owned and still mapped.
            unsafe { UnmapViewOfFile(self.0) };
            self.0.Value = null_mut();
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
fn child_consumes_only_inert_mapped_section_in_test_mode() {
    if std::env::var_os("CLASSMESH_INERT_SECTION_TEST_CHILD").is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("test stdin");
    let remote_value = usize::from_str_radix(line.trim(), 16).expect("test-only handle number");
    assert_ne!(remote_value, 0);
    let section = OwnedHandle(remote_value as HANDLE);
    // SAFETY: the test parent sent a duplicated mapping HANDLE for this process,
    // with a fixed 16-byte committed mapping. No secret or external input.
    let view = OwnedView(unsafe {
        MapViewOfFile(section.0, FILE_MAP_READ, 0, 0, INERT_PUBLIC_MARKER.len())
    });
    assert!(
        !view.0.Value.is_null(),
        "child must map the duplicated section"
    );
    // SAFETY: successful MapViewOfFile above maps at least 16 readable bytes.
    let received =
        unsafe { std::slice::from_raw_parts(view.0.Value.cast::<u8>(), INERT_PUBLIC_MARKER.len()) };
    assert_eq!(received, INERT_PUBLIC_MARKER);
    // The target received only FILE_MAP_READ, NOT the parent's write rights.
    // SAFETY: a write-access request must fail on this read-only mapping handle.
    let writable =
        unsafe { MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, INERT_PUBLIC_MARKER.len()) };
    let was_writable = !writable.Value.is_null();
    if was_writable {
        // SAFETY: on unexpected success, close the real view before failing.
        unsafe { UnmapViewOfFile(writable) };
    }
    assert!(!was_writable, "target may not map a writable view");

    // The source HANDLE in the target has FILE_MAP_READ only. It must not
    // be able to create a different HANDLE with FILE_MAP_WRITE privileges.
    assert_readonly_duplicate_cannot_escalate(section.0);
}

/// Probe both desired-access and SAME_ACCESS duplication in the *target*
/// process. This is an INERT test of Windows section handle semantics; never
/// construe a failed privilege-escalation attempt as production key isolation.
fn assert_readonly_duplicate_cannot_escalate(readonly: HANDLE) {
    use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;

    let self_process = unsafe { GetCurrentProcess() };
    let mut promoted: HANDLE = null_mut();
    // SAFETY: the source is the read-only remote-duplicated section handle in
    // this child, and both process pseudo handles represent this test child.
    let did_promote = unsafe {
        DuplicateHandle(
            self_process,
            readonly,
            self_process,
            &mut promoted,
            FILE_MAP_WRITE,
            0,
            0,
        )
    } != 0;
    if did_promote {
        let promoted = OwnedHandle(promoted);
        let write = OwnedView(unsafe {
            MapViewOfFile(promoted.0, FILE_MAP_WRITE, 0, 0, INERT_PUBLIC_MARKER.len())
        });
        assert!(
            write.0.Value.is_null(),
            "security gate: read-only duplicated section HANDLE permitted a writable mapping"
        );
    }

    let mut same_access: HANDLE = null_mut();
    // SAFETY: requests exactly the read-only rights of the source handle.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                self_process,
                readonly,
                self_process,
                &mut same_access,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "read-only section handle should support same-access duplication"
    );
    let same_access = OwnedHandle(same_access);
    let write = OwnedView(unsafe {
        MapViewOfFile(same_access.0, FILE_MAP_WRITE, 0, 0, INERT_PUBLIC_MARKER.len())
    });
    assert!(
        write.0.Value.is_null(),
        "same-access duplication must never add writable mapping rights"
    );
}

#[test]
fn pagefile_section_is_readable_in_exact_separate_child_after_targeted_duplication() {
    let exe = std::env::current_exe().expect("test executable");
    let child = Command::new(exe)
        .args([
            "--exact",
            "child_consumes_only_inert_mapped_section_in_test_mode",
        ])
        .env("CLASSMESH_INERT_SECTION_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn inert child test process");
    let mut child = ChildGuard(child);

    // SAFETY: INVALID_HANDLE_VALUE creates a private, unnamed pagefile mapping;
    // no inheritable security attributes, process-global name or persistence.
    let section = OwnedHandle(unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null(),
            PAGE_READWRITE,
            0,
            4096,
            null(),
        )
    });
    assert!(!section.0.is_null(), "anonymous mapping creation");

    // SAFETY: the committed mapping is writable by the owning test process.
    let view = OwnedView(unsafe {
        MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, INERT_PUBLIC_MARKER.len())
    });
    assert!(!view.0.Value.is_null(), "parent mapping");
    // SAFETY: successful 16-byte writable view above owns an appropriate region.
    unsafe {
        std::ptr::copy_nonoverlapping(
            INERT_PUBLIC_MARKER.as_ptr(),
            view.0.Value.cast::<u8>(),
            INERT_PUBLIC_MARKER.len(),
        );
    }

    let target_process = child.0.as_raw_handle() as HANDLE;
    assert!(!target_process.is_null());
    let mut remote: HANDLE = null_mut();
    // SAFETY: exact Windows OS-created Child process HANDLE is retained by
    // ChildGuard, and source mapping is a real owned section HANDLE.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                section.0,
                target_process,
                &mut remote,
                FILE_MAP_READ,
                0,
                0,
            )
        },
        0,
        "must duplicate only into actual target child"
    );
    assert!(!remote.is_null());
    // TEST ONLY: deliberately reveal only an INERT handle number over the
    // private test-child stdin. This is forbidden for production v11 keys.
    writeln!(
        child.0.stdin.as_mut().expect("child stdin"),
        "{:x}",
        remote as usize
    )
    .expect("send inert test-only handle value");
    child.0.stdin.take();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll child") {
            assert!(status.success(), "target child failed to map the section");
            break;
        }
        assert!(Instant::now() < deadline, "inert child exceeded time limit");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The target exits before ChildGuard drop: its remote copy is closed by OS.
    // OwnedView and OwnedHandle close the parent's handles on every exit.
}
