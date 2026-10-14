//! Test-only negative qualification: an inert anonymous section HANDLE is
//! duplicated into exactly one Windows child, NOT a second unrelated child.
//! This is SAME-SESSION evidence; it is not a production secret bootstrap.
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

const PUBLIC_MARKER: &[u8; 16] = b"CM-NEG-PROBE-001";
const CHILD_MODE: &str = "CLASSMESH_INERT_WRONG_TARGET_CHILD";

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this wrapper uniquely owns the local OS handle.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedView(MEMORY_MAPPED_VIEW_ADDRESS);

impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            // SAFETY: the view remains mapped until the wrapper is dropped.
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

fn child(mode: &str) -> ChildGuard {
    let exe = std::env::current_exe().expect("native integration test binary");
    ChildGuard(
        Command::new(exe)
            .args(["--exact", "inert_section_isolated_to_target_child"])
            .env(CHILD_MODE, mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn separate native Windows test child"),
    )
}

fn deliver_inert_handle(child: &mut ChildGuard, handle: HANDLE) {
    // Only a public, fixed test marker is mapped. Passing a HANDLE number
    // via stdin is NOT acceptable for a live secret or product v11 IPC.
    writeln!(
        child.0.stdin.as_mut().expect("owned test stdin"),
        "{:x}",
        handle as usize
    )
    .expect("send inert test-only handle number");
    child.0.stdin.take();
}

fn assert_child_completed(child: &mut ChildGuard, role: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll OS-launched child") {
            assert!(
                status.success(),
                "{role} rejected the expected mapping outcome"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{role} did not exit before deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn inert_section_isolated_to_target_child() {
    let Some(mode) = std::env::var_os(CHILD_MODE) else {
        return;
    };
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("test-only stdin");
    let handle_id = usize::from_str_radix(line.trim(), 16).expect("test-only handle");
    assert_ne!(handle_id, 0);
    let section = handle_id as HANDLE;

    // SAFETY: MapViewOfFile performs an OS validity and access check against
    // this process's own HANDLE table; no caller-controlled memory dereference.
    let read_view = unsafe { MapViewOfFile(section, FILE_MAP_READ, 0, 0, PUBLIC_MARKER.len()) };
    match mode.to_str().expect("fixed test mode") {
        "target" => {
            let read_view = OwnedView(read_view);
            assert!(
                !read_view.0.Value.is_null(),
                "target must map its own read-only copy"
            );
            // SAFETY: the successful view maps at least PUBLIC_MARKER.len().
            let bytes = unsafe {
                std::slice::from_raw_parts(read_view.0.Value.cast::<u8>(), PUBLIC_MARKER.len())
            };
            assert_eq!(bytes, PUBLIC_MARKER);
            // SAFETY: the target was granted FILE_MAP_READ only; WRITE must fail.
            let writable =
                unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, PUBLIC_MARKER.len()) };
            let writable = OwnedView(writable);
            assert!(
                writable.0.Value.is_null(),
                "target may not request write access"
            );
            // The target owns this OS-inserted copy of the HANDLE.
            drop(OwnedHandle(section));
        }
        "decoy" => {
            let unexpected = OwnedView(read_view);
            assert!(
                unexpected.0.Value.is_null(),
                "unrelated process must NOT map a HANDLE only duplicated into target"
            );
            // This number is NOT an owned handle in the decoy. Never close it.
        }
        _ => panic!("unrecognized test-only child mode"),
    }
}

#[test]
fn read_only_inert_section_handle_cannot_be_used_by_unrelated_process() {
    let mut target = child("target");
    let mut decoy = child("decoy");
    // SAFETY: anonymous, noninheritable pagefile mapping has no global name.
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
    assert!(
        !section.0.is_null(),
        "create private in-memory inert section"
    );
    let view =
        OwnedView(unsafe { MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, PUBLIC_MARKER.len()) });
    assert!(!view.0.Value.is_null(), "map source section writable");
    // SAFETY: exactly PUBLIC_MARKER.len() bytes are committed and mapped.
    unsafe {
        std::ptr::copy_nonoverlapping(
            PUBLIC_MARKER.as_ptr(),
            view.0.Value.cast::<u8>(),
            PUBLIC_MARKER.len(),
        );
    }

    let exact_target_process = target.0.as_raw_handle() as HANDLE;
    assert!(!exact_target_process.is_null());
    let mut remote: HANDLE = null_mut();
    // SAFETY: the target process HANDLE is from the owned OS-launched Child;
    // duplication does NOT involve the decoy's process HANDLE.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                section.0,
                exact_target_process,
                &mut remote,
                FILE_MAP_READ,
                0,
                0,
            )
        },
        0,
        "duplicate a read-only view into exact target only",
    );
    assert!(!remote.is_null());

    // Both children are given the same NONSECRET *number* to demonstrate
    // that a HANDLE identifier is meaningful only in the owning process.
    deliver_inert_handle(&mut decoy, remote);
    deliver_inert_handle(&mut target, remote);
    assert_child_completed(&mut decoy, "decoy");
    assert_child_completed(&mut target, "target");
    // The target closed its remote handle on exit. Parent view/handle cleaned.
}
