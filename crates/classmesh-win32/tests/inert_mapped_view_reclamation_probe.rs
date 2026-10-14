//! Windows-only, test-only evidence about section VIEW lifetime after a
//! target process's remote section HANDLE is reclaimed by its parent.
//! This uses a fixed PUBLIC marker in the SAME session. It is not key delivery,
//! Session-0->Worker qualification, a production control channel or revocation.
#![cfg(windows)]

use std::io::{BufRead, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const PUBLIC_MARKER: &[u8] = b"CM-INERT-VIEW-ONLY";
const CHILD_ENV: &str = "CLASSMESH_INERT_MAPPED_VIEW_CHILD";

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this is an exclusively owned handle in THIS process.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedView(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            // SAFETY: this wrapper uniquely owns an existing mapped view.
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

// This is the target-side probe. Only runs in an explicitly spawned test
// process; a number from stdin is NOT a production HANDLE bootstrap.
#[test]
fn inert_target_child_observes_view_after_handle_reclamation() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    input.read_line(&mut line).expect("fixed test handle input");
    let remote = usize::from_str_radix(line.trim(), 16)
        .expect("test-only hexadecimal remote handle") as HANDLE;
    assert!(!remote.is_null());

    // SAFETY: Windows validates the HANDLE in this test process. The parent
    // specifically duplicated a read-only anonymous mapping to this child.
    let mapped =
        OwnedView(unsafe { MapViewOfFile(remote, FILE_MAP_READ, 0, 0, PUBLIC_MARKER.len()) });
    assert!(
        !mapped.0.Value.is_null(),
        "target first maps its valid handle"
    );
    println!("CLASSMESH_VIEW_READY");
    std::io::stdout()
        .flush()
        .expect("flush test synchronization");

    line.clear();
    input.read_line(&mut line).expect("revocation signal");
    assert_eq!(line.trim(), "CLOSED");

    // A fresh mapping through the reclaimed HANDLE number MUST fail. The
    // existing view is independent of its creator HANDLE's table entry.
    let fresh =
        OwnedView(unsafe { MapViewOfFile(remote, FILE_MAP_READ, 0, 0, PUBLIC_MARKER.len()) });
    assert!(
        fresh.0.Value.is_null(),
        "reclaimed handle cannot create another view"
    );

    // SAFETY: the existing view is owned by this process and maps at least
    // PUBLIC_MARKER.len() bytes until OwnedView is dropped.
    let bytes =
        unsafe { std::slice::from_raw_parts(mapped.0.Value.cast::<u8>(), PUBLIC_MARKER.len()) };
    assert_eq!(
        bytes, PUBLIC_MARKER,
        "HANDLE closure cannot unmap an existing view"
    );
    println!("CLASSMESH_VIEW_REMAINS");
    std::io::stdout().flush().expect("flush test result");
    // Do NOT call CloseHandle(remote): the parent already revoked this entry.
}

fn wait_for_marker(lines: &Receiver<String>, marker: &str) {
    for _ in 0..20 {
        let line = lines
            .recv_timeout(Duration::from_secs(5))
            .expect("test child failed to respond before bounded timeout");
        if line.contains(marker) {
            return;
        }
    }
    panic!("test child never emitted expected public marker");
}

#[test]
fn inert_mapped_view_survives_parent_closing_child_section_handle() {
    let exe = std::env::current_exe().expect("current Windows test executable");
    let child = Command::new(exe)
        .args([
            "--exact",
            "inert_target_child_observes_view_after_handle_reclamation",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn isolated target test child");
    let mut child = ChildGuard(child);

    // Never expose a key or name. An anonymous, non-inheritable pagefile-backed
    // section stores ONLY this fixed inert public marker.
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
    assert!(!section.0.is_null(), "anonymous inert section");
    let source_view =
        OwnedView(unsafe { MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, PUBLIC_MARKER.len()) });
    assert!(!source_view.0.Value.is_null());
    // SAFETY: source_view covers the fixed marker length and is writeable.
    unsafe {
        std::ptr::copy_nonoverlapping(
            PUBLIC_MARKER.as_ptr(),
            source_view.0.Value.cast::<u8>(),
            PUBLIC_MARKER.len(),
        );
    }

    let target = child.0.as_raw_handle() as HANDLE;
    assert!(
        !target.is_null(),
        "actual OS-launched target process HANDLE"
    );
    let mut remote: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                section.0,
                target,
                &mut remote,
                FILE_MAP_READ,
                0,
                0,
            )
        },
        0,
        "duplicate read-only section into actual target only"
    );
    assert!(!remote.is_null());

    let stdout = child.0.stdout.take().expect("child output");
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    // Deliberately transfer only the numeric handle of a PUBLIC INERT object
    // via private test stdin; this technique is REJECTED for production keys.
    writeln!(
        child.0.stdin.as_mut().expect("child stdin"),
        "{:x}",
        remote as usize
    )
    .expect("send test-only handle number");
    child
        .0
        .stdin
        .as_mut()
        .expect("child stdin")
        .flush()
        .expect("flush");
    wait_for_marker(&rx, "CLASSMESH_VIEW_READY");

    // After the target MAPS the object, reclaim/close ONLY its remote HANDLE.
    // This is a genuine OS remote handle-table close, not a test mock.
    let mut reclaimed: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                target,
                remote,
                GetCurrentProcess(),
                &mut reclaimed,
                FILE_MAP_READ,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        },
        0,
        "parent must reclaim target-side handle"
    );
    let reclaimed = OwnedHandle(reclaimed);
    assert!(!reclaimed.0.is_null());

    writeln!(child.0.stdin.as_mut().expect("child stdin"), "CLOSED")
        .expect("send after-reclamation test signal");
    child.0.stdin.take();
    wait_for_marker(&rx, "CLASSMESH_VIEW_REMAINS");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(exit) = child.0.try_wait().expect("poll native target") {
            assert!(exit.success(), "child must finish without access violation");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "target did not exit before deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.join().expect("join bounded child output reader");
}
