//! Test-only comparison of section OBJECT protection vs HANDLE access.
//! Same-session child, anonymous zero pages, no secret and NO key bootstrap.
#![cfg(windows)]

use std::io::{BufRead, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READONLY, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: exclusively owned local handle.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedView(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            // SAFETY: successful view owned by this wrapper.
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
fn child_probes_maximum_readonly_object_protection() {
    if std::env::var_os("CLASSMESH_INERT_READONLY_TEST_CHILD").is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("test-only target handle");
    let number = usize::from_str_radix(line.trim(), 16).expect("hex test handle");
    assert_ne!(number, 0);
    let section = OwnedHandle(number as HANDLE);
    let view = OwnedView(unsafe { MapViewOfFile(section.0, FILE_MAP_READ, 0, 0, 4096) });
    assert!(
        !view.0.Value.is_null(),
        "the child can read zero-filled section"
    );
    // SAFETY: successful mapping contains at least one initialized zero byte.
    assert_eq!(unsafe { *view.0.Value.cast::<u8>() }, 0);

    let direct_write = OwnedView(unsafe { MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, 4096) });
    assert!(direct_write.0.Value.is_null(), "direct writable map denied");

    let current = unsafe { GetCurrentProcess() };
    let mut promoted: HANDLE = null_mut();
    // The OS may permit a more privileged HANDLE. Section maximum protection
    // must still prohibit actually mapping writable pages.
    if unsafe {
        DuplicateHandle(
            current,
            section.0,
            current,
            &mut promoted,
            FILE_MAP_WRITE,
            0,
            0,
        )
    } != 0
    {
        let promoted = OwnedHandle(promoted);
        let promoted_write =
            OwnedView(unsafe { MapViewOfFile(promoted.0, FILE_MAP_WRITE, 0, 0, 4096) });
        assert!(
            promoted_write.0.Value.is_null(),
            "PAGE_READONLY section must reject writable view, even after handle promotion"
        );
    }

    let mut cloned: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                current,
                section.0,
                current,
                &mut cloned,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "same-access cloning should remain usable for read-only view"
    );
    let cloned = OwnedHandle(cloned);
    let cloned_write = OwnedView(unsafe { MapViewOfFile(cloned.0, FILE_MAP_WRITE, 0, 0, 4096) });
    assert!(
        cloned_write.0.Value.is_null(),
        "same-access clone must not map writable pages"
    );
}

#[test]
fn readonly_at_creation_section_remains_nonwritable_in_actual_child() {
    let exe = std::env::current_exe().expect("this test executable");
    let child = Command::new(exe)
        .args(["--exact", "child_probes_maximum_readonly_object_protection"])
        .env("CLASSMESH_INERT_READONLY_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual same-session child");
    let mut child = ChildGuard(child);

    // SAFETY: pagefile-backed, noninheritable, zero-initialized public mapping.
    // PAGE_READONLY is set at object CREATION; there is no secret to populate.
    let section = OwnedHandle(unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, null(), PAGE_READONLY, 0, 4096, null())
    });
    assert!(!section.0.is_null(), "create inert read-only section");

    let target_process = child.0.as_raw_handle() as HANDLE;
    let mut remote: HANDLE = null_mut();
    // SAFETY: real retained target process HANDLE and valid source section.
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
        "duplicate only into actual spawned child"
    );
    assert!(!remote.is_null());
    writeln!(
        child.0.stdin.take().expect("child stdin"),
        "{:x}",
        remote as usize
    )
    .expect("send public test-only handle number");
    // The remote HANDLE belongs only to the child; the parent must not close
    // it with CloseHandle in the parent process.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("poll child exit") {
            if !status.success() {
                let mut stderr = String::new();
                child
                    .0
                    .stderr
                    .take()
                    .expect("child stderr")
                    .read_to_string(&mut stderr)
                    .expect("test child diagnostics");
                panic!("inert native readonly child failed: {stderr}");
            }
            break;
        }
        assert!(Instant::now() < deadline, "bounded child test deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}
