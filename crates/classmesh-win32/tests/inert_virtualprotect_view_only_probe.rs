//! Test-only Windows section rights characterization using inert public bytes.
//! VirtualProtect of one mapped VIEW is not a reliable section-object seal.
#![cfg(windows)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualProtect,
    FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READONLY, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: local uniquely owned handle.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedView(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            // SAFETY: local uniquely owned mapping view.
            unsafe { UnmapViewOfFile(self.0) };
            self.0.Value = null_mut();
        }
    }
}

#[test]
fn readonly_virtualprotect_of_view_does_not_reduce_section_object_write_rights() {
    // SAFETY: ephemeral anonymous pagefile section, no disk path, no secret.
    let section = OwnedHandle(unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, null(), PAGE_READWRITE, 0, 4096, null())
    });
    assert!(!section.0.is_null(), "create writable inert object");
    let initial = OwnedView(unsafe { MapViewOfFile(section.0, FILE_MAP_WRITE, 0, 0, 4096) });
    assert!(!initial.0.Value.is_null(), "initial owner must map writable");
    // SAFETY: the initial view maps 4096 owned writable bytes.
    unsafe { *initial.0.Value.cast::<u8>() = 0x42 };

    let mut previous = 0_u32;
    // SAFETY: valid committed view; PAGE_READONLY is compatible with its
    // PAGE_READWRITE file-mapping object maximum protection.
    assert_ne!(
        unsafe { VirtualProtect(initial.0.Value, 4096, PAGE_READONLY, &mut previous) },
        0,
        "downgrade only the original view to PAGE_READONLY"
    );
    assert_eq!(previous, PAGE_READWRITE);

    // Duplicate a reduced-rights handle *within the same process* to model
    // a read-only receiver without any real or cross-session key bootstrap.
    let current = unsafe { GetCurrentProcess() };
    let mut reduced: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                current, section.0, current, &mut reduced, FILE_MAP_READ, 0, 0,
            )
        },
        0,
        "create a separate FILE_MAP_READ handle"
    );
    let reduced = OwnedHandle(reduced);
    let direct_write = OwnedView(unsafe {
        MapViewOfFile(reduced.0, FILE_MAP_WRITE, 0, 0, 4096)
    });
    assert!(direct_write.0.Value.is_null(), "read-reduced handle denies direct write view");

    // Microsoft permits DuplicateHandle to request more object access in
    // some cases. Here the writable SECTION object remains PAGE_READWRITE
    // even after VirtualProtect limited only the initial mapped view.
    let mut promoted: HANDLE = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                current, reduced.0, current, &mut promoted, FILE_MAP_WRITE, 0, 0,
            )
        },
        0,
        "the parent's view-only VirtualProtect cannot remove section write rights"
    );
    let promoted = OwnedHandle(promoted);
    let later_write = OwnedView(unsafe {
        MapViewOfFile(promoted.0, FILE_MAP_WRITE, 0, 0, 4096)
    });
    assert!(
        !later_write.0.Value.is_null(),
        "a new writable section view remains possible; NEVER use this as key integrity protection"
    );
    // SAFETY: the new view is readable and shares the original inert section.
    assert_eq!(unsafe { *later_write.0.Value.cast::<u8>() }, 0x42);
}
