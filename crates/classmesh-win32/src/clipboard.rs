//! Read-only, bounded Win32 CF_UNICODETEXT adapter. Not yet invoked from
//! interactive Worker dispatch or enabled on the Service control path.
//!
//! SAFETY: Read only within a locked, size-checked OS-owned global allocation.
//! The clipboard is opened and closed exactly once, the global memory is
//! unlocked on all exits, and only the local zeroizing copy is owned by us.
use crate::clipboard_bounds::{
    ClipboardUnicodeReadError, ClipboardUnicodeUnits, MAX_CLIPBOARD_UTF16_UNITS,
    copy_bounded_clipboard_unicode,
};
use windows_sys::Win32::System::DataExchange::{
    CF_UNICODETEXT, CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

struct OpenClipboardGuard;

impl Drop for OpenClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: constructed only after a successful OpenClipboard call.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

struct LockedGlobalMemory(*mut core::ffi::c_void);

impl Drop for LockedGlobalMemory {
    fn drop(&mut self) {
        // SAFETY: constructed only after a successful GlobalLock on this handle.
        unsafe {
            let _ = GlobalUnlock(self.0);
        }
    }
}

/// Called only from an interactive Worker *after* authenticated, permission-
/// checked dispatch. Does not itself authorize access or transmit any text.
/// Returns None if the clipboard does not provide CF_UNICODETEXT.
pub fn read_clipboard_unicode() -> Result<Option<ClipboardUnicodeUnits>, ClipboardUnicodeReadError>
{
    // SAFETY: A null owner HWND is documented for opening the caller's
    // associated clipboard. Guard ensures CloseClipboard on all later paths.
    if unsafe { OpenClipboard(core::ptr::null_mut()) } == 0 {
        return Err(ClipboardUnicodeReadError::Busy);
    }
    let _clipboard = OpenClipboardGuard;

    // SAFETY: Clipboard is open for the current thread.
    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) } == 0 {
        return Ok(None);
    }
    // SAFETY: Required format is advertised while the clipboard is open.
    let memory = unsafe { GetClipboardData(CF_UNICODETEXT) };
    if memory.is_null() {
        return Err(ClipboardUnicodeReadError::Unavailable);
    }
    // SAFETY: The returned HGLOBAL remains owned by the clipboard, open here.
    let bytes = unsafe { GlobalSize(memory) };
    if bytes == 0 || bytes % core::mem::size_of::<u16>() != 0 {
        return Err(ClipboardUnicodeReadError::InvalidLayout);
    }
    if bytes / core::mem::size_of::<u16>() > MAX_CLIPBOARD_UTF16_UNITS {
        return Err(ClipboardUnicodeReadError::TooLarge);
    }

    // SAFETY: Locking a clipboard-owned HGLOBAL gives a stable pointer while
    // it remains locked, and _clipboard keeps the clipboard open until return.
    let pointer = unsafe { GlobalLock(memory) };
    if pointer.is_null() {
        return Err(ClipboardUnicodeReadError::MemoryUnavailable);
    }
    let _locked = LockedGlobalMemory(memory);
    // SAFETY: bytes were read from the OS HGLOBAL allocation, checked to be
    // nonzero, even and conservatively <=64Ki UTF-16 units + NUL. The pointer
    // remains locked for the lifetime of this bounded borrowed slice.
    let borrowed = unsafe {
        core::slice::from_raw_parts(pointer.cast::<u16>(), bytes / core::mem::size_of::<u16>())
    };
    copy_bounded_clipboard_unicode(borrowed).map(Some)
}
