use std::ffi::OsStr;
use std::fmt;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_DEFAULT_TIMEOUT_MS: u32 = 5_000;
const MAX_REJECTED_PEERS: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeError {
    pub stage: &'static str,
    pub win32_error: u32,
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed with Win32 error {}",
            self.stage, self.win32_error
        )
    }
}

impl std::error::Error for PipeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipePeer {
    pub process_id: u32,
    pub session_id: u32,
}

/// Blocking local named-pipe endpoint used only for Service <-> Session Worker IPC.
///
/// Pipe ACLs deliberately allow local callers to reach the endpoint because the Service and Worker
/// run under different identities. Authorization is completed by binding the connected pipe to the
/// exact Worker PID and Windows session returned by the Service's process launcher. Remote clients
/// are rejected by the pipe mode itself.
#[derive(Debug)]
pub struct NamedPipeServer {
    handle: HANDLE,
}

// The HANDLE is uniquely owned by this wrapper and Windows permits pipe I/O from another thread.
unsafe impl Send for NamedPipeServer {}

impl NamedPipeServer {
    pub fn create(name: &str) -> Result<Self, PipeError> {
        let full_name = normalize_pipe_name(name);
        let wide_name = wide_null(OsStr::new(&full_name));

        // A NULL DACL lets the interactive Worker open the Service-created pipe regardless of the
        // user's SID. This is NOT the authorization boundary: after connection we require the exact
        // process id and session id of the Worker the Service launched. Remote clients are disabled.
        // A future hardening step can replace this with a per-user SID DACL without changing the
        // peer-binding model.
        // SAFETY: SECURITY_DESCRIPTOR is POD and then initialized by the Win32 API.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
        // SAFETY: `descriptor` is valid writable storage for a security descriptor.
        if unsafe {
            InitializeSecurityDescriptor(
                &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut _,
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(last_error("InitializeSecurityDescriptor"));
        }
        // SAFETY: initialized descriptor is valid; a present NULL DACL grants access and is paired
        // with strict local PID/session binding after connection.
        if unsafe {
            SetSecurityDescriptorDacl(
                &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut _,
                1,
                null_mut(),
                0,
            )
        } == 0
        {
            return Err(last_error("SetSecurityDescriptorDacl"));
        }

        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut _,
            bInheritHandle: 0,
        };

        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: the UTF-16 name is NUL-terminated, security attributes live through the call, and
        // no output pointers are used.
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                pipe_mode,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                PIPE_DEFAULT_TIMEOUT_MS,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateNamedPipeW"));
        }
        Ok(Self { handle })
    }

    /// Waits for the exact Worker process launched by the Service. Unexpected local clients are
    /// disconnected and cannot become an authenticated IPC peer.
    pub fn accept_expected(
        &mut self,
        expected_process_id: u32,
        expected_session_id: u32,
    ) -> Result<PipePeer, PipeError> {
        for _ in 0..MAX_REJECTED_PEERS {
            self.connect_one()?;
            let peer = self.peer()?;
            if peer.process_id == expected_process_id && peer.session_id == expected_session_id {
                return Ok(peer);
            }
            self.disconnect()?;
        }
        Err(PipeError {
            stage: "NamedPipePeerValidation",
            win32_error: 5, // ERROR_ACCESS_DENIED
        })
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, PipeError> {
        read_handle(self.handle, buffer)
    }

    pub fn write_all(&self, mut bytes: &[u8]) -> Result<(), PipeError> {
        while !bytes.is_empty() {
            let written = write_handle(self.handle, bytes)?;
            if written == 0 {
                return Err(PipeError {
                    stage: "WriteFileZeroProgress",
                    win32_error: 0,
                });
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), PipeError> {
        // SAFETY: this is the server handle created by CreateNamedPipeW.
        if unsafe { DisconnectNamedPipe(self.handle) } == 0 {
            let error = unsafe { GetLastError() };
            // ERROR_PIPE_NOT_CONNECTED is harmless when teardown races with peer exit.
            if error != 233 {
                return Err(PipeError {
                    stage: "DisconnectNamedPipe",
                    win32_error: error,
                });
            }
        }
        Ok(())
    }

    fn connect_one(&self) -> Result<(), PipeError> {
        // SAFETY: valid server pipe handle; synchronous connect uses a NULL OVERLAPPED pointer.
        if unsafe { ConnectNamedPipe(self.handle, null_mut()) } != 0 {
            return Ok(());
        }
        // A client may connect after CreateNamedPipeW but before ConnectNamedPipe; Windows reports
        // ERROR_PIPE_CONNECTED in that race and the connection is valid.
        let error = unsafe { GetLastError() };
        if error == ERROR_PIPE_CONNECTED {
            Ok(())
        } else {
            Err(PipeError {
                stage: "ConnectNamedPipe",
                win32_error: error,
            })
        }
    }

    fn peer(&self) -> Result<PipePeer, PipeError> {
        let mut process_id = 0_u32;
        let mut session_id = 0_u32;
        // SAFETY: both output pointers are valid for one u32 and the handle is connected.
        if unsafe { GetNamedPipeClientProcessId(self.handle, &mut process_id) } == 0 {
            return Err(last_error("GetNamedPipeClientProcessId"));
        }
        // SAFETY: same conditions as process-id query.
        if unsafe { GetNamedPipeClientSessionId(self.handle, &mut session_id) } == 0 {
            return Err(last_error("GetNamedPipeClientSessionId"));
        }
        Ok(PipePeer {
            process_id,
            session_id,
        })
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
            // SAFETY: uniquely owned kernel HANDLE.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

#[derive(Debug)]
pub struct NamedPipeClient {
    handle: HANDLE,
}

unsafe impl Send for NamedPipeClient {}

impl NamedPipeClient {
    pub fn connect(name: &str, timeout: Duration) -> Result<Self, PipeError> {
        let full_name = normalize_pipe_name(name);
        let wide_name = wide_null(OsStr::new(&full_name));
        let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);

        loop {
            // SAFETY: path is valid NUL-terminated UTF-16; remaining optional pointers are NULL.
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                return Ok(Self { handle });
            }

            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND {
                return Err(PipeError {
                    stage: "CreateFileW(pipe)",
                    win32_error: error,
                });
            }
            if Instant::now() >= deadline {
                return Err(PipeError {
                    stage: "NamedPipeConnectTimeout",
                    win32_error: error,
                });
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, PipeError> {
        read_handle(self.handle, buffer)
    }

    pub fn write_all(&self, mut bytes: &[u8]) -> Result<(), PipeError> {
        while !bytes.is_empty() {
            let written = write_handle(self.handle, bytes)?;
            if written == 0 {
                return Err(PipeError {
                    stage: "WriteFileZeroProgress",
                    win32_error: 0,
                });
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }
}

impl Drop for NamedPipeClient {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
            // SAFETY: uniquely owned kernel HANDLE.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

#[must_use]
pub fn worker_pipe_name(service_process_id: u32, session_id: u32, generation: u64) -> String {
    format!("ClassMesh-{service_process_id:08x}-{session_id:08x}-{generation:016x}")
}

fn normalize_pipe_name(name: &str) -> String {
    if name.starts_with(r"\\.\pipe\") {
        name.to_owned()
    } else {
        format!(r"\\.\pipe\{name}")
    }
}

fn read_handle(handle: HANDLE, buffer: &mut [u8]) -> Result<usize, PipeError> {
    let to_read = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let mut read = 0_u32;
    // SAFETY: valid pipe handle, writable buffer of at least `to_read` bytes and valid count output.
    if unsafe { ReadFile(handle, buffer.as_mut_ptr(), to_read, &mut read, null_mut()) } == 0 {
        return Err(last_error("ReadFile(pipe)"));
    }
    Ok(read as usize)
}

fn write_handle(handle: HANDLE, bytes: &[u8]) -> Result<usize, PipeError> {
    let to_write = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let mut written = 0_u32;
    // SAFETY: valid pipe handle, readable buffer of at least `to_write` bytes and valid count output.
    if unsafe { WriteFile(handle, bytes.as_ptr(), to_write, &mut written, null_mut()) } == 0 {
        return Err(last_error("WriteFile(pipe)"));
    }
    Ok(written as usize)
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(stage: &'static str) -> PipeError {
    // SAFETY: GetLastError has no preconditions and is read directly after a failing Win32 call.
    PipeError {
        stage,
        win32_error: unsafe { GetLastError() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_stable_and_local() {
        let name = worker_pipe_name(0x1234, 7, 9);
        assert_eq!(name, "ClassMesh-00001234-00000007-0000000000000009");
        assert!(normalize_pipe_name(&name).starts_with(r"\\.\pipe\ClassMesh-"));
    }
}
