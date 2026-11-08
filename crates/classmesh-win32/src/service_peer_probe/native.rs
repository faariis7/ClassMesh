//! Read-only native observations; no authenticated Service identity is issued.

use super::{ProcessIdentity, READ_ONLY_PROCESS_RIGHTS};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::null;
use windows_sys::Win32::Foundation::{
    FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, GetNamedPipeServerSessionId};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
};

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

/// Kernel observation from an ALREADY owned fixture connection. This function
/// never connects to a live product pipe, reads bytes or accepts a claimed PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeObservation {
    pub pid: u32,
    pub session: u32,
}

pub fn observe_pipe_server(pipe: BorrowedHandle<'_>) -> io::Result<PipeObservation> {
    let (mut pid, mut session) = (0, 0);
    // SAFETY: borrowed handle lives throughout both calls; scalar outputs valid.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe.as_raw_handle(), &mut session) } == 0
        || pid == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(PipeObservation { pid, session })
}

/// Original retained process object. This is an observation, NEVER an
/// authenticated principal and never accepted by Service/Worker authentication.
#[derive(Debug)]
pub struct ObservedProcess {
    handle: OwnedHandle,
    identity: ProcessIdentity,
}

impl ObservedProcess {
    /// Independent acquisition. An OS denial is terminal; no delegated fallback.
    pub fn open(pid: u32) -> io::Result<Self> {
        if pid == 0 {
            return Err(denied("zero process identity"));
        }
        // SAFETY: requests only query/synchronize, not an inherited handle.
        let raw = unsafe { OpenProcess(READ_ONLY_PROCESS_RIGHTS, 0, pid) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcess transfers one owned handle.
        let process = Self::from_readonly_handle(unsafe { OwnedHandle::from_raw_handle(raw) })?;
        if process.identity.pid != pid {
            return Err(denied("process identity changed"));
        }
        Ok(process)
    }

    // Private: no remote integer-to-owned-handle API is exposed.
    fn from_readonly_handle(handle: OwnedHandle) -> io::Result<Self> {
        let raw = handle.as_raw_handle();
        let pid = unsafe { GetProcessId(raw) };
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        let (mut created, mut exited, mut kernel, mut user): (
            FILETIME,
            FILETIME,
            FILETIME,
            FILETIME,
        ) = unsafe { zeroed() };
        if unsafe { GetProcessTimes(raw, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let identity = ProcessIdentity {
            pid,
            created: (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
        };
        let process = Self { handle, identity };
        if process.granted_access()? != READ_ONLY_PROCESS_RIGHTS
            || process.inheritable()?
            || !process.is_alive()?
        {
            return Err(denied(
                "not a live noninheritable minimum-right process object",
            ));
        }
        Ok(process)
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    pub fn is_alive(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn inheritable(&self) -> io::Result<bool> {
        let mut flags = 0;
        if unsafe { GetHandleInformation(self.handle.as_raw_handle(), &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags & HANDLE_FLAG_INHERIT != 0)
    }

    pub fn granted_access(&self) -> io::Result<u32> {
        // Documented PUBLIC_OBJECT_BASIC_INFORMATION; reserved fields retained
        // exactly for ABI size. No object names/handles are enumerated.
        #[repr(C)]
        struct Basic {
            attributes: u32,
            access: u32,
            handles: u32,
            pointers: u32,
            reserved: [u32; 10],
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(
                handle: HANDLE,
                class: i32,
                output: *mut std::ffi::c_void,
                size: u32,
                returned: *mut u32,
            ) -> i32;
        }
        let mut info: Basic = unsafe { zeroed() };
        let mut returned = 0;
        // SAFETY: live process HANDLE, aligned ABI output, ObjectBasicInformation.
        let status = unsafe {
            NtQueryObject(
                self.handle.as_raw_handle(),
                0,
                (&mut info as *mut Basic).cast(),
                size_of::<Basic>() as u32,
                &mut returned,
            )
        };
        if status < 0 || returned as usize != size_of::<Basic>() {
            return Err(denied("cannot establish actual granted process mask"));
        }
        Ok(info.access)
    }

    pub fn image_path(&self) -> io::Result<PathBuf> {
        let mut buffer = vec![0u16; 32768];
        let mut len = buffer.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(
                self.handle.as_raw_handle(),
                0,
                buffer.as_mut_ptr(),
                &mut len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if len == 0 || len as usize >= buffer.len() {
            return Err(denied("invalid process image length"));
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmObservation {
    pub pid: u32,
    pub state: u32,
    pub service_type: u32,
    pub binary_command: OsString,
    pub account: OsString,
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct ServiceReader {
    _manager: ServiceHandle,
    service: ServiceHandle,
}

impl ServiceReader {
    fn open(name: &str) -> io::Result<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // Local machine only, minimum read/query rights. No mutation APIs.
        let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(io::Error::last_os_error());
        }
        let manager = ServiceHandle(manager);
        let service = unsafe {
            OpenServiceW(
                manager.0,
                wide.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
            )
        };
        if service.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _manager: manager,
            service: ServiceHandle(service),
        })
    }

    fn observe(&self) -> io::Result<ScmObservation> {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                self.service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // QueryServiceConfigW maximum documented buffer = 8KiB. usize provides
        // alignment for the struct; pointer strings are bounded inside it.
        let mut buffer = vec![0usize; 8192 / size_of::<usize>()];
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if unsafe { QueryServiceConfigW(self.service.0, config, 8192, &mut needed) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let config = unsafe { &*config };
        fn string(buffer: &[usize], ptr: *const u16) -> io::Result<OsString> {
            let start = buffer.as_ptr() as usize;
            let end = start + size_of_val(buffer);
            let p = ptr as usize;
            if p < start || p >= end || p % 2 != 0 {
                return Err(denied("invalid SCM string pointer"));
            }
            // SAFETY: range/alignment checked against the live buffer; bounded
            // search never follows an SCM pointer outside the allocation.
            let chars = unsafe { std::slice::from_raw_parts(ptr, (end - p) / 2) };
            let len = chars
                .iter()
                .position(|c| *c == 0)
                .ok_or_else(|| denied("unterminated SCM string"))?;
            Ok(OsString::from_wide(&chars[..len]))
        }
        if config.dwServiceType != status.dwServiceType {
            return Err(denied("SCM type changed during query"));
        }
        Ok(ScmObservation {
            pid: status.dwProcessId,
            state: status.dwCurrentState,
            service_type: config.dwServiceType,
            binary_command: string(&buffer, config.lpBinaryPathName)?,
            account: string(&buffer, config.lpServiceStartName)?,
        })
    }
}

/// Fixed product SCM name, local read-only access. Absence/access denial is error.
pub fn observe_classmesh_scm() -> io::Result<ScmObservation> {
    ServiceReader::open("ClassMeshService")?.observe()
}

/// A retained lab file/digest comparison, NOT signed/protected artifact trust.
#[derive(Debug)]
pub struct ImageSample {
    file: File,
    hash: [u8; 32],
}

impl ImageSample {
    pub fn open(path: &Path) -> io::Result<Self> {
        // Operator-owned ordinary local fixture names only. This syntactic
        // restriction is not a protected ancestry/path identity attestation.
        let s = path
            .to_str()
            .ok_or_else(|| denied("non-Unicode lab sample path"))?;
        let bytes = s.as_bytes();
        if bytes.len() < 4
            || !bytes[0].is_ascii_alphabetic()
            || &bytes[1..3] != b":\\"
            || s[3..].split('\\').any(|part| {
                let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.ends_with(['.', ' '])
                    || part.contains([':', '/', '\0', '"'])
                    || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.len() == 4
                        && stem.as_bytes()[3].is_ascii_digit())
            })
        {
            return Err(denied("not an ordinary absolute local lab sample path"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied("image sample is not a regular file"));
        }
        let hash = Self::digest(&mut file)?;
        Ok(Self { file, hash })
    }

    fn digest(file: &mut File) -> io::Result<[u8; 32]> {
        const MAX: u64 = 128 * 1024 * 1024;
        if file.metadata()?.len() > MAX {
            return Err(denied("image sample exceeds bound"));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut input = file.take(MAX + 1);
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut total = 0;
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX {
                return Err(denied("image sample grew beyond bound"));
            }
            hash.update(&buffer[..n]);
        }
        Ok(hash.finalize().into())
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.hash
    }

    pub fn recheck(&mut self) -> io::Result<()> {
        if Self::digest(&mut self.file)? != self.hash {
            return Err(denied("image sample changed"));
        }
        Ok(())
    }
}

/// Unqualified observations only. Retains the original independently acquired
/// process and sampled file; borrowing the caller's pipe prevents its reuse.
/// This is NOT an authenticated lease or evidence of a signed running image.
pub struct UnqualifiedObservation<'a> {
    pipe: BorrowedHandle<'a>,
    reader: ServiceReader,
    process: ObservedProcess,
    image: ImageSample,
    scm: ScmObservation,
    path: PathBuf,
    invalidated: bool,
}

pub fn observe_candidate<'a>(
    pipe: BorrowedHandle<'a>,
    lab_image: &Path,
    lab_sha256: [u8; 32],
) -> io::Result<UnqualifiedObservation<'a>> {
    let reader = ServiceReader::open("ClassMeshService")?;
    let scm = reader.observe()?;
    let peer = observe_pipe_server(pipe)?;
    if scm.pid == 0
        || scm.pid != peer.pid
        || peer.session != 0
        || scm.state != SERVICE_RUNNING
        || scm.service_type != SERVICE_WIN32_OWN_PROCESS
        || !scm
            .account
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("LocalSystem"))
    {
        return Err(denied("SCM and kernel pipe observations do not match"));
    }
    // A quoted absolute no-arguments lab path only. No shell parsing or claim
    // that this matches the protected installed image/loaded image section.
    let path = lab_image.to_path_buf();
    if !path.is_absolute()
        || scm.binary_command != OsString::from(format!("\"{}\"", path.display()))
    {
        return Err(denied("ambiguous or different registered image command"));
    }
    let process = ObservedProcess::open(peer.pid)?;
    if process.image_path()? != path {
        return Err(denied("running image path differs from lab sample"));
    }
    let image = ImageSample::open(&path)?;
    if image.sha256() != lab_sha256 {
        return Err(denied("lab image hash mismatch"));
    }
    let mut observation = UnqualifiedObservation {
        pipe,
        reader,
        process,
        image,
        scm,
        path,
        invalidated: false,
    };
    observation.recheck()?;
    Ok(observation)
}

impl UnqualifiedObservation<'_> {
    pub fn process_identity(&self) -> ProcessIdentity {
        self.process.identity()
    }

    /// Rechecks only these unqualified observations. NEVER upgrades to trust.
    pub fn recheck(&mut self) -> io::Result<()> {
        if self.invalidated {
            return Err(denied("candidate observation was invalidated"));
        }
        let result = self.check_observations();
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    fn check_observations(&mut self) -> io::Result<()> {
        let peer = observe_pipe_server(self.pipe)?;
        if self.reader.observe()? != self.scm
            || peer.pid != self.process.identity.pid
            || peer.session != 0
            || !self.process.is_alive()?
            || self.process.image_path()? != self.path
        {
            return Err(denied("candidate observations changed"));
        }
        self.image.recheck()
    }
}

#[cfg(test)]
fn same_account(a: BorrowedHandle<'_>, b: BorrowedHandle<'_>) -> io::Result<bool> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    fn sid(process: BorrowedHandle<'_>) -> io::Result<Vec<usize>> {
        let mut raw = null_mut();
        if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut size = 0;
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
        if size < size_of::<TOKEN_USER>() as u32 || size > 65536 {
            return Err(denied("invalid token SID size"));
        }
        let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                data.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(data)
    }
    let (a, b) = (sid(a)?, sid(b)?);
    let a = unsafe { &*a.as_ptr().cast::<TOKEN_USER>() };
    let b = unsafe { &*b.as_ptr().cast::<TOKEN_USER>() };
    Ok(unsafe { EqualSid(a.User.Sid, b.User.Sid) } != 0)
}

#[cfg(test)]
mod tests;
