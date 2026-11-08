//! Unchanged-current-token measurement. No token creation/switch/impersonation,
//! privilege adjustment, SCM mutation, handle transfer or authentication result.

use super::{CallerContext, ProcessObject};
use serde::Serialize;
use std::io;
use std::mem::{offset_of, size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_NO_TOKEN, FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, LUID, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use windows_sys::Win32::System::Threading::*;

pub const PROCESS_OBSERVE_RIGHTS: u32 = 0x0010_1000;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() {
        Err(io::Error::last_os_error())
    }
    // SAFETY: callers pass a newly returned successful native HANDLE.
    else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}

struct TokenData {
    class: TOKEN_INFORMATION_CLASS,
    words: Vec<usize>,
    used: usize,
}
impl TokenData {
    fn get(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Self> {
        let mut size = 0;
        unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut size) };
        if size == 0 || size > 65536 {
            return Err(invalid("unavailable or oversized token information"));
        }
        let mut words = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        let capacity = size;
        if unsafe {
            GetTokenInformation(token, class, words.as_mut_ptr().cast(), capacity, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if size == 0 || size > capacity {
            return Err(invalid("token buffer size changed"));
        }
        Ok(Self {
            class,
            words,
            used: size as usize,
        })
    }
    fn value<T: Copy>(&self, offset: usize) -> io::Result<T> {
        if offset
            .checked_add(size_of::<T>())
            .is_none_or(|end| end > self.used)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "truncated token value: class {}, offset {offset}, expected {} bytes, returned {}",
                    self.class,
                    size_of::<T>(),
                    self.used
                ),
            ));
        }
        Ok(unsafe {
            std::ptr::read_unaligned(self.words.as_ptr().cast::<u8>().add(offset).cast::<T>())
        })
    }
    fn sid_string(&self, sid: PSID) -> io::Result<String> {
        let start = self.words.as_ptr() as usize;
        let address = sid as usize;
        if address < start
            || address % 4 != 0
            || address
                .checked_add(8)
                .is_none_or(|end| end > start + self.used)
        {
            return Err(invalid("token SID outside original buffer"));
        }
        let count = unsafe { *((address + 1) as *const u8) } as usize;
        if count > 15
            || address + 8 + 4 * count > start + self.used
            || unsafe { IsValidSid(sid) } == 0
        {
            return Err(invalid("invalid token SID"));
        }
        let mut raw = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SID syntax has at most 15 subauthorities; output is OS-allocated and
        // NUL terminated. Free it on both success and bounded syntax failure.
        let result = (|| {
            let mut len = 0;
            while len < 192 && unsafe { *raw.add(len) } != 0 {
                len += 1;
            }
            if len == 192 {
                return Err(invalid("SID string exceeds bound"));
            }
            String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
                .map_err(|_| invalid("SID encoding"))
        })();
        unsafe { LocalFree(raw.cast()) };
        result
    }
}

fn token_for_process(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    owned(raw)
}
fn scalar(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
    // Only documented DWORD/TOKEN_TYPE/elevation representations.
    // TokenIsRestricted is RESERVED, not a supported DWORD query.
    if ![
        TokenType,
        TokenElevation,
        TokenElevationType,
        TokenHasRestrictions,
        TokenIsAppContainer,
        TokenSessionId,
        TokenUIAccess,
    ]
    .contains(&class)
    {
        return Err(invalid("unsupported scalar token information class"));
    }
    TokenData::get(token, class)?.value(0)
}
fn luid(luid: LUID) -> u64 {
    (u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallerAudit {
    pub pid: u32,
    pub user_sid: String,
    pub context: CallerContext,
    pub token_id: u64,
    pub token_modified_id: u64,
    pub enabled_standard_privileges: Vec<String>,
}

pub fn audit_current_caller() -> io::Result<CallerAudit> {
    let mut thread_token = null_mut();
    let impersonating =
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) } != 0 {
            drop(owned(thread_token)?);
            true
        } else if io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
            false
        } else {
            return Err(io::Error::last_os_error());
        };
    let token = token_for_process(unsafe { GetCurrentProcess() })?;
    let raw = token.as_raw_handle();
    let before = TokenData::get(raw, TokenStatistics)?.value::<TOKEN_STATISTICS>(0)?;
    if scalar(raw, TokenType)? != TokenPrimary as u32 {
        return Err(invalid("caller token is not primary"));
    }
    let user = TokenData::get(raw, TokenUser)?;
    let user_sid = user.sid_string(user.value::<TOKEN_USER>(0)?.User.Sid)?;
    let groups = TokenData::get(raw, TokenGroups)?;
    let count: u32 = groups.value(0)?;
    if count as usize
        > groups.used.saturating_sub(offset_of!(TOKEN_GROUPS, Groups))
            / size_of::<SID_AND_ATTRIBUTES>()
    {
        return Err(invalid("group count exceeds original buffer"));
    }
    let mut admin_sid_present = false;
    let mut effective_admin = false;
    for index in 0..count as usize {
        let item: SID_AND_ATTRIBUTES = groups
            .value(offset_of!(TOKEN_GROUPS, Groups) + index * size_of::<SID_AND_ATTRIBUTES>())?;
        let sid = groups.sid_string(item.Sid)?;
        if sid == "S-1-5-32-544" {
            admin_sid_present = true;
            effective_admin |= item.Attributes & SE_GROUP_ENABLED as u32 != 0
                && item.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0;
        }
    }
    let label = TokenData::get(raw, TokenIntegrityLevel)?;
    let integrity_sid = label.sid_string(label.value::<TOKEN_MANDATORY_LABEL>(0)?.Label.Sid)?;
    let integrity = integrity_sid
        .strip_prefix("S-1-16-")
        .and_then(|rid| rid.parse().ok())
        .ok_or_else(|| invalid("integrity SID"))?;
    let privileges = TokenData::get(raw, TokenPrivileges)?;
    let count: u32 = privileges.value(0)?;
    if count as usize
        > privileges
            .used
            .saturating_sub(offset_of!(TOKEN_PRIVILEGES, Privileges))
            / size_of::<LUID_AND_ATTRIBUTES>()
    {
        return Err(invalid("privilege count exceeds original buffer"));
    }
    let names = [
        "SeChangeNotifyPrivilege",
        "SeShutdownPrivilege",
        "SeUndockPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeTimeZonePrivilege",
        "SeDebugPrivilege",
    ];
    let mut known = Vec::new();
    for name in names {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut value: LUID = unsafe { zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), wide.as_ptr(), &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        known.push((luid(value), name));
    }
    let mut debug_present = false;
    let mut unexpected_privileges = false;
    let mut enabled_standard_privileges = Vec::new();
    for index in 0..count as usize {
        let item: LUID_AND_ATTRIBUTES = privileges.value(
            offset_of!(TOKEN_PRIVILEGES, Privileges) + index * size_of::<LUID_AND_ATTRIBUTES>(),
        )?;
        let name = known
            .iter()
            .find(|(id, _)| *id == luid(item.Luid))
            .map(|(_, name)| *name);
        match name {
            Some("SeDebugPrivilege") => {
                debug_present = true;
                unexpected_privileges = true;
            }
            Some(name) => {
                if item.Attributes & SE_PRIVILEGE_ENABLED != 0 {
                    enabled_standard_privileges.push(name.to_string());
                }
            }
            None => unexpected_privileges = true,
        }
    }
    let context = CallerContext {
        elevated: scalar(raw, TokenElevation)? != 0,
        elevation_type: scalar(raw, TokenElevationType)?,
        admin_sid_present,
        effective_admin,
        service_account: matches!(user_sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20"),
        debug_present,
        unexpected_privileges,
        restricted: scalar(raw, TokenHasRestrictions)? != 0
            || TokenData::get(raw, TokenRestrictedSids)?.value::<u32>(0)? != 0,
        app_container: scalar(raw, TokenIsAppContainer)? != 0,
        impersonating,
        integrity,
        session: scalar(raw, TokenSessionId)?,
        ui_access: scalar(raw, TokenUIAccess)? != 0,
    };
    let stats = TokenData::get(raw, TokenStatistics)?.value::<TOKEN_STATISTICS>(0)?;
    if luid(before.TokenId) != luid(stats.TokenId)
        || luid(before.ModifiedId) != luid(stats.ModifiedId)
    {
        return Err(invalid("caller token changed while auditing"));
    }
    Ok(CallerAudit {
        pid: std::process::id(),
        context,
        user_sid,
        token_id: luid(stats.TokenId),
        token_modified_id: luid(stats.ModifiedId),
        enabled_standard_privileges,
    })
}

#[derive(Debug, Serialize)]
pub struct TargetObservation {
    pub service_name: &'static str,
    pub scm_pid: u32,
    pub requested_access: u32,
    pub open_error: Option<i32>,
    pub object: Option<ProcessObject>,
    pub actual_access: Option<u32>,
    pub inheritable: Option<bool>,
    pub session: Option<u32>,
    pub actual_account_sid: Option<String>,
    pub token_query_error: Option<i32>,
    pub current_system_account: Option<bool>,
    pub loaded_signed_image: &'static str,
}

#[derive(Debug, Serialize)]
pub struct EvidenceReport {
    pub schema: u32,
    pub outcome: &'static str,
    pub reason: Option<String>,
    pub caller: Option<CallerAudit>,
    pub target: Option<TargetObservation>,
    pub authenticated_service_worker: bool,
}

fn collect_with(
    mut caller: impl FnMut() -> io::Result<CallerAudit>,
    target: impl FnOnce() -> io::Result<TargetObservation>,
) -> EvidenceReport {
    let mut result = EvidenceReport {
        schema: 1,
        outcome: "NOT_MEASURED_CALLER_CONTEXT",
        reason: None,
        caller: None,
        target: None,
        authenticated_service_worker: false,
    };
    let audit = match caller() {
        Ok(audit) => audit,
        Err(e) => {
            result.reason = Some(e.to_string());
            return result;
        }
    };
    let refusal = audit.context.refusal();
    result.caller = Some(audit.clone());
    if let Some(reason) = refusal {
        result.reason = Some(reason.to_string());
        return result;
    }
    match target() {
        Ok(target) => {
            result.outcome = if target.open_error.is_some() {
                "PROCESS_ACCESS_DENIED_OR_UNAVAILABLE"
            } else {
                "PROCESS_ACCESS_OBSERVED_NOT_AUTHENTICATED"
            };
            result.target = Some(target);
        }
        Err(e) => {
            result.outcome = "MEASUREMENT_ERROR";
            result.reason = Some(e.to_string());
        }
    }
    match caller() {
        Ok(after) if after == audit => (),
        _ => {
            result.outcome = "INVALIDATED_CALLER_CONTEXT_CHANGED";
            result.reason = Some("caller token changed or recheck failed".into());
        }
    }
    result
}

struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn fixed_service_pid() -> io::Result<u32> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ScHandle(manager);
    let name: Vec<u16> = "DcomLaunch\0".encode_utf16().collect();
    let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ScHandle(raw);
    let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err(invalid("fixed existing service not running"));
    }
    Ok(status.dwProcessId)
}

fn process_object(raw: HANDLE) -> io::Result<ProcessObject> {
    let pid = unsafe { GetProcessId(raw) };
    let (mut creation, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    if pid == 0
        || unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessObject {
        pid,
        created: (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
    })
}
fn alive(raw: HANDLE) -> io::Result<bool> {
    match unsafe { WaitForSingleObject(raw, 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}
fn granted_access(raw: HANDLE) -> io::Result<u32> {
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
            h: HANDLE,
            class: i32,
            data: *mut std::ffi::c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut data: Basic = unsafe { zeroed() };
    let mut returned = 0;
    let status = unsafe {
        NtQueryObject(
            raw,
            0,
            (&mut data as *mut Basic).cast(),
            size_of::<Basic>() as u32,
            &mut returned,
        )
    };
    if status < 0 || returned as usize != size_of::<Basic>() {
        return Err(invalid("granted access unavailable"));
    }
    Ok(data.access)
}

fn observe_fixed_target() -> io::Result<TargetObservation> {
    let pid = fixed_service_pid()?;
    let mut result = TargetObservation {
        service_name: "DcomLaunch",
        scm_pid: pid,
        requested_access: PROCESS_OBSERVE_RIGHTS,
        open_error: None,
        object: None,
        actual_access: None,
        inheritable: None,
        session: None,
        actual_account_sid: None,
        token_query_error: None,
        current_system_account: None,
        loaded_signed_image: "UNVERIFIED",
    };
    let raw = unsafe { OpenProcess(PROCESS_OBSERVE_RIGHTS, 0, pid) };
    if raw.is_null() {
        result.open_error = io::Error::last_os_error().raw_os_error();
        return Ok(result);
    }
    let process = owned(raw)?;
    let object = process_object(process.as_raw_handle())?;
    let access = granted_access(process.as_raw_handle())?;
    let mut flags = 0;
    let mut session = 0;
    if unsafe { GetHandleInformation(process.as_raw_handle(), &mut flags) } == 0
        || unsafe { ProcessIdToSessionId(object.pid, &mut session) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if access != PROCESS_OBSERVE_RIGHTS || flags & HANDLE_FLAG_INHERIT != 0 || object.pid != pid {
        return Err(invalid("unexpected process rights/identity"));
    }
    result.object = Some(object);
    result.actual_access = Some(access);
    result.inheritable = Some(false);
    result.session = Some(session);
    // Optional independent CURRENT account observation from this exact kernel
    // process object, never from SCM config or Service-supplied metadata.
    match token_for_process(process.as_raw_handle()) {
        Ok(token) => {
            let user = TokenData::get(token.as_raw_handle(), TokenUser)?;
            let sid = user.sid_string(user.value::<TOKEN_USER>(0)?.User.Sid)?;
            result.current_system_account = Some(sid == "S-1-5-18");
            result.actual_account_sid = Some(sid);
        }
        Err(e) => result.token_query_error = e.raw_os_error(),
    }
    // Slow work precedes the final retained-object liveness check. No reopen.
    if fixed_service_pid()? != pid {
        return Err(invalid("SCM process changed"));
    }
    object
        .require_same_live(
            process_object(process.as_raw_handle())?,
            alive(process.as_raw_handle())?,
        )
        .map_err(invalid)?;
    Ok(result)
}

pub fn measure_current_context() -> EvidenceReport {
    collect_with(audit_current_caller, observe_fixed_target)
}

#[cfg(test)]
mod tests;
