use std::fmt::{Display, Formatter};
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Shutdown::{
    InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_APPLICATION,
    SHTDN_REASON_MINOR_MAINTENANCE, SHUTDOWN_REASON,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const CLASSMESH_POWER_REASON: SHUTDOWN_REASON =
    SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_MAINTENANCE | SHTDN_REASON_FLAG_PLANNED;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPowerAction {
    Restart,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPowerRequestOutcome {
    /// Windows accepted the asynchronous restart/shutdown request and the
    /// temporary shutdown privilege was restored before returning.
    Accepted,
    /// Windows accepted the asynchronous request, but restoring the process
    /// token's previous privilege state failed. The request may still execute,
    /// so callers must not report this as a rejected power action.
    AcceptedPrivilegeRestoreFailed,
}

/// Narrow boundary for destructive local-machine power actions.
///
/// Production uses `Win32SystemPowerController`; hosted tests should inject a
/// recording implementation and must never call the real backend.
pub trait SystemPowerController {
    fn request(
        &mut self,
        action: SystemPowerAction,
    ) -> Result<SystemPowerRequestOutcome, SystemPowerError>;
}

#[derive(Debug, Default)]
pub struct Win32SystemPowerController;

impl SystemPowerController for Win32SystemPowerController {
    fn request(
        &mut self,
        action: SystemPowerAction,
    ) -> Result<SystemPowerRequestOutcome, SystemPowerError> {
        request_system_power(action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemPowerStage {
    OpenProcessToken,
    LookupShutdownPrivilege,
    EnableShutdownPrivilege,
    RequestRejected,
    RestoreShutdownPrivilege,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPowerError {
    stage: SystemPowerStage,
}

impl SystemPowerError {
    const fn at(stage: SystemPowerStage) -> Self {
        Self { stage }
    }

    #[must_use]
    pub const fn diagnostic_code(self) -> &'static str {
        match self.stage {
            SystemPowerStage::OpenProcessToken => "system_power.open_token_failed",
            SystemPowerStage::LookupShutdownPrivilege => {
                "system_power.lookup_shutdown_privilege_failed"
            }
            SystemPowerStage::EnableShutdownPrivilege => {
                "system_power.enable_shutdown_privilege_failed"
            }
            SystemPowerStage::RequestRejected => "system_power.request_rejected",
            SystemPowerStage::RestoreShutdownPrivilege => {
                "system_power.restore_shutdown_privilege_failed"
            }
        }
    }
}

impl Display for SystemPowerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for SystemPowerError {}

fn request_system_power(
    action: SystemPowerAction,
) -> Result<SystemPowerRequestOutcome, SystemPowerError> {
    let mut privilege = ShutdownPrivilegeGuard::enable()?;
    let reboot_after_shutdown = reboot_after_shutdown(action);

    // SAFETY: both optional string pointers are null for a local-machine request,
    // all scalar arguments are valid, and the scoped guard above enabled the
    // local shutdown privilege. We intentionally do not force applications
    // closed so unsaved interactive work is not discarded by this boundary.
    let accepted = unsafe {
        InitiateSystemShutdownExW(
            null(),
            null(),
            0,
            0,
            reboot_after_shutdown,
            CLASSMESH_POWER_REASON,
        )
    };
    let restored = privilege.restore();
    finish_power_request(accepted != 0, restored)
}

fn finish_power_request(
    accepted: bool,
    restored: Result<(), SystemPowerError>,
) -> Result<SystemPowerRequestOutcome, SystemPowerError> {
    match (accepted, restored) {
        (true, Ok(())) => Ok(SystemPowerRequestOutcome::Accepted),
        (true, Err(_)) => Ok(SystemPowerRequestOutcome::AcceptedPrivilegeRestoreFailed),
        (false, Ok(())) => Err(SystemPowerError::at(SystemPowerStage::RequestRejected)),
        // Cleanup failure takes precedence when Windows rejected the request:
        // leaving SE_SHUTDOWN_NAME enabled is the more security-relevant state.
        (false, Err(error)) => Err(error),
    }
}

const fn reboot_after_shutdown(action: SystemPowerAction) -> i32 {
    match action {
        SystemPowerAction::Restart => 1,
        SystemPowerAction::Shutdown => 0,
    }
}

struct ShutdownPrivilegeGuard {
    token: TokenHandle,
    previous: TOKEN_PRIVILEGES,
    restore_pending: bool,
}

impl ShutdownPrivilegeGuard {
    fn enable() -> Result<Self, SystemPowerError> {
        let mut raw_token: HANDLE = null_mut();

        // SAFETY: GetCurrentProcess returns the current-process pseudo handle and
        // raw_token points to valid writable storage for the returned token handle.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw_token,
            )
        } == 0
        {
            return Err(SystemPowerError::at(SystemPowerStage::OpenProcessToken));
        }
        let token = TokenHandle(raw_token);

        // SAFETY: LUID is plain data and zero is a valid initialization before
        // LookupPrivilegeValueW overwrites it.
        let mut luid: LUID = unsafe { zeroed() };
        // SAFETY: null selects the local system, SE_SHUTDOWN_NAME is a valid
        // NUL-terminated Windows constant, and luid is writable.
        if unsafe { LookupPrivilegeValueW(null(), SE_SHUTDOWN_NAME, &mut luid) } == 0 {
            return Err(SystemPowerError::at(
                SystemPowerStage::LookupShutdownPrivilege,
            ));
        }

        let desired = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: TOKEN_PRIVILEGES is plain data and Windows will overwrite the
        // previous state for the single privilege requested above.
        let mut previous: TOKEN_PRIVILEGES = unsafe { zeroed() };
        let mut previous_len = 0_u32;

        // SAFETY: token is an owned process-token handle with adjust/query rights;
        // desired and previous both point to valid TOKEN_PRIVILEGES storage.
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &desired,
                u32::try_from(size_of::<TOKEN_PRIVILEGES>())
                    .expect("TOKEN_PRIVILEGES size fits u32"),
                &mut previous,
                &mut previous_len,
            )
        };
        // AdjustTokenPrivileges may return non-zero even when the requested
        // privilege was not present. Microsoft documents GetLastError as the
        // authoritative signal for that case, so both signals are required.
        // SAFETY: GetLastError has no preconditions and is read immediately after
        // AdjustTokenPrivileges.
        let privilege_status = unsafe { GetLastError() };
        if !privilege_adjustment_succeeded(adjusted, privilege_status) {
            return Err(SystemPowerError::at(
                SystemPowerStage::EnableShutdownPrivilege,
            ));
        }

        Ok(Self {
            token,
            previous,
            restore_pending: true,
        })
    }

    fn restore(&mut self) -> Result<(), SystemPowerError> {
        if !self.restore_pending {
            return Ok(());
        }

        // SAFETY: token remains owned by this guard and previous is the exact
        // state returned by the successful privilege-adjustment call above.
        let restored = unsafe {
            AdjustTokenPrivileges(self.token.0, 0, &self.previous, 0, null_mut(), null_mut())
        };
        // SAFETY: GetLastError is read immediately after AdjustTokenPrivileges;
        // a non-zero BOOL alone does not guarantee every requested privilege was
        // adjusted.
        let privilege_status = unsafe { GetLastError() };
        if !privilege_adjustment_succeeded(restored, privilege_status) {
            return Err(SystemPowerError::at(
                SystemPowerStage::RestoreShutdownPrivilege,
            ));
        }

        self.restore_pending = false;
        Ok(())
    }
}

impl Drop for ShutdownPrivilegeGuard {
    fn drop(&mut self) {
        if self.restore_pending {
            // Best effort only in Drop. The explicit restore path above reports
            // whether Windows accepted the action before privilege restoration
            // failed; Drop retries restoration without masking that truth.
            // SAFETY: the token and previous state remain valid until fields drop.
            unsafe {
                AdjustTokenPrivileges(self.token.0, 0, &self.previous, 0, null_mut(), null_mut());
            }
            self.restore_pending = false;
        }
    }
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership of the process-token handle is unique to this
            // wrapper and ends here.
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

const fn privilege_adjustment_succeeded(adjusted: i32, status: u32) -> bool {
    adjusted != 0 && status == ERROR_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_controller<T: SystemPowerController>() {}

    #[test]
    fn production_type_implements_narrow_power_controller_contract() {
        assert_controller::<Win32SystemPowerController>();
    }

    #[test]
    fn power_actions_map_to_closed_win32_reboot_flags() {
        assert_eq!(reboot_after_shutdown(SystemPowerAction::Restart), 1);
        assert_eq!(reboot_after_shutdown(SystemPowerAction::Shutdown), 0);
    }

    #[test]
    fn shutdown_reason_is_planned_application_maintenance() {
        assert_eq!(
            CLASSMESH_POWER_REASON,
            SHTDN_REASON_MAJOR_APPLICATION
                | SHTDN_REASON_MINOR_MAINTENANCE
                | SHTDN_REASON_FLAG_PLANNED
        );
    }

    #[test]
    fn privilege_adjustment_requires_bool_success_and_error_success() {
        assert!(privilege_adjustment_succeeded(1, ERROR_SUCCESS));
        assert!(!privilege_adjustment_succeeded(0, ERROR_SUCCESS));
        assert!(!privilege_adjustment_succeeded(1, 1));
    }

    #[test]
    fn request_outcome_preserves_acceptance_and_cleanup_truth() {
        let restore_error = SystemPowerError::at(SystemPowerStage::RestoreShutdownPrivilege);

        assert_eq!(
            finish_power_request(true, Ok(())),
            Ok(SystemPowerRequestOutcome::Accepted)
        );
        assert_eq!(
            finish_power_request(true, Err(restore_error)),
            Ok(SystemPowerRequestOutcome::AcceptedPrivilegeRestoreFailed)
        );
        assert_eq!(
            finish_power_request(false, Ok(())),
            Err(SystemPowerError::at(SystemPowerStage::RequestRejected))
        );
        assert_eq!(
            finish_power_request(false, Err(restore_error)),
            Err(restore_error)
        );
    }

    #[test]
    fn power_diagnostic_codes_are_stable_and_value_free() {
        for (stage, expected) in [
            (
                SystemPowerStage::OpenProcessToken,
                "system_power.open_token_failed",
            ),
            (
                SystemPowerStage::LookupShutdownPrivilege,
                "system_power.lookup_shutdown_privilege_failed",
            ),
            (
                SystemPowerStage::EnableShutdownPrivilege,
                "system_power.enable_shutdown_privilege_failed",
            ),
            (
                SystemPowerStage::RequestRejected,
                "system_power.request_rejected",
            ),
            (
                SystemPowerStage::RestoreShutdownPrivilege,
                "system_power.restore_shutdown_privilege_failed",
            ),
        ] {
            let error = SystemPowerError::at(stage);
            assert_eq!(error.diagnostic_code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }
}
