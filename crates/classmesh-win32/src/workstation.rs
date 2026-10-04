use std::fmt::{Display, Formatter};
use std::io;

use windows_sys::Win32::System::Shutdown::LockWorkStation;

/// Narrow boundary for locking the current interactive workstation.
///
/// Production uses `Win32WorkstationLocker`; tests can provide a recording
/// implementation so hosted CI never locks its own session.
pub trait WorkstationLocker {
    fn lock_workstation(&mut self) -> Result<(), WorkstationLockError>;
}

#[derive(Debug, Default)]
pub struct Win32WorkstationLocker;

impl WorkstationLocker for Win32WorkstationLocker {
    fn lock_workstation(&mut self) -> Result<(), WorkstationLockError> {
        // SAFETY: LockWorkStation takes no pointers or caller-owned buffers. The
        // Worker runs in the signed-in interactive user session; a zero return is
        // converted into a bounded diagnostic error rather than retried or routed
        // through a shell.
        let result = unsafe { LockWorkStation() };
        if result == 0 {
            return Err(WorkstationLockError::Rejected(io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WorkstationLockError {
    Rejected(io::Error),
}

impl WorkstationLockError {
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Rejected(_) => "worker.workstation.lock_rejected",
        }
    }
}

impl Display for WorkstationLockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(source) => {
                write!(formatter, "LockWorkStation rejected the request: {source}")
            }
        }
    }
}

impl std::error::Error for WorkstationLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workstation_lock_diagnostic_code_is_stable_and_value_free() {
        let error = WorkstationLockError::Rejected(io::Error::from_raw_os_error(5));
        assert_eq!(error.diagnostic_code(), "worker.workstation.lock_rejected");
    }
}
