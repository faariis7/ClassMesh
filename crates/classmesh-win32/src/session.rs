use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use crate::LaunchError;

pub fn current_session_id() -> Result<u32, LaunchError> {
    // SAFETY: GetCurrentProcessId has no preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    let mut session_id = 0_u32;
    // SAFETY: `session_id` is a valid writable pointer and the process id refers to this process.
    if unsafe { ProcessIdToSessionId(process_id, &mut session_id) } == 0 {
        // SAFETY: GetLastError has no preconditions and is read immediately after failure.
        return Err(LaunchError {
            stage: "ProcessIdToSessionId",
            win32_error: unsafe { GetLastError() },
        });
    }
    Ok(session_id)
}
