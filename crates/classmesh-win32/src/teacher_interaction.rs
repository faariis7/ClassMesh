use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::System::RemoteDesktop::{WTS_CURRENT_SERVER_HANDLE, WTSSendMessageW};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONINFORMATION, MB_OK, MB_OKCANCEL, SW_SHOWNORMAL,
};

const CLASSMESH_MESSAGE_TITLE: &str = "ClassMesh";
const SHELL_SUCCESS_THRESHOLD: isize = 32;
const DEFAULT_BROWSER_ACTIVATION_TARGET: &str = "https:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsAppIdentity {
    DefaultBrowser,
    Calculator,
    TextEditor,
}

impl WindowsAppIdentity {
    const fn shell_target(self) -> &'static str {
        match self {
            Self::DefaultBrowser => DEFAULT_BROWSER_ACTIVATION_TARGET,
            Self::Calculator => "calc.exe",
            Self::TextEditor => "notepad.exe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherInteractionAcceptance {
    /// Windows accepted an asynchronous display/activation request. This does
    /// not claim that the user dismissed a message or that an application
    /// finished starting.
    Accepted,
}

pub trait TeacherMessagePresenter {
    fn present_message(
        &mut self,
        session_id: u32,
        text: &str,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError>;
}

pub trait OpenTargetLauncher {
    fn open_https(
        &mut self,
        url: &str,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError>;

    fn open_app(
        &mut self,
        app: WindowsAppIdentity,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError>;
}

#[derive(Debug, Default)]
pub struct Win32TeacherMessagePresenter;

/// Only the user's explicit OK response is completion. Unlike asynchronous
/// WTSSendMessageW, this API waits (with a strict positive deadline) and MUST
/// be run off the interactive Worker's IPC/capture thread.
///
/// This uses MB_OKCANCEL to distinguish an explicit dismiss from a timeout;
/// the standard asynchronous presenter remains available to older callers.
pub fn confirm_teacher_message(
    session_id: u32,
    text: &str,
    timeout_seconds: u32,
) -> Result<(), TeacherInteractionExecutionError> {
    if session_id == 0 {
        return Err(TeacherInteractionExecutionError::InvalidSession);
    }
    validate_confirmation_timeout(timeout_seconds)?;
    let mut title = utf16_with_nul(CLASSMESH_MESSAGE_TITLE)?;
    let mut message = utf16_with_nul(text)?;
    let title_bytes = utf16_payload_bytes(&title)?;
    let message_bytes = utf16_payload_bytes(&message)?;
    let mut response = 0_i32;
    // SAFETY: Owned, writable, NUL-terminated UTF-16 buffers remain alive
    // through the bounded Win32 call. Only the dedicated confirmation thread
    // is permitted to invoke this blocking form of WTSSendMessageW.
    let delivered = unsafe {
        WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            title.as_mut_ptr(),
            title_bytes,
            message.as_mut_ptr(),
            message_bytes,
            MB_OKCANCEL | MB_ICONINFORMATION,
            timeout_seconds,
            &mut response,
            1,
        )
    };
    if delivered == 0 {
        return Err(TeacherInteractionExecutionError::MessageRejected);
    }
    classify_message_confirmation(response)
}

fn validate_confirmation_timeout(seconds: u32) -> Result<(), TeacherInteractionExecutionError> {
    if !(1..=15).contains(&seconds) {
        return Err(TeacherInteractionExecutionError::InvalidTimeout);
    }
    Ok(())
}

fn classify_message_confirmation(response: i32) -> Result<(), TeacherInteractionExecutionError> {
    // Win32 WTSSendMessageW: IDOK=1, IDCANCEL=2, IDTIMEOUT=32000,
    // IDASYNC=32001. Neither queued delivery nor timeout means the user saw
    // and acknowledged a message.
    match response {
        1 => Ok(()),
        2 => Err(TeacherInteractionExecutionError::MessageDismissed),
        32_000 => Err(TeacherInteractionExecutionError::MessageTimedOut),
        _ => Err(TeacherInteractionExecutionError::MessageUnexpectedResponse),
    }
}

impl TeacherMessagePresenter for Win32TeacherMessagePresenter {
    fn present_message(
        &mut self,
        session_id: u32,
        text: &str,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError> {
        if session_id == 0 {
            return Err(TeacherInteractionExecutionError::InvalidSession);
        }
        let mut title = utf16_with_nul(CLASSMESH_MESSAGE_TITLE)?;
        let mut message = utf16_with_nul(text)?;
        let title_bytes = utf16_payload_bytes(&title)?;
        let message_bytes = utf16_payload_bytes(&message)?;
        let mut response = 0_i32;

        // SAFETY: title/message are owned, writable, NUL-terminated UTF-16 buffers.
        // The byte lengths intentionally exclude their terminators as required by
        // WTSSendMessageW. bWait is FALSE so this interactive Worker thread never
        // blocks waiting for user acknowledgement.
        let accepted = unsafe {
            WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                title.as_mut_ptr(),
                title_bytes,
                message.as_mut_ptr(),
                message_bytes,
                MB_OK | MB_ICONINFORMATION,
                0,
                &mut response,
                0,
            )
        };
        if accepted == 0 {
            return Err(TeacherInteractionExecutionError::MessageRejected);
        }
        Ok(TeacherInteractionAcceptance::Accepted)
    }
}

#[derive(Debug, Default)]
pub struct Win32OpenTargetLauncher;

impl OpenTargetLauncher for Win32OpenTargetLauncher {
    fn open_https(
        &mut self,
        url: &str,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError> {
        if !is_https_target(url) {
            return Err(TeacherInteractionExecutionError::InvalidTarget);
        }
        shell_open(url)
    }

    fn open_app(
        &mut self,
        app: WindowsAppIdentity,
    ) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError> {
        shell_open(app.shell_target())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherInteractionExecutionError {
    InvalidSession,
    InvalidTarget,
    EmbeddedNul,
    ValueTooLong,
    MessageRejected,
    MessageDismissed,
    MessageTimedOut,
    MessageUnexpectedResponse,
    InvalidTimeout,
    TargetRejected,
}

impl TeacherInteractionExecutionError {
    #[must_use]
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::InvalidSession => "teacher_interaction.invalid_session",
            Self::InvalidTarget => "teacher_interaction.invalid_target",
            Self::EmbeddedNul => "teacher_interaction.embedded_nul",
            Self::ValueTooLong => "teacher_interaction.value_too_long",
            Self::MessageRejected => "teacher_interaction.message_rejected",
            Self::MessageDismissed => "teacher_interaction.message_dismissed",
            Self::MessageTimedOut => "teacher_interaction.message_confirmation_timeout",
            Self::MessageUnexpectedResponse => "teacher_interaction.message_unknown_response",
            Self::InvalidTimeout => "teacher_interaction.message_invalid_timeout",
            Self::TargetRejected => "teacher_interaction.target_rejected",
        }
    }
}

impl Display for TeacherInteractionExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for TeacherInteractionExecutionError {}

fn shell_open(
    target: &str,
) -> Result<TeacherInteractionAcceptance, TeacherInteractionExecutionError> {
    let target = utf16_with_nul(target)?;

    // SAFETY: target is a NUL-terminated UTF-16 string that remains alive for the
    // call. Operation/parameters/directory are null, so no command line, shell
    // fragment, environment expansion or arbitrary arguments cross this boundary.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            null(),
            target.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    if !shell_result_is_success(result as isize) {
        return Err(TeacherInteractionExecutionError::TargetRejected);
    }
    Ok(TeacherInteractionAcceptance::Accepted)
}

fn is_https_target(target: &str) -> bool {
    target.len() > "https://".len() && target.starts_with("https://")
}

fn utf16_with_nul(value: &str) -> Result<Vec<u16>, TeacherInteractionExecutionError> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(TeacherInteractionExecutionError::EmbeddedNul);
    }
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);
    Ok(encoded)
}

fn utf16_payload_bytes(encoded_with_nul: &[u16]) -> Result<u32, TeacherInteractionExecutionError> {
    let payload_units = encoded_with_nul
        .len()
        .checked_sub(1)
        .ok_or(TeacherInteractionExecutionError::ValueTooLong)?;
    let bytes = payload_units
        .checked_mul(size_of::<u16>())
        .ok_or(TeacherInteractionExecutionError::ValueTooLong)?;
    u32::try_from(bytes).map_err(|_| TeacherInteractionExecutionError::ValueTooLong)
}

const fn shell_result_is_success(result: isize) -> bool {
    result > SHELL_SUCCESS_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_message_presenter<T: TeacherMessagePresenter>() {}
    fn assert_target_launcher<T: OpenTargetLauncher>() {}

    #[test]
    fn production_types_implement_narrow_interaction_contracts() {
        assert_message_presenter::<Win32TeacherMessagePresenter>();
        assert_target_launcher::<Win32OpenTargetLauncher>();
    }

    #[test]
    fn app_identity_maps_only_to_closed_fixed_shell_targets() {
        assert_eq!(
            WindowsAppIdentity::DefaultBrowser.shell_target(),
            DEFAULT_BROWSER_ACTIVATION_TARGET
        );
        assert_eq!(WindowsAppIdentity::Calculator.shell_target(), "calc.exe");
        assert_eq!(WindowsAppIdentity::TextEditor.shell_target(), "notepad.exe");
    }

    #[test]
    fn blocking_windows_confirmation_only_completes_after_explicit_ok() {
        assert_eq!(classify_message_confirmation(1), Ok(()));
        for (response, failure) in [
            (2, TeacherInteractionExecutionError::MessageDismissed),
            (32_000, TeacherInteractionExecutionError::MessageTimedOut),
            (
                32_001,
                TeacherInteractionExecutionError::MessageUnexpectedResponse,
            ),
            (
                0,
                TeacherInteractionExecutionError::MessageUnexpectedResponse,
            ),
        ] {
            assert_eq!(classify_message_confirmation(response), Err(failure));
        }
        // Zero would wait indefinitely and a huge deadline could orphan a
        // Worker dialog beyond its authenticated Service owner.
        assert!(validate_confirmation_timeout(0).is_err());
        assert!(validate_confirmation_timeout(16).is_err());
        assert!(validate_confirmation_timeout(15).is_ok());
    }

    #[test]
    fn shell_acceptance_is_truthful_and_bounded() {
        assert!(!shell_result_is_success(0));
        assert!(!shell_result_is_success(32));
        assert!(shell_result_is_success(33));
    }

    #[test]
    fn https_boundary_rejects_non_https_shapes_before_shell() {
        for invalid in [
            "",
            "https://",
            "http://example.com",
            "file:///C:/Windows/System32/calc.exe",
            "calc.exe",
        ] {
            assert!(!is_https_target(invalid), "{invalid}");
        }
        assert!(is_https_target("https://example.com/"));
    }

    #[test]
    fn utf16_helpers_reject_embedded_nul_and_count_payload_bytes() {
        assert_eq!(
            utf16_with_nul("bad\0value"),
            Err(TeacherInteractionExecutionError::EmbeddedNul)
        );
        let value = utf16_with_nul("AB").expect("valid UTF-16");
        assert_eq!(value, vec![65, 66, 0]);
        assert_eq!(utf16_payload_bytes(&value), Ok(4));
    }

    #[test]
    fn diagnostics_are_stable_and_value_free() {
        for (error, expected) in [
            (
                TeacherInteractionExecutionError::InvalidSession,
                "teacher_interaction.invalid_session",
            ),
            (
                TeacherInteractionExecutionError::InvalidTarget,
                "teacher_interaction.invalid_target",
            ),
            (
                TeacherInteractionExecutionError::EmbeddedNul,
                "teacher_interaction.embedded_nul",
            ),
            (
                TeacherInteractionExecutionError::ValueTooLong,
                "teacher_interaction.value_too_long",
            ),
            (
                TeacherInteractionExecutionError::MessageRejected,
                "teacher_interaction.message_rejected",
            ),
            (
                TeacherInteractionExecutionError::TargetRejected,
                "teacher_interaction.target_rejected",
            ),
        ] {
            assert_eq!(error.diagnostic_code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }
}
