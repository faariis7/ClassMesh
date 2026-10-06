use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use crate::control_wire::{
    AppIdentity, OpenTarget, TeacherInteractionKind, TeacherInteractionRequest,
    TeacherInteractionResult, TeacherInteractionState, open_target, teacher_interaction_request,
};
use crate::{Capability, ProtocolVersion};

pub const TEACHER_INTERACTION_MIN_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 6 };
pub const MAX_TEACHER_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_OPEN_URL_BYTES: usize = 2 * 1024;
pub const MAX_INTERACTION_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherInteractionError {
    MissingAction,
    EmptyMessage,
    MessageTooLarge,
    MessageContainsControlCharacter,
    MissingTarget,
    UrlTooLarge,
    UnsupportedUrlScheme,
    InvalidUrl,
    InvalidApp,
    InvalidKind,
    InvalidState,
    DiagnosticTooLarge,
}

#[must_use]
pub fn teacher_message_available(
    version: ProtocolVersion,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    version.major == TEACHER_INTERACTION_MIN_VERSION.major
        && version.minor >= TEACHER_INTERACTION_MIN_VERSION.minor
        && capabilities.contains(&Capability::TeacherMessage)
}

#[must_use]
pub fn open_target_available(
    version: ProtocolVersion,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    version.major == TEACHER_INTERACTION_MIN_VERSION.major
        && version.minor >= TEACHER_INTERACTION_MIN_VERSION.minor
        && capabilities.contains(&Capability::OpenTarget)
}

pub fn validate_request(
    request: &TeacherInteractionRequest,
) -> Result<TeacherInteractionKind, TeacherInteractionError> {
    match request
        .action
        .as_ref()
        .ok_or(TeacherInteractionError::MissingAction)?
    {
        teacher_interaction_request::Action::Message(message) => {
            validate_message(&message.text_utf8)?;
            Ok(TeacherInteractionKind::Message)
        }
        teacher_interaction_request::Action::OpenTarget(target) => {
            validate_open_target(target)?;
            Ok(TeacherInteractionKind::OpenTarget)
        }
    }
}

pub fn validate_result(result: &TeacherInteractionResult) -> Result<(), TeacherInteractionError> {
    let kind = TeacherInteractionKind::try_from(result.kind)
        .map_err(|_| TeacherInteractionError::InvalidKind)?;
    if kind == TeacherInteractionKind::Unspecified {
        return Err(TeacherInteractionError::InvalidKind);
    }

    let state = TeacherInteractionState::try_from(result.state)
        .map_err(|_| TeacherInteractionError::InvalidState)?;
    if state == TeacherInteractionState::Unspecified {
        return Err(TeacherInteractionError::InvalidState);
    }

    if result.diagnostic.len() > MAX_INTERACTION_DIAGNOSTIC_BYTES {
        return Err(TeacherInteractionError::DiagnosticTooLarge);
    }

    Ok(())
}

pub fn validate_message(text: &str) -> Result<(), TeacherInteractionError> {
    if text.trim().is_empty() {
        return Err(TeacherInteractionError::EmptyMessage);
    }
    if text.len() > MAX_TEACHER_MESSAGE_BYTES {
        return Err(TeacherInteractionError::MessageTooLarge);
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(TeacherInteractionError::MessageContainsControlCharacter);
    }
    Ok(())
}

pub fn validate_open_target(target: &OpenTarget) -> Result<(), TeacherInteractionError> {
    match target
        .target
        .as_ref()
        .ok_or(TeacherInteractionError::MissingTarget)?
    {
        open_target::Target::HttpsUrl(url) => validate_https_url(url),
        open_target::Target::App(value) => {
            let app =
                AppIdentity::try_from(*value).map_err(|_| TeacherInteractionError::InvalidApp)?;
            if app == AppIdentity::Unspecified {
                return Err(TeacherInteractionError::InvalidApp);
            }
            Ok(())
        }
    }
}

pub fn validate_https_url(url: &str) -> Result<(), TeacherInteractionError> {
    if url.len() > MAX_OPEN_URL_BYTES {
        return Err(TeacherInteractionError::UrlTooLarge);
    }
    if !url.starts_with("https://") {
        return Err(TeacherInteractionError::UnsupportedUrlScheme);
    }
    if url
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '\\')
    {
        return Err(TeacherInteractionError::InvalidUrl);
    }

    let remainder = &url["https://".len()..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];

    if authority.is_empty() || authority.contains('@') {
        return Err(TeacherInteractionError::InvalidUrl);
    }

    validate_authority(authority)
}

fn validate_authority(authority: &str) -> Result<(), TeacherInteractionError> {
    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some(close) = ipv6.find(']') else {
            return Err(TeacherInteractionError::InvalidUrl);
        };
        if close == 0 {
            return Err(TeacherInteractionError::InvalidUrl);
        }
        ipv6[..close]
            .parse::<Ipv6Addr>()
            .map_err(|_| TeacherInteractionError::InvalidUrl)?;

        let suffix = &ipv6[(close + 1)..];
        if suffix.is_empty() {
            return Ok(());
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return Err(TeacherInteractionError::InvalidUrl);
        };
        return validate_port(port);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        Some(_) => return Err(TeacherInteractionError::InvalidUrl),
        None => (authority, None),
    };

    if !valid_ascii_host(host) {
        return Err(TeacherInteractionError::InvalidUrl);
    }

    if let Some(port) = port {
        validate_port(port)?;
    }

    Ok(())
}

fn valid_ascii_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }

    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

fn validate_port(port: &str) -> Result<(), TeacherInteractionError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TeacherInteractionError::InvalidUrl);
    }

    let parsed = port
        .parse::<u16>()
        .map_err(|_| TeacherInteractionError::InvalidUrl)?;
    if parsed == 0 {
        return Err(TeacherInteractionError::InvalidUrl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::control_wire::{
        TeacherInteractionResult, TeacherMessage, open_target, teacher_interaction_request,
    };

    use super::*;

    fn message_request(text: &str) -> TeacherInteractionRequest {
        TeacherInteractionRequest {
            action: Some(teacher_interaction_request::Action::Message(
                TeacherMessage {
                    text_utf8: text.to_owned(),
                },
            )),
        }
    }

    fn url_request(url: &str) -> TeacherInteractionRequest {
        TeacherInteractionRequest {
            action: Some(teacher_interaction_request::Action::OpenTarget(
                OpenTarget {
                    target: Some(open_target::Target::HttpsUrl(url.to_owned())),
                },
            )),
        }
    }

    fn app_request(app: AppIdentity) -> TeacherInteractionRequest {
        TeacherInteractionRequest {
            action: Some(teacher_interaction_request::Action::OpenTarget(
                OpenTarget {
                    target: Some(open_target::Target::App(app as i32)),
                },
            )),
        }
    }

    #[test]
    fn availability_requires_v06_and_exact_capability() {
        let message = BTreeSet::from([Capability::TeacherMessage]);
        let open = BTreeSet::from([Capability::OpenTarget]);

        assert!(!teacher_message_available(
            ProtocolVersion { major: 0, minor: 5 },
            &message
        ));
        assert!(!teacher_message_available(
            TEACHER_INTERACTION_MIN_VERSION,
            &BTreeSet::new()
        ));
        assert!(teacher_message_available(
            TEACHER_INTERACTION_MIN_VERSION,
            &message
        ));
        assert!(!open_target_available(
            TEACHER_INTERACTION_MIN_VERSION,
            &message
        ));
        assert!(open_target_available(
            TEACHER_INTERACTION_MIN_VERSION,
            &open
        ));
    }

    #[test]
    fn teacher_message_is_non_empty_bounded_and_control_safe() {
        assert_eq!(
            validate_request(&message_request("Class starts in five minutes.")),
            Ok(TeacherInteractionKind::Message)
        );
        assert_eq!(
            validate_request(&message_request("   \n\t")),
            Err(TeacherInteractionError::EmptyMessage)
        );
        assert_eq!(
            validate_request(&message_request(&"x".repeat(MAX_TEACHER_MESSAGE_BYTES + 1))),
            Err(TeacherInteractionError::MessageTooLarge)
        );
        assert_eq!(
            validate_request(&message_request("hello\0student")),
            Err(TeacherInteractionError::MessageContainsControlCharacter)
        );
    }

    #[test]
    fn https_target_accepts_strict_hosts_and_rejects_shell_like_inputs() {
        for url in [
            "https://example.com",
            "https://example.com/lesson?id=7#part-2",
            "https://127.0.0.1:8443/status",
            "https://[::1]:443/",
        ] {
            assert_eq!(
                validate_request(&url_request(url)),
                Ok(TeacherInteractionKind::OpenTarget),
                "{url}"
            );
        }

        for url in [
            "http://example.com",
            "file:///C:/Windows/System32/cmd.exe",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                validate_request(&url_request(url)),
                Err(TeacherInteractionError::UnsupportedUrlScheme),
                "{url}"
            );
        }

        for url in [
            "https://",
            "https://user@example.com",
            "https://example.com\\..\\cmd.exe",
            "https://example.com bad",
            "https://.example.com",
            "https://-example.com",
            "https://example-.com",
            "https://example..com",
            "https://example.com:0",
            "https://[not-an-ipv6]/",
        ] {
            assert_eq!(
                validate_request(&url_request(url)),
                Err(TeacherInteractionError::InvalidUrl),
                "{url}"
            );
        }

        assert_eq!(
            validate_request(&url_request(&format!(
                "https://example.com/{}",
                "x".repeat(MAX_OPEN_URL_BYTES)
            ))),
            Err(TeacherInteractionError::UrlTooLarge)
        );
    }

    #[test]
    fn app_target_accepts_only_closed_known_identities() {
        for app in [
            AppIdentity::DefaultBrowser,
            AppIdentity::Calculator,
            AppIdentity::TextEditor,
        ] {
            assert_eq!(
                validate_request(&app_request(app)),
                Ok(TeacherInteractionKind::OpenTarget)
            );
        }

        assert_eq!(
            validate_request(&app_request(AppIdentity::Unspecified)),
            Err(TeacherInteractionError::InvalidApp)
        );

        let invalid = TeacherInteractionRequest {
            action: Some(teacher_interaction_request::Action::OpenTarget(
                OpenTarget {
                    target: Some(open_target::Target::App(i32::MAX)),
                },
            )),
        };
        assert_eq!(
            validate_request(&invalid),
            Err(TeacherInteractionError::InvalidApp)
        );
    }

    #[test]
    fn request_requires_an_action_and_open_target_requires_a_target() {
        assert_eq!(
            validate_request(&TeacherInteractionRequest { action: None }),
            Err(TeacherInteractionError::MissingAction)
        );
        assert_eq!(
            validate_request(&TeacherInteractionRequest {
                action: Some(teacher_interaction_request::Action::OpenTarget(
                    OpenTarget { target: None }
                )),
            }),
            Err(TeacherInteractionError::MissingTarget)
        );
    }

    #[test]
    fn result_requires_known_kind_state_and_bounded_diagnostic() {
        let mut result = TeacherInteractionResult {
            kind: TeacherInteractionKind::Message as i32,
            state: TeacherInteractionState::Accepted as i32,
            diagnostic: String::new(),
        };
        assert_eq!(validate_result(&result), Ok(()));

        result.kind = TeacherInteractionKind::Unspecified as i32;
        assert_eq!(
            validate_result(&result),
            Err(TeacherInteractionError::InvalidKind)
        );

        result.kind = TeacherInteractionKind::OpenTarget as i32;
        result.state = i32::MAX;
        assert_eq!(
            validate_result(&result),
            Err(TeacherInteractionError::InvalidState)
        );

        result.state = TeacherInteractionState::Failed as i32;
        result.diagnostic = "x".repeat(MAX_INTERACTION_DIAGNOSTIC_BYTES + 1);
        assert_eq!(
            validate_result(&result),
            Err(TeacherInteractionError::DiagnosticTooLarge)
        );
    }
}
