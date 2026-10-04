use std::collections::BTreeSet;

use crate::control_wire::{
    SystemAction, SystemActionRequest, SystemActionResult, SystemActionState,
};
use crate::{Capability, ProtocolVersion};

pub const SYSTEM_ACTION_MIN_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 5 };
pub const MAX_SYSTEM_ACTION_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemActionControlError {
    InvalidAction,
    InvalidState,
    DiagnosticTooLarge,
}

#[must_use]
pub fn system_actions_available(
    version: ProtocolVersion,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    version.major == SYSTEM_ACTION_MIN_VERSION.major
        && version.minor >= SYSTEM_ACTION_MIN_VERSION.minor
        && capabilities.contains(&Capability::SystemActions)
}

pub fn validate_request(request: &SystemActionRequest) -> Result<(), SystemActionControlError> {
    system_action(request.action).map(|_| ())
}

pub fn validate_result(result: &SystemActionResult) -> Result<(), SystemActionControlError> {
    system_action(result.action)?;

    let state = SystemActionState::try_from(result.state)
        .map_err(|_| SystemActionControlError::InvalidState)?;
    if state == SystemActionState::Unspecified {
        return Err(SystemActionControlError::InvalidState);
    }

    if result.diagnostic.len() > MAX_SYSTEM_ACTION_DIAGNOSTIC_BYTES {
        return Err(SystemActionControlError::DiagnosticTooLarge);
    }

    Ok(())
}

pub fn system_action(value: i32) -> Result<SystemAction, SystemActionControlError> {
    let action =
        SystemAction::try_from(value).map_err(|_| SystemActionControlError::InvalidAction)?;
    if action == SystemAction::Unspecified {
        return Err(SystemActionControlError::InvalidAction);
    }
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: SystemAction) -> SystemActionRequest {
        SystemActionRequest {
            action: action as i32,
        }
    }

    fn result(action: SystemAction, state: SystemActionState) -> SystemActionResult {
        SystemActionResult {
            action: action as i32,
            state: state as i32,
            diagnostic: String::new(),
        }
    }

    #[test]
    fn availability_requires_v05_and_explicit_capability() {
        let capability = BTreeSet::from([Capability::SystemActions]);

        assert!(!system_actions_available(
            ProtocolVersion { major: 0, minor: 4 },
            &capability
        ));
        assert!(!system_actions_available(
            ProtocolVersion { major: 1, minor: 5 },
            &capability
        ));
        assert!(!system_actions_available(
            SYSTEM_ACTION_MIN_VERSION,
            &BTreeSet::new()
        ));
        assert!(system_actions_available(
            SYSTEM_ACTION_MIN_VERSION,
            &capability
        ));
        assert!(system_actions_available(
            ProtocolVersion { major: 0, minor: 9 },
            &capability
        ));
    }

    #[test]
    fn request_accepts_only_known_non_unspecified_actions() {
        for action in [
            SystemAction::Lock,
            SystemAction::Restart,
            SystemAction::Shutdown,
        ] {
            assert_eq!(validate_request(&request(action)), Ok(()));
        }

        assert_eq!(
            validate_request(&request(SystemAction::Unspecified)),
            Err(SystemActionControlError::InvalidAction)
        );
        assert_eq!(
            validate_request(&SystemActionRequest { action: i32::MAX }),
            Err(SystemActionControlError::InvalidAction)
        );
    }

    #[test]
    fn result_requires_known_action_state_and_bounded_diagnostic() {
        for state in [
            SystemActionState::Accepted,
            SystemActionState::Completed,
            SystemActionState::Rejected,
            SystemActionState::Failed,
        ] {
            assert_eq!(validate_result(&result(SystemAction::Lock, state)), Ok(()));
        }

        assert_eq!(
            validate_result(&result(
                SystemAction::Unspecified,
                SystemActionState::Accepted
            )),
            Err(SystemActionControlError::InvalidAction)
        );

        let mut invalid_state = result(SystemAction::Restart, SystemActionState::Accepted);
        invalid_state.state = SystemActionState::Unspecified as i32;
        assert_eq!(
            validate_result(&invalid_state),
            Err(SystemActionControlError::InvalidState)
        );

        invalid_state.state = i32::MAX;
        assert_eq!(
            validate_result(&invalid_state),
            Err(SystemActionControlError::InvalidState)
        );

        let mut bounded = result(SystemAction::Shutdown, SystemActionState::Failed);
        bounded.diagnostic = "x".repeat(MAX_SYSTEM_ACTION_DIAGNOSTIC_BYTES);
        assert_eq!(validate_result(&bounded), Ok(()));

        bounded.diagnostic.push('x');
        assert_eq!(
            validate_result(&bounded),
            Err(SystemActionControlError::DiagnosticTooLarge)
        );
    }
}
