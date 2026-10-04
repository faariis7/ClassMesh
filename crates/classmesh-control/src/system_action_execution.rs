use classmesh_protocol::control_wire::{SystemAction, SystemActionResult, SystemActionState};
use classmesh_protocol::system_action::validate_result;

use crate::dispatch::AuthorizedSystemAction;

pub const EXECUTOR_UNAVAILABLE_DIAGNOSTIC: &str = "system_action.executor_unavailable";
pub const EXECUTION_FAILED_DIAGNOSTIC: &str = "system_action.execution_failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemActionExecutionOutcome {
    Accepted,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemActionExecutionError {
    Unavailable,
    Failed,
}

pub trait SystemActionExecutor {
    fn execute(
        &mut self,
        action: AuthorizedSystemAction,
    ) -> Result<SystemActionExecutionOutcome, SystemActionExecutionError>;
}

#[must_use]
pub fn execute_system_action<E>(
    executor: &mut E,
    action: AuthorizedSystemAction,
) -> SystemActionResult
where
    E: SystemActionExecutor + ?Sized,
{
    let wire_action = action.action();

    let (state, diagnostic) = match executor.execute(action) {
        Ok(SystemActionExecutionOutcome::Accepted) => (SystemActionState::Accepted, String::new()),
        Ok(SystemActionExecutionOutcome::Completed) => {
            (SystemActionState::Completed, String::new())
        }
        Err(SystemActionExecutionError::Unavailable) => (
            SystemActionState::Rejected,
            EXECUTOR_UNAVAILABLE_DIAGNOSTIC.to_owned(),
        ),
        Err(SystemActionExecutionError::Failed) => (
            SystemActionState::Failed,
            EXECUTION_FAILED_DIAGNOSTIC.to_owned(),
        ),
    };

    let result = SystemActionResult {
        action: wire_action as i32,
        state: state as i32,
        diagnostic,
    };
    debug_assert_eq!(validate_result(&result), Ok(()));

    result
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::system_action::{
        MAX_SYSTEM_ACTION_DIAGNOSTIC_BYTES, SystemActionControlError, validate_result,
    };

    use super::*;

    #[derive(Debug)]
    struct RecordingExecutor {
        calls: Vec<SystemAction>,
        response: Result<SystemActionExecutionOutcome, SystemActionExecutionError>,
    }

    impl RecordingExecutor {
        fn returning(
            response: Result<SystemActionExecutionOutcome, SystemActionExecutionError>,
        ) -> Self {
            Self {
                calls: Vec::new(),
                response,
            }
        }
    }

    impl SystemActionExecutor for RecordingExecutor {
        fn execute(
            &mut self,
            action: AuthorizedSystemAction,
        ) -> Result<SystemActionExecutionOutcome, SystemActionExecutionError> {
            self.calls.push(action.action());
            self.response
        }
    }

    fn authorized(action: SystemAction) -> AuthorizedSystemAction {
        AuthorizedSystemAction::from_validated(action).expect("valid closed action")
    }

    #[test]
    fn forwards_each_authorized_action_exactly_once_to_the_executor() {
        for action in [
            SystemAction::Lock,
            SystemAction::Restart,
            SystemAction::Shutdown,
        ] {
            let mut executor =
                RecordingExecutor::returning(Ok(SystemActionExecutionOutcome::Completed));
            let result = execute_system_action(&mut executor, authorized(action));

            assert_eq!(executor.calls, vec![action]);
            assert_eq!(result.action, action as i32);
            assert_eq!(result.state, SystemActionState::Completed as i32);
            assert!(result.diagnostic.is_empty());
            assert_eq!(validate_result(&result), Ok(()));
        }
    }

    #[test]
    fn accepted_outcome_maps_without_fabricating_completion() {
        let mut executor =
            RecordingExecutor::returning(Ok(SystemActionExecutionOutcome::Accepted));

        let result = execute_system_action(&mut executor, authorized(SystemAction::Restart));

        assert_eq!(result.state, SystemActionState::Accepted as i32);
        assert!(result.diagnostic.is_empty());
    }

    #[test]
    fn backend_failures_map_to_bounded_non_sensitive_result_states() {
        for (error, expected_state, expected_diagnostic) in [
            (
                SystemActionExecutionError::Unavailable,
                SystemActionState::Rejected,
                EXECUTOR_UNAVAILABLE_DIAGNOSTIC,
            ),
            (
                SystemActionExecutionError::Failed,
                SystemActionState::Failed,
                EXECUTION_FAILED_DIAGNOSTIC,
            ),
        ] {
            let mut executor = RecordingExecutor::returning(Err(error));
            let result =
                execute_system_action(&mut executor, authorized(SystemAction::Shutdown));

            assert_eq!(executor.calls, vec![SystemAction::Shutdown]);
            assert_eq!(result.state, expected_state as i32);
            assert_eq!(result.diagnostic, expected_diagnostic);
            assert!(result.diagnostic.len() <= MAX_SYSTEM_ACTION_DIAGNOSTIC_BYTES);
            assert_eq!(validate_result(&result), Ok(()));
        }
    }

    #[test]
    fn authorized_token_rejects_unspecified_action() {
        assert_eq!(
            AuthorizedSystemAction::from_validated(SystemAction::Unspecified),
            Err(SystemActionControlError::InvalidAction)
        );
    }
}
