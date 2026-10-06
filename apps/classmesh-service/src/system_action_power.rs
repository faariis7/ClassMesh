use classmesh_control::dispatch::AuthorizedSystemAction;
use classmesh_control::system_action_execution::{
    SystemActionExecutionError, SystemActionExecutionOutcome, SystemActionExecutor,
};
use classmesh_protocol::control_wire::SystemAction;
use classmesh_win32::{SystemPowerAction, SystemPowerController, SystemPowerRequestOutcome};

const PRIVILEGE_RESTORE_WARNING: &str = "system_power.restore_shutdown_privilege_failed";

#[derive(Debug)]
pub(crate) struct ServicePowerSystemActionExecutor<C> {
    controller: C,
}

impl<C> ServicePowerSystemActionExecutor<C> {
    pub(crate) const fn new(controller: C) -> Self {
        Self { controller }
    }
}

impl<C> ServicePowerSystemActionExecutor<C>
where
    C: SystemPowerController,
{
    fn execute_action(
        &mut self,
        action: SystemAction,
    ) -> Result<SystemActionExecutionOutcome, SystemActionExecutionError> {
        let power_action = match action {
            SystemAction::Restart => SystemPowerAction::Restart,
            SystemAction::Shutdown => SystemPowerAction::Shutdown,
            SystemAction::Lock | SystemAction::Unspecified => {
                return Err(SystemActionExecutionError::Unavailable);
            }
        };

        match self.controller.request(power_action) {
            Ok(SystemPowerRequestOutcome::Accepted) => Ok(SystemActionExecutionOutcome::Accepted),
            Ok(SystemPowerRequestOutcome::AcceptedPrivilegeRestoreFailed) => {
                eprintln!(
                    "ClassMesh system power request accepted with cleanup warning: {PRIVILEGE_RESTORE_WARNING}"
                );
                Ok(SystemActionExecutionOutcome::Accepted)
            }
            Err(error) => {
                eprintln!(
                    "ClassMesh system power request failed: {}",
                    error.diagnostic_code()
                );
                Err(SystemActionExecutionError::Failed)
            }
        }
    }
}

impl<C> SystemActionExecutor for ServicePowerSystemActionExecutor<C>
where
    C: SystemPowerController,
{
    fn execute(
        &mut self,
        action: AuthorizedSystemAction,
    ) -> Result<SystemActionExecutionOutcome, SystemActionExecutionError> {
        self.execute_action(action.action())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RecordingPowerController {
        calls: Vec<SystemPowerAction>,
        response: Result<SystemPowerRequestOutcome, classmesh_win32::SystemPowerError>,
    }

    impl RecordingPowerController {
        fn returning(
            response: Result<SystemPowerRequestOutcome, classmesh_win32::SystemPowerError>,
        ) -> Self {
            Self {
                calls: Vec::new(),
                response,
            }
        }
    }

    impl SystemPowerController for RecordingPowerController {
        fn request(
            &mut self,
            action: SystemPowerAction,
        ) -> Result<SystemPowerRequestOutcome, classmesh_win32::SystemPowerError> {
            self.calls.push(action);
            self.response
        }
    }

    #[test]
    fn maps_only_restart_and_shutdown_to_the_power_controller() {
        for (action, expected) in [
            (SystemAction::Restart, SystemPowerAction::Restart),
            (SystemAction::Shutdown, SystemPowerAction::Shutdown),
        ] {
            let controller =
                RecordingPowerController::returning(Ok(SystemPowerRequestOutcome::Accepted));
            let mut executor = ServicePowerSystemActionExecutor::new(controller);

            assert_eq!(
                executor.execute_action(action),
                Ok(SystemActionExecutionOutcome::Accepted)
            );
            assert_eq!(executor.controller.calls, vec![expected]);
        }
    }

    #[test]
    fn lock_and_unspecified_never_reach_the_service_power_controller() {
        for action in [SystemAction::Lock, SystemAction::Unspecified] {
            let controller =
                RecordingPowerController::returning(Ok(SystemPowerRequestOutcome::Accepted));
            let mut executor = ServicePowerSystemActionExecutor::new(controller);

            assert_eq!(
                executor.execute_action(action),
                Err(SystemActionExecutionError::Unavailable)
            );
            assert!(executor.controller.calls.is_empty());
        }
    }

    #[test]
    fn accepted_cleanup_warning_stays_accepted() {
        let controller = RecordingPowerController::returning(Ok(
            SystemPowerRequestOutcome::AcceptedPrivilegeRestoreFailed,
        ));
        let mut executor = ServicePowerSystemActionExecutor::new(controller);

        assert_eq!(
            executor.execute_action(SystemAction::Restart),
            Ok(SystemActionExecutionOutcome::Accepted)
        );
        assert_eq!(executor.controller.calls, vec![SystemPowerAction::Restart]);
    }
}
