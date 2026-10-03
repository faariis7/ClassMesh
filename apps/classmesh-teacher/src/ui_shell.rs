use classmesh_video::monitoring_scheduler::MonitoringSourceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TeacherUiSection {
    #[default]
    Classroom,
    Focus,
    Presentation,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiMessage {
    Navigate(TeacherUiSection),
    SelectDevice(Option<MonitoringSourceId>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiAction {
    SelectDevice(Option<MonitoringSourceId>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeacherUiShellState {
    active_section: TeacherUiSection,
}

impl TeacherUiShellState {
    #[must_use]
    pub const fn active_section(&self) -> TeacherUiSection {
        self.active_section
    }

    pub fn handle(&mut self, message: TeacherUiMessage) -> Option<TeacherUiAction> {
        match message {
            TeacherUiMessage::Navigate(section) => {
                self.active_section = section;
                None
            }
            TeacherUiMessage::SelectDevice(source_id) => {
                Some(TeacherUiAction::SelectDevice(source_id))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_defaults_to_classroom_without_engine_action() {
        let shell = TeacherUiShellState::default();
        assert_eq!(shell.active_section(), TeacherUiSection::Classroom);
    }

    #[test]
    fn navigation_is_shell_local_and_emits_no_engine_action() {
        let mut shell = TeacherUiShellState::default();
        assert_eq!(
            shell.handle(TeacherUiMessage::Navigate(TeacherUiSection::Diagnostics)),
            None
        );
        assert_eq!(shell.active_section(), TeacherUiSection::Diagnostics);
    }

    #[test]
    fn selection_is_emitted_as_typed_action_without_becoming_shell_state() {
        let mut shell = TeacherUiShellState::default();
        let source_id = MonitoringSourceId(42);

        assert_eq!(
            shell.handle(TeacherUiMessage::SelectDevice(Some(source_id))),
            Some(TeacherUiAction::SelectDevice(Some(source_id)))
        );
        assert_eq!(shell.active_section(), TeacherUiSection::Classroom);

        assert_eq!(
            shell.handle(TeacherUiMessage::SelectDevice(None)),
            Some(TeacherUiAction::SelectDevice(None))
        );
    }
}
