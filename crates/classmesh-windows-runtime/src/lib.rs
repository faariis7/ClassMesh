#![forbid(unsafe_code)]

pub mod ipc;
pub mod worker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Logon(SessionId),
    Logoff(SessionId),
    Lock(SessionId),
    Unlock(SessionId),
    ConsoleConnect(SessionId),
    ConsoleDisconnect(SessionId),
    RemoteConnect(SessionId),
    RemoteDisconnect(SessionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Stopped,
    Starting(SessionId),
    Running(SessionId),
    Suspended(SessionId),
    Stopping(SessionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorAction {
    None,
    LaunchWorker(SessionId),
    StopWorker(SessionId),
    SuspendMedia(SessionId),
    ResumeMedia(SessionId),
    ReplaceWorker {
        old_session: SessionId,
        new_session: SessionId,
    },
}

/// Pure state machine used by the Windows Service before platform-specific WTS/process APIs are
/// invoked. Keeping policy separate from Win32 calls makes user switching and lock/unlock behavior
/// deterministic and unit-testable.
#[derive(Debug)]
pub struct SessionSupervisor {
    worker: WorkerState,
    active_session: Option<SessionId>,
}

impl Default for SessionSupervisor {
    fn default() -> Self {
        Self {
            worker: WorkerState::Stopped,
            active_session: None,
        }
    }
}

impl SessionSupervisor {
    #[must_use]
    pub const fn worker_state(&self) -> WorkerState {
        self.worker
    }

    #[must_use]
    pub const fn active_session(&self) -> Option<SessionId> {
        self.active_session
    }

    pub fn on_event(&mut self, event: SessionEvent) -> SupervisorAction {
        match event {
            SessionEvent::Logon(session)
            | SessionEvent::ConsoleConnect(session)
            | SessionEvent::RemoteConnect(session) => self.activate(session),
            SessionEvent::Logoff(session) => self.logoff(session),
            SessionEvent::Lock(session) => self.lock(session),
            SessionEvent::Unlock(session) => self.unlock(session),
            SessionEvent::ConsoleDisconnect(session) | SessionEvent::RemoteDisconnect(session) => {
                self.disconnect(session)
            }
        }
    }

    pub fn mark_worker_running(&mut self, session: SessionId) {
        if self.worker == WorkerState::Starting(session) {
            self.worker = WorkerState::Running(session);
        }
    }

    pub fn mark_worker_stopped(&mut self, session: SessionId) {
        if matches!(
            self.worker,
            WorkerState::Stopping(current)
                | WorkerState::Starting(current)
                | WorkerState::Running(current)
                | WorkerState::Suspended(current)
                if current == session
        ) {
            self.worker = WorkerState::Stopped;
        }
    }

    /// Called when a worker crashes unexpectedly. The service retains the active session and can
    /// relaunch only the worker instead of restarting the machine-level service.
    pub fn worker_crashed(&mut self, session: SessionId) -> SupervisorAction {
        if self.active_session == Some(session) {
            self.worker = WorkerState::Starting(session);
            SupervisorAction::LaunchWorker(session)
        } else {
            self.worker = WorkerState::Stopped;
            SupervisorAction::None
        }
    }

    fn activate(&mut self, session: SessionId) -> SupervisorAction {
        self.active_session = Some(session);
        match self.worker {
            WorkerState::Stopped => {
                self.worker = WorkerState::Starting(session);
                SupervisorAction::LaunchWorker(session)
            }
            WorkerState::Starting(current)
            | WorkerState::Running(current)
            | WorkerState::Suspended(current)
            | WorkerState::Stopping(current)
                if current == session =>
            {
                SupervisorAction::None
            }
            WorkerState::Starting(current)
            | WorkerState::Running(current)
            | WorkerState::Suspended(current)
            | WorkerState::Stopping(current) => {
                self.worker = WorkerState::Starting(session);
                SupervisorAction::ReplaceWorker {
                    old_session: current,
                    new_session: session,
                }
            }
        }
    }

    fn logoff(&mut self, session: SessionId) -> SupervisorAction {
        if self.active_session == Some(session) {
            self.active_session = None;
        }
        match self.worker {
            WorkerState::Starting(current)
            | WorkerState::Running(current)
            | WorkerState::Suspended(current)
                if current == session =>
            {
                self.worker = WorkerState::Stopping(session);
                SupervisorAction::StopWorker(session)
            }
            WorkerState::Stopping(current) if current == session => SupervisorAction::None,
            _ => SupervisorAction::None,
        }
    }

    fn lock(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker == WorkerState::Running(session) {
            self.worker = WorkerState::Suspended(session);
            return SupervisorAction::SuspendMedia(session);
        }
        SupervisorAction::None
    }

    fn unlock(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker == WorkerState::Suspended(session) {
            self.worker = WorkerState::Running(session);
            return SupervisorAction::ResumeMedia(session);
        }
        self.activate(session)
    }

    fn disconnect(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker == WorkerState::Running(session) {
            self.worker = WorkerState::Suspended(session);
            return SupervisorAction::SuspendMedia(session);
        }
        SupervisorAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_launches_worker_in_user_session() {
        let mut supervisor = SessionSupervisor::default();
        assert_eq!(
            supervisor.on_event(SessionEvent::Logon(SessionId(1))),
            SupervisorAction::LaunchWorker(SessionId(1))
        );
        assert_eq!(
            supervisor.worker_state(),
            WorkerState::Starting(SessionId(1))
        );
        supervisor.mark_worker_running(SessionId(1));
        assert_eq!(
            supervisor.worker_state(),
            WorkerState::Running(SessionId(1))
        );
    }

    #[test]
    fn lock_suspends_media_without_stopping_worker() {
        let mut supervisor = SessionSupervisor::default();
        let _ = supervisor.on_event(SessionEvent::Logon(SessionId(3)));
        supervisor.mark_worker_running(SessionId(3));
        assert_eq!(
            supervisor.on_event(SessionEvent::Lock(SessionId(3))),
            SupervisorAction::SuspendMedia(SessionId(3))
        );
        assert_eq!(
            supervisor.worker_state(),
            WorkerState::Suspended(SessionId(3))
        );
        assert_eq!(
            supervisor.on_event(SessionEvent::Unlock(SessionId(3))),
            SupervisorAction::ResumeMedia(SessionId(3))
        );
    }

    #[test]
    fn fast_user_switch_replaces_worker() {
        let mut supervisor = SessionSupervisor::default();
        let _ = supervisor.on_event(SessionEvent::Logon(SessionId(1)));
        supervisor.mark_worker_running(SessionId(1));
        assert_eq!(
            supervisor.on_event(SessionEvent::Logon(SessionId(2))),
            SupervisorAction::ReplaceWorker {
                old_session: SessionId(1),
                new_session: SessionId(2)
            }
        );
        assert_eq!(supervisor.active_session(), Some(SessionId(2)));
    }

    #[test]
    fn lock_unlock_cycle_preserves_active_session_and_worker_identity() {
        let mut supervisor = SessionSupervisor::default();
        let session = SessionId(11);

        assert_eq!(
            supervisor.on_event(SessionEvent::Logon(session)),
            SupervisorAction::LaunchWorker(session)
        );
        supervisor.mark_worker_running(session);
        assert_eq!(supervisor.active_session(), Some(session));

        assert_eq!(
            supervisor.on_event(SessionEvent::Lock(session)),
            SupervisorAction::SuspendMedia(session)
        );
        assert_eq!(supervisor.worker_state(), WorkerState::Suspended(session));
        assert_eq!(supervisor.active_session(), Some(session));

        assert_eq!(
            supervisor.on_event(SessionEvent::Unlock(session)),
            SupervisorAction::ResumeMedia(session)
        );
        assert_eq!(supervisor.worker_state(), WorkerState::Running(session));
        assert_eq!(supervisor.active_session(), Some(session));
    }

    #[test]
    fn fast_user_switch_from_suspended_session_replaces_worker() {
        let mut supervisor = SessionSupervisor::default();
        let first = SessionId(21);
        let second = SessionId(22);

        let _ = supervisor.on_event(SessionEvent::Logon(first));
        supervisor.mark_worker_running(first);
        assert_eq!(
            supervisor.on_event(SessionEvent::Lock(first)),
            SupervisorAction::SuspendMedia(first)
        );

        assert_eq!(
            supervisor.on_event(SessionEvent::Logon(second)),
            SupervisorAction::ReplaceWorker {
                old_session: first,
                new_session: second,
            }
        );
        assert_eq!(supervisor.active_session(), Some(second));
        assert_eq!(supervisor.worker_state(), WorkerState::Starting(second));
    }

    #[test]
    fn active_worker_crash_relaunches_and_can_return_to_running() {
        let mut supervisor = SessionSupervisor::default();
        let session = SessionId(31);

        let _ = supervisor.on_event(SessionEvent::Logon(session));
        supervisor.mark_worker_running(session);

        assert_eq!(
            supervisor.worker_crashed(session),
            SupervisorAction::LaunchWorker(session)
        );
        assert_eq!(supervisor.worker_state(), WorkerState::Starting(session));
        assert_eq!(supervisor.active_session(), Some(session));

        supervisor.mark_worker_running(session);
        assert_eq!(supervisor.worker_state(), WorkerState::Running(session));
        assert_eq!(supervisor.active_session(), Some(session));
    }

    #[test]
    fn worker_crash_restarts_worker_not_service() {
        let mut supervisor = SessionSupervisor::default();
        let _ = supervisor.on_event(SessionEvent::Logon(SessionId(7)));
        supervisor.mark_worker_running(SessionId(7));
        assert_eq!(
            supervisor.worker_crashed(SessionId(7)),
            SupervisorAction::LaunchWorker(SessionId(7))
        );
        assert_eq!(
            supervisor.worker_state(),
            WorkerState::Starting(SessionId(7))
        );
    }
}
