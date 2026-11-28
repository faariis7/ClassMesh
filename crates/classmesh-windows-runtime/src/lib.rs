#![forbid(unsafe_code)]

pub mod clipboard_read_send;
pub mod ipc;
pub mod ipc_sensitive;
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
    desktop_suspended: Option<SessionId>,
    disconnected_session: Option<SessionId>,
    asleep: bool,
}

impl Default for SessionSupervisor {
    fn default() -> Self {
        Self {
            worker: WorkerState::Stopped,
            active_session: None,
            desktop_suspended: None,
            disconnected_session: None,
            asleep: false,
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
            SessionEvent::Logon(session) => self.activate(session),
            SessionEvent::ConsoleConnect(session) | SessionEvent::RemoteConnect(session) => {
                self.connect(session)
            }
            SessionEvent::Logoff(session) => self.logoff(session),
            SessionEvent::Lock(session) => self.lock(session),
            SessionEvent::Unlock(session) => self.unlock(session),
            SessionEvent::ConsoleDisconnect(session) | SessionEvent::RemoteDisconnect(session) => {
                self.disconnect(session)
            }
        }
    }

    pub fn mark_worker_running(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker != WorkerState::Starting(session) {
            return SupervisorAction::None;
        }
        self.worker = WorkerState::Running(session);
        if self.media_blocked(session) {
            return self.suspend_running(session);
        }
        SupervisorAction::None
    }

    pub fn suspend_for_sleep(&mut self) -> SupervisorAction {
        self.asleep = true;
        self.active_session
            .map_or(SupervisorAction::None, |session| {
                self.suspend_running(session)
            })
    }

    pub fn resume_after_sleep(&mut self) -> SupervisorAction {
        if !std::mem::take(&mut self.asleep) {
            return SupervisorAction::None;
        }
        self.active_session
            .map_or(SupervisorAction::None, |session| {
                self.resume_desktop(session)
            })
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
            SupervisorAction::None
        }
    }

    fn activate(&mut self, session: SessionId) -> SupervisorAction {
        if self.active_session != Some(session) {
            self.desktop_suspended = None;
            self.disconnected_session = None;
        }
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
            self.desktop_suspended = None;
            self.disconnected_session = None;
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
        if self.active_session == Some(session) {
            self.desktop_suspended = Some(session);
            return self.suspend_running(session);
        }
        SupervisorAction::None
    }

    fn suspend_running(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker == WorkerState::Running(session) {
            self.worker = WorkerState::Suspended(session);
            return SupervisorAction::SuspendMedia(session);
        }
        SupervisorAction::None
    }

    fn media_blocked(&self, session: SessionId) -> bool {
        self.asleep
            || self.desktop_suspended == Some(session)
            || self.disconnected_session == Some(session)
    }

    fn resume_desktop(&mut self, session: SessionId) -> SupervisorAction {
        if self.worker == WorkerState::Suspended(session) && !self.media_blocked(session) {
            self.worker = WorkerState::Running(session);
            return SupervisorAction::ResumeMedia(session);
        }
        SupervisorAction::None
    }

    fn connect(&mut self, session: SessionId) -> SupervisorAction {
        let action = self.activate(session);
        if self.disconnected_session == Some(session) {
            self.disconnected_session = None;
        }
        if action == SupervisorAction::None {
            return self.resume_desktop(session);
        }
        action
    }

    fn unlock(&mut self, session: SessionId) -> SupervisorAction {
        if self.active_session.is_some_and(|active| active != session) {
            return SupervisorAction::None;
        }
        self.desktop_suspended = None;
        if self.media_blocked(session) {
            return SupervisorAction::None;
        }
        if self.worker == WorkerState::Suspended(session) {
            return self.resume_desktop(session);
        }
        self.activate(session)
    }

    fn disconnect(&mut self, session: SessionId) -> SupervisorAction {
        if self.active_session == Some(session) {
            self.disconnected_session = Some(session);
            return self.suspend_running(session);
        }
        SupervisorAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnecting_the_same_desktop_resumes_only_when_unlocked() {
        let session = SessionId(11);
        let mut supervisor = SessionSupervisor::default();
        supervisor.on_event(SessionEvent::RemoteConnect(session));
        supervisor.mark_worker_running(session);
        assert_eq!(
            supervisor.on_event(SessionEvent::RemoteDisconnect(session)),
            SupervisorAction::SuspendMedia(session)
        );
        assert_eq!(
            supervisor.on_event(SessionEvent::RemoteConnect(session)),
            SupervisorAction::ResumeMedia(session)
        );
        supervisor.on_event(SessionEvent::Lock(session));
        supervisor.on_event(SessionEvent::RemoteDisconnect(session));
        assert_eq!(
            supervisor.on_event(SessionEvent::RemoteConnect(session)),
            SupervisorAction::None
        );
        assert_eq!(
            supervisor.on_event(SessionEvent::Unlock(session)),
            SupervisorAction::ResumeMedia(session)
        );
    }

    #[test]
    fn sleeping_and_locked_desktop_suspend_independently() {
        let session = SessionId(11);
        let mut supervisor = SessionSupervisor::default();
        supervisor.on_event(SessionEvent::Logon(session));
        assert_eq!(
            supervisor.mark_worker_running(session),
            SupervisorAction::None
        );
        assert_eq!(
            supervisor.suspend_for_sleep(),
            SupervisorAction::SuspendMedia(session)
        );
        assert_eq!(
            supervisor.on_event(SessionEvent::Lock(session)),
            SupervisorAction::None
        );
        assert_eq!(supervisor.resume_after_sleep(), SupervisorAction::None);
        assert_eq!(supervisor.worker_state(), WorkerState::Suspended(session));
        assert_eq!(
            supervisor.on_event(SessionEvent::Unlock(session)),
            SupervisorAction::ResumeMedia(session)
        );
        assert_eq!(supervisor.resume_after_sleep(), SupervisorAction::None);
    }

    #[test]
    fn lock_during_startup_and_stale_unlock_preserve_the_current_worker() {
        let old = SessionId(10);
        let current = SessionId(11);
        let mut supervisor = SessionSupervisor::default();
        supervisor.on_event(SessionEvent::Logon(old));
        supervisor.mark_worker_running(old);
        supervisor.on_event(SessionEvent::Logon(current));
        assert_eq!(
            supervisor.on_event(SessionEvent::Unlock(old)),
            SupervisorAction::None
        );
        assert_eq!(supervisor.worker_crashed(old), SupervisorAction::None);
        assert_eq!(supervisor.worker_state(), WorkerState::Starting(current));
        supervisor.on_event(SessionEvent::Lock(current));
        assert_eq!(
            supervisor.mark_worker_running(current),
            SupervisorAction::SuspendMedia(current)
        );
        assert_eq!(supervisor.worker_state(), WorkerState::Suspended(current));
    }

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
