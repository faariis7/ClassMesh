use crate::{ControlState, MediaState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    Offline,
    Connecting,
    Online,
    ControlRecovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceHealth {
    pub presence: PresenceState,
    pub media: MediaState,
    pub worker_ready: bool,
    pub service_ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPolicy {
    pub suspect_after_us: u64,
    pub offline_after_us: u64,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            suspect_after_us: 6_000_000,
            offline_after_us: 10_000_000,
        }
    }
}

#[derive(Debug)]
pub struct PresenceTracker {
    control: ControlState,
    media: MediaState,
    service_ready: bool,
    worker_ready: bool,
    last_heartbeat_us: Option<u64>,
    policy: HeartbeatPolicy,
}

impl PresenceTracker {
    #[must_use]
    pub const fn new(policy: HeartbeatPolicy) -> Self {
        Self {
            control: ControlState::Disconnected,
            media: MediaState::Idle,
            service_ready: false,
            worker_ready: false,
            last_heartbeat_us: None,
            policy,
        }
    }

    pub fn set_control_state(&mut self, control: ControlState) {
        self.control = control;
    }

    pub fn set_media_state(&mut self, media: MediaState) {
        self.media = media;
    }

    pub fn set_service_ready(&mut self, ready: bool) {
        self.service_ready = ready;
    }

    pub fn set_worker_ready(&mut self, ready: bool) {
        self.worker_ready = ready;
    }

    pub fn heartbeat(&mut self, now_us: u64) {
        self.last_heartbeat_us = Some(now_us);
        self.control = ControlState::Authenticated;
    }

    #[must_use]
    pub fn health(&self, now_us: u64) -> DeviceHealth {
        let presence = match self.control {
            ControlState::Disconnected => PresenceState::Offline,
            ControlState::Connecting => PresenceState::Connecting,
            ControlState::Recovering => PresenceState::ControlRecovering,
            ControlState::Authenticated => match self.last_heartbeat_us {
                None => PresenceState::Connecting,
                Some(last)
                    if now_us.saturating_sub(last) >= self.policy.offline_after_us =>
                {
                    PresenceState::Offline
                }
                Some(last)
                    if now_us.saturating_sub(last) >= self.policy.suspect_after_us =>
                {
                    PresenceState::ControlRecovering
                }
                Some(_) => PresenceState::Online,
            },
        };

        DeviceHealth {
            presence,
            media: self.media,
            worker_ready: self.worker_ready,
            service_ready: self.service_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_media_does_not_make_authenticated_device_offline() {
        let mut tracker = PresenceTracker::new(HeartbeatPolicy::default());
        tracker.set_service_ready(true);
        tracker.heartbeat(1_000_000);
        tracker.set_media_state(MediaState::Recovering);
        let health = tracker.health(2_000_000);
        assert_eq!(health.presence, PresenceState::Online);
        assert_eq!(health.media, MediaState::Recovering);
    }

    #[test]
    fn stale_control_heartbeat_eventually_marks_device_offline() {
        let mut tracker = PresenceTracker::new(HeartbeatPolicy {
            suspect_after_us: 5,
            offline_after_us: 10,
        });
        tracker.heartbeat(100);
        assert_eq!(tracker.health(104).presence, PresenceState::Online);
        assert_eq!(tracker.health(106).presence, PresenceState::ControlRecovering);
        assert_eq!(tracker.health(110).presence, PresenceState::Offline);
    }

    #[test]
    fn worker_can_be_down_while_service_and_device_remain_online() {
        let mut tracker = PresenceTracker::new(HeartbeatPolicy::default());
        tracker.set_service_ready(true);
        tracker.set_worker_ready(false);
        tracker.heartbeat(0);
        let health = tracker.health(1);
        assert_eq!(health.presence, PresenceState::Online);
        assert!(health.service_ready);
        assert!(!health.worker_ready);
    }
}
