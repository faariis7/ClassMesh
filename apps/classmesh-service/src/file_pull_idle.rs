//! Monotonic idle recovery for a live Service-owned file pull.
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilePullIdleLease {
    last_progress: Instant,
}

impl FilePullIdleLease {
    pub(crate) fn new(now: Instant) -> Self {
        Self { last_progress: now }
    }

    pub(crate) fn refresh(&mut self, now: Instant) {
        if now > self.last_progress {
            self.last_progress = now;
        }
    }

    pub(crate) fn expired(&self, now: Instant, limit: Duration) -> bool {
        now.saturating_duration_since(self.last_progress) >= limit
    }
}
/// Only genuine, monotonically advancing acknowledgements may keep a
/// Service-owned file source alive. The peer cannot claim Completed until
/// this Service actually emitted Finish for the exact declared byte total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilePullAckLedger {
    total_size: u64,
    last_offset: u64,
    expected_chunk_end: Option<u64>,
    accepted: bool,
    finish_sent: bool,
    completed: bool,
}

impl FilePullAckLedger {
    pub(crate) const fn new(total_size: u64) -> Self {
        Self {
            total_size,
            last_offset: 0,
            expected_chunk_end: None,
            accepted: false,
            finish_sent: false,
            completed: false,
        }
    }

    pub(crate) fn accept_status(
        &mut self,
        state: classmesh_protocol::control_wire::FileTransferState,
        next_offset: u64,
    ) -> bool {
        use classmesh_protocol::control_wire::FileTransferState;
        if self.completed || self.total_size == 0 {
            return false;
        }
        match state {
            FileTransferState::Accepted if !self.accepted && next_offset == 0 => {
                self.accepted = true;
                true
            }
            FileTransferState::Progress
                if self.accepted
                    && !self.finish_sent
                    && self.expected_chunk_end == Some(next_offset)
                    && next_offset > self.last_offset
                    && next_offset <= self.total_size =>
            {
                self.last_offset = next_offset;
                self.expected_chunk_end = None;
                true
            }
            FileTransferState::Completed if self.finish_sent && next_offset == self.total_size => {
                self.completed = true;
                true
            }
            _ => false,
        }
    }

    /// Call only for a real chunk produced by FileTransferSourceSession.
    /// An authenticated peer must ACK precisely this chunk end, not an
    /// invented offset that jumps past bytes the Service never sent.
    pub(crate) fn record_chunk_end(&mut self, chunk_end: u64) -> bool {
        if self.accepted
            && !self.finish_sent
            && !self.completed
            && self.expected_chunk_end.is_none()
            && chunk_end > self.last_offset
            && chunk_end <= self.total_size
        {
            self.expected_chunk_end = Some(chunk_end);
            true
        } else {
            false
        }
    }

    pub(crate) fn mark_finish_sent(&mut self) -> bool {
        if self.accepted
            && !self.completed
            && !self.finish_sent
            && self.last_offset == self.total_size
            && self.expected_chunk_end.is_none()
        {
            self.finish_sent = true;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FilePullIdleLease;
    use std::time::{Duration, Instant};

    const IDLE_LIMIT: Duration = Duration::from_secs(60);

    #[test]
    fn idle_pull_expires_on_boundary_without_network_progress() {
        let started = Instant::now();
        let lease = FilePullIdleLease::new(started);
        assert!(!lease.expired(started + IDLE_LIMIT - Duration::from_nanos(1), IDLE_LIMIT));
        assert!(lease.expired(started + IDLE_LIMIT, IDLE_LIMIT));
    }

    #[test]
    fn accepted_progress_refreshes_the_idle_window() {
        let started = Instant::now();
        let mut lease = FilePullIdleLease::new(started);
        lease.refresh(started + Duration::from_secs(30));
        assert!(!lease.expired(started + Duration::from_secs(89), IDLE_LIMIT));
        assert!(lease.expired(started + Duration::from_secs(90), IDLE_LIMIT));
    }

    #[test]
    fn duplicated_or_stalled_ack_never_refreshes_a_pending_file_pull() {
        use super::FilePullAckLedger;
        use classmesh_protocol::control_wire::FileTransferState as State;
        let mut acks = FilePullAckLedger::new(7);
        assert!(!acks.accept_status(State::Progress, 1), "must accept first");
        assert!(
            !acks.accept_status(State::Completed, 7),
            "cannot fake completion"
        );
        assert!(acks.accept_status(State::Accepted, 0));
        assert!(
            !acks.accept_status(State::Accepted, 0),
            "cannot replay Accepted"
        );
        assert!(
            !acks.accept_status(State::Progress, 0),
            "no progress from zero"
        );
        assert!(
            !acks.accept_status(State::Progress, 3),
            "untransmitted offset cannot be acknowledged"
        );
        assert!(acks.record_chunk_end(3));
        assert!(
            !acks.accept_status(State::Progress, 4),
            "ack cannot skip the actual chunk"
        );
        assert!(acks.accept_status(State::Progress, 3));
        assert!(
            !acks.accept_status(State::Progress, 3),
            "replayed offset is not progress"
        );
        assert!(
            !acks.accept_status(State::Progress, 2),
            "regression is not progress"
        );
        assert!(
            !acks.accept_status(State::Progress, 8),
            "cannot pass declared total"
        );
        assert!(!acks.accept_status(State::Completed, 7), "finish not sent");
        assert!(acks.record_chunk_end(7));
        assert!(acks.accept_status(State::Progress, 7));
        assert!(acks.mark_finish_sent());
        assert!(
            !acks.accept_status(State::Progress, 7),
            "cannot replay Finish indefinitely"
        );
        assert!(acks.accept_status(State::Completed, 7));
        assert!(
            !acks.accept_status(State::Completed, 7),
            "cannot complete twice"
        );
    }

    #[test]
    fn finalization_is_not_allowed_until_exact_total_is_acknowledged() {
        use super::FilePullAckLedger;
        use classmesh_protocol::control_wire::FileTransferState as State;
        let mut acks = FilePullAckLedger::new(64);
        assert!(!acks.mark_finish_sent());
        assert!(acks.accept_status(State::Accepted, 0));
        assert!(acks.record_chunk_end(32));
        assert!(acks.accept_status(State::Progress, 32));
        assert!(!acks.mark_finish_sent());
        assert!(acks.record_chunk_end(64));
        assert!(acks.accept_status(State::Progress, 64));
        assert!(acks.mark_finish_sent());
        assert!(!acks.accept_status(State::Completed, 63));
        assert!(acks.accept_status(State::Completed, 64));
    }

    #[test]
    fn earlier_clock_sample_cannot_roll_back_a_valid_progress_time() {
        let started = Instant::now();
        let mut lease = FilePullIdleLease::new(started);
        lease.refresh(started + Duration::from_secs(30));
        lease.refresh(started + Duration::from_secs(20));
        assert!(!lease.expired(started + Duration::from_secs(89), IDLE_LIMIT));
        assert!(lease.expired(started + Duration::from_secs(90), IDLE_LIMIT));
    }
}
