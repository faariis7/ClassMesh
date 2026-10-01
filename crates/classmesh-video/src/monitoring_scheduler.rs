use std::collections::BTreeMap;

use crate::monitoring::MonitoringProfile;

pub const DEFAULT_MAX_MONITORING_SOURCES: usize = 64;
pub const DEFAULT_MONITORING_WORK_BUDGET: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonitoringSourceId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringPriority {
    Visible,
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringSchedulerConfig {
    pub max_sources: usize,
    pub max_actions_per_tick: usize,
}

impl Default for MonitoringSchedulerConfig {
    fn default() -> Self {
        Self {
            max_sources: DEFAULT_MAX_MONITORING_SOURCES,
            max_actions_per_tick: DEFAULT_MONITORING_WORK_BUDGET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringSchedulerError {
    InvalidMaxSources,
    InvalidWorkBudget,
    DuplicateSource,
    SourceLimitReached,
    UnknownSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringScheduleAction {
    CaptureThumbnail {
        source_id: MonitoringSourceId,
        profile: MonitoringProfile,
    },
    PromoteInteractive {
        source_id: MonitoringSourceId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceMode {
    Thumbnail,
    PromotionRequested,
    PromotedInteractive,
}

#[derive(Debug, Clone, Copy)]
struct SourceState {
    profile: MonitoringProfile,
    priority: MonitoringPriority,
    mode: SourceMode,
    next_due_us: Option<u64>,
}

#[derive(Debug)]
pub struct MonitoringScheduler {
    config: MonitoringSchedulerConfig,
    sources: BTreeMap<MonitoringSourceId, SourceState>,
}

impl MonitoringScheduler {
    pub fn new(_config: MonitoringSchedulerConfig) -> Result<Self, MonitoringSchedulerError> {
        todo!("Phase 9A RED: validate scheduler limits")
    }

    pub fn add_source(
        &mut self,
        _source_id: MonitoringSourceId,
        _profile: MonitoringProfile,
        _priority: MonitoringPriority,
    ) -> Result<(), MonitoringSchedulerError> {
        todo!("Phase 9A RED: add a bounded monitoring source")
    }

    pub fn remove_source(&mut self, _source_id: MonitoringSourceId) -> bool {
        todo!("Phase 9A RED: remove a monitoring source")
    }

    pub fn set_priority(
        &mut self,
        _source_id: MonitoringSourceId,
        _priority: MonitoringPriority,
    ) -> Result<(), MonitoringSchedulerError> {
        todo!("Phase 9A RED: update monitoring priority")
    }

    pub fn request_interactive_promotion(
        &mut self,
        _source_id: MonitoringSourceId,
    ) -> Result<(), MonitoringSchedulerError> {
        todo!("Phase 9A RED: request interactive promotion")
    }

    pub fn resume_thumbnail(
        &mut self,
        _source_id: MonitoringSourceId,
    ) -> Result<(), MonitoringSchedulerError> {
        todo!("Phase 9A RED: resume thumbnail scheduling")
    }

    #[must_use]
    pub fn poll(&mut self, _now_us: u64) -> Vec<MonitoringScheduleAction> {
        todo!("Phase 9A RED: schedule bounded thumbnail work")
    }

    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::MonitoringProfile;

    fn profile(fps: u8) -> MonitoringProfile {
        MonitoringProfile::for_thumbnail_at_fps(320, 180, fps).unwrap()
    }

    fn source(action: MonitoringScheduleAction) -> MonitoringSourceId {
        match action {
            MonitoringScheduleAction::CaptureThumbnail { source_id, .. }
            | MonitoringScheduleAction::PromoteInteractive { source_id } => source_id,
        }
    }

    #[test]
    fn work_budget_bounds_every_poll() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 8,
            max_actions_per_tick: 2,
        })
        .unwrap();

        for id in 1..=5 {
            scheduler
                .add_source(
                    MonitoringSourceId(id),
                    profile(2),
                    MonitoringPriority::Visible,
                )
                .unwrap();
        }

        assert_eq!(scheduler.poll(0).len(), 2);
        assert_eq!(scheduler.poll(0).len(), 2);
        assert_eq!(scheduler.poll(0).len(), 1);
    }

    #[test]
    fn visible_thumbnail_wins_when_budget_is_tight() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 4,
            max_actions_per_tick: 1,
        })
        .unwrap();
        scheduler
            .add_source(
                MonitoringSourceId(1),
                profile(2),
                MonitoringPriority::Background,
            )
            .unwrap();
        scheduler
            .add_source(
                MonitoringSourceId(2),
                profile(2),
                MonitoringPriority::Visible,
            )
            .unwrap();

        let actions = scheduler.poll(0);
        assert_eq!(actions.len(), 1);
        assert_eq!(source(actions[0]), MonitoringSourceId(2));
    }

    #[test]
    fn missed_intervals_do_not_create_bursts() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 2,
            max_actions_per_tick: 2,
        })
        .unwrap();
        scheduler
            .add_source(
                MonitoringSourceId(1),
                profile(2),
                MonitoringPriority::Visible,
            )
            .unwrap();

        assert_eq!(scheduler.poll(0).len(), 1);
        assert!(scheduler.poll(100_000).is_empty());
        assert_eq!(scheduler.poll(5_000_000).len(), 1);
        assert!(scheduler.poll(5_000_000).is_empty());
    }

    #[test]
    fn promotion_is_emitted_once_and_suppresses_thumbnail_work() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig::default()).unwrap();
        let id = MonitoringSourceId(7);
        scheduler
            .add_source(id, profile(3), MonitoringPriority::Visible)
            .unwrap();
        scheduler.request_interactive_promotion(id).unwrap();

        assert_eq!(
            scheduler.poll(0),
            vec![MonitoringScheduleAction::PromoteInteractive { source_id: id }]
        );
        assert!(scheduler.poll(1_000_000).is_empty());

        scheduler.resume_thumbnail(id).unwrap();
        assert!(matches!(
            scheduler.poll(1_000_000).as_slice(),
            [MonitoringScheduleAction::CaptureThumbnail { source_id, .. }] if *source_id == id
        ));
    }

    #[test]
    fn source_capacity_is_bounded() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 1,
            max_actions_per_tick: 1,
        })
        .unwrap();
        scheduler
            .add_source(
                MonitoringSourceId(1),
                profile(2),
                MonitoringPriority::Visible,
            )
            .unwrap();
        assert_eq!(
            scheduler.add_source(
                MonitoringSourceId(2),
                profile(2),
                MonitoringPriority::Visible,
            ),
            Err(MonitoringSchedulerError::SourceLimitReached)
        );
    }
}
