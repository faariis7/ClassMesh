use std::collections::BTreeMap;

use crate::monitoring::MonitoringProfile;

pub const DEFAULT_MAX_MONITORING_SOURCES: usize = 64;
pub const DEFAULT_MONITORING_WORK_BUDGET: usize = 4;
// When background work stays ready under continuous visible load, reserve one
// opportunity on the fourth capacity-bearing poll. Promotions always take precedence.
const MAX_BACKGROUND_SKIPPED_POLLS: u8 = 3;

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
    background_skipped_polls: u8,
}

impl MonitoringScheduler {
    pub fn new(config: MonitoringSchedulerConfig) -> Result<Self, MonitoringSchedulerError> {
        if config.max_sources == 0 {
            return Err(MonitoringSchedulerError::InvalidMaxSources);
        }
        if config.max_actions_per_tick == 0 {
            return Err(MonitoringSchedulerError::InvalidWorkBudget);
        }

        Ok(Self {
            config,
            sources: BTreeMap::new(),
            background_skipped_polls: 0,
        })
    }

    pub fn add_source(
        &mut self,
        source_id: MonitoringSourceId,
        profile: MonitoringProfile,
        priority: MonitoringPriority,
    ) -> Result<(), MonitoringSchedulerError> {
        if self.sources.contains_key(&source_id) {
            return Err(MonitoringSchedulerError::DuplicateSource);
        }
        if self.sources.len() >= self.config.max_sources {
            return Err(MonitoringSchedulerError::SourceLimitReached);
        }

        self.sources.insert(
            source_id,
            SourceState {
                profile,
                priority,
                mode: SourceMode::Thumbnail,
                next_due_us: None,
            },
        );
        Ok(())
    }

    pub fn remove_source(&mut self, source_id: MonitoringSourceId) -> bool {
        self.sources.remove(&source_id).is_some()
    }

    pub fn set_priority(
        &mut self,
        source_id: MonitoringSourceId,
        priority: MonitoringPriority,
    ) -> Result<(), MonitoringSchedulerError> {
        let state = self
            .sources
            .get_mut(&source_id)
            .ok_or(MonitoringSchedulerError::UnknownSource)?;
        state.priority = priority;
        Ok(())
    }

    pub fn request_interactive_promotion(
        &mut self,
        source_id: MonitoringSourceId,
    ) -> Result<(), MonitoringSchedulerError> {
        let state = self
            .sources
            .get_mut(&source_id)
            .ok_or(MonitoringSchedulerError::UnknownSource)?;
        if state.mode == SourceMode::Thumbnail {
            state.mode = SourceMode::PromotionRequested;
            state.next_due_us = None;
        }
        Ok(())
    }

    pub fn resume_thumbnail(
        &mut self,
        source_id: MonitoringSourceId,
    ) -> Result<(), MonitoringSchedulerError> {
        let state = self
            .sources
            .get_mut(&source_id)
            .ok_or(MonitoringSchedulerError::UnknownSource)?;
        state.mode = SourceMode::Thumbnail;
        state.next_due_us = None;
        Ok(())
    }

    #[must_use]
    pub fn poll(&mut self, now_us: u64) -> Vec<MonitoringScheduleAction> {
        let mut actions = Vec::with_capacity(self.config.max_actions_per_tick);

        let promotions: Vec<MonitoringSourceId> = self
            .sources
            .iter()
            .filter_map(|(&source_id, state)| {
                (state.mode == SourceMode::PromotionRequested).then_some(source_id)
            })
            .collect();
        for source_id in promotions
            .into_iter()
            .take(self.config.max_actions_per_tick)
        {
            let Some(state) = self.sources.get_mut(&source_id) else {
                continue;
            };
            state.mode = SourceMode::PromotedInteractive;
            state.next_due_us = None;
            actions.push(MonitoringScheduleAction::PromoteInteractive { source_id });
        }

        let remaining = self
            .config
            .max_actions_per_tick
            .saturating_sub(actions.len());
        if remaining == 0 {
            return actions;
        }

        let mut due: Vec<(u8, u64, MonitoringSourceId)> = self
            .sources
            .iter()
            .filter_map(|(&source_id, state)| {
                if state.mode != SourceMode::Thumbnail {
                    return None;
                }
                let due_at = state.next_due_us.unwrap_or(0);
                if now_us < due_at {
                    return None;
                }
                let priority_rank = match state.priority {
                    MonitoringPriority::Visible => 0,
                    MonitoringPriority::Background => 1,
                };
                Some((priority_rank, due_at, source_id))
            })
            .collect();
        due.sort_unstable();
        let background_due = due.iter().any(|(rank, _, _)| *rank == 1);
        // Reserve at most one action to guarantee bounded progress for a due
        // background thumbnail. Priority still governs the other budget slots.
        let reserved_background = if self.background_skipped_polls >= MAX_BACKGROUND_SKIPPED_POLLS {
            due.iter()
                .position(|(rank, _, _)| *rank == 1)
                .map(|index| due.remove(index))
        } else {
            None
        };
        let mut selected = Vec::with_capacity(remaining);
        if let Some(entry) = reserved_background {
            selected.push(entry);
        }
        selected.extend(due.into_iter().take(remaining - selected.len()));
        let background_selected = selected.iter().any(|(rank, _, _)| *rank == 1);
        self.background_skipped_polls = if background_due && !background_selected {
            self.background_skipped_polls
                .saturating_add(1)
                .min(MAX_BACKGROUND_SKIPPED_POLLS)
        } else {
            0
        };

        for (_, _, source_id) in selected {
            let Some(state) = self.sources.get_mut(&source_id) else {
                continue;
            };
            let interval_us = 1_000_000 / u64::from(state.profile.fps());
            state.next_due_us = Some(now_us.saturating_add(interval_us));
            actions.push(MonitoringScheduleAction::CaptureThumbnail {
                source_id,
                profile: state.profile,
            });
        }

        actions
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
    fn perpetually_due_visible_thumbnail_cannot_starve_background_forever() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 2,
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
        scheduler
            .add_source(
                MonitoringSourceId(2),
                profile(2),
                MonitoringPriority::Background,
            )
            .unwrap();
        let selected: Vec<_> = (0..4)
            .map(|tick| source(scheduler.poll(tick * 500_000)[0]))
            .collect();
        assert_eq!(
            selected[0],
            MonitoringSourceId(1),
            "visible must win initially"
        );
        assert!(
            selected.contains(&MonitoringSourceId(2)),
            "background must receive a bounded share despite continuous visible demand: {selected:?}"
        );
    }

    #[test]
    fn fair_background_allocation_rotates_among_multiple_due_sources() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 4,
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
        for id in 2..=4 {
            scheduler
                .add_source(
                    MonitoringSourceId(id),
                    profile(2),
                    MonitoringPriority::Background,
                )
                .unwrap();
        }
        let selected: Vec<_> = (0..16)
            .map(|tick| source(scheduler.poll(tick * 500_000)[0]))
            .collect();
        for id in 2..=4 {
            assert!(
                selected.contains(&MonitoringSourceId(id)),
                "background source {id} must eventually run: {selected:?}"
            );
        }
    }

    #[test]
    fn full_monitoring_grid_gets_bounded_background_progress_without_exceeding_work_budget() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 40,
            max_actions_per_tick: 4,
        })
        .unwrap();
        for id in 1..=32 {
            scheduler
                .add_source(
                    MonitoringSourceId(id),
                    profile(2),
                    MonitoringPriority::Visible,
                )
                .unwrap();
        }
        for id in 33..=40 {
            scheduler
                .add_source(
                    MonitoringSourceId(id),
                    profile(2),
                    MonitoringPriority::Background,
                )
                .unwrap();
        }
        let mut visible_actions = 0;
        let mut background_ids = std::collections::BTreeSet::new();
        for tick in 0..40 {
            let actions = scheduler.poll(tick * 500_000);
            assert!(actions.len() <= 4);
            for action in actions {
                let id = source(action).0;
                if id <= 32 {
                    visible_actions += 1;
                } else {
                    background_ids.insert(id);
                }
            }
        }
        assert_eq!(background_ids, (33..=40).collect());
        assert!(
            visible_actions > 80,
            "visible stream must keep most throughput"
        );
    }

    #[test]
    fn interactive_promotion_preempts_due_background_fairness_slot() {
        let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
            max_sources: 3,
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
        scheduler
            .add_source(
                MonitoringSourceId(2),
                profile(2),
                MonitoringPriority::Background,
            )
            .unwrap();
        scheduler
            .add_source(
                MonitoringSourceId(3),
                profile(2),
                MonitoringPriority::Visible,
            )
            .unwrap();
        for tick in 0..3 {
            assert_eq!(scheduler.poll(tick * 500_000).len(), 1);
        }
        scheduler
            .request_interactive_promotion(MonitoringSourceId(3))
            .unwrap();
        assert_eq!(
            scheduler.poll(1_500_000),
            vec![MonitoringScheduleAction::PromoteInteractive {
                source_id: MonitoringSourceId(3)
            }]
        );
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
