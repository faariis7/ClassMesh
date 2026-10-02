use std::collections::BTreeSet;
use std::fmt;

use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::monitoring::MonitoringProfile;
use classmesh_video::monitoring_fanin::{
    MonitoringFanIn, MonitoringFanInConfig, MonitoringFanInError, MonitoringThumbnailUpdate,
};
use classmesh_video::monitoring_scheduler::{
    MonitoringPriority, MonitoringScheduleAction, MonitoringScheduler, MonitoringSchedulerConfig,
    MonitoringSchedulerError, MonitoringSourceId,
};
use classmesh_video::{Codec, EncodedFrameMeta};

pub const MONITORING_GRID_SCALE_POINTS: &[usize] = &[5, 10, 20, 30];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringGridBenchmarkConfig {
    pub sources: usize,
    pub rounds: u32,
    pub scheduler_budget: usize,
    pub drain_budget: usize,
}

impl Default for MonitoringGridBenchmarkConfig {
    fn default() -> Self {
        Self {
            sources: 30,
            rounds: 30,
            scheduler_budget: 4,
            drain_budget: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringGridBenchmarkError {
    UnsupportedSourceCount(usize),
    InvalidRounds,
    InvalidSchedulerBudget,
    InvalidDrainBudget,
    Scheduler(MonitoringSchedulerError),
    FanIn(MonitoringFanInError),
    FairnessViolation,
    PromotionInvariant,
    BudgetViolation,
}

impl fmt::Display for MonitoringGridBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSourceCount(count) => write!(
                formatter,
                "unsupported monitoring source count {count}; expected 5, 10, 20, or 30"
            ),
            Self::InvalidRounds => write!(formatter, "rounds must be non-zero"),
            Self::InvalidSchedulerBudget => write!(formatter, "scheduler budget must be non-zero"),
            Self::InvalidDrainBudget => write!(formatter, "drain budget must be non-zero"),
            Self::Scheduler(error) => write!(formatter, "monitoring scheduler error: {error:?}"),
            Self::FanIn(error) => write!(formatter, "monitoring fan-in error: {error:?}"),
            Self::FairnessViolation => write!(formatter, "not every monitoring source was observed"),
            Self::PromotionInvariant => write!(formatter, "interactive promotion invariant failed"),
            Self::BudgetViolation => write!(formatter, "bounded monitoring work budget was exceeded"),
        }
    }
}

impl std::error::Error for MonitoringGridBenchmarkError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringGridBenchmarkReport {
    pub sources: usize,
    pub rounds: u32,
    pub profile_width: u16,
    pub profile_height: u16,
    pub profile_fps: u8,
    pub scheduler_budget: usize,
    pub drain_budget: usize,
    pub max_scheduler_actions: usize,
    pub max_drain_updates: usize,
    pub peak_pending_sources: usize,
    pub superseded_updates: u64,
    pub rejected_updates: u64,
    pub promotion_actions: u64,
    pub observed_sources: usize,
}

pub fn run_monitoring_grid_benchmark(
    config: MonitoringGridBenchmarkConfig,
) -> Result<MonitoringGridBenchmarkReport, MonitoringGridBenchmarkError> {
    validate_config(config)?;

    let profile =
        MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).expect("static profile is valid");
    let mut scheduler = MonitoringScheduler::new(MonitoringSchedulerConfig {
        max_sources: config.sources,
        max_actions_per_tick: config.scheduler_budget,
    })
    .map_err(MonitoringGridBenchmarkError::Scheduler)?;
    let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig {
        max_sources: config.sources,
        max_updates_per_drain: config.drain_budget,
    })
    .map_err(MonitoringGridBenchmarkError::FanIn)?;

    for source in 1..=config.sources {
        scheduler
            .add_source(
                MonitoringSourceId(source as u64),
                profile,
                MonitoringPriority::Visible,
            )
            .map_err(MonitoringGridBenchmarkError::Scheduler)?;
    }

    let promoted = MonitoringSourceId(1);
    let promotion_round = config.rounds / 2;
    let mut promotion_actions = 0_u64;
    let mut frame_id = 1_u64;
    let mut max_scheduler_actions = 0_usize;
    let mut max_drain_updates = 0_usize;
    let mut peak_pending_sources = 0_usize;
    let mut observed = BTreeSet::new();

    for round in 0..config.rounds {
        if round == promotion_round {
            scheduler
                .request_interactive_promotion(promoted)
                .map_err(MonitoringGridBenchmarkError::Scheduler)?;
        }

        let now_us = u64::from(round).saturating_mul(333_334);
        loop {
            let actions = scheduler.poll(now_us);
            if actions.is_empty() {
                break;
            }
            max_scheduler_actions = max_scheduler_actions.max(actions.len());
            if actions.len() > config.scheduler_budget {
                return Err(MonitoringGridBenchmarkError::BudgetViolation);
            }

            for action in actions {
                match action {
                    MonitoringScheduleAction::CaptureThumbnail { source_id, .. } => {
                        fanin
                            .push(update(source_id, frame_id))
                            .map_err(MonitoringGridBenchmarkError::FanIn)?;
                        frame_id = frame_id.saturating_add(1);

                        // One deliberately superseded source proves latest-only behavior without
                        // growing a per-source queue.
                        if source_id == MonitoringSourceId(2) {
                            fanin
                                .push(update(source_id, frame_id))
                                .map_err(MonitoringGridBenchmarkError::FanIn)?;
                            frame_id = frame_id.saturating_add(1);
                        }
                    }
                    MonitoringScheduleAction::PromoteInteractive { source_id } => {
                        if source_id != promoted {
                            return Err(MonitoringGridBenchmarkError::PromotionInvariant);
                        }
                        promotion_actions = promotion_actions.saturating_add(1);
                    }
                }
            }

            peak_pending_sources = peak_pending_sources.max(fanin.stats().pending_sources);
            drain_all(
                &mut fanin,
                config.drain_budget,
                &mut max_drain_updates,
                &mut observed,
            )?;
        }

        if round == promotion_round {
            scheduler
                .resume_thumbnail(promoted)
                .map_err(MonitoringGridBenchmarkError::Scheduler)?;
        }
    }

    drain_all(
        &mut fanin,
        config.drain_budget,
        &mut max_drain_updates,
        &mut observed,
    )?;

    if promotion_actions != 1 {
        return Err(MonitoringGridBenchmarkError::PromotionInvariant);
    }
    if observed.len() != config.sources {
        return Err(MonitoringGridBenchmarkError::FairnessViolation);
    }

    let stats = fanin.stats();
    Ok(MonitoringGridBenchmarkReport {
        sources: config.sources,
        rounds: config.rounds,
        profile_width: profile.width(),
        profile_height: profile.height(),
        profile_fps: profile.fps(),
        scheduler_budget: config.scheduler_budget,
        drain_budget: config.drain_budget,
        max_scheduler_actions,
        max_drain_updates,
        peak_pending_sources,
        superseded_updates: stats.superseded_updates,
        rejected_updates: stats.rejected_updates,
        promotion_actions,
        observed_sources: observed.len(),
    })
}

fn validate_config(config: MonitoringGridBenchmarkConfig) -> Result<(), MonitoringGridBenchmarkError> {
    if !MONITORING_GRID_SCALE_POINTS.contains(&config.sources) {
        return Err(MonitoringGridBenchmarkError::UnsupportedSourceCount(
            config.sources,
        ));
    }
    if config.rounds == 0 {
        return Err(MonitoringGridBenchmarkError::InvalidRounds);
    }
    if config.scheduler_budget == 0 {
        return Err(MonitoringGridBenchmarkError::InvalidSchedulerBudget);
    }
    if config.drain_budget == 0 {
        return Err(MonitoringGridBenchmarkError::InvalidDrainBudget);
    }
    Ok(())
}

fn update(source_id: MonitoringSourceId, frame_id: u64) -> MonitoringThumbnailUpdate {
    MonitoringThumbnailUpdate::new(
        source_id,
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id,
                timestamp_us: frame_id.saturating_mul(1_000),
                keyframe: true,
            },
            Codec::H264,
            vec![u8::try_from(frame_id).unwrap_or(0); 64],
        ),
    )
}

fn drain_all(
    fanin: &mut MonitoringFanIn,
    drain_budget: usize,
    max_drain_updates: &mut usize,
    observed: &mut BTreeSet<MonitoringSourceId>,
) -> Result<(), MonitoringGridBenchmarkError> {
    loop {
        let drained = fanin.drain();
        if drained.is_empty() {
            break;
        }
        *max_drain_updates = (*max_drain_updates).max(drained.len());
        if drained.len() > drain_budget {
            return Err(MonitoringGridBenchmarkError::BudgetViolation);
        }
        for update in drained {
            observed.insert(update.source_id());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_scale_points_keep_work_bounded_and_fair() {
        for sources in MONITORING_GRID_SCALE_POINTS {
            let report = run_monitoring_grid_benchmark(MonitoringGridBenchmarkConfig {
                sources: *sources,
                rounds: 8,
                scheduler_budget: 4,
                drain_budget: 8,
            })
            .unwrap();
            assert_eq!(report.observed_sources, *sources);
            assert!(report.max_scheduler_actions <= 4);
            assert!(report.max_drain_updates <= 8);
            assert!(report.peak_pending_sources <= *sources);
            assert!(report.superseded_updates > 0);
            assert_eq!(report.rejected_updates, 0);
            assert_eq!(report.promotion_actions, 1);
            assert_eq!(
                (report.profile_width, report.profile_height, report.profile_fps),
                (320, 180, 3)
            );
        }
    }

    #[test]
    fn invalid_scale_and_budgets_fail_closed() {
        assert!(matches!(
            run_monitoring_grid_benchmark(MonitoringGridBenchmarkConfig {
                sources: 6,
                ..MonitoringGridBenchmarkConfig::default()
            }),
            Err(MonitoringGridBenchmarkError::UnsupportedSourceCount(6))
        ));
        assert!(matches!(
            run_monitoring_grid_benchmark(MonitoringGridBenchmarkConfig {
                scheduler_budget: 0,
                ..MonitoringGridBenchmarkConfig::default()
            }),
            Err(MonitoringGridBenchmarkError::InvalidSchedulerBudget)
        ));
    }
}
