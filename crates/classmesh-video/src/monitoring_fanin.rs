use std::collections::BTreeMap;

use crate::distributor::SharedEncodedFrame;
use crate::monitoring_scheduler::MonitoringSourceId;

pub const DEFAULT_MAX_MONITORING_FANIN_SOURCES: usize = 64;
pub const DEFAULT_MONITORING_DRAIN_BUDGET: usize = 8;

#[derive(Debug, Clone)]
pub struct MonitoringThumbnailUpdate {
    source_id: MonitoringSourceId,
    frame: SharedEncodedFrame,
}

impl MonitoringThumbnailUpdate {
    #[must_use]
    pub const fn new(source_id: MonitoringSourceId, frame: SharedEncodedFrame) -> Self {
        Self { source_id, frame }
    }

    #[must_use]
    pub const fn source_id(&self) -> MonitoringSourceId {
        self.source_id
    }

    #[must_use]
    pub const fn frame(&self) -> &SharedEncodedFrame {
        &self.frame
    }

    #[must_use]
    pub fn into_frame(self) -> SharedEncodedFrame {
        self.frame
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringFanInConfig {
    pub max_sources: usize,
    pub max_updates_per_drain: usize,
}

impl Default for MonitoringFanInConfig {
    fn default() -> Self {
        Self {
            max_sources: DEFAULT_MAX_MONITORING_FANIN_SOURCES,
            max_updates_per_drain: DEFAULT_MONITORING_DRAIN_BUDGET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringFanInError {
    InvalidMaxSources,
    InvalidDrainBudget,
    SourceLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringFanInPush {
    Inserted,
    Replaced,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonitoringFanInStats {
    pub pending_sources: usize,
    pub accepted_updates: u64,
    pub superseded_updates: u64,
    pub rejected_updates: u64,
}

#[derive(Debug)]
pub struct MonitoringFanIn {
    config: MonitoringFanInConfig,
    pending: BTreeMap<MonitoringSourceId, SharedEncodedFrame>,
    cursor: Option<MonitoringSourceId>,
    accepted_updates: u64,
    superseded_updates: u64,
    rejected_updates: u64,
}

impl MonitoringFanIn {
    pub fn new(config: MonitoringFanInConfig) -> Result<Self, MonitoringFanInError> {
        if config.max_sources == 0 {
            return Err(MonitoringFanInError::InvalidMaxSources);
        }
        if config.max_updates_per_drain == 0 {
            return Err(MonitoringFanInError::InvalidDrainBudget);
        }

        Ok(Self {
            config,
            pending: BTreeMap::new(),
            cursor: None,
            accepted_updates: 0,
            superseded_updates: 0,
            rejected_updates: 0,
        })
    }

    pub fn push(
        &mut self,
        update: MonitoringThumbnailUpdate,
    ) -> Result<MonitoringFanInPush, MonitoringFanInError> {
        let source_id = update.source_id();

        if self.pending.contains_key(&source_id) {
            self.pending.insert(source_id, update.into_frame());
            self.accepted_updates = self.accepted_updates.saturating_add(1);
            self.superseded_updates = self.superseded_updates.saturating_add(1);
            return Ok(MonitoringFanInPush::Replaced);
        }

        if self.pending.len() >= self.config.max_sources {
            self.rejected_updates = self.rejected_updates.saturating_add(1);
            return Err(MonitoringFanInError::SourceLimitReached);
        }

        self.pending.insert(source_id, update.into_frame());
        self.accepted_updates = self.accepted_updates.saturating_add(1);
        Ok(MonitoringFanInPush::Inserted)
    }

    #[must_use]
    pub fn drain(&mut self) -> Vec<MonitoringThumbnailUpdate> {
        if self.pending.is_empty() {
            return Vec::new();
        }

        let keys: Vec<MonitoringSourceId> = self.pending.keys().copied().collect();
        let start = self
            .cursor
            .map_or(0, |cursor| keys.partition_point(|source_id| *source_id <= cursor));
        let selected: Vec<MonitoringSourceId> = keys[start..]
            .iter()
            .chain(keys[..start].iter())
            .copied()
            .take(self.config.max_updates_per_drain)
            .collect();

        let mut drained = Vec::with_capacity(selected.len());
        for source_id in selected {
            let Some(frame) = self.pending.remove(&source_id) else {
                continue;
            };
            self.cursor = Some(source_id);
            drained.push(MonitoringThumbnailUpdate::new(source_id, frame));
        }
        drained
    }

    #[must_use]
    pub fn stats(&self) -> MonitoringFanInStats {
        MonitoringFanInStats {
            pending_sources: self.pending.len(),
            accepted_updates: self.accepted_updates,
            superseded_updates: self.superseded_updates,
            rejected_updates: self.rejected_updates,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{Codec, EncodedFrameMeta};

    use super::*;

    fn update(source: u64, frame_id: u64) -> MonitoringThumbnailUpdate {
        MonitoringThumbnailUpdate::new(
            MonitoringSourceId(source),
            SharedEncodedFrame::new(
                EncodedFrameMeta {
                    frame_id,
                    timestamp_us: frame_id * 1_000,
                    keyframe: frame_id == 1,
                },
                Codec::H264,
                vec![u8::try_from(frame_id).unwrap_or(0); 16],
            ),
        )
    }

    #[test]
    fn source_count_is_bounded_without_evicting_existing_students() {
        let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig {
            max_sources: 2,
            max_updates_per_drain: 2,
        })
        .unwrap();

        assert_eq!(fanin.push(update(1, 1)), Ok(MonitoringFanInPush::Inserted));
        assert_eq!(fanin.push(update(2, 1)), Ok(MonitoringFanInPush::Inserted));
        assert_eq!(
            fanin.push(update(3, 1)),
            Err(MonitoringFanInError::SourceLimitReached)
        );
        assert_eq!(fanin.stats().pending_sources, 2);
        assert_eq!(fanin.stats().rejected_updates, 1);
    }

    #[test]
    fn repeated_student_updates_replace_stale_frame_without_queue_growth() {
        let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig::default()).unwrap();
        fanin.push(update(7, 1)).unwrap();
        fanin.push(update(7, 2)).unwrap();
        fanin.push(update(7, 3)).unwrap();

        assert_eq!(fanin.stats().pending_sources, 1);
        assert_eq!(fanin.stats().superseded_updates, 2);
        let drained = fanin.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].source_id(), MonitoringSourceId(7));
        assert_eq!(drained[0].frame().meta.frame_id, 3);
    }

    #[test]
    fn drain_budget_is_hard_bounded() {
        let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig {
            max_sources: 8,
            max_updates_per_drain: 2,
        })
        .unwrap();
        for source in 1..=5 {
            fanin.push(update(source, 1)).unwrap();
        }

        assert_eq!(fanin.drain().len(), 2);
        assert_eq!(fanin.drain().len(), 2);
        assert_eq!(fanin.drain().len(), 1);
    }

    #[test]
    fn drain_rotates_across_sources_instead_of_starving_high_ids() {
        let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig {
            max_sources: 4,
            max_updates_per_drain: 1,
        })
        .unwrap();
        for source in 1..=3 {
            fanin.push(update(source, 1)).unwrap();
        }

        assert_eq!(fanin.drain()[0].source_id(), MonitoringSourceId(1));
        fanin.push(update(1, 2)).unwrap();
        assert_eq!(fanin.drain()[0].source_id(), MonitoringSourceId(2));
        fanin.push(update(2, 2)).unwrap();
        assert_eq!(fanin.drain()[0].source_id(), MonitoringSourceId(3));
    }

    #[test]
    fn replacement_does_not_copy_encoded_payload() {
        let mut fanin = MonitoringFanIn::new(MonitoringFanInConfig::default()).unwrap();
        let original = update(4, 10);
        let allocation = Arc::clone(&original.frame().data);
        fanin.push(original).unwrap();

        let drained = fanin.drain();
        assert!(Arc::ptr_eq(&allocation, &drained[0].frame().data));
    }

    #[test]
    fn invalid_limits_fail_closed() {
        assert!(matches!(
            MonitoringFanIn::new(MonitoringFanInConfig {
                max_sources: 0,
                max_updates_per_drain: 1,
            }),
            Err(MonitoringFanInError::InvalidMaxSources)
        ));
        assert!(matches!(
            MonitoringFanIn::new(MonitoringFanInConfig {
                max_sources: 1,
                max_updates_per_drain: 0,
            }),
            Err(MonitoringFanInError::InvalidDrainBudget)
        ));
    }
}
