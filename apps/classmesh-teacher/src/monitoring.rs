use classmesh_video::monitoring_fanin::{
    MonitoringFanIn, MonitoringFanInConfig, MonitoringFanInError, MonitoringFanInPush,
    MonitoringFanInStats, MonitoringThumbnailUpdate,
};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

#[derive(Debug)]
pub struct TeacherMonitoringAggregator {
    fanin: MonitoringFanIn,
}

impl TeacherMonitoringAggregator {
    pub fn new(config: MonitoringFanInConfig) -> Result<Self, MonitoringFanInError> {
        Ok(Self {
            fanin: MonitoringFanIn::new(config)?,
        })
    }

    pub fn accept(
        &mut self,
        update: MonitoringThumbnailUpdate,
    ) -> Result<MonitoringFanInPush, MonitoringFanInError> {
        self.fanin.push(update)
    }

    pub fn discard(&mut self, source_id: MonitoringSourceId) -> bool {
        self.fanin.discard_source(source_id)
    }

    #[must_use]
    pub fn drain(&mut self) -> Vec<MonitoringThumbnailUpdate> {
        self.fanin.drain()
    }

    #[must_use]
    pub fn stats(&self) -> MonitoringFanInStats {
        self.fanin.stats()
    }
}

#[cfg(test)]
mod tests {
    use classmesh_video::distributor::SharedEncodedFrame;
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;
    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;

    fn update(source: u64, frame_id: u64) -> MonitoringThumbnailUpdate {
        MonitoringThumbnailUpdate::new(
            MonitoringSourceId(source),
            SharedEncodedFrame::new(
                EncodedFrameMeta {
                    frame_id,
                    timestamp_us: frame_id * 1_000,
                    keyframe: true,
                },
                Codec::H264,
                vec![1; 8],
            ),
        )
    }

    #[test]
    fn teacher_aggregation_keeps_latest_student_thumbnail_only() {
        let mut aggregator =
            TeacherMonitoringAggregator::new(MonitoringFanInConfig::default()).unwrap();
        aggregator.accept(update(9, 1)).unwrap();
        aggregator.accept(update(9, 2)).unwrap();

        let drained = aggregator.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].source_id(), MonitoringSourceId(9));
        assert_eq!(drained[0].frame().meta.frame_id, 2);
    }
}
