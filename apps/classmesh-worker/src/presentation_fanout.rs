use std::fmt;
use std::time::Duration;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_video::distributor::{
    DistributorError, FrameDistributor, SharedEncodedFrame, SinkId, SinkMode, SinkStats,
};

use crate::presentation::{
    PresentationError, PresentationPipeline, PresentationProfile, PresentationStats,
    PresentationTarget,
};

#[derive(Debug)]
pub enum PresentationFanoutError {
    Presentation(PresentationError),
    Distributor(DistributorError),
}

impl fmt::Display for PresentationFanoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Presentation(error) => write!(formatter, "presentation encode: {error}"),
            Self::Distributor(error) => write!(formatter, "presentation fan-out: {error:?}"),
        }
    }
}

impl std::error::Error for PresentationFanoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Presentation(error) => Some(error),
            Self::Distributor(_) => None,
        }
    }
}

impl From<PresentationError> for PresentationFanoutError {
    fn from(value: PresentationError) -> Self {
        Self::Presentation(value)
    }
}

impl From<DistributorError> for PresentationFanoutError {
    fn from(value: DistributorError) -> Self {
        Self::Distributor(value)
    }
}

/// Teacher video-engine owner for one encoded classroom rendition.
///
/// The Media Foundation encoder is created lazily from the first DXGI frame. Every completed H.264
/// access unit is published once into the bounded `FrameDistributor`, which shares the same
/// `Arc<[u8]>` allocation across multicast, unicast, recording or future SFU sinks. Transport and
/// group-key ownership intentionally stay outside this runtime.
#[derive(Debug)]
pub struct PresentationFanoutRuntime {
    target: PresentationTarget,
    pipeline: Option<PresentationPipeline>,
    distributor: FrameDistributor,
}

impl PresentationFanoutRuntime {
    pub fn new(target: PresentationTarget) -> Result<Self, PresentationFanoutError> {
        target.validate()?;
        Ok(Self {
            target,
            pipeline: None,
            distributor: FrameDistributor::default(),
        })
    }

    pub fn with_limits(
        target: PresentationTarget,
        max_sinks: usize,
        max_queue_depth: usize,
    ) -> Result<Self, PresentationFanoutError> {
        target.validate()?;
        Ok(Self {
            target,
            pipeline: None,
            distributor: FrameDistributor::with_limits(max_sinks, max_queue_depth)?,
        })
    }

    #[must_use]
    pub const fn target(&self) -> PresentationTarget {
        self.target
    }

    #[must_use]
    pub fn capture_interval(&self) -> Duration {
        Duration::from_micros(1_000_000_u64 / u64::from(self.target.fps))
    }

    #[must_use]
    pub fn profile(&self) -> Option<PresentationProfile> {
        self.pipeline.as_ref().map(PresentationPipeline::profile)
    }

    #[must_use]
    pub fn presentation_stats(&self) -> Option<PresentationStats> {
        self.pipeline.as_ref().map(PresentationPipeline::stats)
    }

    pub fn add_sink(
        &mut self,
        id: SinkId,
        mode: SinkMode,
        capacity: usize,
    ) -> Result<(), PresentationFanoutError> {
        self.distributor.add_sink(id, mode, capacity)?;
        Ok(())
    }

    pub fn remove_sink(&mut self, id: SinkId) -> bool {
        self.distributor.remove_sink(id)
    }

    #[must_use]
    pub fn sink_stats(&self, id: SinkId) -> Option<SinkStats> {
        self.distributor.stats(id)
    }

    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.distributor.sink_count()
    }

    pub fn pop_latest(&mut self, id: SinkId) -> Option<SharedEncodedFrame> {
        self.distributor.pop_latest(id)
    }

    /// Encodes one captured frame and publishes every completed encoder output exactly once.
    ///
    /// A single capture submission may make multiple delayed encoder outputs ready; all of them are
    /// published through the same distributor and each sink applies its own bounded latest-frame
    /// policy.
    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<usize, PresentationFanoutError> {
        if self.pipeline.is_none() {
            self.pipeline = Some(PresentationPipeline::from_first_frame_with_target(
                &frame,
                self.target,
            )?);
        }

        let outputs = self
            .pipeline
            .as_mut()
            .expect("presentation fan-out pipeline initialized above")
            .process_frame(meta, frame)?;
        let published = outputs.len();
        for output in outputs {
            self.distributor.publish(output);
        }
        Ok(published)
    }

    /// Clears only encoder/GPU state after capture or device recovery.
    ///
    /// Sink registrations remain intact, but all queued encoded frames are discarded so stale media
    /// from the old pipeline cannot be emitted after recovery.
    pub fn reset_pipeline(&mut self) {
        self.pipeline = None;
        self.distributor.discard_queued();
    }

    /// Requests an IDR only when the hardware encoder is already initialized.
    ///
    /// Coordinating and rate-limiting receiver requests remains a caller policy (Phase 7G).
    pub fn request_keyframe(&mut self) -> Result<bool, PresentationFanoutError> {
        let Some(pipeline) = self.pipeline.as_mut() else {
            return Ok(false);
        };
        pipeline.request_keyframe()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;

    fn frame(id: u64) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id.saturating_mul(33_333),
                keyframe: id == 1,
            },
            Codec::H264,
            vec![u8::try_from(id).unwrap_or(0); 32],
        )
    }

    #[test]
    fn constructor_rejects_invalid_target_and_distributor_limits() {
        let invalid = PresentationTarget {
            max_width: 1920,
            max_height: 1080,
            fps: 0,
            bitrate_bps: 5_000_000,
        };
        assert!(matches!(
            PresentationFanoutRuntime::new(invalid),
            Err(PresentationFanoutError::Presentation(
                PresentationError::InvalidTargetProfile
            ))
        ));

        assert!(matches!(
            PresentationFanoutRuntime::with_limits(PresentationTarget::default(), 0, 2),
            Err(PresentationFanoutError::Distributor(
                DistributorError::InvalidMaxSinks
            ))
        ));
        assert!(matches!(
            PresentationFanoutRuntime::with_limits(PresentationTarget::default(), 2, 0),
            Err(PresentationFanoutError::Distributor(
                DistributorError::InvalidMaxQueueDepth
            ))
        ));
    }

    #[test]
    fn reset_discards_stale_media_but_preserves_sink_registration() {
        let mut runtime =
            PresentationFanoutRuntime::with_limits(PresentationTarget::default(), 2, 2)
                .expect("valid fan-out runtime");
        runtime
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("multicast sink");

        let shared = frame(1);
        let pointer = Arc::as_ptr(&shared.data);
        runtime.distributor.publish(shared);
        assert_eq!(runtime.sink_stats(SinkId(1)).expect("stats").queued, 1);

        runtime.reset_pipeline();

        let stats = runtime.sink_stats(SinkId(1)).expect("sink survives reset");
        assert_eq!(stats.queued, 0);
        assert_eq!(stats.dropped, 1);
        assert_eq!(runtime.sink_count(), 1);

        let next = frame(2);
        let next_pointer = Arc::as_ptr(&next.data);
        runtime.distributor.publish(next);
        let delivered = runtime.pop_latest(SinkId(1)).expect("sink still receives");
        assert_eq!(Arc::as_ptr(&delivered.data), next_pointer);
        assert_ne!(Arc::as_ptr(&delivered.data), pointer);
    }

    #[test]
    fn one_published_allocation_is_shared_across_multiple_transport_sinks() {
        let mut runtime = PresentationFanoutRuntime::new(PresentationTarget::default())
            .expect("valid fan-out runtime");
        runtime
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("multicast sink");
        runtime
            .add_sink(SinkId(2), SinkMode::Unicast, 2)
            .expect("unicast sink");

        let shared = frame(7);
        let pointer = Arc::as_ptr(&shared.data);
        runtime.distributor.publish(shared);

        let multicast = runtime.pop_latest(SinkId(1)).expect("multicast frame");
        let unicast = runtime.pop_latest(SinkId(2)).expect("unicast frame");
        assert_eq!(Arc::as_ptr(&multicast.data), pointer);
        assert_eq!(Arc::as_ptr(&unicast.data), pointer);
    }

    #[test]
    fn keyframe_request_before_first_capture_is_a_noop() {
        let mut runtime = PresentationFanoutRuntime::new(PresentationTarget::default())
            .expect("valid fan-out runtime");
        assert!(!runtime.request_keyframe().expect("no-op request"));
    }
}
