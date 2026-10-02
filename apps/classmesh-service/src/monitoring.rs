use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::monitoring_fanin::MonitoringThumbnailUpdate;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

/// Builds the transport-neutral monitoring update handed to the dedicated monitoring path.
///
/// This intentionally does not use the reliable control envelope/channel. The eventual monitoring
/// transport may backpressure or drop independently without delaying authenticated control traffic.
#[must_use]
pub(crate) fn build_monitoring_thumbnail_update(
    source_id: MonitoringSourceId,
    frame: SharedEncodedFrame,
) -> MonitoringThumbnailUpdate {
    MonitoringThumbnailUpdate::new(source_id, frame)
}

#[cfg(test)]
mod tests {
    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;

    #[test]
    fn service_monitoring_update_preserves_source_and_frame_identity() {
        let frame = SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: 17,
                timestamp_us: 9_000,
                keyframe: true,
            },
            Codec::H264,
            vec![7; 8],
        );
        let update = build_monitoring_thumbnail_update(MonitoringSourceId(4), frame);
        assert_eq!(update.source_id(), MonitoringSourceId(4));
        assert_eq!(update.frame().meta.frame_id, 17);
    }
}
