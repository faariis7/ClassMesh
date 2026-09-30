use std::fmt;
use std::time::Duration;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_network::multicast_sender::{
    DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY, ProtectedMulticastBackpressureDrop,
    ProtectedMulticastDistributorSink, ProtectedMulticastFrameSender, ProtectedMulticastSendError,
    ProtectedMulticastSenderConfig, ProtectedMulticastSinkError, ProtectedMulticastTrySendOutcome,
};
use classmesh_network::transport::SendFrameReport;
use classmesh_security::AuthorizationStore;
use classmesh_security::group_media_coordinator::GroupMediaCoordinator;
use classmesh_video::distributor::{SinkId, SinkStats};

use crate::presentation::{PresentationProfile, PresentationStats, PresentationTarget};
use crate::presentation_fanout::{PresentationFanoutError, PresentationFanoutRuntime};

#[derive(Debug)]
pub enum PresentationMulticastSendRuntimeError {
    Fanout(PresentationFanoutError),
    Network(ProtectedMulticastSendError),
    Sink(ProtectedMulticastSinkError),
}

impl fmt::Display for PresentationMulticastSendRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fanout(error) => write!(formatter, "teacher presentation fan-out: {error}"),
            Self::Network(error) => write!(formatter, "teacher presentation multicast: {error}"),
            Self::Sink(error) => write!(formatter, "teacher presentation multicast sink: {error}"),
        }
    }
}

impl std::error::Error for PresentationMulticastSendRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fanout(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::Sink(error) => Some(error),
        }
    }
}

impl From<PresentationFanoutError> for PresentationMulticastSendRuntimeError {
    fn from(value: PresentationFanoutError) -> Self {
        Self::Fanout(value)
    }
}

impl From<ProtectedMulticastSendError> for PresentationMulticastSendRuntimeError {
    fn from(value: ProtectedMulticastSendError) -> Self {
        Self::Network(value)
    }
}

impl From<ProtectedMulticastSinkError> for PresentationMulticastSendRuntimeError {
    fn from(value: ProtectedMulticastSinkError) -> Self {
        Self::Sink(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationMulticastSendStep {
    pub encoded_outputs: usize,
    pub sent: Option<SendFrameReport>,
    pub backpressure_drop: Option<ProtectedMulticastBackpressureDrop>,
}

fn delivery_fields(
    outcome: Option<ProtectedMulticastTrySendOutcome>,
) -> (
    Option<SendFrameReport>,
    Option<ProtectedMulticastBackpressureDrop>,
) {
    match outcome {
        None => (None, None),
        Some(ProtectedMulticastTrySendOutcome::Sent(report)) => (Some(report), None),
        Some(ProtectedMulticastTrySendOutcome::DroppedBackpressure(drop)) => (None, Some(drop)),
    }
}

/// Production Teacher video-engine composition for one protected multicast rendition.
///
/// This runtime owns capture-to-H.264 fan-out plus the multicast socket/sink. The caller retains the
/// authoritative `GroupMediaCoordinator` and `AuthorizationStore`, so key epochs, SFrame counters
/// and live receiver authorization remain single-owned by Teacher Core. The multicast sink removes
/// the next decoder-safe shared frame before sealing/sending. The live socket is nonblocking:
/// kernel send-buffer pressure becomes an explicit media-local drop and never stalls capture/control
/// or retries the same sealed frame/counter.
#[derive(Debug)]
pub struct PresentationMulticastSendRuntime {
    fanout: PresentationFanoutRuntime,
    sink: ProtectedMulticastDistributorSink,
    sender: ProtectedMulticastFrameSender,
}

impl PresentationMulticastSendRuntime {
    pub fn bind(
        target: PresentationTarget,
        sender_config: ProtectedMulticastSenderConfig,
        sink_id: SinkId,
    ) -> Result<Self, PresentationMulticastSendRuntimeError> {
        Self::bind_with_capacity(
            target,
            sender_config,
            sink_id,
            DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY,
        )
    }

    pub fn bind_with_capacity(
        target: PresentationTarget,
        sender_config: ProtectedMulticastSenderConfig,
        sink_id: SinkId,
        queue_capacity: usize,
    ) -> Result<Self, PresentationMulticastSendRuntimeError> {
        let mut fanout = PresentationFanoutRuntime::new(target)?;
        let sink = ProtectedMulticastDistributorSink::attach(
            fanout.distributor_mut(),
            sink_id,
            queue_capacity,
        )?;
        let sender = ProtectedMulticastFrameSender::bind_nonblocking(sender_config)?;
        Ok(Self {
            fanout,
            sink,
            sender,
        })
    }

    #[must_use]
    pub fn capture_interval(&self) -> Duration {
        self.fanout.capture_interval()
    }

    #[must_use]
    pub fn profile(&self) -> Option<PresentationProfile> {
        self.fanout.profile()
    }

    #[must_use]
    pub fn presentation_stats(&self) -> Option<PresentationStats> {
        self.fanout.presentation_stats()
    }

    #[must_use]
    pub fn sink_stats(&self) -> Option<SinkStats> {
        self.sink.stats(self.fanout.distributor())
    }

    pub fn reset_pipeline(&mut self) {
        self.fanout.reset_pipeline();
    }

    pub fn request_keyframe(&mut self) -> Result<bool, PresentationMulticastSendRuntimeError> {
        self.fanout.request_keyframe().map_err(Into::into)
    }

    /// Encodes once, publishes once into the bounded fan-out, then sends only the newest queued
    /// multicast frame through the existing SFrame-protected sender.
    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
    ) -> Result<PresentationMulticastSendStep, PresentationMulticastSendRuntimeError> {
        let encoded_outputs = self.fanout.process_frame(meta, frame)?;
        let delivery = match self.sink.take_next_decodable(self.fanout.distributor_mut()) {
            Some(frame) => Some(self.sender.try_send_shared_h264_frame(
                coordinator,
                authorization,
                &frame,
            )?),
            None => None,
        };
        let (sent, backpressure_drop) = delivery_fields(delivery);
        Ok(PresentationMulticastSendStep {
            encoded_outputs,
            sent,
            backpressure_drop,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use classmesh_network::multicast::{MulticastMembership, MulticastProbeOutcome};
    use classmesh_security::group_media::GroupMediaEpoch;
    use classmesh_video::distributor::DistributorError;

    use crate::presentation::PresentationError;

    use super::*;

    fn sender_config() -> ProtectedMulticastSenderConfig {
        let membership =
            MulticastMembership::new(Ipv4Addr::new(239, 10, 20, 30), Ipv4Addr::new(192, 0, 2, 10))
                .expect("valid administrative multicast membership");
        ProtectedMulticastSenderConfig::new(
            membership,
            49_000,
            700,
            800,
            GroupMediaEpoch::new(1).expect("non-zero epoch"),
            MulticastProbeOutcome::Available,
        )
        .expect("valid protected sender config")
    }

    #[test]
    fn invalid_target_fails_before_multicast_socket_bind() {
        let invalid = PresentationTarget {
            max_width: 1920,
            max_height: 1080,
            fps: 0,
            bitrate_bps: 5_000_000,
        };
        assert!(matches!(
            PresentationMulticastSendRuntime::bind(invalid, sender_config(), SinkId(1)),
            Err(PresentationMulticastSendRuntimeError::Fanout(
                PresentationFanoutError::Presentation(PresentationError::InvalidTargetProfile)
            ))
        ));
    }

    #[test]
    fn invalid_sink_capacity_fails_before_multicast_socket_bind() {
        assert!(matches!(
            PresentationMulticastSendRuntime::bind_with_capacity(
                PresentationTarget::default(),
                sender_config(),
                SinkId(1),
                0,
            ),
            Err(PresentationMulticastSendRuntimeError::Sink(
                ProtectedMulticastSinkError::Distributor(DistributorError::InvalidQueueCapacity)
            ))
        ));
    }

    #[test]
    fn delivery_fields_keep_success_and_backpressure_mutually_exclusive() {
        let report = SendFrameReport {
            frame_id: 42,
            packets: 3,
            payload_bytes: 1_024,
            first_sequence: 10,
            next_sequence: 13,
        };
        assert_eq!(
            delivery_fields(Some(ProtectedMulticastTrySendOutcome::Sent(report))),
            (Some(report), None)
        );

        let drop = ProtectedMulticastBackpressureDrop {
            frame_id: 43,
            packets_sent: 1,
            packets_total: 4,
        };
        assert_eq!(
            delivery_fields(Some(ProtectedMulticastTrySendOutcome::DroppedBackpressure(
                drop
            ))),
            (None, Some(drop))
        );
        assert_eq!(delivery_fields(None), (None, None));
    }
}
