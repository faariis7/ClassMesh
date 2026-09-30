use std::fmt;
use std::time::Duration;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_network::multicast_sender::{
    DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY, ProtectedMulticastBackpressureDrop,
    ProtectedMulticastDistributorSink, ProtectedMulticastFrameSender, ProtectedMulticastSendError,
    ProtectedMulticastSenderConfig, ProtectedMulticastSinkError, ProtectedMulticastTrySendOutcome,
};
use classmesh_network::protected_unicast_sender::{
    ProtectedUnicastFanout, ProtectedUnicastFanoutDelivery, ProtectedUnicastFanoutError,
    ProtectedUnicastSenderConfig,
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
    Unicast(ProtectedUnicastFanoutError),
}

impl fmt::Display for PresentationMulticastSendRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fanout(error) => write!(formatter, "teacher presentation fan-out: {error}"),
            Self::Network(error) => write!(formatter, "teacher presentation multicast: {error}"),
            Self::Sink(error) => write!(formatter, "teacher presentation multicast sink: {error}"),
            Self::Unicast(error) => {
                write!(formatter, "teacher presentation unicast fan-out: {error}")
            }
        }
    }
}

impl std::error::Error for PresentationMulticastSendRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fanout(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::Sink(error) => Some(error),
            Self::Unicast(error) => Some(error),
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

impl From<ProtectedUnicastFanoutError> for PresentationMulticastSendRuntimeError {
    fn from(value: ProtectedUnicastFanoutError) -> Self {
        Self::Unicast(value)
    }
}

#[derive(Debug)]
pub struct PresentationMulticastSendStep {
    pub encoded_outputs: usize,
    pub sent: Option<SendFrameReport>,
    pub backpressure_drop: Option<ProtectedMulticastBackpressureDrop>,
    pub unicast_deliveries: Vec<ProtectedUnicastFanoutDelivery>,
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

/// Production Teacher video-engine composition for one encoded presentation rendition.
///
/// This runtime owns one capture-to-H.264 fan-out, the multicast socket/sink and bounded explicit
/// unicast outlier sinks. The caller retains the authoritative `GroupMediaCoordinator` and
/// `AuthorizationStore`, so key epochs, SFrame counters, fallback policy and live receiver
/// authorization remain single-owned by Teacher Core. Every transport drains decoder-safe frames
/// from the same encoded-frame distributor; unicast outliers never create another encoder. All live
/// UDP sockets are nonblocking, so per-destination pressure remains media-local and cannot stall
/// capture/control or other healthy receivers.
#[derive(Debug)]
pub struct PresentationMulticastSendRuntime {
    fanout: PresentationFanoutRuntime,
    sink: ProtectedMulticastDistributorSink,
    sender: ProtectedMulticastFrameSender,
    unicast: ProtectedUnicastFanout,
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
            unicast: ProtectedUnicastFanout::default(),
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

    pub fn attach_unicast_outlier(
        &mut self,
        sink_id: SinkId,
        config: ProtectedUnicastSenderConfig,
        queue_capacity: usize,
    ) -> Result<(), PresentationMulticastSendRuntimeError> {
        self.unicast
            .attach(
                self.fanout.distributor_mut(),
                sink_id,
                config,
                queue_capacity,
            )
            .map_err(Into::into)
    }

    pub fn detach_unicast_outlier(&mut self, sink_id: SinkId) -> bool {
        self.unicast.detach(self.fanout.distributor_mut(), sink_id)
    }

    #[must_use]
    pub fn unicast_outlier_count(&self) -> usize {
        self.unicast.len()
    }

    pub fn reset_pipeline(&mut self) {
        self.fanout.reset_pipeline();
    }

    pub fn request_keyframe(&mut self) -> Result<bool, PresentationMulticastSendRuntimeError> {
        self.fanout.request_keyframe().map_err(Into::into)
    }

    /// Encodes once and publishes once into the bounded shared fan-out.
    ///
    /// Multicast and every explicit unicast outlier then drain decoder-safe frames independently.
    /// The unicast fan-out seals each shared encoded allocation once for all outliers consuming that
    /// same frame; multicast keeps its existing protected sender path.
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
        let unicast_deliveries =
            self.unicast
                .drain(self.fanout.distributor_mut(), coordinator, authorization)?;
        Ok(PresentationMulticastSendStep {
            encoded_outputs,
            sent,
            backpressure_drop,
            unicast_deliveries,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use classmesh_core::keyframe::PresentationKeyframeRequest;
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
    fn runtime_contract_exposes_bounded_unicast_outlier_management() {
        use classmesh_network::protected_unicast_sender::ProtectedUnicastSenderConfig;

        fn assert_api(
            runtime: &mut PresentationMulticastSendRuntime,
            sink_id: SinkId,
            config: ProtectedUnicastSenderConfig,
        ) {
            let _ = runtime.attach_unicast_outlier(sink_id, config, 2);
            let _ = runtime.detach_unicast_outlier(sink_id);
            let _: usize = runtime.unicast_outlier_count();
        }

        let _ = assert_api
            as fn(&mut PresentationMulticastSendRuntime, SinkId, ProtectedUnicastSenderConfig);
    }

    #[test]
    fn send_step_keeps_unicast_delivery_results_separate_from_multicast() {
        let step = PresentationMulticastSendStep {
            encoded_outputs: 1,
            sent: None,
            backpressure_drop: None,
            unicast_deliveries: Vec::new(),
        };
        assert!(step.unicast_deliveries.is_empty());
    }

    #[test]
    fn presentation_keyframe_directive_must_match_exact_sender_binding() {
        let config = sender_config();
        let exact =
            PresentationKeyframeRequest::new(config.presentation_id(), config.stream_id(), 42)
                .expect("valid exact directive");
        assert!(presentation_keyframe_request_matches(config, exact));

        let wrong_presentation =
            PresentationKeyframeRequest::new(config.presentation_id() + 1, config.stream_id(), 42)
                .expect("valid drifted directive");
        assert!(!presentation_keyframe_request_matches(
            config,
            wrong_presentation
        ));

        let wrong_stream =
            PresentationKeyframeRequest::new(config.presentation_id(), config.stream_id() + 1, 42)
                .expect("valid drifted directive");
        assert!(!presentation_keyframe_request_matches(config, wrong_stream));
    }

    #[test]
    fn runtime_contract_accepts_only_sanitized_keyframe_directive() {
        fn assert_api(
            runtime: &mut PresentationMulticastSendRuntime,
            request: PresentationKeyframeRequest,
        ) {
            let _ = runtime.apply_keyframe_request(request);
        }

        let _ =
            assert_api as fn(&mut PresentationMulticastSendRuntime, PresentationKeyframeRequest);
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
