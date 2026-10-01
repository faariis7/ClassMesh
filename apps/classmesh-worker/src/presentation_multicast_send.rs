use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_network::multicast_sender::{
    DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY, ProtectedMulticastBackpressureDrop,
    ProtectedMulticastDistributorSink, ProtectedMulticastFrameSender, ProtectedMulticastSendError,
    ProtectedMulticastSenderConfig, ProtectedMulticastSinkError, ProtectedMulticastTrySendOutcome,
};
use classmesh_network::protected_unicast_sender::{
    ProtectedUnicastFanout, ProtectedUnicastFanoutDelivery, ProtectedUnicastFanoutError,
    ProtectedUnicastSendError, ProtectedUnicastSenderConfig,
};
use classmesh_network::transport::SendFrameReport;
use classmesh_security::AuthorizationStore;
use classmesh_security::group_media::GroupMediaEpoch;
use classmesh_security::group_media_coordinator::GroupMediaCoordinator;
use classmesh_video::distributor::{SinkId, SinkStats};
use classmesh_windows_runtime::ipc::{
    ServicePresentationSenderUnicastAction, ServicePresentationSenderUnicastActionKind,
};

use crate::presentation::{PresentationProfile, PresentationStats, PresentationTarget};
use crate::presentation_fanout::{PresentationFanoutError, PresentationFanoutRuntime};

#[derive(Debug)]
pub enum PresentationMulticastSendRuntimeError {
    Fanout(PresentationFanoutError),
    Network(ProtectedMulticastSendError),
    Sink(ProtectedMulticastSinkError),
    Unicast(ProtectedUnicastFanoutError),
    UnicastActionConfig(ProtectedUnicastSendError),
    UnicastActionBindingMismatch,
    UnicastActionSlotOccupied,
    StaleUnicastDetach,
    UnicastActionStateMismatch,
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
            Self::UnicastActionConfig(error) => {
                write!(
                    formatter,
                    "teacher presentation unicast action config: {error}"
                )
            }
            Self::UnicastActionBindingMismatch => formatter.write_str(
                "teacher presentation unicast action does not match the live sender binding",
            ),
            Self::UnicastActionSlotOccupied => formatter.write_str(
                "teacher presentation unicast runtime slot is already bound differently",
            ),
            Self::StaleUnicastDetach => formatter.write_str(
                "teacher presentation unicast detach does not match the current runtime binding",
            ),
            Self::UnicastActionStateMismatch => formatter.write_str(
                "teacher presentation unicast runtime state diverged from the media fan-out",
            ),
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
            Self::UnicastActionConfig(error) => Some(error),
            Self::UnicastActionBindingMismatch
            | Self::UnicastActionSlotOccupied
            | Self::StaleUnicastDetach
            | Self::UnicastActionStateMismatch => None,
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

fn presentation_keyframe_request_matches(
    config: ProtectedMulticastSenderConfig,
    request: PresentationKeyframeRequest,
) -> bool {
    request.presentation_id() == config.presentation_id()
        && request.stream_id() == config.stream_id()
}

fn presentation_sender_unicast_action_matches(
    config: ProtectedMulticastSenderConfig,
    action: ServicePresentationSenderUnicastAction,
) -> bool {
    action.slot_id != 0
        && action.presentation_id == config.presentation_id()
        && action.stream_id == config.stream_id()
        && action.epoch == config.epoch().get()
}

fn protected_unicast_config_from_action(
    sender_config: ProtectedMulticastSenderConfig,
    action: ServicePresentationSenderUnicastAction,
) -> Result<ProtectedUnicastSenderConfig, PresentationMulticastSendRuntimeError> {
    if !presentation_sender_unicast_action_matches(sender_config, action) {
        return Err(PresentationMulticastSendRuntimeError::UnicastActionBindingMismatch);
    }
    let epoch = GroupMediaEpoch::new(action.epoch)
        .map_err(|_| PresentationMulticastSendRuntimeError::UnicastActionBindingMismatch)?;
    ProtectedUnicastSenderConfig::new(
        action.destination,
        action.presentation_id,
        action.stream_id,
        epoch,
    )
    .map_err(PresentationMulticastSendRuntimeError::UnicastActionConfig)
}

fn same_unicast_action_binding(
    left: ServicePresentationSenderUnicastAction,
    right: ServicePresentationSenderUnicastAction,
) -> bool {
    left.slot_id == right.slot_id
        && left.presentation_id == right.presentation_id
        && left.stream_id == right.stream_id
        && left.epoch == right.epoch
        && left.destination == right.destination
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentationUnicastActionDecision {
    Noop,
    Attach(SinkId),
    Detach(SinkId),
}

#[derive(Debug, Default)]
struct PresentationUnicastActionBindings {
    active: BTreeMap<SinkId, ServicePresentationSenderUnicastAction>,
}

impl PresentationUnicastActionBindings {
    fn classify(
        &self,
        sender_config: ProtectedMulticastSenderConfig,
        action: ServicePresentationSenderUnicastAction,
    ) -> Result<PresentationUnicastActionDecision, PresentationMulticastSendRuntimeError> {
        let _ = protected_unicast_config_from_action(sender_config, action)?;
        let sink_id = SinkId(action.slot_id);
        match action.kind {
            ServicePresentationSenderUnicastActionKind::Attach => match self.active.get(&sink_id) {
                None => Ok(PresentationUnicastActionDecision::Attach(sink_id)),
                Some(current) if same_unicast_action_binding(*current, action) => {
                    Ok(PresentationUnicastActionDecision::Noop)
                }
                Some(_) => Err(PresentationMulticastSendRuntimeError::UnicastActionSlotOccupied),
            },
            ServicePresentationSenderUnicastActionKind::Detach => match self.active.get(&sink_id) {
                None => Ok(PresentationUnicastActionDecision::Noop),
                Some(current) if same_unicast_action_binding(*current, action) => {
                    Ok(PresentationUnicastActionDecision::Detach(sink_id))
                }
                Some(_) => Err(PresentationMulticastSendRuntimeError::StaleUnicastDetach),
            },
        }
    }

    fn record_attach(&mut self, action: ServicePresentationSenderUnicastAction) {
        self.active.insert(SinkId(action.slot_id), action);
    }

    fn record_detach(&mut self, action: ServicePresentationSenderUnicastAction) {
        let sink_id = SinkId(action.slot_id);
        if self
            .active
            .get(&sink_id)
            .is_some_and(|current| same_unicast_action_binding(*current, action))
        {
            self.active.remove(&sink_id);
        }
    }

    #[cfg(test)]
    fn current(&self, sink_id: SinkId) -> Option<ServicePresentationSenderUnicastAction> {
        self.active.get(&sink_id).copied()
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationMulticastSendBinding {
    presentation_id: u64,
    stream_id: u32,
    epoch: u32,
}

impl PresentationMulticastSendBinding {
    fn from_sender_config(config: ProtectedMulticastSenderConfig) -> Self {
        Self {
            presentation_id: config.presentation_id(),
            stream_id: config.stream_id(),
            epoch: config.epoch().get(),
        }
    }

    #[must_use]
    pub const fn presentation_id(self) -> u64 {
        self.presentation_id
    }

    #[must_use]
    pub const fn stream_id(self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }
}

#[derive(Debug)]
pub struct PresentationMulticastSendRuntime {
    fanout: PresentationFanoutRuntime,
    sink: ProtectedMulticastDistributorSink,
    sender: ProtectedMulticastFrameSender,
    sender_config: ProtectedMulticastSenderConfig,
    unicast: ProtectedUnicastFanout,
    unicast_bindings: PresentationUnicastActionBindings,
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
            sender_config,
            unicast: ProtectedUnicastFanout::default(),
            unicast_bindings: PresentationUnicastActionBindings::default(),
        })
    }

    #[must_use]
    pub fn binding(&self) -> PresentationMulticastSendBinding {
        PresentationMulticastSendBinding::from_sender_config(self.sender_config)
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

    pub fn apply_unicast_sender_action(
        &mut self,
        action: ServicePresentationSenderUnicastAction,
        queue_capacity: usize,
    ) -> Result<bool, PresentationMulticastSendRuntimeError> {
        match self.unicast_bindings.classify(self.sender_config, action)? {
            PresentationUnicastActionDecision::Noop => Ok(false),
            PresentationUnicastActionDecision::Attach(sink_id) => {
                let config = protected_unicast_config_from_action(self.sender_config, action)?;
                self.attach_unicast_outlier(sink_id, config, queue_capacity)?;
                self.unicast_bindings.record_attach(action);
                Ok(true)
            }
            PresentationUnicastActionDecision::Detach(sink_id) => {
                if !self.detach_unicast_outlier(sink_id) {
                    return Err(PresentationMulticastSendRuntimeError::UnicastActionStateMismatch);
                }
                self.unicast_bindings.record_detach(action);
                Ok(true)
            }
        }
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

    pub fn apply_keyframe_request(
        &mut self,
        request: PresentationKeyframeRequest,
    ) -> Result<bool, PresentationMulticastSendRuntimeError> {
        if !presentation_keyframe_request_matches(self.sender_config, request) {
            return Ok(false);
        }
        self.request_keyframe()
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

    use classmesh_network::multicast::{MulticastMembership, MulticastProbeOutcome};
    use classmesh_security::group_media::GroupMediaEpoch;
    use classmesh_video::distributor::DistributorError;
    use classmesh_windows_runtime::ipc::{
        ServicePresentationSenderUnicastAction, ServicePresentationSenderUnicastActionKind,
    };

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
            let _: Result<bool, PresentationMulticastSendRuntimeError> =
                runtime.apply_keyframe_request(request);
        }

        let _ =
            assert_api as fn(&mut PresentationMulticastSendRuntime, PresentationKeyframeRequest);
    }

    fn sender_action(
        kind: ServicePresentationSenderUnicastActionKind,
        slot_id: u64,
        destination: &str,
    ) -> ServicePresentationSenderUnicastAction {
        let config = sender_config();
        ServicePresentationSenderUnicastAction {
            kind,
            slot_id,
            presentation_id: config.presentation_id(),
            stream_id: config.stream_id(),
            epoch: config.epoch().get(),
            destination: destination.parse().expect("valid destination"),
        }
    }

    #[test]
    fn sender_unicast_action_requires_exact_live_presentation_binding() {
        let config = sender_config();
        let exact = sender_action(
            ServicePresentationSenderUnicastActionKind::Attach,
            11,
            "192.0.2.44:49001",
        );
        assert!(presentation_sender_unicast_action_matches(config, exact));

        let mut wrong_presentation = exact;
        wrong_presentation.presentation_id += 1;
        assert!(!presentation_sender_unicast_action_matches(
            config,
            wrong_presentation
        ));

        let mut wrong_stream = exact;
        wrong_stream.stream_id += 1;
        assert!(!presentation_sender_unicast_action_matches(
            config,
            wrong_stream
        ));

        let mut wrong_epoch = exact;
        wrong_epoch.epoch += 1;
        assert!(!presentation_sender_unicast_action_matches(
            config,
            wrong_epoch
        ));
    }

    #[test]
    fn sender_unicast_binding_state_is_idempotent_and_rejects_stale_detach() {
        let config = sender_config();
        let mut bindings = PresentationUnicastActionBindings::default();
        let first = sender_action(
            ServicePresentationSenderUnicastActionKind::Attach,
            11,
            "192.0.2.44:49001",
        );

        assert_eq!(
            bindings.classify(config, first).expect("first attach"),
            PresentationUnicastActionDecision::Attach(SinkId(11))
        );
        bindings.record_attach(first);
        assert_eq!(
            bindings.classify(config, first).expect("retry attach"),
            PresentationUnicastActionDecision::Noop
        );

        let detach_first = ServicePresentationSenderUnicastAction {
            kind: ServicePresentationSenderUnicastActionKind::Detach,
            ..first
        };
        assert_eq!(
            bindings
                .classify(config, detach_first)
                .expect("exact detach"),
            PresentationUnicastActionDecision::Detach(SinkId(11))
        );
        bindings.record_detach(detach_first);

        let replacement = sender_action(
            ServicePresentationSenderUnicastActionKind::Attach,
            11,
            "192.0.2.44:49002",
        );
        assert_eq!(
            bindings
                .classify(config, replacement)
                .expect("replacement attach"),
            PresentationUnicastActionDecision::Attach(SinkId(11))
        );
        bindings.record_attach(replacement);

        assert!(matches!(
            bindings.classify(config, detach_first),
            Err(PresentationMulticastSendRuntimeError::StaleUnicastDetach)
        ));
        assert_eq!(bindings.current(SinkId(11)), Some(replacement));
    }

    #[test]
    fn runtime_contract_applies_typed_sender_unicast_actions() {
        fn assert_api(
            runtime: &mut PresentationMulticastSendRuntime,
            action: ServicePresentationSenderUnicastAction,
        ) {
            let _: Result<bool, PresentationMulticastSendRuntimeError> =
                runtime.apply_unicast_sender_action(action, 2);
        }

        let _ = assert_api
            as fn(&mut PresentationMulticastSendRuntime, ServicePresentationSenderUnicastAction);
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
