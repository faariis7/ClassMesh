use std::fmt;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_protocol::media::MEDIA_HEADER_LEN;
use classmesh_security::AuthorizationStore;
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaError, GroupMediaFrameBinding, SealedGroupMediaFrame,
};
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, GroupMediaCoordinatorError,
};
use classmesh_video::Codec;
use classmesh_video::distributor::{
    DistributorError, FrameDistributor, SharedEncodedFrame, SinkId, SinkMode, SinkStats,
};

use crate::multicast::{MulticastMembership, MulticastProbeOutcome};
use crate::transport::SendFrameReport;
use crate::udp::{DatagramError, UdpMediaSocket};
use crate::{MediaPacket, PacketizeError, PacketizeMeta, packetize_frame};

pub const MULTICAST_MEDIA_TTL: u32 = 1;
pub const DEFAULT_MULTICAST_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
pub const DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedMulticastSenderConfig {
    membership: MulticastMembership,
    port: u16,
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
}

impl ProtectedMulticastSenderConfig {
    pub fn new(
        membership: MulticastMembership,
        port: u16,
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        probe_outcome: MulticastProbeOutcome,
    ) -> Result<Self, ProtectedMulticastSendError> {
        if !probe_outcome.can_advertise_udp_multicast() {
            return Err(ProtectedMulticastSendError::MulticastUnavailable);
        }
        if port == 0 {
            return Err(ProtectedMulticastSendError::InvalidPort);
        }
        if presentation_id == 0 {
            return Err(ProtectedMulticastSendError::InvalidPresentationId);
        }
        if stream_id == 0 {
            return Err(ProtectedMulticastSendError::InvalidStreamId);
        }

        Ok(Self {
            membership,
            port,
            presentation_id,
            stream_id,
            epoch,
        })
    }

    #[must_use]
    pub const fn membership(self) -> MulticastMembership {
        self.membership
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
    pub const fn epoch(self) -> GroupMediaEpoch {
        self.epoch
    }

    #[must_use]
    pub fn destination(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.membership.group(), self.port))
    }

    #[must_use]
    pub fn local_bind(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.membership.interface(), 0))
    }

    fn accepts_binding(self, binding: GroupMediaFrameBinding) -> bool {
        binding.presentation_id() == self.presentation_id
            && binding.stream_id() == self.stream_id
            && binding.epoch() == self.epoch
    }
}

#[derive(Debug)]
pub enum ProtectedMulticastSendError {
    MulticastUnavailable,
    InvalidPort,
    InvalidPresentationId,
    InvalidStreamId,
    ProtocolVersionOutOfRange,
    FrameBindingMismatch,
    UnsupportedCodec,
    Security(GroupMediaError),
    Coordinator(GroupMediaCoordinatorError),
    Packetize(PacketizeError),
    Datagram(DatagramError),
    ShortDatagramWrite,
}

impl fmt::Display for ProtectedMulticastSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MulticastUnavailable => {
                formatter.write_str("multicast runtime probe did not establish local availability")
            }
            Self::InvalidPort => formatter.write_str("multicast destination port must be non-zero"),
            Self::InvalidPresentationId => {
                formatter.write_str("multicast presentation id must be non-zero")
            }
            Self::InvalidStreamId => formatter.write_str("multicast stream id must be non-zero"),
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit the media header")
            }
            Self::FrameBindingMismatch => {
                formatter.write_str("sealed group-media frame does not match multicast sender")
            }
            Self::UnsupportedCodec => {
                formatter.write_str("presentation multicast sender requires H.264")
            }
            Self::Security(error) => write!(formatter, "group-media binding: {error}"),
            Self::Coordinator(error) => write!(formatter, "group-media coordinator: {error}"),
            Self::Packetize(error) => {
                write!(formatter, "multicast packetization failed: {error:?}")
            }
            Self::Datagram(error) => write!(formatter, "multicast UDP send failed: {error}"),
            Self::ShortDatagramWrite => {
                formatter.write_str("multicast UDP write did not send the complete datagram")
            }
        }
    }
}

impl std::error::Error for ProtectedMulticastSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::Security(error) => Some(error),
            Self::Coordinator(error) => Some(error),
            Self::MulticastUnavailable
            | Self::InvalidPort
            | Self::InvalidPresentationId
            | Self::InvalidStreamId
            | Self::ProtocolVersionOutOfRange
            | Self::FrameBindingMismatch
            | Self::UnsupportedCodec
            | Self::Packetize(_)
            | Self::ShortDatagramWrite => None,
        }
    }
}

impl From<PacketizeError> for ProtectedMulticastSendError {
    fn from(value: PacketizeError) -> Self {
        Self::Packetize(value)
    }
}

impl From<DatagramError> for ProtectedMulticastSendError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

impl From<GroupMediaError> for ProtectedMulticastSendError {
    fn from(value: GroupMediaError) -> Self {
        Self::Security(value)
    }
}

impl From<GroupMediaCoordinatorError> for ProtectedMulticastSendError {
    fn from(value: GroupMediaCoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

#[derive(Debug)]
pub enum ProtectedMulticastSinkError {
    Distributor(DistributorError),
    Send(ProtectedMulticastSendError),
}

impl fmt::Display for ProtectedMulticastSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Distributor(error) => {
                write!(formatter, "presentation multicast fan-out: {error:?}")
            }
            Self::Send(error) => write!(formatter, "presentation multicast send: {error}"),
        }
    }
}

impl std::error::Error for ProtectedMulticastSinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Send(error) => Some(error),
            Self::Distributor(_) => None,
        }
    }
}

impl From<DistributorError> for ProtectedMulticastSinkError {
    fn from(value: DistributorError) -> Self {
        Self::Distributor(value)
    }
}

impl From<ProtectedMulticastSendError> for ProtectedMulticastSinkError {
    fn from(value: ProtectedMulticastSendError) -> Self {
        Self::Send(value)
    }
}

/// Bounded multicast attachment for the shared encoded-frame distributor.
///
/// The caller owns the distributor so the same `SharedEncodedFrame` allocation can also feed
/// future unicast/SFU/recording sinks. This adapter only registers one multicast queue and drains
/// its newest frame; older queued frames are discarded by `FrameDistributor` rather than allowing
/// presentation latency to grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedMulticastDistributorSink {
    id: SinkId,
}

impl ProtectedMulticastDistributorSink {
    pub fn attach(
        distributor: &mut FrameDistributor,
        id: SinkId,
        capacity: usize,
    ) -> Result<Self, ProtectedMulticastSinkError> {
        distributor.add_sink(id, SinkMode::Multicast, capacity)?;
        Ok(Self { id })
    }

    #[must_use]
    pub const fn id(self) -> SinkId {
        self.id
    }

    #[must_use]
    pub fn stats(self, distributor: &FrameDistributor) -> Option<SinkStats> {
        distributor.stats(self.id)
    }

    pub fn take_latest(self, distributor: &mut FrameDistributor) -> Option<SharedEncodedFrame> {
        distributor.pop_latest(self.id)
    }

    pub fn send_latest(
        self,
        distributor: &mut FrameDistributor,
        sender: &mut ProtectedMulticastFrameSender,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
    ) -> Result<Option<SendFrameReport>, ProtectedMulticastSinkError> {
        let Some(frame) = self.take_latest(distributor) else {
            return Ok(None);
        };
        sender
            .send_shared_h264_frame(coordinator, authorization, &frame)
            .map(Some)
            .map_err(Into::into)
    }

    pub fn detach(self, distributor: &mut FrameDistributor) -> bool {
        distributor.remove_sink(self.id)
    }
}

fn protect_shared_h264_frame(
    config: ProtectedMulticastSenderConfig,
    coordinator: &mut GroupMediaCoordinator,
    authorization: &AuthorizationStore,
    frame: &SharedEncodedFrame,
) -> Result<SealedGroupMediaFrame, ProtectedMulticastSendError> {
    if frame.codec != Codec::H264 {
        return Err(ProtectedMulticastSendError::UnsupportedCodec);
    }

    let binding = GroupMediaFrameBinding::new(
        config.presentation_id(),
        config.stream_id(),
        config.epoch(),
        frame.meta.frame_id,
        frame.meta.timestamp_us,
        frame.meta.keyframe,
    )?;
    coordinator
        .seal_bound_frame(authorization, frame.data.as_ref(), binding)
        .map_err(Into::into)
}

#[derive(Debug)]
struct PreparedMulticastFrame {
    packets: Vec<MediaPacket>,
    first_sequence: u32,
    next_sequence: u32,
}

#[derive(Debug)]
struct ProtectedMulticastPacketizer {
    config: ProtectedMulticastSenderConfig,
    next_sequence: u32,
}

impl ProtectedMulticastPacketizer {
    const fn new(config: ProtectedMulticastSenderConfig) -> Self {
        Self {
            config,
            next_sequence: 0,
        }
    }

    fn packetize(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<PreparedMulticastFrame, ProtectedMulticastSendError> {
        let binding = frame.binding();
        if !self.config.accepts_binding(binding) {
            return Err(ProtectedMulticastSendError::FrameBindingMismatch);
        }

        let protocol_major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| ProtectedMulticastSendError::ProtocolVersionOutOfRange)?;
        let protocol_minor = u8::try_from(PROTOCOL_VERSION.minor)
            .map_err(|_| ProtectedMulticastSendError::ProtocolVersionOutOfRange)?;
        let first_sequence = self.next_sequence;
        let packets = packetize_frame(
            frame.as_bytes(),
            PacketizeMeta {
                protocol_major,
                protocol_minor,
                stream_id: binding.stream_id(),
                frame_id: binding.frame_id(),
                first_sequence,
                timestamp_us: binding.timestamp_us(),
                keyframe: binding.keyframe(),
            },
        )?;
        let packet_count = u32::try_from(packets.len())
            .map_err(|_| ProtectedMulticastSendError::Packetize(PacketizeError::TooManyPackets))?;
        let next_sequence = first_sequence.wrapping_add(packet_count);
        self.next_sequence = next_sequence;
        Ok(PreparedMulticastFrame {
            packets,
            first_sequence,
            next_sequence,
        })
    }
}

#[derive(Debug)]
pub struct ProtectedMulticastFrameSender {
    socket: UdpMediaSocket,
    packetizer: ProtectedMulticastPacketizer,
    destination: SocketAddr,
}

impl ProtectedMulticastFrameSender {
    pub fn bind(
        config: ProtectedMulticastSenderConfig,
    ) -> Result<Self, ProtectedMulticastSendError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_write_timeout(Some(DEFAULT_MULTICAST_WRITE_TIMEOUT))?;
        socket.set_multicast_interface_v4(config.membership().interface())?;
        socket.set_multicast_ttl_v4(MULTICAST_MEDIA_TTL)?;

        Ok(Self {
            socket,
            packetizer: ProtectedMulticastPacketizer::new(config),
            destination: config.destination(),
        })
    }

    pub fn send_shared_h264_frame(
        &mut self,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
        frame: &SharedEncodedFrame,
    ) -> Result<SendFrameReport, ProtectedMulticastSendError> {
        let sealed =
            protect_shared_h264_frame(self.packetizer.config, coordinator, authorization, frame)?;
        self.send_frame(&sealed)
    }

    pub fn send_frame(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<SendFrameReport, ProtectedMulticastSendError> {
        let binding = frame.binding();
        let prepared = self.packetizer.packetize(frame)?;

        for packet in &prepared.packets {
            let expected = MEDIA_HEADER_LEN + packet.payload.len();
            let written = self.socket.send_packet_to(packet, self.destination)?;
            if written != expected {
                return Err(ProtectedMulticastSendError::ShortDatagramWrite);
            }
        }

        Ok(SendFrameReport {
            frame_id: binding.frame_id(),
            packets: prepared.packets.len(),
            payload_bytes: frame.len(),
            first_sequence: prepared.first_sequence,
            next_sequence: prepared.next_sequence,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedMulticastSendError> {
        self.socket.local_addr().map_err(Into::into)
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr};

    use classmesh_protocol::media::{MAX_PACKET_PAYLOAD, MediaFlags};
    use classmesh_security::group_media::{GroupMediaKeyMaterial, GroupMediaSender};
    use classmesh_security::{
        CredentialFingerprint, CredentialRecord, Permission, Principal, PrincipalId, PrincipalKind,
    };
    use classmesh_video::EncodedFrameMeta;

    use crate::multicast::MulticastProbeFailure;

    use super::*;

    fn membership() -> MulticastMembership {
        MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, 30),
            Ipv4Addr::new(192, 168, 50, 10),
        )
        .expect("valid classroom multicast membership")
    }

    fn epoch(value: u32) -> GroupMediaEpoch {
        GroupMediaEpoch::new(value).expect("non-zero epoch")
    }

    fn config(epoch: GroupMediaEpoch) -> ProtectedMulticastSenderConfig {
        ProtectedMulticastSenderConfig::new(
            membership(),
            50_000,
            700,
            800,
            epoch,
            MulticastProbeOutcome::Available,
        )
        .expect("valid sender config")
    }

    fn sealed_frame(
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        frame_id: u64,
        timestamp_us: u64,
        keyframe: bool,
        bytes: usize,
    ) -> SealedGroupMediaFrame {
        let material = GroupMediaKeyMaterial::generate().expect("test key");
        let mut sender = GroupMediaSender::new(epoch, &material).expect("test sender");
        let binding = GroupMediaFrameBinding::new(
            presentation_id,
            stream_id,
            epoch,
            frame_id,
            timestamp_us,
            keyframe,
        )
        .expect("valid binding");
        sender
            .seal_bound_frame(&vec![0x5a; bytes], binding)
            .expect("sealed frame")
    }

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn authorization_with_receiver(value: u8) -> AuthorizationStore {
        let principal_id = principal(value);
        let fingerprint = CredentialFingerprint([value.wrapping_add(100); 32]);
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::ReceivePresentation);
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 1));

        let mut authorization = AuthorizationStore::default();
        authorization
            .upsert(Principal {
                id: principal_id,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions,
                credentials,
            })
            .expect("test receiver principal registers");
        authorization
    }

    fn shared_frame(codec: Codec, frame_id: u64, keyframe: bool) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id,
                timestamp_us: frame_id.saturating_mul(33_333),
                keyframe,
            },
            codec,
            vec![0x5a; 128],
        )
    }

    #[test]
    fn multicast_distributor_sink_is_bounded_and_keeps_latest_shared_frame() {
        use std::sync::Arc;

        let mut distributor = FrameDistributor::default();
        let sink = ProtectedMulticastDistributorSink::attach(
            &mut distributor,
            SinkId(99),
            DEFAULT_PROTECTED_MULTICAST_SINK_QUEUE_CAPACITY,
        )
        .expect("multicast sink attaches");

        let first = shared_frame(Codec::H264, 1, true);
        let second = shared_frame(Codec::H264, 2, false);
        let latest = shared_frame(Codec::H264, 3, false);
        let latest_ptr = Arc::as_ptr(&latest.data);

        distributor.publish(first);
        distributor.publish(second);
        distributor.publish(latest);

        let before = sink.stats(&distributor).expect("sink stats");
        assert_eq!(before.mode, SinkMode::Multicast);
        assert_eq!(before.queued, 2);
        assert_eq!(before.dropped, 1);

        let drained = sink
            .take_latest(&mut distributor)
            .expect("latest frame available");
        assert_eq!(drained.meta.frame_id, 3);
        assert_eq!(Arc::as_ptr(&drained.data), latest_ptr);

        let after = sink.stats(&distributor).expect("sink stats after drain");
        assert_eq!(after.queued, 0);
        assert_eq!(after.dropped, 2);
        assert!(sink.detach(&mut distributor));
        assert!(sink.stats(&distributor).is_none());
    }

    #[test]
    fn multicast_distributor_sink_reuses_distributor_capacity_validation() {
        let mut distributor = FrameDistributor::with_limits(1, 2).expect("bounded distributor");
        assert!(matches!(
            ProtectedMulticastDistributorSink::attach(&mut distributor, SinkId(1), 0),
            Err(ProtectedMulticastSinkError::Distributor(
                DistributorError::InvalidQueueCapacity
            ))
        ));
        assert!(matches!(
            ProtectedMulticastDistributorSink::attach(&mut distributor, SinkId(1), 3),
            Err(ProtectedMulticastSinkError::Distributor(
                DistributorError::QueueCapacityExceeded
            ))
        ));

        ProtectedMulticastDistributorSink::attach(&mut distributor, SinkId(1), 1)
            .expect("first sink");
        assert!(matches!(
            ProtectedMulticastDistributorSink::attach(&mut distributor, SinkId(2), 1),
            Err(ProtectedMulticastSinkError::Distributor(
                DistributorError::SinkLimitReached
            ))
        ));
    }

    #[test]
    fn shared_h264_frame_is_sealed_by_existing_coordinator_sender() {
        let authorization = authorization_with_receiver(1);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver registers");
        let active_epoch = coordinator.begin_epoch().expect("epoch starts");
        let frame = shared_frame(Codec::H264, 91, true);

        let sealed = protect_shared_h264_frame(
            config(active_epoch),
            &mut coordinator,
            &authorization,
            &frame,
        )
        .expect("shared H.264 frame is protected");
        let binding = sealed.binding();

        assert_eq!(binding.presentation_id(), 700);
        assert_eq!(binding.stream_id(), 800);
        assert_eq!(binding.epoch(), active_epoch);
        assert_eq!(binding.frame_id(), 91);
        assert_eq!(binding.timestamp_us(), 91 * 33_333);
        assert!(binding.keyframe());
        assert!(!sealed.is_empty());
    }

    #[test]
    fn shared_multicast_bridge_rejects_non_h264_before_sealing() {
        let authorization = authorization_with_receiver(1);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver registers");
        let active_epoch = coordinator.begin_epoch().expect("epoch starts");

        assert!(matches!(
            protect_shared_h264_frame(
                config(active_epoch),
                &mut coordinator,
                &authorization,
                &shared_frame(Codec::Hevc, 1, true),
            ),
            Err(ProtectedMulticastSendError::UnsupportedCodec)
        ));
    }

    #[test]
    fn shared_multicast_bridge_fails_closed_when_rotation_is_required() {
        let authorization = authorization_with_receiver(1);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver registers");
        let active_epoch = coordinator.begin_epoch().expect("epoch starts");
        assert!(coordinator.remove_receiver(principal(1)));
        assert!(coordinator.rotation_required());

        assert!(matches!(
            protect_shared_h264_frame(
                config(active_epoch),
                &mut coordinator,
                &authorization,
                &shared_frame(Codec::H264, 2, false),
            ),
            Err(ProtectedMulticastSendError::Coordinator(
                GroupMediaCoordinatorError::RotationRequired
            ))
        ));
    }

    #[test]
    fn shared_multicast_bridge_rejects_sender_epoch_drift() {
        let authorization = authorization_with_receiver(1);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver registers");
        let first_epoch = coordinator.begin_epoch().expect("first epoch starts");
        let second_epoch = coordinator.begin_epoch().expect("second epoch starts");
        assert_ne!(first_epoch, second_epoch);

        assert!(matches!(
            protect_shared_h264_frame(
                config(first_epoch),
                &mut coordinator,
                &authorization,
                &shared_frame(Codec::H264, 3, false),
            ),
            Err(ProtectedMulticastSendError::Coordinator(
                GroupMediaCoordinatorError::Crypto(GroupMediaError::BindingEpochMismatch)
            ))
        ));
    }

    #[test]
    fn sender_config_requires_runtime_probe_and_nonzero_binding() {
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                700,
                800,
                epoch(1),
                MulticastProbeOutcome::Unavailable(MulticastProbeFailure::JoinFailed),
            ),
            Err(ProtectedMulticastSendError::MulticastUnavailable)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                0,
                700,
                800,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidPort)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                0,
                800,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidPresentationId)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                700,
                0,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidStreamId)
        ));
    }

    #[test]
    fn packetizer_uses_authenticated_binding_and_advances_sequence() {
        let epoch = epoch(3);
        let mut packetizer = ProtectedMulticastPacketizer::new(config(epoch));
        let first = sealed_frame(700, 800, epoch, 91, 123_456, true, MAX_PACKET_PAYLOAD * 2);
        let prepared = packetizer.packetize(&first).expect("packetized frame");

        assert!(prepared.packets.len() >= 2);
        assert_eq!(prepared.first_sequence, 0);
        assert_eq!(
            prepared.next_sequence,
            u32::try_from(prepared.packets.len()).expect("bounded packet count")
        );
        assert_eq!(prepared.packets[0].header.protocol_major, 0);
        assert_eq!(prepared.packets[0].header.protocol_minor, 4);
        assert_eq!(prepared.packets[0].header.stream_id, 800);
        assert_eq!(prepared.packets[0].header.frame_id, 91);
        assert_eq!(prepared.packets[0].header.sequence, 0);
        assert_eq!(prepared.packets[0].header.timestamp_us, 123_456);
        assert!(
            prepared.packets[0]
                .header
                .flags
                .contains(MediaFlags::KEYFRAME)
        );

        let second = sealed_frame(700, 800, epoch, 92, 156_789, false, 32);
        let next = packetizer.packetize(&second).expect("second frame");
        assert_eq!(next.packets[0].header.sequence, prepared.next_sequence);
        assert!(!next.packets[0].header.flags.contains(MediaFlags::KEYFRAME));
    }

    #[test]
    fn binding_mismatch_is_rejected_without_consuming_sequence() {
        let epoch = epoch(4);
        let mut packetizer = ProtectedMulticastPacketizer::new(config(epoch));
        let wrong = sealed_frame(701, 800, epoch, 1, 1_000, false, 32);

        assert!(matches!(
            packetizer.packetize(&wrong),
            Err(ProtectedMulticastSendError::FrameBindingMismatch)
        ));

        let valid = sealed_frame(700, 800, epoch, 2, 2_000, false, 32);
        let prepared = packetizer.packetize(&valid).expect("valid frame");
        assert_eq!(prepared.packets[0].header.sequence, 0);
    }

    #[test]
    fn config_pins_local_interface_and_classroom_destination() {
        let config = config(epoch(5));
        assert_eq!(
            config.local_bind(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 10)), 0)
        );
        assert_eq!(
            config.destination(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 10, 20, 30)), 50_000)
        );
    }
}
