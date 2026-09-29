use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::media::{MAX_PACKET_PAYLOAD, MediaFlags};
use classmesh_security::group_media::MAX_GROUP_MEDIA_SEALED_BYTES;

use crate::multicast::{MulticastMembership, MulticastProbeFailure, MulticastProbeOutcome};
use crate::receiver::ReceiverEvent;
use crate::udp::DatagramError;
use crate::{MediaPacket, PacketizeMeta, packetize_frame};

use super::runtime::{DatagramFailureDisposition, classify_datagram_failure};

use super::*;

fn membership() -> MulticastMembership {
    MulticastMembership::new(
        Ipv4Addr::new(239, 10, 20, 30),
        Ipv4Addr::new(192, 168, 50, 10),
    )
    .expect("valid classroom multicast membership")
}

fn sender() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 50, 20)
}

fn config() -> ProtectedMulticastReceiverConfig {
    ProtectedMulticastReceiverConfig::new(
        membership(),
        50_000,
        sender(),
        800,
        MulticastProbeOutcome::Available,
    )
    .expect("valid receiver config")
}

fn source() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(sender()), 49_999)
}

fn packets(frame_id: u64, keyframe: bool) -> Vec<MediaPacket> {
    packetize_frame(
        &vec![0x5a; MAX_PACKET_PAYLOAD * 2 + 17],
        PacketizeMeta {
            protocol_major: 0,
            protocol_minor: 4,
            stream_id: 800,
            frame_id,
            first_sequence: 10,
            timestamp_us: frame_id * 33_333,
            keyframe,
        },
    )
    .expect("test ciphertext packetizes")
}

#[test]
fn malformed_datagrams_are_media_local_but_real_io_failures_are_not() {
    assert_eq!(
        classify_datagram_failure(&DatagramError::PayloadLengthMismatch),
        DatagramFailureDisposition::DropMalformed
    );
    assert_eq!(
        classify_datagram_failure(&DatagramError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "test timeout",
        ))),
        DatagramFailureDisposition::Tick
    );
    assert_eq!(
        classify_datagram_failure(&DatagramError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "test reset",
        ))),
        DatagramFailureDisposition::Fail
    );
}

#[test]
fn config_requires_probe_unicast_sender_and_nonzero_binding() {
    assert!(matches!(
        ProtectedMulticastReceiverConfig::new(
            membership(),
            50_000,
            sender(),
            800,
            MulticastProbeOutcome::Unavailable(MulticastProbeFailure::JoinFailed),
        ),
        Err(ProtectedMulticastReceiveError::MulticastUnavailable)
    ));
    assert!(matches!(
        ProtectedMulticastReceiverConfig::new(
            membership(),
            0,
            sender(),
            800,
            MulticastProbeOutcome::Available,
        ),
        Err(ProtectedMulticastReceiveError::InvalidPort)
    ));
    for invalid in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(239, 1, 2, 3),
    ] {
        assert!(matches!(
            ProtectedMulticastReceiverConfig::new(
                membership(),
                50_000,
                invalid,
                800,
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastReceiveError::InvalidExpectedSender)
        ));
    }
    assert!(matches!(
        ProtectedMulticastReceiverConfig::new(
            membership(),
            50_000,
            sender(),
            0,
            MulticastProbeOutcome::Available,
        ),
        Err(ProtectedMulticastReceiveError::InvalidStreamId)
    ));
}

#[test]
fn exact_sender_stream_and_version_reassemble_ciphertext() {
    let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
    let frame = packets(9, true);
    let expected: Vec<u8> = frame
        .iter()
        .flat_map(|packet| packet.payload.iter().copied())
        .collect();
    let mut ready = None;

    for packet in frame.iter().rev() {
        if let ProtectedMulticastReceiveOutcome::Events(batch) =
            state.push_packet(5_000, packet, source())
            && let Some(frame) = batch.frames.into_iter().next()
        {
            ready = Some(frame);
        }
    }

    let ready = ready.expect("complete ciphertext frame");
    assert_eq!(ready.stream_id(), 800);
    assert_eq!(ready.frame_id(), 9);
    assert_eq!(ready.timestamp_us(), 9 * 33_333);
    assert!(ready.keyframe());
    assert_eq!(ready.ciphertext(), expected);
}

#[test]
fn unexpected_source_stream_version_and_group_retransmit_are_media_local_drops() {
    let cases = [
        (
            packets(1, false).remove(0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 21)), 49_999),
            MulticastPacketDropReason::UnexpectedSource,
        ),
        (
            {
                let mut packet = packets(1, false).remove(0);
                packet.header.stream_id = 801;
                packet
            },
            source(),
            MulticastPacketDropReason::WrongStream,
        ),
        (
            {
                let mut packet = packets(1, false).remove(0);
                packet.header.protocol_minor = 3;
                packet
            },
            source(),
            MulticastPacketDropReason::UnexpectedProtocolVersion,
        ),
        (
            {
                let mut packet = packets(1, false).remove(0);
                packet.header.flags = packet.header.flags | MediaFlags::RETRANSMIT;
                packet
            },
            source(),
            MulticastPacketDropReason::RetransmitUnsupported,
        ),
        (
            {
                let mut packet = packets(1, false).remove(0);
                packet.header.flags = packet.header.flags | MediaFlags::FEC;
                packet
            },
            source(),
            MulticastPacketDropReason::FecUnsupported,
        ),
    ];

    for (packet, packet_source, expected) in cases {
        let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
        assert_eq!(
            state.push_packet(0, &packet, packet_source),
            ProtectedMulticastReceiveOutcome::Dropped(expected)
        );
        assert_eq!(state.dropped_frames(), 0);
    }
}

#[test]
fn oversized_packet_count_is_dropped_before_receiver_window_allocation() {
    let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
    let mut packet = packets(3, false).remove(0);
    let max_packets = MAX_GROUP_MEDIA_SEALED_BYTES.div_ceil(MAX_PACKET_PAYLOAD);
    packet.header.packet_count =
        u16::try_from(max_packets + 1).expect("group-media packet bound fits u16");
    packet.header.packet_index = 0;

    assert_eq!(
        state.push_packet(0, &packet, source()),
        ProtectedMulticastReceiveOutcome::Dropped(MulticastPacketDropReason::FrameTooLarge)
    );
    assert_eq!(state.dropped_frames(), 0);
}

#[test]
fn oversized_completed_ciphertext_is_not_exposed_to_sframe_runtime() {
    let batch =
        ProtectedMulticastReceiveBatch::from_receiver_events(vec![ReceiverEvent::FrameReady(
            crate::AssembledFrame {
                stream_id: 800,
                frame_id: 5,
                timestamp_us: 5_000,
                keyframe: false,
                data: vec![0x5a; MAX_GROUP_MEDIA_SEALED_BYTES + 1],
            },
        )]);

    assert!(batch.frames.is_empty());
    assert_eq!(batch.dropped_invalid_frames, 1);
    assert!(!batch.is_empty());
}

#[test]
fn receiver_window_feedback_is_exposed_without_transport_retransmission() {
    let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
    let frame = packets(2, false);
    let _ = state.push_packet(0, &frame[0], source());
    let _ = state.push_packet(1_000, &frame[2], source());

    let nack = state.tick(25_000);
    assert!(matches!(
        nack.feedback.as_slice(),
        [FeedbackMessage::Nack {
            stream_id: 800,
            frame_id: 2,
            missing_packet_indices,
        }] if missing_packet_indices == &vec![1]
    ));

    let expired = state.tick(100_000);
    assert!(expired.feedback.iter().any(|feedback| matches!(
        feedback,
        FeedbackMessage::RequestKeyframe {
            stream_id: 800,
            after_frame_id: 2,
        }
    )));
    assert_eq!(expired.dropped_stale_frames, 1);
    assert_eq!(state.dropped_frames(), 1);
}

#[test]
fn multicast_nack_feedback_is_bounded_to_control_contract() {
    let missing: Vec<u16> =
        (0..u16::try_from(MAX_NACK_PACKET_INDICES + 5).expect("small test bound")).collect();
    let batch =
        ProtectedMulticastReceiveBatch::from_receiver_events(vec![ReceiverEvent::NeedNack {
            stream_id: 800,
            frame_id: 44,
            missing_packet_indices: missing,
        }]);

    let [
        FeedbackMessage::Nack {
            missing_packet_indices,
            ..
        },
    ] = batch.feedback.as_slice()
    else {
        panic!("expected bounded NACK");
    };
    assert_eq!(missing_packet_indices.len(), MAX_NACK_PACKET_INDICES);
}

#[test]
fn receiver_config_binds_all_ipv4_interfaces_but_joins_selected_interface() {
    let config = config();
    assert_eq!(
        config.local_bind(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000)
    );
    assert_eq!(
        config.membership().interface(),
        Ipv4Addr::new(192, 168, 50, 10)
    );
    assert_eq!(config.membership().group(), Ipv4Addr::new(239, 10, 20, 30));
}
