use classmesh_core::adaptation::AdaptationPolicy;
use classmesh_core::{NetworkMetrics, StreamKind};
use classmesh_network::receiver::{ReceiverEvent, ReceiverPolicy, ReceiverWindow};
use classmesh_network::{PacketizeMeta, packetize_frame};
use classmesh_protocol::media::MAX_PACKET_PAYLOAD;

fn main() {
    println!("ClassMesh lab — synthetic media transport check");

    let synthetic_frame = vec![0xAB_u8; MAX_PACKET_PAYLOAD * 4 + 123];
    let packets = packetize_frame(
        &synthetic_frame,
        PacketizeMeta {
            protocol_major: 0,
            protocol_minor: 1,
            stream_id: 1,
            frame_id: 1,
            first_sequence: 100,
            timestamp_us: 0,
            keyframe: true,
        },
    )
    .expect("synthetic frame must packetize");

    println!(
        "frame={} bytes -> {} datagrams (payload budget={} bytes)",
        synthetic_frame.len(),
        packets.len(),
        MAX_PACKET_PAYLOAD
    );

    let dropped_index = packets.len() / 2;
    let mut receiver = ReceiverWindow::new(ReceiverPolicy::default());
    let mut events = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        if index == dropped_index {
            println!("injecting loss: packet index {index}");
            continue;
        }
        events.extend(
            receiver
                .push(0, packet)
                .expect("synthetic packet should be accepted"),
        );
    }

    events.extend(receiver.tick(25_000));
    for event in events {
        match event {
            ReceiverEvent::NeedNack {
                frame_id,
                missing_packet_indices,
                ..
            } => println!(
                "receiver requests NACK for frame {frame_id}, missing={missing_packet_indices:?}"
            ),
            ReceiverEvent::FrameReady(frame) => {
                println!(
                    "frame {} completed ({} bytes)",
                    frame.frame_id,
                    frame.data.len()
                )
            }
            ReceiverEvent::NeedKeyframe { after_frame_id, .. } => {
                println!("receiver requests keyframe after stale frame {after_frame_id}")
            }
            ReceiverEvent::DroppedStaleFrame { frame_id, .. } => {
                println!("dropped stale frame {frame_id}")
            }
        }
    }

    let policy = AdaptationPolicy::default();
    let healthy_wired = NetworkMetrics {
        rtt_ms: 5.0,
        packet_loss: 0.001,
        jitter_ms: 0.5,
        decode_fps: 30.0,
        queue_delay_ms: 3.0,
        estimated_mbps: 900.0,
        multicast_viable: true,
        wireless: false,
    };
    let decision = policy.decide(StreamKind::TeacherPresentation, healthy_wired);
    println!(
        "healthy wired decision: {:?}, {}x{}@{} {}kbps",
        decision.transport,
        decision.profile.width,
        decision.profile.height,
        decision.profile.fps,
        decision.profile.bitrate_kbps
    );

    let congested_wifi = NetworkMetrics {
        rtt_ms: 95.0,
        packet_loss: 0.035,
        jitter_ms: 22.0,
        decode_fps: 22.0,
        queue_delay_ms: 35.0,
        estimated_mbps: 8.0,
        multicast_viable: false,
        wireless: true,
    };
    let decision = policy.decide(StreamKind::TeacherPresentation, congested_wifi);
    println!(
        "congested Wi-Fi decision: {:?}, {}x{}@{} {}kbps",
        decision.transport,
        decision.profile.width,
        decision.profile.height,
        decision.profile.fps,
        decision.profile.bitrate_kbps
    );
}
