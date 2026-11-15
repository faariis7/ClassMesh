//! Local sockets and ephemeral SFrame keys exercise the Worker up to the
//! authenticated access-unit boundary. Native fixture and multicast runs are
//! explicitly enabled by the lab operator.
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

use classmesh_lab::recorded_media::{MAX_INPUT_BYTES, parse_access_units};
use classmesh_network::multicast_receiver::{
    MulticastPacketDropReason, ProtectedMulticastReceiveBatch as Batch,
    ProtectedMulticastReceiveOutcome as Outcome,
};
use classmesh_network::protected_unicast_sender::{
    ProtectedUnicastFrameSender, ProtectedUnicastSenderConfig, ProtectedUnicastTrySendOutcome,
};
use classmesh_network::udp::UdpMediaSocket;
use classmesh_network::{MediaPacket, PacketizeMeta, packetize_frame};
use classmesh_protocol::control_wire::PresentationKeyGrant;
use classmesh_protocol::media::MEDIA_PROTOCOL_VERSION;
use classmesh_security::group_media::{
    GROUP_MEDIA_KEY_BYTES, GroupMediaEpoch, GroupMediaFrameBinding, GroupMediaKeyMaterial,
    GroupMediaSender, SealedGroupMediaFrame,
};
use classmesh_windows_runtime::ipc::{
    ServicePresentationKeyClear, ServicePresentationMulticastStart, ServicePresentationUnicastStart,
};
use classmesh_windows_runtime::ipc_sensitive::{
    PresentationKeyInstallBinding, SensitivePresentationKeyInstall,
};
use classmesh_worker::group_media_receive::{WorkerGroupMediaKeyError, WorkerGroupMediaKeyState};
use classmesh_worker::presentation_multicast_receive::WorkerPresentationMulticastRuntime;
use classmesh_worker::presentation_unicast_receive::WorkerPresentationUnicastRuntime;
use sha2::{Digest, Sha256};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 23, 94);
const PRESENTATION: u64 = 55;
const STREAM: u32 = 9;
const FPS: u8 = 12;

#[derive(Clone, Copy, Debug)]
enum Route {
    Unicast,
    Multicast(Ipv4Addr),
}

impl Route {
    fn source(self) -> Ipv4Addr {
        match self {
            Self::Unicast => Ipv4Addr::LOCALHOST,
            Self::Multicast(interface) => interface,
        }
    }

    fn endpoint(self, port: u16) -> SocketAddr {
        match self {
            Self::Unicast => (Ipv4Addr::LOCALHOST, port).into(),
            Self::Multicast(_) => (GROUP, port).into(),
        }
    }

    fn socket(self) -> UdpMediaSocket {
        let socket = UdpMediaSocket::bind((self.source(), 0).into()).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        if let Self::Multicast(interface) = self {
            socket.set_multicast_interface_v4(interface).unwrap();
            socket.set_multicast_loop_v4(true).unwrap();
            socket.set_multicast_ttl_v4(0).unwrap();
        }
        socket
    }
}

enum WorkerReceiver {
    Unicast(WorkerPresentationUnicastRuntime),
    Multicast(WorkerPresentationMulticastRuntime),
}

impl WorkerReceiver {
    fn start(route: Route, port: u16, session: u64, dimensions: (u16, u16)) -> Self {
        let (width, height) = dimensions;
        match route {
            Route::Unicast => Self::Unicast(
                WorkerPresentationUnicastRuntime::start(ServicePresentationUnicastStart {
                    control_session_id: session,
                    request_id: 1,
                    presentation_id: PRESENTATION,
                    stream_id: STREAM,
                    width,
                    height,
                    fps: FPS,
                    bitrate_kbps: 1_000,
                    port,
                    teacher_source: route.source().into(),
                })
                .unwrap(),
            ),
            Route::Multicast(interface) => Self::Multicast(
                WorkerPresentationMulticastRuntime::start(ServicePresentationMulticastStart {
                    control_session_id: session,
                    request_id: 1,
                    presentation_id: PRESENTATION,
                    stream_id: STREAM,
                    width,
                    height,
                    fps: FPS,
                    bitrate_kbps: 1_000,
                    group: GROUP,
                    port,
                    interface,
                    teacher_source: interface,
                })
                .unwrap(),
            ),
        }
    }

    fn matches(&self, binding: PresentationKeyInstallBinding) -> bool {
        match self {
            Self::Unicast(receiver) => receiver.matches_key_binding(binding),
            Self::Multicast(receiver) => receiver.matches_key_binding(binding),
        }
    }

    fn try_receive(&self) -> Option<Outcome> {
        match self {
            Self::Unicast(receiver) => receiver.try_receive(),
            Self::Multicast(receiver) => receiver.try_receive(),
        }
    }

    fn dropped_events(&self) -> u64 {
        match self {
            Self::Unicast(receiver) => receiver.dropped_events(),
            Self::Multicast(receiver) => receiver.dropped_events(),
        }
    }

    fn receive_event(&self) -> Outcome {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(outcome) = self.try_receive() {
                return outcome;
            }
            assert!(
                Instant::now() < deadline,
                "Worker did not receive a socket event"
            );
            sleep(Duration::from_millis(1));
        }
    }

    fn batch(&self) -> Batch {
        match self.receive_event() {
            Outcome::Events(batch) => batch,
            Outcome::Dropped(reason) => panic!("unexpected socket rejection: {reason:?}"),
        }
    }
}

fn install_key(
    keys: &mut WorkerGroupMediaKeyState,
    session: u64,
    epoch: u32,
) -> (PresentationKeyInstallBinding, GroupMediaSender) {
    let mut grant = PresentationKeyGrant {
        presentation_id: PRESENTATION,
        stream_id: u64::from(STREAM),
        epoch,
        key_material: vec![0; GROUP_MEDIA_KEY_BYTES],
    };
    getrandom::fill(&mut grant.key_material).unwrap();
    let material =
        GroupMediaKeyMaterial::import_received_wire(&mut grant.key_material.clone()).unwrap();
    let install =
        SensitivePresentationKeyInstall::take_from_control_grant(session, 2, &mut grant).unwrap();
    let binding = keys.install(install).unwrap();
    let sender = GroupMediaSender::new(GroupMediaEpoch::new(epoch).unwrap(), &material).unwrap();
    (binding, sender)
}

fn seal(
    sender: &mut GroupMediaSender,
    binding: PresentationKeyInstallBinding,
    id: u64,
    timestamp_us: u64,
    keyframe: bool,
    bytes: &[u8],
) -> SealedGroupMediaFrame {
    let frame = GroupMediaFrameBinding::new(
        binding.presentation_id,
        binding.stream_id,
        GroupMediaEpoch::new(binding.epoch).unwrap(),
        id,
        timestamp_us,
        keyframe,
    )
    .unwrap();
    sender.seal_bound_frame(bytes, frame).unwrap()
}

fn packets(frame: &SealedGroupMediaFrame) -> Vec<MediaPacket> {
    let binding = frame.binding();
    packetize_frame(
        frame.as_bytes(),
        PacketizeMeta {
            protocol_major: u8::try_from(MEDIA_PROTOCOL_VERSION.major).unwrap(),
            protocol_minor: u8::try_from(MEDIA_PROTOCOL_VERSION.minor).unwrap(),
            stream_id: binding.stream_id(),
            frame_id: binding.frame_id(),
            first_sequence: 0,
            timestamp_us: binding.timestamp_us(),
            keyframe: binding.keyframe(),
        },
    )
    .unwrap()
}

fn deliver(socket: &UdpMediaSocket, destination: SocketAddr, packets: &[MediaPacket]) {
    for packet in packets {
        socket.send_packet_to(packet, destination).unwrap();
    }
}

fn next_frame(
    receiver: &WorkerReceiver,
) -> classmesh_network::multicast_receiver::ReceivedGroupMediaCiphertext {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            Instant::now() < deadline,
            "Worker did not assemble the frame"
        );
        let mut batch = receiver.batch();
        assert_eq!(batch.dropped_stale_frames, 0);
        if let Some(frame) = batch.frames.pop() {
            assert!(batch.frames.is_empty());
            return frame;
        }
    }
}

fn verify_route(route: Route, dimensions: (u16, u16), source: &[u8]) {
    let reservation = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let receiver = WorkerReceiver::start(route, port, 1, dimensions);
    let destination = route.endpoint(port);
    let socket = route.socket();
    let mut keys = WorkerGroupMediaKeyState::default();
    let (binding, mut sender) = install_key(&mut keys, 1, 1);
    assert!(receiver.matches(binding));

    // A fragment is received and generates feedback, then expires at the
    // deployed policy. Its late suffix cannot complete the expired assembly.
    let partial = seal(&mut sender, binding, 1, 0, true, &[0x42; 2_400]);
    let partial = packets(&partial);
    deliver(&socket, destination, &partial[..1]);
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < Duration::from_secs(2));
        let batch = receiver.batch();
        assert!(batch.frames.is_empty());
        if batch.dropped_stale_frames != 0 {
            break;
        }
    }
    deliver(&socket, destination, &partial[1..]);

    let epoch = GroupMediaEpoch::new(binding.epoch).unwrap();
    let mut unicast = match route {
        Route::Unicast => Some(
            ProtectedUnicastFrameSender::bind_nonblocking(
                ProtectedUnicastSenderConfig::new(destination, PRESENTATION, STREAM, epoch)
                    .unwrap(),
            )
            .unwrap(),
        ),
        Route::Multicast(_) => None,
    };
    let mut received_hash = Sha256::new();
    let units = parse_access_units(source).unwrap();
    let started = Instant::now();
    let mut last_frame = None;
    for (index, unit) in units.iter().enumerate() {
        let timestamp_us = index as u64 * 1_000_000 / u64::from(FPS);
        let due = started + Duration::from_micros(timestamp_us);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            sleep(wait);
        }
        let id = index as u64 + 2;
        let frame = seal(
            &mut sender,
            binding,
            id,
            timestamp_us,
            unit.keyframe,
            unit.data,
        );
        if let Some(sender) = unicast.as_mut() {
            assert!(matches!(
                sender.try_send_frame(&frame).unwrap(),
                ProtectedUnicastTrySendOutcome::Sent(_)
            ));
        } else {
            deliver(&socket, destination, &packets(&frame));
        }
        let ciphertext = next_frame(&receiver);
        let unit = keys.open_access_unit(ciphertext).unwrap();
        assert_eq!(unit.frame_id, id);
        received_hash.update(&unit.data);
        last_frame = Some(frame);
    }
    let actual = received_hash.finalize();
    assert_eq!(actual, Sha256::digest(source));
    assert_eq!(
        keys.authentication_stats().unwrap().opened_frames,
        units.len() as u64
    );
    assert_eq!(receiver.dropped_events(), 0);

    // Stop and reopen the same endpoint with a new control binding and
    // fresh epoch. Old ciphertext can reach the socket but cannot authenticate.
    let clear = ServicePresentationKeyClear {
        control_session_id: binding.control_session_id,
        request_id: binding.request_id,
        presentation_id: binding.presentation_id,
        stream_id: binding.stream_id,
        epoch: binding.epoch,
    };
    assert!(keys.clear_if_matches(clear));
    drop(receiver);
    let receiver = WorkerReceiver::start(route, port, 2, dimensions);
    let (new_binding, mut sender) = install_key(&mut keys, 2, 2);
    assert!(!receiver.matches(binding));
    assert!(receiver.matches(new_binding));

    let old = last_frame.unwrap();
    deliver(&socket, destination, &packets(&old));
    assert!(matches!(
        keys.open_access_unit(next_frame(&receiver)),
        Err(WorkerGroupMediaKeyError::Security(_))
    ));
    let id = old.binding().frame_id() + 1;
    let fresh = seal(&mut sender, new_binding, id, 0, true, units[0].data);
    deliver(&socket, destination, &packets(&fresh));
    assert_eq!(
        keys.open_access_unit(next_frame(&receiver)).unwrap().data,
        units[0].data
    );

    // Keep the consumer paused while validly encoded wrong-stream datagrams
    // generate drop outcomes. The Worker still bounds its outcome queue.
    let small = seal(&mut sender, new_binding, id + 1, 0, true, &[0x42]);
    let mut wrong = packets(&small).remove(0);
    wrong.header.stream_id += 1;
    for index in 0..96 {
        deliver(&socket, destination, std::slice::from_ref(&wrong));
        if index % 8 == 7 {
            sleep(Duration::from_millis(1));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while receiver.dropped_events() < 32 {
        assert!(
            Instant::now() < deadline,
            "expected bounded queue backpressure"
        );
        sleep(Duration::from_millis(1));
    }
    for _ in 0..64 {
        assert_eq!(
            receiver.receive_event(),
            Outcome::Dropped(MulticastPacketDropReason::WrongStream)
        );
    }
    assert!(receiver.try_receive().is_none());
    eprintln!(
        "{route:?} {}x{} frames={} SHA256={actual:x} expiry=pass reconnect=pass queue=pass",
        dimensions.0,
        dimensions.1,
        units.len(),
    );
}

fn read_fixture(path: PathBuf) -> Vec<u8> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .unwrap();
    assert!(data.len() <= MAX_INPUT_BYTES);
    data
}

#[test]
fn recorded_frames_reach_the_worker_authentication_boundary() {
    let Some(fixtures) = std::env::var_os("CLASSMESH_M3_FIXTURES").map(PathBuf::from) else {
        let mut data = vec![0, 0, 1, 9, 0xf0, 0, 0, 1, 0x65];
        data.extend_from_slice(&[0x5a; 2_400]);
        data.extend_from_slice(&[0, 0, 1, 9, 0xf0, 0, 0, 1, 0x41, 0x6a]);
        verify_route(Route::Unicast, (320, 180), &data);
        return;
    };
    let multicast = std::env::var("CLASSMESH_M3_MULTICAST_INTERFACE")
        .ok()
        .map(|interface| Route::Multicast(interface.parse().unwrap()));
    for route in std::iter::once(Route::Unicast).chain(multicast) {
        for dimensions in [(320, 180), (64, 64), (32, 32)] {
            let data =
                read_fixture(fixtures.join(format!("{}x{}.h264", dimensions.0, dimensions.1)));
            assert_eq!(parse_access_units(&data).unwrap().len(), 36);
            verify_route(route, dimensions, &data);
        }
    }
}
