//! Two-host synthetic qualification of the protected multicast UDP/Worker path.
use std::error::Error;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use classmesh_network::multicast::{MulticastMembership, MulticastProbeOutcome};
use classmesh_network::multicast_diagnostics::{DeliveryStage, DeliveryTrace};
use classmesh_network::multicast_sender::{
    ProtectedMulticastFrameSender, ProtectedMulticastSenderConfig, ProtectedMulticastTrySendOutcome,
};
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaFrameBinding, GroupMediaKeyMaterial, GroupMediaSender,
};
use classmesh_windows_runtime::ipc::ServicePresentationMulticastStart;
use classmesh_worker::presentation_multicast_receive::WorkerPresentationMulticastRuntime;

const PRESENTATION: u64 = 1;
const FPS: u8 = 30;
const MAX_FRAME_BYTES: u64 = 16_384;
const DRAIN_BATCH: usize = 64;
const MAX_FRAMES: u64 = 240;
const MAX_SECONDS: u64 = 60;
type LabResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct Route {
    interface: Ipv4Addr,
    destination: SocketAddrV4,
    stream: u32,
}

impl Route {
    fn parse(interface: &str, group: &str, port: &str, stream: &str) -> LabResult<Self> {
        let interface = interface.parse()?;
        let group = group.parse()?;
        MulticastMembership::new(group, interface)
            .map_err(|error| format!("invalid multicast membership: {error:?}"))?;
        let port = port.parse()?;
        let stream = stream.parse()?;
        if port == 0 || stream == 0 {
            return Err("port and stream must be nonzero".into());
        }
        Ok(Self {
            interface,
            destination: SocketAddrV4::new(group, port),
            stream,
        })
    }

    fn report(
        self,
        role: &str,
        sender: impl std::fmt::Display,
        complete: bool,
        trace: &DeliveryTrace,
        consumer: Option<(u64, u64)>,
    ) -> io::Result<()> {
        let mut out = io::BufWriter::new(io::stdout().lock());
        writeln!(out, "# format=classmesh-multicast-delivery-v1")?;
        writeln!(out, "# role={role}")?;
        writeln!(out, "# interface={}", self.interface)?;
        writeln!(out, "# sender={sender}")?;
        writeln!(out, "# destination={}", self.destination)?;
        writeln!(out, "# stream={}", self.stream)?;
        writeln!(out, "# complete={complete}")?;
        writeln!(
            out,
            "# started_unix_us={}",
            trace
                .wall_start()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_micros()
        )?;
        writeln!(out, "# omitted={}", trace.omitted())?;
        if let Some((outcomes, frames)) = consumer {
            writeln!(out, "# worker_consumer_outcomes={outcomes}")?;
            writeln!(out, "# worker_consumer_frames={frames}")?;
        }
        for stage in DeliveryStage::ALL {
            writeln!(out, "# {stage:?}={}", trace.count(stage))?;
        }
        writeln!(
            out,
            "stage\telapsed_us\tpeer\tstream\tframe\tsequence\tindex\tcount\tmedia_us\trejection"
        )?;
        for event in trace.events() {
            write!(out, "{:?}\t{}\t", event.stage, event.elapsed_us)?;
            if let (Some(packet), Some(peer)) = (event.packet, event.peer) {
                write!(
                    out,
                    "{peer}\t{}\t{}\t{}\t{}\t{}\t{}\t",
                    packet.stream_id,
                    packet.frame_id,
                    packet.sequence,
                    packet.packet_index,
                    packet.packet_count,
                    packet.timestamp_us
                )?;
            } else if let Some(frame) = event.frame_id {
                write!(out, "\t\t{frame}\t\t\t\t\t")?;
            } else {
                write!(out, "\t\t\t\t\t\t\t")?;
            }
            if let Some(reason) = event.rejection {
                write!(out, "{reason:?}")?;
            }
            writeln!(out)?;
        }
        out.flush()
    }
}

fn main() -> LabResult<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [role, interface, group, port, stream, frames, frame_bytes] if role == "send" => {
            let route = Route::parse(interface, group, port, stream)?;
            send(route, bounded(frames, MAX_FRAMES)?, usize::try_from(bounded(frame_bytes, MAX_FRAME_BYTES)?)?)
        }
        [role, interface, sender, group, port, stream, seconds] if role == "receive" => {
            let route = Route::parse(interface, group, port, stream)?;
            receive(route, sender.parse()?, bounded(seconds, MAX_SECONDS)?)
        }
        _ => Err("usage: multicast_delivery send <interface-ip> <group> <port> <stream> <frames:1..240> <frame-bytes:1..16384>\n       multicast_delivery receive <interface-ip> <sender-ip> <group> <port> <stream> <seconds:1..60>".into()),
    }
}

fn bounded(value: &str, max: u64) -> LabResult<u64> {
    let value = value.parse()?;
    if !(1..=max).contains(&value) {
        return Err(format!("value must be in 1..={max}").into());
    }
    Ok(value)
}

fn send(route: Route, frames: u64, frame_bytes: usize) -> LabResult<()> {
    let epoch = GroupMediaEpoch::new(1)?;
    let config = ProtectedMulticastSenderConfig::new(
        MulticastMembership::new(*route.destination.ip(), route.interface)
            .map_err(|error| format!("invalid multicast membership: {error:?}"))?,
        route.destination.port(),
        PRESENTATION,
        route.stream,
        epoch,
        // Explicit lab operator selection. Production capability negotiation is outside this example.
        MulticastProbeOutcome::Available,
    )?;
    let mut socket = ProtectedMulticastFrameSender::bind_nonblocking(config)?;
    let source = socket.local_addr()?;
    let mut protector = GroupMediaSender::new(epoch, &GroupMediaKeyMaterial::generate()?)?;
    let mut trace = DeliveryTrace::new();
    let mut backpressured_frames = 0;
    let payload = vec![0xa5; frame_bytes];
    let result = (|| -> LabResult<()> {
        let started = Instant::now();
        for frame_id in 1..=frames {
            let media_us = (frame_id - 1) * 1_000_000 / u64::from(FPS);
            thread::sleep(Duration::from_micros(media_us).saturating_sub(started.elapsed()));
            let sealed = protector.seal_bound_frame(
                &payload,
                GroupMediaFrameBinding::new(
                    PRESENTATION,
                    route.stream,
                    epoch,
                    frame_id,
                    media_us,
                    true,
                )?,
            )?;
            if let ProtectedMulticastTrySendOutcome::DroppedBackpressure(_) =
                socket.try_send_frame_observed(&sealed, Some(&mut trace))?
            {
                backpressured_frames += 1;
            }
        }
        Ok(())
    })();
    route.report("send", source, result.is_ok(), &trace, None)?;
    eprintln!("sender_backpressured_frames={backpressured_frames}");
    result
}

fn receive(route: Route, sender: Ipv4Addr, seconds: u64) -> LabResult<()> {
    let mut worker =
        WorkerPresentationMulticastRuntime::start_diagnostics(ServicePresentationMulticastStart {
            control_session_id: 1,
            request_id: 1,
            presentation_id: PRESENTATION,
            stream_id: route.stream,
            width: 320,
            height: 180,
            fps: FPS,
            bitrate_kbps: 2_000,
            group: *route.destination.ip(),
            port: route.destination.port(),
            interface: route.interface,
            teacher_source: sender,
        })?;
    eprintln!(
        "receiver_ready interface={} group={}",
        route.interface, route.destination
    );
    let started = Instant::now();
    let mut drained = 0;
    let mut drained_frames = 0;
    let mut drain = |worker: &WorkerPresentationMulticastRuntime| {
        let mut had_outcome = false;
        for outcome in std::iter::from_fn(|| worker.try_receive()).take(DRAIN_BATCH) {
            had_outcome = true;
            drained += 1;
            if let classmesh_network::multicast_receiver::ProtectedMulticastReceiveOutcome::Events(
                batch,
            ) = outcome
            {
                drained_frames += batch.frames.len() as u64;
            }
        }
        had_outcome
    };
    while started.elapsed() < Duration::from_secs(seconds) && !worker.failed() {
        drain(&worker);
        thread::sleep(Duration::from_millis(1));
    }
    let trace = worker
        .finish_diagnostics()
        .ok_or("receiver trace unavailable")?;
    while drain(&worker) {}
    let dropped_frames = trace.count(DeliveryStage::FrameQueueFull)
        + trace.count(DeliveryStage::FrameQueueDisconnected);
    let complete = !worker.failed()
        && drained == trace.count(DeliveryStage::Queued)
        && worker.dropped_events() == trace.count(DeliveryStage::QueueFull)
        && drained_frames + dropped_frames == trace.count(DeliveryStage::FrameAssembled);
    route.report(
        "receive",
        sender,
        complete,
        &trace,
        Some((drained, drained_frames)),
    )?;
    if !complete {
        return Err("receiver terminated early or trace and Worker totals disagree".into());
    }
    Ok(())
}
