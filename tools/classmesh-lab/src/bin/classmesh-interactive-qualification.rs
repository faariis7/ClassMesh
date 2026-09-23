#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-interactive-qualification is supported only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use classmesh_control::client_session::connect_client_session_with_retries;
    use classmesh_control::quic::{
        DEFAULT_IO_TIMEOUT, DEFAULT_RECONNECT_POLICY, enrolled_client_config,
    };
    use classmesh_control::ControlHello;
    use classmesh_identity_win::{
        CngMachineKey, DurableMachineIdentity, cng_client_cert_resolver,
    };
    use classmesh_protocol::control_wire::{
        ControlEnvelope, Heartbeat, InputEvent, KeyEvent, KeyframeRequest,
        MediaHealth as WireMediaHealth, MediaTransport, MouseMove, ProtocolVersion as WireVersion,
        ReceiverFeedback, ReleaseAllInput, StreamKind as WireStreamKind, StreamOffer, VideoCodec,
        VideoProfile, control_envelope, input_event,
    };
    use classmesh_protocol::media::{MEDIA_HEADER_LEN, MediaFlags, MediaPacketHeader};
    use classmesh_protocol::{Capability, ControlRole, PROTOCOL_VERSION};
    use classmesh_security::PrincipalId;
    use quinn::Endpoint;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout};

    type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Debug, Clone)]
    struct Config {
        connect: SocketAddr,
        server_name: String,
        identity_path: PathBuf,
        udp_listen: SocketAddr,
        seconds: u64,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        input_pulse: bool,
        degraded_feedback: bool,
        drop_media_after: Option<u64>,
        hold_key_vk: Option<u32>,
    }

    #[derive(Debug, Default)]
    struct MediaStats {
        packets: u64,
        invalid_packets: u64,
        foreign_stream_packets: u64,
        frames: u64,
        keyframes: u64,
        retransmits: u64,
        bytes: u64,
        highest_frame_id: Option<u64>,
        highest_keyframe_id: Option<u64>,
    }

    impl Config {
        fn parse() -> Result<Self, String> {
            let mut args = std::env::args().skip(1);
            let mut connect = None;
            let mut server_name = None;
            let mut identity_path = None;
            let mut udp_listen = "0.0.0.0:57020"
                .parse::<SocketAddr>()
                .expect("static socket address");
            let mut seconds = 30_u64;
            let mut width = 1280_u32;
            let mut height = 720_u32;
            let mut fps = 30_u32;
            let mut bitrate_kbps = 2_500_u32;
            let mut input_pulse = false;
            let mut degraded_feedback = false;
            let mut drop_media_after = None;
            let mut hold_key_vk = None;

            while let Some(arg) = args.next() {
                let mut value = || {
                    args.next()
                        .ok_or_else(|| format!("missing value after {arg}"))
                };
                match arg.as_str() {
                    "--connect" => {
                        connect = Some(
                            value()?
                                .parse()
                                .map_err(|_| "--connect must be IP:port".to_owned())?,
                        );
                    }
                    "--server-name" => server_name = Some(value()?),
                    "--identity" => identity_path = Some(PathBuf::from(value()?)),
                    "--udp-listen" => {
                        udp_listen = value()?
                            .parse()
                            .map_err(|_| "--udp-listen must be IP:port".to_owned())?;
                    }
                    "--seconds" => {
                        seconds = value()?
                            .parse()
                            .map_err(|_| "--seconds must be an integer".to_owned())?;
                    }
                    "--width" => {
                        width = value()?
                            .parse()
                            .map_err(|_| "--width must be an integer".to_owned())?;
                    }
                    "--height" => {
                        height = value()?
                            .parse()
                            .map_err(|_| "--height must be an integer".to_owned())?;
                    }
                    "--fps" => {
                        fps = value()?
                            .parse()
                            .map_err(|_| "--fps must be an integer".to_owned())?;
                    }
                    "--bitrate-kbps" => {
                        bitrate_kbps = value()?
                            .parse()
                            .map_err(|_| "--bitrate-kbps must be an integer".to_owned())?;
                    }
                    "--input-pulse" => input_pulse = true,
                    "--degraded-feedback" => degraded_feedback = true,
                    "--drop-media-after" => {
                        drop_media_after = Some(
                            value()?
                                .parse()
                                .map_err(|_| "--drop-media-after must be an integer".to_owned())?,
                        );
                    }
                    "--hold-key-vk" => {
                        hold_key_vk = Some(
                            value()?
                                .parse()
                                .map_err(|_| "--hold-key-vk must be an integer".to_owned())?,
                        );
                    }
                    "--help" | "-h" => return Err(Self::usage().to_owned()),
                    _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
                }
            }

            let connect = connect.ok_or_else(|| format!("--connect is required\n\n{}", Self::usage()))?;
            let server_name =
                server_name.ok_or_else(|| format!("--server-name is required\n\n{}", Self::usage()))?;
            let identity_path =
                identity_path.ok_or_else(|| format!("--identity is required\n\n{}", Self::usage()))?;
            if seconds == 0 {
                return Err("--seconds must be greater than zero".to_owned());
            }
            if udp_listen.port() == 0 {
                return Err("--udp-listen port must be non-zero".to_owned());
            }
            if let Some(drop_after) = drop_media_after
                && (drop_after == 0 || drop_after >= seconds)
            {
                return Err("--drop-media-after must be > 0 and < --seconds".to_owned());
            }
            if hold_key_vk.is_some_and(|vk| vk == 0 || vk > u32::from(u16::MAX)) {
                return Err("--hold-key-vk must be in 1..=65535".to_owned());
            }

            Ok(Self {
                connect,
                server_name,
                identity_path,
                udp_listen,
                seconds,
                width,
                height,
                fps,
                bitrate_kbps,
                input_pulse,
                degraded_feedback,
                drop_media_after,
                hold_key_vk,
            })
        }

        fn usage() -> &'static str {
            "ClassMesh Phase 6F interactive qualification client\n\n\
Required:\n\
  --connect <student-ip:port>\n\
  --server-name <certificate-dns-name>\n\
  --identity <teacher-machine-identity.json>\n\n\
Optional:\n\
  --udp-listen <ip:port>       default 0.0.0.0:57020\n\
  --seconds <n>                default 30\n\
  --width <n>                  default 1280\n\
  --height <n>                 default 720\n\
  --fps <n>                    default 30\n\
  --bitrate-kbps <n>           default 2500\n\
  --input-pulse                move pointer +12/-12 and ReleaseAll\n\
  --degraded-feedback          send two bounded degraded feedback samples\n\
  --drop-media-after <seconds> close UDP receiver while control heartbeats continue\n\
  --hold-key-vk <vk>           press a key then disconnect without key-up to test cleanup"
        }
    }

    fn wire_version() -> WireVersion {
        WireVersion {
            major: u32::from(PROTOCOL_VERSION.major),
            minor: u32::from(PROTOCOL_VERSION.minor),
        }
    }

    fn envelope(
        session_id: u64,
        sequence: u64,
        request_id: u64,
        payload: control_envelope::Payload,
    ) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session_id,
            sequence,
            protocol_version: Some(wire_version()),
            request_id,
            payload: Some(payload),
        }
    }

    fn input_envelope(
        session_id: u64,
        sequence: u64,
        event: input_event::Event,
        started: Instant,
    ) -> ControlEnvelope {
        envelope(
            session_id,
            sequence,
            0,
            control_envelope::Payload::InputEvent(InputEvent {
                sequence,
                timestamp_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                event: Some(event),
            }),
        )
    }

    async fn send_input_pulse(
        channel: &mut classmesh_control::quic::ControlChannel,
        session_id: u64,
        sequence: &mut u64,
        started: Instant,
    ) -> AppResult {
        for event in [
            input_event::Event::MouseMove(MouseMove {
                x: 12,
                y: 0,
                absolute: false,
            }),
            input_event::Event::MouseMove(MouseMove {
                x: -12,
                y: 0,
                absolute: false,
            }),
            input_event::Event::ReleaseAll(ReleaseAllInput {}),
        ] {
            *sequence = sequence
                .checked_add(1)
                .ok_or("control sequence exhausted")?;
            channel
                .send(&input_envelope(session_id, *sequence, event, started))
                .await?;
        }
        println!("input_pulse=sent");
        Ok(())
    }

    async fn receive_media(
        socket: UdpSocket,
        stream_id: u32,
        seconds: u64,
        drop_after: Option<u64>,
    ) -> MediaStats {
        let started = Instant::now();
        let receive_for = drop_after.unwrap_or(seconds);
        let mut stats = MediaStats::default();
        let mut buffer = vec![0_u8; MEDIA_HEADER_LEN + 1_200];

        while started.elapsed() < Duration::from_secs(receive_for) {
            match timeout(Duration::from_millis(250), socket.recv_from(&mut buffer)).await {
                Ok(Ok((len, _))) => {
                    stats.bytes = stats.bytes.saturating_add(len as u64);
                    match MediaPacketHeader::decode(&buffer[..len]) {
                        Ok(header) if header.stream_id == stream_id => {
                            stats.packets = stats.packets.saturating_add(1);
                            if header.flags.contains(MediaFlags::RETRANSMIT) {
                                stats.retransmits = stats.retransmits.saturating_add(1);
                            }
                            if stats.highest_frame_id.is_none_or(|frame| header.frame_id > frame) {
                                stats.highest_frame_id = Some(header.frame_id);
                                stats.frames = stats.frames.saturating_add(1);
                            }
                            if header.flags.contains(MediaFlags::KEYFRAME)
                                && stats
                                    .highest_keyframe_id
                                    .is_none_or(|frame| header.frame_id > frame)
                            {
                                stats.highest_keyframe_id = Some(header.frame_id);
                                stats.keyframes = stats.keyframes.saturating_add(1);
                            }
                        }
                        Ok(_) => {
                            stats.foreign_stream_packets =
                                stats.foreign_stream_packets.saturating_add(1);
                        }
                        Err(_) => {
                            stats.invalid_packets = stats.invalid_packets.saturating_add(1);
                        }
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }

        if drop_after.is_some() {
            println!("media_receiver=closed elapsed_s={}", started.elapsed().as_secs());
        }
        stats
    }

    pub async fn run() -> AppResult {
        let config = match Config::parse() {
            Ok(config) => config,
            Err(message) => {
                eprintln!("{message}");
                if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
                    return Ok(());
                }
                return Err("invalid arguments".into());
            }
        };

        let identity = DurableMachineIdentity::new(&config.identity_path)
            .load()?
            .ok_or_else(|| format!("teacher identity not found: {}", config.identity_path.display()))?;
        let key = CngMachineKey::open(identity.cng_key_name.clone())?;
        let certificate_chain = identity
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let resolver = cng_client_cert_resolver(certificate_chain, key)?;

        let mut roots = RootCertStore::empty();
        for root in &identity.trust_roots_der {
            roots.add(CertificateDer::from(root.clone()))?;
        }
        if roots.is_empty() {
            return Err("teacher identity has no trusted server roots".into());
        }

        let bind = match config.connect.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(enrolled_client_config(roots, resolver)?);

        let udp = UdpSocket::bind(config.udp_listen).await?;
        let udp_address = udp.local_addr()?;
        let principal = PrincipalId(identity.principal_id);
        let hello = ControlHello {
            principal_id: principal,
            role: ControlRole::Teacher,
            version: PROTOCOL_VERSION,
            capabilities: BTreeSet::from([
                Capability::UdpUnicast,
                Capability::H264HardwareDecode,
            ]),
            hostname: std::env::var("COMPUTERNAME")
                .unwrap_or_else(|_| "phase6f-teacher".to_owned()),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
        };

        let mut session = connect_client_session_with_retries(
            &endpoint,
            config.connect,
            &config.server_name,
            &hello,
            DEFAULT_IO_TIMEOUT,
            DEFAULT_RECONNECT_POLICY,
        )
        .await?;
        let session_id = session.established.control_session_id;
        println!(
            "control=connected session_id={} negotiated={:?}",
            session_id, session.established.negotiated.capabilities
        );

        if !session
            .established
            .negotiated
            .capabilities
            .contains(&Capability::UdpUnicast)
        {
            return Err("student did not negotiate UDP unicast; Worker media capability is not ready".into());
        }

        let stream_id = 6_001_u32;
        let port = udp_address.port();
        let parameters = {
            let [high, low] = port.to_be_bytes();
            vec![1, high, low]
        };
        let mut sequence = 2_u64;
        let offer_request_id = 2_u64;
        let offer = StreamOffer {
            stream_id: u64::from(stream_id),
            kind: WireStreamKind::Interactive as i32,
            transport: MediaTransport::UdpUnicast as i32,
            profile: Some(VideoProfile {
                width: config.width,
                height: config.height,
                fps: config.fps,
                bitrate_kbps: config.bitrate_kbps,
                codec: VideoCodec::H264 as i32,
            }),
            transport_parameters: parameters,
        };
        session
            .channel
            .send(&envelope(
                session_id,
                sequence,
                offer_request_id,
                control_envelope::Payload::StreamOffer(offer),
            ))
            .await?;
        let answer_envelope = session.channel.receive().await?;
        let Some(control_envelope::Payload::StreamAnswer(answer)) = answer_envelope.payload else {
            return Err("expected StreamAnswer".into());
        };
        if answer.stream_id != u64::from(stream_id) || answer_envelope.request_id != offer_request_id {
            return Err("StreamAnswer correlation mismatch".into());
        }
        if !answer.accepted {
            return Err(format!("interactive stream rejected: {}", answer.rejection_reason).into());
        }
        println!(
            "stream=accepted stream_id={} udp_port={} profile={}x{}@{} bitrate_kbps={}",
            stream_id, port, config.width, config.height, config.fps, config.bitrate_kbps
        );

        let media_task = tokio::spawn(receive_media(
            udp,
            stream_id,
            config.seconds,
            config.drop_media_after,
        ));
        let started = Instant::now();

        if config.input_pulse {
            send_input_pulse(&mut session.channel, session_id, &mut sequence, started).await?;
        }

        if config.degraded_feedback {
            for sample in 0..2 {
                sequence = sequence
                    .checked_add(1)
                    .ok_or("control sequence exhausted")?;
                let feedback = ReceiverFeedback {
                    stream_id: u64::from(stream_id),
                    rtt_ms: 45.0,
                    packet_loss: 0.12,
                    jitter_ms: 20.0,
                    decode_fps: 20.0,
                    decode_latency_ms: 15.0,
                    render_latency_ms: 10.0,
                    queue_delay_ms: 25.0,
                    dropped_frames: 3,
                    reordered_packets: 2,
                    received_bitrate_bps: 1_200_000,
                };
                session
                    .channel
                    .send(&envelope(
                        session_id,
                        sequence,
                        0,
                        control_envelope::Payload::ReceiverFeedback(feedback),
                    ))
                    .await?;
                if sample == 1 {
                    let response = timeout(Duration::from_secs(2), session.channel.receive())
                        .await
                        .map_err(|_| "timed out waiting for StreamReconfigure")??;
                    let Some(control_envelope::Payload::StreamReconfigure(reconfigure)) =
                        response.payload
                    else {
                        return Err("expected StreamReconfigure after degraded feedback".into());
                    };
                    println!(
                        "adaptation=reconfigured stream_id={} profile={:?}",
                        reconfigure.stream_id, reconfigure.profile
                    );
                }
            }
        }

        sequence = sequence
            .checked_add(1)
            .ok_or("control sequence exhausted")?;
        session
            .channel
            .send(&envelope(
                session_id,
                sequence,
                0,
                control_envelope::Payload::KeyframeRequest(KeyframeRequest {
                    stream_id: u64::from(stream_id),
                    last_decodable_frame_id: 0,
                }),
            ))
            .await?;
        println!("keyframe_request=sent");

        let mut second_pulse_sent = false;
        while started.elapsed() < Duration::from_secs(config.seconds) {
            sequence = sequence
                .checked_add(1)
                .ok_or("control sequence exhausted")?;
            let elapsed = started.elapsed();
            let media_failed = config
                .drop_media_after
                .is_some_and(|drop_after| elapsed >= Duration::from_secs(drop_after));
            let heartbeat_sequence = sequence;
            session
                .channel
                .send(&envelope(
                    session_id,
                    heartbeat_sequence,
                    0,
                    control_envelope::Payload::Heartbeat(Heartbeat {
                        monotonic_time_us: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
                        control_session_id: session_id,
                        media: if media_failed {
                            WireMediaHealth::Failed as i32
                        } else {
                            WireMediaHealth::Streaming as i32
                        },
                    }),
                ))
                .await?;
            let ack = session.channel.receive().await?;
            let Some(control_envelope::Payload::HeartbeatAck(ack)) = ack.payload else {
                return Err("expected HeartbeatAck".into());
            };
            if ack.heartbeat_sequence != heartbeat_sequence {
                return Err("HeartbeatAck sequence mismatch".into());
            }

            if config.input_pulse
                && !second_pulse_sent
                && config
                    .drop_media_after
                    .is_some_and(|drop_after| elapsed >= Duration::from_secs(drop_after + 1))
            {
                send_input_pulse(&mut session.channel, session_id, &mut sequence, started).await?;
                second_pulse_sent = true;
                println!("control_after_media_drop=responsive");
            }

            sleep(Duration::from_secs(1)).await;
        }

        let stats = media_task.await?;
        println!(
            "media packets={} frames={} keyframes={} retransmits={} invalid={} foreign={} bytes={}",
            stats.packets,
            stats.frames,
            stats.keyframes,
            stats.retransmits,
            stats.invalid_packets,
            stats.foreign_stream_packets,
            stats.bytes
        );
        if stats.packets == 0 {
            return Err("no production focused-media packets were received".into());
        }

        if let Some(vk) = config.hold_key_vk {
            sequence = sequence
                .checked_add(1)
                .ok_or("control sequence exhausted")?;
            session
                .channel
                .send(&input_envelope(
                    session_id,
                    sequence,
                    input_event::Event::Key(KeyEvent {
                        virtual_key: vk,
                        scan_code: 0,
                        down: true,
                        extended: false,
                    }),
                    started,
                ))
                .await?;
            println!(
                "disconnect_cleanup_test=armed virtual_key={} closing_without_key_up=true",
                vk
            );
        } else if config.input_pulse {
            sequence = sequence
                .checked_add(1)
                .ok_or("control sequence exhausted")?;
            session
                .channel
                .send(&input_envelope(
                    session_id,
                    sequence,
                    input_event::Event::ReleaseAll(ReleaseAllInput {}),
                    started,
                ))
                .await?;
        }

        session
            .connection
            .close(0_u32.into(), b"phase6f qualification complete");
        endpoint.wait_idle().await;
        println!("qualification=complete control_heartbeats=responsive");
        Ok(())
    }
}

#[cfg(windows)]
#[tokio::main]
async fn main() {
    if let Err(error) = windows_app::run().await {
        eprintln!("qualification failed: {error}");
        std::process::exit(1);
    }
}
