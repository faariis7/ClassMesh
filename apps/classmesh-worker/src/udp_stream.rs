use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_core::adaptation::StreamProfile;
use classmesh_network::feedback::{FeedbackOutcome, apply_sender_feedback};
use classmesh_network::transport::{UdpFrameSender, UdpSendError, UdpSenderConfig};
use classmesh_network::udp::{DatagramError, UdpMediaSocket};
use classmesh_protocol::control_wire::{MediaTransport, StreamReconfigure, VideoCodec};
use classmesh_protocol::feedback::FeedbackMessage;
use classmesh_video::KeyframeCoordinator;
use classmesh_windows_runtime::ipc::ServiceUdpStreamStart;

use crate::presentation::{PresentationError, PresentationPipeline, PresentationTarget};

const MEDIA_WRITE_TIMEOUT: Duration = Duration::from_millis(20);
const MIN_KEYFRAME_INTERVAL_US: u64 = 500_000;

#[derive(Debug)]
pub enum FocusedUdpStreamError {
    Datagram(DatagramError),
    Presentation(PresentationError),
    Send(UdpSendError),
    InvalidProfile,
    StreamMismatch,
    TransportChangeUnsupported,
    UnsupportedCodec,
}

impl fmt::Display for FocusedUdpStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagram(error) => write!(formatter, "UDP media socket failed: {error}"),
            Self::Presentation(error) => write!(formatter, "H264 presentation failed: {error}"),
            Self::Send(error) => write!(formatter, "UDP media send failed: {error:?}"),
            Self::InvalidProfile => formatter.write_str("invalid focused UDP H264 profile"),
            Self::StreamMismatch => formatter.write_str("focused UDP stream id mismatch"),
            Self::TransportChangeUnsupported => {
                formatter.write_str("focused UDP transport change requires a new stream offer")
            }
            Self::UnsupportedCodec => formatter.write_str("focused UDP stream requires H264"),
        }
    }
}

impl std::error::Error for FocusedUdpStreamError {}

impl From<DatagramError> for FocusedUdpStreamError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

impl From<PresentationError> for FocusedUdpStreamError {
    fn from(value: PresentationError) -> Self {
        Self::Presentation(value)
    }
}

impl From<UdpSendError> for FocusedUdpStreamError {
    fn from(value: UdpSendError) -> Self {
        Self::Send(value)
    }
}

#[derive(Debug)]
pub struct FocusedUdpStream {
    stream_id: u32,
    destination: SocketAddr,
    profile: StreamProfile,
    sender: UdpFrameSender,
    pipeline: Option<PresentationPipeline>,
    keyframes: KeyframeCoordinator,
    clock: Instant,
}

impl FocusedUdpStream {
    pub fn new(start: ServiceUdpStreamStart) -> Result<Self, FocusedUdpStreamError> {
        let profile = StreamProfile::new(start.width, start.height, start.fps, start.bitrate_kbps)
            .validate()
            .map_err(|_| FocusedUdpStreamError::InvalidProfile)?;
        let local = match start.destination.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpMediaSocket::bind(local)?;
        socket.set_write_timeout(Some(MEDIA_WRITE_TIMEOUT))?;
        let sender = UdpFrameSender::new(
            socket,
            UdpSenderConfig::presentation(start.stream_id, start.destination),
        );
        Ok(Self {
            stream_id: start.stream_id,
            destination: start.destination,
            profile,
            sender,
            pipeline: None,
            keyframes: KeyframeCoordinator::new(MIN_KEYFRAME_INTERVAL_US),
            clock: Instant::now(),
        })
    }

    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    #[must_use]
    pub fn capture_interval(&self) -> Duration {
        Duration::from_micros(1_000_000_u64 / u64::from(self.profile.fps))
    }

    pub fn reset_pipeline(&mut self) {
        self.pipeline = None;
    }

    pub fn apply_reconfigure(
        &mut self,
        reconfigure: &StreamReconfigure,
    ) -> Result<(), FocusedUdpStreamError> {
        let stream_id = u32::try_from(reconfigure.stream_id)
            .map_err(|_| FocusedUdpStreamError::StreamMismatch)?;
        if stream_id != self.stream_id {
            return Err(FocusedUdpStreamError::StreamMismatch);
        }
        if reconfigure.transport != MediaTransport::Unspecified as i32
            || !reconfigure.transport_parameters.is_empty()
        {
            return Err(FocusedUdpStreamError::TransportChangeUnsupported);
        }
        let profile = reconfigure
            .profile
            .as_ref()
            .ok_or(FocusedUdpStreamError::InvalidProfile)?;
        if profile.codec != VideoCodec::H264 as i32 {
            return Err(FocusedUdpStreamError::UnsupportedCodec);
        }
        let width =
            u16::try_from(profile.width).map_err(|_| FocusedUdpStreamError::InvalidProfile)?;
        let height =
            u16::try_from(profile.height).map_err(|_| FocusedUdpStreamError::InvalidProfile)?;
        let fps = u8::try_from(profile.fps).map_err(|_| FocusedUdpStreamError::InvalidProfile)?;
        let profile = StreamProfile::new(width, height, fps, profile.bitrate_kbps)
            .validate()
            .map_err(|_| FocusedUdpStreamError::InvalidProfile)?;
        if profile != self.profile {
            self.profile = profile;
            self.pipeline = None;
        }
        Ok(())
    }

    pub fn apply_feedback(
        &mut self,
        feedback: &FeedbackMessage,
    ) -> Result<FeedbackOutcome, FocusedUdpStreamError> {
        if feedback.stream_id() != self.stream_id {
            return Err(FocusedUdpStreamError::StreamMismatch);
        }
        let now_us = u64::try_from(self.clock.elapsed().as_micros()).unwrap_or(u64::MAX);
        let outcome = apply_sender_feedback(&mut self.sender, now_us, feedback)?;
        if outcome.keyframe_requested {
            self.keyframes.request();
            self.request_keyframe_if_due(now_us)?;
        }
        Ok(outcome)
    }

    fn request_keyframe_if_due(&mut self, now_us: u64) -> Result<(), FocusedUdpStreamError> {
        let Some(pipeline) = self.pipeline.as_mut() else {
            return Ok(());
        };
        if self.keyframes.poll(now_us) {
            pipeline.request_keyframe()?;
        }
        Ok(())
    }

    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<usize, FocusedUdpStreamError> {
        if self.pipeline.is_none() {
            let target = PresentationTarget::try_from(self.profile)?;
            self.pipeline = Some(PresentationPipeline::from_first_frame_with_target(
                &frame, target,
            )?);
        }
        let now_us = u64::try_from(self.clock.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.request_keyframe_if_due(now_us)?;
        let outputs = self
            .pipeline
            .as_mut()
            .expect("focused UDP pipeline initialized")
            .process_frame(meta, frame)?;
        let mut sent = 0_usize;
        for output in outputs {
            self.sender.send_frame(now_us, &output)?;
            sent = sent.saturating_add(1);
        }
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> ServiceUdpStreamStart {
        ServiceUdpStreamStart {
            stream_id: 7,
            destination: "127.0.0.1:9000".parse().expect("destination"),
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 2_500,
        }
    }

    fn reconfigure(stream_id: u64) -> StreamReconfigure {
        StreamReconfigure {
            stream_id,
            profile: Some(classmesh_protocol::control_wire::VideoProfile {
                width: 960,
                height: 540,
                fps: 30,
                bitrate_kbps: 1_500,
                codec: VideoCodec::H264 as i32,
            }),
            transport: MediaTransport::Unspecified as i32,
            transport_parameters: Vec::new(),
        }
    }

    #[test]
    fn focused_udp_feedback_is_stream_bound_and_keyframes_are_coalesced() {
        let mut stream = FocusedUdpStream::new(start()).expect("stream should bind");
        let request = FeedbackMessage::RequestKeyframe {
            stream_id: 7,
            after_frame_id: 41,
        };
        let outcome = stream
            .apply_feedback(&request)
            .expect("matching keyframe request should queue");
        assert!(outcome.keyframe_requested);
        assert_eq!(stream.keyframes.pending_requests(), 1);

        stream
            .apply_feedback(&request)
            .expect("duplicate request should coalesce");
        assert_eq!(stream.keyframes.pending_requests(), 2);

        assert!(matches!(
            stream.apply_feedback(&FeedbackMessage::RequestKeyframe {
                stream_id: 8,
                after_frame_id: 41,
            }),
            Err(FocusedUdpStreamError::StreamMismatch)
        ));
    }

    #[test]
    fn focused_udp_nack_uses_bounded_sender_cache() {
        let mut stream = FocusedUdpStream::new(start()).expect("stream should bind");
        let outcome = stream
            .apply_feedback(&FeedbackMessage::Nack {
                stream_id: 7,
                frame_id: 99,
                missing_packet_indices: vec![0, 2],
            })
            .expect("cache miss is not a transport failure");
        assert_eq!(outcome.retransmitted_packets, 0);
        assert!(!outcome.keyframe_requested);
    }

    #[test]
    fn focused_udp_stream_reconfigure_is_profile_only_and_stream_bound() {
        let mut stream = FocusedUdpStream::new(start()).expect("stream should bind");
        assert_eq!(stream.stream_id(), 7);
        assert_eq!(
            stream.destination(),
            "127.0.0.1:9000".parse().expect("socket")
        );
        assert_eq!(stream.capture_interval(), Duration::from_micros(33_333));

        stream
            .apply_reconfigure(&reconfigure(7))
            .expect("profile-only reconfigure should apply");
        assert_eq!(stream.capture_interval(), Duration::from_micros(33_333));

        assert!(matches!(
            stream.apply_reconfigure(&reconfigure(8)),
            Err(FocusedUdpStreamError::StreamMismatch)
        ));

        let mut transport_change = reconfigure(7);
        transport_change.transport = MediaTransport::QuicDatagram as i32;
        assert!(matches!(
            stream.apply_reconfigure(&transport_change),
            Err(FocusedUdpStreamError::TransportChangeUnsupported)
        ));
    }
}
