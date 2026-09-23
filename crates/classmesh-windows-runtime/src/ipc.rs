use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use classmesh_core::adaptation::StreamProfile;
use classmesh_protocol::control_wire::{InputEvent, StreamReconfigure};
use prost::Message;

pub const IPC_MAGIC: u32 = 0x434D_4950; // "CMIP"
pub const IPC_HEADER_LEN: usize = 12;
pub const MAX_IPC_MESSAGE: usize = 1_048_576;
pub const IPC_VERSION_MAJOR: u8 = 0;
pub const IPC_VERSION_MINOR: u8 = 5;

const MESSAGE_WORKER_HELLO: u16 = 1;
const MESSAGE_SERVICE_READY: u16 = 2;
const MESSAGE_CONTROL: u16 = 10;
const MESSAGE_INPUT_EVENT: u16 = 11;
const MESSAGE_STREAM_RECONFIGURE: u16 = 12;
const MESSAGE_WORKER_CAPABILITIES: u16 = 13;
const MESSAGE_WORKER_ENCODER_EVIDENCE: u16 = 14;
const MESSAGE_WORKER_ENCODER_CACHE_QUERY: u16 = 15;
const MESSAGE_SERVICE_ENCODER_CACHE_RESULT: u16 = 16;
const MESSAGE_SERVICE_UDP_STREAM_START: u16 = 17;
const SERVICE_UDP_STREAM_START_LEN: usize = 32;

const MAX_EVIDENCE_ADAPTER_IDENTITY: usize = 128;
const MAX_EVIDENCE_DRIVER_VERSION: usize = 128;
const MAX_EVIDENCE_ENCODER_CLSID: usize = 128;
const MAX_EVIDENCE_BACKEND: usize = 256;
const ENCODER_EVIDENCE_FIXED_LEN: usize = 50;

const WORKER_CAP_DXGI_CAPTURE: u32 = 1 << 0;
const WORKER_CAP_H264_HARDWARE_ENCODE: u32 = 1 << 1;
const KNOWN_WORKER_CAPABILITIES: u32 = WORKER_CAP_DXGI_CAPTURE | WORKER_CAP_H264_HARDWARE_ENCODE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcRole {
    Service,
    Worker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    AwaitingPeerHello,
    AwaitingChallengeResponse,
    Authenticated,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    PeerHelloValid,
    PeerHelloInvalid,
    ChallengeResponseValid,
    ChallengeResponseInvalid,
}

#[derive(Debug)]
pub struct IpcHandshake {
    state: HandshakeState,
}

impl Default for IpcHandshake {
    fn default() -> Self {
        Self {
            state: HandshakeState::AwaitingPeerHello,
        }
    }
}

impl IpcHandshake {
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn on_event(&mut self, event: HandshakeEvent) {
        self.state = match (self.state, event) {
            (HandshakeState::AwaitingPeerHello, HandshakeEvent::PeerHelloValid) => {
                HandshakeState::AwaitingChallengeResponse
            }
            (HandshakeState::AwaitingChallengeResponse, HandshakeEvent::ChallengeResponseValid) => {
                HandshakeState::Authenticated
            }
            (_, HandshakeEvent::PeerHelloInvalid | HandshakeEvent::ChallengeResponseInvalid) => {
                HandshakeState::Rejected
            }
            (state, _) => state,
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub message_type: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcFrameError {
    Truncated,
    BadMagic,
    PayloadTooLarge,
    LengthMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcControlCommand {
    SuspendMedia,
    ResumeMedia,
    Shutdown,
    ReleaseInput,
    ClearFocusedProfile,
}

impl IpcControlCommand {
    const fn as_byte(self) -> u8 {
        match self {
            Self::SuspendMedia => 1,
            Self::ResumeMedia => 2,
            Self::Shutdown => 3,
            Self::ReleaseInput => 4,
            Self::ClearFocusedProfile => 5,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SuspendMedia),
            2 => Some(Self::ResumeMedia),
            3 => Some(Self::Shutdown),
            4 => Some(Self::ReleaseInput),
            5 => Some(Self::ClearFocusedProfile),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerRuntimeCapabilities {
    pub process_id: u32,
    pub session_id: u32,
    flags: u32,
}

impl WorkerRuntimeCapabilities {
    #[must_use]
    pub const fn new(
        process_id: u32,
        session_id: u32,
        dxgi_capture: bool,
        h264_hardware_encode: bool,
    ) -> Self {
        let mut flags = 0_u32;
        if dxgi_capture {
            flags |= WORKER_CAP_DXGI_CAPTURE;
        }
        if h264_hardware_encode {
            flags |= WORKER_CAP_H264_HARDWARE_ENCODE;
        }
        Self {
            process_id,
            session_id,
            flags,
        }
    }

    #[must_use]
    pub const fn dxgi_capture(self) -> bool {
        self.flags & WORKER_CAP_DXGI_CAPTURE != 0
    }

    #[must_use]
    pub const fn h264_hardware_encode(self) -> bool {
        self.flags & WORKER_CAP_H264_HARDWARE_ENCODE != 0
    }

    #[must_use]
    pub const fn known_flags(self) -> u32 {
        self.flags & KNOWN_WORKER_CAPABILITIES
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerEncoderEvidence {
    pub process_id: u32,
    pub session_id: u32,
    pub adapter_identity: String,
    pub driver_version: String,
    pub encoder_clsid: String,
    pub width: u16,
    pub height: u16,
    pub target_fps: u16,
    pub bitrate_bps: u32,
    pub backend: String,
    pub advertised_hardware: bool,
    pub gpu_native_input: bool,
    pub low_latency_accepted: bool,
    pub reset_ok: bool,
    pub dynamic_bitrate_ok: bool,
    pub keyframe_request_ok: bool,
    pub encoder_class: u8,
    pub sustained_fps: f32,
    pub p50_encode_ms: f32,
    pub p95_encode_ms: f32,
    pub output_frames: u32,
    pub dropped_or_missing: u32,
}

impl WorkerEncoderEvidence {
    fn validate(&self) -> Result<(), IpcMessageError> {
        if self.process_id == 0
            || self.session_id == 0
            || self.width == 0
            || self.height == 0
            || self.target_fps == 0
            || self.bitrate_bps == 0
            || self.encoder_class > 3
            || !self.sustained_fps.is_finite()
            || self.sustained_fps < 0.0
            || !self.p50_encode_ms.is_finite()
            || self.p50_encode_ms <= 0.0
            || !self.p95_encode_ms.is_finite()
            || self.p95_encode_ms <= 0.0
            || self.p50_encode_ms > self.p95_encode_ms
        {
            return Err(IpcMessageError::InvalidPayload);
        }
        validate_evidence_string(&self.adapter_identity, MAX_EVIDENCE_ADAPTER_IDENTITY)?;
        validate_evidence_string(&self.driver_version, MAX_EVIDENCE_DRIVER_VERSION)?;
        validate_evidence_string(&self.encoder_clsid, MAX_EVIDENCE_ENCODER_CLSID)?;
        validate_evidence_string(&self.backend, MAX_EVIDENCE_BACKEND)?;
        Ok(())
    }
}

fn validate_evidence_string(value: &str, maximum: usize) -> Result<(), IpcMessageError> {
    if value.is_empty() || value.len() > maximum || value.len() > usize::from(u16::MAX) {
        return Err(IpcMessageError::InvalidPayload);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerEncoderCacheQuery {
    pub process_id: u32,
    pub session_id: u32,
    pub adapter_identity: String,
    pub driver_version: String,
    pub encoder_clsid: String,
    pub width: u16,
    pub height: u16,
    pub target_fps: u16,
    pub bitrate_bps: u32,
}

impl WorkerEncoderCacheQuery {
    fn validate(&self) -> Result<(), IpcMessageError> {
        if self.process_id == 0
            || self.session_id == 0
            || self.width == 0
            || self.height == 0
            || self.target_fps == 0
            || self.bitrate_bps == 0
        {
            return Err(IpcMessageError::InvalidPayload);
        }
        validate_evidence_string(&self.adapter_identity, MAX_EVIDENCE_ADAPTER_IDENTITY)?;
        validate_evidence_string(&self.driver_version, MAX_EVIDENCE_DRIVER_VERSION)?;
        validate_evidence_string(&self.encoder_clsid, MAX_EVIDENCE_ENCODER_CLSID)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceEncoderCacheResult {
    pub process_id: u32,
    pub session_id: u32,
    pub hit: bool,
    pub qualified: bool,
}

impl ServiceEncoderCacheResult {
    fn validate(self) -> Result<(), IpcMessageError> {
        if self.process_id == 0 || self.session_id == 0 || (self.qualified && !self.hit) {
            return Err(IpcMessageError::InvalidPayload);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUdpStreamStart {
    pub stream_id: u32,
    pub destination: SocketAddr,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub bitrate_kbps: u32,
}

impl ServiceUdpStreamStart {
    fn validate(self) -> Result<(), IpcMessageError> {
        if self.stream_id == 0 || self.destination.port() == 0 {
            return Err(IpcMessageError::InvalidPayload);
        }
        StreamProfile::new(self.width, self.height, self.fps, self.bitrate_kbps)
            .validate()
            .map_err(|_| IpcMessageError::InvalidPayload)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IpcMessage {
    WorkerHello { process_id: u32, session_id: u32 },
    ServiceReady,
    Control(IpcControlCommand),
    InputEvent(InputEvent),
    StreamReconfigure(StreamReconfigure),
    WorkerCapabilities(WorkerRuntimeCapabilities),
    WorkerEncoderEvidence(WorkerEncoderEvidence),
    WorkerEncoderCacheQuery(WorkerEncoderCacheQuery),
    ServiceEncoderCacheResult(ServiceEncoderCacheResult),
    ServiceUdpStreamStart(ServiceUdpStreamStart),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcMessageError {
    UnsupportedVersion,
    UnknownMessageType,
    InvalidPayload,
}

impl IpcHeader {
    pub fn encode(self) -> Result<[u8; IPC_HEADER_LEN], IpcFrameError> {
        if usize::try_from(self.payload_len).unwrap_or(usize::MAX) > MAX_IPC_MESSAGE {
            return Err(IpcFrameError::PayloadTooLarge);
        }
        let mut bytes = [0_u8; IPC_HEADER_LEN];
        bytes[0..4].copy_from_slice(&IPC_MAGIC.to_be_bytes());
        bytes[4] = self.version_major;
        bytes[5] = self.version_minor;
        bytes[6..8].copy_from_slice(&self.message_type.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.payload_len.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(data: &[u8]) -> Result<Self, IpcFrameError> {
        if data.len() < IPC_HEADER_LEN {
            return Err(IpcFrameError::Truncated);
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != IPC_MAGIC {
            return Err(IpcFrameError::BadMagic);
        }
        let payload_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        if usize::try_from(payload_len).unwrap_or(usize::MAX) > MAX_IPC_MESSAGE {
            return Err(IpcFrameError::PayloadTooLarge);
        }
        Ok(Self {
            version_major: data[4],
            version_minor: data[5],
            message_type: u16::from_be_bytes([data[6], data[7]]),
            payload_len,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcFrame {
    pub header: IpcHeader,
    pub payload: Vec<u8>,
}

impl IpcFrame {
    pub fn encode(&self) -> Result<Vec<u8>, IpcFrameError> {
        if self.payload.len() != usize::try_from(self.header.payload_len).unwrap_or(usize::MAX) {
            return Err(IpcFrameError::LengthMismatch);
        }
        let header = self.header.encode()?;
        let mut output = Vec::with_capacity(IPC_HEADER_LEN + self.payload.len());
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    #[must_use]
    pub fn worker_hello(process_id: u32, session_id: u32) -> Self {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&process_id.to_be_bytes());
        payload.extend_from_slice(&session_id.to_be_bytes());
        Self::new(MESSAGE_WORKER_HELLO, payload)
    }

    #[must_use]
    pub fn service_ready() -> Self {
        Self::new(MESSAGE_SERVICE_READY, Vec::new())
    }

    #[must_use]
    pub fn control(command: IpcControlCommand) -> Self {
        Self::new(MESSAGE_CONTROL, vec![command.as_byte()])
    }

    #[must_use]
    pub fn input_event(event: &InputEvent) -> Self {
        Self::new(MESSAGE_INPUT_EVENT, event.encode_to_vec())
    }

    #[must_use]
    pub fn stream_reconfigure(reconfigure: &StreamReconfigure) -> Self {
        Self::new(MESSAGE_STREAM_RECONFIGURE, reconfigure.encode_to_vec())
    }

    #[must_use]
    pub fn worker_capabilities(capabilities: WorkerRuntimeCapabilities) -> Self {
        let mut payload = Vec::with_capacity(12);
        payload.extend_from_slice(&capabilities.process_id.to_be_bytes());
        payload.extend_from_slice(&capabilities.session_id.to_be_bytes());
        payload.extend_from_slice(&capabilities.known_flags().to_be_bytes());
        Self::new(MESSAGE_WORKER_CAPABILITIES, payload)
    }

    pub fn worker_encoder_evidence(
        evidence: &WorkerEncoderEvidence,
    ) -> Result<Self, IpcMessageError> {
        evidence.validate()?;
        let mut payload = Vec::with_capacity(
            ENCODER_EVIDENCE_FIXED_LEN
                + evidence.adapter_identity.len()
                + evidence.driver_version.len()
                + evidence.encoder_clsid.len()
                + evidence.backend.len(),
        );
        payload.extend_from_slice(&evidence.process_id.to_be_bytes());
        payload.extend_from_slice(&evidence.session_id.to_be_bytes());
        payload.extend_from_slice(&evidence.width.to_be_bytes());
        payload.extend_from_slice(&evidence.height.to_be_bytes());
        payload.extend_from_slice(&evidence.target_fps.to_be_bytes());
        payload.extend_from_slice(&evidence.bitrate_bps.to_be_bytes());
        let mut flags = 0_u16;
        flags |= u16::from(evidence.advertised_hardware);
        flags |= u16::from(evidence.gpu_native_input) << 1;
        flags |= u16::from(evidence.low_latency_accepted) << 2;
        flags |= u16::from(evidence.reset_ok) << 3;
        flags |= u16::from(evidence.dynamic_bitrate_ok) << 4;
        flags |= u16::from(evidence.keyframe_request_ok) << 5;
        payload.extend_from_slice(&flags.to_be_bytes());
        payload.push(evidence.encoder_class);
        payload.push(0);
        payload.extend_from_slice(&evidence.sustained_fps.to_bits().to_be_bytes());
        payload.extend_from_slice(&evidence.p50_encode_ms.to_bits().to_be_bytes());
        payload.extend_from_slice(&evidence.p95_encode_ms.to_bits().to_be_bytes());
        payload.extend_from_slice(&evidence.output_frames.to_be_bytes());
        payload.extend_from_slice(&evidence.dropped_or_missing.to_be_bytes());
        for value in [
            &evidence.adapter_identity,
            &evidence.driver_version,
            &evidence.encoder_clsid,
            &evidence.backend,
        ] {
            let len = u16::try_from(value.len()).map_err(|_| IpcMessageError::InvalidPayload)?;
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
        Ok(Self::new(MESSAGE_WORKER_ENCODER_EVIDENCE, payload))
    }

    pub fn worker_encoder_cache_query(
        query: &WorkerEncoderCacheQuery,
    ) -> Result<Self, IpcMessageError> {
        query.validate()?;
        let mut payload = Vec::with_capacity(
            24 + query.adapter_identity.len()
                + query.driver_version.len()
                + query.encoder_clsid.len(),
        );
        payload.extend_from_slice(&query.process_id.to_be_bytes());
        payload.extend_from_slice(&query.session_id.to_be_bytes());
        payload.extend_from_slice(&query.width.to_be_bytes());
        payload.extend_from_slice(&query.height.to_be_bytes());
        payload.extend_from_slice(&query.target_fps.to_be_bytes());
        payload.extend_from_slice(&query.bitrate_bps.to_be_bytes());
        for value in [
            &query.adapter_identity,
            &query.driver_version,
            &query.encoder_clsid,
        ] {
            let len = u16::try_from(value.len()).map_err(|_| IpcMessageError::InvalidPayload)?;
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
        Ok(Self::new(MESSAGE_WORKER_ENCODER_CACHE_QUERY, payload))
    }

    pub fn service_encoder_cache_result(
        result: ServiceEncoderCacheResult,
    ) -> Result<Self, IpcMessageError> {
        result.validate()?;
        let mut payload = Vec::with_capacity(10);
        payload.extend_from_slice(&result.process_id.to_be_bytes());
        payload.extend_from_slice(&result.session_id.to_be_bytes());
        let flags = u8::from(result.hit) | (u8::from(result.qualified) << 1);
        payload.push(flags);
        payload.push(0);
        Ok(Self::new(MESSAGE_SERVICE_ENCODER_CACHE_RESULT, payload))
    }

    pub fn service_udp_stream_start(start: ServiceUdpStreamStart) -> Result<Self, IpcMessageError> {
        start.validate()?;
        let mut payload = Vec::with_capacity(SERVICE_UDP_STREAM_START_LEN);
        payload.extend_from_slice(&start.stream_id.to_be_bytes());
        payload.extend_from_slice(&start.width.to_be_bytes());
        payload.extend_from_slice(&start.height.to_be_bytes());
        payload.push(start.fps);
        let (family, address) = match start.destination.ip() {
            IpAddr::V4(address) => {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&address.octets());
                (4_u8, bytes)
            }
            IpAddr::V6(address) => (6_u8, address.octets()),
        };
        payload.push(family);
        payload.extend_from_slice(&start.destination.port().to_be_bytes());
        payload.extend_from_slice(&start.bitrate_kbps.to_be_bytes());
        payload.extend_from_slice(&address);
        debug_assert_eq!(payload.len(), SERVICE_UDP_STREAM_START_LEN);
        Ok(Self::new(MESSAGE_SERVICE_UDP_STREAM_START, payload))
    }

    pub fn message(&self) -> Result<IpcMessage, IpcMessageError> {
        if self.header.version_major != IPC_VERSION_MAJOR {
            return Err(IpcMessageError::UnsupportedVersion);
        }

        match self.header.message_type {
            MESSAGE_WORKER_HELLO => {
                if self.payload.len() != 8 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let process_id = u32::from_be_bytes([
                    self.payload[0],
                    self.payload[1],
                    self.payload[2],
                    self.payload[3],
                ]);
                let session_id = u32::from_be_bytes([
                    self.payload[4],
                    self.payload[5],
                    self.payload[6],
                    self.payload[7],
                ]);
                Ok(IpcMessage::WorkerHello {
                    process_id,
                    session_id,
                })
            }
            MESSAGE_SERVICE_READY => {
                if self.payload.is_empty() {
                    Ok(IpcMessage::ServiceReady)
                } else {
                    Err(IpcMessageError::InvalidPayload)
                }
            }
            MESSAGE_CONTROL => {
                let [raw] = self.payload.as_slice() else {
                    return Err(IpcMessageError::InvalidPayload);
                };
                let command =
                    IpcControlCommand::from_byte(*raw).ok_or(IpcMessageError::InvalidPayload)?;
                Ok(IpcMessage::Control(command))
            }
            MESSAGE_INPUT_EVENT => {
                let event = InputEvent::decode(self.payload.as_slice())
                    .map_err(|_| IpcMessageError::InvalidPayload)?;
                Ok(IpcMessage::InputEvent(event))
            }
            MESSAGE_STREAM_RECONFIGURE => {
                let reconfigure = StreamReconfigure::decode(self.payload.as_slice())
                    .map_err(|_| IpcMessageError::InvalidPayload)?;
                Ok(IpcMessage::StreamReconfigure(reconfigure))
            }
            MESSAGE_WORKER_CAPABILITIES => {
                if self.payload.len() != 12 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let process_id = u32::from_be_bytes([
                    self.payload[0],
                    self.payload[1],
                    self.payload[2],
                    self.payload[3],
                ]);
                let session_id = u32::from_be_bytes([
                    self.payload[4],
                    self.payload[5],
                    self.payload[6],
                    self.payload[7],
                ]);
                let flags = u32::from_be_bytes([
                    self.payload[8],
                    self.payload[9],
                    self.payload[10],
                    self.payload[11],
                ]);
                Ok(IpcMessage::WorkerCapabilities(WorkerRuntimeCapabilities {
                    process_id,
                    session_id,
                    flags: flags & KNOWN_WORKER_CAPABILITIES,
                }))
            }
            MESSAGE_WORKER_ENCODER_EVIDENCE => {
                if self.payload.len() < ENCODER_EVIDENCE_FIXED_LEN {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let process_id = u32::from_be_bytes(self.payload[0..4].try_into().expect("slice"));
                let session_id = u32::from_be_bytes(self.payload[4..8].try_into().expect("slice"));
                let width = u16::from_be_bytes(self.payload[8..10].try_into().expect("slice"));
                let height = u16::from_be_bytes(self.payload[10..12].try_into().expect("slice"));
                let target_fps =
                    u16::from_be_bytes(self.payload[12..14].try_into().expect("slice"));
                let bitrate_bps =
                    u32::from_be_bytes(self.payload[14..18].try_into().expect("slice"));
                let flags = u16::from_be_bytes(self.payload[18..20].try_into().expect("slice"));
                if flags & !0x003f != 0 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let encoder_class = self.payload[20];
                if self.payload[21] != 0 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let sustained_fps = f32::from_bits(u32::from_be_bytes(
                    self.payload[22..26].try_into().expect("slice"),
                ));
                let p50_encode_ms = f32::from_bits(u32::from_be_bytes(
                    self.payload[26..30].try_into().expect("slice"),
                ));
                let p95_encode_ms = f32::from_bits(u32::from_be_bytes(
                    self.payload[30..34].try_into().expect("slice"),
                ));
                let output_frames =
                    u32::from_be_bytes(self.payload[34..38].try_into().expect("slice"));
                let dropped_or_missing =
                    u32::from_be_bytes(self.payload[38..42].try_into().expect("slice"));
                let mut cursor = 42_usize;
                let mut next_string = |maximum: usize| -> Result<String, IpcMessageError> {
                    let end_len = cursor
                        .checked_add(2)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let length_bytes = self
                        .payload
                        .get(cursor..end_len)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let length = usize::from(u16::from_be_bytes(
                        length_bytes.try_into().expect("two bytes"),
                    ));
                    cursor = end_len;
                    if length == 0 || length > maximum {
                        return Err(IpcMessageError::InvalidPayload);
                    }
                    let end = cursor
                        .checked_add(length)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let bytes = self
                        .payload
                        .get(cursor..end)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    cursor = end;
                    String::from_utf8(bytes.to_vec()).map_err(|_| IpcMessageError::InvalidPayload)
                };
                let adapter_identity = next_string(MAX_EVIDENCE_ADAPTER_IDENTITY)?;
                let driver_version = next_string(MAX_EVIDENCE_DRIVER_VERSION)?;
                let encoder_clsid = next_string(MAX_EVIDENCE_ENCODER_CLSID)?;
                let backend = next_string(MAX_EVIDENCE_BACKEND)?;
                if cursor != self.payload.len() {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let evidence = WorkerEncoderEvidence {
                    process_id,
                    session_id,
                    adapter_identity,
                    driver_version,
                    encoder_clsid,
                    width,
                    height,
                    target_fps,
                    bitrate_bps,
                    backend,
                    advertised_hardware: flags & (1 << 0) != 0,
                    gpu_native_input: flags & (1 << 1) != 0,
                    low_latency_accepted: flags & (1 << 2) != 0,
                    reset_ok: flags & (1 << 3) != 0,
                    dynamic_bitrate_ok: flags & (1 << 4) != 0,
                    keyframe_request_ok: flags & (1 << 5) != 0,
                    encoder_class,
                    sustained_fps,
                    p50_encode_ms,
                    p95_encode_ms,
                    output_frames,
                    dropped_or_missing,
                };
                evidence.validate()?;
                Ok(IpcMessage::WorkerEncoderEvidence(evidence))
            }
            MESSAGE_WORKER_ENCODER_CACHE_QUERY => {
                if self.payload.len() < 24 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let process_id = u32::from_be_bytes(self.payload[0..4].try_into().expect("slice"));
                let session_id = u32::from_be_bytes(self.payload[4..8].try_into().expect("slice"));
                let width = u16::from_be_bytes(self.payload[8..10].try_into().expect("slice"));
                let height = u16::from_be_bytes(self.payload[10..12].try_into().expect("slice"));
                let target_fps =
                    u16::from_be_bytes(self.payload[12..14].try_into().expect("slice"));
                let bitrate_bps =
                    u32::from_be_bytes(self.payload[14..18].try_into().expect("slice"));
                let mut cursor = 18_usize;
                let mut next_string = |maximum: usize| -> Result<String, IpcMessageError> {
                    let end_len = cursor
                        .checked_add(2)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let length_bytes = self
                        .payload
                        .get(cursor..end_len)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let length = usize::from(u16::from_be_bytes(
                        length_bytes.try_into().expect("two bytes"),
                    ));
                    cursor = end_len;
                    if length == 0 || length > maximum {
                        return Err(IpcMessageError::InvalidPayload);
                    }
                    let end = cursor
                        .checked_add(length)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    let bytes = self
                        .payload
                        .get(cursor..end)
                        .ok_or(IpcMessageError::InvalidPayload)?;
                    cursor = end;
                    String::from_utf8(bytes.to_vec()).map_err(|_| IpcMessageError::InvalidPayload)
                };
                let adapter_identity = next_string(MAX_EVIDENCE_ADAPTER_IDENTITY)?;
                let driver_version = next_string(MAX_EVIDENCE_DRIVER_VERSION)?;
                let encoder_clsid = next_string(MAX_EVIDENCE_ENCODER_CLSID)?;
                if cursor != self.payload.len() {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let query = WorkerEncoderCacheQuery {
                    process_id,
                    session_id,
                    adapter_identity,
                    driver_version,
                    encoder_clsid,
                    width,
                    height,
                    target_fps,
                    bitrate_bps,
                };
                query.validate()?;
                Ok(IpcMessage::WorkerEncoderCacheQuery(query))
            }
            MESSAGE_SERVICE_ENCODER_CACHE_RESULT => {
                if self.payload.len() != 10 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let process_id = u32::from_be_bytes(self.payload[0..4].try_into().expect("slice"));
                let session_id = u32::from_be_bytes(self.payload[4..8].try_into().expect("slice"));
                let flags = self.payload[8];
                if flags & !0x03 != 0 || self.payload[9] != 0 {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let result = ServiceEncoderCacheResult {
                    process_id,
                    session_id,
                    hit: flags & 1 != 0,
                    qualified: flags & 2 != 0,
                };
                result.validate()?;
                Ok(IpcMessage::ServiceEncoderCacheResult(result))
            }
            MESSAGE_SERVICE_UDP_STREAM_START => {
                if self.payload.len() != SERVICE_UDP_STREAM_START_LEN {
                    return Err(IpcMessageError::InvalidPayload);
                }
                let stream_id = u32::from_be_bytes(self.payload[0..4].try_into().expect("slice"));
                let width = u16::from_be_bytes(self.payload[4..6].try_into().expect("slice"));
                let height = u16::from_be_bytes(self.payload[6..8].try_into().expect("slice"));
                let fps = self.payload[8];
                let family = self.payload[9];
                let port = u16::from_be_bytes(self.payload[10..12].try_into().expect("slice"));
                let bitrate_kbps =
                    u32::from_be_bytes(self.payload[12..16].try_into().expect("slice"));
                let address_bytes: [u8; 16] = self.payload[16..32].try_into().expect("slice");
                let ip = match family {
                    4 => {
                        if address_bytes[4..].iter().any(|byte| *byte != 0) {
                            return Err(IpcMessageError::InvalidPayload);
                        }
                        IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(&address_bytes[..4]).expect("four bytes"),
                        ))
                    }
                    6 => IpAddr::V6(Ipv6Addr::from(address_bytes)),
                    _ => return Err(IpcMessageError::InvalidPayload),
                };
                let start = ServiceUdpStreamStart {
                    stream_id,
                    destination: SocketAddr::new(ip, port),
                    width,
                    height,
                    fps,
                    bitrate_kbps,
                };
                start.validate()?;
                Ok(IpcMessage::ServiceUdpStreamStart(start))
            }
            _ => Err(IpcMessageError::UnknownMessageType),
        }
    }

    fn new(message_type: u16, payload: Vec<u8>) -> Self {
        Self {
            header: IpcHeader {
                version_major: IPC_VERSION_MAJOR,
                version_minor: IPC_VERSION_MINOR,
                message_type,
                payload_len: u32::try_from(payload.len()).expect("IPC payload length is bounded"),
            },
            payload,
        }
    }
}

/// Incremental parser suitable for a named-pipe byte stream. Input buffering is bounded so a
/// malformed peer cannot grow memory indefinitely before sending a valid frame.
#[derive(Debug)]
pub struct IpcFrameDecoder {
    buffer: VecDeque<u8>,
}

impl Default for IpcFrameDecoder {
    fn default() -> Self {
        Self {
            buffer: VecDeque::with_capacity(IPC_HEADER_LEN * 2),
        }
    }
}

impl IpcFrameDecoder {
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Vec<IpcFrame>, IpcFrameError> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_IPC_MESSAGE + IPC_HEADER_LEN {
            return Err(IpcFrameError::PayloadTooLarge);
        }
        self.buffer.extend(bytes.iter().copied());
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < IPC_HEADER_LEN {
                break;
            }
            let header_bytes: Vec<u8> = self.buffer.iter().take(IPC_HEADER_LEN).copied().collect();
            let header = IpcHeader::decode(&header_bytes)?;
            let payload_len =
                usize::try_from(header.payload_len).map_err(|_| IpcFrameError::PayloadTooLarge)?;
            let frame_len = IPC_HEADER_LEN.saturating_add(payload_len);
            if self.buffer.len() < frame_len {
                break;
            }
            for _ in 0..IPC_HEADER_LEN {
                let _ = self.buffer.pop_front();
            }
            let mut payload = Vec::with_capacity(payload_len);
            for _ in 0..payload_len {
                payload.push(self.buffer.pop_front().expect("frame length was checked"));
            }
            frames.push(IpcFrame { header, payload });
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> IpcFrame {
        IpcFrame {
            header: IpcHeader {
                version_major: IPC_VERSION_MAJOR,
                version_minor: IPC_VERSION_MINOR,
                message_type: 99,
                payload_len: u32::try_from(payload.len()).expect("small test payload"),
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn decoder_handles_fragmented_pipe_reads() {
        let bytes = frame(&[1, 2, 3, 4]).encode().expect("frame should encode");
        let mut decoder = IpcFrameDecoder::default();
        assert!(
            decoder
                .push_bytes(&bytes[..5])
                .expect("partial input valid")
                .is_empty()
        );
        let decoded = decoder
            .push_bytes(&bytes[5..])
            .expect("remaining input valid");
        assert_eq!(decoded, vec![frame(&[1, 2, 3, 4])]);
    }

    #[test]
    fn handshake_rejects_bad_challenge_response() {
        let mut handshake = IpcHandshake::default();
        handshake.on_event(HandshakeEvent::PeerHelloValid);
        assert_eq!(handshake.state(), HandshakeState::AwaitingChallengeResponse);
        handshake.on_event(HandshakeEvent::ChallengeResponseInvalid);
        assert_eq!(handshake.state(), HandshakeState::Rejected);
    }

    #[test]
    fn typed_control_message_round_trips() {
        for command in [
            IpcControlCommand::SuspendMedia,
            IpcControlCommand::ResumeMedia,
            IpcControlCommand::Shutdown,
            IpcControlCommand::ReleaseInput,
            IpcControlCommand::ClearFocusedProfile,
        ] {
            let frame = IpcFrame::control(command);
            let encoded = frame.encode().expect("control frame should encode");
            let mut decoder = IpcFrameDecoder::default();
            let frames = decoder
                .push_bytes(&encoded)
                .expect("control frame should decode");
            assert_eq!(
                frames[0].message().expect("typed message should decode"),
                IpcMessage::Control(command)
            );
        }
    }

    #[test]
    fn worker_capabilities_round_trip_and_ignore_unknown_flags() {
        let capabilities = WorkerRuntimeCapabilities::new(42, 7, true, false);
        let encoded = IpcFrame::worker_capabilities(capabilities)
            .encode()
            .expect("capability frame should encode");
        let mut decoder = IpcFrameDecoder::default();
        let frames = decoder
            .push_bytes(&encoded)
            .expect("capability frame should decode");

        assert_eq!(
            frames[0].message().expect("typed capability message"),
            IpcMessage::WorkerCapabilities(capabilities)
        );

        let mut frame = IpcFrame::worker_capabilities(capabilities);
        frame.payload[8..12]
            .copy_from_slice(&(capabilities.known_flags() | (1 << 31)).to_be_bytes());
        assert_eq!(
            frame
                .message()
                .expect("unknown future flag should be ignored"),
            IpcMessage::WorkerCapabilities(capabilities)
        );
    }

    #[test]
    fn worker_encoder_evidence_round_trips() {
        let evidence = WorkerEncoderEvidence {
            process_id: 42,
            session_id: 7,
            adapter_identity: "55667788:11223344".into(),
            driver_version: "31.0.15.5123".into(),
            encoder_clsid: "{encoder-clsid}".into(),
            width: 1280,
            height: 720,
            target_fps: 30,
            bitrate_bps: 2_500_000,
            backend: "test encoder".into(),
            advertised_hardware: true,
            gpu_native_input: true,
            low_latency_accepted: true,
            reset_ok: true,
            dynamic_bitrate_ok: false,
            keyframe_request_ok: true,
            encoder_class: 1,
            sustained_fps: 30.0,
            p50_encode_ms: 4.0,
            p95_encode_ms: 8.0,
            output_frames: 120,
            dropped_or_missing: 0,
        };
        let encoded = IpcFrame::worker_encoder_evidence(&evidence)
            .expect("valid evidence")
            .encode()
            .expect("evidence frame should encode");
        let mut decoder = IpcFrameDecoder::default();
        let frames = decoder
            .push_bytes(&encoded)
            .expect("evidence frame should decode");
        assert_eq!(
            frames[0].message().expect("typed evidence"),
            IpcMessage::WorkerEncoderEvidence(evidence)
        );
    }

    #[test]
    fn encoder_cache_query_and_result_round_trip() {
        let query = WorkerEncoderCacheQuery {
            process_id: 42,
            session_id: 7,
            adapter_identity: "55667788:11223344".into(),
            driver_version: "31.0.15.5123".into(),
            encoder_clsid: "{encoder-clsid}".into(),
            width: 1280,
            height: 720,
            target_fps: 30,
            bitrate_bps: 2_500_000,
        };
        let query_frame = IpcFrame::worker_encoder_cache_query(&query).expect("valid cache query");
        assert_eq!(
            query_frame.message().expect("typed cache query"),
            IpcMessage::WorkerEncoderCacheQuery(query)
        );

        let result = ServiceEncoderCacheResult {
            process_id: 42,
            session_id: 7,
            hit: true,
            qualified: true,
        };
        let result_frame =
            IpcFrame::service_encoder_cache_result(result).expect("valid cache result");
        assert_eq!(
            result_frame.message().expect("typed cache result"),
            IpcMessage::ServiceEncoderCacheResult(result)
        );
    }

    #[test]
    fn service_udp_stream_start_round_trips_ipv4_and_ipv6() {
        for destination in [
            "192.0.2.44:9000".parse().expect("ipv4 destination"),
            "[2001:db8::44]:9001".parse().expect("ipv6 destination"),
        ] {
            let start = ServiceUdpStreamStart {
                stream_id: 7,
                destination,
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 2_500,
            };
            let frame = IpcFrame::service_udp_stream_start(start).expect("valid UDP stream start");
            assert_eq!(
                frame.message().expect("typed UDP stream start"),
                IpcMessage::ServiceUdpStreamStart(start)
            );
        }
    }

    #[test]
    fn service_udp_stream_start_rejects_invalid_identity_and_profile() {
        let valid = ServiceUdpStreamStart {
            stream_id: 7,
            destination: "192.0.2.44:9000".parse().expect("destination"),
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 2_500,
        };
        assert_eq!(
            IpcFrame::service_udp_stream_start(ServiceUdpStreamStart {
                stream_id: 0,
                ..valid
            }),
            Err(IpcMessageError::InvalidPayload)
        );
        assert_eq!(
            IpcFrame::service_udp_stream_start(ServiceUdpStreamStart {
                destination: "192.0.2.44:0".parse().expect("zero-port destination"),
                ..valid
            }),
            Err(IpcMessageError::InvalidPayload)
        );
        assert_eq!(
            IpcFrame::service_udp_stream_start(ServiceUdpStreamStart { width: 0, ..valid }),
            Err(IpcMessageError::InvalidPayload)
        );
    }

    #[test]
    fn cache_result_cannot_claim_qualified_without_hit() {
        let result = ServiceEncoderCacheResult {
            process_id: 42,
            session_id: 7,
            hit: false,
            qualified: true,
        };
        assert_eq!(
            IpcFrame::service_encoder_cache_result(result),
            Err(IpcMessageError::InvalidPayload)
        );
    }

    #[test]
    fn malformed_worker_encoder_evidence_is_rejected() {
        let frame = IpcFrame::new(MESSAGE_WORKER_ENCODER_EVIDENCE, vec![0; 41]);
        assert_eq!(frame.message(), Err(IpcMessageError::InvalidPayload));
    }

    #[test]
    fn malformed_worker_capability_payload_is_rejected() {
        let frame = IpcFrame::new(MESSAGE_WORKER_CAPABILITIES, vec![0; 11]);
        assert_eq!(frame.message(), Err(IpcMessageError::InvalidPayload));
    }

    #[test]
    fn input_event_round_trips_through_bounded_ipc_frame() {
        let event = InputEvent {
            sequence: 9,
            timestamp_us: 123,
            event: Some(
                classmesh_protocol::control_wire::input_event::Event::ReleaseAll(
                    classmesh_protocol::control_wire::ReleaseAllInput {},
                ),
            ),
        };
        let encoded = IpcFrame::input_event(&event)
            .encode()
            .expect("input event should encode");
        let mut decoder = IpcFrameDecoder::default();
        let frames = decoder
            .push_bytes(&encoded)
            .expect("input event should decode");
        assert_eq!(
            frames[0].message().expect("typed message should decode"),
            IpcMessage::InputEvent(event)
        );
    }

    #[test]
    fn stream_reconfigure_round_trips_through_bounded_ipc_frame() {
        let reconfigure = StreamReconfigure {
            stream_id: 17,
            profile: Some(classmesh_protocol::control_wire::VideoProfile {
                width: 960,
                height: 540,
                fps: 30,
                bitrate_kbps: 1_500,
                codec: classmesh_protocol::control_wire::VideoCodec::H264 as i32,
            }),
            transport: classmesh_protocol::control_wire::MediaTransport::Unspecified as i32,
            transport_parameters: Vec::new(),
        };
        let encoded = IpcFrame::stream_reconfigure(&reconfigure)
            .encode()
            .expect("stream reconfigure should encode");
        let mut decoder = IpcFrameDecoder::default();
        let frames = decoder
            .push_bytes(&encoded)
            .expect("stream reconfigure should decode");
        assert_eq!(
            frames[0].message().expect("typed message should decode"),
            IpcMessage::StreamReconfigure(reconfigure)
        );
    }

    #[test]
    fn worker_hello_carries_process_and_session_identity() {
        let hello = IpcFrame::worker_hello(42, 7);
        assert_eq!(
            hello.message().expect("hello should decode"),
            IpcMessage::WorkerHello {
                process_id: 42,
                session_id: 7
            }
        );
    }
}
