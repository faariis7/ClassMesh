use std::collections::VecDeque;

use classmesh_protocol::control_wire::InputEvent;
use prost::Message;

pub const IPC_MAGIC: u32 = 0x434D_4950; // "CMIP"
pub const IPC_HEADER_LEN: usize = 12;
pub const MAX_IPC_MESSAGE: usize = 1_048_576;
pub const IPC_VERSION_MAJOR: u8 = 0;
pub const IPC_VERSION_MINOR: u8 = 1;

const MESSAGE_WORKER_HELLO: u16 = 1;
const MESSAGE_SERVICE_READY: u16 = 2;
const MESSAGE_CONTROL: u16 = 10;
const MESSAGE_INPUT_EVENT: u16 = 11;

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
}

impl IpcControlCommand {
    const fn as_byte(self) -> u8 {
        match self {
            Self::SuspendMedia => 1,
            Self::ResumeMedia => 2,
            Self::Shutdown => 3,
        }
    }

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SuspendMedia),
            2 => Some(Self::ResumeMedia),
            3 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IpcMessage {
    WorkerHello { process_id: u32, session_id: u32 },
    ServiceReady,
    Control(IpcControlCommand),
    InputEvent(InputEvent),
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
        let frame = IpcFrame::control(IpcControlCommand::SuspendMedia);
        let encoded = frame.encode().expect("control frame should encode");
        let mut decoder = IpcFrameDecoder::default();
        let frames = decoder
            .push_bytes(&encoded)
            .expect("control frame should decode");
        assert_eq!(
            frames[0].message().expect("typed message should decode"),
            IpcMessage::Control(IpcControlCommand::SuspendMedia)
        );
    }

    #[test]
    fn input_event_round_trips_through_bounded_ipc_frame() {
        let event = InputEvent {
            sequence: 9,
            timestamp_us: 123,
            event: Some(classmesh_protocol::control_wire::input_event::Event::ReleaseAll(
                classmesh_protocol::control_wire::ReleaseAllInput {},
            )),
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
