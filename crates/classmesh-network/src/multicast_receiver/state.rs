use std::net::{IpAddr, SocketAddr};

use crate::MediaPacket;
use crate::protected_media_receive::{
    ProtectedMediaReceiveCoreError, ProtectedMediaReceiveState,
};

use super::config::{ProtectedMulticastReceiveError, ProtectedMulticastReceiverConfig};

pub use crate::protected_media_receive::{
    ProtectedMediaPacketDropReason as MulticastPacketDropReason,
    ProtectedMediaReceiveBatch as ProtectedMulticastReceiveBatch,
    ProtectedMediaReceiveOutcome as ProtectedMulticastReceiveOutcome,
    ReceivedGroupMediaCiphertext,
};

#[derive(Debug)]
pub struct ProtectedMulticastReceiveState {
    inner: ProtectedMediaReceiveState,
}

impl ProtectedMulticastReceiveState {
    pub fn new(
        config: ProtectedMulticastReceiverConfig,
    ) -> Result<Self, ProtectedMulticastReceiveError> {
        let inner = ProtectedMediaReceiveState::new(
            IpAddr::V4(config.expected_sender()),
            config.stream_id(),
        )
        .map_err(map_core_error)?;

        Ok(Self { inner })
    }

    pub fn push_packet(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
        source: SocketAddr,
    ) -> ProtectedMulticastReceiveOutcome {
        self.inner.push_packet(now_us, packet, source)
    }

    #[must_use]
    pub fn tick(&mut self, now_us: u64) -> ProtectedMulticastReceiveBatch {
        self.inner.tick(now_us)
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.inner.dropped_frames()
    }
}

const fn map_core_error(error: ProtectedMediaReceiveCoreError) -> ProtectedMulticastReceiveError {
    match error {
        ProtectedMediaReceiveCoreError::InvalidStreamId => {
            ProtectedMulticastReceiveError::InvalidStreamId
        }
        ProtectedMediaReceiveCoreError::ProtocolVersionOutOfRange => {
            ProtectedMulticastReceiveError::ProtocolVersionOutOfRange
        }
    }
}
