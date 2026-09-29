use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::multicast::MulticastMembership;
use crate::udp::{DatagramError, UdpMediaSocket};

use super::config::{ProtectedMulticastReceiveError, ProtectedMulticastReceiverConfig};
use super::state::{ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveState};

pub const DEFAULT_MULTICAST_READ_TIMEOUT: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub struct ProtectedMulticastFrameReceiver {
    socket: UdpMediaSocket,
    membership: MulticastMembership,
    state: ProtectedMulticastReceiveState,
}

impl ProtectedMulticastFrameReceiver {
    pub fn bind(
        config: ProtectedMulticastReceiverConfig,
    ) -> Result<Self, ProtectedMulticastReceiveError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_read_timeout(Some(DEFAULT_MULTICAST_READ_TIMEOUT))?;
        socket.join_multicast_v4(config.membership().group(), config.membership().interface())?;

        Ok(Self {
            socket,
            membership: config.membership(),
            state: ProtectedMulticastReceiveState::new(config)?,
        })
    }

    pub fn receive_once(
        &mut self,
        now_us: u64,
    ) -> Result<ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveError> {
        match self.socket.receive_packet() {
            Ok((packet, source)) => Ok(self.state.push_packet(now_us, &packet, source)),
            Err(DatagramError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(ProtectedMulticastReceiveOutcome::Events(
                    self.state.tick(now_us),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.state.dropped_frames()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedMulticastReceiveError> {
        self.socket.local_addr().map_err(Into::into)
    }
}

impl Drop for ProtectedMulticastFrameReceiver {
    fn drop(&mut self) {
        let _ = self
            .socket
            .leave_multicast_v4(self.membership.group(), self.membership.interface());
    }
}
