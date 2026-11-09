use std::net::SocketAddr;
use std::time::Duration;

use crate::multicast::MulticastMembership;
pub(super) use crate::protected_media_receive::{
    DatagramFailureDisposition, classify_datagram_failure,
};
use crate::udp::UdpMediaSocket;

use super::config::{ProtectedMulticastReceiveError, ProtectedMulticastReceiverConfig};
use super::state::{
    MulticastPacketDropReason, ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveState,
};

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

    /// Compatibility API for callers that already own a precise media clock.
    pub fn receive_once(
        &mut self,
        now_us: u64,
    ) -> Result<ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveError> {
        self.receive_once_with_clock(|| now_us)
    }

    /// Samples monotonic time after the OS socket wait on both packet arrival
    /// and timeout expiry; protected source/stream/epoch admission remains
    /// unchanged and media policies keep their existing bounded deadlines.
    pub fn receive_once_with_clock(
        &mut self,
        clock: impl FnOnce() -> u64,
    ) -> Result<ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveError> {
        match self.socket.receive_packet() {
            Ok((packet, source)) => Ok(self.state.push_packet(clock(), &packet, source)),
            Err(error) => match classify_datagram_failure(&error) {
                DatagramFailureDisposition::Tick => Ok(ProtectedMulticastReceiveOutcome::Events(
                    self.state.tick(clock()),
                )),
                DatagramFailureDisposition::DropMalformed => {
                    Ok(ProtectedMulticastReceiveOutcome::Dropped(
                        MulticastPacketDropReason::MalformedDatagram,
                    ))
                }
                DatagramFailureDisposition::Fail => Err(error.into()),
            },
        }
    }

    #[must_use]
    pub const fn stats(&self) -> crate::protected_media_receive::ProtectedMediaReceiveStats {
        self.state.stats()
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

#[cfg(test)]
mod receive_clock_tests {
    use super::*;
    use crate::multicast::MulticastProbeOutcome;
    use crate::{PacketizeMeta, packetize_frame};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[test]
    fn protected_multicast_socket_samples_clock_after_packet_or_timeout() {
        // The real multicast interface is intentionally NOT joined in this
        // timing test. Use a test-only loopback socket; source is deliberately
        // invalid for the enrolled multicast sender and remains denied.
        let membership = MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, 30),
            Ipv4Addr::new(192, 168, 50, 10),
        )
        .unwrap();
        let config = ProtectedMulticastReceiverConfig::new(
            membership,
            50000,
            Ipv4Addr::new(192, 168, 50, 20),
            800,
            MulticastProbeOutcome::Available,
        )
        .unwrap();
        let socket =
            UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let mut receiver = ProtectedMulticastFrameReceiver {
            socket,
            membership,
            state: ProtectedMulticastReceiveState::new(config).unwrap(),
        };
        let transmitted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&transmitted);
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            let socket =
                UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                    .unwrap();
            let frame = packetize_frame(
                &[0x5a],
                PacketizeMeta {
                    protocol_major: 0,
                    protocol_minor: 4,
                    stream_id: 800,
                    frame_id: 1,
                    first_sequence: 10,
                    timestamp_us: 100_000,
                    keyframe: true,
                },
            )
            .unwrap();
            signal.store(true, Ordering::Release);
            socket
                .send_packet_to(
                    &frame[0],
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
                )
                .unwrap();
        });
        let outcome = receiver
            .receive_once_with_clock(|| {
                assert!(
                    transmitted.load(Ordering::Acquire),
                    "clock before read would falsely age fragments"
                );
                100_000
            })
            .unwrap();
        assert!(
            matches!(outcome, ProtectedMulticastReceiveOutcome::Dropped(_)),
            "unapproved loopback sender must remain denied"
        );
        sender.join().unwrap();
        receiver
            .socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut sampled_on_timeout = false;
        let outcome = receiver
            .receive_once_with_clock(|| {
                sampled_on_timeout = true;
                200_000
            })
            .unwrap();
        assert!(matches!(
            outcome,
            ProtectedMulticastReceiveOutcome::Events(_)
        ));
        assert!(
            sampled_on_timeout,
            "timeout tick clock must be sampled after recv wait"
        );
    }
}
