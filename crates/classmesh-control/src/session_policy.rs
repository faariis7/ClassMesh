use std::collections::BTreeSet;

use classmesh_protocol::control_wire::{StreamOffer, StreamReconfigure};
use classmesh_protocol::Capability;

const MEDIA_TRANSPORT_UDP_MULTICAST: i32 = 1;
const MEDIA_TRANSPORT_UDP_UNICAST: i32 = 2;
const MEDIA_TRANSPORT_QUIC_DATAGRAM: i32 = 3;
const MEDIA_TRANSPORT_WEBRTC: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPolicyError {
    UnsupportedOrUnspecifiedTransport { transport: i32 },
    MissingNegotiatedCapability { capability: Capability },
}

#[must_use]
pub const fn required_transport_capability(transport: i32) -> Option<Capability> {
    match transport {
        MEDIA_TRANSPORT_UDP_MULTICAST => Some(Capability::UdpMulticast),
        MEDIA_TRANSPORT_UDP_UNICAST => Some(Capability::UdpUnicast),
        MEDIA_TRANSPORT_QUIC_DATAGRAM => Some(Capability::QuicDatagram),
        MEDIA_TRANSPORT_WEBRTC => Some(Capability::WebRtc),
        _ => None,
    }
}

pub fn validate_negotiated_transport(
    negotiated_capabilities: &BTreeSet<Capability>,
    transport: i32,
) -> Result<(), SessionPolicyError> {
    let Some(required) = required_transport_capability(transport) else {
        return Err(SessionPolicyError::UnsupportedOrUnspecifiedTransport { transport });
    };
    if !negotiated_capabilities.contains(&required) {
        return Err(SessionPolicyError::MissingNegotiatedCapability {
            capability: required,
        });
    }
    Ok(())
}

pub fn validate_stream_offer(
    negotiated_capabilities: &BTreeSet<Capability>,
    offer: &StreamOffer,
) -> Result<(), SessionPolicyError> {
    validate_negotiated_transport(negotiated_capabilities, offer.transport)
}

pub fn validate_stream_reconfigure(
    negotiated_capabilities: &BTreeSet<Capability>,
    reconfigure: &StreamReconfigure,
) -> Result<(), SessionPolicyError> {
    validate_negotiated_transport(negotiated_capabilities, reconfigure.transport)
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::control_wire::{StreamKind, VideoProfile};

    use super::*;

    fn offer(transport: i32) -> StreamOffer {
        StreamOffer {
            stream_id: 7,
            kind: StreamKind::Monitoring as i32,
            transport,
            profile: Some(VideoProfile {
                width: 1920,
                height: 1080,
                fps: 30,
                bitrate_kbps: 4_000,
                codec: 1,
            }),
            transport_parameters: Vec::new(),
        }
    }

    #[test]
    fn negotiated_transport_must_have_matching_capability() {
        let capabilities = BTreeSet::from([Capability::UdpUnicast]);

        validate_stream_offer(&capabilities, &offer(MEDIA_TRANSPORT_UDP_UNICAST))
            .expect("negotiated UDP unicast should be accepted");
        assert_eq!(
            validate_stream_offer(&capabilities, &offer(MEDIA_TRANSPORT_QUIC_DATAGRAM)),
            Err(SessionPolicyError::MissingNegotiatedCapability {
                capability: Capability::QuicDatagram,
            })
        );
    }

    #[test]
    fn unspecified_and_reliable_fallback_fail_closed_until_explicitly_negotiated() {
        let capabilities = BTreeSet::from([
            Capability::UdpMulticast,
            Capability::UdpUnicast,
            Capability::QuicDatagram,
            Capability::WebRtc,
        ]);

        for transport in [0, 5, 99] {
            assert_eq!(
                validate_stream_offer(&capabilities, &offer(transport)),
                Err(SessionPolicyError::UnsupportedOrUnspecifiedTransport { transport })
            );
        }
    }

    #[test]
    fn reconfigure_uses_the_same_negotiated_transport_policy() {
        let capabilities = BTreeSet::from([Capability::WebRtc]);
        let reconfigure = StreamReconfigure {
            stream_id: 7,
            profile: None,
            transport: MEDIA_TRANSPORT_WEBRTC,
            transport_parameters: Vec::new(),
        };

        validate_stream_reconfigure(&capabilities, &reconfigure)
            .expect("negotiated WebRTC should be accepted");
    }
}
