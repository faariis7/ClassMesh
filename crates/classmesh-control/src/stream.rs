use std::net::{IpAddr, SocketAddr};

use classmesh_core::adaptation::{StreamProfile, StreamProfileError};
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::{
    MediaTransport as WireMediaTransport, StreamKind as WireStreamKind, StreamOffer, VideoCodec,
    VideoProfile,
};

pub const MAX_STREAM_TRANSPORT_PARAMETERS: usize = 4 * 1024;
pub const UDP_UNICAST_PARAMETERS_VERSION: u8 = 1;
pub const UDP_UNICAST_PARAMETERS_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOfferError {
    InvalidStreamId,
    UnsupportedKind,
    MissingProfile,
    UnsupportedCodec,
    ProfileValueOutOfRange,
    InvalidProfile(StreamProfileError),
    UnsupportedTransport,
    TransportCapabilityNotNegotiated,
    TransportParametersTooLarge,
    InvalidUdpUnicastParameters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInteractiveStreamOffer {
    pub stream_id: u64,
    pub profile: StreamProfile,
    pub transport: WireMediaTransport,
    pub transport_parameters: Vec<u8>,
}

pub fn udp_unicast_port(parameters: &[u8]) -> Result<u16, StreamOfferError> {
    let [version, high, low] = parameters else {
        return Err(StreamOfferError::InvalidUdpUnicastParameters);
    };
    if *version != UDP_UNICAST_PARAMETERS_VERSION {
        return Err(StreamOfferError::InvalidUdpUnicastParameters);
    }
    let port = u16::from_be_bytes([*high, *low]);
    if port == 0 {
        return Err(StreamOfferError::InvalidUdpUnicastParameters);
    }
    Ok(port)
}

pub fn peer_bound_udp_unicast_destination(
    peer_ip: IpAddr,
    parameters: &[u8],
) -> Result<SocketAddr, StreamOfferError> {
    Ok(SocketAddr::new(peer_ip, udp_unicast_port(parameters)?))
}

pub fn stream_profile_from_wire(profile: &VideoProfile) -> Result<StreamProfile, StreamOfferError> {
    if profile.codec != VideoCodec::H264 as i32 {
        return Err(StreamOfferError::UnsupportedCodec);
    }

    let width =
        u16::try_from(profile.width).map_err(|_| StreamOfferError::ProfileValueOutOfRange)?;
    let height =
        u16::try_from(profile.height).map_err(|_| StreamOfferError::ProfileValueOutOfRange)?;
    let fps = u8::try_from(profile.fps).map_err(|_| StreamOfferError::ProfileValueOutOfRange)?;

    StreamProfile::new(width, height, fps, profile.bitrate_kbps)
        .validate()
        .map_err(StreamOfferError::InvalidProfile)
}

#[must_use]
pub fn stream_profile_to_wire(profile: StreamProfile) -> VideoProfile {
    VideoProfile {
        width: u32::from(profile.width),
        height: u32::from(profile.height),
        fps: u32::from(profile.fps),
        bitrate_kbps: profile.bitrate_kbps,
        codec: VideoCodec::H264 as i32,
    }
}

pub fn validate_interactive_stream_offer(
    offer: &StreamOffer,
    negotiated_capabilities: &std::collections::BTreeSet<Capability>,
) -> Result<ValidatedInteractiveStreamOffer, StreamOfferError> {
    if offer.stream_id == 0 {
        return Err(StreamOfferError::InvalidStreamId);
    }
    if offer.kind != WireStreamKind::Interactive as i32 {
        return Err(StreamOfferError::UnsupportedKind);
    }
    if offer.transport_parameters.len() > MAX_STREAM_TRANSPORT_PARAMETERS {
        return Err(StreamOfferError::TransportParametersTooLarge);
    }

    let profile = offer
        .profile
        .as_ref()
        .ok_or(StreamOfferError::MissingProfile)
        .and_then(stream_profile_from_wire)?;

    let transport = WireMediaTransport::try_from(offer.transport)
        .map_err(|_| StreamOfferError::UnsupportedTransport)?;
    let required_capability = match transport {
        WireMediaTransport::UdpUnicast => {
            let _ = udp_unicast_port(&offer.transport_parameters)?;
            Capability::UdpUnicast
        }
        WireMediaTransport::QuicDatagram => Capability::QuicDatagram,
        WireMediaTransport::Webrtc => Capability::WebRtc,
        WireMediaTransport::Unspecified
        | WireMediaTransport::UdpMulticast
        | WireMediaTransport::ReliableFallback => {
            return Err(StreamOfferError::UnsupportedTransport);
        }
    };
    if !negotiated_capabilities.contains(&required_capability) {
        return Err(StreamOfferError::TransportCapabilityNotNegotiated);
    }

    Ok(ValidatedInteractiveStreamOffer {
        stream_id: offer.stream_id,
        profile,
        transport,
        transport_parameters: offer.transport_parameters.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn offer(transport: WireMediaTransport) -> StreamOffer {
        StreamOffer {
            stream_id: 7,
            kind: WireStreamKind::Interactive as i32,
            transport: transport as i32,
            profile: Some(VideoProfile {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 2_500,
                codec: VideoCodec::H264 as i32,
            }),
            transport_parameters: vec![1, 2, 3],
        }
    }

    #[test]
    fn explicit_unicast_offer_requires_negotiated_transport_capability() {
        let offer = offer(WireMediaTransport::UdpUnicast);
        assert_eq!(
            validate_interactive_stream_offer(&offer, &BTreeSet::new()),
            Err(StreamOfferError::TransportCapabilityNotNegotiated)
        );

        let validated =
            validate_interactive_stream_offer(&offer, &BTreeSet::from([Capability::UdpUnicast]))
                .expect("negotiated UDP unicast should validate");
        assert_eq!(validated.stream_id, 7);
        assert_eq!(validated.profile, StreamProfile::new(1280, 720, 30, 2_500));
        assert_eq!(validated.transport, WireMediaTransport::UdpUnicast);
    }

    #[test]
    fn interactive_offer_never_invents_or_accepts_an_implicit_transport() {
        for transport in [
            WireMediaTransport::Unspecified,
            WireMediaTransport::UdpMulticast,
            WireMediaTransport::ReliableFallback,
        ] {
            assert_eq!(
                validate_interactive_stream_offer(&offer(transport), &BTreeSet::new()),
                Err(StreamOfferError::UnsupportedTransport)
            );
        }
    }

    #[test]
    fn invalid_profile_and_large_transport_parameters_fail_closed() {
        let mut bad_profile = offer(WireMediaTransport::QuicDatagram);
        bad_profile.profile.as_mut().expect("profile").width = 1_919;
        assert!(matches!(
            validate_interactive_stream_offer(
                &bad_profile,
                &BTreeSet::from([Capability::QuicDatagram]),
            ),
            Err(StreamOfferError::InvalidProfile(
                StreamProfileError::InvalidGeometry
            ))
        ));

        let mut large = offer(WireMediaTransport::QuicDatagram);
        large.transport_parameters = vec![0; MAX_STREAM_TRANSPORT_PARAMETERS + 1];
        assert_eq!(
            validate_interactive_stream_offer(&large, &BTreeSet::from([Capability::QuicDatagram]),),
            Err(StreamOfferError::TransportParametersTooLarge)
        );
    }

    #[test]
    fn only_interactive_h264_nonzero_streams_are_accepted() {
        let capabilities = BTreeSet::from([Capability::WebRtc]);

        let mut zero = offer(WireMediaTransport::Webrtc);
        zero.stream_id = 0;
        assert_eq!(
            validate_interactive_stream_offer(&zero, &capabilities),
            Err(StreamOfferError::InvalidStreamId)
        );

        let mut monitoring = offer(WireMediaTransport::Webrtc);
        monitoring.kind = WireStreamKind::Monitoring as i32;
        assert_eq!(
            validate_interactive_stream_offer(&monitoring, &capabilities),
            Err(StreamOfferError::UnsupportedKind)
        );

        let mut hevc = offer(WireMediaTransport::Webrtc);
        hevc.profile.as_mut().expect("profile").codec = VideoCodec::Hevc as i32;
        assert_eq!(
            validate_interactive_stream_offer(&hevc, &capabilities),
            Err(StreamOfferError::UnsupportedCodec)
        );
    }

    #[test]
    fn udp_unicast_parameters_are_versioned_port_only() {
        assert_eq!(udp_unicast_port(&[1, 0x1f, 0x90]), Ok(8080));
        assert_eq!(
            udp_unicast_port(&[2, 0x1f, 0x90]),
            Err(StreamOfferError::InvalidUdpUnicastParameters)
        );
        assert_eq!(
            udp_unicast_port(&[1, 0, 0]),
            Err(StreamOfferError::InvalidUdpUnicastParameters)
        );
        assert_eq!(
            udp_unicast_port(&[1, 0x1f, 0x90, 1]),
            Err(StreamOfferError::InvalidUdpUnicastParameters)
        );
    }

    #[test]
    fn udp_destination_ip_is_bound_to_authenticated_control_peer() {
        let peer = "192.0.2.44".parse::<IpAddr>().expect("peer ip");
        let destination =
            peer_bound_udp_unicast_destination(peer, &[1, 0x23, 0x28]).expect("destination");
        assert_eq!(destination, "192.0.2.44:9000".parse().expect("socket"));
    }

    #[test]
    fn wire_profile_round_trip_preserves_bounded_h264_profile() {
        let profile = StreamProfile::new(960, 540, 30, 1_500);
        assert_eq!(
            stream_profile_from_wire(&stream_profile_to_wire(profile)),
            Ok(profile)
        );
    }
}
