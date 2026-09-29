use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use classmesh_core::adaptation::{StreamProfile, StreamProfileError};
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::{
    MediaTransport as WireMediaTransport, StreamKind as WireStreamKind, StreamOffer, VideoCodec,
    VideoProfile,
};

pub const MAX_STREAM_TRANSPORT_PARAMETERS: usize = 4 * 1024;
pub const UDP_UNICAST_PARAMETERS_VERSION: u8 = 1;
pub const UDP_UNICAST_PARAMETERS_LEN: usize = 3;
pub const UDP_MULTICAST_PARAMETERS_VERSION: u8 = 1;
pub const UDP_MULTICAST_PARAMETERS_LEN: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOfferError {
    InvalidStreamId,
    StreamIdOutOfRange,
    UnsupportedKind,
    MissingProfile,
    UnsupportedCodec,
    ProfileValueOutOfRange,
    InvalidProfile(StreamProfileError),
    UnsupportedTransport,
    TransportCapabilityNotNegotiated,
    TransportParametersTooLarge,
    InvalidUdpUnicastParameters,
    InvalidUdpMulticastParameters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInteractiveStreamOffer {
    pub stream_id: u64,
    pub profile: StreamProfile,
    pub transport: WireMediaTransport,
    pub transport_parameters: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMulticastParameters {
    pub group: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPresentationStreamOffer {
    pub stream_id: u64,
    pub profile: StreamProfile,
    pub multicast: UdpMulticastParameters,
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

pub fn udp_multicast_parameters(
    parameters: &[u8],
) -> Result<UdpMulticastParameters, StreamOfferError> {
    let [version, a, b, c, d, high, low] = parameters else {
        return Err(StreamOfferError::InvalidUdpMulticastParameters);
    };
    if *version != UDP_MULTICAST_PARAMETERS_VERSION {
        return Err(StreamOfferError::InvalidUdpMulticastParameters);
    }
    let group = Ipv4Addr::new(*a, *b, *c, *d);
    if group.octets()[0] != 239 {
        return Err(StreamOfferError::InvalidUdpMulticastParameters);
    }
    let port = u16::from_be_bytes([*high, *low]);
    if port == 0 {
        return Err(StreamOfferError::InvalidUdpMulticastParameters);
    }
    Ok(UdpMulticastParameters { group, port })
}

pub fn udp_multicast_transport_parameters(
    group: Ipv4Addr,
    port: u16,
) -> Result<[u8; UDP_MULTICAST_PARAMETERS_LEN], StreamOfferError> {
    if group.octets()[0] != 239 || port == 0 {
        return Err(StreamOfferError::InvalidUdpMulticastParameters);
    }
    let [high, low] = port.to_be_bytes();
    let [a, b, c, d] = group.octets();
    Ok([
        UDP_MULTICAST_PARAMETERS_VERSION,
        a,
        b,
        c,
        d,
        high,
        low,
    ])
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
    if u32::try_from(offer.stream_id).is_err() {
        return Err(StreamOfferError::StreamIdOutOfRange);
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

pub fn validate_presentation_stream_offer(
    offer: &StreamOffer,
    negotiated_capabilities: &std::collections::BTreeSet<Capability>,
) -> Result<ValidatedPresentationStreamOffer, StreamOfferError> {
    if offer.stream_id == 0 {
        return Err(StreamOfferError::InvalidStreamId);
    }
    if u32::try_from(offer.stream_id).is_err() {
        return Err(StreamOfferError::StreamIdOutOfRange);
    }
    if offer.kind != WireStreamKind::TeacherPresentation as i32 {
        return Err(StreamOfferError::UnsupportedKind);
    }
    if offer.transport_parameters.len() > MAX_STREAM_TRANSPORT_PARAMETERS {
        return Err(StreamOfferError::TransportParametersTooLarge);
    }
    if !negotiated_capabilities.contains(&Capability::TeacherPresentation)
        || !negotiated_capabilities.contains(&Capability::SframeGroupMedia)
        || !negotiated_capabilities.contains(&Capability::UdpMulticast)
    {
        return Err(StreamOfferError::TransportCapabilityNotNegotiated);
    }

    let profile = offer
        .profile
        .as_ref()
        .ok_or(StreamOfferError::MissingProfile)
        .and_then(stream_profile_from_wire)?;
    let transport = WireMediaTransport::try_from(offer.transport)
        .map_err(|_| StreamOfferError::UnsupportedTransport)?;
    if transport != WireMediaTransport::UdpMulticast {
        return Err(StreamOfferError::UnsupportedTransport);
    }
    let multicast = udp_multicast_parameters(&offer.transport_parameters)?;

    Ok(ValidatedPresentationStreamOffer {
        stream_id: offer.stream_id,
        profile,
        multicast,
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

    fn presentation_offer() -> StreamOffer {
        StreamOffer {
            stream_id: 9,
            kind: WireStreamKind::TeacherPresentation as i32,
            transport: WireMediaTransport::UdpMulticast as i32,
            profile: Some(VideoProfile {
                width: 1920,
                height: 1080,
                fps: 30,
                bitrate_kbps: 5_000,
                codec: VideoCodec::H264 as i32,
            }),
            transport_parameters: udp_multicast_transport_parameters(
                Ipv4Addr::new(239, 10, 20, 30),
                50_000,
            )
            .expect("valid multicast parameters")
            .to_vec(),
        }
    }

    fn presentation_caps() -> BTreeSet<Capability> {
        BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpMulticast,
        ])
    }

    #[test]
    fn presentation_multicast_offer_requires_exact_capability_contract() {
        let offer = presentation_offer();
        for missing in [
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpMulticast,
        ] {
            let mut capabilities = presentation_caps();
            capabilities.remove(&missing);
            assert_eq!(
                validate_presentation_stream_offer(&offer, &capabilities),
                Err(StreamOfferError::TransportCapabilityNotNegotiated)
            );
        }

        let validated =
            validate_presentation_stream_offer(&offer, &presentation_caps()).expect("valid offer");
        assert_eq!(validated.stream_id, 9);
        assert_eq!(
            validated.multicast,
            UdpMulticastParameters {
                group: Ipv4Addr::new(239, 10, 20, 30),
                port: 50_000,
            }
        );
    }

    #[test]
    fn presentation_multicast_parameters_are_versioned_group_and_port_only() {
        let encoded =
            udp_multicast_transport_parameters(Ipv4Addr::new(239, 1, 2, 3), 50_000)
                .expect("valid parameters");
        assert_eq!(encoded.len(), UDP_MULTICAST_PARAMETERS_LEN);
        assert_eq!(
            udp_multicast_parameters(&encoded),
            Ok(UdpMulticastParameters {
                group: Ipv4Addr::new(239, 1, 2, 3),
                port: 50_000,
            })
        );

        for invalid in [
            vec![2, 239, 1, 2, 3, 0xc3, 0x50],
            vec![1, 224, 1, 2, 3, 0xc3, 0x50],
            vec![1, 239, 1, 2, 3, 0, 0],
            vec![1, 239, 1, 2, 3, 0xc3],
        ] {
            assert_eq!(
                udp_multicast_parameters(&invalid),
                Err(StreamOfferError::InvalidUdpMulticastParameters)
            );
        }
    }

    #[test]
    fn presentation_offer_does_not_accept_sender_or_receiver_interface_in_parameters() {
        let mut offer = presentation_offer();
        offer.transport_parameters.push(192);
        assert_eq!(
            validate_presentation_stream_offer(&offer, &presentation_caps()),
            Err(StreamOfferError::InvalidUdpMulticastParameters)
        );
    }

    #[test]
    fn presentation_offer_rejects_wrong_kind_transport_or_stream_range() {
        let mut wrong_kind = presentation_offer();
        wrong_kind.kind = WireStreamKind::Interactive as i32;
        assert_eq!(
            validate_presentation_stream_offer(&wrong_kind, &presentation_caps()),
            Err(StreamOfferError::UnsupportedKind)
        );

        let mut wrong_transport = presentation_offer();
        wrong_transport.transport = WireMediaTransport::UdpUnicast as i32;
        assert_eq!(
            validate_presentation_stream_offer(&wrong_transport, &presentation_caps()),
            Err(StreamOfferError::UnsupportedTransport)
        );

        let mut too_large = presentation_offer();
        too_large.stream_id = u64::from(u32::MAX) + 1;
        assert_eq!(
            validate_presentation_stream_offer(&too_large, &presentation_caps()),
            Err(StreamOfferError::StreamIdOutOfRange)
        );
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
    fn stream_id_must_fit_media_packet_header() {
        let capabilities = BTreeSet::from([Capability::UdpUnicast]);
        let mut large = offer(WireMediaTransport::UdpUnicast);
        large.stream_id = u64::from(u32::MAX) + 1;
        assert_eq!(
            validate_interactive_stream_offer(&large, &capabilities),
            Err(StreamOfferError::StreamIdOutOfRange)
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
