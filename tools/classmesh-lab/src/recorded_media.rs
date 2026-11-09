//! A bounded, loopback-only offline H.264 access-unit fixture for testing the
//! existing real UDP media reassembler when a VM has no hardware H.264 encoder.
//! Never treated as ClassMesh live capture, remote authorization, GPU decode,
//! presented frames, or completion of #688 M3.

use std::net::SocketAddr;

pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACCESS_UNIT_BYTES: usize = 512 * 1024;
const MAX_ACCESS_UNITS: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedMediaError {
    MissingAccessUnitDelimiter,
    MissingOrMalformedNal,
    NotKeyframeBootstrapped,
    MissingVideoSlice,
    InputTooLarge,
    FrameTooLarge,
    TooManyFrames,
}

impl std::fmt::Display for RecordedMediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recorded H.264 fixture rejected: {self:?}")
    }
}
impl std::error::Error for RecordedMediaError {}

#[derive(Debug, Clone, Copy)]
pub struct AnnexBAccessUnit<'a> {
    pub data: &'a [u8],
    pub keyframe: bool,
}

/// A lab-only boundary: recorded media is deliberately restricted to local
/// loopback to prevent this diagnostic sender being used as an unauthenticated
/// remote media producer. Normal QUIC/Teacher/Service authorization unchanged.
pub fn validate_params(destination: SocketAddr, fps: u8) -> Result<(), &'static str> {
    if !matches!(destination.ip(), std::net::IpAddr::V4(ip) if ip.is_loopback()) {
        return Err("diagnostic UDP destination must be loopback");
    }
    if !(1..=60).contains(&fps) {
        return Err("recorded media diagnostic FPS must be 1..=60");
    }
    Ok(())
}

fn prefix_len(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i..i + 3) == Some(&[0, 0, 1]) {
        Some(3)
    } else if bytes.get(i..i + 4) == Some(&[0, 0, 0, 1]) {
        Some(4)
    } else {
        None
    }
}

/// Splits a bounded Annex-B by Access Unit Delimiter NAL type 9, retaining
/// original bytes byte-for-byte (including start codes) for later SHA compare.
/// It *does not* decode or claim that video content is visible or changing.
/// Rejects first non-IDR frame and any fragment without an actual VCL NAL.
pub fn parse_access_units(bytes: &[u8]) -> Result<Vec<AnnexBAccessUnit<'_>>, RecordedMediaError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(RecordedMediaError::InputTooLarge);
    }
    if bytes.is_empty() || prefix_len(bytes, 0).is_none() {
        return Err(RecordedMediaError::MissingAccessUnitDelimiter);
    }
    let mut starts: Vec<(usize, u8)> = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if let Some(prefix) = prefix_len(bytes, cursor) {
            let header = *bytes
                .get(cursor + prefix)
                .ok_or(RecordedMediaError::MissingOrMalformedNal)?;
            let typ = header & 0x1f;
            if typ == 0 || (header & 0x80) != 0 {
                return Err(RecordedMediaError::MissingOrMalformedNal);
            }
            starts.push((cursor, typ));
            cursor += prefix + 1;
        } else {
            cursor += 1;
        }
    }
    if bytes.ends_with(&[0, 0, 1]) || bytes.ends_with(&[0, 0, 0, 1]) {
        return Err(RecordedMediaError::MissingOrMalformedNal);
    }
    if starts.first().is_none_or(|(_, t)| *t != 9) {
        return Err(RecordedMediaError::MissingAccessUnitDelimiter);
    }
    let boundaries: Vec<usize> = starts
        .iter()
        .filter_map(|(pos, t)| (*t == 9).then_some(*pos))
        .collect();
    if boundaries.len() > MAX_ACCESS_UNITS {
        return Err(RecordedMediaError::TooManyFrames);
    }
    let mut frames = Vec::with_capacity(boundaries.len());
    for (index, start) in boundaries.iter().copied().enumerate() {
        let end = boundaries.get(index + 1).copied().unwrap_or(bytes.len());
        let data = &bytes[start..end];
        if data.len() > MAX_ACCESS_UNIT_BYTES {
            return Err(RecordedMediaError::FrameTooLarge);
        }
        let mut vcl = false;
        let mut keyframe = false;
        for (_, typ) in starts.iter().filter(|(pos, _)| *pos >= start && *pos < end) {
            vcl |= *typ == 1 || *typ == 5;
            keyframe |= *typ == 5;
        }
        if !vcl {
            return Err(RecordedMediaError::MissingVideoSlice);
        }
        if index == 0 && !keyframe {
            return Err(RecordedMediaError::NotKeyframeBootstrapped);
        }
        frames.push(AnnexBAccessUnit { data, keyframe });
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal Annex-B NALs exercise framing, not H.264 decode.
    const AUD: &[u8] = &[0, 0, 0, 1, 0x09, 0xF0];
    const IDR: &[u8] = &[0, 0, 1, 0x65, 0xAB];
    const P: &[u8] = &[0, 0, 1, 0x41, 0xCD];

    #[test]
    fn extracts_idr_then_non_keyframe_from_aud_separated_annexb() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(AUD);
        bytes.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x12]); // SPS
        bytes.extend_from_slice(&[0, 0, 0, 1, 0x68, 0x34]); // PPS
        bytes.extend_from_slice(IDR);
        let first_len = bytes.len();
        bytes.extend_from_slice(AUD);
        bytes.extend_from_slice(P);
        let frames = parse_access_units(&bytes).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, &bytes[..first_len]);
        assert!(frames[0].keyframe);
        assert_eq!(frames[1].data, &bytes[first_len..]);
        assert!(!frames[1].keyframe);
    }

    #[test]
    fn rejects_streams_without_aud_or_first_idr_and_without_vcl() {
        assert!(parse_access_units(IDR).is_err());
        let mut p_only = AUD.to_vec();
        p_only.extend_from_slice(P);
        assert!(parse_access_units(&p_only).is_err());
        let mut metadata_only = AUD.to_vec();
        metadata_only.extend_from_slice(&[0, 0, 1, 0x67, 0x12]);
        assert!(parse_access_units(&metadata_only).is_err());
    }

    #[test]
    fn refuses_partial_headers_and_oversized_untrusted_media() {
        let mut truncated = AUD.to_vec();
        truncated.extend_from_slice(&[0, 0, 1]);
        assert!(parse_access_units(&truncated).is_err());
        assert!(parse_access_units(&vec![0; MAX_INPUT_BYTES + 1]).is_err());
    }

    #[test]
    fn actual_udp_loopback_reassembles_two_aud_frames_byte_exact_and_ordered() {
        use classmesh_network::receiver::{ReceiverEvent, ReceiverPolicy};
        use classmesh_network::transport::{UdpFrameReceiver, UdpFrameSender, UdpSenderConfig};
        use classmesh_video::distributor::SharedEncodedFrame;
        use classmesh_video::{Codec, EncodedFrameMeta};
        use std::time::Duration;

        let mut bytes = AUD.to_vec();
        bytes.extend_from_slice(IDR);
        bytes.extend_from_slice(AUD);
        bytes.extend_from_slice(P);
        let units = parse_access_units(&bytes).unwrap();
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut receiver = UdpFrameReceiver::bind(loopback, ReceiverPolicy::default()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let to = receiver.local_addr().unwrap();
        let mut sender =
            UdpFrameSender::bind(loopback, UdpSenderConfig::presentation(1, to)).unwrap();
        for (index, unit) in units.iter().enumerate() {
            let id = u64::try_from(index + 1).unwrap();
            let meta = EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id * 50_000,
                keyframe: unit.keyframe,
            };
            let frame = SharedEncodedFrame::new(meta, Codec::H264, unit.data.to_vec());
            let sent = sender.send_frame(meta.timestamp_us, &frame).unwrap();
            let mut received = None;
            for _ in 0..sent.packets {
                let batch = receiver.receive_once(meta.timestamp_us).unwrap();
                for event in batch.events {
                    if let ReceiverEvent::FrameReady(done) = event {
                        received = Some(done);
                    }
                }
            }
            let assembled = received.expect("real datagrams must reconstruct one frame");
            assert_eq!(assembled.frame_id, id);
            assert_eq!(assembled.data.as_slice(), unit.data);
            assert_eq!(assembled.keyframe, unit.keyframe);
        }
        assert_eq!(sender.stats().frames_sent, 2);
    }

    #[test]
    fn refuses_non_loopback_destination_and_invalid_fps() {
        assert!(validate_params("127.0.0.1:57000".parse().unwrap(), 12).is_ok());
        assert!(validate_params("192.168.0.2:57000".parse().unwrap(), 12).is_err());
        assert!(validate_params("[::1]:57000".parse().unwrap(), 12).is_err());
        assert!(validate_params("127.0.0.1:57000".parse().unwrap(), 0).is_err());
        assert!(validate_params("127.0.0.1:57000".parse().unwrap(), 61).is_err());
    }
}
