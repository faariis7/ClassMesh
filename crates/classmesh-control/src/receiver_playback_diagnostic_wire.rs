//! Read-only, bounded, opt-in receiver playback diagnostic for an already
//! independently authorized Teacher owner. The caller must verify PrincipalId,
//! TLS credential, live control session, current Worker generation, and cap 18.
//! This pure builder does not grant such authority.
use crate::receiver_telemetry::ReceiverTelemetryBinding;
use crate::receiver_telemetry_service_runtime::ReceiverTelemetryAdmittedDiagnostic;
use classmesh_protocol::ProtocolVersion;
use classmesh_protocol::control_wire::{
    ControlEnvelope, ProtocolVersion as WireProtocolVersion, ReceiverPlaybackDiagnostic,
    control_envelope,
};

pub fn build_after_authorized_teacher(
    admitted: ReceiverTelemetryAdmittedDiagnostic,
    teacher_control_session_id: u64,
    negotiated: ProtocolVersion,
    outbound_sequence: u64,
) -> Result<ControlEnvelope, &'static str> {
    let owner: ReceiverTelemetryBinding = admitted.binding;
    if !owner.is_valid()
        || owner.control_session_id != teacher_control_session_id
        || negotiated.major != 0
        || negotiated.minor < 8
        || outbound_sequence == 0
        || admitted.sequence == 0
    {
        return Err("control.playback_diagnostic.wrong_owner_or_version");
    }
    let interval_ms = u64::try_from(admitted.interval.elapsed.as_millis())
        .map_err(|_| "control.playback_diagnostic.bad_interval")?;
    if !(1..=30_000).contains(&interval_ms) {
        return Err("control.playback_diagnostic.bad_interval");
    }
    let data = ReceiverPlaybackDiagnostic {
        presentation_id: owner.presentation_id,
        stream_id: u64::from(owner.stream_id),
        epoch: owner.epoch,
        receiver_generation: owner.receiver_generation,
        sequence: admitted.sequence,
        interval_ms,
        authenticated_frames: admitted.interval.authenticated_frames,
        rejected_frames: admitted.interval.rejected_frames,
        decoded_frames: admitted.interval.decoded_frames,
        presented_frames: admitted.interval.presented_frames,
        present_errors: admitted.interval.present_errors,
        decode_errors: admitted.interval.decode_errors,
        keyframe_waits: admitted.interval.keyframe_waits,
        queue_drops: admitted.interval.queue_drops,
    };
    Ok(ControlEnvelope {
        control_session_id: teacher_control_session_id,
        sequence: outbound_sequence,
        protocol_version: Some(WireProtocolVersion {
            major: u32::from(negotiated.major),
            minor: u32::from(negotiated.minor),
        }),
        request_id: 0,
        payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(data)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver_telemetry::ReceiverTelemetryInterval;
    use std::time::{Duration, Instant};
    fn diagnostic() -> ReceiverTelemetryAdmittedDiagnostic {
        ReceiverTelemetryAdmittedDiagnostic {
            binding: ReceiverTelemetryBinding {
                process_id: 1,
                session_id: 2,
                worker_generation: 3,
                control_session_id: 4,
                request_id: 5,
                presentation_id: 6,
                stream_id: 7,
                epoch: 8,
                receiver_generation: 9,
            },
            sequence: 10,
            interval: ReceiverTelemetryInterval {
                elapsed: Duration::from_millis(5_000),
                authenticated_frames: 11,
                rejected_frames: 12,
                decoded_frames: 13,
                presented_frames: 14,
                present_errors: 15,
                decode_errors: 16,
                keyframe_waits: 17,
                queue_drops: 18,
            },
            service_received_at: Instant::now(),
        }
    }

    #[test]
    fn authorized_wire_emits_only_real_playback_deltas_and_never_network_inference() {
        use prost::Message;
        let diag = diagnostic();
        let envelope =
            build_after_authorized_teacher(diag, 4, ProtocolVersion { major: 0, minor: 8 }, 19)
                .unwrap();
        assert_eq!(envelope.control_session_id, 4);
        assert_eq!(envelope.request_id, 0);
        let bytes = envelope.encode_to_vec();
        let again = ControlEnvelope::decode(bytes.as_slice()).unwrap();
        let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(value)) = again.payload
        else {
            panic!("read-only typed playback data expected");
        };
        assert_eq!(value.presentation_id, 6);
        assert_eq!(value.stream_id, 7);
        assert_eq!(value.receiver_generation, 9);
        assert_eq!(value.interval_ms, 5_000);
        assert_eq!(value.decoded_frames, 13);
        assert_eq!(value.presented_frames, 14);
        assert_eq!(value.queue_drops, 18);
        assert!(!format!("{value:?}").contains("rtt"));
        assert!(!format!("{value:?}").contains("packet_loss"));
    }

    #[test]
    fn wrong_control_session_version_zero_sequence_or_age_rejected_before_wire() {
        let valid = diagnostic();
        let now = ProtocolVersion { major: 0, minor: 8 };
        assert!(build_after_authorized_teacher(valid, 5, now, 19).is_err());
        assert!(
            build_after_authorized_teacher(valid, 4, ProtocolVersion { major: 0, minor: 7 }, 19)
                .is_err()
        );
        assert!(build_after_authorized_teacher(valid, 4, now, 0).is_err());
        let mut invalid = valid;
        invalid.sequence = 0;
        assert!(build_after_authorized_teacher(invalid, 4, now, 19).is_err());
        invalid = valid;
        invalid.interval.elapsed = Duration::ZERO;
        assert!(build_after_authorized_teacher(invalid, 4, now, 19).is_err());
        invalid.interval.elapsed = Duration::from_secs(31);
        assert!(build_after_authorized_teacher(invalid, 4, now, 19).is_err());
    }
}
