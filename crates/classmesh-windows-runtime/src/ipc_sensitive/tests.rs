use classmesh_protocol::control_wire::PresentationKeyGrant;
use classmesh_protocol::group_media_control::PRESENTATION_GROUP_KEY_BYTES;

use super::*;
use crate::ipc::{
    IPC_HEADER_LEN, IPC_VERSION_MAJOR, IPC_VERSION_MINOR, IpcFrame, IpcFrameDecoder, IpcFrameError,
    IpcHeader, IpcMessage, IpcMessageError, MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
};

fn grant(value: u8) -> PresentationKeyGrant {
    PresentationKeyGrant {
        presentation_id: 55,
        stream_id: 7,
        epoch: 3,
        key_material: vec![value; PRESENTATION_GROUP_KEY_BYTES],
    }
}

fn sensitive(value: u8) -> SensitivePresentationKeyInstall {
    let mut grant = grant(value);
    let sensitive = SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant)
        .expect("valid sensitive IPC install");
    assert!(grant.key_material.iter().all(|byte| *byte == 0));
    sensitive
}

#[test]
fn control_grant_is_taken_once_and_source_is_zeroized() {
    let mut grant = grant(0x5a);
    let install = SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant)
        .expect("valid grant");
    assert!(grant.key_material.iter().all(|byte| *byte == 0));
    assert_eq!(
        install.binding(),
        PresentationKeyInstallBinding {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        }
    );
    let debug = format!("{install:?}");
    assert!(debug.contains("key_material_len"));
    assert!(!debug.contains("[90"));
}

#[test]
fn rejected_control_grant_still_zeroizes_source_key() {
    let mut invalid_binding = grant(0x6a);
    invalid_binding.stream_id = 0;
    assert_eq!(
        SensitivePresentationKeyInstall::take_from_control_grant(
            77,
            44,
            &mut invalid_binding,
        )
        .err(),
        Some(IpcMessageError::InvalidPayload)
    );
    assert!(
        invalid_binding
            .key_material
            .iter()
            .all(|byte| *byte == 0)
    );

    let mut invalid_session = grant(0x6b);
    assert_eq!(
        SensitivePresentationKeyInstall::take_from_control_grant(
            0,
            44,
            &mut invalid_session,
        )
        .err(),
        Some(IpcMessageError::InvalidPayload)
    );
    assert!(
        invalid_session
            .key_material
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn generic_decoder_rejects_sensitive_message_type() {
    let encoded = sensitive(0x44).encode().expect("sensitive frame encodes");
    let mut decoder = IpcFrameDecoder::default();
    assert_eq!(
        decoder.push_bytes(encoded.as_slice()),
        Err(IpcFrameError::SensitiveMessageRequiresZeroizingDecoder)
    );
}

#[test]
fn sensitive_decoder_round_trips_fragmented_key_and_zeroizes_input_chunks() {
    let mut encoded = sensitive(0x33).encode().expect("sensitive frame encodes");
    let split = IPC_HEADER_LEN + 40;
    let (first, second) = encoded.split_at_mut(split);
    let mut decoder = SensitiveIpcFrameDecoder::default();

    assert!(
        decoder
            .push_bytes_zeroizing(first)
            .expect("first fragment accepted")
            .is_empty()
    );
    assert!(first.iter().all(|byte| *byte == 0));

    let mut decoded = decoder
        .push_bytes_zeroizing(second)
        .expect("second fragment accepted");
    assert!(second.iter().all(|byte| *byte == 0));
    assert_eq!(decoded.len(), 1);

    let DecodedIpcFrame::PresentationKeyInstall(install) = decoded.remove(0) else {
        panic!("expected sensitive presentation-key install");
    };
    assert_eq!(install.binding().control_session_id, 77);
    assert_eq!(install.binding().request_id, 44);
    assert_eq!(install.binding().presentation_id, 55);
    assert_eq!(install.binding().stream_id, 7);
    assert_eq!(install.binding().epoch, 3);

    let (_, key_material) = install.into_parts();
    assert!(key_material.iter().all(|byte| *byte == 0x33));
}

#[test]
fn malformed_sensitive_frame_zeroizes_caller_and_internal_buffer() {
    let header = IpcHeader {
        version_major: IPC_VERSION_MAJOR,
        version_minor: IPC_VERSION_MINOR,
        message_type: MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
        payload_len: 1,
    }
    .encode()
    .expect("header encodes");
    let mut bytes = Vec::from(header);
    bytes.push(0x5a);

    let mut decoder = SensitiveIpcFrameDecoder::default();
    assert!(matches!(
        decoder.push_bytes_zeroizing(bytes.as_mut_slice()),
        Err(IpcFrameError::InvalidSensitivePayload)
    ));
    assert!(bytes.iter().all(|byte| *byte == 0));
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn sensitive_message_requires_exact_ipc_v06() {
    let mut encoded = sensitive(0x22).encode().expect("sensitive frame encodes");
    encoded[5] = IPC_VERSION_MINOR.saturating_sub(1);
    let mut decoder = SensitiveIpcFrameDecoder::default();

    assert!(matches!(
        decoder.push_bytes_zeroizing(encoded.as_mut_slice()),
        Err(IpcFrameError::InvalidSensitivePayload)
    ));
    assert!(encoded.iter().all(|byte| *byte == 0));
}

#[test]
fn secure_decoder_preserves_regular_message_behavior_and_zeroizes_read_buffer() {
    let mut bytes = IpcFrame::worker_hello(42, 7)
        .encode()
        .expect("worker hello encodes");
    let mut decoder = SensitiveIpcFrameDecoder::default();
    let mut decoded = decoder
        .push_bytes_zeroizing(bytes.as_mut_slice())
        .expect("regular frame accepted");
    assert!(bytes.iter().all(|byte| *byte == 0));

    let DecodedIpcFrame::Regular(frame) = decoded.remove(0) else {
        panic!("expected regular IPC frame");
    };
    assert_eq!(
        frame.message().expect("regular message remains typed"),
        IpcMessage::WorkerHello {
            process_id: 42,
            session_id: 7,
        }
    );
}
