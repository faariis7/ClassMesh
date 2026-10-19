//! Thin, typed mapping between the existing protected Worker presentation
//! IPC contracts and the Service-owned Phase 10 receiver lifetime ledger.
//! Does not register any IPC frame or authenticate its caller.
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryAuthorizedKey;
use classmesh_windows_runtime::ipc::{
    ServicePresentationMulticastStart, ServicePresentationUnicastStart,
    WorkerPresentationMulticastStartResult, WorkerPresentationMulticastStartStatus,
    WorkerPresentationUnicastStartResult, WorkerPresentationUnicastStartStatus,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

/// The protected key's grant ID is distinct from the subsequent stream-start
/// request ID and must be retained to reject stale clear/replacement events.
pub(crate) fn key_from_confirmed_grant(
    key: PresentationKeyInstallBinding,
) -> ReceiverTelemetryAuthorizedKey {
    ReceiverTelemetryAuthorizedKey {
        control_session_id: key.control_session_id,
        key_grant_request_id: key.request_id,
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        epoch: key.epoch,
    }
}

pub(crate) fn multicast_start_identity(
    start: ServicePresentationMulticastStart,
    owner: ReceiverTelemetryCurrentWorker,
    authorized: PresentationKeyInstallBinding,
) -> ReceiverTelemetryStart {
    ReceiverTelemetryStart {
        process_id: owner.process_id,
        session_id: owner.session_id,
        worker_generation: owner.worker_generation,
        control_session_id: start.control_session_id,
        request_id: start.request_id,
        presentation_id: start.presentation_id,
        stream_id: start.stream_id,
        epoch: authorized.epoch,
    }
}

pub(crate) fn unicast_start_identity(
    start: ServicePresentationUnicastStart,
    owner: ReceiverTelemetryCurrentWorker,
    authorized: PresentationKeyInstallBinding,
) -> ReceiverTelemetryStart {
    ReceiverTelemetryStart {
        process_id: owner.process_id,
        session_id: owner.session_id,
        worker_generation: owner.worker_generation,
        control_session_id: start.control_session_id,
        request_id: start.request_id,
        presentation_id: start.presentation_id,
        stream_id: start.stream_id,
        epoch: authorized.epoch,
    }
}

pub(crate) fn multicast_ack(
    result: WorkerPresentationMulticastStartResult,
) -> ReceiverTelemetryStartAck {
    ReceiverTelemetryStartAck {
        process_id: result.process_id,
        session_id: result.session_id,
        control_session_id: result.control_session_id,
        request_id: result.request_id,
        presentation_id: result.presentation_id,
        stream_id: result.stream_id,
        status: match result.status {
            WorkerPresentationMulticastStartStatus::Started => {
                ReceiverTelemetryStartAckStatus::Started
            }
            WorkerPresentationMulticastStartStatus::Rejected => {
                ReceiverTelemetryStartAckStatus::Rejected
            }
        },
    }
}

pub(crate) fn unicast_ack(
    result: WorkerPresentationUnicastStartResult,
) -> ReceiverTelemetryStartAck {
    ReceiverTelemetryStartAck {
        process_id: result.process_id,
        session_id: result.session_id,
        control_session_id: result.control_session_id,
        request_id: result.request_id,
        presentation_id: result.presentation_id,
        stream_id: result.stream_id,
        status: match result.status {
            WorkerPresentationUnicastStartStatus::Started => {
                ReceiverTelemetryStartAckStatus::Started
            }
            WorkerPresentationUnicastStartStatus::Rejected => {
                ReceiverTelemetryStartAckStatus::Rejected
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryServiceRuntime;
    use std::net::{IpAddr, Ipv4Addr};

    fn owner() -> ReceiverTelemetryCurrentWorker {
        ReceiverTelemetryCurrentWorker {
            process_id: 421,
            session_id: 3,
            worker_generation: 9,
        }
    }
    fn confirmed() -> PresentationKeyInstallBinding {
        PresentationKeyInstallBinding {
            control_session_id: 21,
            request_id: 32,
            presentation_id: 43,
            stream_id: 8,
            epoch: 14,
        }
    }

    #[test]
    fn multicast_grant_epoch_and_worker_generation_come_from_service_not_start_reply() {
        let key = confirmed();
        let start = ServicePresentationMulticastStart {
            control_session_id: key.control_session_id,
            request_id: 33,
            presentation_id: key.presentation_id,
            stream_id: key.stream_id,
            width: 1280,
            height: 720,
            fps: 20,
            bitrate_kbps: 3000,
            group: Ipv4Addr::new(239, 2, 3, 4),
            port: 49000,
            interface: Ipv4Addr::new(192, 0, 2, 1),
            teacher_source: Ipv4Addr::new(192, 0, 2, 2),
        };
        let reply = WorkerPresentationMulticastStartResult {
            process_id: owner().process_id,
            session_id: owner().session_id,
            control_session_id: start.control_session_id,
            request_id: start.request_id,
            presentation_id: start.presentation_id,
            stream_id: start.stream_id,
            status: WorkerPresentationMulticastStartStatus::Started,
        };
        let mut runtime = ReceiverTelemetryServiceRuntime::default();
        runtime
            .confirm_key_installed(key_from_confirmed_grant(key), owner())
            .unwrap();
        let pending = multicast_start_identity(start, owner(), key);
        assert_eq!(pending.worker_generation, 9);
        assert_eq!(pending.epoch, 14);
        assert_eq!(pending.request_id, 33);
        assert_ne!(pending.request_id, key.request_id);
        assert_eq!(
            runtime
                .activate_correlated_start(pending, owner(), multicast_ack(reply))
                .unwrap()
                .receiver_generation,
            1
        );
    }

    #[test]
    fn unicast_ack_rejection_never_allocates_receiver_generation() {
        let key = confirmed();
        let start = ServicePresentationUnicastStart {
            control_session_id: key.control_session_id,
            request_id: 44,
            presentation_id: key.presentation_id,
            stream_id: key.stream_id,
            width: 800,
            height: 600,
            fps: 15,
            bitrate_kbps: 1500,
            port: 49002,
            teacher_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        };
        let mut reply = WorkerPresentationUnicastStartResult {
            process_id: owner().process_id,
            session_id: owner().session_id,
            control_session_id: start.control_session_id,
            request_id: start.request_id,
            presentation_id: start.presentation_id,
            stream_id: start.stream_id,
            status: WorkerPresentationUnicastStartStatus::Rejected,
        };
        let mut runtime = ReceiverTelemetryServiceRuntime::default();
        runtime
            .confirm_key_installed(key_from_confirmed_grant(key), owner())
            .unwrap();
        let pending = unicast_start_identity(start, owner(), key);
        assert!(
            runtime
                .activate_correlated_start(pending, owner(), unicast_ack(reply))
                .is_err()
        );
        assert!(runtime.current().is_none());
        reply.status = WorkerPresentationUnicastStartStatus::Started;
        assert_eq!(
            runtime
                .activate_correlated_start(pending, owner(), unicast_ack(reply))
                .unwrap()
                .receiver_generation,
            1
        );
    }
}
