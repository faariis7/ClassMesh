//! Thin, typed mapping between the existing protected Worker presentation
//! IPC contracts and the Service-owned Phase 10 receiver lifetime ledger.
//! Does not register any IPC frame or authenticate its caller.
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime,
    ReceiverTelemetryServiceStreamError,
};
use classmesh_windows_runtime::ipc::{
    ServicePresentationMulticastStart, ServicePresentationUnicastStart,
    WorkerPresentationMulticastStartResult, WorkerPresentationMulticastStartStatus,
    WorkerPresentationUnicastStartResult, WorkerPresentationUnicastStartStatus,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use std::time::Instant;

/// Service-owned 250ms Worker liveness poll hook, called only after the
/// authoritative WorkerManager has refreshed the actual launched process and
/// authenticated pipe generation. Expire any outstanding incomplete receiver
/// telemetry even if no further bytes arrive. Do not derive peer identity
/// from media bytes or from a Worker-reported PID.
///
/// No receiver has yet been authorized during normal startup => no-op. A
/// missing authenticated Worker immediately retires any stale grant. Stale
/// peer candidates cannot consume or cancel a replacement receiver.
pub(crate) fn service_receiver_telemetry_poll_tick(
    runtime: &mut ReceiverTelemetryServiceRuntime,
    worker: Option<ReceiverTelemetryCurrentWorker>,
    service_now: Instant,
) -> Result<(), ReceiverTelemetryServiceStreamError> {
    let Some(worker) = worker else {
        runtime.worker_changed();
        return Ok(());
    };
    match runtime.expire_partial_stream_after_verified_peer(worker, service_now) {
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized) => Ok(()),
        result => result,
    }
}

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

    fn armed_telemetry() -> ReceiverTelemetryServiceRuntime {
        let key = confirmed();
        let mut runtime = ReceiverTelemetryServiceRuntime::default();
        runtime
            .confirm_key_installed(key_from_confirmed_grant(key), owner())
            .unwrap();
        runtime
            .activate_correlated_start(
                ReceiverTelemetryStart {
                    process_id: owner().process_id,
                    session_id: owner().session_id,
                    worker_generation: owner().worker_generation,
                    control_session_id: key.control_session_id,
                    request_id: 33,
                    presentation_id: key.presentation_id,
                    stream_id: key.stream_id,
                    epoch: key.epoch,
                },
                owner(),
                ReceiverTelemetryStartAck {
                    process_id: owner().process_id,
                    session_id: owner().session_id,
                    control_session_id: key.control_session_id,
                    request_id: 33,
                    presentation_id: key.presentation_id,
                    stream_id: key.stream_id,
                    status: ReceiverTelemetryStartAckStatus::Started,
                },
            )
            .unwrap();
        runtime
    }

    #[test]
    fn authenticated_service_worker_poll_expires_idle_partial_and_key() {
        use classmesh_control::receiver_telemetry_service_runtime::ReceiverTelemetryServiceStreamError;
        use classmesh_control::receiver_telemetry_stream_framing::{
            MAX_RECEIVER_TELEMETRY_PARTIAL_AGE, ReceiverTelemetryFrameStreamError,
        };
        use std::time::{Duration, Instant};
        let mut runtime = armed_telemetry();
        let at = Instant::now();
        assert_eq!(
            runtime.observe_stream_chunk_after_verified_peer(owner(), &[42], at),
            Ok(None)
        );
        assert_eq!(
            service_receiver_telemetry_poll_tick(
                &mut runtime,
                Some(owner()),
                at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE
            ),
            Ok(())
        );
        assert_eq!(
            service_receiver_telemetry_poll_tick(
                &mut runtime,
                Some(owner()),
                at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE + Duration::from_nanos(1)
            ),
            Err(ReceiverTelemetryServiceStreamError::Framing(
                ReceiverTelemetryFrameStreamError::PartialTimedOut
            ))
        );
        assert!(runtime.current().is_none());
        assert!(runtime.worker_grant_after_verified_peer(owner()).is_none());
    }

    #[test]
    fn poll_without_authenticated_worker_revokes_current_telemetry() {
        use std::time::Instant;
        let mut runtime = armed_telemetry();
        assert!(runtime.current().is_some());
        assert_eq!(
            service_receiver_telemetry_poll_tick(&mut runtime, None, Instant::now()),
            Ok(())
        );
        assert!(runtime.current().is_none());
        assert!(runtime.worker_grant_after_verified_peer(owner()).is_none());
    }

    #[test]
    fn old_worker_poll_cannot_expire_an_authorized_successor() {
        use std::time::{Duration, Instant};
        let mut runtime = armed_telemetry();
        let at = Instant::now();
        assert_eq!(
            runtime.observe_stream_chunk_after_verified_peer(owner(), &[42], at),
            Ok(None)
        );
        let mut old = owner();
        old.worker_generation -= 1;
        assert_eq!(
            service_receiver_telemetry_poll_tick(
                &mut runtime,
                Some(old),
                at + Duration::from_secs(10)
            ),
            Ok(())
        );
        assert!(runtime.current().is_some());
        assert_eq!(service_receiver_telemetry_poll_tick(&mut runtime, Some(owner()), at + Duration::from_secs(10)),
            Err(ReceiverTelemetryServiceStreamError::Framing(
                classmesh_control::receiver_telemetry_stream_framing::ReceiverTelemetryFrameStreamError::PartialTimedOut
            ))
        );
    }
}
