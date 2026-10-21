//! Best-effort telemetry sender on a separate thread. Never touch the
//! privileged blocking Worker→Service control pipe with report bytes.
//!
//! A grant is accepted only from the already-authenticated primary IPC
//! and is revalidated against the current installed key, media start,
//! independently reported OS Service PID, Worker PID and Windows session.

use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_transport::encode_receiver_telemetry;
use classmesh_win32::{ReceiverTelemetryPipeClient, telemetry_pipe_name::TelemetryPipeIdentity};
use classmesh_windows_runtime::ipc::ServiceReceiverTelemetryGrant;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use classmesh_worker::presentation_delivery_telemetry::PresentationDeliveryReport;

#[must_use]
pub(crate) fn grant_matches_current_receiver(
    grant: ServiceReceiverTelemetryGrant,
    os_primary_service_pid: u32,
    own_pid: u32,
    own_session: u32,
    key: Option<PresentationKeyInstallBinding>,
    current_start_id: Option<u64>,
) -> bool {
    let Some(key) = key else {
        return false;
    };
    grant.is_valid()
        && grant.service_process_id == os_primary_service_pid
        && grant.worker_process_id == own_pid
        && grant.worker_session_id == own_session
        && grant.control_session_id == key.control_session_id
        && grant.presentation_id == key.presentation_id
        && grant.stream_id == key.stream_id
        && grant.epoch == key.epoch
        && current_start_id == Some(grant.start_request_id)
        // A grant/install id is NOT the media start request id.
        && grant.start_request_id != key.request_id
}

pub(crate) struct BestEffortReceiverSender {
    grant: ServiceReceiverTelemetryGrant,
    outbox: SyncSender<[u8; 136]>,
}

impl BestEffortReceiverSender {
    /// The isolated diagnostics thread owns all slow native operations.
    /// Caller only constructs exact credentials/identity and a one-slot
    /// nonblocking mailbox; any connect/write failure drops this incarnation.
    pub(crate) fn start(
        grant: ServiceReceiverTelemetryGrant,
        os_primary_service_pid: u32,
        own_pid: u32,
        own_session: u32,
        key: Option<PresentationKeyInstallBinding>,
        current_start_id: Option<u64>,
    ) -> Result<Self, &'static str> {
        if !grant_matches_current_receiver(
            grant,
            os_primary_service_pid,
            own_pid,
            own_session,
            key,
            current_start_id,
        ) {
            return Err("WorkerTelemetryGrantMismatch");
        }
        let identity = TelemetryPipeIdentity {
            service_process_id: grant.service_process_id,
            worker_process_id: grant.worker_process_id,
            worker_session_id: grant.worker_session_id,
            worker_generation: grant.worker_generation,
            receiver_generation: grant.receiver_generation,
        };
        let (outbox, rx) = mpsc::sync_channel::<[u8; 136]>(1);
        thread::Builder::new()
            .name("classmesh-phase10-telemetry-sender".to_owned())
            .spawn(move || {
                let Ok(mut pipe) =
                    ReceiverTelemetryPipeClient::connect_from_verified_service(identity)
                else {
                    return;
                };
                while let Ok(frame) = rx.recv() {
                    if pipe.send_once(&frame, Duration::from_millis(250)).is_err() {
                        return;
                    }
                }
            })
            .map_err(|_| "WorkerTelemetrySenderSpawnFailed")?;
        Ok(Self { grant, outbox })
    }

    /// Derive a real counter snapshot only from the unique locally active
    /// healthy renderer and installed protected key. Never retry a full
    /// mailbox; a dropped interval must trigger rebaseline at the Service.
    pub(crate) fn offer(
        &self,
        report: PresentationDeliveryReport,
        installed_key: PresentationKeyInstallBinding,
        current_start_id: Option<u64>,
        os_primary_service_pid: u32,
        own_pid: u32,
        own_session: u32,
    ) -> Result<bool, &'static str> {
        let grant = self.grant;
        if !grant_matches_current_receiver(
            grant,
            os_primary_service_pid,
            own_pid,
            own_session,
            Some(installed_key),
            current_start_id,
        ) {
            return Err("WorkerTelemetryReportNoLongerAuthorized");
        }
        let binding = ReceiverTelemetryBinding {
            process_id: grant.worker_process_id,
            session_id: grant.worker_session_id,
            worker_generation: grant.worker_generation,
            control_session_id: grant.control_session_id,
            request_id: grant.start_request_id,
            presentation_id: grant.presentation_id,
            stream_id: grant.stream_id,
            epoch: grant.epoch,
            receiver_generation: grant.receiver_generation,
        };
        let snapshot = report
            .snapshot_for_authorized_start(binding, installed_key, grant.start_request_id)
            .ok_or("WorkerTelemetrySnapshotNoLongerAuthorized")?;
        let frame =
            encode_receiver_telemetry(&snapshot).map_err(|_| "WorkerTelemetryEncodeInvalid")?;
        match self.outbox.try_send(frame) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => Err("WorkerTelemetrySenderDisconnected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PresentationKeyInstallBinding {
        PresentationKeyInstallBinding {
            control_session_id: 11,
            request_id: 12,
            presentation_id: 13,
            stream_id: 14,
            epoch: 15,
        }
    }
    fn grant() -> ServiceReceiverTelemetryGrant {
        ServiceReceiverTelemetryGrant {
            service_process_id: 23,
            worker_process_id: 25,
            worker_session_id: 27,
            worker_generation: 29,
            receiver_generation: 31,
            control_session_id: 11,
            start_request_id: 22,
            presentation_id: 13,
            stream_id: 14,
            epoch: 15,
        }
    }

    #[test]
    fn native_sender_cannot_start_from_forged_service_pid_key_or_start() {
        assert!(grant_matches_current_receiver(
            grant(),
            23,
            25,
            27,
            Some(key()),
            Some(22)
        ));
        for (service, pid, sess, start) in [
            (999, 25, 27, Some(22)),
            (23, 999, 27, Some(22)),
            (23, 25, 999, Some(22)),
            (23, 25, 27, Some(12)),
            (23, 25, 27, None),
        ] {
            assert!(!grant_matches_current_receiver(
                grant(),
                service,
                pid,
                sess,
                Some(key()),
                start,
            ));
        }
        assert!(!grant_matches_current_receiver(
            grant(),
            23,
            25,
            27,
            None,
            Some(22),
        ));
        let mut old_key = key();
        old_key.epoch += 1;
        assert!(!grant_matches_current_receiver(
            grant(),
            23,
            25,
            27,
            Some(old_key),
            Some(22),
        ));
        let mut malformed = grant();
        malformed.receiver_generation = 0;
        assert!(!grant_matches_current_receiver(
            malformed,
            23,
            25,
            27,
            Some(key()),
            Some(22),
        ));
    }
}
