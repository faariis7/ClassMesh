//! Separate local telemetry pipe ADDRESS only. Naming is not authentication.
//! The privileged Service must verify the OS pipe peer, launched process,
//! current receiver incarnation and protected presentation grant before I/O.

/// Unique bounded local name per Service, Worker incarnation and receiver
/// incarnation. Never use the address as a credential or source of identity.
#[must_use]
pub fn receiver_telemetry_pipe_name(
    service_process_id: u32,
    worker_session_id: u32,
    worker_generation: u64,
    receiver_generation: u64,
) -> Option<String> {
    if service_process_id == 0
        || worker_session_id == 0
        || worker_generation == 0
        || receiver_generation == 0
    {
        return None;
    }
    Some(format!(
        "ClassMesh-Telemetry-{service_process_id:08x}-{worker_session_id:08x}-{worker_generation:016x}-{receiver_generation:016x}"
    ))
}

/// Service-owned expected process/Worker/receiver incarnation for one
/// throwaway diagnostics listener. Fields must come from the authenticated
/// Service runtime, NOT Worker bytes or a pipe path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryPipeIdentity {
    pub service_process_id: u32,
    pub worker_process_id: u32,
    pub worker_session_id: u32,
    pub worker_generation: u64,
    pub receiver_generation: u64,
}

impl TelemetryPipeIdentity {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.service_process_id != 0
            && self.worker_process_id != 0
            && self.worker_session_id != 0
            && self.worker_generation != 0
            && self.receiver_generation != 0
    }

    #[must_use]
    pub fn pipe_name(self) -> Option<String> {
        self.is_valid().then(|| {
            receiver_telemetry_pipe_name(
                self.service_process_id,
                self.worker_session_id,
                self.worker_generation,
                self.receiver_generation,
            )
            .expect("validated telemetry identity")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_receiver_and_worker_get_distinct_telemetry_pipe_addresses() {
        let a = receiver_telemetry_pipe_name(0x1234, 7, 9, 10).unwrap();
        assert_eq!(
            a,
            "ClassMesh-Telemetry-00001234-00000007-0000000000000009-000000000000000a"
        );
        assert_ne!(a, receiver_telemetry_pipe_name(0x1234, 7, 9, 11).unwrap());
        assert_ne!(a, receiver_telemetry_pipe_name(0x1234, 7, 10, 10).unwrap());
        assert_ne!(a, "ClassMesh-00001234-00000007-0000000000000009");
        assert!(!a.contains("Sensitive"));
    }

    #[test]
    fn invalid_unbound_pipe_names_are_rejected_before_allocation() {
        for (pid, session, worker, receiver) in
            [(0, 7, 9, 10), (2, 0, 9, 10), (2, 7, 0, 10), (2, 7, 9, 0)]
        {
            assert!(receiver_telemetry_pipe_name(pid, session, worker, receiver).is_none());
        }
    }
}
