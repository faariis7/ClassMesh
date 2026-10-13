//! Inactive future-v12 sensitive Worker→Service Named Pipe address only.
//!
//! The address MUST NOT be treated as proof of peer identity, authentication,
//! authorization, or a bearer secret. A future Windows caller must create a
//! separate ACL-restricted LOCAL pipe and independently attest the OS peer
//! process/session, Worker incarnation, authenticated control and read grants.

/// Non-secret identity fields that make the sensitive pipe name disjoint for
/// each Worker incarnation and for each authorized control request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitivePipeNameBinding {
    pub service_process_id: u32,
    pub worker_session_id: u32,
    pub worker_generation: u64,
    pub control_session_id: u64,
    pub control_sequence: u64,
    pub request_id: u64,
}

impl SensitivePipeNameBinding {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.service_process_id != 0
            && self.worker_session_id != 0
            && self.worker_generation != 0
            && self.control_session_id != 0
            && self.control_sequence != 0
            && self.request_id != 0
    }
}

/// Returns a bounded, deterministic pipe *address*, never an authorization
/// token. An unbound request cannot be used to allocate a sensitive pipe.
/// Does not open, listen on or connect to a Windows pipe.
#[must_use]
pub fn sensitive_worker_pipe_name(identity: SensitivePipeNameBinding) -> Option<String> {
    if !identity.is_valid() {
        return None;
    }
    Some(format!(
        "ClassMesh-Sensitive-v12-{service:08x}-{session:08x}-{generation:016x}-{control:016x}-{sequence:016x}-{request:016x}",
        service = identity.service_process_id,
        session = identity.worker_session_id,
        generation = identity.worker_generation,
        control = identity.control_session_id,
        sequence = identity.control_sequence,
        request = identity.request_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SensitivePipeNameBinding {
        SensitivePipeNameBinding {
            service_process_id: 0x1234,
            worker_session_id: 7,
            worker_generation: 9,
            control_session_id: 10,
            control_sequence: 11,
            request_id: 12,
        }
    }

    fn admission() -> SensitivePipeAdmission {
        SensitivePipeAdmission::register(binding(), binding(), 77, 0x1234)
            .expect("exact service and Worker incarnation")
    }

    #[test]
    fn sensitive_admission_accepts_only_exact_os_worker_peer() {
        let gate = admission();
        assert_eq!(
            gate.pipe_name(),
            sensitive_worker_pipe_name(binding()).expect("valid name"),
        );
        assert_eq!(gate.validate_os_peer(binding(), 0x1234, 77, 7), Ok(()));
        assert_eq!(
            gate.validate_os_peer(binding(), 0x1234, 78, 7),
            Err(SensitivePipeAdmissionError::UnexpectedWorkerPeer),
        );
        assert_eq!(
            gate.validate_os_peer(binding(), 0x1234, 77, 8),
            Err(SensitivePipeAdmissionError::UnexpectedWorkerPeer),
        );
    }

    #[test]
    fn sensitive_admission_refuses_missing_expected_or_current_identity() {
        for expected in [
            SensitivePipeNameBinding { service_process_id: 0, ..binding() },
            SensitivePipeNameBinding { worker_generation: 0, ..binding() },
            SensitivePipeNameBinding { control_session_id: 0, ..binding() },
            SensitivePipeNameBinding { control_sequence: 0, ..binding() },
            SensitivePipeNameBinding { request_id: 0, ..binding() },
        ] {
            assert_eq!(
                SensitivePipeAdmission::register(expected, expected, 77, 0x1234).err(),
                Some(SensitivePipeAdmissionError::InvalidIdentity),
            );
        }
        assert_eq!(
            SensitivePipeAdmission::register(binding(), binding(), 0, 0x1234).err(),
            Some(SensitivePipeAdmissionError::InvalidIdentity),
        );
        assert_eq!(
            SensitivePipeAdmission::register(binding(), binding(), 77, 0).err(),
            Some(SensitivePipeAdmissionError::ServiceProcessChanged),
        );
        assert_eq!(
            SensitivePipeAdmission::register(binding(), binding(), 77, 0x1235).err(),
            Some(SensitivePipeAdmissionError::ServiceProcessChanged),
        );
    }

    #[test]
    fn sensitive_admission_denies_replaced_worker_or_control_request() {
        let gate = admission();
        for changed in [
            SensitivePipeNameBinding { service_process_id: 9, ..binding() },
            SensitivePipeNameBinding { worker_session_id: 9, ..binding() },
            SensitivePipeNameBinding { worker_generation: 10, ..binding() },
            SensitivePipeNameBinding { control_session_id: 10 + 1, ..binding() },
            SensitivePipeNameBinding { control_sequence: 11 + 1, ..binding() },
            SensitivePipeNameBinding { request_id: 12 + 1, ..binding() },
        ] {
            assert_eq!(
                gate.validate_os_peer(changed, 0x1234, 77, 7),
                Err(SensitivePipeAdmissionError::BindingChanged),
            );
            assert_eq!(
                SensitivePipeAdmission::register(binding(), changed, 77, 0x1234).err(),
                Some(SensitivePipeAdmissionError::BindingChanged),
            );
        }
        assert_eq!(
            gate.validate_os_peer(binding(), 0x1235, 77, 7),
            Err(SensitivePipeAdmissionError::ServiceProcessChanged),
        );
    }

    #[test]
    fn sensitive_pipe_has_independent_bounded_namespace_and_stable_identity() {
        let name = sensitive_worker_pipe_name(binding()).expect("valid identity");
        assert_eq!(
            name,
            "ClassMesh-Sensitive-v12-00001234-00000007-0000000000000009-000000000000000a-000000000000000b-000000000000000c"
        );
        assert!(name.is_ascii());
        assert!(name.len() < 128);
        assert!(!name.starts_with("ClassMesh-00001234-"));
    }

    #[test]
    fn every_worker_and_control_binding_dimension_gets_a_distinct_path() {
        let baseline = sensitive_worker_pipe_name(binding()).expect("baseline");
        for changed in [
            SensitivePipeNameBinding {
                service_process_id: 8,
                ..binding()
            },
            SensitivePipeNameBinding {
                worker_session_id: 8,
                ..binding()
            },
            SensitivePipeNameBinding {
                worker_generation: 8,
                ..binding()
            },
            SensitivePipeNameBinding {
                control_session_id: 8,
                ..binding()
            },
            SensitivePipeNameBinding {
                control_sequence: 8,
                ..binding()
            },
            SensitivePipeNameBinding {
                request_id: 8,
                ..binding()
            },
        ] {
            assert_ne!(
                sensitive_worker_pipe_name(changed).expect("valid"),
                baseline
            );
        }
    }

    #[test]
    fn zero_or_unbound_component_is_denied_without_a_pipe_name() {
        for invalid in [
            SensitivePipeNameBinding {
                service_process_id: 0,
                ..binding()
            },
            SensitivePipeNameBinding {
                worker_session_id: 0,
                ..binding()
            },
            SensitivePipeNameBinding {
                worker_generation: 0,
                ..binding()
            },
            SensitivePipeNameBinding {
                control_session_id: 0,
                ..binding()
            },
            SensitivePipeNameBinding {
                control_sequence: 0,
                ..binding()
            },
            SensitivePipeNameBinding {
                request_id: 0,
                ..binding()
            },
        ] {
            assert_eq!(sensitive_worker_pipe_name(invalid), None);
        }
    }
}
