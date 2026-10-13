//! Pure, platform-independent tests for an inactive future-v12 sensitive pipe namespace.
//! Names are discoverable addresses, NEVER authentication tokens.

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
            SensitivePipeNameBinding { service_process_id: 8, ..binding() },
            SensitivePipeNameBinding { worker_session_id: 8, ..binding() },
            SensitivePipeNameBinding { worker_generation: 8, ..binding() },
            SensitivePipeNameBinding { control_session_id: 8, ..binding() },
            SensitivePipeNameBinding { control_sequence: 8, ..binding() },
            SensitivePipeNameBinding { request_id: 8, ..binding() },
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
            SensitivePipeNameBinding { service_process_id: 0, ..binding() },
            SensitivePipeNameBinding { worker_session_id: 0, ..binding() },
            SensitivePipeNameBinding { worker_generation: 0, ..binding() },
            SensitivePipeNameBinding { control_session_id: 0, ..binding() },
            SensitivePipeNameBinding { control_sequence: 0, ..binding() },
            SensitivePipeNameBinding { request_id: 0, ..binding() },
        ] {
            assert_eq!(sensitive_worker_pipe_name(invalid), None);
        }
    }
}
