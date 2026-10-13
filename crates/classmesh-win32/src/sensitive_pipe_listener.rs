//! Future-v12 dedicated sensitive channel allocation only. No secret I/O APIs.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensitive_pipe_name::SensitivePipeNameBinding;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };
    use std::ptr::null_mut;

    fn system_sid() -> Vec<u8> {
        let mut sid = vec![0; SECURITY_MAX_SID_SIZE as usize];
        let mut size = u32::try_from(sid.len()).expect("known SID size");
        // SAFETY: buffer and length are valid; this returns a Windows-defined SID.
        assert_ne!(
            unsafe { CreateWellKnownSid(WinLocalSystemSid, null_mut(), sid.as_mut_ptr().cast(), &mut size) },
            0,
        );
        sid.truncate(size as usize);
        sid
    }

    fn admission() -> SensitivePipeAdmission {
        let identity = SensitivePipeNameBinding {
            service_process_id: std::process::id(),
            worker_session_id: 42,
            worker_generation: 7,
            control_session_id: 4,
            control_sequence: 5,
            request_id: 6,
        };
        SensitivePipeAdmission::register(identity, identity, 77, std::process::id())
            .expect("current exact identity")
    }

    #[test]
    fn rejects_untrusted_or_missing_user_sid_before_sensitive_allocation() {
        let expected = admission();
        let err = SensitivePipeListener::create(&expected, &[])
            .expect_err("empty SID must fail closed");
        assert_eq!(err.stage, "NamedPipeUserSidValidation");
        let err = SensitivePipeListener::create(&expected, &[1, 2, 3])
            .expect_err("invalid SID must fail closed");
        assert_eq!(err.stage, "NamedPipeUserSidValidation");
    }

    #[test]
    fn bound_sensitive_pipe_is_one_local_instance_and_does_not_expose_io() {
        let expected = admission();
        let sid = system_sid();
        let first = SensitivePipeListener::create(&expected, &sid)
            .expect("OS can create one isolated sensitive pipe");
        assert_eq!(first.pipe_name(), expected.pipe_name());
        assert!(first.pipe_name().starts_with("ClassMesh-Sensitive-v12-"));
        let duplicate = SensitivePipeListener::create(&expected, &sid);
        assert!(duplicate.is_err(), "first-instance restriction must reject second creation");
    }
}
