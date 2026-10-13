//! Future-v12 dedicated sensitive channel allocation only. No secret I/O APIs.
//!
//! Creating this pipe does NOT authorize a Worker or negotiate v12. The caller
//! must separately verify the connected OS peer, launched Worker HANDLE,
//! trusted Service policy, current grant, replay binding and cancellation-safe
//! overlapped I/O before ever accepting a clipboard byte.

use crate::named_pipe::{NamedPipeServer, PipeError};
use crate::sensitive_pipe_name::SensitivePipeAdmission;

/// Owns an ACL-restricted, local-only, inbound-only, overlapped named-pipe
/// instance. Intentionally exposes NO connection, read or write methods.
#[derive(Debug)]
pub struct SensitivePipeListener {
    name: String,
    _owned_pipe: NamedPipeServer,
}

impl SensitivePipeListener {
    /// Only allocation is supported; authentication and I/O are future gates.
    pub fn create(
        admission: &SensitivePipeAdmission,
        user_sid: &[u8],
    ) -> Result<Self, PipeError> {
        let name = admission.pipe_name();
        let pipe = NamedPipeServer::create_sensitive_overlapped_for_user(&name, user_sid)?;
        Ok(Self {
            name,
            _owned_pipe: pipe,
        })
    }

    /// Address only, not a bearer secret or proof of peer identity.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.name
    }
}

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
        // SID header is present, but its declared subauthority array is not:
        // never hand this truncated buffer to an unchecked Win32 SID parser.
        let err = SensitivePipeListener::create(&expected, &[1, 15, 0, 0, 0, 0, 0, 0])
            .expect_err("truncated SID must fail before IsValidSid");
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
