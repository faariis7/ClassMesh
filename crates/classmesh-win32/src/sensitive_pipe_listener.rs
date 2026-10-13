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
    pub fn create(admission: &SensitivePipeAdmission, user_sid: &[u8]) -> Result<Self, PipeError> {
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
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };

    fn system_sid() -> Vec<u8> {
        let mut sid = vec![0; SECURITY_MAX_SID_SIZE as usize];
        let mut size = u32::try_from(sid.len()).expect("known SID size");
        // SAFETY: buffer and length are valid; this returns a Windows-defined SID.
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinLocalSystemSid,
                    null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut size,
                )
            },
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
        let err =
            SensitivePipeListener::create(&expected, &[]).expect_err("empty SID must fail closed");
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
    fn sensitive_accept_rejects_invalid_deadlines_without_starting_io() {
        let listener = SensitivePipeListener::create(&admission(), &system_sid())
            .expect("test listener");
        let mut listener = listener;
        let err = listener.wait_for_os_peer(std::time::Duration::from_millis(2_501))
            .expect_err("deadline over 2500ms must fail closed");
        assert_eq!(err.stage, "SensitivePipeConnectDeadline");
        let err = listener.wait_for_os_peer(std::time::Duration::ZERO)
            .expect_err("zero duration is not a valid deadline");
        assert_eq!(err.stage, "SensitivePipeConnectDeadline");
    }

    #[test]
    fn sensitive_accept_cancels_pending_overlapped_connection_on_deadline() {
        let mut listener = SensitivePipeListener::create(&admission(), &system_sid())
            .expect("local sensitive pipe");
        let start = std::time::Instant::now();
        let err = listener.wait_for_os_peer(std::time::Duration::from_millis(75))
            .expect_err("no client must result in a cancelled operation");
        assert_eq!(err.stage, "SensitivePipeConnectTimeout");
        assert!(start.elapsed() < std::time::Duration::from_secs(3),
            "cancellation must drain promptly under healthy Windows");
        drop(listener); // no kernel operation may still borrow OVERLAPPED here
    }

    #[test]
    fn overlapped_sensitive_connect_returns_os_reported_local_client() {
        use windows_sys::Win32::Security::WinAuthenticatedUserSid;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING,
        };
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE};

        // A group SID is used only in this throwaway localhost unit test so
        // the current unprivileged test process may also connect as client.
        let mut test_sid = vec![0; SECURITY_MAX_SID_SIZE as usize];
        let mut size = test_sid.len() as u32;
        assert_ne!(unsafe {
            CreateWellKnownSid(
                WinAuthenticatedUserSid, null_mut(), test_sid.as_mut_ptr().cast(), &mut size,
            )
        }, 0);
        test_sid.truncate(size as usize);

        let mut listener = SensitivePipeListener::create(&admission(), &test_sid)
            .expect("create temporary test-only local listener");
        let full = format!(r"\\.\pipe\{}", listener.pipe_name());
        let client = std::thread::spawn(move || {
            use std::os::windows::ffi::OsStrExt;
            let name: Vec<u16> = std::ffi::OsStr::new(&full)
                .encode_wide().chain(std::iter::once(0)).collect();
            std::thread::sleep(std::time::Duration::from_millis(20));
            let handle = unsafe {
                CreateFileW(name.as_ptr(), GENERIC_WRITE, FILE_SHARE_NONE,
                            std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut())
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE, "test client must connect");
            std::thread::sleep(std::time::Duration::from_millis(60));
            assert_ne!(unsafe { CloseHandle(handle) }, 0);
        });
        let peer = listener.wait_for_os_peer(std::time::Duration::from_secs(2))
            .expect("client connected before deadline");
        assert_eq!(peer.process_id(), std::process::id());
        assert_eq!(peer.session_id(), crate::current_session_id().expect("Windows session"));
        client.join().expect("test client");
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
        assert!(
            duplicate.is_err(),
            "first-instance restriction must reject second creation"
        );
    }
}
