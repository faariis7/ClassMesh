//! Windows-only, two-process native named-pipe telemetry ingress qualification.
//! NOT production Worker/Service plumbing: only the real Windows process/session
//! peer attestation, OS pipe bytes, fixed decoder and Service admission are live.
//! There is NO new IPC message, nonblocking diagnostic sender, privilege, or
//! claimed Service-process-token attestation in this test.
#![cfg(windows)]

use std::mem::size_of;
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::ReceiverTelemetrySnapshot;
use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
};
use classmesh_control::receiver_telemetry_service_admission::ReceiverTelemetryServiceAdmissionError;
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime,
};
use classmesh_control::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, encode_receiver_telemetry,
};
use classmesh_win32::{NamedPipeClient, NamedPipeServer, current_session_id};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const CHILD_PIPE: &str = "CLASSMESH_PHASE10_NATIVE_PIPE";
const CHILD_WRONG_CLAIM: &str = "CLASSMESH_PHASE10_WRONG_PID_CLAIM";
static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

struct OwnedToken(HANDLE);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: an owned OS token returned by OpenProcessToken.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Get a test SID from the current Windows access token, not a caller
/// supplied name/pipe payload. The production Service obtains the intended
/// interactive SID independently as LocalSystem.
fn current_user_sid_for_test() -> Vec<u8> {
    let mut token = null_mut();
    // SAFETY: the pseudo-handle is valid and the output HANDLE is writable.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0,
        "native current Windows token must be readable"
    );
    let token = OwnedToken(token);
    let mut required = 0_u32;
    // SAFETY: zero-sized probe reports required bytes.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
    assert!(((size_of::<TOKEN_USER>() as u32)..=4096).contains(&required));
    let mut buffer = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
    // SAFETY: word-aligned buffer is large enough for TOKEN_USER.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        },
        0
    );
    // SAFETY: successful TokenUser call initialized the aligned storage.
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    assert_ne!(unsafe { IsValidSid(sid) }, 0);
    let len = unsafe { GetLengthSid(sid) };
    assert!((8..=4096).contains(&len));
    let mut copy = vec![0_u8; len as usize];
    // SAFETY: validated SID and writable destination of exact SID length.
    assert_ne!(unsafe { CopySid(len, copy.as_mut_ptr().cast(), sid) }, 0);
    copy
}

fn identity(process_id: u32, session_id: u32) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id,
        session_id,
        worker_generation: 42,
        control_session_id: 30,
        request_id: 91, // authorized media-start request
        presentation_id: 40,
        stream_id: 8,
        epoch: 2,
        receiver_generation: 1,
    }
}

/// Child entry point invoked by the parent using the standard Rust test runner.
/// Public test values only. It has no ability to mint Service authority.
#[test]
fn child_send_native_report() {
    let Ok(pipe_name) = std::env::var(CHILD_PIPE) else {
        return;
    };
    let session_id = current_session_id().expect("Windows child session");
    let mut owner = identity(std::process::id(), session_id);
    if std::env::var_os(CHILD_WRONG_CLAIM).is_some() {
        owner.process_id = owner.process_id.saturating_add(1);
    }
    let report = ReceiverTelemetrySnapshot {
        binding: owner,
        sequence: 1,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: 10,
            rejected_frames: 2,
            queue_drops: 3,
            ..Default::default()
        },
    };
    let pipe = NamedPipeClient::connect(&pipe_name, Duration::from_secs(3))
        .expect("native Worker child connects to local test Service");
    pipe.write_all(&encode_receiver_telemetry(&report).unwrap())
        .expect("native pipe writes one fixed-width report");
}

fn grant_service_for_real_peer(
    peer: ReceiverTelemetryCurrentWorker,
) -> ReceiverTelemetryServiceRuntime {
    let mut service = ReceiverTelemetryServiceRuntime::default();
    let key = ReceiverTelemetryAuthorizedKey {
        control_session_id: 30,
        key_grant_request_id: 51,
        presentation_id: 40,
        stream_id: 8,
        epoch: 2,
    };
    // Test-simulated *correlated* protected key + media-start acknowledgements.
    // In production these arrive from separately authenticated session events.
    service.confirm_key_installed(key, peer).unwrap();
    let start = ReceiverTelemetryStart {
        process_id: peer.process_id,
        session_id: peer.session_id,
        worker_generation: peer.worker_generation,
        control_session_id: key.control_session_id,
        request_id: 91,
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        epoch: key.epoch,
    };
    service
        .activate_correlated_start(
            start,
            peer,
            ReceiverTelemetryStartAck {
                process_id: peer.process_id,
                session_id: peer.session_id,
                control_session_id: start.control_session_id,
                request_id: start.request_id,
                presentation_id: start.presentation_id,
                stream_id: start.stream_id,
                status: ReceiverTelemetryStartAckStatus::Started,
            },
        )
        .unwrap();
    assert_eq!(
        service.current(),
        Some(identity(peer.process_id, peer.session_id))
    );
    service
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// This reads real Windows byte-mode pipe data, which may arrive in partial
/// chunks. It is run on a disposable test-only thread and NEVER on Worker
/// decode/render or privileged Service control loops.
fn receive_exact(mut pipe: NamedPipeServer, pid: u32, session_id: u32) -> (u32, u32, Vec<u8>) {
    let attested = pipe
        .accept_expected(pid, session_id)
        .expect("OS-observed child PID and Windows session match expected process");
    let mut bytes = [0_u8; RECEIVER_TELEMETRY_WIRE_LEN];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = pipe
            .read(&mut bytes[offset..])
            .expect("read native pipe data");
        assert_ne!(n, 0, "complete fixed-width native report required");
        offset += n;
    }
    let _ = pipe.disconnect();
    (attested.process_id(), attested.session_id(), bytes.to_vec())
}

fn run_native_pipe_case(wrong_claim: bool) {
    let session_id = current_session_id().expect("native Windows session");
    let name = format!(
        "ClassMesh-Phase10-NativeSmoke-{}-{}",
        std::process::id(),
        NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
    );
    let user_sid = current_user_sid_for_test();
    let server = NamedPipeServer::create_for_user(&name, &user_sid).expect("OS local DACL pipe");
    let (tx, rx) = mpsc::sync_channel(1);

    // Windows kernel verifies the distinct child process on accept. The
    // parent does not trust the process/session fields within report bytes.
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("child_send_native_report")
        .arg("--nocapture")
        .env(CHILD_PIPE, &name)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if wrong_claim {
        command.env(CHILD_WRONG_CLAIM, "1");
    }
    let mut child = ChildGuard(
        command
            .spawn()
            .expect("native separate Worker test process"),
    );
    let pid = child.0.id();
    let reader = std::thread::spawn(move || {
        let result = receive_exact(server, pid, session_id);
        let _ = tx.send(result);
    });
    let (observed_pid, observed_session, bytes) = rx
        .recv_timeout(Duration::from_secs(8))
        .expect("finite test deadline waiting for native OS pipe receiver");
    assert_eq!(observed_pid, pid, "OS pipe identity, never payload PID");
    assert_eq!(observed_session, session_id);

    let worker = ReceiverTelemetryCurrentWorker {
        process_id: observed_pid,
        session_id: observed_session,
        worker_generation: 42, // test-owned generation, not sent by pipe
    };
    let mut service = grant_service_for_real_peer(worker);
    let admitted = service.observe_after_verified_peer(worker, &bytes, Instant::now());
    if wrong_claim {
        assert!(
            matches!(
                admitted,
                Err(ReceiverTelemetryServiceAdmissionError::Ingress(_))
            ),
            "forged Worker-reported PID must not enter Service state"
        );
        assert!(!service.has_fresh_for_verified_peer(worker, Instant::now()));
    } else {
        assert_eq!(admitted, Ok(ReceiverTelemetryDecision::Baseline));
        assert!(service.has_fresh_for_verified_peer(worker, Instant::now()));
        service.worker_changed();
        assert_eq!(
            service.observe_after_verified_peer(worker, &bytes, Instant::now()),
            Err(ReceiverTelemetryServiceAdmissionError::NoActiveRuntime)
        );
    }
    reader.join().expect("native receiver thread completes");
    // Exit status proves the child successfully completed its real write;
    // otherwise do not let a partial/failed test masquerade as a pass.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(exit) = child.0.try_wait().expect("query native child exit") {
            assert!(exit.success(), "native Worker child exited unsuccessfully");
            break;
        }
        assert!(Instant::now() < deadline, "native child must terminate");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn native_separate_process_pipe_accepts_os_attested_worker_and_rejects_after_revoke() {
    run_native_pipe_case(false);
}

#[test]
fn native_pipe_os_peer_cannot_authorize_forged_report_process_identity() {
    run_native_pipe_case(true);
}
