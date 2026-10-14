//! Contract tests first: future v12 handshake proof, entirely inactive.
use super::clipboard_read_frame::CLIPBOARD_READ_SUCCESS_FUTURE_MINOR;
use super::clipboard_read_success::ClipboardReadSuccessBinding;
use super::clipboard_read_transport_gate::SensitiveReadGrants;
use super::v12_challenge::{
    SensitiveV12Challenge, SensitiveV12ChallengeError, V12LiveAuthority, compute_v12_challenge_mac,
};
use crate::ipc::IPC_VERSION_MAJOR;
use zeroize::Zeroizing;

const VERSION: (u8, u8) = (IPC_VERSION_MAJOR, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR);
const START: u64 = 1_000;

fn binding() -> ClipboardReadSuccessBinding {
    ClipboardReadSuccessBinding {
        worker_process_id: 42,
        worker_session_id: 7,
        worker_generation: 4,
        control_session_id: 77,
        control_sequence: 101,
        request_id: 19,
    }
}
fn grants() -> SensitiveReadGrants {
    SensitiveReadGrants {
        clipboard_capability: true,
        read_permission: true,
    }
}
fn key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0xA5; 32])
}
fn pending() -> SensitiveV12Challenge {
    SensitiveV12Challenge::issue(key(), binding(), START).expect("trusted request")
}
fn proof(
    p: &SensitiveV12Challenge,
    secret: &[u8; 32],
    version: (u8, u8),
    id: ClipboardReadSuccessBinding,
) -> [u8; 32] {
    compute_v12_challenge_mac(secret, &p.nonce().expect("pending nonce"), version, id)
}
fn live(
    id: ClipboardReadSuccessBinding,
    permissions: SensitiveReadGrants,
) -> Option<V12LiveAuthority> {
    Some(V12LiveAuthority {
        binding: id,
        grants: permissions,
    })
}

#[test]
fn authentic_exact_request_is_single_use_and_fresh_service_nonces_differ() {
    let mut p = pending();
    let second = pending();
    assert_ne!(p.nonce(), second.nonce(), "service must use OS CSPRNG");
    let mac = proof(&p, &key(), VERSION, binding());
    assert_eq!(
        p.verify(&mac, VERSION, START + 1, || live(binding(), grants())),
        Ok(())
    );
    assert_eq!(p.nonce(), None);
    assert_eq!(
        p.verify(&mac, VERSION, START + 2, || live(binding(), grants())),
        Err(SensitiveV12ChallengeError::AlreadyUsed)
    );
}

#[test]
fn wrong_key_or_mac_poison_challenge_permanently() {
    let mut p = pending();
    let wrong = [0xAA; 32];
    let mac = proof(&p, &wrong, VERSION, binding());
    assert_eq!(
        p.verify(&mac, VERSION, START + 1, || live(binding(), grants())),
        Err(SensitiveV12ChallengeError::InvalidProof)
    );
    let valid_mac =
        compute_v12_challenge_mac(&key(), &p.nonce().unwrap_or([0x00; 32]), VERSION, binding());
    assert_ne!(mac, valid_mac);
    assert_eq!(
        p.verify(&mac, VERSION, START + 2, || live(binding(), grants())),
        Err(SensitiveV12ChallengeError::AlreadyUsed)
    );
}

#[test]
fn downgrade_and_unexpected_version_fail_closed() {
    for version in [
        (IPC_VERSION_MAJOR, 11),
        (IPC_VERSION_MAJOR + 1, CLIPBOARD_READ_SUCCESS_FUTURE_MINOR),
    ] {
        let mut p = pending();
        let mac = proof(&p, &key(), version, binding());
        assert_eq!(
            p.verify(&mac, version, START + 1, || live(binding(), grants())),
            Err(SensitiveV12ChallengeError::WrongVersion)
        );
        assert_eq!(p.nonce(), None);
    }
}

#[test]
fn every_worker_and_control_field_is_bound_to_the_proof() {
    let current = binding();
    let changed = [
        ClipboardReadSuccessBinding {
            worker_process_id: 43,
            ..current
        },
        ClipboardReadSuccessBinding {
            worker_session_id: 8,
            ..current
        },
        ClipboardReadSuccessBinding {
            worker_generation: 5,
            ..current
        },
        ClipboardReadSuccessBinding {
            control_session_id: 78,
            ..current
        },
        ClipboardReadSuccessBinding {
            control_sequence: 102,
            ..current
        },
        ClipboardReadSuccessBinding {
            request_id: 20,
            ..current
        },
    ];
    for mismatch in changed {
        let mut p = pending();
        let mac = proof(&p, &key(), VERSION, current);
        assert_eq!(
            p.verify(&mac, VERSION, START + 1, || live(mismatch, grants())),
            Err(SensitiveV12ChallengeError::BindingChanged)
        );
        assert_eq!(p.nonce(), None);
    }
}

#[test]
fn unavailable_current_policy_and_each_missing_grant_fail_closed() {
    let valid_grants = grants();
    for policy in [
        None,
        live(
            binding(),
            SensitiveReadGrants {
                clipboard_capability: false,
                ..valid_grants
            },
        ),
        live(
            binding(),
            SensitiveReadGrants {
                read_permission: false,
                ..valid_grants
            },
        ),
    ] {
        let mut p = pending();
        let mac = proof(&p, &key(), VERSION, binding());
        let error = if policy.is_none() {
            SensitiveV12ChallengeError::CurrentAuthorityUnavailable
        } else {
            SensitiveV12ChallengeError::NotAuthorized
        };
        assert_eq!(p.verify(&mac, VERSION, START + 1, || policy), Err(error));
        assert_eq!(p.nonce(), None);
    }
}

#[test]
fn expired_regressed_and_cancelled_operations_never_accept() {
    for (time, error) in [
        (START - 1, SensitiveV12ChallengeError::ClockRegression),
        (START + 2_500, SensitiveV12ChallengeError::Expired),
    ] {
        let mut p = pending();
        let mac = proof(&p, &key(), VERSION, binding());
        assert_eq!(
            p.verify(&mac, VERSION, time, || live(binding(), grants())),
            Err(error)
        );
    }
    let mut p = pending();
    let mac = proof(&p, &key(), VERSION, binding());
    assert!(p.cancel());
    assert!(!p.cancel());
    assert_eq!(
        p.verify(&mac, VERSION, START + 1, || live(binding(), grants())),
        Err(SensitiveV12ChallengeError::AlreadyUsed)
    );
}

#[test]
fn invalid_binding_or_zero_secret_is_rejected_and_debug_never_exposes_secrets() {
    let mut bad = binding();
    bad.request_id = 0;
    assert_eq!(
        SensitiveV12Challenge::issue(key(), bad, START).err(),
        Some(SensitiveV12ChallengeError::InvalidBinding)
    );
    assert_eq!(
        SensitiveV12Challenge::issue(Zeroizing::new([0; 32]), binding(), START).err(),
        Some(SensitiveV12ChallengeError::InvalidKey)
    );
    assert_eq!(
        SensitiveV12Challenge::issue(key(), binding(), u64::MAX).err(),
        Some(SensitiveV12ChallengeError::ClockOverflow)
    );
    let p = pending();
    let debug = format!("{p:?}");
    assert!(!debug.contains("a5a5"));
    assert!(!debug.contains("nonce"));
    assert!(!debug.contains("key"));
}
#[test]
fn cryptographic_transcript_rejects_a_different_binding_or_challenge() {
    let mut first = pending();
    let mut second = pending();
    let mut changed = binding();
    changed.request_id += 1;
    let first_nonce = first.nonce().expect("first challenge");
    let changed_binding_mac = proof(&first, &key(), VERSION, changed);
    assert_eq!(
        first.verify(&changed_binding_mac, VERSION, START + 1, || live(
            binding(),
            grants()
        )),
        Err(SensitiveV12ChallengeError::InvalidProof)
    );
    let cross_request_mac = compute_v12_challenge_mac(&key(), &first_nonce, VERSION, binding());
    // A separately issued Service request must never accept the old proof.
    assert_eq!(
        second.verify(&cross_request_mac, VERSION, START + 1, || live(
            binding(),
            grants()
        )),
        Err(SensitiveV12ChallengeError::InvalidProof)
    );
}
#[test]
fn no_response_expiry_clears_pending_nonce_without_waiting_for_a_proof() {
    let mut p = pending();
    assert!(!p.expire(START + 2_499));
    assert!(p.nonce().is_some());
    assert!(p.expire(START + 2_500));
    assert_eq!(p.nonce(), None);
    assert!(!p.expire(START + 2_501));
    assert_eq!(
        p.verify(&[0; 32], VERSION, START + 2_501, || live(binding(), grants())),
        Err(SensitiveV12ChallengeError::AlreadyUsed)
    );

    let mut p = pending();
    assert!(p.expire(START - 1), "regressed monotonic clock poisons a challenge");
    assert_eq!(p.nonce(), None);
}
