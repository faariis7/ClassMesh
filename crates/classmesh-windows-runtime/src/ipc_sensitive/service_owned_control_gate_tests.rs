//! TDD first: intentionally RED until the inert Service-owned policy gate exists.
use super::clipboard_read_success::ClipboardReadSuccessBinding;
use super::clipboard_read_transport_gate::SensitiveReadGrants;
use super::service_owned_control_gate::{
    LiveServiceReadState, MAX_POLICY_FRAGMENTS, ServiceReadGate, ServiceReadGateError,
    ServiceReadStage,
};
use std::cell::Cell;

fn id() -> ClipboardReadSuccessBinding {
    ClipboardReadSuccessBinding {
        worker_process_id: 42,
        worker_session_id: 7,
        worker_generation: 4,
        control_session_id: 77,
        control_sequence: 101,
        request_id: 19,
    }
}

fn live() -> LiveServiceReadState {
    LiveServiceReadState {
        binding: id(),
        grants: SensitiveReadGrants {
            clipboard_capability: true,
            read_permission: true,
        },
        native_client_pid: 42,
        native_client_session: 7,
        original_worker_alive: true,
        control_authenticated: true,
    }
}

fn connected() -> ServiceReadGate {
    let mut gate = ServiceReadGate::new(id(), 1_000, || Some(live())).unwrap();
    gate.check(ServiceReadStage::Connected, 1_001, || Some(live()))
        .unwrap();
    gate
}

#[test]
fn fresh_service_state_is_sampled_at_each_gate_and_consumed_once() {
    let count = Cell::new(0);
    let next = || {
        count.set(count.get() + 1);
        Some(live())
    };
    let mut gate = ServiceReadGate::new(id(), 1_000, next).unwrap();
    for (stage, time) in [
        (ServiceReadStage::Connected, 1_001),
        (ServiceReadStage::BeforeRead, 1_002),
        (ServiceReadStage::Fragment, 1_003),
        (ServiceReadStage::Fragment, 1_004),
        (ServiceReadStage::BeforeDelivery, 1_005),
    ] {
        gate.check(stage, time, next).unwrap();
    }
    assert_eq!(count.get(), 6, "must not memoize any live Service snapshot");
    assert!(!gate.is_pending());
    assert_eq!(
        gate.check(ServiceReadStage::BeforeDelivery, 1_006, next),
        Err(ServiceReadGateError::AlreadyUsed)
    );
    assert_eq!(count.get(), 6, "replay must not query Service state again");
}

#[test]
fn all_six_binding_fields_are_rechecked_and_revoke_request() {
    let base = id();
    let variants = [
        ClipboardReadSuccessBinding {
            worker_process_id: 43,
            ..base
        },
        ClipboardReadSuccessBinding {
            worker_session_id: 8,
            ..base
        },
        ClipboardReadSuccessBinding {
            worker_generation: 5,
            ..base
        },
        ClipboardReadSuccessBinding {
            control_session_id: 78,
            ..base
        },
        ClipboardReadSuccessBinding {
            control_sequence: 102,
            ..base
        },
        ClipboardReadSuccessBinding {
            request_id: 20,
            ..base
        },
    ];
    for changed in variants {
        for phase in [
            ServiceReadStage::Connected,
            ServiceReadStage::BeforeRead,
            ServiceReadStage::Fragment,
            ServiceReadStage::BeforeDelivery,
        ] {
            let mut gate = connected();
            if phase == ServiceReadStage::Connected {
                gate = ServiceReadGate::new(id(), 1000, || Some(live())).unwrap();
            } else if phase == ServiceReadStage::Fragment
                || phase == ServiceReadStage::BeforeDelivery
            {
                gate.check(ServiceReadStage::BeforeRead, 1002, || Some(live()))
                    .unwrap();
                if phase == ServiceReadStage::BeforeDelivery {
                    gate.check(ServiceReadStage::Fragment, 1003, || Some(live()))
                        .unwrap();
                }
            }
            assert_eq!(
                gate.check(phase, 1004, || Some(LiveServiceReadState {
                    binding: changed,
                    ..live()
                })),
                Err(ServiceReadGateError::BindingChanged)
            );
            assert!(!gate.is_pending());
            assert_eq!(
                gate.check(phase, 1005, || Some(live())),
                Err(ServiceReadGateError::AlreadyUsed)
            );
        }
    }
}

#[test]
fn current_capability_and_read_permission_are_independently_mandatory() {
    for revoked in [
        SensitiveReadGrants {
            clipboard_capability: false,
            read_permission: true,
        },
        SensitiveReadGrants {
            clipboard_capability: true,
            read_permission: false,
        },
    ] {
        assert_eq!(
            ServiceReadGate::new(id(), 1000, || Some(LiveServiceReadState {
                grants: revoked,
                ..live()
            }))
            .err(),
            Some(ServiceReadGateError::PermissionRevoked)
        );
        for phase in [
            ServiceReadStage::Connected,
            ServiceReadStage::BeforeRead,
            ServiceReadStage::Fragment,
            ServiceReadStage::BeforeDelivery,
        ] {
            let mut gate = ServiceReadGate::new(id(), 1000, || Some(live())).unwrap();
            if phase != ServiceReadStage::Connected {
                gate.check(ServiceReadStage::Connected, 1001, || Some(live()))
                    .unwrap();
            }
            if phase == ServiceReadStage::Fragment || phase == ServiceReadStage::BeforeDelivery {
                gate.check(ServiceReadStage::BeforeRead, 1002, || Some(live()))
                    .unwrap();
            }
            if phase == ServiceReadStage::BeforeDelivery {
                gate.check(ServiceReadStage::Fragment, 1003, || Some(live()))
                    .unwrap();
            }
            assert_eq!(
                gate.check(phase, 1004, || Some(LiveServiceReadState {
                    grants: revoked,
                    ..live()
                })),
                Err(ServiceReadGateError::PermissionRevoked)
            );
            assert!(!gate.is_pending());
        }
    }
}

#[test]
fn loss_of_real_worker_peer_or_authenticated_control_poison_gate() {
    for (bad, err) in [
        (
            LiveServiceReadState {
                native_client_pid: 43,
                ..live()
            },
            ServiceReadGateError::PeerMismatch,
        ),
        (
            LiveServiceReadState {
                native_client_session: 8,
                ..live()
            },
            ServiceReadGateError::PeerMismatch,
        ),
        (
            LiveServiceReadState {
                original_worker_alive: false,
                ..live()
            },
            ServiceReadGateError::WorkerDead,
        ),
        (
            LiveServiceReadState {
                control_authenticated: false,
                ..live()
            },
            ServiceReadGateError::ControlUnavailable,
        ),
    ] {
        let mut gate = connected();
        assert_eq!(
            gate.check(ServiceReadStage::BeforeRead, 1002, || Some(bad)),
            Err(err)
        );
        assert!(!gate.is_pending());
        assert_eq!(
            gate.check(ServiceReadStage::BeforeRead, 1003, || Some(live())),
            Err(ServiceReadGateError::AlreadyUsed)
        );
    }
    assert_eq!(
        ServiceReadGate::new(id(), 1000, || None).err(),
        Some(ServiceReadGateError::AuthorityUnavailable)
    );
    let mut gate = connected();
    assert_eq!(
        gate.check(ServiceReadStage::BeforeRead, 1002, || None),
        Err(ServiceReadGateError::AuthorityUnavailable)
    );
    assert!(!gate.is_pending());
}

#[test]
fn fail_closed_on_clock_errors_ordering_and_fragment_budget() {
    let mut gate = connected();
    assert_eq!(
        gate.check(ServiceReadStage::Fragment, 1002, || Some(live())),
        Err(ServiceReadGateError::BadStage)
    );
    assert!(!gate.is_pending());

    let mut gate = connected();
    assert_eq!(
        gate.check(ServiceReadStage::BeforeRead, 999, || Some(live())),
        Err(ServiceReadGateError::ClockRegression)
    );
    assert!(!gate.is_pending());

    let mut gate = connected();
    assert_eq!(
        gate.check(ServiceReadStage::BeforeRead, 3500, || Some(live())),
        Err(ServiceReadGateError::Expired)
    );
    assert!(!gate.is_pending());

    let mut gate = connected();
    gate.check(ServiceReadStage::BeforeRead, 1002, || Some(live()))
        .unwrap();
    for _ in 0..MAX_POLICY_FRAGMENTS {
        gate.check(ServiceReadStage::Fragment, 1003, || Some(live()))
            .unwrap();
    }
    assert_eq!(
        gate.check(ServiceReadStage::Fragment, 1004, || Some(live())),
        Err(ServiceReadGateError::BudgetExceeded)
    );
    assert!(!gate.is_pending());

    let mut gate = connected();
    gate.check(ServiceReadStage::BeforeRead, 1002, || Some(live()))
        .unwrap();
    assert_eq!(
        gate.check(ServiceReadStage::BeforeDelivery, 1003, || Some(live())),
        Err(ServiceReadGateError::BadStage)
    );
    assert!(!gate.is_pending());
}

#[test]
fn invalid_or_overflowing_request_never_admitted() {
    let bad = ClipboardReadSuccessBinding {
        control_sequence: 0,
        ..id()
    };
    assert_eq!(
        ServiceReadGate::new(bad, 1000, || Some(live())).err(),
        Some(ServiceReadGateError::InvalidBinding)
    );
    assert_eq!(
        ServiceReadGate::new(id(), u64::MAX, || Some(live())).err(),
        Some(ServiceReadGateError::ClockOverflow)
    );
}

#[test]
fn explicit_cancellation_is_permanent_and_idempotent() {
    let mut gate = connected();
    assert!(gate.cancel());
    assert!(!gate.cancel());
    assert!(!gate.is_pending());
    assert_eq!(
        gate.check(ServiceReadStage::BeforeRead, 1002, || Some(live())),
        Err(ServiceReadGateError::AlreadyUsed)
    );
}

#[test]
fn native_peer_and_grant_denials_also_apply_at_first_admission() {
    for bad in [
        LiveServiceReadState {
            native_client_pid: 999,
            ..live()
        },
        LiveServiceReadState {
            native_client_session: 99,
            ..live()
        },
    ] {
        assert_eq!(
            ServiceReadGate::new(id(), 1000, || Some(bad)).err(),
            Some(ServiceReadGateError::PeerMismatch)
        );
    }
    assert_eq!(
        ServiceReadGate::new(id(), 1000, || Some(LiveServiceReadState {
            original_worker_alive: false,
            ..live()
        }))
        .err(),
        Some(ServiceReadGateError::WorkerDead)
    );
    assert_eq!(
        ServiceReadGate::new(id(), 1000, || Some(LiveServiceReadState {
            control_authenticated: false,
            ..live()
        }))
        .err(),
        Some(ServiceReadGateError::ControlUnavailable)
    );
}

#[test]
fn panicking_live_service_accessor_must_poison_pending_request() {
    let mut gate = connected();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = gate.check(ServiceReadStage::BeforeRead, 1002, || {
            panic!("simulated trusted authority accessor unavailable")
        });
    }));
    assert!(panic.is_err(), "test must exercise an unwinding accessor");
    assert!(
        !gate.is_pending(),
        "panic cannot leave old authorization pending"
    );
    assert_eq!(
        gate.check(ServiceReadStage::BeforeRead, 1003, || Some(live())),
        Err(ServiceReadGateError::AlreadyUsed)
    );
}
