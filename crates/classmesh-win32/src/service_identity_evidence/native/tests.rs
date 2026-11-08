use super::*;

#[test]
fn current_token_audit_is_native_and_queries_do_not_modify_it() {
    let first = audit_current_caller().unwrap();
    let second = audit_current_caller().unwrap();
    assert_eq!(first, second);
    assert!(!first.user_sid.is_empty());
    assert_eq!(first.pid, std::process::id());
}

#[test]
fn actual_nonordinary_caller_is_refused_before_target_callback() {
    let audit = audit_current_caller().unwrap();
    let mut called = false;
    let result = collect_with(
        || Ok(audit.clone()),
        || {
            called = true;
            Err(io::Error::other("fixture target failure"))
        },
    );
    if audit.context.refusal().is_some() {
        assert!(!called, "ineligible native context reached target access");
        assert_eq!(result.outcome, "NOT_MEASURED_CALLER_CONTEXT");
        assert!(result.target.is_none());
    } else {
        assert!(called);
        assert_eq!(result.outcome, "MEASUREMENT_ERROR");
    }
    assert!(!result.authenticated_service_worker);
}

#[test]
fn unknown_native_caller_is_refused_without_attempting_target_access() {
    let result = collect_with(
        || Err(io::Error::other("caller query denied")),
        || panic!("must not touch target"),
    );
    assert_eq!(result.outcome, "NOT_MEASURED_CALLER_CONTEXT");
    assert!(result.caller.is_none() && result.target.is_none());
    assert!(!result.authenticated_service_worker);
}

#[test]
fn synthetic_post_measurement_context_change_invalidates_result() {
    // State-machine evidence only: never present this constructed caller as an
    // actual ordinary Windows account or actual target-access measurement.
    let mut audit = audit_current_caller().unwrap();
    audit.context = CallerContext {
        elevated: false,
        elevation_type: 1,
        admin_sid_present: false,
        effective_admin: false,
        service_account: false,
        debug_present: false,
        unexpected_privileges: false,
        restricted: false,
        app_container: false,
        impersonating: false,
        integrity: 0x2000,
        session: 1,
        ui_access: false,
    };
    let mut calls = 0;
    let result = collect_with(
        || {
            calls += 1;
            if calls == 1 {
                Ok(audit.clone())
            } else {
                Err(io::Error::other("context recheck denied"))
            }
        },
        || Err(io::Error::other("synthetic incomplete target observation")),
    );
    assert_eq!(result.outcome, "INVALIDATED_CALLER_CONTEXT_CHANGED");
    assert!(!result.authenticated_service_worker);
}

#[test]
fn malformed_token_buffer_is_rejected_before_sid_traversal() {
    let buffer = TokenData {
        words: vec![0; 4],
        used: 8,
    };
    assert!(buffer.value::<u64>(4).is_err());
    assert!(buffer.sid_string(usize::MAX as PSID).is_err());
    assert!(buffer.sid_string(std::ptr::null_mut()).is_err());
}
