#![cfg(windows)]
//! Disposable Windows-only same-HANDLE policy-byte binding proof. No Service wiring.
use std::fs;
use std::io;
use std::process::Command;

use classmesh_security::PrincipalId;
use classmesh_security::persistence::{DurableAuthorizationState, PersistenceError};
use classmesh_security::policy_epoch::encode_bound_policy_checkpoint;
use classmesh_win32::policy_file_origin::open_protected_policy_leaf;

fn icacls(path: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("icacls.exe")
            .arg(path)
            .args(args)
            .status()
            .expect("native Windows ACL tool")
            .success()
    );
}

fn protect(path: &std::path::Path) {
    icacls(path, &["/reset"]);
    icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
        ],
    );
    icacls(path, &["/setowner", "*S-1-5-32-544"]);
}

#[test]
fn bound_policy_uses_two_retained_protected_handles_and_rejects_tampering() {
    let fixture = std::env::temp_dir().join(format!(
        "classmesh-bound-policy-smoke-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&fixture);
    fs::create_dir_all(&fixture).unwrap();
    let policy = fixture.join("authorization.json");
    let anchor = fixture.join("epoch-v2.bin");
    let original = br#"{"version":1,"principals":[]}"#;
    fs::write(&policy, original).unwrap();
    fs::write(
        &anchor,
        encode_bound_policy_checkpoint(31, original).unwrap(),
    )
    .unwrap();
    for path in [&policy, &anchor] {
        assert_eq!(
            open_protected_policy_leaf(path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        protect(path);
    }
    let (anchor_handle, policy_handle) = (
        open_protected_policy_leaf(&anchor).unwrap(),
        open_protected_policy_leaf(&policy).unwrap(),
    );
    assert!(fs::write(&policy, b"replaced").is_err());
    assert!(fs::write(&anchor, b"rollback").is_err());
    let restored = DurableAuthorizationState::parse_bound_primary_from_open_files(
        anchor_handle,
        policy_handle,
        31,
    )
    .unwrap();
    assert!(restored.principal(PrincipalId([0; 32])).is_none());
    let (anchor_handle, policy_handle) = (
        open_protected_policy_leaf(&anchor).unwrap(),
        open_protected_policy_leaf(&policy).unwrap(),
    );
    assert!(matches!(
        DurableAuthorizationState::parse_bound_primary_from_open_files(
            anchor_handle,
            policy_handle,
            30
        ),
        Err(PersistenceError::UntrustedPolicyBinding)
    ));
    icacls(&policy, &["/grant", "*S-1-5-32-545:R"]);
    assert_eq!(
        open_protected_policy_leaf(&policy).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_dir_all(&fixture).unwrap();
}
