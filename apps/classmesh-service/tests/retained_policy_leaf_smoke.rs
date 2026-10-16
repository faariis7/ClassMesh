#![cfg(windows)]
//! Disposable Windows integration qualification only. This exercises the
//! leaf's retained HANDLE into the bounded parser, not ancestor trust,
//! persistent rollback protection, SCM identity or live policy publication.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use classmesh_security::persistence::DurableAuthorizationState;
use classmesh_security::{AuthorizationStore, Permission, Principal, PrincipalId, PrincipalKind};
use classmesh_win32::policy_file_origin::open_protected_policy_leaf;

fn icacls(path: &Path, options: &[&str]) {
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(options)
        .status()
        .expect("native Windows ACL utility");
    assert!(status.success(), "icacls failed: {options:?}");
}

#[test]
fn protected_leaf_passes_retained_handle_to_bounded_parser() {
    let folder = std::env::temp_dir().join(format!(
        "classmesh-service-policy-handle-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&folder);
    fs::create_dir_all(&folder).unwrap();
    let path = folder.join("authorization.json");
    let durable = DurableAuthorizationState::new(&path);
    let principal = PrincipalId([77; 32]);
    let mut store = AuthorizationStore::default();
    store
        .upsert(Principal {
            id: principal,
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions: BTreeSet::from([Permission::ViewMonitoring]),
            credentials: BTreeMap::new(),
        })
        .unwrap();
    durable.save(&store).unwrap();

    assert_eq!(
        open_protected_policy_leaf(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied,
        "untrusted user-owned leaf must not parse as trusted policy"
    );
    icacls(
        &path,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
        ],
    );
    icacls(&path, &["/setowner", "*S-1-5-32-544"]);
    let retained = open_protected_policy_leaf(&path).unwrap();

    // Exclusive sharing keeps other writers from replacing the file while
    // this exact retained handle is being parsed.
    assert!(fs::write(&path, b"{malicious replacement").is_err());
    let loaded = DurableAuthorizationState::parse_primary_from_open_file(retained).unwrap();
    let restored = loaded.principal(principal).expect("original principal");
    assert!(restored.enabled);
    assert!(restored.permissions.contains(&Permission::ViewMonitoring));

    icacls(&path, &["/grant", "*S-1-5-32-545:R"]);
    assert_eq!(
        open_protected_policy_leaf(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_dir_all(folder).unwrap();
}
