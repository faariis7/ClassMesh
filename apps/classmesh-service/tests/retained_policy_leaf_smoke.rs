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
use classmesh_win32::policy_file_origin::{
    open_protected_epoch_policy_in_app_root, open_protected_policy_in_app_root,
    open_protected_policy_in_program_data,
    open_protected_policy_leaf,
};

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
    icacls(&path, &["/reset"]);
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
    let retained = open_protected_policy_leaf(&path).unwrap_or_else(|error| {
        eprintln!("protected leaf attestation failed: {error}");
        let _ = Command::new("icacls.exe").arg(&path).status();
        panic!("protected fixture ACL rejected: {error}");
    });

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

#[test]
fn pinned_protected_subtree_keeps_original_authorization_during_parse() {
    let fixture = std::env::temp_dir().join(format!(
        "classmesh-service-pinned-subtree-{}",
        std::process::id()
    ));
    let app = fixture.join("ClassMesh");
    let state = app.join("state");
    fs::create_dir_all(&state).unwrap();
    let path = state.join("authorization.json");
    let durable = DurableAuthorizationState::new(&path);
    let principal = PrincipalId([88; 32]);
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
    for directory in [&app, &state] {
        icacls(directory, &["/reset"]);
        icacls(
            directory,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
        );
        icacls(directory, &["/setowner", "*S-1-5-32-544"]);
    }
    icacls(&path, &["/reset"]);
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

    let pinned = open_protected_policy_in_app_root(&app).unwrap_or_else(|error| {
        eprintln!("protected subtree attestation failed: {error}");
        for node in [&app, &state, &path] {
            let _ = Command::new("icacls.exe").arg(node).status();
        }
        panic!("protected subtree fixture rejected: {error}");
    });
    let loaded = pinned.with_file(|file| {
        DurableAuthorizationState::parse_primary_from_open_file(file.try_clone().unwrap())
    });
    assert!(loaded.unwrap().principal(principal).unwrap().enabled);
    drop(pinned);

    icacls(&state, &["/grant", "*S-1-5-32-545:R"]);
    assert_eq!(
        open_protected_policy_in_app_root(&app).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn protected_programdata_prefix_pins_same_handle_during_policy_parse() {
    let fixture = std::env::temp_dir().join(format!(
        "classmesh-service-programdata-prefix-{}",
        std::process::id()
    ));
    let program_data = fixture.join("ProgramData");
    let app = program_data.join("ClassMesh");
    let state = app.join("state");
    fs::create_dir_all(&state).unwrap();
    let path = state.join("authorization.json");
    let durable = DurableAuthorizationState::new(&path);
    let principal = PrincipalId([99; 32]);
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

    for directory in [&program_data, &app, &state] {
        icacls(directory, &["/reset"]);
        icacls(
            directory,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
        );
        icacls(directory, &["/setowner", "*S-1-5-32-544"]);
    }
    icacls(&path, &["/reset"]);
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

    let candidate = open_protected_policy_in_program_data(&program_data).unwrap_or_else(|error| {
        eprintln!("protected ProgramData fixture attestation failed: {error}");
        for node in [&program_data, &app, &state, &path] {
            let _ = Command::new("icacls.exe").arg(node).status();
        }
        panic!("protected ProgramData fixture rejected: {error}");
    });
    assert!(
        fs::rename(&program_data, fixture.join("renamed-programdata")).is_err(),
        "ancestor must remain pinned while the parser runs"
    );
    let loaded = candidate.with_file(|file| {
        DurableAuthorizationState::parse_primary_from_open_file(file.try_clone().unwrap())
    });
    assert!(loaded.unwrap().principal(principal).unwrap().enabled);
    drop(candidate);

    icacls(&program_data, &["/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    assert_eq!(
        open_protected_policy_in_program_data(&program_data)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_dir_all(fixture).unwrap();
}


/// Integration proof only: an epoch-selected protected leaf is parsed through
/// its pinned HANDLE while the protected ClassMesh/state parents remain held.
/// The V2 record here is a test fixture, NOT a trusted durable epoch anchor.
#[test]
fn protected_epoch_blob_matches_v2_checkpoint_on_same_pinned_handle() {
    use classmesh_security::policy_epoch::{
        BoundPolicyError, encode_bound_policy_checkpoint, verify_bound_policy_checkpoint,
    };

    let fixture = std::env::temp_dir().join(format!(
        "classmesh-service-epoch-blob-{}",
        std::process::id()
    ));
    let app = fixture.join("ClassMesh");
    let state = app.join("state");
    fs::create_dir_all(&state).unwrap();
    let path = state.join("policy-0000000000000033.json");
    let original = br#"{"version":1,"principals":[]}"#;
    fs::write(&path, original).unwrap();
    for directory in [&app, &state] {
        icacls(directory, &["/reset"]);
        icacls(directory, &["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]);
        icacls(directory, &["/setowner", "*S-1-5-32-544"]);
    }
    icacls(&path, &["/reset"]);
    icacls(&path, &["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]);
    icacls(&path, &["/setowner", "*S-1-5-32-544"]);
    let checkpoint = encode_bound_policy_checkpoint(51, original).unwrap();
    let pinned = open_protected_epoch_policy_in_app_root(&app, 51).unwrap();
    assert!(fs::rename(&state, app.join("state-replaced")).is_err());
    let verified = pinned.with_file(|file| {
        verify_bound_policy_checkpoint(checkpoint.as_slice(), file, 4096)
    }).unwrap();
    assert_eq!(verified.epoch(), 51);
    assert_eq!(verified.policy_bytes(), original);
    drop(pinned);

    let wrong = encode_bound_policy_checkpoint(51, b"different policy").unwrap();
    let pinned = open_protected_epoch_policy_in_app_root(&app, 51).unwrap();
    assert_eq!(pinned.with_file(|file| {
        verify_bound_policy_checkpoint(wrong.as_slice(), file, 4096)
    }).unwrap_err(), BoundPolicyError::DigestMismatch);
    drop(pinned);
    assert_eq!(open_protected_epoch_policy_in_app_root(&app, 52).unwrap_err().kind(), io::ErrorKind::NotFound);
    fs::remove_dir_all(fixture).unwrap();
}
