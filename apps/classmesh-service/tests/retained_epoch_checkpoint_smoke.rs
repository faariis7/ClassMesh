#![cfg(windows)]
//! Native Windows proof of a retained HANDLE feeding the bounded epoch codec.
//! This is NOT a trusted persistent anti-rollback store or production loader.
use std::fs;
use std::io;
use std::process::Command;

use classmesh_security::policy_epoch::{
    encode_policy_epoch_checkpoint, parse_policy_epoch_checkpoint, verify_startup_policy_epoch,
};
use classmesh_win32::policy_file_origin::open_protected_policy_leaf;

fn icacls(path: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("icacls.exe")
            .arg(path)
            .args(args)
            .status()
            .expect("Windows ACL utility")
            .success()
    );
}

#[test]
fn protected_retained_epoch_handle_denies_replacement_and_rollback() {
    let fixture = std::env::temp_dir().join(format!(
        "classmesh-epoch-retained-handle-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&fixture);
    fs::create_dir_all(&fixture).unwrap();
    let path = fixture.join("trusted-epoch.bin");
    let original = encode_policy_epoch_checkpoint(12).unwrap();
    fs::write(&path, original).unwrap();

    assert_eq!(
        open_protected_policy_leaf(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
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
    let pinned = open_protected_policy_leaf(&path).unwrap();
    assert!(fs::write(&path, encode_policy_epoch_checkpoint(11).unwrap()).is_err());
    let trusted = parse_policy_epoch_checkpoint(pinned).unwrap();
    assert_eq!(trusted, 12);
    assert!(verify_startup_policy_epoch(trusted, 11).is_err());
    assert!(verify_startup_policy_epoch(trusted, 13).is_err());
    assert_eq!(verify_startup_policy_epoch(trusted, 12), Ok(()));

    icacls(&path, &["/grant", "*S-1-5-32-545:R"]);
    assert_eq!(
        open_protected_policy_leaf(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_dir_all(&fixture).unwrap();
}
