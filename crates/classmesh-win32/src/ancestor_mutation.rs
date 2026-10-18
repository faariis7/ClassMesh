//! Disposable native attack fixture. No system directory is modified.
use std::fs::{File, OpenOptions};
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};

fn set_junction(writer: &File, target: &std::path::Path) -> std::io::Result<()> {
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let print: Vec<u16> = target.to_str().unwrap().encode_utf16().collect();
    let substitute: Vec<u16> = format!(r"\??\{}", target.display())
        .encode_utf16()
        .collect();
    // REPARSE_DATA_BUFFER mount-point layout, byte offsets into PathBuffer.
    let mut data = Vec::new();
    data.extend_from_slice(&0xa0000003u32.to_le_bytes());
    let path_bytes = (substitute.len() + print.len() + 2) * 2;
    data.extend_from_slice(&u16::try_from(8 + path_bytes).unwrap().to_le_bytes());
    for field in [
        0,
        0,
        substitute.len() * 2,
        (substitute.len() + 1) * 2,
        print.len() * 2,
    ] {
        data.extend_from_slice(&u16::try_from(field).unwrap().to_le_bytes());
    }
    for ch in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    let mut returned = 0;
    // Safety: live synchronous directory HANDLE, initialized input buffer of
    // the declared size, no output buffer or asynchronous OVERLAPPED lifetime.
    let ok = unsafe {
        DeviceIoControl(
            writer.as_raw_handle(),
            0x000900a4,
            data.as_ptr().cast(),
            data.len() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[test]
fn preexisting_attribute_writer_cannot_redirect_retained_parent() {
    use crate::nt_relative_directory::open_relative_readonly_directory;
    let fixture = std::env::temp_dir().join(format!(
        "classmesh-ancestor-mutation-{}",
        std::process::id()
    ));
    std::fs::create_dir(&fixture).unwrap();
    let parent_path = fixture.join("parent");
    let target_path = fixture.join("target");
    std::fs::create_dir(&parent_path).unwrap();
    std::fs::create_dir(&target_path).unwrap();
    std::fs::create_dir(target_path.join("attacker-child")).unwrap();
    // Acquire mutation rights BEFORE retaining the candidate parent.
    let writer = OpenOptions::new()
        .access_mode(0x100)
        .share_mode(7)
        .custom_flags(0x02200000)
        .open(&parent_path)
        .unwrap();
    let fixture_handle = OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(0x02200000)
        .open(&fixture)
        .unwrap();
    let parent = open_relative_readonly_directory(&fixture_handle, "parent").unwrap();
    set_junction(&writer, &target_path).expect("attack must actually mutate retained parent");
    assert!(
        parent.metadata().unwrap().file_type().is_symlink(),
        "mutation witness"
    );
    // Positive control: the pathname now reaches the attacker target.
    assert!(parent_path.join("attacker-child").is_dir());
    let child = open_relative_readonly_directory(&parent, "attacker-child");
    assert!(
        crate::nt_relative_directory::create_relative_protected_directory(&parent, "new-child")
            .is_err()
    );
    assert!(!target_path.join("new-child").exists());
    eprintln!("retained-parent open after mutation: {child:?}");
    drop(writer);
    drop(parent);
    drop(fixture_handle);
    std::fs::remove_dir(&parent_path).unwrap();
    std::fs::remove_dir_all(&fixture).unwrap();
    assert!(
        child.is_err(),
        "retained parent must not resolve attacker target"
    );
}

#[test]
fn create_only_bootstrap_uses_retained_parent_and_installs_acl_atomically() {
    use crate::nt_relative_directory::{
        create_relative_protected_directory, open_relative_protected_node,
    };
    let fixture =
        std::env::temp_dir().join(format!("classmesh-relative-create-{}", std::process::id()));
    std::fs::create_dir(&fixture).unwrap();
    let original = fixture.join("original");
    let moved = fixture.join("moved");
    std::fs::create_dir(&original).unwrap();
    assert!(
        std::process::Command::new("icacls.exe")
            .arg(&original)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)F"])
            .status()
            .unwrap()
            .success()
    );
    let parent = OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(0x02200000)
        .open(&original)
        .unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    let root = create_relative_protected_directory(&parent, "ClassMesh").expect("atomic create");
    assert!(
        !original.join("ClassMesh").exists(),
        "do not re-resolve replaced path"
    );
    assert!(moved.join("ClassMesh").is_dir());
    let state = create_relative_protected_directory(&root, "state").unwrap();
    assert!(create_relative_protected_directory(&root, "state").is_err());
    assert!(std::fs::rename(moved.join("ClassMesh"), moved.join("renamed")).is_err());
    assert!(open_relative_protected_node(&root, "state", true).is_ok());
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let attempt = || {
            barrier.wait();
            create_relative_protected_directory(&root, "contended")
        };
        let first = scope.spawn(attempt);
        let second = scope.spawn(attempt);
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            outcomes.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one creator; loser must never adopt winner's directory"
        );
    });
    drop(state);
    drop(root);
    assert!(
        create_relative_protected_directory(&parent, "ClassMesh").is_err(),
        "never adopt even a protected existing directory"
    );
    std::fs::write(moved.join("file"), b"preserve").unwrap();
    assert!(create_relative_protected_directory(&parent, "file").is_err());
    assert_eq!(std::fs::read(moved.join("file")).unwrap(), b"preserve");
    for name in ["..", "child:stream", "nested\\child"] {
        assert!(create_relative_protected_directory(&parent, name).is_err());
    }
    drop(parent);
    std::fs::remove_dir_all(&fixture).unwrap();
}
