//! Inert chain-to-reader boundary. No durable epoch or Service publication.
use crate::nt_relative_directory::{open_relative_protected_node, same_native_file_identity};
use std::{
    fs::File,
    io::{self, Read},
};

// Independent acquisition ceilings for the fixed V2 record; the existing
// downstream security parser must validate framing, digest, epoch and its own
// limits. This acquisition boundary does not invoke it or publish policy.
const V2_CHECKPOINT_BYTES: u64 = 48;
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

struct PinnedPolicyReadCandidate {
    directories: Vec<File>,
}

impl PinnedPolicyReadCandidate {
    fn open(scope: &str) -> io::Result<Self> {
        if !crate::policy_file_origin::safe_child_leaf(scope) {
            return Err(denied());
        }
        let mut directories = crate::system_volume::pin_system_program_data()?;
        let app =
            open_relative_protected_node(directories.last().ok_or_else(denied)?, scope, true)?;
        let state = open_relative_protected_node(&app, "state", true)?;
        directories.push(app);
        directories.push(state);
        Ok(Self { directories })
    }

    /// Consuming API retains the entire chain throughout the callback. Readers
    /// expose neither File cloning nor raw HANDLEs. The epoch is a candidate,
    /// not an independently authenticated durable version.
    fn read<T>(
        self,
        epoch: u64,
        maximum_bytes: usize,
        action: impl FnOnce(&mut dyn Read, &mut dyn Read) -> T,
    ) -> io::Result<T> {
        if epoch == 0 || maximum_bytes == 0 {
            return Err(denied());
        }
        let state = self.directories.last().ok_or_else(denied)?;
        let checkpoint = open_relative_protected_node(state, "policy-checkpoint.v2", false)?;
        let policy =
            open_relative_protected_node(state, &format!("policy-{epoch:016x}.json"), false)?;
        if same_native_file_identity(&checkpoint, &policy)? {
            return Err(denied());
        }
        // Match the V2 framing and allocation ceilings; an extra byte is kept
        // for the downstream parser to reject oversize instead of truncating it.
        let mut checkpoint_reader = checkpoint.take(V2_CHECKPOINT_BYTES + 1);
        let mut policy_reader = policy.take((maximum_bytes.min(MAX_POLICY_BYTES) + 1) as u64);
        Ok(action(&mut checkpoint_reader, &mut policy_reader))
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified retained policy read",
    )
}

#[test]
fn independently_rooted_read_keeps_all_handles_and_bounds_bytes() {
    use crate::nt_relative_directory::create_relative_protected_directory;
    let roots = crate::system_volume::pin_system_program_data().unwrap();
    let scope = format!("ClassMesh-inert-reader-{}", std::process::id());
    // Only a newly created test-owned scope; never use the installed ClassMesh.
    let app = create_relative_protected_directory(roots.last().unwrap(), &scope).unwrap();
    let state = create_relative_protected_directory(&app, "state").unwrap();
    let path = crate::program_data_known_folder::resolve_os_program_data_path()
        .unwrap()
        .join(&scope);
    let state_path = path.join("state");
    let checkpoint = state_path.join("policy-checkpoint.v2");
    let blob = state_path.join("policy-0000000000000007.json");
    for (file, bytes) in [
        (&checkpoint, b"checkpoint".as_slice()),
        (&blob, b"bounded policy".as_slice()),
    ] {
        std::fs::write(file, bytes).unwrap();
        for args in [
            vec!["/reset"],
            vec![
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ],
            vec!["/setowner", "*S-1-5-32-544"],
        ] {
            assert!(
                std::process::Command::new("icacls.exe")
                    .arg(file)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    drop(state);
    drop(app);
    let candidate = PinnedPolicyReadCandidate::open(&scope).unwrap();
    let bytes = candidate
        .read(7, 4, |checkpoint_reader, policy_reader| {
            assert!(std::fs::rename(&state_path, path.join("moved")).is_err());
            assert!(std::fs::write(&blob, b"replaced").is_err());
            let mut header = Vec::new();
            checkpoint_reader.read_to_end(&mut header).unwrap();
            assert_eq!(header, b"checkpoint");
            let mut bytes = Vec::new();
            policy_reader.read_to_end(&mut bytes).unwrap();
            bytes
        })
        .expect("rooted bounded read");
    assert_eq!(
        bytes, b"bound",
        "bound plus one sentinel lets parser detect oversize"
    );
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .read(8, 1024, |_, _| ())
            .is_err()
    );
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .read(0, 1024, |_, _| ())
            .is_err()
    );
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .read(7, 0, |_, _| ())
            .is_err()
    );
    // Readers are closed on callback return; a fresh candidate reads original
    // bytes in full, and the fixed checkpoint ceiling preserves an oversize byte.
    std::fs::write(&checkpoint, [0u8; 50]).unwrap();
    PinnedPolicyReadCandidate::open(&scope)
        .unwrap()
        .read(7, 1024, |header, policy| {
            let mut record = Vec::new();
            header.read_to_end(&mut record).unwrap();
            assert_eq!(record.len(), 49);
            let mut bytes = Vec::new();
            policy.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"bounded policy");
        })
        .unwrap();
    assert!(
        std::process::Command::new("icacls.exe")
            .arg(&blob)
            .args(["/grant", "*S-1-5-32-545:R"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .read(7, 1024, |_, _| panic!("untrusted leaf reached reader"))
            .is_err()
    );
    drop(roots);
    std::fs::remove_dir_all(path).unwrap();
}
