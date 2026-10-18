//! Inert chain-to-reader boundary. No durable epoch or Service publication.
use crate::nt_relative_directory::{open_relative_protected_node, same_native_file_identity};
use std::{
    fs::File,
    io::{self, Read},
};

// Independent acquisition ceilings for the fixed V2 record. parse_candidate
// invokes the canonical parser inside these bounds; neither method publishes.
const V2_CHECKPOINT_BYTES: u64 = 48;
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

struct PinnedPolicyReadCandidate {
    directories: Vec<File>,
}

impl PinnedPolicyReadCandidate {
    fn parse_registry_candidate(
        self,
        anchor: &crate::registry_epoch::RegistryAnchor,
    ) -> io::Result<classmesh_security::AuthorizationStore> {
        crate::trusted_policy::parse_registry_policy(
            self.directories.last().ok_or_else(denied)?,
            anchor,
        )
        .map(|(_, store)| store)
    }

    /// A parsed candidate, not a publication capability. The supplied expected
    /// epoch has no independent durable authority in this qualification harness.
    fn parse_candidate(
        self,
        expected_epoch: u64,
    ) -> io::Result<classmesh_security::AuthorizationStore> {
        self.read(expected_epoch, MAX_POLICY_BYTES, |checkpoint, policy| {
            classmesh_security::persistence::DurableAuthorizationState::parse_bound_primary_from_readers(
                checkpoint, policy, expected_epoch,
            )
        })?
        .map_err(|_| denied())
    }

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
        protect_fixture_leaf(file);
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
    // Exercise the canonical V2 digest and authorization parser through the
    // opaque readers; an expected epoch is still NOT a durable authority.
    let valid = br#"{"version":1,"principals":[]}"#;
    let record =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, valid).unwrap();
    std::fs::write(&checkpoint, record).unwrap();
    std::fs::write(&blob, vec![0; MAX_POLICY_BYTES + 1]).unwrap();
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_candidate(7)
            .is_err()
    );
    std::fs::write(&blob, valid).unwrap();
    let parsed = PinnedPolicyReadCandidate::open(&scope)
        .unwrap()
        .parse_candidate(7)
        .expect("canonical parser accepts exact bound candidate");
    assert!(
        parsed
            .principal(classmesh_security::PrincipalId([0; 32]))
            .is_none()
    );
    let candidate = PinnedPolicyReadCandidate::open(&scope).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            let _ = candidate.read::<()>(7, 1024, |_, _| panic!("injected reader unwind"));
        })
        .is_err()
    );
    // An unwind must release the original leaf and state handles too.
    std::fs::write(&blob, valid).unwrap();
    std::fs::rename(&state_path, path.join("after-unwind")).unwrap();
    std::fs::rename(path.join("after-unwind"), &state_path).unwrap();
    for bad_record in [
        record[..47].to_vec(),
        [record.as_slice(), &[0]].concat(),
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(8, valid)
            .unwrap()
            .to_vec(),
    ] {
        std::fs::write(&checkpoint, bad_record).unwrap();
        assert!(
            PinnedPolicyReadCandidate::open(&scope)
                .unwrap()
                .parse_candidate(7)
                .is_err()
        );
    }
    std::fs::write(&checkpoint, record).unwrap();
    std::fs::write(&blob, [valid.as_slice(), b" "].concat()).unwrap();
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_candidate(7)
            .is_err()
    );
    let malformed = b"invalid JSON";
    std::fs::write(
        &checkpoint,
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, malformed).unwrap(),
    )
    .unwrap();
    std::fs::write(&blob, malformed).unwrap();
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_candidate(7)
            .is_err()
    );
    std::fs::write(&checkpoint, record).unwrap();
    std::fs::write(&blob, valid).unwrap();
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_candidate(0)
            .is_err()
    );
    // The independent Registry record selects and binds the policy. A local
    // checkpoint and old blobs must not override that authority.
    let anchor_scope = format!("ClassMesh-anchor-probe-reader-{}", std::process::id());
    let anchor = crate::registry_epoch::RegistryAnchor::create(&anchor_scope, &record).unwrap();
    std::fs::remove_file(&checkpoint).unwrap();
    PinnedPolicyReadCandidate::open(&scope)
        .unwrap()
        .parse_registry_candidate(&anchor)
        .expect("registry-rooted candidate");
    std::fs::write(&blob, [valid.as_slice(), b" "].concat()).unwrap();
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_registry_candidate(&anchor)
            .is_err()
    );
    std::fs::write(&blob, valid).unwrap();
    let next = classmesh_security::policy_epoch::encode_bound_policy_checkpoint(9, valid).unwrap();
    anchor.advance(&record, &next).unwrap();
    // Epoch 7 still exists, but missing committed epoch 9 must never fall back.
    assert!(
        PinnedPolicyReadCandidate::open(&scope)
            .unwrap()
            .parse_registry_candidate(&anchor)
            .is_err()
    );
    let newer_blob = state_path.join("policy-0000000000000009.json");
    std::fs::write(&newer_blob, valid).unwrap();
    protect_fixture_leaf(&newer_blob);
    PinnedPolicyReadCandidate::open(&scope)
        .unwrap()
        .parse_registry_candidate(&anchor)
        .unwrap();
    assert!(anchor.advance(&next, &record).is_err());
    drop(anchor);
    crate::registry_epoch::remove_fixture(&anchor_scope);
    std::fs::write(&checkpoint, record).unwrap();
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

fn protect_fixture_leaf(file: &std::path::Path) {
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
