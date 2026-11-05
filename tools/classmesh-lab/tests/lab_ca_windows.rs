#![cfg(windows)]
//! Native integration: real executables, CNG keys, signed certificates and persistence.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use classmesh_control::enrollment::{ENROLLMENT_MIN_VERSION, validate_enrollment_result_binding};
use classmesh_identity_win::{
    CngMachineKey, CngRcgenSigningKey, DurableMachineIdentity, cng_server_cert_resolver,
};
use classmesh_protocol::control_wire::{EnrollmentRequest, EnrollmentResult};
use classmesh_security::{PrincipalId, PrincipalKind, persistence::DurableAuthorizationState};
use prost::Message;
use rcgen::{CertificateSigningRequestParams, Issuer};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};
use sha2::{Digest, Sha256};

const CA: &str = env!("CARGO_BIN_EXE_classmesh-lab-ca");
const REQUEST: &str = env!("CARGO_BIN_EXE_classmesh-enrollment-request");
const AUTHORITY: &str = env!("CARGO_BIN_EXE_classmesh-enrollment-authority");
const INSTALL: &str = env!("CARGO_BIN_EXE_classmesh-enrollment-install");
const STAGE: &str = env!("CARGO_BIN_EXE_classmesh-student-authorization-init");

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn nonce() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).unwrap();
    hex(&bytes)
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn run(exe: &str, args: &[&str]) -> Output {
    Command::new(exe)
        .args(args)
        .output()
        .expect("native CLI execution")
}
fn success(exe: &str, args: &[&str]) -> Output {
    let output = run(exe, args);
    assert!(
        output.status.success(),
        "{exe}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
struct Lab {
    id: String,
    root: PathBuf,
}
impl Lab {
    fn new() -> Self {
        let id = nonce();
        success(CA, &["bootstrap", "--lab-only", "--session", &id]);
        Self {
            root: std::env::temp_dir().join(format!("ClassMesh-LabCA-{id}")),
            id,
        }
    }
    fn cert(&self) -> PathBuf {
        self.root.join("ca.der")
    }
    fn key(&self) -> String {
        format!("ClassMesh-LabCA-{}", self.id)
    }
    fn cleanup(&self) {
        success(CA, &["cleanup", "--lab-only", "--session", &self.id]);
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        if self.root.exists() {
            let output = run(CA, &["cleanup", "--lab-only", "--session", &self.id]);
            assert!(
                output.status.success(),
                "owned CA cleanup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ClassMesh-Enrollment-Test-{}", nonce()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only newly created test tree");
    }
}
struct DeviceKey(CngMachineKey);
impl Drop for DeviceKey {
    fn drop(&mut self) {
        self.0
            .clone()
            .delete()
            .expect("delete only key created by this test's CSR command");
        assert!(CngMachineKey::open(self.0.name().to_owned()).is_err());
    }
}
fn request(root: &Path, role: &str, label: &str) -> (PathBuf, EnrollmentRequest, DeviceKey) {
    let path = root.join(format!("{label}-request.pb"));
    success(
        REQUEST,
        &[
            "--role",
            role,
            "--display-name",
            label,
            "--output",
            text(&path),
        ],
    );
    let req = EnrollmentRequest::decode(fs::read(&path).unwrap().as_slice()).unwrap();
    let prefix = if role == "teacher" {
        "Teacher"
    } else {
        "StudentDevice"
    };
    let key =
        CngMachineKey::open(format!("ClassMesh-{prefix}-{}", hex(&req.principal_id))).unwrap();
    assert_eq!(key.export_policy().unwrap(), 0);
    (path, req, DeviceKey(key))
}
fn issue(lab: &Lab, req: &Path, output: &Path, role: &str) -> EnrollmentResult {
    success(
        AUTHORITY,
        &[
            "--role",
            role,
            "--request",
            text(req),
            "--ca-cert",
            text(&lab.cert()),
            "--ca-key-name",
            &lab.key(),
            "--output",
            text(output),
            "--lifetime-hours",
            "1",
        ],
    );
    EnrollmentResult::decode(fs::read(output).unwrap().as_slice()).unwrap()
}
fn install_args<'a>(
    req: &'a Path,
    res: &'a Path,
    ca: &'a Path,
    out: &'a Path,
    role: &'a str,
) -> Vec<&'a str> {
    vec![
        "--role",
        role,
        "--request",
        text(req),
        "--result",
        text(res),
        "--trust-root",
        text(ca),
        "--identity-output",
        text(out),
    ]
}

#[test]
fn bootstrap_creates_and_cleans_a_real_nonexportable_machine_ca() {
    assert!(
        !run(CA, &["bootstrap"]).status.success(),
        "explicit lab opt-in required"
    );
    let lab = Lab::new();
    let key = CngMachineKey::open(lab.key()).unwrap();
    assert_eq!(key.export_policy().unwrap(), 0);
    let cert = fs::read(lab.cert()).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert).unwrap();
    assert!(parsed.basic_constraints().unwrap().unwrap().value.ca);
    cng_server_cert_resolver(vec![CertificateDer::from(cert)], key).unwrap();
    assert!(
        !run(CA, &["bootstrap", "--lab-only", "--session", &lab.id])
            .status
            .success()
    );
    let extra = lab.root.join("not-owned.txt");
    fs::write(&extra, b"do not delete").unwrap();
    assert!(
        !run(CA, &["cleanup", "--lab-only", "--session", &lab.id])
            .status
            .success()
    );
    assert_eq!(fs::read(&extra).unwrap(), b"do not delete");
    fs::remove_file(extra).unwrap();
    let receipt_path = lab.root.join("ownership.bin");
    let receipt = fs::read(&receipt_path).unwrap();
    let mut forged = receipt.clone();
    *forged.last_mut().unwrap() ^= 1;
    fs::write(&receipt_path, forged).unwrap();
    assert!(
        !run(CA, &["cleanup", "--lab-only", "--session", &lab.id])
            .status
            .success()
    );
    assert!(CngMachineKey::open(lab.key()).is_ok());
    fs::write(receipt_path, receipt).unwrap();
    lab.cleanup();
    assert!(!lab.root.exists());
    assert!(CngMachineKey::open(lab.key()).is_err());
    println!(
        "lab_ca=P256_machine_nonexportable; collision_and_forged_cleanup=REJECTED; cleanup=PASS"
    );
}

#[test]
fn bootstrap_never_adopts_or_deletes_preexisting_key_or_directory() {
    let id = nonce();
    let root = std::env::temp_dir().join(format!("ClassMesh-LabCA-{id}"));
    let key = CngMachineKey::create(format!("ClassMesh-LabCA-{id}")).unwrap();
    let public = key.public_key_blob().unwrap();
    assert!(
        !run(CA, &["bootstrap", "--lab-only", "--session", &id])
            .status
            .success()
    );
    assert!(
        !run(CA, &["cleanup", "--lab-only", "--session", &id])
            .status
            .success()
    );
    assert_eq!(key.public_key_blob().unwrap(), public);
    assert!(!root.exists());
    key.delete().unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("not-owned.txt"), b"keep").unwrap();
    assert!(
        !run(CA, &["bootstrap", "--lab-only", "--session", &id])
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("not-owned.txt")).unwrap(), b"keep");
    fs::remove_file(root.join("not-owned.txt")).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn student_cycle_reloads_real_identity_and_rejects_untrusted_results() {
    let lab = Lab::new();
    let scratch = Scratch::new();
    let root = &scratch.0;
    let (request_path, req, _student_key) = request(root, "student-device", "student");
    let result_path = root.join("approved.pb");
    let approved = issue(&lab, &request_path, &result_path, "student-device");
    let principal: [u8; 32] = req.principal_id.clone().try_into().unwrap();
    let csr_hash: [u8; 32] = Sha256::digest(&req.pkcs10_csr_der).into();
    validate_enrollment_result_binding(ENROLLMENT_MIN_VERSION, &principal, &csr_hash, &approved)
        .unwrap();
    let stage = std::env::temp_dir().join(format!("ClassMesh-Student-Stage-{}", nonce()));
    assert!(!stage.exists());
    // Guard owns only this fresh, per-test TEMP name, including failure cleanup.
    struct StageDrop(PathBuf);
    impl Drop for StageDrop {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }
    let _stage = StageDrop(stage.clone());
    let ca = lab.cert();
    let identity = root.join("machine-identity.json");
    success(
        INSTALL,
        &install_args(
            &request_path,
            &result_path,
            &ca,
            &identity,
            "student-device",
        ),
    );
    success(
        STAGE,
        &[
            "--request",
            text(&request_path),
            "--result",
            text(&result_path),
            "--trust-root",
            text(&ca),
            "--output-dir",
            text(&stage),
        ],
    );
    let bundle = DurableMachineIdentity::new(&identity)
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(bundle.principal_id, principal);
    assert_eq!(bundle.certificate_chain_der, approved.certificate_chain_der);
    let reopened = CngMachineKey::open(bundle.cng_key_name.clone()).unwrap();
    assert_eq!(reopened.export_policy().unwrap(), 0);
    cng_server_cert_resolver(
        bundle
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
        reopened,
    )
    .unwrap();
    let store = DurableAuthorizationState::new(stage.join("state/authorization.json"))
        .load()
        .unwrap()
        .unwrap();
    let device = store.principal(PrincipalId(principal)).unwrap();
    assert_eq!(device.kind, PrincipalKind::StudentDevice);
    assert!(device.permissions.is_empty());
    assert!(
        fs::read_to_string(stage.join("config/control-runtime.json"))
            .unwrap()
            .contains("127.0.0.1:5151")
    );
    println!(
        "student_cycle=PASS; principal={}; csr_sha256={}; identity_reload=CNG_bound; privileged_permissions=0",
        hex(&principal),
        hex(&csr_hash)
    );
    assert!(
        !run(
            INSTALL,
            &install_args(
                &request_path,
                &result_path,
                &ca,
                &identity,
                "student-device"
            )
        )
        .status
        .success()
    );
    assert!(
        !run(
            REQUEST,
            &[
                "--role",
                "student-device",
                "--display-name",
                "duplicate",
                "--output",
                text(&request_path)
            ]
        )
        .status
        .success()
    );
    assert!(
        !run(
            STAGE,
            &[
                "--request",
                text(&request_path),
                "--result",
                text(&result_path),
                "--trust-root",
                text(&ca),
                "--output-dir",
                text(&stage)
            ]
        )
        .status
        .success()
    );

    let (other_path, _other, _other_key) = request(root, "student-device", "other");
    let other_result = issue(
        &lab,
        &other_path,
        &root.join("other-approved.pb"),
        "student-device",
    );
    let untrusted_lab = Lab::new();
    let untrusted = issue(
        &untrusted_lab,
        &request_path,
        &root.join("untrusted.pb"),
        "student-device",
    );
    let mut wrong_key = other_result;
    wrong_key.principal_id = req.principal_id.clone();
    wrong_key.csr_sha256 = csr_hash.to_vec();
    let mut wrong_principal = approved.clone();
    wrong_principal.principal_id[0] ^= 1;
    let mut wrong_csr = approved.clone();
    wrong_csr.csr_sha256[0] ^= 1;
    let mut forged = approved.clone();
    *forged.certificate_chain_der[0].last_mut().unwrap() ^= 1;
    forged.credential_fingerprint_sha256 =
        Sha256::digest(&forged.certificate_chain_der[0]).to_vec();
    let mut expired = approved.clone();
    let mut csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
        req.pkcs10_csr_der.as_slice(),
    ))
    .unwrap();
    let now = SystemTime::now();
    csr.params.not_before = (now - Duration::from_secs(7200)).into();
    csr.params.not_after = (now - Duration::from_secs(3600)).into();
    let issuer = Issuer::from_ca_cert_der(
        &CertificateDer::from(fs::read(&ca).unwrap()),
        CngRcgenSigningKey::new(CngMachineKey::open(lab.key()).unwrap()).unwrap(),
    )
    .unwrap();
    expired.certificate_chain_der[0] = csr.signed_by(&issuer).unwrap().der().to_vec();
    expired.credential_fingerprint_sha256 =
        Sha256::digest(&expired.certificate_chain_der[0]).to_vec();
    // Keep the protobuf's claimed future expiry: the actual signed leaf must be checked.
    for (label, value) in [
        ("wrong-key", wrong_key),
        ("wrong-principal", wrong_principal),
        ("wrong-csr", wrong_csr),
        ("forged-signature", forged),
        ("untrusted-ca", untrusted),
        ("expired-leaf", expired),
    ] {
        let bad = root.join(format!("{label}.pb"));
        fs::write(&bad, value.encode_to_vec()).unwrap();
        let out = root.join(format!("{label}-identity.json"));
        let installed = run(
            INSTALL,
            &install_args(&request_path, &bad, &ca, &out, "student-device"),
        );
        assert!(
            !installed.status.success(),
            "{label}: installer accepted invalid enrollment"
        );
        assert!(!out.exists(), "{label}: identity created");
        let bad_stage = std::env::temp_dir().join(format!("ClassMesh-Reject-{}", nonce()));
        let staged = run(
            STAGE,
            &[
                "--request",
                text(&request_path),
                "--result",
                text(&bad),
                "--trust-root",
                text(&ca),
                "--output-dir",
                text(&bad_stage),
            ],
        );
        assert!(
            !staged.status.success(),
            "{label}: authorizer accepted invalid enrollment"
        );
        assert!(!bad_stage.exists());
        println!("negative={label}; installer_and_stager=REJECTED; identity_created=false");
    }
    let (teacher_path, _teacher, _teacher_key) = request(root, "teacher", "teacher");
    let teacher_result_path = root.join("teacher-approved.pb");
    issue(&lab, &teacher_path, &teacher_result_path, "teacher");
    for (path, res, opposite) in [
        (&request_path, &result_path, "teacher"),
        (&teacher_path, &teacher_result_path, "student-device"),
    ] {
        let out = root.join(format!("role-{opposite}.json"));
        assert!(
            !run(INSTALL, &install_args(path, res, &ca, &out, opposite))
                .status
                .success()
        );
        assert!(!out.exists());
        let result = root.join(format!("role-{opposite}.pb"));
        assert!(
            !run(
                AUTHORITY,
                &[
                    "--role",
                    opposite,
                    "--request",
                    text(path),
                    "--ca-cert",
                    text(&ca),
                    "--ca-key-name",
                    &lab.key(),
                    "--output",
                    text(&result)
                ]
            )
            .status
            .success()
        );
        assert!(!result.exists());
    }
    for (path, res, role) in [
        (&request_path, &teacher_result_path, "student-device"),
        (&teacher_path, &result_path, "teacher"),
    ] {
        let out = root.join(format!("cross-credential-{role}.json"));
        assert!(
            !run(INSTALL, &install_args(path, res, &ca, &out, role))
                .status
                .success()
        );
        assert!(!out.exists());
    }
    assert!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            < u128::from(bundle.not_after_unix_ms)
    );
    println!(
        "negative=reuse_and_cross_role; result=REJECTED; system_trust_and_programdata=UNMODIFIED"
    );
}

#[test]
fn teacher_authorization_requires_proven_issuer_and_role_before_grant() {
    // Real Windows CNG keys and CLI executables. This would have failed against
    // the legacy result-only grant, which never verified the CA signature.
    const GRANT: &str = env!("CARGO_BIN_EXE_classmesh-student-authorize-teacher");
    let lab = Lab::new();
    let scratch = Scratch::new();
    let root = &scratch.0;

    let (student_request, _student, _student_key) =
        request(root, "student-device", "student_for_grant");
    let student_result = root.join("student-for-grant.pb");
    issue(&lab, &student_request, &student_result, "student-device");

    // Staging creates a zero-privilege StudentDevice without touching
    // ProgramData; all subsequent grants target ONLY this owned temp file.
    let stage = std::env::temp_dir().join(format!("ClassMesh-Grant-Stage-{}", nonce()));
    struct OwnedStage(PathBuf);
    impl Drop for OwnedStage {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("clean owned temporary stage");
            }
        }
    }
    let _stage = OwnedStage(stage.clone());
    success(
        STAGE,
        &[
            "--request",
            text(&student_request),
            "--result",
            text(&student_result),
            "--trust-root",
            text(&lab.cert()),
            "--output-dir",
            text(&stage),
        ],
    );
    let authorization = stage.join("state/authorization.json");
    let original_state = fs::read(&authorization).unwrap();

    let (teacher_request, teacher, _teacher_key) = request(root, "teacher", "teacher_for_grant");
    let approved_path = root.join("teacher-for-grant.pb");
    let approved = issue(&lab, &teacher_request, &approved_path, "teacher");
    let correct_ca = lab.cert();

    let authorized = |req: &Path, result: &Path, ca: &Path| {
        run(
            GRANT,
            &[
                "--request",
                text(req),
                "--result",
                text(result),
                "--trust-root",
                text(ca),
                "--authorization",
                text(&authorization),
            ],
        )
    };
    let assert_rejected_without_write = |label: &str, req: &Path, result: &Path, ca: &Path| {
        let before = fs::read(&authorization).unwrap();
        let output = authorized(req, result, ca);
        assert!(
            !output.status.success(),
            "{label} unexpectedly granted Teacher permissions"
        );
        assert_eq!(
            fs::read(&authorization).unwrap(),
            before,
            "{label} mutated authorization on rejection"
        );
    };

    // Fail closed on omitted proof, wrong issuer, modified signed leaf, wrong
    // CSR, and wrong role—even if the protobuf fingerprint is recomputed.
    let no_root = run(
        GRANT,
        &[
            "--request",
            text(&teacher_request),
            "--result",
            text(&approved_path),
            "--authorization",
            text(&authorization),
        ],
    );
    assert!(!no_root.status.success());
    assert_eq!(fs::read(&authorization).unwrap(), original_state);

    let untrusted_lab = Lab::new();
    assert_rejected_without_write(
        "untrusted-issuer",
        &teacher_request,
        &approved_path,
        &untrusted_lab.cert(),
    );
    let mut forged = approved.clone();
    *forged.certificate_chain_der[0].last_mut().unwrap() ^= 1;
    forged.credential_fingerprint_sha256 =
        Sha256::digest(&forged.certificate_chain_der[0]).to_vec();
    let forged_path = root.join("forged-teacher.pb");
    fs::write(&forged_path, forged.encode_to_vec()).unwrap();
    assert_rejected_without_write(
        "forged-leaf-signature",
        &teacher_request,
        &forged_path,
        &correct_ca,
    );

    let (other_request, _other_teacher, _other_teacher_key) =
        request(root, "teacher", "other_teacher_for_grant");
    assert_rejected_without_write("unbound-csr", &other_request, &approved_path, &correct_ca);
    assert_rejected_without_write(
        "student-not-teacher",
        &student_request,
        &student_result,
        &correct_ca,
    );

    // A valid signed and issuer-verified Teacher may get ONLY these two
    // existing control permissions; no credential or privilege is invented.
    let result = authorized(&teacher_request, &approved_path, &correct_ca);
    assert!(
        result.status.success(),
        "valid Teacher was rejected: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let state = DurableAuthorizationState::new(&authorization)
        .load()
        .unwrap()
        .unwrap();
    let grant = state
        .principal(PrincipalId(
            teacher.principal_id.clone().try_into().unwrap(),
        ))
        .expect("approved Teacher exists");
    assert_eq!(grant.kind, PrincipalKind::Teacher);
    assert_eq!(grant.permissions.len(), 2);
    assert!(
        grant
            .permissions
            .contains(&classmesh_security::Permission::ViewInteractive)
    );
    assert!(
        grant
            .permissions
            .contains(&classmesh_security::Permission::ControlInput)
    );
    assert_rejected_without_write(
        "duplicate-teacher",
        &teacher_request,
        &approved_path,
        &correct_ca,
    );
}
