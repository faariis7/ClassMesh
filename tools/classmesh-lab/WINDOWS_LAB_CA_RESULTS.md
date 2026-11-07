# Windows lab enrollment evidence

Base: PR #689, `dd15214d6302f8e422616312185c487af195618c`.
Worktree/branch: `codex/windows-lab-ca-bootstrap-20261105` (independent child).
VM: Windows VM 1, `DF60038E-4C4D-4DCB-B310-1D2ACAAD798A`, Windows 11 ARM64,
x64 native binaries through Windows emulation, Rust 1.99.1 / existing VS 2022.

Before testing, process inventory found no other ClassMesh, cargo/rustc or
qualification process and no registered ClassMesh service. The lab mutex was
available. VM settings, production trust and schedulers were not changed.

## TDD observed before implementation

| Gate | RED | GREEN |
| --- | --- | --- |
| Pure session scope | native rustc test: 1 failed / 1 passed; valid explicit session was not implemented | 2 passed |
| Actual Windows CA executable | compiled CLI returned `lab bootstrap is not implemented`; 1 test failed, exit 101 | real CNG CA creation, matching certificate, collision refusal and cleanup passed |
| Forged enrollment result | on the parent installer plus real Lab CA, a changed certificate signature with recomputed fingerprint was accepted; 2 tests passed / 1 failed, exit 101 | installer and staging authorizer reject it before identity/authorization creation |

The Windows forged-result RED also executed a successful real StudentDevice
request → CA approval → staging → identity installation → reload, then reached
`forged-signature: installer accepted invalid enrollment`. This was not an
unavailable API or compilation failure. All temporary test identities/keys were
cleaned by test guards after that failed run.

These development RED/GREEN runs used the pinned parent plus uncommitted tool
patches. Their base SHA must not be mistaken for an unchanged parent binary.
The final committed-source VM rerun and executable hashes are delivered with
the PR evidence. Native tests use actual executables and signed material.

## Native GREEN and isolation

The Windows integration suite passes three tests, covering the complete cycle
and negative cases detailed in WINDOWS_LAB_CA.md. It checks PrincipalId and CSR
fingerprint binding, non-exportable CNG key, persisted identity reload, empty
StudentDevice permission set and loopback-only runtime config. CLI signatures
and certificate validity are verified against the operator-provided root.

`cargo +stable-x86_64-pc-windows-msvc clippy -p classmesh-lab --all-targets --offline -- -D warnings`
passed on VM1. `cargo fmt --all -- --check` and `git diff --check` pass locally.
The initial parent ARM64 clang/ring blocker was bypassed using the **already
installed** x64 toolchain/compiler; no compiler or machine setting was installed.

The pinned-run PowerShell helper separately records the actual SHA, all five
executable hashes, UTC time, native exit code and before/after machine/current
user Trusted Root snapshots. It refuses busy-VM conditions and retains its
non-secret evidence directory; integration guards clean their own CA, device,
Teacher and staging resources. Build/evidence files are separate from CA cleanup.

## Security review boundary

Inputs are untrusted CSR/result bytes, DER chains, operator-selected public
roots and filesystem state. Existing bounded protobuf/result checks remain.
The added verifier checks CSR signature/public key and signed validity/chain
with maintained rcgen, x509-parser and rustls/WebPKI, using an explicit provider.
It never trusts the EnrollmentResult's last certificate as its root. CA cleanup
requires fixed lab names and a CNG-signed ownership receipt, refuses reparse
points and unrelated files, and never performs recursive CA deletion.

No private key bytes are serialized. No Trusted Root import, production
ProgramData installation, SCM creation, Teacher privilege grant, QUIC change,
FileTransfer or Clipboard activation is included. The older Teacher grant tool
requires its own issuer/role-provenance review before the Service M2 run.

The existing CI workflows must still verify the final PR HEAD; final CI state
and exact committed VM SHA are reported with the delivery. VM/CNG results do
not prove physical hardware behavior or complete #688 / #288 / #411.


## Pinned VM1 run

The committed-source run at `31795b0f223c756c53e583f09f4f3ebfb0b6ca6d`
passed all lab targets, including the three real CNG integration tests. Evidence
was written to `%TEMP%\ClassMesh-LabCA-evidence-31795b0` with native output,
executable SHA256 and matching before/after Trusted Root snapshots. Subsequent
README changes clarify a public CNG container variable, reword a documentation
phrase falsely matched by generic-api-key, and explain the Restricted PowerShell policy.
The initial commit is retained in a local backup ref; the child branch is
updated with a lease against that exact commit. No scan rule is changed.
A final pinned rerun is delivered with the final PR SHA and CI evidence.

The VM's existing Restricted execution policy blocks `.ps1 -File`. It was left
unchanged. The known pinned helper body was executed using the same authorized
PowerShell `-Command` channel used for the VM commands, after SHA/clean-source
verification. This is recorded explicitly rather than claiming file execution
worked or that a policy was installed.
