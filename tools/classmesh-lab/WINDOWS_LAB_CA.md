# Windows Lab CA and StudentDevice enrollment

Parent: Draft PR #689 at `dd15214d6302f8e422616312185c487af195618c`.
Delivery tracker: #688 (M2 enrollment subset only).

`classmesh-lab-ca` is a real Windows-only executable using the existing
`CngMachineKey` / `CngRcgenSigningKey` implementations. It creates a machine-scoped,
signing-only ECDSA P-256 key with export policy zero and a self-signed, 48-hour
lab CA (path length zero). The CA certificate and signed ownership receipt are
public files in a new direct child of the invoking account's TEMP. No private
key is exported, no Windows certificate store is modified, and no Service,
Teacher, Worker, QUIC, Clipboard or FileTransfer configuration is changed.

## Build and bootstrap

Use an existing Visual Studio x64 developer shell. The explicit x64 toolchain
also works under Windows 11 ARM64 emulation; it avoids the parent attempt's
ARM64 `ring`/clang blocker without installing or changing a compiler.

```powershell
cargo +stable-x86_64-pc-windows-msvc build -p classmesh-lab --bins
$bin = Join-Path (Get-Location) 'target\debug'
$id = [Guid]::NewGuid().ToString('N')
& "$bin\classmesh-lab-ca.exe" bootstrap --lab-only --session $id
$ca = Join-Path $env:TEMP "ClassMesh-LabCA-$id\ca.der"
$caContainerName = "ClassMesh-LabCA-$id"
& "$bin\classmesh-lab-ca.exe" inspect --lab-only --session $id
```

Without `--session`, bootstrap generates a cryptographically random 128-bit
session and prints it. `inspect` and `cleanup` require the printed session.
Every operation requires `--lab-only`. Existing directory, files or CNG key
cause rejection; there is no overwrite, adoption or production-key-name option.

## Real enrollment sequence

Create a separate, new TEMP workspace for public request/result files. Preserve
the printed PrincipalId, CNG key name and hashes as operator evidence.

```powershell
$work = Join-Path $env:TEMP ('ClassMesh-Enrollment-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -ErrorAction Stop
$request = Join-Path $work 'student-request.pb'
$result = Join-Path $work 'student-approved.pb'
& "$bin\classmesh-enrollment-request.exe" --role student-device --display-name VM1-Lab --output $request
& "$bin\classmesh-enrollment-authority.exe" --role student-device --request $request --ca-cert $ca --ca-key-name $caContainerName --output $result --lifetime-hours 1
$identity = Join-Path $work 'machine-identity.json'
& "$bin\classmesh-enrollment-install.exe" --role student-device --request $request --result $result --trust-root $ca --identity-output $identity
$stage = Join-Path $env:TEMP ('ClassMesh-Student-Stage-' + [Guid]::NewGuid().ToString('N'))
& "$bin\classmesh-student-authorization-init.exe" --request $request --result $result --trust-root $ca --output-dir $stage --bind-address 127.0.0.1:5151
```

Check `$LASTEXITCODE` after each executable before advancing. The automated
native test below performs these checks and guarantees its owned cleanup.
Teacher remains the default role in the existing request/authority/installer;
StudentDevice requires explicit opt-in on all three.

The stager now **requires `--trust-root`** (repeatable, at most 16). This intentional
fail-closed tightening prevents an EnrollmentResult from establishing trust in
its own issuer. Both installer and stager verify CA signatures using rustls/
WebPKI, actual signed certificate validity/expiry, current CSR proof-of-possession,
CSR and leaf public components, stable principal identity, CSR digest and credential fingerprint.
The existing CNG resolver then checks the leaf against the non-exportable
machine key. Certificate expiry is encoded to seconds; result expiry must agree
at that precision. No DNS-peer or revocation proof is claimed by this offline
staging check, and the network authentication implementation is unchanged.

The successful output consists of:

- `$work/machine-identity.json`: PrincipalId, CNG key reference, public chain,
  explicit public trust roots and expiry.
- `state/authorization.json`: one StudentDevice principal with **zero privileged
  command permissions**.
- `config/control-runtime.json`: version 1, `127.0.0.1:5151`, multicast null.

Identity is installed before authorization/config generation. These two fresh
TEMP workspaces keep that sequence while respecting the authorizer's new-directory
requirement. They are disposable staging files, not an authorized ProgramData installation.

## Native tests, ownership and cleanup

Run the real integration tests in an otherwise idle Windows lab session:

```powershell
cargo +stable-x86_64-pc-windows-msvc test -p classmesh-lab --test lab_ca_windows -- --nocapture --test-threads=1
```

The tests invoke the five actual executables, use real CNG signatures and real
on-disk persistence, reload the identity and authorization, and check zero device
permissions. They clean their own newly generated CA/device/Teacher keys and
fresh staging trees through guards even on assertion failure. They do not use
mock certificates or mock CNG. Deliberately invalid negative certificates are
real signed/modified DER material, never positive-path placeholders.

To record a pinned run, root-store snapshots, executable SHA256 and full output,
use `scripts/Invoke-WindowsLabEnrollment.ps1 -RepositoryRoot <checkout>
-ExpectedSha <40-hex SHA> -EvidenceDirectory <new TEMP child>`. It requires an
explicit elevated session, a clean tool checkout, no active ClassMesh test/build
or running service, and an exclusive `Global\ClassMesh-Lab-Exclusive` mutex.
It uses the existing x64 compiler and a target directory in that checkout only.
It changes no machine execution policy or persistent build environment. On a
Restricted-policy lab VM, run the verified pinned helper body through the
already authorized PowerShell `-Command` execution channel instead of changing
the machine policy; the standalone native CLI itself needs no script policy change. If
required dependencies are absent, run the ordinary build once before its
offline test invocation. Evidence and build outputs remain for inspection.

For the CA resources created by bootstrap:

```powershell
& "$bin\classmesh-lab-ca.exe" cleanup --lab-only --session $id
```

Cleanup accepts no arbitrary path or key. It checks the fixed TEMP session path,
reparse-point exclusion, exact known file set, CA/public-key hashes and a CNG
signature binding the receipt to the directory. Only then does it delete that
key, the two known files and the empty directory. Unknown files, absent/forged
receipt, changed certificate or existing unrelated key are refused. The receipt
prevents accidental adoption/tampering; it is not a boundary against a privileged
operator who already controls that CNG signing key.

Bootstrap error recovery removes only files and the key it successfully created
in that invocation; it never deletes a collided key or directory. A process/OS
interruption during cleanup may leave public files after key deletion; the tool
fails closed rather than adopting unverifiable leftovers. Investigate such a
receipt explicitly. For an unmodified completed session normal cleanup is
verified by native tests.

For a manual enrollment, the request tool owns a separate device key; CA cleanup
does not delete it. Record its successful request's exact generated key name,
verify the staging identity refers to that key, then delete only that known test
key with Windows CNG and remove only the newly created `$work` / `$stage` trees.
Do not enumerate/delete keys by a broad prefix. Prefer the automated integration
exercise when retaining staged identity is unnecessary.

## Proven behavior and Service handoff

RED/GREEN and VM evidence are recorded in [WINDOWS_LAB_CA_RESULTS.md](WINDOWS_LAB_CA_RESULTS.md).
The native suite rejects:

- Certificate with another CNG/CSR public key; wrong PrincipalId or CSR digest.
- Tampered certificate signature with a recomputed result fingerprint.
- Correctly signed but untrusted CA chain; expired signed leaf with a forged
  future expiry in the result.
- Reused request/result/identity/staging files and pre-existing CA keys/directories.
- Opposite enrollment CLI role and Teacher/StudentDevice credential cross-pairing.
- A forged cleanup receipt or an unexpected file in the CA directory.

Service developer next steps, outside this PR:

1. Reproduce enrollment at the pinned child SHA, verify CSR/result hashes and
   device CNG key identity/export policy; preserve the CA's explicit trusted
   provenance. Do not import this lab root into Windows Trusted Root Store.
2. Use the reviewed protected installer/provisioner to establish the real
   ClassMesh ProgramData identity, authorization, runtime config, ACL/ownership
   and rollback/Registry anchors. TEMP staging alone supplies no such authority.
3. Independently approve a Teacher enrollment before assigning ViewInteractive /
   ControlInput. The older `classmesh-student-authorize-teacher` grant utility is
   **not hardened or qualified by this patch**: it consumes result metadata and
   needs separate review of issuer/role provenance before use. A StudentDevice
   result must never be treated as Teacher approval. No Teacher permissions are
   inserted by this exercise.
4. Under the authorized SCM path, verify LocalSystem can open the intended
   machine CNG key and attested state; register/start only the disposable test
   service, retain startup/authorization logs, and prove authenticated Teacher
   control and Service-owned Worker launch. Those operations are not performed
   here. Bind remains loopback until a separately reviewed runtime/network step.
5. Clean only those separately owned SCM/installer resources after testing.

MVP #688 M2 as a whole, real SCM/LocalSystem operation, authenticated remote
Teacher/Worker behavior, signing/production CA trust, security review and physical
qualification remain separate gates. Successful enrollment does not close them.
