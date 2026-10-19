# Phase 10 native Windows VM test gates

Run the portable worker/receiver telemetry qualifications in an isolated Windows
checkout. These commands are **not** live privileged Worker→Service IPC,
physical two-PC testing, GPU decode/render validation, or classroom-scale
acceptance.

The bounded helper `scripts/phase10-native-vm-gates.ps1` has four modes:
`Help` and `Plan` only print information; `Receiver` is **non-elevated**;
`MachineKey` is **Administrator-only** for the separately scoped Windows CNG
machine-key tests. It rejects the wrong security context before invoking
Cargo, and neither mode elevates the caller, changes Windows policy, installs
tools or runs the entire workspace with admin rights.

Example on a signed-in Windows ARM64 VM with native Rust and a locally
installed LLVM ARM64 `clang.exe` (adjust paths for that VM):

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\phase10-native-vm-gates-test.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\phase10-native-vm-gates.ps1 -Mode Plan
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\phase10-native-vm-gates.ps1 -Mode Receiver -ClangBin C:\LLVM\bin -TargetDir C:\temp\classmesh-target
```

Run the **same helper** with `-Mode MachineKey` only from a separate,
deliberately elevated PowerShell session. The process-scoped
`-ExecutionPolicy Bypass` shown here does not modify machine or user policy;
use only reviewed local scripts. Passing an explicit `-TargetDir` isolates
build outputs from Astra's own test worktrees.

The `Receiver` suite runs rustfmt, warnings-denied Worker/Service Clippy,
Worker library tests and all `classmesh-control` tests, including passive
codec, revocation and Service ingress integration regressions. The
`MachineKey` suite runs `classmesh-identity-win --lib` and exercises actual
machine-scoped non-exportable CNG P-256 keys and TLS certificate resolution.

**Do not substitute blanket `cargo test --workspace` as Administrator.**
Some other Phase 12 tests legitimately need protected NT, registry, SCM,
ProgramData or privileged executable access and retain independent physical
and least-privilege test gates. Report each permission-gated result separately,
not as a Phase 10 code regression or proof that classroom media runs on hardware.
