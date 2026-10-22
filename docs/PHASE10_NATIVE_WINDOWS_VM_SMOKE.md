# Phase 10 native Windows telemetry smoke bundle

## Purpose

Validate the **exact Windows x64 native test executable from the same
ClassMesh CI commit** on a second Windows machine or virtual machine without
requiring an ARM64 C/LLVM toolchain or rebuilding Rust dependencies.

This is a software smoke test of real Windows kernel named-pipe identity:
the binary starts an independent child Windows process, verifies real client
PID/session as reported by Windows, transfers a complete fixed 136-byte
diagnostic record, rejects stale/revoked peers after idle reads, and checks
that a duplicated original process HANDLE remains valid after the original
wrapper drops.

## Reproducible artifact

From a successful GitHub Actions Windows Build job, download the artifact

    classmesh-phase10-native-telemetry-smoke-windows-x64

The bundle contains:

- classmesh-win32-native-tests.exe: frozen from the default-feature
  cargo test --workspace Windows x64 build before optional feature variants.
- phase10-native-telemetry-smoke.ps1: Windows-only runner.
- native-smoke-index.json: exact CI source commit, binary size and SHA-256.
- hosted-ci-smoke-result.json: CI checks, not physical classroom proof.

The manifest has a strict schema. Tampered/missing executables, forged
source revisions, wrong byte counts and symbolic-link substitutions fail
closed before any binary executes. Confirm the source SHA against the
GitHub Actions run itself: it is metadata, not repository attestation.

After extracting onto a **disposable Windows VM**:

    .\phase10-native-telemetry-smoke.ps1 -Mode ValidateBundle -BundleDir .
    .\phase10-native-telemetry-smoke.ps1 -Mode Run -BundleDir .

Use a fresh -ResultsDir if retaining outputs. A successful run produces
native-smoke-result.json recording the source SHA and names of four
native regression tests. It never sets Service flags, registers Windows
services, changes transport defaults or enables Teacher control.

A Windows-on-ARM VM can run the x64 binary through OS emulation if the
required Win32 APIs are available. A failed execution because of OS or
runtime compatibility is an environment finding, not evidence of a
production classroom regression.

## Boundaries

This smoke is not a live production Service/Worker pair, credential-enrolled
Teacher, actual classroom video/latency/packet-loss test, 5/10/20/30
physical receiver scale test, or 30-minute Wi-Fi soak. Phase 10G Issue
#288 and Phase 4/7/8/9 physical gates remain OPEN. The privileged
CLASSMESH_ENABLE_PHASE10_TELEMETRY Service opt-in stays disabled by default.

scripts/phase10-native-telemetry-smoke-tests.ps1 contains strict negative
manifest tests using a deliberately non-executable fixture.
