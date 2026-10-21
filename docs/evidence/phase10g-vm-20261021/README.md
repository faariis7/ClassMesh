# Phase 10G VM synthetic evidence — 2026-10-21

**Classification: SYNTHETIC ONLY; PHYSICAL 10G UNQUALIFIED.** These runs are
not actual 5/10/20/30 independent receiver machines, not physical network or
GPU/codec performance tests, and not grounds for choosing production transport.

## Exact source

- Source: GitHub Actions run **39601537031**, PR #593, validated exact PR head
  `43462b166dd3fb735565b6159b782149d17c77dc`. That PR was Squash-merged
  on main as `ed80fad4df935be6e3f4b8b821c3dba4a04ca914`.
- Artifact name: `classmesh-phase10g-adaptive-qualification-windows-x64`.
- `classmesh-adaptive-controller-benchmark.exe` SHA-256:
  `88bc23c56b8a597fabf75082ea7736128e2871d5a0933e96aa1c2c920ba0eb0a`.
- File hash was checked on both guest VMs after copying the **same x64 binary**.
  Windows 11 ARM64 ran it under **x64 emulation**, *not* natively compiled ARM64.
- Native Rust build attempt on VM1 could not proceed because `ring` required
  `clang`, missing from that guest; rather than alter the VM or bypass checks,
  the already-CI-qualified x64 artifact was used.

## Two distinct Windows VM runs

- **VM1**: VMPal Windows 11 24H2 ARM64, guest build 26100.9711.
- **VM2**: VMPal Windows 11 25H2 ARM64, guest build 26200.
- Each guest ran `classmesh-adaptive-controller-benchmark.exe --receivers N
  --rounds 30` separately, for N = 5, 10, 20, 30, with exit code 0.
- All eight results explicitly report `physical_qualification=false`,
  `production_default_selected=false`, and
  `synthetic_invariants_passed=true`.
- One degraded receiver leaves **N−1** high-quality peers unaffected; silent
  telemetry expires one receiver without repeated route churn; recovery
  requires hysteresis; noisy inputs cause zero tier changes; unresolved
  transport/rendition candidates remain blocked.
- Logs are copied verbatim from guests and stored alongside this note.
  Identical results/hashes across guests demonstrate a deterministic benchmark,
  **not independent physical network behavior or measurement**.

## SHA-256 of guest log files

Each row has **two separate log files**, `vm1-synthetic-N.txt` and
`vm2-synthetic-N.txt`, and both happen to have identical bytes.

| N | SHA-256 of each VM log |
|---:|---|
| 5 | `279c4a08dda158e7be9af28ec6c49e20618ced50dfa27100828fe5b111b2298f` |
| 10 | `d01e1db78e155f1bba1037ecfc2f00bf4ecfeda520c785c8256792fb89b1c994` |
| 20 | `c03eb7c35342a152d44083af08b92f05fb529a86ba6f098c10f9301d0b0f5158` |
| 30 | `365ec4efccd563e3b667d89d50e3828782bdd048d97364b061e158254af83fc2` |

## Still open: physical acceptance

To close [Phase 10G issue #288](https://github.com/faariis7/ClassMesh/issues/288),
execute the documented 5/10/20/30 receiver scenarios on actual connected
classroom devices (as feasible) and retain exact Teacher and receiver logs,
network/transport/recovery metrics, hardware, OS, codec and binary hashes,
plus at least a 30-minute soak at the largest feasible real scale. Review
dependent Phase 4/7/8/9 physical gates independently. Do not declare a
production default from the above VM synthetic run.
