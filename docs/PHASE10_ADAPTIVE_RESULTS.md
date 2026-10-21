# Phase 10G Adaptive Controller Results

Status: **PENDING PHYSICAL EXECUTION**

Hosted CI and synthetic benchmarks do not establish physical qualification or select production defaults.

## 2026-10-21 Windows VM synthetic qualification (not physical)

Verified Windows 11 **24H2 VM1** and **25H2 VM2**, both ARM64 with the
same exact CI-built **x64 binary under emulation**, against **5, 10, 20 and
30 synthetic receivers at 30 rounds per count**. All eight runs exited
successfully with `synthetic_invariants_passed=true`,
`physical_qualification=false`, `production_default_selected=false`;
a single weak or silent receiver remained isolated while N-1 peers stayed
High; borderline/noisy samples never flapped the quality tier.

Source CI run `39601537031` / PR #593, binary SHA-256
`88bc23c56b8a597fabf75082ea7736128e2871d5a0933e96aa1c2c920ba0eb0a`.
Original guest outputs, per-file SHA-256 and environment limitations are in
[`docs/evidence/phase10g-vm-20261021/`](evidence/phase10g-vm-20261021/README.md).
This adds cross-VM Windows execution evidence; it is **not** 5/10/20/30
real receiver machines, a live network test, media performance validation
or the required largest-feasible-scale 30-minute soak. The physical scale
matrix and all unresolved production-default decisions below remain pending.

## Environment

- Date/time:
- Teacher machine:
- Receiver machines:
- Network/switch/AP:
- Build commit:
- Media workload/profile:
- Duration:
- Physical gates already qualified:
- Notes:

## Scale matrix

| Receivers | Weak-client isolation | Noisy-sample hysteresis | Congestion/latest-frame-wins | Invalid/stale telemetry | Path-gate behavior | Resource stability | Result |
|---:|---|---|---|---|---|---|---|
| 5 | pending | pending | pending | pending | pending | pending | pending |
| 10 | pending | pending | pending | pending | pending | pending | pending |
| 20 | pending | pending | pending | pending | pending | pending | pending |
| 30 | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available |

## Evidence references

For each executed row record:

- manifest path/hash;
- Teacher log path/hash;
- exact per-receiver evidence set;
- network/topology/recovery/encoder evidence when available;
- observed profile/cohort changes;
- any candidate path/rendition decisions and the physical gate evidence that allowed or blocked them;
- anomalies and reruns.

## Qualification decision

Phase 10G qualified: **UNDETERMINED**

## Production defaults

- one-to-one transport: **UNDETERMINED**
- wired multicast viability: **UNDETERMINED**
- Wi-Fi fan-out strategy: **UNDETERMINED**
- relay/SFU default: **UNDETERMINED**
- multi-rendition count: **UNDETERMINED**

Do not replace missing physical evidence with CI results or synthetic benchmark output.
