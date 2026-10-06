# Phase 12B4 System-Action Windows Qualification

## Scope

Phase 12B4 separates delivery/preflight evidence from physical execution evidence.

- **12B4a** is non-destructive tooling and retained evidence. It may identify the exact Windows build, validate bundle integrity, record environment facts, and assert the intended typed routing contract. It must not invoke Lock, Restart, Shutdown, `classmesh-service.exe`, or any power API.
- **12B4b** is the physical gate. Safe Lock execution requires explicit retained evidence. Restart/Shutdown requires an explicitly disposable Windows target before destructive execution may be attempted.

Hosted CI passing 12B4a is not physical system-action acceptance.

## Expected routing contract

- Lock: existing authenticated Service dispatch -> existing typed Worker IPC -> interactive `LockWorkStation` boundary.
- Restart: existing authenticated Service dispatch -> existing authorized `SystemActionExecutor` -> Service-side Win32 power controller.
- Shutdown: same Service-side power route as Restart.
- Service system-action dispatch queue remains bounded at capacity 1.
- Windows power acceptance is asynchronous: an accepted request is reported as `Accepted`, never fabricated as `Completed`.

## Bundle

The Windows CI artifact `classmesh-phase12b4-system-action-qualification-windows-x64` contains:

- `classmesh-service.exe` — exact release build used for qualification identity only; 12B4a never launches it.
- `phase12b4-system-actions.ps1` — non-destructive helper.
- this qualification guide.
- `PHASE12_SYSTEM_ACTION_RESULTS.md` — results template.
- generated `system-action-bundle-index.json` with SHA-256 hashes.
- `ci-evidence/system-action-preflight-evidence.json` from the hosted Windows runner.

## Integrity validation

From an extracted bundle:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase12b4-system-actions.ps1 -Mode ValidateBundle -BundleDir .
```

## Non-destructive preflight

To collect environment/integrity evidence without invoking a system action:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase12b4-system-actions.ps1 `
  -Mode CollectPreflight `
  -BundleDir . `
  -EvidenceDir .\preflight-evidence
```

`CollectPreflight` only reads the bundle, hashes the exact Service executable, and records Windows environment metadata. It never launches the Service executable and never calls Lock/Restart/Shutdown.

## 12B4b physical evidence

Keep Lock and destructive power evidence separate.

### Lock

A physical Lock test must retain enough evidence to show that the authorized request reached the interactive Worker path and the signed-in workstation actually locked. Because a lock can require credentials to recover the session, perform it only when interactive recovery is prepared.

### Restart / Shutdown

Do not run these on hosted CI or a non-disposable user VM. Destructive validation requires an explicitly disposable Windows target plus retained evidence spanning:

1. target identity and disposable-target approval;
2. exact bundle/build hashes;
3. authorized request ID/action;
4. `Accepted` response before the asynchronous OS action;
5. observed restart/shutdown and subsequent boot/power-state evidence;
6. post-action Service recovery where applicable.

A dry run, source review, mocked controller, or non-destructive preflight must never be reported as physical Restart/Shutdown acceptance.

## Independent gates

Phase 12 evidence does not close Phase 4, 6F, 7D/7H, 8D, 9F, or 10G.
