# Phase 11F4 Teacher UI Windows Smoke

## Scope

This check verifies the delivered Windows Teacher UI artifact only. It does **not** qualify media transport, multicast, classroom scale, adaptive networking, or any other open physical gate.

The smoke uses the exact release executable built by Windows CI and retained in the `classmesh-phase11f4-teacher-ui-windows-x64` artifact.

## Bundle integrity

The bundle contains:

- `classmesh-teacher-ui.exe`
- `phase11f4-teacher-ui-smoke.ps1`
- this guide
- `PHASE11_TEACHER_UI_SMOKE_RESULTS.md`
- generated `teacher-ui-bundle-index.json`

The index records bounded file metadata and SHA-256 hashes. Validate it before launch:

```powershell
.\phase11f4-teacher-ui-smoke.ps1 -Mode ValidateBundle -BundleDir .
```

## Interactive launch smoke

Run from a signed-in interactive Windows user session. Session 0 is intentionally rejected so an invisible service-session launch cannot be mistaken for UI validation.

```powershell
.\phase11f4-teacher-ui-smoke.ps1 `
  -Mode Smoke `
  -BundleDir . `
  -EvidenceDir .\evidence `
  -StartupSeconds 5 `
  -LeaveRunning
```

The helper requires the process to remain alive for the bounded startup interval and writes `evidence\launch-smoke-evidence.json`. A successful launch smoke does **not** set visual/accessibility acceptance.

## Visual and accessibility review

While the process remains open, review the UI-specific surfaces:

1. Window title is **ClassMesh Teacher** and the app is responsive.
2. Keyboard navigation can reach the Classroom, Focus, Presentation, and Diagnostics sections without pointer-only dependence.
3. Focus indication is visible and section selection is distinguishable without relying only on subtle color differences.
4. Text is readable at the Windows scale in use; labels and buttons are not clipped.
5. Empty states are clear and do not imply engine or network state that is unavailable.
6. Classroom control-presence and media-health wording remain independent.
7. Focus does not fabricate a selected device or interactive state.
8. Presentation idle state does not fabricate a binding/profile or transport choice.
9. Diagnostics does not fabricate a selected device, evidence, or troubleshooting default.
10. No UI action silently closes Phase 4/6/7/8/9/10 physical gates.

The standalone smoke shell may have no live classroom devices attached. Do not add synthetic production defaults merely to populate screenshots; live/data-dependent behavior remains covered by the established view-model/action tests.

## Evidence and conclusion

Record observations in `PHASE11_TEACHER_UI_SMOKE_RESULTS.md`. Keep launch smoke and visual/accessibility conclusions separate.

Only Phase 11 UI-specific exit criteria may be closed from this evidence. The following remain independent until their own physical evidence exists:

- Phase 4 / Issue #3
- Phase 6F / Issue #108
- Phase 7D/7H / Issue #153
- Phase 8D / Issue #276
- Phase 9F / Issue #281
- Phase 10G / Issue #288
