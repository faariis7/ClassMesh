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

The schema-2 index records bounded file metadata, SHA-256 hashes and the CI host's MSVC toolset version. Validate it before launch:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 -Mode ValidateBundle -BundleDir .
```

`-ExecutionPolicy Bypass` is process-local here; it does not change the machine or user execution policy.

Check the installed **x64** Visual C++ Redistributable before launching the UI:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 -Mode PreflightRuntime -BundleDir .
```

The helper requires x64 Windows or Windows ARM64 with x64 emulation, then reads the x64 runtime version from the Windows Registry and requires it to be at least the bundle's recorded MSVC toolset version. Missing, malformed, conflicting or older runtime records fail with an actionable diagnostic; it never installs software. Microsoft documents the [same-or-later version rule and x64 package for ARM64 devices](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) and the [runtime Registry values](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files). Registry presence is a prerequisite check; the launch smoke below still verifies a real window.

## Interactive launch smoke

Run from a signed-in interactive Windows user session. Session 0 is intentionally rejected so an invisible service-session launch cannot be mistaken for UI validation.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 `
  -Mode Smoke `
  -BundleDir . `
  -EvidenceDir .\evidence `
  -StartupSeconds 5 `
  -LeaveRunning
```

The helper checks the x64 runtime, requires the process to remain alive for the bounded startup interval, and requires a responsive **ClassMesh Teacher** top-level window in the same session before writing `evidence\launch-smoke-evidence.json`. `main_window_observed` is always `true` on success. The old `-RequireResponsiveWindow` switch remains accepted for existing commands, but the window check is now mandatory. A successful launch smoke does **not** set visual/accessibility acceptance.

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
