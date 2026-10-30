# Phase 11F4 Teacher UI Smoke Results

Status: **Pass — Phase 11 UI closeout complete**

## Phase 13 exact CI artifact prerequisite retest — 2026-10-29

PR #642 merged as `4dead76a8ba2f6004e9b5a9d03dee455210a5376`. Exact-head CI run `40853923424` passed Portable Rust and Windows Build and produced `classmesh-phase11f4-teacher-ui-windows-x64` (artifact id `12889571162`). The downloaded bundle index SHA-256 is `cc6f6eb144d43d8a34b27efb3c627a228443c5d0cd036b6f897e3d61f833d6ab`; its executable SHA-256 is `42c813446240afb6ab48923f38fa6c0fdb0cfc1fd91c29274b372adaad3db894`.

On VM1, the unchanged CI bundle passed schema-2 hash validation and `PreflightRuntime`. Its build toolset requires x64 Visual C++ runtime `14.51.36231.0`; the installed runtime was `14.51.36247.0` on Windows ARM64. Non-admin Session 1 `Smoke` passed after seven seconds with a responsive **ClassMesh Teacher** window and `main_window_observed=true`. The retained local smoke JSON SHA-256 is `53cb7007052aee6b8eec1d26485d402620e7a5e4ff00e1e68a94925084fa1ec0` (observed 2026-10-29T10:18:07Z); the process was cleaned up.

The same exact CI executable was then launched through the visible VM1 Windows desktop. The window appeared; Tab/Enter navigation reached Classroom, Focus, Presentation, Device Actions and Diagnostics. Empty-state text showed zero enrolled devices, idle presentation and no fabricated device diagnostics. Alt+F4 closed the visible test window. This is a limited current-artifact VM visual/keyboard retest. The earlier Phase 11 closeout below remains its own evidence. Fresh-clean Windows first-launch, full accessibility review for this artifact, signed installer deployment, Service/Worker prerequisite matrix and physical classroom qualification are still open.

## Initial 11F4b review

The initial green-CI artifact passed integrity and Session 1 launch smoke, keyboard traversal/activation, visible focus and truthful empty-state review on the connected Windows 11 ARM64 VM at 100% DPI. It found one blocking defect: the Diagnostics navigation label was clipped at the default window size.

That finding was retained before remediation and did not close any unrelated physical gate.

## 11F4c remediation

PR #327 removed the duplicated in-app `ClassMesh Teacher` heading from the navigation row, retained the product name in the native window title, switched the navigation row to wrapped layout, and established explicit 800x600 default / 600x420 minimum viewport intent.

- Portable Rust CI: **Pass**
- Windows CI: **Pass**
- CI run: `37189571622` (CI #1315)
- PR head tested: `a2ceb72fe5825e8d4ac00426eac3abaefc185ef7`
- Artifact: `classmesh-phase11f4-teacher-ui-windows-x64`
- Artifact ZIP SHA-256: `d746190e419e866478b0e62868c0a264e53673c36806767172afe131f3b9850f`
- Bundle index SHA-256: `e344a315a28450328cc280f5625bdf74c9920f707850bd14444be5bba9c36293`
- Teacher UI executable SHA-256: `4bf47f5785b872aba5d5a0ff4e8f91f365462cce5a0ec2fa139cb90c936a27df`

## Windows retest environment

- Device: connected Parallels Windows 11 VM
- OS architecture: ARM64
- Artifact architecture: x64, running through Windows emulation
- Interactive session: signed-in console Session 1
- Display: 1710x953
- System DPI: 96 (100%)
- Startup smoke: 5 seconds
- Process remained alive/responsive: **Pass**

The temporary Task Scheduler test task allowed execution while the VM reported battery power. No global Windows power or execution-policy setting was changed.

## 11F4c visual/accessibility retest

- Window title / responsiveness: **Pass**
- Default-size navigation: **Pass** — Classroom / Focus / Presentation / Diagnostics all fully visible
- Keyboard section traversal: **Pass**
- Visible keyboard focus: **Pass**
- Diagnostics keyboard activation: **Pass**
- Classroom empty state: **Pass**
- Focus empty state: **Pass** — requires a selected classroom device; no fabricated interactive session
- Presentation empty state: **Pass** — `Media: Idle`, no fabricated binding/profile/transport
- Diagnostics empty state: **Pass** — requires a selected classroom device; no fabricated evidence/override
- Narrow-window stress check: **Pass** — a programmatic forced resize below the declared normal minimum still kept all navigation labels visible; this is a stress observation, not a claim that external Win32 APIs must honor the normal interactive minimum-size constraint
- Control/media independence with a live device: not exercised by this standalone empty-state smoke; remains covered by the existing 11A/11E projection tests
- Unrelated physical gates: **unchanged/open**

## Retained evidence hashes

- Launch smoke JSON: `4f4459f0220daaba7437933eb74f680192965485fc14578ee35b987a33c2d6e3`
- Retest JSON: `48777b3a59c6736ee2b00bda2a247c0b3db8e7517cd07379882f98703696ea24`
- Default Classroom screenshot: `727baabe155e5dffe6c46223c022bfd60641b9661b473f3c10abcbb3f334304f`
- Tab focus Classroom: `2072f3b3b9688c77bedfde902aacd5e157818576d64c58858e63a4d5b7a1357a`
- Tab focus Focus: `54535bc8515983a37ea46145b0538ba9f62995516e59ca7271402c5601300857`
- Tab focus Presentation: `5d0cc562ae695c707a0ad266fa878365da630dcbc26963f93ff893658e7c0a60`
- Tab focus Diagnostics: `688d89735b1ff8370e133afab47d70deca253b55bef6ae1c5c67d64e732590da`
- Diagnostics activated: `ed9c5d89cde39be0886dcc703bde6c6c37fdc9c0c5cf69251be266b85930ed8d`
- Focus activated: `4d29581ac212b606f96d031f923ebc04154c9cc3372a3792d1c785e7bd35f087`
- Presentation activated: `1ebde5bb855ff630d78e507b3fa06bcaa28dd69da47b8c0a29b8c54fdea8ca3a`
- Narrow-window stress screenshot: `1f346097ccc35ce1b729b0361dd2fc7862571461dce6fbdc6a4315f6f3917885`

## Conclusion

- Phase 11 UI launch smoke: **Pass**
- Phase 11 visual/accessibility review at the tested Windows configuration: **Pass**
- Runtime-confirmed navigation finding: **Resolved by PR #327 and clean retest**
- Phase 11 closeout: **Pass**

This result closes only the Phase 11 Teacher UI gate. It does **not** qualify Phase 4, 6F, 7D/7H, 8D, 9F, or 10G.
