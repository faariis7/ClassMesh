# ClassMesh Agent Handoff

## QUICK RESUME — authoritative GitHub Live 2026-10-14 after #482

**Main** `6d6b71a0c596eecd010121b36d6ca526813dd2d6`. **Merged, exact-head Portable + full Windows CI green:** #480 (`8b333b2`, run `38601169040`) documents real native security fail; #481 (`4ce3afe`, run `38602651786`) compares an inert zero-filled anonymous `PAGE_READONLY` section created read-only in a **separate same-session child**; #482 (`6d6b71a`, run `38603907410`) demonstrates `VirtualProtect(PAGE_READONLY)` on one parent's view leaves an original `PAGE_READWRITE` section eligible for a new writable view. Local Synology Rustfmt, workspace Clippy `-D warnings` and full tests were green for the corresponding code heads.

**CRITICAL UNMERGED RED SECURITY GATE:** #477 (head `b0d8b91890c62a0b065b808590ebf055e97a0843`) hosted Windows CI `38594235925` FAILED because child-side `DuplicateHandle(FILE_MAP_WRITE)` from a `FILE_MAP_READ` HANDLE to the original `PAGE_READWRITE` anonymous section **produced an actually writable mapping**. Keep #477 OPEN and RED; do NOT weaken its hard assertion, claim cross-user privilege escalation, or use the proposed short-lived section as a secret bootstrap. The #481/#482 green comparison tests are diagnostic findings, NOT an authorization for keys. Blocker #479; design qualification #465; tracking #328.

**Next:** independent security-review of a **different** bootstrap approach, especially an independently authenticated outbound v12 channel with strict Service identity and exact launched Worker HANDLE, SID/session, generation, current control/grants and challenge/replay proof. Before ANY HMAC key transfer demand actual privileged Session 0/LocalSystem→interactive Worker inert positive + negative/teardown tests. Existing v12 named pipe remains inbound-only and has NO authenticated Service→Worker key delivery. **Production generic IPC v11 ClipboardRead still failure-only**; no actual payload, Teacher result, VM2, 2-PC, GPU/classroom/UX/accessibility gates are closed. Mac unavailable and VM2 recorded over its disk quota: do not resume/resize VM2 without resource investigation. Older blocks below archival.

---

## QUICK RESUME — GitHub Live 2026-10-14, after PR #474

**Authoritative main:** `bdcc88b1f01f836d9c6e1d2a3f02de1c0d63e8eb`. **No open PRs**. All #463/#464/#466/#468/#470/#471/#472/#473/#474 merged; do not repeat them. #473 exact-head hosted run `38556156734` **Portable Rust and Windows Build SUCCESS**, #474 run `38557805601` **both SUCCESS**. #473 established only same-session read-only inert section mapping in a spawned child; #474 tested a decoy unable to use the target-only HANDLE number. Neither qualifies LocalSystem Session-0 to interactive launched Worker, real key secrecy, native authorization or payload transfer.

**Current/Next:** Phase **12E18c3** qualification before choosing any real Service→Worker per-request HMAC-key bootstrap. Read the top of `docs/WORK_PLAN.md`, `docs/IMPLEMENTATION_STATUS.md` and `docs/PHASE12E18C_BOOTSTRAP.md`, plus Issues #328/#465. Obtain safe privileged cross-session *inert* positive+wrong-process/wrong-session+revocation/cleanup evidence using an actually owned launched Worker process HANDLE; security-review the outcome before choosing a short-lived targeted memory section or independently authenticated outbound v12 channel. Never put secrets/transferable bearer HANDLEs on generic v11, disk, registry, argv, logs or environment. Existing inbound-only v12 listener cannot send a key/challenge.

**Still absent:** real v12 key provisioning and authenticated version negotiation attached to OS peer/current grants, zeroizing/cancel-safe OVERLAPPED **payload** ReadFile with CancelIoEx completion drain, native Worker Unicode ClipboardRead and a Teacher success result. **Production v11 ClipboardRead remains failure-only/unavailable.** All physical 2-PC/GPU/classroom/Wi-Fi/monitoring/adaptive/security/visual-accessibility gates OPEN. Internal transient HMAC state zeroization in `ring` has NOT been proved simply because caller-owned key data is wiped.

**Resource caution:** Mac Data ~**13 GiB free / 97% used**, VM2 virtual disk **56.7/56 GB**, VM1+VM2 currently suspended. Do not resume VM2, expand disks, erase snapshots or install large guest tooling without first resolving storage. Use Synology and GitHub Windows CI for initial inert code tests; hosted CI does not prove privileged cross-session behavior or physical acceptance.

**Discipline:** GitHub Live first, living plan before coding, narrow test-led PR, Rustfmt/workspace Clippy -D warnings/workspace tests, independent security review and latest-exact-head Portable Rust AND full Windows Build success before routine squash merging. Older handoff notes below are historical, not live state.
---

## QUICK RESUME — verified main after #468 (2026-10-14)

**GitHub Live checkpoint:** `main=d3f1daa9df92aa490cdd71a3f5aec86d1a5e4064`; PR #468 12E18b HMAC challenge helper **squash merged**, exact-head `d994700` run `38544709117` Portable Rust **SUCCESS**, Windows Build **SUCCESS**. PR #463/#464/#466/#467 likewise merged; do NOT repeat E17/E18a. Isolated Service-issued one-shot version- and six-field-bound ring HMAC proof, fresh OS nonce, 2500ms deadline/cancellation, MAC-before-policy, panic-safe owned key wiping; local 11 tests × 30 loops (330 cases) passing, full Synology fmt/Clippy/workspace tests passing. Independent native VM testing was NOT run on #468 because Mac only ~14 GiB free and VMPal VM2 exceeds disk quota.

**Current/Next:** independent 12E18c bootstrap design in `docs/PHASE12E18C_BOOTSTRAP.md`. Before coding Service↔Worker secret transfer, prove actual launched Worker cross-session Handle duplication or alternative separate authenticated v12 control channel with targeted OS PID/session, live SessionProcess HANDLE, replay/timeout/grant revocation and zeroizing cleanup. Existing future-v12 listener is **inbound-only** and not able to send a challenge; do not send the 32-byte key or a bearer-capability handle over legacy v11. Ring HMAC internal transient state zeroization is not confirmed; review before production keys. Native Windows OVERLAPPED payload ReadFile with CancelIoEx + completion drain and Worker clipboard read/Teacher response remain UNSOLVED. v11 is failure-only, native clipboard E2E and physical two-PC/GPU/classroom/accessibility gates OPEN. CI/security review required for every code PR before Squash.

**Resource safety:** VM2 is suspended with virtual disk limit 56 GB exceeded, VM1 suspended, Mac Data volume 97% used (~14 GiB free). No random VM resumption, resizing or snapshot deletion. Source of truth GitHub Live; all earlier dated text is archival.

---


## QUICK RESUME — Phase 12E18b unmerged 2026-10-14 (live branch)

**Baseline:** Latest `main` `4cb0d5551d0bae866212e654a86e4e1bece20543` after merged #463/#464/#466/#467; no open earlier v12 PR. Branch `feat/phase12e18b-v12-hmac-gate` in `/tmp/classmesh-e18b` on Mac has test-first isolated new `ipc_sensitive/v12_challenge.rs`, with `ring` HMAC-SHA256, fresh OS nonce, exact v12 version, all six request/Worker identifiers, one-time proof, deadline, current Service-owned grants and cancel wipe. Plan was committed first `8d609ea`; RED test commit `2086543` produced expected missing-module compilation failure in Synology; implemented and local GREEN, plus tampered transcript/cross-challenge test. Synology all-workspace Rustfmt/Clippy -D warnings/tests PASS on the updated local files. Hosted Portable+Windows CI, security review and merge **NOT YET VERIFIED** in this checkpoint. Verify PR state live; never infer merge.

**Still NOT done:** Secure Service→Worker per-request key provisioning, authenticated v12 native wire/session challenge exchange and live OS peer coupling; owned/cancelled/drained OVERLAPPED **payload** ReadFile and buffer lifetime, zeroization on mid-fragment revocation, real Worker Unicode clipboard read and one authoritative Teacher response. Active v11 stays failure-only and no new secret route exists. VM2 disk cap at 56 GB and ~14 GiB Mac free; do not resume VM2 without storage repair/approval, do not delete VM snapshots. VM1 also remains suspended. Physical 2-PC/GPU/classroom/accessibility/clipboard E2E remain OPEN. Resume with exact-head CI and security review before Squash merge, then separate next PR.


## QUICK RESUME — GitHub Live 2026-10-14 after PR #466

**Source of truth:** `faariis7/ClassMesh` latest `main` `186a592927561775063ecd22ec014e3fddbc537d`; PRs #457/#458/#460/#461/#463/#464/#466 all merged. #463 exact-head CI #38477133947 and #464 #38480088598 Portable Rust and full Windows Build SUCCESS; #466 exact-head run #38518184041 **both PASS**, squash merged to `186a592927561775063ecd22ec014e3fddbc537d`. Security reviews were recorded. Phase12E18a #466 replaces the unsafe stale by-value Service control binding around native v12 ConnectNamedPipe with a Service-supplied current-policy accessor evaluated before and after OS connect. Missing/stale control denies and disconnects the attached peer; actual launched Worker process HANDLE and six-field control matching remain enforced. VM1 native ARM64 library tests **44/44**, VM2 same compiled binary **44/44**; VM1 rustfmt/Clippy -D warnings and Synology full workspace fmt/Clippy/tests PASS. TDD RED compilation evidence before the change recorded. No further Phase12E18a PR pending at this checkpoint.

**Live software:** ClipboardRead on the production generic IPC v11 (minor 11) remains **failure-only/unavailable**. All dedicated v12 named-pipe creation, process/OS peer binding and overlapped connection are **inactive security prerequisites**, NOT authenticated v12 session negotiation or plaintext delivery. Issue **#465** remains open for authenticated Service-issued one-shot challenge/version handshake and trusted **current** ClipboardText+ReadClipboard grants/revocation. Existing generic v11 WorkerHello/ServiceReady and current named-pipe PID do **not** authenticate sensitive data. Next technical gates: replay/expiry and permissions on every fragment, dedicated cancellation-safe owned OVERLAPPED **payload ReadFile** with targeted CancelIoEx and final OS completion drain before zeroization/free, native Worker read, isolated Teacher result only after authenticated authorization. No secret bytes on v11, logs or artifact output.

**Physical/VM evidence:** VM1 and VM2 are independent Windows ARM64 VMs on the Mac; running the same 44 test cases on each is **not** an inter-machine clipboard E2E or physical two-PC classroom/GPU/media/latency/accessibility qualification. All issues #3/#108/#153/#276/#281/#288 and Phase12E gates remain OPEN. VM2 hit VMPal's virtual disk cap; increased limit 49→56 GB but it grew again to 56.7 GB on resume/suspend. **DO NOT resume or enlarge VM2 again until storage diagnosed**: macOS disk had about 15 GiB free after that cycle, 97% used. VM1 currently suspended; use GitHub Windows CI/Synology for further tests until Mac storage is safe. Do not delete existing VM snapshots without explicit permission.

**Engineering rules:** Verify GitHub Live / Issue #328 / Issue #465, update living plan before code, TDD small reversible PRs, fmt/Clippy -D warnings/full workspace tests, native Windows tests where relevant, security review and exact-head hosted Portable+Windows CI green **before** merge. Mark hardware and native clipboard acceptance as OPEN until real evidence. Earlier date-stamped material is archival.

Older date-stamped material below is historical and must not override this block.


---

> **GitHub Live handoff — 2026-10-13, verified main `bc5974a604b1d7d7e5aa7def2a7d93298b6e8390`:** Phase 12E clipboard PRs **#413–#446 are merged**. #445 keeps reserved-v12 sensitive decoding in the original zeroizing allocation; #446 constructs the future-v12 frame directly in one zeroizing output buffer, with Portable Rust and Windows Build CI green on the reconciled head. **PR #448** is open on a separate branch for an **inactive** zeroizing Service→Teacher clipboard-success response serializer; exact-head CI is pending and the change must not be treated as deployed. The **active production Service/Worker IPC remains minor 11, ClipboardRead failure-only**; isolated v12 codecs, native Windows clipboard reader, Worker/Service sensitive inbox and Teacher-response encoder are not wired into a live end-to-end feature. Next technical gate is authenticated explicit v12 negotiation, dedicated Worker→Service sensitive pipe and lifecycle/permission/sequence binding, then native Worker invocation and validated Teacher UX on a Windows VM. Physical two-PC, GPU/media, classroom, accessibility and real clipboard exchange gates remain OPEN. The checkpoint text below is archival.

> **Verified handoff — 2026-10-12 Saudi local, GitHub Live authoritative:** `main` at `bd8ed6f6257fc3aed2797080f6bdb85498a0d058` includes merged Phase 12E clipboard PRs **#413–#437**, including #436's isolated identity-bound future v12 Worker sender and #437's bounded one-shot zeroizing sensitive Service inbox. **Only PR #438 documentation refresh remains open in the checked series**; check GitHub Live before proceeding. Existing production control runs clipboard-read **failure-only over v11**; v12 sensitive frame, stream, Win32 Unicode reader and bound inbox/sender remain isolated, not connected to authenticated Service/Worker and Teacher response. Next: version-negotiated sensitive Worker→Service pipe integration, authorization/identity/sequence/timeout/zeroizing lifecycle tests, then native Worker read event and Teacher UX; verify CI, Windows VM smoke and separate physical two-PC qualification. Do not route clipboard text through generic v11 IPC. All hardware/media/classroom gates remain OPEN. Older dated checkpoints below are historical.

> **Current agent handoff — 2026-10-12 Saudi local; GitHub Live overrides historical content below.** Main `7fa8b1a59198da86eaf899bf1cf21e280745ae98` includes merged clipboard PRs **#413–#427 and #429**. Distinguish three stages: **(1) implemented and merged:** permission+capability guards, metadata-only Worker read with correlated unavailable result, zeroizing/bounded UTF-16 codecs, write NUL rejection and reserved v12 sensitive success **payload/frame** codec; **(2) unmerged:** #428 Windows CI cache, #430 reserved v12 sensitive streaming decoder, both with CI pending on last observation; **(3) not implemented or not qualified:** native Windows clipboard content access, zeroizing sensitive frame integration with authenticated Service/Worker and Teacher, Teacher UI, true E2E classroom session and physical hardware/multi-machine gates. Preserve release/physical gates as OPEN. Before modifying code, inspect live main/heads/PRs/CI and review `docs/WORK_PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md`, and Issue #328; avoid duplicating already merged phases. Small test-led PRs; no real clipboard success until dedicated sensitive decoder, identity-bound results, cancellation and zeroizing ownership are enforced and Windows/VM tests pass. Historical PR/VM evidence below remains archival, not today's PR state.

> **Latest handoff — 2026-10-11 16:56 UTC, overrides historical status lines below. GitHub Live remains authoritative.**
>
> **Completed:** #410 Phase 12E3a merged into main (`19df0f0`); #412 VM1 Teacher empty-state and documentation evidence merged into main (`f32039f`). VMPal 0.69 agent CLI controls two Windows 11 ARM64 VMs via the Mac; VM1 (`DF60038E-4C4D-4DCB-B310-1D2ACAAD798A`) currently locked, VM2 (`B20645A3-347F-4622-89DF-28283E936612`) confirmed usable for real interactive-window qualification. This is **Mac VMPal CLI/MCP bridge**, not direct native ChatGPT VMPal MCP connectivity.
>
> **Open and CI-green, not merged:** PR #413 12E3b clipboard injection, head `3b1d01e`, CI #1659 Portable Rust/Windows green, local `classmesh-control` 199 tests, fmt/Clippy green; security review tests enforce redacted Debug and non-Clone opaque authorized commands. PR #414 opt-in `-RequireResponsiveWindow` smoke, head `e67f49b`, CI #1661 Portable Rust/Windows green. Require review and user approval before merges into main.
>
> **Windows VM2 real smoke (PR #414):** CI #1661 artifact ID `11707807431` zip SHA `bb1fe7441518214b0b5ccf9c848df088e3a3504b060d9207fba465d076c883f3`; indexed Teacher EXE SHA `20eb252aa902398f9a488f3760d6e4cb57eaf0a5eaa186288fea6b8fb197f298`. `ValidateBundle` passed. Strict `-RequireResponsiveWindow` failed exit 1 when VC++ x64 runtime was absent; after saving snapshot `Before-VC-Redist-PR414-20261011` and installing official Microsoft-signed `vc_redist.x64.exe` (SHA `843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c`, install exit 0), exact same artifact passed strict smoke with `main_window_observed=true`, `session_id=1`, `visual_accessibility_reviewed=null`, `physical_media_transport_qualified=null`. Default smoke passed separately and recorded `main_window_observed=null`. VM2 evidence: `C:\Users\ahmed\ClassMeshTeacherSmokePR414\evidence-strict\launch-smoke-evidence.json`. Detailed durable notes: [PR #414](https://github.com/faariis7/ClassMesh/pull/414), [Issue #411](https://github.com/faariis7/ClassMesh/issues/411).
>
> **Next:** (1) review #413/#414 against current main and seek user merge approval; (2) implement test-led authenticated Service↔Worker clipboard command execution/read-response routing, with capability/permission/sequence/correlation and cancellation cases; (3) resume 12D4b actual staged-file trusted candidate and transport/results; (4) keep all physical issues #3/#108/#153/#276/#281/#288 and 12B4b/12C4 open. Do **not** infer real network/Teacher↔Student integration or accessibility qualification from VM GUI smoke.


> Evidence snapshot: 2026-10-11. **GitHub Live is always authoritative.** Recheck current main, open PRs, Issues, jobs and instructions before work. This file is a checkpoint, not automatic proof that no later change exists.

## Current
- Main verified after documentation PR #409: `316067a7143179a3602a20dd149216b8860eb6e3`. Recheck GitHub Live before changing code.
- Active product Issue: [#328](https://github.com/faariis7/ClassMesh/issues/328), Phase 12 administrative features.
- Clipboard 12E3+ orchestration / Teacher UI **not yet implemented**; existing Phase 6E text-only bounded protocol must be reused.
- Phase 12D Teacher file transfer remains incomplete at the live staged-candidate producer and authenticated transport/result UI integration boundaries.

## Completed
- PR #407 (12E1): existing-wire 64 KiB clipboard text validation and unavailable-response semantics.
- PR #408 (12E2): central privileged ClipboardWrite dispatch calls `validate_write`, preserving validation before authorization/replay checks and explicit WriteClipboard permission.
- PRs #400–#405: bounded Teacher file-transfer UI pending-action/candidate lifecycle contracts; **not** a real end-to-end file-transfer claim.

## In progress
- Phase 12E3a PR #410 is in CI #1653 at this checkpoint (Portable Rust succeeded; Windows Build had not yet completed). Opaque dispatch tokens and their tests are proposed, not merged until all gates pass.

## Next
1. Inspect the current authenticated Teacher/Service post-Hello pipeline and existing clipboard read/write Worker routes.
2. Specify the smallest missing 12E3 slice, exact authorization/capability/sequence/correlation requirements and negative tests; retain a bounded queue and text-only wire.
3. Use test-first implementation on a branch from up-to-date main. Verify Rustfmt, Clippy, workspace tests and Portable Rust + Windows Build CI; review before merge.
4. Return to 12D4b's trusted staged-file producer and actual Teacher transport/result handoff without exposing arbitrary filesystem paths.
5. Execute exact-build interactive Teacher UI qualification on Windows; keep VM evidence distinct from physical PC/GPU/network acceptance.
6. Continue Phase 12F/12G then Phase 13 per ROADMAP, without closing open qualification gates.

## Blocked / deferred
- No second Windows target required yet; cross-VM/multi-PC tests are deliberately deferred.
- Hosted CI and one ARM64 virtual Windows instance do not qualify physical GPU capture, throughput, classroom-scale or two-physical-PC outcomes.
- Production Teacher file-pull candidate source, transport-result path, and clipboard interactive execution are not accepted by existing hosted CI.

## Open PRs
- ClassMesh: [PR #410](https://github.com/faariis7/ClassMesh/pull/410), Phase 12E3a, awaiting CI/review in this snapshot. [PR #409](https://github.com/faariis7/ClassMesh/pull/409) already merged.
- agent-skills: [PR #5](https://github.com/faariis7/agent-skills/pull/5) merged as `a4bead87e34e7180df939787e109bd66bfb6b642` after live 0.69 CLI/guest verification.

## CI status
- [PR #408 CI #1650](https://github.com/faariis7/ClassMesh/actions/runs/38145955105): completed success; Portable Rust and Windows Build jobs passed on head `0a6a65a`.
- [Merged-main CI #1651](https://github.com/faariis7/ClassMesh/actions/runs/38146937198): completed success; Portable Rust and Windows Build jobs passed on `780d7ec`.
- [PR #409 CI #1652](https://github.com/faariis7/ClassMesh/actions/runs/38150139588): Portable Rust + Windows Build completed successfully on `9fd51a8` before squash merge `316067a`.
- PR #410 CI #1653: Portable Rust success, Windows Build still pending as this checkpoint was authored. Verify CI Live before merging; do not substitute earlier green statuses.
- The statuses above apply **only to those exact commits**, not to future PRs.

## VMPal / test evidence
- Mac host observed VMPal 0.69 build 69; `vmpal list --json` confirms Windows VM 1 (`DF60038E-4C4D-4DCB-B310-1D2ACAAD798A`) running with agent control enabled.
- Guest `vmpal exec` succeeded: Windows 11 Pro ARM64 24H2, OS build 26100, PowerShell 5.1.26100.9457, interactive user. `vmpal ui ... status --json` reports authorized USB-HID control; `observe --text` returned desktop text. VMPal Tools 0.48.
- This confirms **CLI bridge access via Remote Desktop Commander**, not a native VMPal MCP connection in this conversation.
- **Exact-build Teacher GUI runtime evidence (2026-10-11):** CI #1646 x64 `classmesh-teacher-ui.exe` SHA-256 `ce9e88e3d724dbf11b92a7aa23eae9da77023c7480aa3c3e2ff02e17676eb75e` initially failed visibly with missing `VCRUNTIME140.dll` on the ARM64 Windows VM. A VMPal snapshot `Before-VC-Redist-ClassMesh-2026-10-11` was taken. Downloaded official Microsoft x64 VC++ redistributable, verified Valid Microsoft Corporation Authenticode signature (SHA-256 `843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c`), installed using `/install /quiet /norestart`, exit 0; x64+ARM64 version `14.51.36247.00` appeared in registry.
- **GUI re-test:** Same executable then showed ClassMesh Teacher in interactive Session 1, `Responding=True`, with truthful empty states and successful VMPal HID navigation of Classroom, Focus, Presentation, Diagnostics and Device Actions; screenshots retained on authorized Mac in `/tmp/classmesh-teacher-{classroom,focus,presentation,diagnostics,actions,tab-focus}-20261011.png`. Process remained responsive on subsequent check. This is a *single-VM visual/launch qualification only*, not authenticated production clipboard, FileTransfer or physical network/GPU evidence. Deployment fix tracked [Issue #411](https://github.com/faariis7/ClassMesh/issues/411).

## Physical gates (OPEN)
- Phase 4 Issue #3: two physical Windows PCs, 1080p30/latency/impairment/soak; UDP vs QUIC Datagram choice remains undecided.
- Phase 6F Issue #108; Phase 7D/7H #153; Phase 8D #276; Phase 9F #281; Phase 10G #288.
- Phase 12B4b safe Lock/destructive power acceptance; Phase 12C4b interactive Teacher UI qualification; Phase 12D4 real file-transfer runtime/visual qualification.

## Next executable task
**12E3b after #410 CI/merge:** consume opaque authorized clipboard read/write tokens through a narrow bounded Service→Worker seam with exact session/request/capability/permission binding, defined read-response correlation, failure/backpressure/cancel tests and injected non-destructive Windows interfaces. No production clipboard claim until such routing exists. No parallel clipboard protocol or shell endpoint.

## Operating rules
- Read `.agents/skills/classmesh-engineering/SKILL.md`, `docs/WORK_PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md` and affected security/protocol docs.
- The repository root did not contain `AGENTS.md` on 2026-10-11; recheck before later edits.
- Preserve least privilege, bounded queues, explicit replay suppression, existing protocol versioning and no destructive tests on hosted runners or a non-disposable VM.
