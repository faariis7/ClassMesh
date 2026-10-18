# Phase 10 — recover a formerly healthy stream frozen with no packets

## Reproduced defect

PR #554 added a periodic inactivity watchdog that requests a keyframe while the decoder is *waiting* for an IDR. An existing playback stream that had already decoded its keyframe could freeze entirely; with zero new packets, `decoder.waiting_for_keyframe()` could remain false forever, so the watchdog would not request recovery. Two native Windows RED regressions proved this while distinguishing a stream that had *never* received an authenticated frame, a formerly playing stream, and session/key rotation.

## Change and bounded behavior

`PresentationKeyframeSilence` now distinguishes authenticated media progress from the decoder's waiting flag. A bound, active, healthy decoder that has *never* received an authenticated frame does not spontaneously request recovery. After at least one authenticated frame, a 2-second gap is a stalled stream **even if the decoder still considers its last keyframe valid**. The existing Worker event-loop guard requires exactly one active nonfailed Unicast/Multicast receiver matching the *current* `PresentationKeyInstallBinding`, an active decoder and installed media key. The request uses the existing Service/Teacher-authorized `WorkerPresentationFeedback` channel and latest authenticated frame ID, with the existing 2-second request retry gate and Teacher-wide throttle.

To avoid unbounded recovery traffic during an intentionally paused stream or prolonged outage, the silence watchdog issues **at most three successfully dispatched requests per uninterrupted silent episode**. A send failure or throttled request never burns an attempt; a new authenticated frame clears the silence budget and refreshes the inactivity clock. New key epoch, presentation restart, matching key clear and pipeline teardown reset state. Old frames with regressed observation timestamps cannot replace a newer cursor. No new IPC message, controller capability, network protocol or Astra Phase 12 files.

## TDD and gates

Windows VM2 x64 targeted TDD RED: formerly playing stream remained suppressed, cross-epoch state incorrectly treated; follow-up RED for missing sent-request budget. GREEN: 90/90 `classmesh-worker` unit tests, another 4+3+23 Worker binary/integration tests, Clippy with `-D warnings` and Rustfmt. Tests verify exact inactivity boundary, authenticated progress re-arms, no speculative idle request before any authenticated frame, epoch/clear isolation, replayed/old-time evidence ignored, exact three-successful-send budget, and unsuccessful sends do not consume it. Exact-head hosted Portable Rust and Windows Build CI and review are merge gates.

## Remaining limits

An IDR request alone cannot restore video while the underlying media path is physically disconnected. An explicitly *paused* video is not yet identified separately from packet loss; the three-request cap bounds this false positive. No trusted cross-device telemetry reporting channel or two-physical-PC Wi-Fi qualification is claimed.
