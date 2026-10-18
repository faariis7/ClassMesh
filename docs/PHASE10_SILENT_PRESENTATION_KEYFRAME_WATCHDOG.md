# Phase 10 — idle presentation receiver keyframe recovery

## Production gap and recovery path

The Worker live protected multicast/unicast presentation receiver runs its event loop even with zero incoming UDP frames. Previously the Worker requested a keyframe only while handling an incoming authenticated access unit or a decoder error. If the receiver/decoder was stuck waiting for its first or replacement keyframe and **all** media packets stopped, no later frame entered that request path and the existing two-second frame-triggered retry (#552) could not fire.

The Worker now maintains a constant-memory `PresentationKeyframeSilence` clock, bound to the exact `PresentationKeyInstallBinding` (session, presentation, stream and epoch). It starts its clock only after one active, nonfailed protected receiver and decoder match the installed key; initially it waits a two-second grace period. Every successfully AEAD-verified access unit refreshes the clock and its last authenticated frame ID; structurally accepted ciphertext or failed authentication does not. While the decoder is **waiting for keyframe**, a silence of at least two seconds permits a request with the last authenticated frame ID (or supported zero cursor before the first frame). The existing `PresentationKeyframeRetry` allows no more than one successfully transmitted request per two seconds, and the Teacher-side `PresentationRecoveryCoordinator` independently applies the stream-wide keyframe coalescing policy. Both mechanisms use the existing authorized Worker→Service→Teacher feedback message and do not widen Service permissions.

An active decoder that is NOT waiting for an IDR, such as a healthy but intentionally paused presentation, never sends idle requests. Switching key epochs/stream causes a fresh clock and zero initial cursor; a matching key clear, receiver replacement and failed media pipeline reset the clock. The monitor runs in the existing event loop, without extra threads or new wire formats.

## Deterministic test-first verification

Native VM2 x64 RED verified the missing silence watcher. GREEN: four tests cover a quiet decoder since start, exact two-second grace boundary, last authenticated frame cursor and timestamp refresh, epoch/session rotation and reset, lack of requests while healthy, and backwards timestamps. Native VM2 full Worker suite: 86/86 tests, plus 4+3+23 binary/integration tests; warnings-denied Clippy and rustfmt PASS. Exact-head GitHub Portable Rust and Windows Build CI and code review remain mandatory before squash merge.

## Limits and safety

A keyframe request cannot bring back a physically disconnected sender or failed network route. This feature attempts bounded, correctly authorized recovery when the sender can still receive control messages, but does not prove successful rendering under genuine two-host Wi-Fi partition, packet loss, media stalls, or mass classroom load. It does not transmit new per-receiver telemetry or create a new control protocol. Phase12 Registry/root/epoch worktrees and policy authority remain untouched.
