# Phase 10 — receiver playback telemetry admission gate

## Scope and trust boundary

This change adds a **pure Rust, constant-space admission gate** for later Worker→Service receiver playback telemetry. It does **not** create or activate a new IPC message, network sender, Teacher feed, authenticated credential, or adaptive-quality decision. It is intentionally independent of Astra's Phase 12 Windows trust, Registry anchor and IPC versioning work.

Before calling `ReceiverTelemetryGate::activate`, the eventual Service integration **must independently verify** its authenticated Worker pipe and current process, logon session, Worker generation, accepted presentation/stream ownership, installed key epoch and receiver-runtime generation. None of those can be asserted by a Worker-supplied report. A media report cannot activate its own binding. Exact binding change clears the previous baseline; identical activation preserves replay state. A matching clear revokes the gate; a stale clear cannot revoke a replacement.

`ReceiverTelemetryGate::observe` accepts only a nonzero monotonically increasing sequence from that exact binding and measures time on the Service's own monotonic clock. Reject replays, clock regression, malformed identity, counters decreasing and reports faster than 1 second, without advancing state. First sample, skipped sequences and time gaps above 30 seconds yield **Baseline**, never a fabricated valid quality interval. Contiguous, nonregressing counters yield separate authenticated AEAD opens, rejected opens, decoded frames, presented frames, errors, keyframe waits and receiver queue drop deltas. Memory remains O(1) per active gate; no content, keys or frame bytes are retained.

## Why this cannot yet drive automatic quality

Protected UDP sequence gaps are **observed ID discontinuities**, not definitive packet loss. AEAD-authenticated frames are **not** proof of decoding or display. Cumulative queue drops are **receiver-runtime-local**, not UDP loss. None of these local counters measures RTT or a true loss ratio; the gate deliberately returns neither synthetic RTT, packet-loss percentages nor a receiver health tier.

An **authenticated, version-negotiated Worker→Service telemetry IPC contract** is still required, including bounded sender rate, replay-resistant lifecycle, Service authorization, explicit drop behavior and revocation. Service→Teacher delivery needs its own mutually authenticated control-session correlation, bounded storage, independent per-receiver samples and safe adaptation policy. Phase 12 version changes must be coordinated before introducing message IDs. This feature stays passive until that integration and native Windows security qualification are complete.

## Worker-local monotonic sequence and read-only liveness

The real Worker `PresentationDeliveryTelemetry` diagnostic now stamps each eligible five-second report with a per-binding `sample_sequence`. Undue polls do not consume sequence IDs. The number starts at 1 after exact media binding/epoch reset or pipeline teardown; exhaustion stops emission instead of wrapping to a replayed ID. The Worker still logs **locally only**; no new privileged IPC write or wire contract was introduced.

The pure Service-side `ReceiverTelemetryGate::has_fresh_report(service_now)` checks whether a report has been accepted for the active binding within the bounded 30-second continuity window, using the Service monotonic clock. An invalid replay cannot refresh liveness; missing baseline, a cleared/replaced binding, a clock regression or expired report returns false. This is a **read-only liveness diagnostic**: it does not synthesize a media-quality sample, prove Worker truthfulness or change existing adaptation.

**Outstanding cadence mismatch:** the present Worker local diagnostic is emitted every 5 seconds while `ReceiverQualityPolicy::default().max_sample_age_us` is 2 seconds. Before wiring new metrics into automatic adaptation, align separately proven authenticated publisher cadence, bounded coalescing/backpressure, freshness expiry and independent network measurements; otherwise healthy devices may oscillate to Emergency between reports. Neither 30-second gate liveness nor a sequence number authorizes quality promotion, provides RTT, or turns UDP gaps into loss percentages. The phase-12-owned IPC version must not be changed here.

## Regression and CI

`cargo test -p classmesh-control --test receiver_telemetry_admission` covers exact binding, stale Worker/runtime generations, replay, non-monotonic clocks, nonregressing counters, duplicate activation, revocation, too-frequent reporting, missing sequences, stale gaps and independently recorded authenticated/decoded/presented deltas.

The Remote Desktop Commander monthly limit prevented an **independent current-turn Windows VM2 rerun**. Prior tests for the earlier Worker watch dog do not validate this module. Require Rustfmt, all-targets warnings-denied Clippy, exact-head Portable Rust and Windows Build hosted CI. Preserve separate physical two-PC and classroom-congestion qualification gates. Do not treat hosted CI as physical evidence.

## Passive byte ingress, still not an authenticated pipe

`ReceiverTelemetryIngress` composes the strict decoder and admission gate at a
single read-only boundary. The Service must call `activate_verified` using a
binding derived **independently** from its authenticated Worker IPC peer,
process/session/Worker generation, accepted presentation and currently active
receive-runtime generation. Decoded payload bytes never activate the gate.
Malformed, replayed, mismatched-epoch and counter-regressing frames cannot
advance its baseline. Exact lifecycle revocation clears the binding; stale
revocation cannot clear a replacement. No new message ID, live producer,
privileged channel, Worker→Service delivery or quality promotion is introduced.

`cargo test -p classmesh-control --test receiver_telemetry_ingress` checks
unauthorized bytes, wire errors, wrong epochs, replay, valid deltas and
replacement/revocation. Native authenticated transport integration and VM2 or
physical-machine qualification are still required before runtime use.

## Worker-local exact receiver selection

The existing Worker-local five-second playback diagnostic now reads `queue_drops`
only from exactly one *healthy* multicast or unicast receive runtime whose
presentation binding matches the currently installed key. A missing, failed,
wrong-epoch, or ambiguous pair of receive runtimes is not misreported as a
legitimate zero-drop observation, and there is no fallback to the first present
receiver. This is an actual Worker runtime diagnostic guard, not a network
sender or IPC authorization. Both receiver modes retain their existing keyframe
recovery and teardown behavior. Tests cover zero drops, either mode, absent
matching runtime and a conflicting pair. Host CI cannot substitute for the
native two-host playback qualification.

## Local Worker counter continuity before eventual IPC

The five-second Worker diagnostic additionally refuses to publish a subsequent
report if its cumulative authenticated AEAD opens, rejected opens, or the exact
receiver-runtime queue-drop counter decreases under the **same** key binding.
The violation latches fail closed: a later increasing count cannot hide the
reset and reestablish an apparently continuous report or consume sequence IDs.
An explicit Worker presentation pipeline reset or new key binding establishes
fresh sequence 1. This catches a same-binding receiver/auth counter restart at
its source; it is not independent authentication or a replacement for the
Service's exact receiver-generation admission, and it does not activate IPC.

## Real Worker counter type alignment, without implicit authority

`PresentationDeliveryReport::playback_counters` now maps actual Worker
five-second playback telemetry to the shared `ReceiverPlaybackCounters` type,
used by the passive Phase 10 byte codec/admission gate. The existing Worker
runtime log reads that typed result. AEAD authentication counters remain
separate from decoded, presented, errors, keyframe waits and receiver-local
queue drops. The per-presentation report sequence stays outside the counter
struct, as required by the eventual exact owner/receiver binding envelope.
This is local type alignment only; no new Worker→Service sender, IPC message,
trusted owner assertion, or adaptive policy decision was enabled.

## Thread-safe nonblocking telemetry handoff (pre-IPC)

`ReceiverTelemetryConcurrentMailbox` shares one latest-only report slot via
`Arc<Mutex<ReceiverTelemetryMailbox>>` with **`try_lock` only**. A Worker video
producer never blocks behind another thread: contention returns `Busy` and a
poisoned slot returns `Poisoned` (fail closed). Accepted reports coalesce in
constant space and reject invalid/replayed/mismatched binding, while exact
replacement/clear prevents stale senders from draining a successor. A future
independent sender must take a copy, drop the lock, independently check the
current authenticated Worker and receiver generation, then use nonblocking I/O
or discard; **it must not write to the existing blocking Worker media loop**.
This is the bounded producer/consumer seam, not an active transport, IPC
message, credential, thread, or quality promotion. Unit tests exercise 10,000
coalesced offers, deterministic contention, poisoned-lock failure and exact
binding replacement without requiring a live Windows guest.

## Revocation-aware sender checkout lease (pre-IPC)

The concurrent mailbox now issues an **opaque local checkout lease** rather
than giving an eventual sender an untracked raw sample. Each lease binds the
full sample and sequence to a strictly increasing mailbox lifecycle
incarnation and a **weak reference to its originating mailbox allocation**.
The weak identity prevents one receiver mailbox from accepting a lookalike
lease from another even if their process/session, presentation, epoch and
sequence fields happen to match. A lease does not retain the mailbox after
shutdown. Clear + reactivation with the same binding consumes a new
incarnation, so an old checkout cannot reappear as current (ABA). Exhausted
incarnation counters reject reactivation without wrapping. A newer offered
sample invalidates an older checkout, including if the newer report is itself
later drained. Identical trusted activation leaves legitimate leases intact.

`try_checkout_matching` and `try_lease_is_current` return `Busy` instead of
waiting for another thread, or `Poisoned` if the underlying lock was poisoned.
The former raw-drain method on the **concurrent** wrapper is intentionally
removed to avoid bypassing the lease; the lower-level nonconcurrent mailbox
still supports its existing internal tests. Thread-ordered regressions test
revocation after checkout, same-ID lifecycle reuse, cross-mailbox isolation,
congestion, latest-only sequence invalidation, lock failures and overflow.

**Critical trust limitation:** the local lease validation is advisory and
not atomic with network or pipe I/O. A revocation may race immediately after
any pre-send check. A future *separately authenticated and authorized*
Worker→Service channel MUST independently reject mismatched Worker ownership,
receive generation, session and key epoch on arrival; it must not use this
lease as authentication or authorization. No new IPC frame or live sending
is enabled here; no adaptive-quality decisions are changed.

## Bounded Worker-local freshness of queued and checked-out reports

`ReceiverTelemetryConcurrentMailbox` now stamps only a **successfully offered**
snapshot with `Instant::now()` on the producing machine. The time is private
monotonic process-local evidence, **never** serialized from or controlled by a
remote report. A queued report that ages beyond the existing
`MAX_RECEIVER_TELEMETRY_GAP` (**30 seconds**) is discarded at checkout; a
previously checked-out lease becomes invalid on the same strict boundary,
even if no new sample has arrived. Exactly 30 seconds remains fresh; an
instant beyond 30 seconds or a local clock regression fails closed. Invalid,
replayed or regressing-clock offers cannot refresh the timestamp or advance
the accepted sequence, and a new exact binding/revocation resets its age.
The producer and sender remain nonblocking and use one report slot.

This is an **upper bound for optional Worker diagnostic forwarding**, not a
quality measurement freshness policy. `ReceiverQualityPolicy` still uses its
**2-second** maximum sample age, while the existing Worker diagnostic cadence
is **5 seconds**. Those are intentionally not equated; the metrics are still
not eligible for adaptive-quality promotion until independent cadence and
network-measurement validation, separately authenticated Service admission,
transport backpressure tests and physical qualification are complete.
No new IPC, transport sender or privileged authorization was enabled.

## Portable pre-IPC Worker to Service handoff qualification

The `receiver_telemetry_handoff_integration` test module exercises a simulated
Worker sender and a separately Service-authorized ingress using the REAL
fixed-width codec, bounded Worker mailbox and Service continuity gate. It
covers admission only after independent exact identity activation; 5-second
counter-delta continuity; a 4,000-report bounded coalescing sequence gap
downgrading to a *baseline* rather than a healthy interval; Worker generation
and receiver replacement with an already-copied old wire report; tampered
packet rejection without poisoning the authorized sequence; and strict
isolation of two simultaneous receiver mailboxes and Service cohorts.

This is test-only local IPC *composition*, not a working Worker-to-Service
transport. The test deliberately supplies Service identity activation from
the harness, not bytes. An actual Service MUST verify the peer's authenticated
OS process/session, Worker generation and active receiver lifetime on arrival,
prioritize administrative control over best-effort telemetry, reject after
revocation even if the sender passed a now-stale local lease check, and
coordinate IPC message compatibility with the Phase 12 workstream.
No synthetic RTT, packet-loss, remote quality score, or adaptive promotion
is derived from these receiver playback diagnostics. Hosted Rust/Windows
tests do not qualify native GPU behavior or two physical PCs.


## Local Worker bound-key snapshot composition

`PresentationDeliveryReport::snapshot_for_bound_key` converts actual Worker
AEAD/decode/render/queue-drops counters into the portable
`ReceiverTelemetrySnapshot` only when the separately provided complete owner
binding is nonzero, its media identity exactly equals the **currently
installed** protected presentation key binding (control-session, request,
presentation, stream and key epoch), and the local report sequence is nonzero.
The function carries external Worker/receiver generation identity unchanged
and does **not** authenticate it, authorize transport, or self-activate the
Service admission gate; those are independent Service-controlled lifecycles.
Wrong epoch/request/session or invalid owner must fail without any serialized
bytes. This helper remains passive, with no new privileged IPC or automatic
adaptation/quality upgrade. Tests cover exact positive mapping and rejection
of every mismatched protected media-key identity field.
