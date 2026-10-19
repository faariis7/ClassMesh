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
presentation, stream and key epoch), the **private source binding captured
at report emission** also matches that installed key, and the local report
sequence is nonzero. A delayed report issued under an old epoch cannot be
relabelled by passing a matching new external owner and current key.
The function carries external Worker/receiver generation identity unchanged
and does **not** authenticate it, authorize transport, or self-activate the
Service admission gate; those are independent Service-controlled lifecycles.
Wrong epoch/request/session or invalid owner must fail without any serialized
bytes. This helper remains passive, with no new privileged IPC or automatic
adaptation/quality upgrade. Tests cover exact positive mapping and rejection
of every mismatched protected media-key identity field.


## Real Worker diagnostic through the portable Service gate

A Worker-library cross-layer qualification test drives the **real**
`PresentationDeliveryTelemetry::report_if_due` through the
`snapshot_for_bound_key` consistency guard, fixed-width wire encoder and
`ReceiverTelemetryIngress` Service gate. Before independent Service
activation the report is rejected. Exactly timed contiguous local diagnostics
yield AEAD-open, AEAD-reject and queue-drop **intervals** but do not claim
decoded or presented frames in the absence of actual decoder outcomes. A new
protected key epoch resets the reporter sequence, requires a new independently
activated Service receiver identity and cannot relabel old reports.

The test is strictly an in-process composition with a simulated Service
authority: it does not create, authenticate, prioritize, negotiate or exercise
real Windows IPC, and cannot substitute for native Windows VM and physical
two-host GPU/decode qualification. It makes no adaptive-quality decision.

## Recheck live Service owner before passive report decode

A newly available **optional, stricter** Service-side entry point,
`ReceiverTelemetryIngress::observe_for_current_owner`, requires the Service to
provide its independently verified **currently active** process/session,
Worker generation, accepted presentation/key epoch and receiver-runtime
generation with **every received report**, and refuses mismatches, absent
bindings or invalid owner identities **before decoding report bytes**. The
companion `has_fresh_for_current_owner` refuses to display stale gate liveness
under a different current owner. This closes an in-process stale-owner
notification gap: simply retaining the prior activated binding is not
sufficient evidence that it remains the current authorized Worker.

The old passive `observe_verified` method remains for existing callers and
compatibility; new Service integration should use the owner-aware method.
Neither method authenticates the caller-supplied current owner, pins an OS
process/pipe generation across concurrent replacement, nor establishes a
Worker→Service transport. Actual Service receive code must obtain the owner
from **independent OS peer credentials and an authoritative lifecycle**, hold
that authorization across admission, revalidate on arrival/revocation, and
never use report contents to select it. No Phase 12 IPC/message/version or
adaptive-quality behavior changes were introduced.


## Service-owned receiver-runtime generation ledger

`ReceiverTelemetryServiceLifecycle` is an **inactive, process-local** Phase 10
building block for the future Service-owned authorization chain. A
`ReceiverTelemetryStart` carries only nonzero Worker PID, Windows session,
Service Worker generation and exact protected control/presentation/stream/key
identity. It deliberately has **no receiver-generation input**: after a
separately verified, successful protected receiver start, the Service ledger
assigns a unique monotonically increasing `receiver_generation`. Even a
replacement/retry with exactly the same key epoch receives a fresh number.
Revocation only clears an **exact** active binding, and does not reset the
generation counter or let a stale clear revoke its successor. Invalid starts
never spend a generation, and overflow fails closed rather than wrapping.
A replacement report cannot be accepted under the old generation; a valid
new report must start a new Service ingress baseline.

**Not production wiring or authorization:** the caller of
`activate_after_verified_start` MUST use independently OS-verified
NamedPipe peer PID/session, `WorkerManager.generation`, a correlated
pending authorized request and a *successful* receiver start. Nothing in
this ledger proves these conditions; arbitrary caller-supplied fields have
no authority. Actual activation must be owned by the sole authoritative
Service lifecycle and coordinated with exact revocation, restart, Worker
exit, key clear and in-flight concurrent receive operations. A new Service
process can begin a fresh ledger: do not assume a process-local generation
alone establishes global identity across restarts. The existing owner-aware
ingress must revalidate live peer authority on receipt, and no Worker-created
generation is allowed. There is **no IPC message or channel**, no telemetry
sender, no adaptive-quality promotion, no new privilege or Phase12 change.
Physical two-host and GPU/scale gates remain open.


## Service-owned start-result correlation guard

The additional pure `activate_after_correlated_reply` gate can compare
three **separately acquired** records before minting any runtime generation:
(1) the Service-owned pending, *authorized* protected presentation/key
binding; (2) the independently OS-authenticated current Worker
PID/session plus Service Worker generation; and (3) a successfully parsed
Worker multicast/unicast start acknowledgement. The untrusted ACK must
match PID, session, control-session ID, request, presentation and stream;
its rejected status is not a start. The ACK lacks key epoch and Worker
generation, so **only the current Service authorization/grant** may supply
those fields. A failed correlation must not spend a generation or clear
the current receiver. A stale Worker reply after replacement fails closed.

This is a testable *guard*, not an attested proof by itself: it cannot
authenticate the caller-supplied records, prove the OS peer or prevent a
separate concurrent Service replacement after the comparison. The live
Service must own/pin/revalidate all three inputs within its serialized
lifecycle event processing, and route start/revoke events before attempting
telemetry ingress. No existing IPC frame/version or Phase12 file is edited.


## One Service owner for runtime and passive ingress

`ReceiverTelemetryServiceAdmission` is a passive, in-process composition
of the Service-minted receiver runtime ledger and the existing strict
`ReceiverTelemetryIngress`. Correlated, acknowledged protected starts update
both in one owner operation. Exact receiver-runtime teardown clears both the
lifetime and diagnostic/replay state, while a stale teardown leaves the new
receiver intact. `observe_after_verified_peer` requires the **independently
OS-verified** Worker PID/session plus current Service Worker generation,
compares it to the active Service-owned runtime **before parsing bytes**, and
then admits bytes under the full nine-field Service-minted receiver binding.
A no-runtime or stale-Worker report is rejected without decoding; reused
key epochs still receive a new baseline. Diagnostic liveness stays separate
from the independently fresh 2-second adaptive quality sample contract.

This composition provides no new authentication, no OS-process lifetime
pinning, no protection against concurrent external Worker replacement if the
caller fails to serialize/revalidate, no IPC transport, no sender, and no
quality promotion. The production Service must eventually own exactly one
such lifetime + ingress pair for each authorized receiver slot, derive
`current_worker` from its authenticated Windows pipe/WorkerManager state,
correlate authorized key epoch and runtime start, and revoke on Worker exit,
disconnect, key clear or stop. All still require real implementation and
physical two-host/GPU qualification. No Astra Phase 12 IPC/version file
changed.


## Real Service lifecycle integration (no telemetry transport)

Phase 10 now attaches its passive `ReceiverTelemetryServiceRuntime` to the
actual **Windows Service event loop**, but does not add any IPC message or
receive a diagnostic report in production yet. The real
`PresentationKeyWorkerLease` created from an authorized Control grant and
confirmed Worker install acknowledgement passes its full **key grant request
ID**, presentation, stream and epoch into typed internal multicast/unicast
start dispatch. A new Worker key install immediately retires older receiver
report authority; the matching confirmed key-install reply can re-establish
only the Service-authorized key under the exact OS-bound current Worker
PID/session and `WorkerManager` generation.

On an already-correlated **successful** multicast or unicast start result, the
Service combines its preserved key epoch and authorized pending request with
the current OS-bound Worker identity and actual typed ACK. Only then does the
existing lifecycle allocate a new receiver generation. Malformed/rejected,
stale-worker or wrong-key starts never activate reporting. Key-grant teardown
revokes only the exact current grant (including the grant request ID), and
Worker restarts/session changes retire both grant and receiver report authority.
This is entirely passive; missing optional telemetry state does **not** change
the existing presentation StreamAnswer or deliver any bytes.

**Still not production telemetry:** no Worker→Service transport, no message
ID/IPC negotiation or bounded sender, no Teacher propagation, and no
2-second network/decoder/adaptive-quality evidence. Do not confuse a verified
key grant, a Worker ACK or a current named-pipe peer with authenticated
receiver telemetry bytes. Before accepting the first live report, implement
an independently authenticated, low-priority, nonblocking channel that
rechecks the current Worker/receiver owner on arrival; coordinate shared IPC
changes with the separate Phase 12 owner. Physical two-Windows-host/GPU/scale
gates remain OPEN.
