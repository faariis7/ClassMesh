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

`PresentationDeliveryReport::snapshot_for_authorized_start` maps actual
Worker AEAD/decode/render/queue-drop counters into a portable
`ReceiverTelemetrySnapshot` only when the separately Service-authorized
media-start request ID matches the complete Service-minted receiver owner
and the **private source binding captured at report emission** exactly
matches the installed protected key grant (including its independently
issued **grant request ID**). Both share control-session, presentation, stream and
key epoch. The local report sequence and all required identities must be
nonzero. A delayed report issued under an old epoch cannot be
relabelled by passing a matching new external owner and current key.
The function carries external Worker/receiver generation identity unchanged
and does **not** authenticate it, authorize transport, or self-activate the
Service admission gate; those are independent Service-controlled lifecycles.
Wrong epoch, grant request, independently authorized media-start request,
session or invalid owner must fail without any serialized bytes. The Worker
must not mint its own start or receiver-generation authorization and must
not repurpose the grant request ID as the media start ID. This helper remains passive, with no new privileged IPC or automatic
adaptation/quality upgrade. Tests cover exact positive mapping and rejection
of every mismatched protected media-key identity field.


## Real Worker diagnostic through the portable Service gate

A Worker-library cross-layer qualification test drives the **real**
`PresentationDeliveryTelemetry::report_if_due` through the
`snapshot_for_authorized_start` consistency guard, fixed-width wire encoder and
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

### Distinct key-grant and media-start identity regression

The Worker cross-layer contract test now uses the actual
`ReceiverTelemetryServiceRuntime`'s confirmed protected grant (request 9)
and independently authorized, successfully acknowledged media start
(request 91), rather than pretending these request IDs are the same. It
binds real five-second local diagnostics to the **Service-minted** runtime,
passes the strict fixed-length codec and current-Worker Service ingress,
then confirms an exact protected grant revocation rejects those same bytes.
This does **not** create live IPC, provide authority to the Worker or
qualify adaptive feedback / physical streaming. A pending async report
must still be bound to the exact Service-issued receiver generation **at
the moment it was emitted**; swapping a new owner onto old same-key bytes
is unsafe and cannot be authorized by the key-only report binding.


## Worker report stamped at emission in a bounded outbox

`PresentationDeliveryPublisher` is a new, **inactive** Worker-library
component that owns local `PresentationDeliveryTelemetry` counters and a
single-slot `ReceiverTelemetryConcurrentMailbox`. An independently
authenticated **Service→Worker** lifetime grant must supply
`WorkerReceiverTelemetryAuthorization`: exact Service-minted
PID/session/Worker generation, control-session, media **start request**,
presentation, stream, key epoch, receiver-runtime generation, plus the
distinct installed key **grant request** and separately authorized start
request ID. The Worker cannot create this grant from local key material or
from a report. Such an authenticated grant channel is **not implemented** by
this PR.

When that authorization is externally supplied, `offer_if_due` calls
the actual five-second Worker local diagnostics and stamps the full
Service-issued owner *at emission time*, before placing the immutable
snapshot in a one-slot, nonblocking `try_lock` mailbox. An eventual
sender may check out only that current owner, must validate the send lease
again and MUST independently confirm current OS-authenticated Service and
receiver authorization at the I/O boundary. Neither a stale checkout nor
an old report can be relabelled with a successor receiver generation.
A same-key retry with a new Service-issued receiver generation clears
the prior emission sequence/replay state, while stale or mismatched
authorization cannot displace the active owner. Exact revocation disables
checkout immediately, even if nonblocking mailbox cleanup reports
contention; receiver-generation high-watermark never resets.

This is **not an authenticated telemetry transport**, not integrated
with the production Worker loop, does not create a new IPC message/version,
perform asynchronous pipe writes, promote diagnostics into quality, or
claim two-host/GPU qualification. The eventual end-to-end channel still
needs a versioned Service-to-Worker authorization grant and an independently
authenticated Worker-to-Service bounded, low-priority, cancellation-aware
sender. Its control-channel priority, backpressure and revocation races
must be tested on native Windows. Five-second cumulative diagnostics remain
distinct from two-second independently fresh network/decoder/adaptive
measurements.


## Service-minted Worker receiver lifetime grant (in-process only)

The Service-owned `ReceiverTelemetryServiceRuntime` now issues an
immutable `ReceiverTelemetryWorkerGrant` only when an exact protected key
has been confirmed by the Worker ACK, a correlated successful media
start has minted a receiver generation, and the independently verified
current Worker PID/session/generation **still matches** both active
lifetimes. Its constructor and fields are private to the Service
control crate; callers can inspect only the exact Service-owned
receiver binding and the protected key-grant identity. It cannot be
issued before the media-start ACK, after key clear/Worker replacement,
or for an obsolete Worker incarnation. The Worker-side
`WorkerReceiverTelemetryAuthorization::from_service_grant` accepts this
grant only when the Worker-installed protected grant matches all five
key fields, including the *separate* grant request ID and epoch;
the media-start ID stays in the Service-issued receiver binding.

Tests compose the actual Service key/start state, grant issuance,
Worker's exact installed key and the single-slot outbox, including
revocation, stale peer and incorrect key/grant rejection. These Rust
types are **not credentials**: a real transport must independently
authenticate the operating-system peer, bind process and session to
the Service WorkerManager generation, negotiate a protected payload
version/capability, deliver the grant to the correct Worker and revoke
it atomically on stop/replace. No new privileged IPC, sender, decoder
quality source, or physical two-host qualification is introduced here.


## Fixed-width Service grant payload, without IPC activation

`receiver_telemetry_grant_wire` defines a bounded **96-byte** v1 *payload*
for the existing Service-issued receiver grant: 8-byte magic/version/reserved
prefix, 56-byte exact receiver (including Service-assigned generation and
media-start request ID), and 32-byte independently confirmed protected key
grant (including its **different** key-grant request ID). Encoding requires
an actual `ReceiverTelemetryWorkerGrant` that only the Service lifecycle can
mint. Decoding is strict and allocation-free, and returns an explicitly
`UntrustedReceiverTelemetryGrant`: malformed length/magic/version/reserved
bytes, zero identities, conflicting presentation/session/stream/epoch are
rejected. A separate read-only consistency check requires exact local Worker
PID/Windows session/Worker generation, installed key identity, and authorized
media-start request ID. This check is **not** authentication or an executable
Worker authorization permit.

**Important version collision:** active Windows IPC remains **v11**.
Phase 12 already reserves **future v12 / message 33** for zeroizing clipboard
success. This grant payload is deliberately **not registered** as an IPC frame,
is not sent by Service or admitted by Worker, and does not change the
protocol version, OS privileges, named-pipe transport or decoder. Future
activation must negotiate a compatible protocol with the Phase 12 owner,
authenticate the Service/Worker peer independently, reject stale/replayed
grants at the receiver and revoke on Worker/key/receiver generation change.
A validated payload alone cannot prove issuance, peer authority, delivery or
freshness. An independent low-priority nonblocking Worker→Service telemetry
return path is still absent; do not misuse the 5-second cumulative diagnostic
as a fresh 2-second adaptive quality sample. Physical two-PC/GPU/soak tests
remain OPEN.


## Receiver generation must be independently pinned before grant consistency

The passive, **untrusted** 96-byte grant decoder now requires the caller's
independently known active Service-issued `receiver_generation` in
`matches_verified_local_state`, in addition to verified Worker identity,
installed protected key and separately authorized media-start request ID.
A missing/zero or changed receiver generation fails closed, even if a reused
Worker process/session, protected key and start request otherwise match.
Regression tests cover generation replacement and tampering of generation
bytes in a well-formed payload. This is still only a local comparison: a
caller MUST pin the expected generation from authenticated Service/lifecycle
state, never copy it from the decoded frame, and MUST independently enforce
Service peer authentication and revocation on every received message. No IPC
version, registration, transport, Worker outbox activation or Teacher feed is
introduced by this change.


## Worker permit construction is closed to downstream callers

The passive `WorkerReceiverTelemetryAuthorization` now has private fields
and read-only accessors. Integration callers cannot assemble a plausible
receiver identity, key-install binding and start request into a permit with
a struct literal; they must go through `from_service_grant` using an
in-process Service-minted grant and matching Worker-installed key. Compile-fail
doctest confirms external literal construction is rejected, and runtime tests
mint real generations through the correlated Service key/start lifecycle,
including stale-receiver, invalid installed key, revocation and bounded
outbox behavior. Malformed internal permits remain covered by a module-local
unit test.

**Not a security boundary by itself:** A Rust caller can instantiate a
separate `ReceiverTelemetryServiceRuntime` in process and produce a
locally consistent record; neither these types nor their constructors
authenticate the Windows OS peer. A future privileged transport must
independently authenticate and pin the live Service's exact Worker/receiver
generation and revoke it at every key/receiver/Worker transition. This
change does not register IPC messages, enable telemetry sending or qualify
physical multi-host operation.


## Detached read-only Worker telemetry checkout boundary

`PresentationDeliveryPublisher::readonly_sender` issues a cloneable
`PresentationDeliveryReadonlySender` suitable for a future independent
low-priority sending thread. It permits only `try_checkout_matching` and
`lease_is_current`, never receiver activation, report publishing, key
installation or revocation. The Worker-owned publisher remains the sole
writer of the one-slot bounded diagnostic mailbox. An atomic active receiver
generation is shared with the reader and cleared before revocation, any
replacement attempt, and publisher destruction, invalidating detached reads
even if mailbox cleanup is contended. A reader compares the generation both
before/after checkout and when checking its send lease; the mailbox still
enforces the entire exact binding, sequence and expiration.

Integration tests exercise an actual separate thread checking out a bound
immutable report, replacement to a Service-minted receiver generation,
stale-lease invalidation, exact revocation and publisher destruction while
a new report is queued. This is a **passive in-process boundary only**,
not Windows peer authentication or an IPC/pipe sender. Any eventual sender
must independently verify the Service's currently authenticated OS peer and
current Worker/receiver generation immediately before nonblocking I/O.
No Phase 12 IPC changes, adaptive-quality claim or physical qualification.

## Single-attempt best-effort diagnostic dispatch boundary (still pre-IPC)

`presentation_delivery_dispatch::try_dispatch_once` composes the existing
detached read-only Worker checkout with the fixed-width 136-byte report codec
and a **caller-injected** one-shot diagnostic sink. The caller must provide an
independently authenticated, authoritative **current Service peer/Worker and
receiver lifetime verifier**; the function checks that predicate before
checkout and again just before local lease validation and the injected
nonblocking write. Reject invalid receiver identities, revoked/expired
leases, stale generations and busy/poisoned mailboxes without a write.
Backpressure and disconnection **discard** a checked-out report after one
attempt: there is no unbounded queue, retry loop, sleep or blocking operation
in this helper. A later fresh report may replace it.

**Security/availability limitation:** this is a **portable in-process
composition**, not authenticated Windows Service/Worker IPC and not live
Worker-loop wiring. Both the verifier and sink are supplied by the
integration caller; a dishonest or stale verifier is not made trustworthy by
its name. The sink contract requires a *complete, genuinely nonblocking*
write; the portable function cannot enforce the Windows pipe mode or detect
partial writes. A revocation can still race between the final local check and
kernel I/O. A production sender MUST use a separate low-priority schedule,
independently authenticate the OS peer, hold/pin its actual Worker generation
and receiver authorization, negotiate any new message version with Astra's
Phase 12 IPC owner, avoid blocking media and privileged control, and rely on
Service-side verified-owner admission *again on arrival*. No quality
promotion or Teacher delivery is added; 5-second diagnostics remain ineligible
for the 2-second adaptive sample-age requirement.

`cargo test --offline -p classmesh-worker --test receiver_authorized_outbox`
covers the **six** extra regressions: valid fixed-width frame once only,
pre-check denial preserving pending data, revocation between checkout and
nonblocking send, Service authority changing during dispatch, backpressure/
disconnect one-attempt drops and cross-receiver isolation. The tests inject
a simulated verifier and sink; they do not establish authenticated transport
or physical two-host security/performance qualification.

## Bounded Worker dispatch -> Service admission composition qualification

The new `receiver_delivery_roundtrip` integration suite drives the
**actual** Service-issued key/start/receiver grant through the actual Worker
`PresentationDeliveryPublisher`, detached read-only checkout and
`try_dispatch_once` into a one-slot Rust `sync_channel(1)`, then admits the
exact 136-byte snapshot through
`ReceiverTelemetryServiceRuntime::observe_after_verified_peer`. It runs the
Worker dispatcher on an independent OS thread and verifies that contiguous
five-second counter reports produce only the observed authenticated/queue-drop
intervals, never fabricated decode/present success.

Congestion drops the middle report with **one** `try_send` attempt and zero
retries, so Service sees a sequence gap and returns `Baseline` rather than
asserting healthy uninterrupted media. Later contiguous reports restore only
the actual interval. Independently revoked Service Worker lifetimes reject
previously-sent valid bytes, even if the sender had a current local lease.
An incoming report attributed to a different verified Worker generation is
rejected before decoding and cannot poison the correct active baseline.

**Scope/limitations:** this is strictly portable **in-process, test-only**
composition; `sync_channel` is not a Windows IPC channel. The harness passes
synthetic independently selected Worker identity and simulates a trustworthy
Service peer predicate. It does NOT establish or exercise OS authentication,
new message IDs, live Worker loop delivery, Service→Teacher, automatic quality
control, native GPU performance or the two-physical-PC gate. Phase 12 owns its
IPC changes and future true authenticated transport negotiation.


## Native two-process Windows diagnostic pipe qualification (test-only)

The Windows-only `receiver_native_pipe` test uses an actual local byte-mode
Win32 named pipe with a DACL for the current interactive test-user SID and
LocalSystem. A separately spawned Rust test child connects and writes one
fixed 136-byte diagnostic. The test Service parent calls the existing
`NamedPipeServer::accept_expected`, which obtains the **OS-observed** client
PID and Windows session and compares them to the known spawned child. Only
after that peer check does the test locally simulate correlated protected
key/start ACKs, mint a `ReceiverTelemetryServiceRuntime` generation and
admit the received bytes. An authenticated pipe peer claiming a *different*
PID in its serialized report is rejected; revocation rejects already-read
bytes. Neither the payload's PID nor any credential assertion from the child
can activate the Service lifetime. The child uses real Windows process
isolation, and native `cargo test` runs under a non-elevated account.

**Hard limitation:** this is an independent **native test fixture**, NOT a
production telemetry IPC endpoint or the actual LocalSystem Service. Test
startup authorizations are simulated, Windows OS peer checking covers the
Service's observed *client* PID/session only, and the child does not yet
verify/pin a real LocalSystem Service server token and process lifetime. The
existing `NamedPipeClient::write_all` used in the test is BLOCKING and MUST
NOT be wired into the media/decode or privileged control loop. True
nonblocking, lower-priority transport, complete frame boundaries, protocol
negotiation, independently pinned Service peer and lifecycle synchronization
remain future gates. No Phase 12 changes, app sender/receiver activation,
automatic quality, Teacher feed or physical two-PC qualification.

## Native forged-binding matrix (test-only follow-up)

The real Windows two-process pipe test now carries **nine independent,
syntactically valid forged receiver identity fields** across separate child
process runs: OS-reported process ID and Windows session ID, Service-owned
Worker generation, control session, media-start request, presentation,
stream, key epoch, and receiver generation. Every test keeps the actual
Named Pipe OS-attested PID/session intact while mutating only the bytes
claimed by the child. Service admission must reject each claim, and none
may mark receiver telemetry as fresh. The positive two-process baseline
and rejection of already-read bytes after revocation remain unchanged.

This is **native test coverage, not production integration**. The pipe
client continues to use a blocking write on disposable test threads,
and correlated Service key/start acknowledgements are simulated.
It does not qualify the actual LocalSystem Service or independently
pin its server token, enable Worker-to-Service / Service-to-Teacher
telemetry, authorize quality promotion, or close Phase 10G / other
physical-hardware acceptance gates.


## Bounded byte-stream framing seam (passive, not live IPC)

`ReceiverTelemetryFrameStream` is a Service-owned, **passive** parser for the
fixed-width, versioned 136-byte diagnostic over a future authenticated Windows
byte-mode Named Pipe. OS reads need not align with record boundaries. The
parser retains **at most one incomplete record** (135 bytes), consumes at most
**544 bytes per call** and returns at most **four complete records** per call,
even when an earlier read left a partial record. It has no background queue,
thread, socket, timer, sender, privilege or implicit Service activation.
The parser does not own a thread or wall clock. Its active Service owner
must supply independent monotonic receive timestamps and schedule the passive
expiry check on a bounded timer even if no bytes arrive. This state guard is
not a replacement for cancellation-safe Windows I/O.

Only the independently authenticated and currently authorized Service
receiver binding may activate the parser. The caller must serialize such
activation and reads with Worker/receiver revocation; a caller-supplied
"current owner" is only a comparison, **not a proof of authority**. Switching
to a different receiver clears partial bytes, while repeating the same
activation preserves them. Wrong-owner reads cannot mutate buffered data.
Malformed complete records, forged embedded bindings, zero-length disconnects
and oversized reads clear the entire parser instead of resynchronizing by
scanning untrusted bytes. Each batch is all-or-nothing; no records are emitted
from a batch containing a malformed record.

Pure-Rust tests exercise every split point, coalescing, maximum-size reads
after a partial, Service admission separation, owner replacement and stale
teardown, forged report binding, malformed batches, liveness disconnect and
oversize. The Windows test fixture adds a real separate-process named-pipe
read with deliberately short 17-byte read buffers, proving framing after OS
PID/session attestation and then baseline admission in a **test-owned** Service
state machine.

**Remaining production gates:** independently pinned real LocalSystem
Service/server peer identity, secure version negotiation, cancel-safe
nonblocking diagnostic sender/reader, Service event-loop/lifecycle binding,
Worker/Service/Teacher delivery and real per-receiver adaptive input
qualification. The existing blocking named-pipe test I/O is **not suitable**
for a Worker render/decode or privileged Service control thread. Phase 10G
physical 5/10/20/30-receiver evidence remains OPEN; no physical network,
codec, GPU or user-visible performance claim follows from hosted tests.

## Service-owned framed ingress handoff (passive, no production IPC)

`ReceiverTelemetryServiceRuntime` now owns its `ReceiverTelemetryFrameStream`
inside the **same serialized key/Worker/receiver lifetime**. An independently
correlated, authorized key install and actual Worker receiver-start ACK arm
the exact Service-minted binding. Key-install initiation, exact grant
revocation and Worker exit/replacement clear both Service admission and any
partial buffered frame. A stale Worker candidate may not consume or revoke
a newer stream, and invalid/malformed stream traffic retires the current
receiver and key rather than keeping misleading report liveness.

`observe_stream_chunk_after_verified_peer` accepts bounded byte-mode
chunks **only after** the caller separately authenticates the actual Windows
named-pipe peer and checks the live launched process/session/generation.
It is not a peer authenticator: caller-controlled arguments cannot establish
authority. No state changes on wrong-owner reads. The stream parser validates
each complete frame and rejects incorrect embedded receiver identities.
Within a single coalesced pipe read, only the **latest report** is passed
to the existing replay/counter/interval admission gate; earlier reports
have no independent trustworthy Service arrival timestamp and must not
fabricate a healthy adaptive-quality interval. Out-of-order/duplicated
records inside one batch fail closed; replay across reads also retires
current telemetry. A partial frame alone never refreshes freshness.

Portable TDD tests cover incomplete frames, coalescing, stale peer, key
replacement/revocation, worker exit, malformed fields, duplicate sequence
and disconnected reads. The independent native Windows two-process fixture
now passes forced 17-byte reads directly into this SAME Service runtime
instead of reconstructing a frame and separately admitting it.

**Not yet live:** no production new IPC message, pipe listener, Service
server-token attestation, cancel-safe nonblocking sender/reader, deployed
telemetry integration, Teacher feedback delivery, or physical classroom
performance evidence. Caller must schedule the new passive partial-frame
deadline timer, implement cancellation-safe Windows OS read deadlines,
and serialize OS peer admission with Service revocation. These tests do
**not** close Phase 10G physical qualification or Phase 12 security gates.

## Service-monotonic partial-frame deadline (still passive)

`ReceiverTelemetryServiceRuntime::observe_stream_chunk_after_verified_peer`
now passes its Service-received `Instant` to
`ReceiverTelemetryFrameStream::accept_verified_at`. The parser tracks at
most one partial frame and fixes its first-byte timestamp for its full
lifetime. Subsequent fragments **cannot extend that deadline**. At exactly
`MAX_RECEIVER_TELEMETRY_PARTIAL_AGE` (2 seconds) the partial frame may
finish, but any later byte triggers `PartialTimedOut` and retires the
current key, receiver admission, and partial bytes. Service clock
regression and attempts to splice untimed fixture reads into Service-timed
partial records also fail closed; a wrong/stale Worker cannot consume a
successor's data or invoke expiry.

A real Service event loop **must** call
`expire_partial_stream_after_verified_peer(worker, service_now)` from
its own independent monotonic timeout tick, including when the Worker
ceases to write. This performs bounded O(1) time/space validation and
is safe to run on an idle reader, while preserving complete reports and
their ordinary freshness/admission state. It never waits, reads a pipe,
schedules a timer, creates credentials, admits a Worker itself, invents
RTT/loss or invokes adaptation. TDD regressions cover expiry on both
the next pipe read and an idle Service tick, exact boundary, clock
regression, replacement/stale timer isolation, and mixed parser modes.

**Still required to go live**: genuine authenticated Service/Worker pipe,
separately attested and bounded cancel-safe Windows read/write path and
timer ownership, Worker dispatch, authorized Teacher result delivery and
real physical qualification. Until these are implemented and validated
this is still passive state, not production telemetry.

## Service loop poll-tick wiring (no production telemetry ingress)

The existing Service `WorkerManager::poll` path already runs at a bounded
250ms cadence. The Windows Service loop now calls
`service_receiver_telemetry_poll_tick` after its authoritative Worker liveness
poll, using the current OS-bound process/session/Worker generation and its own
monotonic `Instant`. This calls the parser's two-second partial-frame deadline
without depending on another pipe read. Normal startup without an active
telemetry grant is a no-op; a disappeared authenticated Worker revokes its
Service receiver key. A stale candidate Worker cannot retire a newer live
receiver. Expired partial data retires the admission key and is diagnosed
without stopping the Service's control plane.

The real Service still has **no live Worker-to-Service telemetry byte reader
or sender**; therefore no partial diagnostic actually enters production
today. This is timer scheduling and lifecycle hardening only. Native
Windows Service bridge tests cover expiration during idle reads, missing
Worker revocation and stale Worker isolation. The code does not configure
a new IPC message or modify Phase 12 privileged policy, and it does not
qualify the Phase 10G physical network gate.

## Bounded Service-only admitted diagnostic candidate (no Teacher transport)

A Service-owned `ReceiverTelemetryServiceRuntime` now has **exactly one**
pending playback-counter delta. Only `Interval` from a previously
OS-authenticated Worker, precisely current Service-owned protected key and
receiver generation, valid ordered wire and replay/counter/clock admission may
populate it. The first report and a rebaseline from sequence gaps/long
silence clear the candidate; they do not imply a measured healthy interval.
Coalesced input uses only the latest accepted report. A subsequent accepted
interval replaces the earlier unsent one instead of accumulating backlog.
There is no queue, network I/O, allocation per receiver or sender thread.

`take_diagnostic_after_verified_peer` rechecks the current Worker and
receiver binding. A stale Worker cannot consume or clear someone else's
pending delta. The Service-monotonic candidate expires after
`MAX_SERVICE_DIAGNOSTIC_AGE` (5 seconds); future/retrograde clocks also
discard it. Each successful checkout consumes once. Changing installed
keys, Worker generation or receiver lifetime, invalid wire, timeout or
revocation deletes the candidate. The alternative single-message ingress
cannot allow a failed spoofed call to drain an authorized candidate.

This **is not a Teacher authorization token or an automatic push**. A real
caller MUST authenticate/authorize the exact Teacher PrincipalId and active
control session *before* checkout, then use a separately versioned
authenticated, bounded delivery channel. Neither the local playback counters
nor these intervals represent RTT, packet loss, bandwidth or a validated
adaptive-quality promotion. The dedicated OS-attested and cancellation-safe
Worker-to-Service telemetry channel is also still required. Physical 10G
5/10/20/30-device qualification and Phase 12 security gates remain open.

## Recheck a previously checked-out diagnostic before I/O (dependent slice)

After checkout, **do not** interpret possession of a report as permanent
authority: an intervening receiver restart, newer admitted sample or
rebaseline invalidates that candidate even when its original key epoch
looks unchanged. Before an eventual authorized Teacher delivery, use
`diagnostic_still_current_after_verified_peer`, supplying the independently
verified current Worker and Service-monotonic timestamp. The check compares
the **entire exact admitted diagnostic** against the latest Service-owned
value, including its counters and timestamp, not only its sequence.

This read-only check is not an authentication credential, not Teacher
PrincipalId/session authorization, and cannot make a concurrent outbound
write atomically safe: the real Service must serialize any send with
receiver revocation and re-check the authenticated Teacher session. No
new IPC message, sender, quality estimate or physical qualification is
provided by this slice.


## Native Windows telemetry-only pipe primitive (isolated, not activated)

`classmesh-win32::ReceiverTelemetryPipeListener` and
`ReceiverTelemetryPipeClient` are independent of the blocking
Worker↔Service control channel and the future-v12 sensitive clipboard channel.
A bounded pipe ADDRESS combines Service process ID, Worker Windows session and
generation, and Service-minted receiver generation; it is not an auth token.
The server's real local named pipe is inbound-only, write-only for Worker,
DACL-restricted to LocalSystem + a production session user's exact SID, and
refuses remote clients. Native peer PID/session come from Win32 pipe APIs;
Service additionally compares the currently running **original launched
Worker process HANDLE** and re-reads its own exact active receiver identity
before/after accept and read, including after potentially blocking kernel I/O.
Client verifies the server's OS process ID against the Service identity
authenticated by the existing primary control channel.

Both I/O directions require overlapped handles, bounded frame size
(Worker exactly 136-byte receiver telemetry v1, Service at most four frames
per read) and a 1–250ms per-operation deadline. A timed-out request is
cancelled with `CancelIoEx` and synchronously drained with
`GetOverlappedResult` before request/event/buffer memory is released. A
faulty Windows driver can delay that drain beyond the **logical** deadline;
do not run this code on media/control threads. A timed-out, disconnected or
revoked incarnation must be discarded rather than reused. Native Windows
tests exercise an actual local pipe, Win32-reported peer identity, server-PID
forgery rejection, zero/oversize and deadline rejection, and cancel/drain.

**This is an OS primitive, not live application integration.** There is still
no scheduled Service listener or separate Worker diagnostic sender, no
authenticated receipt into `ReceiverTelemetryServiceRuntime`, and no
authorized Teacher publication. Native Windows CI, explicit Service ledger
binding, cancellation-safe lifecycle/ownership and multiple-machine Phase 10G
evidence are independent requirements before declaring production readiness.
Do not infer authenticated sessions or physical evidence from pipe naming,
hosted CI or a localhost test.


## Native two-process transport and failed-send retirement checkpoint

Windows tests use a REAL child process, not only an intra-process thread,
to verify the PID reported by the named-pipe kernel API, the Windows
session, and one complete 136-byte transmission. A failed attempt now
permanently takes/drops the Worker-owned `ReceiverTelemetryPipeClient`
handle, and follow-on sends return `TelemetryClientRetired`: no retry can
silently resume a partial or stale record. The Service may later own an
independently duplicated original launched Worker process HANDLE via
`SessionProcess::try_clone`, rather than trusting a PID reopened after
process termination. Its native regression checks that dropping the
original owner does not close the clone.

Native two-process smoke and this original-HANDLE lifecycle are
prerequisites, not an activation. No application sender/listener startup,
Teacher wire or mTLS permission, quality promotion, production default
or classroom hardware qualification is implied.


## Idle read is not a disconnect

Worker playback diagnostics are generated on a ~5-second cadence. A Service
reader operating with the required per-request <=250ms Win32 cancellation
budget must distinguish a **cancelled+drained idle read** from pipe death:
return `Ok(None)` only after comparing the original launched Worker HANDLE,
real OS pipe PID/session and current Service receiver generation again.
Continue using a new bounded overlapped read request, never a stale kernel
buffer. A real frame yields `Ok(Some(received_bytes))`. A revoked Worker,
wrong receiver, true disconnect or other I/O failure permanently retires the
connection. A separate Service-monotonic two-second partial-record deadline
still applies to a frame that has actually begun. Native Windows tests prove
multiple empty windows followed by a real complete frame, and fail-closed
revocation after the idle window.


## Optional native Worker→Service runtime (off by default)

The Phase 10 experimental runtime can be enabled by a **privileged Service
process environment** setting \`CLASSMESH_ENABLE_PHASE10_TELEMETRY=1\`. A
missing or differently valued setting keeps both the native listener and
the grant frame disabled in production. Even when enabled, the Service
only sends the v11 typed receiver-binding grant over existing authenticated
control IPC to a Worker that advertised the exact optional capability,
after a protected key install and matching receiver start ACK.

The Service creates an ACL-restricted inbound-only local native pipe,
retains an owned duplicate of the original Worker process HANDLE, and
serializes its key/restart/revocation lifecycle on the privileged main
loop. A single independent background reader waits for the OS-attested
peer, runs bounded cancel/drain reads, assembles only complete 136-byte
receiver diagnostics and enqueues at most one complete frame without
blocking the control plane. The Service main loop checks the exact
Worker/receiver incarnation AGAIN before invoking existing framed
telemetry admission. A full mailbox drops a whole report; the next
sequence gap rebaselines rather than fabricating smooth metrics.

The Worker independently checks the OS Service PID on the already
authenticated primary pipe, the group-media key and the currently
running media-start request ID before accepting the grant. An isolated
sender thread owns the one-shot secondary pipe and single-slot queue.
Only real playback counters from an exact healthy receiver become wire
snapshots. A mismatched/rekeyed/restarted Worker drops its queue; an I/O
failure retires the incarnation. The protocol does not send clipboard
plaintext, Teacher messages, network RTT or inferred UDP loss.

This transport deliberately DOES NOT publish to Teacher or choose a
production quality default. It must pass exact-head native Windows CI,
full binary-pair/VM tests and independent Teacher PrincipalId/session
authorization before actual classroom qualification. Physical Phase
10G Issue #288 stays open.

## Native-report expiry across read completion and queued admission

The native Service reader now persists the **Service monotonic timestamp
of the first received frame byte** through the one-slot mailbox. An
individual bounded overlapped read may begin before the two-second partial
deadline and finish after it. The reader must reject the late completion
even if it fills all 136 bytes; it must also reject a finished record that
waited in the mailbox past the deadline. The Service owner rechecks that
timestamp before admitting a record. A retired native transport must never
admit an already-queued frame just because the passive receiver runtime
still holds a valid key/start binding. Unit tests cover boundary equality,
a delayed final read, expired queued data, and retired transport backlog.

These freshness decisions do not derive Worker RTT/loss or grant Teacher
access, do not relax the default-off rollout setting, and do not replace
physical Phase 10G testing on real classrooms.

## Native reader re-arm and Service clock-regression hardening

A retired Service native telemetry reader must not be revived by re-arming
an identical Worker PID/session/generation and receiver generation. Each
locally armed reader gets a strictly increasing, Service-private incarnation
which is not put in IPC frames or supplied by Worker. The reader loop checks
that exact incarnation before and after OS pipe I/O; its one-slot mailbox
retains the arm incarnation, and privileged Service admission rejects an old
arm's queued report even when its OS receiver identity and timestamp still
match. Counter exhaustion fails closed rather than recycling a token.

A future-dated first-byte timestamp relative to the Service's monotonic clock
is expired immediately; a completed or partial report cannot become fresh
through `Instant` saturating subtraction on Windows. The existing two-second
partial-record deadline, bounded queues, exact OS Worker identity and default-
off activation remain unchanged. Native Windows CI tests are required, and
none of this qualifies physical receiver scale or makes local counters into
RTT/packet-loss estimates.

## Teacher Diagnostics panel: authenticated playback counters (2026-10-22)

The Teacher eframe Diagnostics panel has a separate **Authenticated receiver playback** section for optional v0.8/capability-18 Service-admitted counters. It does **not** reuse or manufacture a ReceiverQualitySample (network RTT, loss, jitter or adaptation votes). Teacher's UI is bound to one selected source and exact current presentation epoch/control session. Its context may be supplied only by an already authenticated/enrolled Service QUIC client with negotiated cap 18; the UI never authenticates a peer. Replay, wrong media/session/legacy version and stale disconnect are rejected by the existing Teacher ledger. Data disappears on device/session change, revocation, or after 10 seconds without a new accepted report; no automatic production transport is enabled.

This is a UI projection and an authenticated-client integration interface, **not evidence of a live Teacher QUIC subscription or full classroom physical qualification**. That integration must use an actually enrolled PrincipalId and TLS session rather than hand-authored UI context. Phase 10G physical gates in #288 remain open.

The projection additionally rejects a new authenticated report whose Teacher-local monotonic reception timestamp is earlier than the last accepted report. The check runs *before* mutating replay state; rejected clock-reversing samples cannot overwrite counters, refresh freshness, or consume a legitimate next sequence. This does not establish clock synchronization between Worker, Service and Teacher, and does not change the external authenticated QUIC-client responsibility.

## Teacher live QUIC receive boundary (candidate, not GUI production wiring)

The classmesh-control Teacher playback receive adapter now accepts a
**caller-owned, existing** ClientControlSession and performs an actual bounded
read from its QUIC ControlChannel (not synthetic events or a separate shadow
receiver). Before and after each read it resolves the TLS-verified server
certificate against a newly acquired snapshot from the canonical
LiveAuthorizationStore **at both authorization points**, requires the exact
expected StudentDevice PrincipalId, and checks a freshly sampled trusted wall
clock for credential expiry. A policy publication revoking that credential
while a network read is pending is denied after I/O, never silently accepted
using the older snapshot. A poisoned policy lock fails closed. It rejects a wrong negotiated Teacher role,
zero or different control session, and playback diagnostics without a negotiated
v0.8 ReceiverPlaybackDiagnostics (capability 18) contract.

Other control envelopes remain available to the *single owner* of the
session's multiplexed control dispatcher; the adapter does not silently drop
messages intended for group-media, feedback, key negotiation or other handlers.
Its AuthenticatedTeacherControlMessage has a private constructor to prevent
UI code from fabricating the proof object. The existing source/session-bound
Teacher ledger still independently validates diagnostic payloads, presentation
epoch, generation, sequence and freshness; this new transport check alone does
not grant permission to present or emit any control command.

Real loopback QUIC tests cover the matched trusted certificate, wrong expected
PrincipalId, inactive credential, v0.8 capability denial, wrong session, unrelated
message preservation and credential **expiry during the receive await**. Tests
use test-only root certificates in a local loopback environment, not production
enrollment. Production callers MUST construct a trusted enrolled client endpoint,
refresh policy and wall time, run one centralized QUIC dispatcher, map the
verified Service PrincipalId to the correct selected monitoring source, and
revoke playback projection on disconnect or trust failure. **The eframe Teacher
GUI is not yet wired to this adapter**, so this is not an enabled production
Teacher subscription. Never infer RTT, packet loss, adaptive quality or Phase
10G physical-qualification results from receiver playback counters.
