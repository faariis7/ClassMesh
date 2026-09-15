# Phase 4 network impairment qualification

This test validates that the ClassMesh one-to-one media path degrades and recovers under controlled UDP packet loss, jitter, and reordering without introducing an unbounded media queue.

The impairment proxy is a qualification tool only. It is not part of the production media architecture and it does not carry control traffic. Receiver feedback should travel directly back to the teacher diagnostic sender.

## Topology

Run the proxy on the teacher machine so only two Windows PCs are required:

```text
Teacher media probe
    |
    | UDP H.264 media -> 127.0.0.1:57010
    v
ClassMesh impairment proxy (teacher PC)
    |   deterministic loss/jitter/reordering
    |
    +-----------------------> Student :57000

Student feedback : ephemeral
    +-----------------------> Teacher :57001
```

The feedback path deliberately bypasses the impairment proxy. This isolates media impairment from the Phase-4 diagnostic feedback channel and makes retransmit/keyframe recovery behavior observable.

## Build artifacts

CI publishes these Windows executables:

- `classmesh-media-probe.exe`
- `classmesh-media-receiver.exe`
- `classmesh-media-recovery-probe.exe`
- `classmesh-network-impairment-proxy.exe`

## Baseline test

First prove the stream without impairment.

On the student PC:

```powershell
.\classmesh-media-receiver.exe --listen 0.0.0.0:57000 --seconds 120 --render --feedback-to <TEACHER_IP>:57001
```

On the teacher PC, start the proxy:

```powershell
.\classmesh-network-impairment-proxy.exe --listen 0.0.0.0:57010 --to <STUDENT_IP>:57000 --seconds 120
```

Then start the teacher media probe:

```powershell
.\classmesh-media-probe.exe --seconds 120 --udp-to 127.0.0.1:57010 --feedback-listen 0.0.0.0:57001
```

Expected baseline:

- student continuously decodes and presents H.264;
- proxy reports zero impairment drops and zero queue drops;
- teacher receives no sustained recovery storm;
- queue depth returns to zero rather than growing over time.

## 1% packet-loss test

Keep the student receiver command unchanged. Run the proxy with deterministic 1% loss:

```powershell
.\classmesh-network-impairment-proxy.exe --listen 0.0.0.0:57010 --to <STUDENT_IP>:57000 --loss-bp 100 --seed 42 --seconds 300
```

Start the teacher media probe for the same duration:

```powershell
.\classmesh-media-probe.exe --seconds 300 --udp-to 127.0.0.1:57010 --feedback-listen 0.0.0.0:57001
```

Expected behavior:

- receiver NACK count rises;
- teacher retransmit count rises when packets are still inside the live retransmit cache;
- occasional keyframe requests are acceptable when a frame becomes stale;
- the control/device session must remain independent from media loss;
- no steadily increasing queue depth is acceptable.

## 3% loss + jitter + reordering

This is the primary Phase-4 recovery scenario:

```powershell
.\classmesh-network-impairment-proxy.exe `
  --listen 0.0.0.0:57010 `
  --to <STUDENT_IP>:57000 `
  --loss-bp 300 `
  --jitter-ms 8 `
  --reorder-bp 500 `
  --reorder-delay-ms 12 `
  --seed 42 `
  --seconds 600
```

Run the student receiver and teacher probe for 600 seconds as above.

Expected behavior:

- reassembly tolerates moderate reordering;
- NACK repairs recent missing packets;
- stale media is abandoned instead of accumulating latency;
- keyframe requests are coalesced rather than creating an IDR storm;
- the student resumes decode after a recoverable loss sequence;
- proxy queue drops should remain zero under normal test settings.

## 5% packet-loss stress test

```powershell
.\classmesh-network-impairment-proxy.exe --listen 0.0.0.0:57010 --to <STUDENT_IP>:57000 --loss-bp 500 --jitter-ms 12 --reorder-bp 800 --reorder-delay-ms 18 --seed 99 --seconds 600
```

This is a degradation test, not a promise of visually perfect video. The acceptance target is bounded latency and recovery without tearing down the independent device/control session.

## 30-minute soak

After the shorter tests pass, run:

```powershell
.\classmesh-network-impairment-proxy.exe --listen 0.0.0.0:57010 --to <STUDENT_IP>:57000 --loss-bp 300 --jitter-ms 8 --reorder-bp 500 --reorder-delay-ms 12 --seed 42 --seconds 1800
```

Teacher:

```powershell
.\classmesh-media-probe.exe --seconds 1800 --udp-to 127.0.0.1:57010 --feedback-listen 0.0.0.0:57001
```

Student:

```powershell
.\classmesh-media-receiver.exe --listen 0.0.0.0:57000 --seconds 1800 --render --feedback-to <TEACHER_IP>:57001
```

Record at least:

- teacher encoded frames and bytes;
- UDP packets and retransmits;
- feedback received/errors;
- keyframe grants/suppressed requests;
- student sequence gaps and reordered/duplicate packets;
- NACK and keyframe-request counts;
- decoded/presented frames and decode errors;
- GPU recovery count and longest recovery duration;
- proxy impairment drops, reorder count, queue drops, and peak queue depth.

## Interpretation

Passing this qualification means the Phase-4 UDP prototype has demonstrated bounded recovery behavior under deterministic network impairment. It does **not** by itself prove the final `<100 ms` end-to-end latency target because capture-to-display timing across two independent PCs needs a synchronized measurement method or a round-trip-based benchmark.

The next transport step after this qualification is to add the QUIC Datagram benchmark and compare it against UDP unicast under the same workload and impairment profile before selecting the production one-to-one transport default.
