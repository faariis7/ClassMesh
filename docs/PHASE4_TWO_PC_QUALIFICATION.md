# Phase 4 two-PC qualification

This is the final physical validation gate for ClassMesh Phase 4. Hosted CI proves the code builds and deterministic tests pass, but it cannot prove real Desktop Duplication, Media Foundation encode/decode, D3D11 presentation, or two-machine LAN latency.

The test uses two signed-in Windows PCs on the same wired LAN:

- **Teacher PC** — capture + hardware H.264 encode + UDP media sender + feedback listener.
- **Student PC** — UDP receiver + hardware H.264 decode + D3D11 flip-model render + feedback sender.

The same machines also run the synthetic UDP vs QUIC Datagram benchmark introduced in PR #29.

## Required CI artifacts

Download and extract these Windows artifacts from a successful `main` CI run:

- `classmesh-media-probe-windows-x64`
- `classmesh-media-receiver-windows-x64`
- `classmesh-media-recovery-probe-windows-x64`
- `classmesh-network-impairment-proxy-windows-x64`
- `classmesh-transport-benchmark-windows-x64`

Place the `.exe` files in one directory on each test PC, for example `C:\ClassMesh\phase4\artifacts`.

The repository script `scripts/phase4-two-pc.ps1` wraps the executables and saves combined stdout/stderr logs under `phase4-results`.

## Network preparation

Use a private/wired LAN for the baseline. Record both IPv4 addresses before testing.

Recommended ports:

- UDP `57000` — student media receiver.
- UDP `57001` — teacher feedback receiver.
- UDP `57010` — teacher impairment proxy input.
- UDP `57100` — synthetic UDP/QUIC Datagram benchmark.

If Windows Firewall blocks the test, allow these inbound UDP ports for the Private profile on the appropriate machine. Do not disable the firewall globally.

Example PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "ClassMesh Phase4 Media" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 57000,57001,57010,57100 -Profile Private
```

Remove the temporary rule after qualification if it is not needed later:

```powershell
Remove-NetFirewallRule -DisplayName "ClassMesh Phase4 Media"
```

## 1. Healthy UDP vs QUIC Datagram benchmark

Use the same duration, packet rate, and payload size for both transports. The default qualification workload is:

- 60 seconds;
- 500 packets/second;
- 1000-byte application datagrams.

### UDP

On Student:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode TransportServer -Transport udp -BinDir C:\ClassMesh\phase4\artifacts -Seconds 60
```

On Teacher:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode TransportClient -Transport udp -Peer <STUDENT_IP>:57100 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 60 -Pps 500 -PayloadBytes 1000
```

Record from the client log:

- accepted datagrams;
- effective loss;
- RTT min/avg/p50/p95/p99/max;
- send errors.

### QUIC Datagram

Start the QUIC server on Student:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode TransportServer -Transport quic -BinDir C:\ClassMesh\phase4\artifacts -Seconds 60 -CertPath C:\ClassMesh\phase4\classmesh-quic-cert.der
```

The server writes a DER certificate before waiting for the client. Copy that exact file to Teacher. This certificate is only for the benchmark; it is not the Phase 5 enrollment identity model.

Then run on Teacher:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode TransportClient -Transport quic -Peer <STUDENT_IP>:57100 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 60 -Pps 500 -PayloadBytes 1000 -CertPath C:\ClassMesh\phase4\classmesh-quic-cert.der
```

Record the same application metrics plus QUIC path statistics:

- path RTT/min RTT;
- congestion window;
- lost packets/bytes;
- congestion events;
- MTU;
- datagram send-buffer space.

Do not select a production default from one number alone. Compare latency distribution, loss, send errors, complexity, and the live media behavior below.

## 2. Live 1080p30 baseline

Use continuous high-motion content on the Teacher desktop. A 60 fps local video, animated browser content, or similarly changing scene is preferable to a mostly static desktop.

On Student, start hardware decode + D3D11 presentation and send feedback directly to Teacher:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaReceiver -Peer <TEACHER_IP>:57001 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120
```

On Teacher, start a zero-impairment proxy to keep the topology identical to later loss tests:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaProxy -Peer <STUDENT_IP>:57000 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120
```

Then start capture/encode/streaming through the local proxy:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaSender -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120
```

Baseline pass conditions:

- Student visibly renders continuous live motion.
- Hardware encoder and decoder initialize successfully.
- `decode_errors=0` or only isolated explained recovery errors.
- `present_errors=0` in the healthy run.
- No sustained NACK/keyframe-request storm.
- Proxy `queue_depth` returns to zero and does not grow monotonically.
- Sender `in_flight`/pool usage stays bounded.
- No device/control identity is treated as offline because media has a problem.

## 3. Deterministic loss/jitter/reorder matrix

Keep Student receiver and Teacher sender commands unchanged. Restart the proxy for each profile.

### 1% loss

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaProxy -Peer <STUDENT_IP>:57000 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120 -LossBp 100 -JitterMs 5 -ReorderBp 100 -ReorderDelayMs 10 -Seed 42
```

### 3% loss

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaProxy -Peer <STUDENT_IP>:57000 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120 -LossBp 300 -JitterMs 20 -ReorderBp 300 -ReorderDelayMs 20 -Seed 42
```

### 5% loss

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaProxy -Peer <STUDENT_IP>:57000 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 120 -LossBp 500 -JitterMs 40 -ReorderBp 500 -ReorderDelayMs 30 -Seed 42
```

Expected behavior is visible degradation and recovery, not an ever-growing latency queue or session failure. Record:

- proxy impairment drops/reorder/peak queue depth;
- receiver sequence gaps, reorder count, NACKs, keyframe requests, stale drops, decoded/presented frames, decode/present errors;
- sender retransmits, feedback received, keyframe forces, pool/rate drops;
- whether picture recovery occurs without restarting either process.

## 4. Recovery injection

Run the live path and exercise the receiver's scheduled GPU-media recovery path:

```powershell
C:\ClassMesh\phase4\artifacts\classmesh-media-receiver.exe --listen 0.0.0.0:57000 --seconds 120 --render --feedback-to <TEACHER_IP>:57001 --recover-after-frames 300
```

Pass condition: decode/render resources rebuild, the stream resumes, and feedback/recovery remains bounded without restarting the whole ClassMesh device session.

## 5. 30-minute soak

Run the 3% profile for 1800 seconds:

Student:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaReceiver -Peer <TEACHER_IP>:57001 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 1800
```

Teacher proxy:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaProxy -Peer <STUDENT_IP>:57000 -BinDir C:\ClassMesh\phase4\artifacts -Seconds 1800 -LossBp 300 -JitterMs 20 -ReorderBp 300 -ReorderDelayMs 20 -Seed 42
```

Teacher sender:

```powershell
.\scripts\phase4-two-pc.ps1 -Mode MediaSender -BinDir C:\ClassMesh\phase4\artifacts -Seconds 1800
```

The soak passes only when:

- rendered video remains live;
- latency does not steadily increase;
- queue depth/pool usage stays bounded;
- memory/handle usage is not visibly growing without bound;
- recovery counters remain explainable;
- the media path can degrade/recover without losing the device/control session.

## 6. Phase 4 exit decision

Update `docs/PHASE4_TWO_PC_RESULTS.md` with the measured results and attach the saved logs to the related issue/PR if useful.

Phase 4 may be closed only when Issue #3 acceptance is demonstrated on physical Windows hardware:

1. 1080p30 teacher motion is rendered on the second PC.
2. Healthy wired-LAN end-to-end latency meets the engineering target of `<100 ms`, once the available latency instrumentation can substantiate it.
3. The 30-minute run has no steadily increasing delay.
4. 1–5% injected loss degrades and recovers video without dropping the device/control session.
5. UDP and QUIC Datagram benchmark results are recorded before selecting the unicast default.

If a metric cannot yet be measured directly, mark it **not instrumented** rather than claiming a pass. That missing instrumentation becomes the next Phase 4 code task.