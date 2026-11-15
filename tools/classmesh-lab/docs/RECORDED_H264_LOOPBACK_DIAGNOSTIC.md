# Recorded H.264 → real UDP receiver: lab-only media qualification

**Not production streaming, authentication, live screen capture, hardware decoding, rendering, or completion of MVP issue #688 M3.** This restricted tool is a temporary laboratory source for diagnosing the existing ClassMesh UDP media framing/reassembly independently of a hardware encoder. It is not invoked by Teacher, Service or Worker in normal operation. It refuses any non-IPv4-loopback destination and applies strict input, access-unit, and framerate limits.

## Preparation on a disposable Windows VM with FFmpeg-generated input

The following creates a **locally generated moving pattern**, not a captured classroom screen. On a machine with FFmpeg + `libx264`:

```sh
ffmpeg -f lavfi -i 'testsrc2=size=32x32:rate=12' -t 3 -pix_fmt yuv420p -c:v libx264 -preset ultrafast -tune zerolatency -bf 0 -g 12 -crf 47 -x264-params 'aud=1:repeat-headers=1' -f h264 moving-source.h264
```

It must contain Annex-B access unit delimiter (AUD, NAL type 9) at the start of **every** frame, with an IDR first and at least one video slice per access unit. The tool splits at AUDs without rewriting a single byte, and will refuse malformed/truncated/oversized input. Verify source with `ffprobe -count_frames` and SHA-256.

## Launch real diagnostic receiver **without** decode/render

```powershell
cargo build -p classmesh-worker --bin classmesh-media-receiver
cargo build -p classmesh-lab --bin classmesh-recorded-media-udp

# Shell 1: receiver starts first. Output file must be in a disposable test directory.
.\target\debug\classmesh-media-receiver.exe --listen 127.0.0.1:57000 --seconds 8 --output C:\Lab\received.h264

# Shell 2: sender only talks to IPv4 loopback, never a remote classroom machine.
.\target\debug\classmesh-recorded-media-udp.exe --input C:\Lab\moving-source.h264 --udp-to 127.0.0.1:57000 --fps 12
```

Check—not assume—the exact result: sender reports `LAB_TRANSPORT_SENT frames=36` (for above fixture) and payload bytes. The receiver should report 36 reassembled frames, zero gaps and zero stale drops, and `Get-FileHash -Algorithm SHA256` on received and input files must match. Verify the source actually has multiple changing decoded-frame hashes with FFmpeg (`-f framemd5`) on a machine equipped to decode the recording. **Do not** call this live capture, GPU decode or a successful ClassMesh video window.

### Fragment timing (issue #729)

Add `--fragment-timing` to the loopback receiver command. After the run it reports
up to 240 frame samples, with the expected and observed packet counts, initial
socket read wait, time from first to last datagram read, time from first read
to completed assembly, and stale-drop counts. The timestamps come from the
receiver's monotonic clock after each socket read returns a valid datagram.
They measure application reads, including socket and scheduling delays.
`None` for a completion interval means assembly did not finish. The timing
report contains no media bytes, sender timestamps, or addresses.

The failure occurs when the receiver passes the pre-read timestamp to the
reassembly window. The 100 ms socket wait can exhaust the window's 80 ms
deadline before the first fragment is processed. The receiver now samples time
after the read. Keep the same input files, 12 fps, and receiver policy when
comparing the two builds. Compare frame counts, input/output SHA-256, observed
sequence gaps, stale drops, and the timing reports.

### Native VM1 experimental evidence (2026-11-09; source PR #728)

The following measurements used the real Windows VM1 `classmesh-media-receiver` program and the new sender on the exact lab branch, without `--render` / `--decode`:

| Recorded H.264 input | Sender | Receiver | Datagrams observed | Result |
|---|---|---|---|---|
| 320×180, 12 fps, 3s | 36 frames / 145 UDP packets | **9 frames** | 145, no sequence gaps; 48 stale drops | **FAIL** (received SHA mismatch) |
| 64×64, 12 fps, 3s | 36 frames / 39 UDP packets | **34 frames** | 39, no sequence gaps; 2 stale drops | **FAIL** (received SHA mismatch) |
| 32×32, 12 fps, 3s, CRF 47 | **36 frames / 36 UDP packets** | **36 frames** | **36**, no gaps/NACKs/stale drops | **PASS**, exact SHA match |

PASS fixture SHA-256 before/after Windows native UDP:
`1720ccaa6742bfc29ec05136c948b4b9d5d14fd3745593bb0935eccfd2635693` (1,982 bytes). On Mac FFmpeg the input decoded to **36 frames with 24 distinct framemd5 digests**; this confirms it contains changes, not a single stationary picture, but the *receiver on VM1 did not decode or present it*.

The high-payload failures are **real**. `ReceiverPolicy::default()` expires partially assembled frames after **80,000 µs** (`nack_after_us = 20,000`), and the VM1 loopback trace shows timeout/expiry even when every sent packet was eventually observed in sequence. The evidence is consistent with elevated inter-packet timing/VM scheduling, but does not alone prove its complete root cause or establish whether physical hardware exhibits it. **Do not raise the production receiver deadline, pretend lost frames arrived, or mislabel a single-datagram PASS as real-time fragmented H.264 success.** Capture finer-grained per-packet timing and qualify on supported hardware before tuning or merging any production policy.


This diagnostic uses the already-existing `UdpFrameSender` and `UdpFrameReceiver` on one OS's real UDP socket. **Do not** enable `--decode` / `--render` on a VM without qualified hardware; the caller should not fabricate successful GPU presentation counts. This is not encrypted or authorized media; it is confined to `127.0.0.0/8` and must never be repurposed for unauthenticated remote traffic. Remove input/output fixtures after retaining hash-only test evidence if needed.

### Protected Worker replay

Place the three bounded AUD-delimited H.264 recordings in a disposable fixture
directory as `320x180.h264`, `64x64.h264`, and `32x32.h264`. Each recording
contains 36 frames. In an isolated Windows VM, set
`CLASSMESH_M3_MULTICAST_INTERFACE` to its local IPv4 interface address to add
the same-host multicast leg. The test sends multicast data with TTL 0.
Unicast always targets IPv4 loopback.

```powershell
$env:CLASSMESH_M3_FIXTURES = 'C:\Lab\m3-fixtures'
$env:CLASSMESH_M3_MULTICAST_INTERFACE = '<isolated local IPv4 interface>'
cargo test -p classmesh-lab --test protected_worker_video -- --nocapture
```

The test runs the real Worker receive threads and opens their delivered
ciphertext using the Worker key state and ephemeral SFrame material. It checks
all 36 authenticated access units against the input SHA-256, expires an
incomplete frame, rejects previous-epoch ciphertext after reopening the
socket, and checks the 64-outcome queue under backpressure. The default CI
test exercises the same unicast lifecycle with an in-memory fixture.
The native lab run provides evidence through the authenticated access-unit
boundary. It does not start the Service, provision trust, decode video, or
display a D3D11 window.

For timing diagnosis, pass `--fragment-timing` to both plain UDP tools. The
sender reports time spent in `send_frame`. The receiver separates time between
reads from time in a later socket read and reports the cost of periodic
status writes. Status reporting waits until the reassembly window has no
pending frame. The receiver continues to apply the same 80 ms deadline to an
incomplete frame.
