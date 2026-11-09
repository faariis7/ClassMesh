# Recorded H.264 → real UDP receiver: lab-only media qualification

**Not production streaming, authentication, live screen capture, hardware decoding, rendering, or completion of MVP issue #688 M3.** This restricted tool is a temporary laboratory source for diagnosing the existing ClassMesh UDP media framing/reassembly independently of a hardware encoder. It is not invoked by Teacher, Service or Worker in normal operation. It refuses any non-IPv4-loopback destination and applies strict input, access-unit, and framerate limits.

## Preparation on a disposable Windows VM with FFmpeg-generated input

The following creates a **locally generated moving pattern**, not a captured classroom screen. On a machine with FFmpeg + `libx264`:

```sh
ffmpeg -f lavfi -i 'testsrc2=size=320x180:rate=12' -t 3 -pix_fmt yuv420p -c:v libx264 -preset ultrafast -tune zerolatency -bf 0 -g 12 -x264-params 'aud=1:repeat-headers=1' -f h264 moving-source.h264
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

Expected evidence: sender reports `LAB_TRANSPORT_SENT frames=36` (for above fixture) and exact payload byte count; receiver reports 36 reassembled frames with zero loss, writes the unchanged Annex-B stream, and exits cleanly; `Get-FileHash -Algorithm SHA256` on received and input files must match. Frame/content variations can be independently verified with FFmpeg (`-f framemd5`) **but do not constitute live capture**.

This diagnostic uses the already-existing `UdpFrameSender` and `UdpFrameReceiver` on one OS's real UDP socket. **Do not** enable `--decode` / `--render` on a VM without qualified hardware; the caller should not fabricate successful GPU presentation counts. This is not encrypted or authorized media; it is confined to `127.0.0.0/8` and must never be repurposed for unauthenticated remote traffic. Remove input/output fixtures after retaining hash-only test evidence if needed.
