# Installed Teacher presentation qualification

The installed Windows Teacher supports one enrolled Student target and an opt-in
protected multicast presentation. Get separate authorization for M3. The M2
Message-only fixture leaves the presentation field absent and grants
`SendTeacherMessage` only.

## Provision a disposable two-host lab

1. Record the exact Draft PR commit, matching Teacher/Service/Worker SHA-256 and
   signer, Windows x64 builds, GPU/driver and Ethernet NIC on each machine.
   Use a lab-only display with moving content. Teacher sends its primary display.
   Verify the [M2 admission procedure](WINDOWS_RUNTIME_PLAN.md) and the exact
   authenticated Worker on the Student before qualifying M3.
2. Use a test wired VLAN with administrator-confirmed IGMP forwarding and an
   approved administratively scoped IPv4 group and UDP port. Run the
   [two-host multicast diagnostic](../tools/classmesh-lab/docs/MULTICAST_DELIVERY_DIAGNOSTIC.md)
   for that topology. Record both interfaces and packet/delivery correlation.
   The sender uses TTL 1. Its host-local multicast probe permits advertising the
   capability and cannot establish two-host delivery.
3. On the approved disposable Teacher, extend a fresh, independently reviewed
   Teacher policy JSON using the optional `presentation` object below. Use
   the actual Teacher interface address routed to the enrolled Student. The
   group, port and limits must be assigned for the lab. Reuse the existing
   protected publication and signed roster. On the Student use an independently
   issued Teacher `StartPresentation` grant and the existing protected Service
   multicast interface on the same VLAN. Service still authorizes each privileged
   request. Run the usual policy validation and package/signature gates before
   publishing or launching.

   ```json
   {
     "presentation": {
       "interface": "192.0.2.10",
       "group": "239.11.0.5",
       "port": 57000,
       "width": 1280,
       "height": 720,
       "fps": 30,
       "bitrate_kbps": 3000
     }
   }
   ```

   These are example values. Use a valid even raster and bounded H.264 profile.
   For a straightforward first run set the test display to the same raster and
   measure the actual encoder output profile.

## Positive and denial cases

- Run the Teacher normally as an ordinary interactive user and open Presentation.
  Click **Start presentation**. Record the exact session and request correlation
  for Service ownership status, the matching SFrame epoch acknowledgment, and
  the Student Worker's accepted stream offer before the sender captures.
  Check capture/encode counts and *changing visible Student output*. Preserve
  the decode/present result and distinguish sender counters from Student output.
- Click **Stop presentation**. Confirm the sender stops, the exact Worker
  receiver and key lease retire, and no old frames render. Start again and
  verify a new presentation/stream ID and new key material. The scoped epoch
  counter can restart at one with the new presentation and key.
- In a reviewed negative run, omit the local presentation object or remove the
  multicast capability. Teacher must leave M2 available and produce no video.
  Retain the configured transport but remove `StartPresentation` at Service
  and verify denial before ownership or media. Exercise stale Stop binding,
  wrong request/stream/epoch acknowledgment, duplicate/replayed control, and
  policy/session retirement during streaming. Capture recovery separately.
- Use bounded packet impairment on the lab path. Record decoder-safe recovery
  through the existing rate-limited keyframe request, CPU/GPU use, capture
  pacing, dropped frames, and p50/p95 glass-to-glass latency. Repeat
  disconnect/reconnect, capture device replacement, Student minimize/restore
  and controlled device loss. Compare with the existing
  [two-PC targets and methodology](PHASE4_TWO_PC_QUALIFICATION.md).
- Follow the existing lab stop and verified cleanup. Use the
  [M3 hardware guide](M3_ASYNC_H264_HARDWARE_QUALIFICATION.md) for a separate
  qualification-only async decode measurement. Keep the stable Student's
  synchronous H.264 decoder and preserve stage-specific logs.

## Transport and codec boundaries

The installed GUI initiates the configured multicast path. Sender-side
protected unicast fan-out and the Service/Worker unicast receiver already
exist. They need an installed-Teacher unicast offer/receiver selection path and
separate physical evidence. Multicast refusal leaves no implicit transport
downgrade. The installed sender owns a single negotiated route, lets the
existing Service release the lease when the control session closes, and stops
emitting frames on cancellation, policy expiry or peer revocation. A separate
media thread keeps capture and encoder delays out of the QUIC control loop.

For VM1, the recorded x64-emulated inventory on VirtIO GPU driver
`100.6.101.58119` enumerated Microsoft’s synchronous H.264 MFT, an empty
adapter-specific decoder list and `E_NOINTERFACE (0x80004002)` at
`d3d11_video_interface`. A D3D11 device and a D3D11-aware MFT do not establish
adapter-backed decode. The installed Student explicitly requires `ID3D11VideoDevice` before it
activates the synchronous decoder. Microsoft supports system-memory MFT
decoding without DXVA, which gives a separate decode-only qualification path.
It would require a separately measured decode and upload/presentation path
before use in the product. Keep the installed renderer gate, bounded buffers
and the existing hardware/performance targets.
Qualify asynchronous/vendor transforms only on the exact physical GPU/driver.
[Microsoft H.264 decoder](https://learn.microsoft.com/en-us/windows/win32/medfound/h-264-video-decoder) · [D3D11 video interface](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nn-d3d11-id3d11videodevice) · [Media Foundation software decode](https://learn.microsoft.com/en-us/windows/win32/medfound/supporting-direct3d-11-video-decoding-in-media-foundation)
