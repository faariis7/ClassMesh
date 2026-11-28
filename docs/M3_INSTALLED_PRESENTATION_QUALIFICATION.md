# Installed Teacher presentation qualification

The installed Windows Teacher supports one enrolled Student and chooses
Unicast or Multicast from its protected policy at startup. Use an approved
two-host M3 lab. The M2 Message-only fixture omits the presentation field
and grants `SendTeacherMessage` only.

## Provision a disposable two-host lab

1. Record the exact [Draft PR #778](https://github.com/faariis7/ClassMesh/pull/778)
   commit, matching Teacher/Service/Worker SHA-256 and signer, Windows x64
   builds, GPU/driver and Ethernet NIC on each machine. Use a lab-only display
   with moving content. Teacher sends its primary display. Verify the
   [M2 admission procedure](WINDOWS_RUNTIME_PLAN.md) and the exact authenticated
   Worker on the Student before qualifying M3.
2. Use a test wired VLAN and a dedicated UDP port. For Multicast, verify IGMP
   forwarding and run the [two-host multicast diagnostic](../tools/classmesh-lab/docs/MULTICAST_DELIVERY_DIAGNOSTIC.md).
   Record both interfaces, group and delivery counts. The sender uses TTL 1.
   Its host-local probe gates capability advertisement. For Unicast, confirm
   the approved Student host can bind the port and that traffic from the
   enrolled Teacher is permitted on the lab network. The existing Service
   advertises `UdpUnicast` with its authenticated Worker's DXGI capture and
   hardware H.264 encode capability report. Record both that advertisement
   and the Student decoder inventory for the physical target.
3. Extend the independently approved protected Teacher policy. Choose one of
   the following presentation objects. Both require the Student to authorize
   the Teacher's existing `StartPresentation` permission. Use the existing
   policy Plan and approved Registry publication flow. Multicast needs the
   configured Teacher IPv4 interface, its scoped group and the corresponding
   Service interface on the lab VLAN. A legacy object with `interface` and
   `group` and no `transport` continues to select Multicast.

   ```json
   {
     "presentation": {
       "transport": "unicast",
       "port": 57000,
       "width": 1280,
       "height": 720,
       "fps": 30,
       "bitrate_kbps": 3000
     }
   }
   ```

   ```json
   {
     "presentation": {
       "transport": "multicast",
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

   Use actual lab assignments. For the first run, set the display to the
   configured even raster and measure the encoder output profile. In Unicast,
   the protected port is the only endpoint parameter in the offer. Teacher
   sends to the authenticated QUIC peer IP, and Service pins the Teacher IP
   for the Worker receiver. The sender retires the route if the peer IP changes
   during setup or streaming. Change transports by starting a new session
   under separately approved configuration.

## Positive and denial cases

- Run this sequence once for each configured transport. Launch Teacher as
  an ordinary interactive user, open Presentation and confirm its Ready label
  names the transport. Click **Start presentation**. Record the exact session and request correlation
  for Service ownership status, the matching SFrame epoch acknowledgment, and
  the Student Worker's accepted stream offer before the sender captures.
  Verify the UI advances through reservation, key, receiver and capture phases.
  Sending indicates a successful protected frame write on Teacher. Capture
  *changing visible Student output* and the separate decoder/present counts.
- Click **Stop presentation**. Confirm the sender stops, the exact Worker
  receiver and key lease retire, and no old frames render. Start again and
  verify a new presentation/stream ID and new key material. The scoped epoch
  counter can restart at one with the new presentation and key.
- In a reviewed negative run, omit the local presentation object or remove the
  multicast capability. Teacher must leave M2 available and produce no video.
  Retain the configured transport but remove `StartPresentation` at Service
  and verify denial before ownership or media. Exercise stale Stop binding,
  wrong request/stream/epoch acknowledgment, duplicate/replayed control, and
  policy/session retirement during streaming. Force an approved UDP bind
  conflict to verify the configured receiver refuses the offer. Teacher should
  complete correlated Stop and allow a clean Start on the same control session
  after the conflict is removed. Record which side supplied each error.
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

Both installed transports use the same authenticated presentation lifecycle,
one shared capture/encode fan-out, the existing protected group-media
coordinator and bounded sinks. A correlated Service Start reserves ownership.
The Worker must acknowledge the exact key and its receiver must accept the
exact selected offer before capture begins. The Service authorizes every
privileged message. The sender rechecks the roster deadline, peer and exact
connection after native encoding and before sealing or sending the frame.
Cancellation, disconnect or loss of authority retire the sender. Stop and
restart wait for both remote confirmation and local sender exit. Missing
confirmation retires the exact control session to let Service release ownership.

## Separate software decode smoke

The prior VM1 inventory under x64 emulation on VirtIO GPU driver
`100.6.101.58119` found Microsoft's synchronous H.264 MFT, an empty
adapter-specific decoder list and `E_NOINTERFACE (0x80004002)` at
`d3d11_video_interface`. Run `classmesh-async-h264-qualify.exe --inventory`
on each candidate lab device. The installed Student requires
`ID3D11VideoDevice` before activating the synchronous decoder.

Microsoft documents the H.264 software MFT and NV12 output. A bounded
decode-only smoke can use a Windows Media Foundation Source Reader on a short,
hashed synthetic H.264 MP4, with no D3D device manager, no hardware transforms
and no process-local transform registration. Record the selected decoder,
negotiated NV12 format, frame count and changing luma digests in system memory.
`MF_SOURCE_READER_DISABLE_DXVA` alone leaves D3D-backed allocation in use
when a manager is supplied. A standalone smoke run belongs on a separate
disposable Windows host. Its results cover software decode of that fixture.
Student rendering still requires the installed synchronous D3D11 path and
the physical output, FPS, latency and recovery measurements above.
[Microsoft H.264 decoder](https://learn.microsoft.com/en-us/windows/win32/medfound/h-264-video-decoder) ·
[Source Reader hardware transforms](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-readwrite-enable-hardware-transforms) ·
[Source Reader DXVA behavior](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-source-reader-disable-dxva)
