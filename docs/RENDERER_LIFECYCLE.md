# ClassMesh Renderer Lifecycle

The student presentation renderer is a GPU-native D3D11 consumer of Media Foundation decoder surfaces. Window lifecycle must not be confused with media or control health.

## Window resize

`WM_SIZE` is handled on the interactive Worker thread that owns the presentation HWND and D3D11 presenter.

- Non-zero client geometry calls `IDXGISwapChain::ResizeBuffers`.
- Backbuffer-dependent state is not cached across frames.
- The video processor is invalidated on resize and rebuilt lazily using the next decoded source texture geometry.
- Aspect ratio is recomputed against the current client area.
- Resize counters are renderer metrics, not network-health metrics.

## Minimize / restore

A minimized HWND reports zero client width or height. ClassMesh treats that as **presentation suspended**, not as a decoder, network, device, or control failure.

While suspended:

- the UDP receiver continues to consume current media;
- the hardware decoder can continue to advance;
- the renderer skips swap-chain presentation;
- no zero-sized `ResizeBuffers` call is made;
- bounded media queues remain unchanged.

On restore the first non-zero `WM_SIZE` resizes the swap chain and presentation resumes without a teacher reconnect.

## Device loss

DXGI errors corresponding to device removed, reset, hung, or driver-internal failure are classified separately from ordinary presentation errors.

Because the Media Foundation decoder and flip presenter intentionally share a D3D11 device, a real device-loss event is a **media GPU pipeline** failure. Recreating only the swap chain is insufficient. The Worker recovery path must recreate:

1. the D3D11 video device;
2. the Media Foundation DXGI device manager / hardware decoder binding;
3. the decoder;
4. the flip-model presenter;
5. keyframe-gated decode state.

Control/device heartbeat remains independent and should stay online while the media pipeline recovers.

## Current diagnostic boundary

The standalone `classmesh-media-receiver --render` now exercises resize/minimize/restore behavior. Full D3D11 device-loss reconstruction is the next hardening step and should be validated by an explicit fault/restart path before integration into the normal long-lived Worker session.
