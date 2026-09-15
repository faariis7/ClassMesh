# Presentation Recovery States

The interactive Worker should model presentation independently from control health.

```text
Ready
  | WM_SIZE(0,0)
  v
Suspended
  | WM_SIZE(non-zero)
  v
Resizing -> Ready

Ready/Resizing
  | DXGI device removed/reset/hung
  v
DeviceLost
  | rebuild D3D11 + decoder + presenter
  v
WaitingForKeyframe
  | next valid IDR
  v
Ready
```

`Suspended` is normal window lifecycle. `DeviceLost` is a GPU media failure. Neither state marks the student device offline while the authenticated control channel and heartbeat remain healthy.
