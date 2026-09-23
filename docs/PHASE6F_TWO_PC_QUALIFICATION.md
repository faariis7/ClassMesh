# Phase 6F physical interactive-control qualification

Phase 6F is the physical validation gate for the production interactive-control path tracked by Issue #108. Hosted CI proves the state machines, authorization checks, IPC contracts, bounded queues and recovery logic build and pass deterministic tests; it does **not** prove real Windows input injection, interactive-session lifecycle behavior, GPU capture/encode behavior, or control/media independence on two physical PCs.

Phase 4 Issue #3 remains a separate gate. Phase 6F must not be used to select UDP vs QUIC Datagram as the product default.

## Required machines and identity state

Use two signed-in Windows PCs on the same private wired LAN:

- **Student PC** — runs the production ClassMesh Service + interactive Worker.
- **Teacher PC** — runs `classmesh-interactive-qualification.exe`.

The Student must already have valid production-style ClassMesh state under:

- `%ProgramData%\ClassMesh\state\machine-identity.json`
- `%ProgramData%\ClassMesh\state\authorization.json`
- `%ProgramData%\ClassMesh\config\control-runtime.json`

The Teacher qualification client requires its own **pre-enrolled teacher** `machine-identity.json`. The identity must reference the matching non-exportable CNG key and trust the Student's issuing root. The teacher principal in the Student authorization store must be enabled and hold at least `ViewInteractive` and `ControlInput`.

Do not copy the Student identity to the Teacher and do not create an exportable private-key shortcut for qualification. If a valid enrolled Teacher identity is not available yet, record Phase 6F as **blocked on enrollment/provisioning** rather than weakening mTLS.

## CI artifact

Use the `classmesh-phase6f-qualification-windows-x64` artifact. It contains the qualification executable, this runbook, and `PHASE6F_TWO_PC_RESULTS.md`.

The client uses the production enrolled QUIC/TLS control stack and focused-media StreamOffer path. It opens a UDP receiver on Teacher, verifies ClassMesh media packet headers, keeps authenticated heartbeats alive, can send bounded degraded feedback, can deliberately close the media receiver while keeping control alive, and can send visible input pulses.

## Student preparation

Confirm `control-runtime.json` binds to a reachable private-LAN address and non-zero port, for example:

    {
      "version": 1,
      "bind_address": "0.0.0.0:44991"
    }

Allow only the required private-profile traffic in Windows Firewall. Do not disable the firewall globally. The exact control UDP port is the configured QUIC listener. The Teacher qualification media receiver defaults to UDP `57020`.

Confirm the Student is signed in and the ClassMesh Worker is running in that interactive session before starting the test.

## 1. Healthy authenticated interactive path

On Teacher:

    .\classmesh-interactive-qualification.exe `
      --connect <STUDENT_IP>:44991 `
      --server-name <STUDENT_CERTIFICATE_DNS_NAME> `
      --identity C:\ClassMesh\teacher\machine-identity.json `
      --udp-listen 0.0.0.0:57020 `
      --seconds 30 `
      --input-pulse

Pass conditions:

- enrolled mTLS + Hello succeeds;
- `UdpUnicast` is negotiated only after the current Worker has published real DXGI + qualified H.264 capability;
- StreamAnswer is accepted only after the Service successfully starts Worker media;
- Teacher receives production ClassMesh media packets for stream `6001`;
- at least one H.264 keyframe is observed;
- the pointer visibly moves right then back when each input pulse is sent;
- authenticated heartbeat acknowledgements continue for the full run;
- no unbounded queue/backpressure failure is reported.

If no media packets arrive, record the failure; do not treat successful control alone as a focused-media pass.

## 2. Degraded feedback and profile adaptation

Run:

    .\classmesh-interactive-qualification.exe `
      --connect <STUDENT_IP>:44991 `
      --server-name <STUDENT_CERTIFICATE_DNS_NAME> `
      --identity C:\ClassMesh\teacher\machine-identity.json `
      --seconds 30 `
      --input-pulse `
      --degraded-feedback

The client sends two bounded degraded `ReceiverFeedback` samples. The production hysteresis path should emit a profile-only `StreamReconfigure`; transport must remain unchanged.

Pass conditions: the client reports `adaptation=reconfigured`, control heartbeat acknowledgements continue, the input pulse remains responsive, and media remains bounded and continues or recovers without restarting control.

This synthetic feedback validates the production control/adaptation path; it is not a substitute for Phase 4 physical loss/jitter measurements.

## 3. Lost media while control remains authenticated

Run:

    .\classmesh-interactive-qualification.exe `
      --connect <STUDENT_IP>:44991 `
      --server-name <STUDENT_CERTIFICATE_DNS_NAME> `
      --identity C:\ClassMesh\teacher\machine-identity.json `
      --seconds 30 `
      --input-pulse `
      --drop-media-after 10

At 10 seconds Teacher deliberately closes its UDP receiver. The QUIC control session remains active and heartbeats continue. One second later the client sends another visible input pulse.

Pass conditions: `control_after_media_drop=responsive` is printed, the second pointer pulse is visible on Student, heartbeat acknowledgements continue after media loss, and the device/control session is not treated as offline solely because media failed.

A Worker media send failure may drop only the focused media state. It must not terminate authenticated control/input.

## 4. Disconnect stuck-key cleanup

Choose a harmless virtual-key code that is easy to observe. Example `0x41` (`A`) is decimal `65`; use a text field only if repeated characters are safe.

    .\classmesh-interactive-qualification.exe `
      --connect <STUDENT_IP>:44991 `
      --server-name <STUDENT_CERTIFICATE_DNS_NAME> `
      --identity C:\ClassMesh\teacher\machine-identity.json `
      --seconds 10 `
      --hold-key-vk 65

At the end the client sends **key-down only** and intentionally closes the authenticated control connection without key-up.

Pass condition: Service/Worker disconnect cleanup releases the ClassMesh-injected key promptly; it must not remain logically pressed. Repeat the same lifecycle expectation for mouse buttons during later UI-level validation.

## 5. Lock/unlock and Worker restart

With an authenticated qualification session active: lock Student; confirm input is unavailable/suspended rather than silently accepted; unlock and allow the intended Worker to resume/restart; start a fresh qualification session and confirm input/media recover; terminate the interactive Worker once and confirm bounded supervision starts the intended replacement Worker; reconnect and repeat the healthy input pulse.

Pass conditions: pressed ClassMesh input is released on lock/Worker loss; no input is silently reported as executed while unavailable; recovery does not require restarting the machine Service; stale Worker PID/session/generation evidence cannot enable the replacement Worker.

Record the explicit Service diagnostic for unavailable input. Do not infer a pass from the absence of visible input.

## 6. Secure desktop

Enter a Windows secure-desktop state on Student using an approved local test procedure. Attempt a qualification input command from Teacher.

Pass conditions: ClassMesh does not claim successful input injection into an unavailable secure desktop; Service emits an explicit non-sensitive unavailable-input diagnostic; there is no retry storm; after returning to the normal interactive desktop, a fresh authorized session can control input again.

Do not automate credential entry or weaken Windows secure-desktop protections for this test.

## 7. Phase 6F exit decision

Update `docs/PHASE6F_TWO_PC_RESULTS.md` with exact hardware, Windows builds, network topology, Student/Teacher identity setup, command lines, observed diagnostics and pass/fail evidence.

Phase 6F may be checked complete in Issue #108 only when physical Windows evidence demonstrates:

1. authenticated mouse/keyboard control remains responsive while focused media is degraded;
2. lost media does not mark the device/control session offline;
3. stuck-key/button cleanup works across disconnect, lock/unlock and Worker restart;
4. secure-desktop/unavailable-input states fail explicitly without silent execution or retry loops;
5. focused adaptation/recovery remains bounded;
6. the clipboard skeleton remains typed/bounded/policy-controlled if exercised.

If a criterion is not physically observed, mark it **not measured** or **blocked** rather than claiming a pass.