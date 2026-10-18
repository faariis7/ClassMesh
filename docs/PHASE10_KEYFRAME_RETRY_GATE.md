# Phase 10 — bounded Worker keyframe recovery retries

## Real failure mode

The Windows Student Worker's live group-media decode loop historically set `presentation_keyframe_request_pending=true` after sending **one** keyframe request. If a requested IDR did not reach the decoder but non-keyframe authenticated video frames kept arriving, every subsequent request was suppressed for the entire recovery episode. The Student could remain stuck waiting for a keyframe indefinitely until an unsolicited IDR happened.

## Fix

`PresentationKeyframeRetry` tracks only the timestamp and exact active `PresentationKeyInstallBinding` of the most recent successfully sent request. A subsequent request is allowed no earlier than two seconds later, if the decoder still reports missing reference/keyframe and new authenticated frames keep arriving. Within the interval all duplicates are suppressed. A newly installed key epoch/stream starts a fresh window, and successful receipt of an authenticated keyframe, completed decoder recovery, matching key clear, receiver replacement or pipeline teardown resets the gate. A failed send does not advance the retry state. The Teacher's existing shared `PresentationRecoveryCoordinator` independently coalesces requests within its default 250ms interval to avoid IDR storms from multiple receivers. No wire, ACL, Service, or Phase12 policy change.

## Tests and boundaries

TDD native Windows x64 RED for absent retry type, GREEN for first immediate request, suppression under two seconds, exact boundary retry, subsequent suppression, key-epoch change, explicit reset and regressed-time fail-closed behavior. Complete Windows VM2 classmesh-worker tests and Clippy all-targets warnings denied plus hosted exact-head Portable/Windows CI are merge gates.

**Important limitation:** This is bounded retry on **subsequent authenticated non-keyframe arrivals or decoder errors**; if the entire stream becomes silent and no further frames arrive, the Worker decode loop has no new trigger and this change alone cannot generate a retry. The full silent-stream timeout and a trusted per-student telemetry channel still require separate integration and physical qualification.
