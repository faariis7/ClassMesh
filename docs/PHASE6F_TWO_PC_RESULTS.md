# Phase 6F two-PC results

Status: **NOT RUN**

Do not change the status to PASS until every required Phase 6F criterion has physical Windows evidence. Use **NOT MEASURED** or **BLOCKED** for missing evidence.

## Environment

| Item | Teacher | Student |
|---|---|---|
| Machine/model | | |
| CPU | | |
| GPU + driver | | |
| Windows build | | |
| ClassMesh commit | | |
| IPv4 | | |
| Connection | wired / Wi-Fi | wired / Wi-Fi |

Student control listener:  
Teacher identity principal:  
Student principal:  
Authorization permissions verified:  

## Evidence matrix

| Test | Result | Evidence / log |
|---|---|---|
| Enrolled mTLS + Hello | NOT RUN | |
| UDP focused StreamAnswer accepted after Worker start | NOT RUN | |
| Production media packets received | NOT RUN | |
| Keyframe observed | NOT RUN | |
| Healthy input pulse visible | NOT RUN | |
| Degraded feedback triggers profile-only reconfigure | NOT RUN | |
| Input remains responsive during degradation | NOT RUN | |
| Media receiver loss does not kill control | NOT RUN | |
| Input pulse after media loss | NOT RUN | |
| Disconnect releases held key/button | NOT RUN | |
| Lock releases input and reports unavailable state | NOT RUN | |
| Unlock/reconnect recovers | NOT RUN | |
| Worker restart cleanup/recovery | NOT RUN | |
| Secure-desktop explicit diagnostic/no retry storm | NOT RUN | |
| Bounded media/control queues observed | NOT RUN | |
| Clipboard policy/bounds if exercised | NOT RUN | |

## Commands

Healthy run:

    <paste exact command>

Degraded feedback run:

    <paste exact command>

Lost-media run:

    <paste exact command>

Disconnect cleanup run:

    <paste exact command>

## Qualification client summaries

Healthy media counters:  
Degraded/adaptation output:  
Lost-media/control output:  
Disconnect cleanup observation:  

## Student diagnostics

Record exact non-sensitive Service/Worker diagnostics for:

- normal stream start;
- media reconfigure;
- media loss;
- input unavailable/suspended;
- disconnect cleanup;
- Worker restart;
- secure desktop.

## Phase 6F decision

- [ ] Mouse/keyboard control remains responsive while focused media is degraded.
- [ ] Media transport failure does not mark device/control offline.
- [ ] Stuck-key/button cleanup verified across disconnect, lock/unlock and Worker restart.
- [ ] Secure-desktop/unavailable-input behavior is explicit and bounded.
- [ ] Focused adaptation/recovery has no unbounded queue growth.
- [ ] Clipboard skeleton remains typed/bounded/policy-controlled if exercised.

Decision: **NOT RUN**

Notes: