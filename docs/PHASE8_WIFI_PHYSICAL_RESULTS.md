# Phase 8D Physical Wi-Fi Results

Status: **PENDING PHYSICAL EXECUTION**

Hosted CI, synthetic fan-out tests and topology replication factors do not select the production Wi-Fi strategy.

## Environment

- Date/time:
- Teacher machine:
- Relay machine (if used):
- Receiver machines:
- Access point/model/firmware:
- SSID/band/channel/channel width:
- Build commit:
- Media profile:
- Test duration:
- Notes:

## Evidence matrix

| Strategy | Receivers | Teacher uplink | AP airtime/load | Queue/drop health | Weak-client isolation | Control liveness | Resource health | Result |
|---|---:|---|---|---|---|---|---|---|
| direct-unicast | 5 | pending | pending | pending | pending | pending | pending | pending |
| direct-unicast | 10 | pending | pending | pending | pending | pending | pending | pending |
| direct-unicast | 20 | pending | pending | pending | pending | pending | pending | pending |
| direct-unicast | 30 | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available |
| relay | 5 | pending | pending | pending | pending | pending | pending | pending |
| relay | 10 | pending | pending | pending | pending | pending | pending | pending |
| relay | 20 | pending | pending | pending | pending | pending | pending | pending |
| relay | 30 | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available | pending/not available |

## Reviewed evidence references

For every executed row record:

- manifest path/hash;
- Teacher telemetry/log path/hash;
- exact receiver evidence set;
- AP telemetry path/hash when available;
- relay telemetry path/hash when applicable;
- physical observation notes;
- anomalies and reruns.

## Strategy decision

Selected strategy: **UNDETERMINED**

Decision must be entered only after comparable physical evidence is reviewed. Do not convert CI success, synthetic benchmark output or an incomplete evidence matrix into a production strategy decision.
