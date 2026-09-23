# Phase 7D Two-PC Multicast Probe

This procedure checks whether two Windows PCs on the intended wired classroom network can exchange a ClassMesh diagnostic datagram through an administratively scoped IPv4 multicast group.

It is a **diagnostic capability probe**, not a production-media security qualification and not a classroom-scale qualification. A PASS here does not complete Phase 7E group-media security or Phase 7H scale testing, and it does not change the Phase 4 UDP-vs-QUIC-Datagram decision.

## What the probe proves

A receiver reports `result=available` only after all of the following happen on the selected LAN interface:

1. the receiver joins the requested multicast group;
2. it receives a valid ClassMesh CMV1 diagnostic packet carrying the exact 128-bit probe token;
3. it leaves the multicast group cleanly.

The receiver is bounded by a timeout and always attempts leave cleanup for every tracked membership before reporting the result.

The sender uses multicast TTL 1 and sends only a small diagnostic token. It does not transmit captured screen/video data.

## Network requirements

- Put both PCs on the same intended classroom VLAN/subnet.
- Use explicit IPv4 addresses assigned to the wired adapters.
- Use a group inside the RFC 2365 administratively scoped range `239.0.0.0/8`.
- Allow the selected UDP port through the local firewall for the test.
- Record switch/VLAN details when IGMP snooping, filtering or multicast routing policy may affect the result.

Example values below use group `239.255.42.99` and UDP port `45070`.

## 1. Generate one correlation token

On either PC:

```powershell
.\classmesh-multicast-probe.exe token
```

Copy the returned 32-character hexadecimal token. Use the same token on sender and receiver.

## 2. Start the receiver first

On PC A, replace `192.168.50.21` with PC A's wired IPv4 address:

```powershell
.\classmesh-multicast-probe.exe receive --group 239.255.42.99 --interface 192.168.50.21 --port 45070 --token <TOKEN> --timeout-ms 10000
```

Leave this command running while starting the sender.

## 3. Send from the other PC

On PC B, replace `192.168.50.22` with PC B's wired IPv4 address:

```powershell
.\classmesh-multicast-probe.exe send --group 239.255.42.99 --interface 192.168.50.22 --port 45070 --token <TOKEN> --count 12 --interval-ms 100
```

The receiver PASS output must include:

```text
joined=true
probe_datagram_observed=true
left_cleanly=true
result=available
```

A non-zero receiver exit means the probe is unavailable. Preserve the printed `reason` and any stderr diagnostics.

## 4. Swap directions

Repeat the test with PC B as receiver and PC A as sender. Bidirectional evidence is useful because host firewall rules, NIC configuration and switch behavior can differ by direction.

## Evidence to retain

For each direction record:

- date/time;
- both PC names and wired IPv4 addresses;
- switch/VLAN/network path;
- multicast group and UDP port;
- sender output;
- receiver output;
- whether any firewall rule was temporarily changed;
- PASS/FAIL and failure reason.

Use `docs/PHASE7_MULTICAST_PROBE_RESULTS.md` as the repository evidence template.

## Interpretation

- `JoinFailed`: the host could not join the group on the specified interface.
- `ProbeDatagramNotObserved`: join succeeded but the matching CMV1 token was not received before timeout.
- `LeaveFailed`: the diagnostic packet may have arrived, but cleanup could not leave the group cleanly.
- `available`: this pair/interface/path passed the bounded diagnostic probe.

Do not infer classroom-scale multicast viability from a single pair. Phase 7H still requires 2/5/10/20+ receiver evidence where hardware permits.

Do not send production presentation media over plain multicast based on this result. Phase 7E must establish authenticated group-media protection, bounded key epochs/rotation and replay handling first.
