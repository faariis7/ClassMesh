# Protected multicast delivery on Windows

Use this short, opt-in run on two physical Windows x64 PCs on the target wired
VLAN. The lab uses the protected multicast sender's nonblocking socket,
production packetizer and SFrame sealing, the receiver's normal source/stream
checks and reassembly, and the Worker receive thread's 64-entry outcome queue.
It sends synthetic bytes with an ephemeral key. The measurement ends at the
Worker queue consumer, before SFrame open, decode or presentation. The existing
[connectivity probe](../src/bin/classmesh-multicast-probe.rs) remains available
for join/leave checks.

## Set up the hosts

Build the same revision on both machines from an x64 developer PowerShell.
Confirm `rustc -vV` shows `x86_64-pc-windows-msvc` and record the Git SHA and
binary hash. Use an isolated lab route and the existing lab firewall allowance
for inbound UDP on the receiver.

```powershell
cargo build -p classmesh-lab --example multicast_delivery
$repo = (Get-Location).Path
$lab = (Resolve-Path '.\target\debug\examples\multicast_delivery.exe').Path
git rev-parse HEAD
Get-FileHash $lab
Get-NetAdapter | Format-Table Name, ifIndex, InterfaceDescription, MacAddress, LinkSpeed
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, InterfaceIndex, IPAddress
$group = '239.255.23.94'
$port = 50494
$stream = 84731 # Choose a fresh nonzero stream ID for each pair of traces.
$txIp = '192.168.50.10'
$rxIp = '192.168.50.20'
```

Replace both IPs with the exact wired adapter addresses. Record the switch/VLAN,
Windows build and adapter driver. Save the interface inventory separately on each
host. Repeat once on the comparison adapter with a new stream ID, keeping the
rest of the setup fixed. A 256-byte frame probes single-datagram delivery. An
8192-byte frame probes back-to-back fragments. Each sender run is at most 240
frames at 30 fps and the receiver window is at most 60 seconds.

## Capture and run

For NIC evidence, in an elevated Windows PowerShell on **each** host, verify
Pktmon is idle and has no active filters (`pktmon status`, `pktmon filter list`).
Match the adapter above to its Pktmon NIC component using `pktmon list`. Use the
selected component ID below. On the sending host set `$side = 'outbound'` and on
the receiving host set `$side = 'inbound'`. Use a fresh directory for each run
and only synthetic traffic on the selected multicast group and UDP port.

```powershell
pktmon filter add ClassMeshDelivery -i $group -p $port -t UDP
pktmon start --capture --comp $component --type flow --pkt-size 80 --file-size 16 --log-mode circular --file-name "$side.etl"
```

Verify both commands succeeded before starting the lab. The capture is capped
at 16 MiB and only retains a short packet prefix. Retain capture counters and
NIC identity with each capture. [Pktmon start](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start)

Run on the receiver. Wait for `receiver_ready` before starting the sender, and
leave enough time for sending and the receiver's expiry window before it exits.

```powershell
& $lab receive $rxIp $txIp $group $port $stream 25 | Set-Content -Encoding ascii receiver.tsv
if ($LASTEXITCODE -ne 0) { throw 'Receiver diagnostic failed' }
```

Run on the sender within the receiver's window.

```powershell
& $lab send $txIp $group $port $stream 120 8192 | Set-Content -Encoding ascii sender.tsv
if ($LASTEXITCODE -ne 0) { throw 'Sender diagnostic failed' }
```

After both lab processes exit, stop Pktmon on each host. Remove the run's
filter even if a lab process fails. Convert the selected NIC's ETL using
Pktmon and export header fields with Wireshark's TShark. Keep the raw captures
local to the lab, and use the JSON report and application TSVs for handoff.

```powershell
pktmon counters | Set-Content -Encoding ascii "$side-counters.txt"
pktmon stop
pktmon filter remove
pktmon etl2pcap "$side.etl" --out "$side.pcapng" --component-id $component
$tshark = "$env:ProgramFiles\Wireshark\tshark.exe"
& $tshark -r "$side.pcapng" -Y "ip.dst == $group && udp.dstport == $port" -T fields -E occurrence=f -e frame.time_epoch -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.payload |
    Set-Content -Encoding ascii "$side.tsv"
```

Copy `receiver.tsv` and the NIC TSV exports to the analysis host. Python 3
compares the exact sender endpoint, destination, stream, sequence, frame and
packet index. Either NIC export can be omitted for an application-only run.

```powershell
python "$repo/tools/classmesh-lab/scripts/multicast_delivery.py" sender.tsv receiver.tsv --outbound outbound.tsv --inbound inbound.tsv |
    Set-Content -Encoding ascii delivery.json
if ($LASTEXITCODE -ne 0) { throw 'Delivery correlation failed' }
```

## Interpret the evidence

| Observation | What it establishes |
| --- | --- |
| `Written` | The sender's UDP API returned the full datagram length. This is independent of NIC and socket observations. |
| `WriteFailed` | A write attempt returned an error or short length. The frame's packet index and count identify any unattempted suffix. |
| Outbound capture | Pktmon observed the datagram at the selected sender NIC component. A physical wire tap or switch observation is needed to establish wire egress. |
| Inbound capture | Pktmon observed the datagram at the selected receiver NIC component. |
| `SocketAccepted` / `SocketRejected` | The receiver read a decodable UDP datagram. The second stage includes the admission or assembly rejection reason. Counts cover the socket, while sequence comparison selects the exact sender endpoint. |
| `Malformed` | A socket read was rejected during datagram decoding or reported as oversized by Winsock. These reads have no reliable packet ID. |
| `StaleFrame` / `InvalidFrame` | Reassembly expired or superseded an incomplete frame, or rejected an oversized completed candidate. |
| `FrameAssembled` / `FrameQueueFull` | Reassembly produced a ciphertext candidate, or Worker queue overflow discarded a candidate with that frame ID. `QueueFull` counts outcome batches, including batches with no completed frames. |

Ranges are inclusive and sorted numerically. A reordered or duplicate
delivery still covers its sequence. The packet set comes from confirmed
sender writes, so missing first and last sequences remain detectable. The TSV
links each sequence to a frame and contains a host-local monotonic timestamp
plus an approximate UTC start anchor. Compare cross-host timing only with
verified clock synchronization. TShark includes NIC observation time in its
export. Packet identity is the primary correlation mechanism.

For a sequence seen outbound and inbound but absent from the socket trace,
inspect receiver-side handling between the capture point and Winsock. For a
sequence seen outbound only, investigate the intervening path and capture
visibility, including switch multicast/IGMP handling. If all fragments arrived
and the Worker dropped their completed frame, use the queue evidence.

An absent capture row means unobserved at that point. Check component identity,
capture coverage, wrap and loss before drawing conclusions. A socket read
with no corresponding capture row is direct evidence of a capture visibility
gap. The report uses `null` for omitted observation points and rejects incomplete
or saturated application traces. Each endpoint retains the first 8192 events
and continues counting after that cap. Diagnostic records contain headers and
counters only. No key or media payload goes into the application trace.

Physical Ethernet qualification remains open until there is paired evidence
from the target LAN. A same-host VM smoke checks native instrumentation only.
