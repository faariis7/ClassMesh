## Unified RC gate — 2026-11-18

Use one exact candidate SHA and `cargo build --locked` on both physical Windows
x64 hosts. The network owner executes the existing two-host commands below for
256-byte and 8192-byte frames on target and comparison adapters, retaining NIC
counter/packet attribution and Worker-consumer totals. Synthetic ciphertext delivery
does not establish SFrame open, decode or presentation: pair it with the approved
authenticated Student production run. VM loopback is diagnostic only. Do not
change persistent firewall/SCM/trust policy to obtain a passing result.

# Protected multicast delivery on Windows

Run the existing synthetic multicast lab as Teacher and Student on two Windows
x64 PCs on the target wired VLAN. The lab uses the production packetizer,
nonblocking protected multicast sender, source/stream checks, reassembly
and Worker's 64-entry outcome queue. It seals synthetic bytes with an ephemeral
key. The measurement ends when the Worker consumer receives a ciphertext
candidate, before authentication, decoding or presentation. The
[connectivity probe](../src/bin/classmesh-multicast-probe.rs) remains available
for join/leave checks.

## Prepare both hosts

Build the same revision on both hosts from developer PowerShell. Use an isolated
lab route and the existing lab firewall allowance for inbound UDP on Student.
Install [TShark](https://www.wireshark.org/download.html) for offline decoding of
Pktmon captures. Run NIC capture in an elevated English-language Windows
PowerShell on each host. The runner checks that Pktmon is idle with no filters
before it starts.

```powershell
cargo build -p classmesh-lab --example multicast_delivery
rustc -vV
git rev-parse HEAD
$lab = (Resolve-Path '.\target\debug\examples\multicast_delivery.exe').Path
$runner = '.\tools\classmesh-lab\scripts\multicast_delivery.ps1'
Get-FileHash $lab
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, InterfaceIndex, IPAddress
Get-NetAdapter | Format-Table Name, ifIndex, InterfaceDescription, MacAddress, LinkSpeed
pktmon list

$teacher = '192.168.50.10'
$student = '192.168.50.20'
$stream = 84731
$common = @{ Lab = $lab; TeacherIp = $teacher; Stream = $stream; Group = '239.255.23.94'; Port = 50494 }
```

Replace the example IPs and component IDs with the explicit wired adapters on
each host. The runner checks the selected NIC's interface index against the IP.
Use a fresh stream ID and output directory for each test pair. Keep the adapter,
driver, Windows build and switch/VLAN details in local lab notes.

## Run Student, then Teacher

In Student's shell, start the receiver first. Wait for the
`receiver_ready. Start Teacher now.` message, which follows socket bind and
multicast join.

```powershell
& $runner @common -Role Student -InterfaceIp $student -ComponentId 12 -Seconds 45 -OutputDirectory '.\student-84731'
```

Start Teacher while Student is listening and leave at least one second after
the send finishes for receive draining and reassembly expiry.

```powershell
& $runner @common -Role Teacher -InterfaceIp $teacher -ComponentId 7 -Frames 120 -FrameBytes 8192 -OutputDirectory '.\teacher-84731'
```

Repeat with `-FrameBytes 256` to exercise single-datagram delivery, and with
`-FrameBytes 8192` on the comparison adapter to exercise multi-datagram frames.
Always use a new stream and fresh directories. A sender run takes up to 240
frames at 30 fps. A Student run listens for up to 60 seconds.

Omit `-ComponentId` for application-only measurements. Use `-Tshark` if the
executable is in a different location. In a single-host VM, run Student
application-only so that Teacher can own the host's one Pktmon session.

## Collect and correlate

Each endpoint stops by itself. Ctrl+C cancels the run. The runner's cleanup
stops its child process and owned capture, checks ownership before removing its
filter and deletes the temporary ETL and pcapng. The capture uses a 64 MB
memory buffer and an 80-byte packet prefix on the selected NIC and lab route.
Only the first 26 bytes of the UDP payload, which are CMV1 header fields, are
retained in the NIC TSV. The trace contains neither payloads nor keys.
Run this only on the isolated synthetic route. Treat all endpoint TSVs as
local because their headers contain addresses and timing.

If the shell was forcibly terminated, verify ownership with `pktmon status`
and `pktmon filter list`. If the remaining session and sole filter belong to
this run, use `pktmon stop` and `pktmon filter remove`, then delete the ETL and
pcapng in the run directory. Run again in a fresh directory. A failed or canceled
endpoint may leave an incomplete local trace for troubleshooting.

On the analysis host, place both completed run directories under the current
directory. The `.count` files are selected-NIC directional flow counters.
The analyzer verifies them against matching TShark rows before attributing
a gap. When an export is missing or rejected, omit that capture and its count
for an application-only or one-sided report.

```powershell
$tx = '.\teacher-84731'
$rx = '.\student-84731'
$analysis = '.\tools\classmesh-lab\scripts\multicast_delivery.py'
$txCount = Get-Content -LiteralPath "$tx\outbound.count"
$rxCount = Get-Content -LiteralPath "$rx\inbound.count"
$report = python $analysis "$tx\sender.tsv" "$rx\receiver.tsv" --outbound "$tx\outbound.tsv" --outbound-count $txCount --inbound "$rx\inbound.tsv" --inbound-count $rxCount --scope two-host-lab --redact-network
if ($LASTEXITCODE -ne 0) { throw 'Delivery correlation failed' }
$report | Set-Content -Encoding ascii delivery.json
```

Use `--scope single-host-vm` for the VM smoke. The scope is operator-supplied.
Share the redacted JSON. After analysis, remove the completed run directories
when the local traces are no longer needed.

## Interpret the evidence

| Report field | What it measures |
| --- | --- |
| `written` and `sender_write_failures` | Complete UDP writes and failed or short write attempts. A failed attempt can leave the rest of its frame unattempted. |
| `outbound_observed`, `inbound_observed` | Matching datagrams observed at the selected Teacher and Student NIC components. A tap or switch capture is needed to establish physical egress from the Teacher. |
| `unique_socket_reads` | Matching decodable datagrams received by Winsock, including those later rejected by media admission or assembly. `Malformed` includes reads without reliable IDs. |
| `sender_to_nic_gap` | Successful writes absent from verified outbound capture and from any later observation. |
| `network_path_gap` | Missing socket reads observed by a count-verified outbound capture and absent from a count-verified inbound capture. Investigate the path between those observation points, including VLAN, switch and IGMP state. |
| `receiver_nic_to_socket_gap` | Matching datagrams reached the count-verified Student NIC with no matching decodable socket read. Inspect Student-side handling between NIC and Winsock. |
| `unattributed_socket_gap` | Missing reads without the observations needed to localize them. |
| `reassembly_expired_frame_ids` | Partial frames discarded after the existing reassembly deadline. |
| `reassembly_window_evicted_frame_ids` | Partial frames displaced when the in-flight frame window was full. |
| `receiver_queue_full_frame_ids` and `worker_consumer_frames` | Completed candidates discarded by the full Worker queue and candidates actually drained by the consumer. `QueueFull` counts outcome batches and can also include outcomes with no completed frame. |

Ranges are inclusive and sorted numerically. A reordered or duplicate read
still covers its sequence. An empty list means there were no qualifying gaps.
A `null` means the observation point or attribution was unavailable. A socket
read without a matching NIC row is a visibility gap and is excluded from loss
attribution. Count agreement checks export completeness for the selected
flow. Check capture coverage, adapter identity and the receiver's listening
window before assigning a physical cause. Cross-host timestamps require
verified clock synchronization. Packet IDs do the correlation.

The analyzer rejects incomplete or saturated endpoint traces. Each endpoint
retains the first 8,192 events and continues counting. Unverified capture
observations remain visible in the report without being used to assign a gap.

Physical Ethernet qualification remains open until both Windows x64 hosts
produce paired NIC captures and endpoint traces on the target wired VLAN,
with results for the affected adapter and a comparison adapter.
