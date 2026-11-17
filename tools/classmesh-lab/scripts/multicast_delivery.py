"""Correlate bounded lab traces and optional TShark exports by CMV1 header."""
import argparse
from collections import Counter
import csv
from itertools import groupby
import json
from pathlib import Path
import struct

MAX_TRACE_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_ROWS = 32_768
STAGES = (
    "Written", "WriteFailed", "SocketAccepted", "SocketRejected", "Malformed",
    "Queued", "QueueFull", "QueueDisconnected", "FrameAssembled",
    "FrameQueueFull", "FrameQueueDisconnected", "StaleFrame", "InvalidFrame",
)
FRAME_DROP_STAGES = ("FrameExpired", "FrameWindowEvicted")


def ranges(keys):
    sequences = sorted({key[1] for key in keys})
    result = []
    for _, group in groupby(enumerate(sequences), lambda pair: pair[1] - pair[0]):
        run = list(group)
        result.append([run[0][1], run[-1][1]])
    return result


def compare(written, received, outbound, inbound=None, *, outbound_verified=False, inbound_verified=False):
    send_order = {key: index for index, key in enumerate(written)}
    sent = set(send_order)
    socket = set()
    highest = -1
    duplicates = reordered = unmatched = 0
    for key in received:
        index = send_order.get(key)
        if index is None:
            unmatched += 1
        elif key in socket:
            duplicates += 1
        else:
            reordered += index < highest
            highest = max(highest, index)
            socket.add(key)

    tx_nic = sent.intersection(outbound) if outbound is not None else None
    rx_nic = sent.intersection(inbound) if inbound is not None else None
    missing = sent - socket
    sender_gap = (missing - tx_nic - (rx_nic or set())) if outbound_verified else None
    path_gap = ((missing & tx_nic) - rx_nic) if outbound_verified and inbound_verified else None
    receiver_gap = (missing & rx_nic) if inbound_verified else None
    attributed = (sender_gap or set()) | (path_gap or set()) | (receiver_gap or set())
    return {
        "written": len(sent),
        "sender_to_nic_gap": ranges(sender_gap) if sender_gap is not None else None,
        "network_path_gap": ranges(path_gap) if path_gap is not None else None,
        "receiver_nic_to_socket_gap": ranges(receiver_gap) if receiver_gap is not None else None,
        "unattributed_socket_gap": ranges(missing - attributed),
        "outbound_observed": len(tx_nic) if tx_nic is not None else None,
        "inbound_observed": len(rx_nic) if rx_nic is not None else None,
        "unique_socket_reads": len(socket),
        "duplicate_socket_reads": duplicates,
        "reordered_socket_reads": reordered,
        "unmatched_socket_reads": unmatched,
        "written_without_socket_read": ranges(sent - socket),
        "written_without_outbound_observation": ranges(sent - tx_nic) if tx_nic is not None else None,
        "outbound_without_socket_read": ranges(tx_nic - socket) if tx_nic is not None else None,
        "socket_read_without_outbound_observation": ranges(socket - tx_nic) if tx_nic is not None else None,
        "outbound_without_inbound_observation": (
            ranges(tx_nic - rx_nic) if tx_nic is not None and rx_nic is not None else None
        ),
        "inbound_without_socket_read": ranges(rx_nic - socket) if rx_nic is not None else None,
        "socket_read_without_inbound_observation": ranges(socket - rx_nic) if rx_nic is not None else None,
    }


def trace(path, role):
    with path.open("rb") as data:
        raw = data.read(MAX_TRACE_BYTES + 1)
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError(f"{path}: trace exceeds size limit")
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    lines = raw.decode(encoding).splitlines()
    meta = dict(line[2:].split("=", 1) for line in lines if line.startswith("# "))
    if meta.get("format") != "classmesh-multicast-delivery-v1" or meta.get("role") != role:
        raise ValueError(f"{path}: invalid trace format or role")
    if meta.get("complete") != "true" or meta.get("omitted") != "0":
        raise ValueError(f"{path}: incomplete or saturated trace; absence cannot be attributed")
    rows = list(csv.DictReader((line for line in lines if not line.startswith("# ")), delimiter="\t"))
    counts = Counter(row["stage"] for row in rows)
    stages = STAGES + tuple(stage for stage in FRAME_DROP_STAGES if stage in meta)
    if set(counts) - set(stages) or any(int(meta[stage]) != counts[stage] for stage in stages):
        raise ValueError(f"{path}: event and counter totals disagree")
    return meta, rows


def packet_key(row):
    return tuple(int(row[field]) for field in ("stream", "sequence", "frame", "index"))


def capture(path, sender_endpoint, destination, stream, expected_count=None):
    """Read epoch, ip.src, udp.srcport, ip.dst, udp.dstport, udp.payload fields."""
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise ValueError(f"{path}: capture export exceeds size limit")
    keys = set()
    matches = 0
    with path.open(encoding="utf-8-sig", newline="") as data:
        for index, row in enumerate(csv.reader(data, delimiter="\t"), 1):
            if index > MAX_CAPTURE_ROWS:
                raise ValueError(f"{path}: capture export exceeds row limit")
            if len(row) != 6:
                raise ValueError(f"{path}:{index}: expected six TShark fields")
            _, src, src_port, dst, dst_port, prefix = row
            if f"{src}:{src_port}" != sender_endpoint or f"{dst}:{dst_port}" != destination:
                continue
            hex_prefix = prefix.replace(":", "")
            if len(hex_prefix) < 52:
                raise ValueError(f"{path}:{index}: capture is too short to correlate route packets")
            header = bytes.fromhex(hex_prefix[:52])
            if header[:6] != b"CMV1\x00\x04":
                continue
            packet_stream, frame, sequence, packet_index = struct.unpack_from(">IQIH", header, 8)
            if packet_stream == stream:
                keys.add((packet_stream, sequence, frame, packet_index))
                matches += 1
    if expected_count is not None and matches != expected_count:
        raise ValueError(
            f"{path}: matched {matches} capture rows, expected {expected_count} from NIC counters"
        )
    return keys


def report(sender_path, receiver_path, outbound_path=None, inbound_path=None, *,
           outbound_count=None, inbound_count=None, redact_network=False, scope="unspecified"):
    for path, count in ((outbound_path, outbound_count), (inbound_path, inbound_count)):
        if count is not None and (path is None or not 0 <= count <= MAX_CAPTURE_ROWS):
            raise ValueError("NIC counts require a capture and must be within the capture row limit")
    tx, tx_rows = trace(sender_path, "send")
    rx, rx_rows = trace(receiver_path, "receive")
    sender, stream, destination = tx["sender"], tx["stream"], tx["destination"]
    if (sender.rsplit(":", 1)[0], stream, destination) != (
        rx["sender"], rx["stream"], rx["destination"]
    ):
        raise ValueError("sender and receiver traces describe different routes")
    written = [packet_key(row) for row in tx_rows if row["stage"] == "Written"]
    received = [
        packet_key(row) for row in rx_rows
        if row["stage"] in ("SocketAccepted", "SocketRejected") and row["peer"] == sender
    ]
    outbound = capture(outbound_path, sender, destination, int(stream), outbound_count) if outbound_path else None
    inbound = capture(inbound_path, sender, destination, int(stream), inbound_count) if inbound_path else None
    outbound_verified = outbound_count is not None
    inbound_verified = inbound_count is not None
    consumer_frames = int(rx["worker_consumer_frames"]) if "worker_consumer_frames" in rx else None
    consumer_outcomes = int(rx["worker_consumer_outcomes"]) if "worker_consumer_outcomes" in rx else None
    if consumer_frames is not None and consumer_frames != (
        int(rx["FrameAssembled"]) - int(rx["FrameQueueFull"]) - int(rx["FrameQueueDisconnected"])
    ):
        raise ValueError("receiver consumer frame and queue totals disagree")
    if consumer_outcomes is not None and consumer_outcomes != int(rx["Queued"]):
        raise ValueError("receiver consumer outcome and queue totals disagree")

    result = {
        "schema_version": 2,
        "scope": scope,
        "outbound_capture_count_verified": outbound_verified,
        "inbound_capture_count_verified": inbound_verified,
        "outbound_counter_packets": outbound_count,
        "inbound_counter_packets": inbound_count,
        "worker_consumer_frames": consumer_frames,
        "worker_consumer_outcomes": consumer_outcomes,
        "stream": int(stream),
        "destination": destination,
        "sender_endpoint": sender,
        "sender_interface": tx["interface"],
        "receiver_interface": rx["interface"],
        "sender_started_unix_us": int(tx["started_unix_us"]),
        "receiver_started_unix_us": int(rx["started_unix_us"]),
        "sender_write_failures": int(tx["WriteFailed"]),
        "sender_write_failed_frame_ids": [
            int(row["frame"]) for row in tx_rows if row["stage"] == "WriteFailed"
        ],
        "receiver_counts": {
            stage: int(rx[stage]) for stage in STAGES[2:] + FRAME_DROP_STAGES if stage in rx
        },
        "receiver_queue_full_frame_ids": [
            int(row["frame"]) for row in rx_rows if row["stage"] == "FrameQueueFull"
        ],
        "receiver_packet_rejections": dict(Counter(row["rejection"] for row in rx_rows if row["rejection"])),
        "reassembly_expired_frame_ids": [
            int(row["frame"]) for row in rx_rows if row["stage"] == "FrameExpired"
        ] if "FrameExpired" in rx else None,
        "reassembly_window_evicted_frame_ids": [
            int(row["frame"]) for row in rx_rows if row["stage"] == "FrameWindowEvicted"
        ] if "FrameWindowEvicted" in rx else None,
        **compare(
            written, received, outbound, inbound,
            outbound_verified=outbound_verified, inbound_verified=inbound_verified,
        ),
    }
    if redact_network:
        for field in ("destination", "sender_endpoint", "sender_interface", "receiver_interface",
                      "sender_started_unix_us", "receiver_started_unix_us"):
            del result[field]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sender", type=Path)
    parser.add_argument("receiver", type=Path)
    parser.add_argument("--outbound", type=Path)
    parser.add_argument("--inbound", type=Path)
    parser.add_argument("--outbound-count", type=int, help="selected NIC outbound Pktmon flow packet count")
    parser.add_argument("--inbound-count", type=int, help="selected NIC inbound Pktmon flow packet count")
    parser.add_argument("--redact-network", action="store_true", help="omit addresses and wall-clock anchors")
    parser.add_argument("--scope", choices=("unspecified", "single-host-vm", "two-host-lab"), default="unspecified")
    args = parser.parse_args()
    try:
        output = report(
            args.sender, args.receiver, args.outbound, args.inbound,
            outbound_count=args.outbound_count, inbound_count=args.inbound_count,
            redact_network=args.redact_network, scope=args.scope,
        )
    except (ValueError, KeyError, OSError) as error:
        parser.exit(2, f"multicast delivery: {error}\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
