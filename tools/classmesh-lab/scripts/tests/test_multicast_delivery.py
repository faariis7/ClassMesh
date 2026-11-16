import importlib.util
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "multicast_delivery.py"
SPEC = importlib.util.spec_from_file_location("multicast_delivery", SCRIPT)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class DeliveryTests(unittest.TestCase):
    def test_missing_ranges_include_leading_internal_and_trailing_writes(self):
        written = [(9, seq, seq, 0) for seq in range(1, 9)]
        outbound = [written[i] for i in (0, 1, 2, 3, 4, 6)]
        received = [written[i] for i in (1, 4, 6)]
        result = diagnostic.compare(written, received, outbound)
        self.assertEqual(result["written_without_socket_read"], [[1, 1], [3, 4], [6, 6], [8, 8]])
        self.assertEqual(result["written_without_outbound_observation"], [[6, 6], [8, 8]])
        self.assertEqual(result["outbound_without_socket_read"], [[1, 1], [3, 4]])

    def test_reordering_duplicates_and_wrong_frame_do_not_fill_a_gap(self):
        written = [(9, seq, 44, seq - 1) for seq in range(1, 5)]
        received = [written[2], written[0], written[2], (9, 2, 45, 1), written[3]]
        result = diagnostic.compare(written, received, None)
        self.assertEqual(result["written_without_socket_read"], [[2, 2]])
        self.assertEqual(result["reordered_socket_reads"], 1)
        self.assertEqual(result["duplicate_socket_reads"], 1)
        self.assertEqual(result["unmatched_socket_reads"], 1)
        self.assertIsNone(result["written_without_outbound_observation"])


    def test_two_nics_separate_inflight_and_pre_socket_gaps(self):
        written = [(9, seq, seq, 0) for seq in range(5)]
        result = diagnostic.compare(written, written[:1], written[:4], written[:2])
        self.assertEqual(result["written_without_outbound_observation"], [[4, 4]])
        self.assertEqual(result["outbound_without_inbound_observation"], [[2, 3]])
        self.assertEqual(result["inbound_without_socket_read"], [[1, 1]])

    def test_capture_correlates_only_the_selected_route_and_stream(self):
        def row(source, stream, sequence):
            header = b"CMV1\x00\x04\x00\x00" + struct.pack(">IQIH", stream, 3, sequence, 2)
            return f"1.25\t{source}\t50123\t239.1.1.4\t50494\t{header.hex(':')}\n"

        with TemporaryDirectory() as directory:
            path = Path(directory) / "nic.tsv"
            path.write_text(
                row("192.168.50.10", 9, 41)
                + row("192.168.50.11", 9, 42)
                + row("192.168.50.10", 8, 43),
                encoding="utf-8",
            )
            self.assertEqual(
                diagnostic.capture(path, "192.168.50.10:50123", "239.1.1.4:50494", 9),
                {(9, 41, 3, 2)},
            )
            path.write_text("1.25\t192.168.50.10\t50123\t239.1.1.4\t50494\t434d\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "too short"):
                diagnostic.capture(path, "192.168.50.10:50123", "239.1.1.4:50494", 9)

    def test_saturated_trace_fails_before_missing_ranges_are_generated(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sender.tsv"
            path.write_text(
                "# format=classmesh-multicast-delivery-v1\n# role=send\n"
                "# complete=true\n# omitted=1\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "saturated"):
                diagnostic.trace(path, "send")


if __name__ == "__main__":
    unittest.main()
