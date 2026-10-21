"""Contract tests for a read-only GitHub Actions elapsed-time report."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

SCRIPT = Path(__file__).resolve().parents[1] / "ci_timing_report.py"
START = datetime(2026, 10, 21, tzinfo=timezone.utc)


def iso(seconds):
    return (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def example_run(windows=1080, portable=35, failed=False, missing_end=False):
    return {
        "databaseId": 39649464235,
        "jobs": [
            {
                "name": "Windows Build",
                "conclusion": "failure" if failed else "success",
                "startedAt": iso(0),
                "completedAt": None if missing_end else iso(windows),
                "steps": [
                    {
                        "name": "Test",
                        "conclusion": "success",
                        "startedAt": iso(10),
                        "completedAt": iso(205),
                    },
                    {
                        "name": "Build Teacher UI shell",
                        "conclusion": "success",
                        "startedAt": iso(220),
                        "completedAt": iso(390),
                    },
                    {"name": "No timestamps", "conclusion": "skipped"},
                ],
            },
            {
                "name": "Portable Rust",
                "conclusion": "success",
                "startedAt": iso(0),
                "completedAt": iso(portable),
                "steps": [],
            },
        ],
    }


class CITimingReportTests(unittest.TestCase):
    def run_report(self, *runs, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            inputs = []
            for i, value in enumerate(runs):
                path = Path(tmp) / f"run{i}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                inputs.append(str(path))
            return subprocess.run(
                [sys.executable, str(SCRIPT), *inputs, *extra],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_reports_windows_and_portable_job_times_and_slowest_stages(self):
        output = self.run_report(example_run(), extra=("--top", "2"))
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("Windows Build", output.stdout)
        self.assertIn("18m 00s", output.stdout)
        self.assertIn("Portable Rust", output.stdout)
        self.assertIn("0m 35s", output.stdout)
        self.assertLess(
            output.stdout.index("Test"),
            output.stdout.index("Build Teacher UI shell"),
        )
        self.assertNotIn("No timestamps", output.stdout)

    def test_compares_successful_windows_samples_without_performance_promise(self):
        output = self.run_report(
            example_run(1080),
            extra=("--compare",),
        )
        self.assertNotEqual(output.returncode, 0)
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.json"
            after = Path(tmp) / "after.json"
            before.write_text(json.dumps(example_run(1080)), encoding="utf-8")
            after.write_text(json.dumps(example_run(600)), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(before), "--compare", str(after)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("44.4%", result.stdout)
            self.assertIn("single-run", result.stdout.lower())

    def test_failed_windows_job_does_not_count_as_successful_benchmark(self):
        output = self.run_report(example_run(failed=True))
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("failure", output.stdout.lower())
        self.assertIn("no successful Windows Build", output.stdout)

    def test_missing_completion_is_labeled_incomplete(self):
        output = self.run_report(example_run(missing_end=True))
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("incomplete", output.stdout.lower())

    def test_rejects_negative_elapsed_time_instead_of_reporting_speedup(self):
        data = example_run()
        data["jobs"][0]["completedAt"] = iso(-10)
        output = self.run_report(data)
        self.assertNotEqual(output.returncode, 0)
        self.assertIn("earlier than", output.stderr)

    def test_median_for_repeated_runs_is_not_the_fastest_sample(self):
        output = self.run_report(example_run(1080), example_run(1200), example_run(900))
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("3 successful Windows Build runs", output.stdout)
        self.assertIn("median 18m 00s", output.stdout)


    def test_three_warm_candidates_use_median_not_fastest_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for i, seconds in enumerate((1080, 1200, 900, 700, 620, 650)):
                path = Path(tmp) / f"measurement_{i}.json"
                path.write_text(json.dumps(example_run(seconds)), encoding="utf-8")
                paths.append(str(path))
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), *paths[:3],
                    "--compare", *paths[3:],
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("39.8%", result.stdout)
            self.assertIn("3 candidate", result.stdout)
            self.assertNotIn("single-run", result.stdout)



if __name__ == "__main__":
    unittest.main()
