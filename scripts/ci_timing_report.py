#!/usr/bin/env python3
"""Read-only local CI timing report from GitHub Actions JSON exports.

This tool never contacts GitHub, changes runner configuration, or calls a
synthetic hardware result physical qualification. Run it on multiple
completed CI JSON exports before changing caching or job topology.
"""
import argparse
import json
from datetime import datetime
from pathlib import Path
from statistics import median


def parse_time(value):
    if not value:
        return None
    timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("CI timestamps must include a UTC offset")
    return timestamp


def duration(data):
    start = parse_time(data.get("startedAt"))
    end = parse_time(data.get("completedAt"))
    if not start or not end:
        return None
    elapsed = (end - start).total_seconds()
    if elapsed < 0:
        raise ValueError("CI completion is earlier than its start")
    return elapsed


def format_time(seconds):
    rounded = round(seconds)
    minutes, seconds = divmod(rounded, 60)
    return f"{minutes}m {seconds:02d}s"


def load_run(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("jobs"), list):
        raise ValueError(f"{path}: expected a GitHub Actions export with jobs[]")
    return raw


def successful_windows_durations(runs):
    output = []
    for run in runs:
        for job in run["jobs"]:
            if job.get("name") == "Windows Build" and job.get("conclusion") == "success":
                elapsed = duration(job)
                if elapsed is not None:
                    output.append(elapsed)
    return output


def render(runs, names, top, compare_paths=None):
    lines = ["ClassMesh GitHub Actions timing report (read-only)"]
    for label, run in zip(names, runs):
        lines.append(f"\nRun {run.get('databaseId', label)} ({label})")
        for job in run["jobs"]:
            name = job.get("name", "Unnamed job")
            result = job.get("conclusion") or "incomplete"
            elapsed = duration(job)
            when = format_time(elapsed) if elapsed is not None else "incomplete"
            lines.append(f"  {name}: {when} [{result}]")

        windows = next((job for job in run["jobs"] if job.get("name") == "Windows Build"), None)
        if windows is not None and top > 0:
            ranked = []
            for step in windows.get("steps") or []:
                elapsed = duration(step)
                if elapsed is not None:
                    ranked.append((elapsed, str(step.get("name") or "Unnamed step")))
            ranked.sort(key=lambda item: (-item[0], item[1]))
            if ranked:
                lines.append(f"  Top {min(top, len(ranked))} Windows Build steps:")
                for elapsed, step_name in ranked[:top]:
                    lines.append(f"    {format_time(elapsed)} {step_name}")

    samples = successful_windows_durations(runs)
    if samples:
        lines.append(
            f"\n{len(samples)} successful Windows Build runs; "
            f"median {format_time(median(samples))}"
        )
    else:
        lines.append("\nno successful Windows Build timing samples")

    if compare_paths is not None:
        others = [load_run(path) for path in compare_paths]
        after = successful_windows_durations(others)
        if not samples or not after:
            raise ValueError("Need successful and timed Windows Build samples to compare")
        before_median, after_median = median(samples), median(after)
        if before_median <= 0:
            raise ValueError("Baseline timing must be positive")
        change = 100.0 * (before_median - after_median) / before_median
        label = "lower" if change >= 0 else "higher"
        lines.append(
            f"Comparison: {abs(change):.1f}% {label} Windows Build elapsed time "
            f"({format_time(before_median)} -> {format_time(after_median)})"
        )
        lines.append(f"{len(samples)} baseline and {len(after)} candidate successful Windows Build runs")
        if len(samples) < 3 or len(after) < 3:
            lines.append(
                "Caution: single-run/few-run comparison only; "
                "do not claim a repeatable speedup without >=3 warm samples."
            )
        else:
            lines.append("Compare cache hits, runner image and CI step sets before attribution.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+", help="Local GH run JSON export files")
    parser.add_argument("--top", type=int, default=8, help="Windows steps per run (default: 8)")
    parser.add_argument("--compare", type=Path, nargs="+", help="Compare baseline median to candidate run files")
    arguments = parser.parse_args()
    if arguments.top < 0 or arguments.top > 100:
        parser.error("--top must be between 0 and 100")
    try:
        print(
            render(
                [load_run(path) for path in arguments.reports],
                [str(path) for path in arguments.reports],
                arguments.top,
                arguments.compare,
            )
        )
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as error:
        parser.exit(status=2, message=f"ci_timing_report: {error}\n")


if __name__ == "__main__":
    main()
