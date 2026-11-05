#!/usr/bin/env python3
"""Offline syntax, deterministic sample and optional Git change-scope checks."""
import sys
sys.dont_write_bytecode = True

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

from audit import render_markdown
from policy import analyze_v2, compare_versions

ROOT = Path(__file__).resolve().parent


def validate_paths(paths):
    return [p for p in paths if ".." in PurePosixPath(p).parts or not (
        p.startswith("tools/classmesh-pr-audit/") or p == ".github/workflows/classmesh-pr-audit.yml")]


def verify_syntax(root):
    errors = []
    for path in sorted(root.rglob("*.py")):
        try:
            compile(path.read_bytes(), str(path), "exec")
        except (OSError, SyntaxError, ValueError):
            errors.append("SYNTAX: " + str(path.relative_to(root)))
    return errors


def verify_example(root):
    try:
        snapshot = json.loads((root / "examples/input.json").read_text(encoding="utf-8"))
        snapshot["mode"] = "FIXTURE_ONLY"
        result = analyze_v2(snapshot)
        result["comparison"] = compare_versions(snapshot)
        expected_json = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        return [name + " MISMATCH" for name, content in (("report.json", expected_json), ("report.md", render_markdown(result)))
                if (root / "examples" / name).read_text(encoding="utf-8") != content]
    except (OSError, ValueError, KeyError, TypeError):
        return ["EXAMPLE_INVALID"]


def verify_scope(base, head):
    if not all(isinstance(s, str) and re.fullmatch(r"[0-9a-f]{40}", s) for s in (base, head)):
        return ["SCOPE_REQUIRES_EXACT_SHAS"]
    try:
        result = subprocess.run(["git", "diff", "--no-renames", "--name-only", "-z", base + "..." + head],
            cwd=ROOT, capture_output=True, check=True, timeout=30)
        paths = result.stdout.decode("utf-8").rstrip("\0").split("\0") if result.stdout else []
        return ["OUT_OF_SCOPE: " + p for p in validate_paths(paths)]
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return ["SCOPE_UNAVAILABLE"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope-base")
    parser.add_argument("--scope-head")
    args = parser.parse_args()
    errors = verify_syntax(ROOT) + verify_example(ROOT)
    if args.scope_base is not None or args.scope_head is not None:
        errors += verify_scope(args.scope_base, args.scope_head)
    print("\n".join(errors) if errors else "PASS: syntax, deterministic sample" + (", change scope" if args.scope_base else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
