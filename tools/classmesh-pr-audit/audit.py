#!/usr/bin/env python3
"""Read-only ClassMesh decision support; writes only to the output directory."""
import sys

# Set before local imports, including when invoked without python -B.
sys.dont_write_bytecode = True

import argparse
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat

from github_source import GitHub, collect
from policy import analyze_v2, compare_versions, clean


def md(value):
    return html.escape(str(value), quote=True).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\n", " ").replace("\r", " ")


def render_markdown(report):
    if report.get("schema_version") == 2:
        from reporting import render
        return render(report)
    lines = ["# تقرير جاهزية طلبات ClassMesh", "",
             "الوضع: **" + md(report["mode"]) + "** · جمع البيانات: **" + report["collection_state"] + "**",
             "", "المستودع: " + md(report["repo"]) + " · الفرع المستهدف: " + md(report["target_branch"]),
             "", "بداية الفحص: " + md(report["captured_at"]) + " · نهايته: " + md(report["finished_at"]),
             "", "هذا تقرير للقراءة فقط. READY_FOR_FINAL_REVIEW تعني جاهزية العرض للمراجعة النهائية، وليست إذنًا بالدمج.",
             "", "## الملخص", "",
             "إجمالي الطلبات: **" + str(report["summary"]["total"]) + "** · الجاهز للمراجعة النهائية: **" + str(report["summary"]["ready_for_final_review"]) + "**", "",
             "قد يظهر الطلب في أكثر من تصنيف؛ لا تُجمع الأعداد باعتبارها طلبات مختلفة.", "",
             "| التصنيف | العدد |", "| --- | ---: |"]
    for name, count in sorted(report["summary"]["by_classification"].items()):
        lines.append("| " + name + " | " + str(count) + " |")
    if report["collection_gaps"]:
        lines += ["", "**نقص في جمع البيانات — UNKNOWN:**"]
        lines += ["- " + md(g["field"]) + ": " + md(g["code"]) for g in report["collection_gaps"]]
    lines += ["", "## التبعيات وأولوية المراجعة", "", "الترتيب يخص معالجة العوائق والمراجعة، ولا يشغّل أي دمج أو مجدول.", ""]
    for chain in report["dependency_chains"]:
        lines.append("- `" + " → ".join("#" + str(n) for n in chain) + "`")
    if not report["dependency_chains"]:
        lines.append("لا توجد سلاسل مكتشفة في البيانات المتاحة؛ راجع التبعيات UNKNOWN لكل طلب.")
    lines += ["", "الأولوية المقترحة (الأساس قبل التابع): `" + " → ".join("#" + str(n) for n in report["suggested_review_order"]) + "`", ""]
    for pr in sorted(report["pull_requests"], key=lambda p: p["suggested_review_priority"] if type(p["suggested_review_priority"]) is int else 999999):
        lines += ["## #" + str(pr["number"]) + " — " + md(pr["title"]), "", md(pr["url"]), "",
            "**التصنيفات:** " + "، ".join(pr["classifications"]), "",
            "- أولوية المراجعة: " + str(pr["suggested_review_priority"]),
            "- Draft: " + md(pr["draft"]) + " · قابلية الدمج: " + md(pr["mergeable"]) + " · GitHub: " + md(pr["mergeable_state"]),
            "- HEAD: `" + md(pr["head_sha"]) + "` (" + md(pr["head_branch"]) + ")",
            "- Base: " + md(pr["base_branch"]) + " · SHA في PR: `" + md(pr["base_sha"]) + "`",
            "- رأس الفرع الأساسي الحالي: `" + md(pr["base_branch_sha"]) + "`",
            "- التبعيات: " + md(pr["dependencies"]["state"]) + " · الآباء: " + md(pr["dependencies"]["parents"]),
            "", "### العوائق", ""]
        lines += ["- **" + b["classification"] + "**: " + md(b["reason"]) + " (" + md(b["code"]) + ")" for b in pr["blockers"]] or ["لا توجد عوائق مكتشفة ضمن نطاق الأدلة المتاحة."]
        for ancestor in pr["dependencies"]["ancestor_blockers"]:
            lines.append("- عوائق الأساس #" + str(ancestor["number"]) + ": " + "، ".join(ancestor["classifications"]))
        lines += ["", "### الفحوص على HEAD الحالي", "", "| الفحص | الحالة | الأدلة |", "| --- | --- | --- |"]
        for name, gate in pr["ci"].items():
            links = "; ".join(item["url"] for item in gate["evidence"] if item["url"] != "UNKNOWN") or "UNKNOWN"
            lines.append("| " + md(name) + " | " + gate["state"] + " | " + md(links) + " |")
            for rejected in gate["rejected_evidence"]:
                lines.append("| ↳ دليل غير مقبول | " + md(rejected["reason"]) + " | " + md(rejected.get("url", "UNKNOWN")) + " |")
        reviews = pr["reviews"]
        lines += ["", "### المراجعات والأمن والقبول اليدوي", "",
            "- عدد الموافقات المطلوب من المستودع: " + md(reviews["repository_required_approvals"]),
            "- الحد الأدنى المستقل وفق سياسة المدقق: " + md(reviews["auditor_required_independent_approvals"]),
            "- الموافقون المستقلون على HEAD: " + ("، ".join(md(r) for r in reviews["independent_approvals"]) or "لا يوجد"),
            "- قرار مراجعات GitHub: " + md(reviews["github_review_decision"]),
            "- المراجعون المطلوبون: " + md(reviews["requested_reviewers"]) + " · الفرق: " + md(reviews["requested_teams"]),
            "- Code scanning: " + pr["security"]["code_scanning"]["state"],
            "- القبول اليدوي/الأجهزة: **" + pr["manual_acceptance"]["state"] + "** — " + md(pr["manual_acceptance"]["reason"])]
        for review in reviews["recorded"]:
            lines.append("- مراجعة مسجلة: " + md(review["reviewer"]) + " · " + review["state"] + " · `" + md(review["commit_sha"]) + "` · " + md(review["url"]))
        for thread in reviews["unresolved_threads"]:
            lines += ["- خيط مفتوح: " + md(thread["id"]) + " · قديم الأسطر: " + md(thread["is_outdated"])]
            lines += ["  - " + md(c["body"]) + " — " + md(c["url"]) for c in thread["comments"]]
        for note in pr["security"]["notes"]:
            lines += ["", "> إشارة أمنية تحتاج قراءة بشرية (" + note["source"] + "): " + md(note["excerpt"]),
                      "> المصدر: " + md(note["url"])]
        for alert in pr["security"]["code_scanning"]["alerts"]:
            lines.append("- تنبيه أمني #" + str(alert["number"]) + " · " + md(alert["state"]) + " · " + md(alert["url"]))
        if pr["missing_evidence"]:
            lines += ["", "### الأدلة الناقصة — UNKNOWN", ""]
            lines += ["- " + md(gap["field"]) + ": " + md(gap["code"]) for gap in pr["missing_evidence"]]
        lines.append("")
    lines += ["## حدود التقرير", ""] + ["- " + md(item) for item in report["limitations"]]
    return "\n".join(lines) + "\n"


def write_reports(output_dir, report, markdown, snapshot=None):
    """Confine writes to a pinned directory descriptor; reject linked targets.

    Existing parent must exist. /tmp's macOS ancestor symlink is fine, but the
    output directory itself and every target must not be symlinks.
    All files are staged before replacement; each replacement is atomic.
    """
    root = Path(output_dir).absolute()
    if root.is_symlink():
        raise ValueError("OUTPUT_DIRECTORY_SYMLINK")
    root.mkdir(mode=0o700, exist_ok=True)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staged = []
    try:
        contents = {"report.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n", "report.md": markdown}
        if snapshot is not None:
            contents["snapshot.json"] = json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"
        for name in contents:
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("OUTPUT_TARGET_LINK_OR_SPECIAL_FILE")
        for name, content in contents.items():
            temporary = ".pr-audit-" + secrets.token_hex(12)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            staged.append(temporary)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        for temporary, name in zip(list(staged), contents):
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            staged.remove(temporary)
    finally:
        for temporary in staged:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # Argument values may contain accidentally pasted credentials.
        self.exit(3, "ERROR: INVALID_ARGUMENTS (use --help)\n")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--repo", default="faariis7/ClassMesh")
    parser.add_argument("--target-branch", default="main")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--fixture", help="Offline snapshot JSON; makes no GitHub calls")
    parser.add_argument("--compare-v1", action="store_true", help="Include V1/V2 decisions from the same snapshot")
    parser.add_argument("--save-snapshot", action="store_true", help="Save sanitized snapshot.json inside output directory")
    parser.add_argument("--timeout", type=float, default=20, help="Per request timeout, seconds (1..60)")
    parser.add_argument("--deadline", type=float, default=600, help="Total request budget, seconds (1..3600)")
    parser.add_argument("--max-requests", type=int, default=1200)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or not (1 <= args.timeout <= 60 and 1 <= args.deadline <= 3600 and 1 <= args.max_requests <= 5000):
        parser.error("invalid")
    try:
        if args.fixture:
            with open(args.fixture, "rb") as stream:
                data = stream.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                raise ValueError("FIXTURE_TOO_LARGE")
            snapshot = json.loads(data)
            snapshot["mode"] = "FIXTURE_ONLY"
        else:
            snapshot = collect(GitHub(args.timeout, args.deadline, args.max_requests), args.repo, args.target_branch)
        # Remove known credential values too, even if they are not GitHub-shaped.
        serialized = json.dumps(clean(snapshot), ensure_ascii=False)
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
            secret = os.environ.get(key)
            if secret:
                serialized = serialized.replace(json.dumps(secret, ensure_ascii=False)[1:-1], "[REDACTED]")
        snapshot = json.loads(serialized)
        report = analyze_v2(snapshot)
        if args.compare_v1:
            report["comparison"] = compare_versions(snapshot)
        write_reports(args.output_dir, report, render_markdown(report), snapshot if args.save_snapshot else None)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print("ERROR: INPUT_OR_OUTPUT_FAILED; no success report is claimed", file=sys.stderr)
        return 3
    print(f"{report['collection_state']}: {report['summary']['total']} PRs; {report['summary']['merge_candidates']} READY_FOR_MERGE (not authorization)")
    return 2 if report["collection_state"] == "PARTIAL" else 0


if __name__ == "__main__":
    sys.exit(main())
