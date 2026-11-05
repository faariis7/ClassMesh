"""Conservative observations of executed trees, not test-sufficiency claims."""
import re

from github_source import is_known, known, unknown

SHA = re.compile(r"[0-9a-f]{40}\Z")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z\s+")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def declared_dependencies(body):
    """Only explicit single-line declarations; arbitrary #mentions are not edges."""
    if not isinstance(body, str):
        return []
    result = set()
    for line in body.splitlines():
        if re.fullmatch(r"\s*Depends-On:\s*#[1-9][0-9]*(?:\s*,\s*#[1-9][0-9]*)*\s*", line, re.I):
            result.update(int(n) for n in re.findall(r"#([0-9]+)", line))
    return sorted(result)


def checkout_commit(log):
    """Reject ambiguous/multiple checkouts or visible later Git tree mutations.

    Only the checkout action's git-log output is retained. Workflow authors can
    control logs: this is GitHub execution evidence, not an attestation of trust.
    """
    if not isinstance(log, str) or len(log) > 8 * 1024 * 1024:
        return unknown("LOG_TOO_LARGE_OR_INVALID", "checkout log")
    lines = [STAMP.sub("", ANSI.sub("", line)).strip() for line in log.splitlines()]
    starts = [i for i, line in enumerate(lines) if line.startswith("##[group]Run actions/checkout@")]
    markers = [i for i, line in enumerate(lines) if re.fullmatch(r'''\[command\].*\bgit(?:\.exe)?["']? log -1 --format=%H''', line)]
    if len(starts) != 1 or len(markers) != 1 or starts[0] >= markers[0]:
        return unknown("CHECKOUT_NOT_UNAMBIGUOUS", "checkout log")
    marker = markers[0]
    if marker + 1 >= len(lines) or not SHA.fullmatch(lines[marker + 1]):
        return unknown("CHECKOUT_SHA_MISSING", "checkout log")
    tail = "\n".join(lines[marker + 2:])
    if re.search(r'''\bgit(?:\.exe)?["']?\s+(?:-[^\n]*?\s+)?(?:checkout|switch|reset|worktree|pull|merge|rebase|read-tree|clone)\b''', tail):
        return unknown("SUBSEQUENT_TREE_CHANGE", "checkout log")
    return known(lines[marker + 1])


def collect_execution_proofs(gh, repo, pr, checks, runs, commits, policy=None):
    from policy import GATES, validate_runs, valid_list
    if not is_known(checks) or not is_known(runs):
        return {}
    try:
        if not valid_list(checks["data"]) or not validate_runs(runs["data"]):
            return {}
        head = pr["head"]["sha"]
        latest = {}
        for run in runs["data"]:
            if run["head_sha"] != head or run["event"] != "pull_request" or not any(p["number"] == pr["number"] for p in run["pull_requests"]):
                continue
            path = run["path"]
            if path not in latest or (run["id"], run["run_attempt"]) > (latest[path]["id"], latest[path]["run_attempt"]):
                latest[path] = run
        proofs = {}
        names = {name for aliases, _ in GATES.values() for name in aliases}
        if is_known(policy) and isinstance(policy["data"], dict):
            names.update(c["context"] for c in policy["data"].get("required_checks", [])
                         if isinstance(c, dict) and isinstance(c.get("context"), str))
        for check in checks["data"]:
            if check.get("name") not in names or check.get("head_sha") != head or check.get("status") != "completed":
                continue
            if not isinstance(check.get("app"), dict) or check["app"].get("slug") != "github-actions":
                continue
            run = next((r for r in latest.values() if r["check_suite_id"] == check.get("check_suite", {}).get("id")), None)
            check_id = check.get("id")
            if run is None or type(check_id) is not int:
                continue
            key = str(check_id)
            job_path = f"repos/{repo}/actions/jobs/{check_id}"
            job = gh.get(job_path)
            if not is_known(job):
                proofs[key] = job
                continue
            data = job["data"]
            if not isinstance(data, dict) or any(data.get(k) != v for k, v in {
                    "id": check_id, "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": head,
                    "status": "completed", "conclusion": check.get("conclusion")}.items()):
                proofs[key] = unknown("JOB_ATTEMPT_OR_IDENTITY_MISMATCH", job_path)
                continue
            raw = gh.get_text(job_path + "/logs")
            observed = checkout_commit(raw["data"]) if is_known(raw) else raw
            if not is_known(observed):
                proofs[key] = observed
                continue
            sha = observed["data"]
            if sha not in commits:
                commits[sha] = gh.get(f"repos/{repo}/git/commits/{sha}")
            commit = commits[sha]
            if not is_known(commit):
                proofs[key] = commit
                continue
            payload = commit["data"]
            if (not isinstance(payload, dict) or payload.get("sha") != sha or not valid_list(payload.get("parents"))
                    or any(not isinstance(p.get("sha"), str) or not SHA.fullmatch(p["sha"]) for p in payload["parents"])):
                proofs[key] = unknown("INVALID_COMMIT_PARENTS", "git commit")
                continue
            proofs[key] = known({"source": "GITHUB_ACTIONS_CHECKOUT_LOG", "check_id": check_id,
                "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": head,
                "checkout_sha": sha, "parents": [p["sha"] for p in payload["parents"]],
                "url": check.get("details_url", "UNKNOWN")})
        return proofs
    except (KeyError, TypeError, ValueError, AttributeError):
        return {}


def validate_base(entry, pr):
    """Keep HEAD success separate from observed integration freshness."""
    from policy import obj, valid_sha, url
    result = {"state": "UNKNOWN", "head_sha": pr["head_sha"], "current_base_sha": pr["base_branch_sha"],
              "reported_merge_sha": obj(obj(entry.get("detail")).get("data")).get("merge_commit_sha") or "UNKNOWN",
              "gates": {}, "reason": "لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس"}
    stable = entry.get("stable")
    if not is_known(stable) or stable["data"] is not True:
        result.update(state="CHANGED_DURING_COLLECTION", reason="تغير PR أو أساسه أثناء الجمع، أو تعذر التحقق من ثباتهما")
        return result
    checks = obj(entry.get("checks")).get("data", [])
    runs = obj(entry.get("runs")).get("data", [])
    proofs = obj(entry.get("execution_proofs"))
    if not isinstance(checks, list) or not isinstance(runs, list):
        return result
    strict = obj(pr.get("branch_policy")).get("strict_checks")
    for name, gate in pr["ci"].items():
        observations = []
        for check in gate["evidence"]:
            value = proofs.get(str(check["check_id"]))
            item = {"state": "UNKNOWN", "check_id": check["check_id"], "url": check["url"],
                    "tested_base_sha": "UNKNOWN", "checkout_sha": "UNKNOWN", "reason": "CHECKOUT_PROOF_UNAVAILABLE"}
            observations.append(item)
            if not is_known(value) or not isinstance(value["data"], dict):
                item["reason"] = obj(obj(value).get("error")).get("code", "CHECKOUT_PROOF_UNAVAILABLE")
                continue
            data = value["data"]
            raw_check = next((c for c in checks if obj(c).get("id") == check["check_id"]), {})
            run = next((r for r in runs if obj(r).get("id") == data.get("run_id")
                        and obj(r).get("run_attempt") == data.get("run_attempt")), {})
            if (data.get("source") != "GITHUB_ACTIONS_CHECKOUT_LOG" or data.get("head_sha") != pr["head_sha"]
                    or data.get("check_id") != check["check_id"] or obj(run).get("head_sha") != pr["head_sha"]
                    or obj(run).get("check_suite_id") != obj(obj(raw_check).get("check_suite")).get("id")
                    or not valid_sha(data.get("checkout_sha")) or not isinstance(data.get("parents"), list)
                    or any(not valid_sha(p) for p in data["parents"]) or check["url"] == "UNKNOWN"
                    or url(data.get("url")) != check["url"]):
                item["reason"] = "PROOF_IDENTITY_MISMATCH"
                continue
            item.update(checkout_sha=data["checkout_sha"], run_id=data["run_id"], run_attempt=data["run_attempt"])
            if data["checkout_sha"] == pr["head_sha"]:
                item.update(state="HEAD_ONLY", reason="رُصد checkout لـHEAD نفسه؛ هذا ليس دليل تكامل مع الأساس")
                if strict is not False:
                    item.update(state="UNKNOWN", reason="STRICT_BASE_RULE_REQUIRES_INTEGRATION_PROOF")
            elif len(data["parents"]) == 2 and data["parents"][1] == pr["head_sha"] and valid_sha(pr["base_branch_sha"]):
                base = data["parents"][0]
                item.update(tested_base_sha=base,
                    state="INTEGRATION_CURRENT" if base == pr["base_branch_sha"] else "INTEGRATION_STALE",
                    reason="آباء commit المرصود يربطونه بـHEAD وإصدار محدد من الأساس")
            else:
                item["reason"] = "UNPROVEN_PR_MERGE_PARENTS"
        states = [o["state"] for o in observations]
        state = "UNKNOWN" if not states or "UNKNOWN" in states else "INTEGRATION_STALE" if "INTEGRATION_STALE" in states else "INTEGRATION_CURRENT" if "INTEGRATION_CURRENT" in states else "HEAD_ONLY"
        result["gates"][name] = {"state": state, "ci_state": gate["state"], "observations": observations,
            "tested_base_sha": next((o["tested_base_sha"] for o in observations if o["tested_base_sha"] != "UNKNOWN"), "UNKNOWN")}
    states = [g["state"] for g in result["gates"].values()]
    if "INTEGRATION_STALE" in states:
        result.update(state="INTEGRATION_STALE", reason="نجاح HEAD محفوظ؛ اختبار التكامل استخدم إصدارًا أقدم من الأساس. إعادة التشغيل وحدها لا تثبت تحديثه")
    elif states and "UNKNOWN" not in states:
        state = "INTEGRATION_CURRENT" if "INTEGRATION_CURRENT" in states else "HEAD_ONLY"
        result.update(state=state, reason="ثبت checkout وآباء نسخة التكامل الحالية" if state == "INTEGRATION_CURRENT" else "الفحوص المرصودة تختبر HEAD وحده؛ تحرك الأساس لا يمحو هذه النتائج ولا يثبت تكاملًا جديدًا")
    return result
