"""Pure conservative readiness policy. UNKNOWN is never an approval."""
import re
from collections import Counter
from urllib.parse import urlsplit

from github_source import is_known

UNKNOWN = "UNKNOWN"
SHA = re.compile(r"[0-9a-f]{40}\Z")
GATES = {
    "Windows Build": (["Windows Build"], ".github/workflows/ci.yml"),
    "Portable Rust": (["Portable Rust"], ".github/workflows/ci.yml"),
    "CodeQL": (["CodeQL Rust security analysis", "CodeQL"], ".github/workflows/security-scanning.yml"),
    "Gitleaks": (["Gitleaks history scan", "Gitleaks"], ".github/workflows/security-scanning.yml"),
}
CLASSIFICATIONS = ["DRAFT", "MERGE_CONFLICT", "CI_FAILED", "CI_PENDING",
                   "SECURITY_REVIEW_REQUIRED", "DEPENDENCY_BLOCKED", "MANUAL_ACCEPTANCE_REQUIRED"]
SECURITY_WORDS = re.compile(r"security|vulnerab|CVE-|\bP[012]\b|privileg|trust.boundary|replay|أمن|امني|صلاحيات", re.I)


def redact(value):
    if not isinstance(value, str):
        return value
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})", "[REDACTED]", value)
    value = re.sub(r"(?i)\b(?:bearer|token)\s+[A-Za-z0-9._~+/-]{8,}", "[REDACTED]", value)
    return value


def clean(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(key): clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def url(value):
    if not isinstance(value, str):
        return UNKNOWN
    try:
        parts = urlsplit(value)
        if parts.scheme == "https" and parts.hostname == "github.com" and not parts.username and not parts.password:
            return "https://github.com" + parts.path + ("#" + parts.fragment if parts.fragment else "")
    except ValueError:
        pass
    return UNKNOWN


def obj(value):
    return value if isinstance(value, dict) else {}


def text(value):
    return value if isinstance(value, str) and value else UNKNOWN


def valid_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def valid_list(value):
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def evidence(entry, key, validator, gaps):
    item = entry.get(key)
    if is_known(item):
        try:
            if validator(item["data"]):
                return item["data"]
        except (KeyError, TypeError, ValueError, AttributeError):
            pass
        code = "INVALID_RESPONSE"
    else:
        code = obj(obj(item).get("error")).get("code", "MISSING_DATA")
    gaps.append({"field": key, "code": code})
    return None


def validate_pr(pr):
    return (isinstance(pr, dict) and type(pr["number"]) is int and pr["number"] > 0
            and isinstance(pr["title"], str) and type(pr["draft"]) is bool
            and pr["state"] == "open" and isinstance(pr["user"]["login"], str)
            and isinstance(pr["head"]["ref"], str) and isinstance(pr["base"]["ref"], str)
            and valid_sha(pr["head"]["sha"]) and valid_sha(pr["base"]["sha"])
            and isinstance(pr["head"]["repo"]["full_name"], str)
            and isinstance(pr["base"]["repo"]["full_name"], str)
            and valid_list(pr["requested_reviewers"]) and valid_list(pr["requested_teams"]))


def validate_policy(data):
    return (isinstance(data, dict) and type(data["required_approvals"]) is int
            and data["required_approvals"] >= 0
            and all(type(data[key]) is bool for key in ("code_owner_review", "last_push_approval", "conversation_resolution"))
            and valid_list(data["required_checks"])
            and all(isinstance(item["context"], str) and item["context"]
                    and (item.get("app_id") is None or type(item["app_id"]) is int) for item in data["required_checks"])
            and isinstance(data["unsupported_rules"], list)
            and all(isinstance(rule, str) for rule in data["unsupported_rules"]))


def validate_runs(rows):
    return valid_list(rows) and all(
        type(r["id"]) is int and type(r["workflow_id"]) is int and type(r["check_suite_id"]) is int
        and type(r["run_attempt"]) is int and r["run_attempt"] > 0
        and isinstance(r["head_sha"], str) and isinstance(r["path"], str)
        and isinstance(r["event"], str) and isinstance(r["status"], str)
        and valid_list(r["pull_requests"]) and all(type(p["number"]) is int for p in r["pull_requests"])
        for r in rows)


def check_state(check):
    if check.get("status") in ("queued", "in_progress", "waiting", "pending", "requested"):
        return "PENDING"
    if check.get("status") != "completed":
        return UNKNOWN
    if check.get("conclusion") == "success":
        return "SUCCESS"
    if check.get("conclusion") in ("failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"):
        return "FAILED"
    # skipped / neutral / missing are not a successful ClassMesh gate.
    return UNKNOWN


def aggregate(states):
    for state in ("FAILED", "PENDING", UNKNOWN):
        if state in states:
            return state
    return "SUCCESS" if states else UNKNOWN


def evaluate_gate(names, workflow, pr, checks, runs, app_id=None):
    result = {"state": UNKNOWN, "head_sha": obj(pr.get("head")).get("sha", UNKNOWN),
              "evidence": [], "rejected_evidence": [], "reason": "لا يوجد دليل مكتمل على HEAD الحالي"}
    if checks is None or runs is None or not valid_sha(result["head_sha"]):
        return result
    sha = result["head_sha"]
    relevant_runs = []
    for run in runs:
        if (run.get("head_sha") == sha and run.get("event") == "pull_request"
                and (workflow is None or run.get("path") == workflow)
                and any(obj(p).get("number") == pr.get("number") for p in (run.get("pull_requests") or []))):
            relevant_runs.append(run)
    latest = {}
    for run in relevant_runs:
        key = run.get("workflow_id")
        if type(key) is not int or type(run.get("id")) is not int:
            continue
        if key not in latest or (run["id"], run.get("run_attempt", 0)) > (latest[key]["id"], latest[key].get("run_attempt", 0)):
            latest[key] = run
    candidates = []
    for check in checks:
        if check.get("name") not in names:
            continue
        reason = None
        if check.get("head_sha") != sha:
            reason = "STALE_OR_OTHER_HEAD"
        elif obj(check.get("app")).get("slug") != "github-actions":
            reason = "UNTRUSTED_CHECK_APP"
        elif app_id not in (None, -1) and obj(check.get("app")).get("id") != app_id:
            reason = "WRONG_REQUIRED_APP"
        candidates.append(check) if reason is None else result["rejected_evidence"].append({
            "name": check.get("name"), "head_sha": check.get("head_sha", UNKNOWN), "reason": reason,
            "url": url(check.get("details_url"))})
    # A new run with no jobs yet must invalidate the previous green run.
    if any(run.get("status") in ("queued", "in_progress", "waiting", "pending", "requested") for run in latest.values()):
        result.update(state="PENDING", reason="تشغيل أحدث على HEAD الحالي لم يكتمل")
        return result
    selected = {}
    for check in candidates:
        suite = obj(check.get("check_suite")).get("id")
        run = next((r for r in latest.values() if r.get("check_suite_id") == suite), None)
        reason = None
        if run is None:
            reason = "NO_CURRENT_PR_WORKFLOW_BINDING"
        elif run.get("status") != "completed":
            reason = "WORKFLOW_STATUS_UNKNOWN"
        elif type(run.get("run_attempt")) is not int:
            reason = "ATTEMPT_UNKNOWN"
        elif run["run_attempt"] > 1 and (not isinstance(check.get("started_at"), str)
                or not isinstance(run.get("run_started_at"), str) or check["started_at"] < run["run_started_at"]):
            reason = "PREVIOUS_ATTEMPT"
        if reason:
            result["rejected_evidence"].append({"name": check.get("name"), "reason": reason,
                                                "url": url(check.get("details_url"))})
            continue
        key = check["name"]
        if type(check.get("id")) is not int:
            continue
        if key not in selected or check["id"] > selected[key]["id"]:
            selected[key] = check
    for check in selected.values():
        result["evidence"].append({"name": check["name"], "head_sha": sha,
            "state": check_state(check), "conclusion": check.get("conclusion") or UNKNOWN,
            "check_id": check["id"], "url": url(check.get("details_url"))})
    result["state"] = aggregate([item["state"] for item in result["evidence"]])
    if result["state"] != UNKNOWN:
        result["reason"] = "نتائج مرتبطة بـHEAD الحالي وتشغيل PR الحالي"
    return result


def analyze_entry(entry, snapshot):
    gaps, blockers = [], []

    def block(category, code, text):
        if not any(b["code"] == code for b in blockers):
            blockers.append({"classification": category, "code": code, "reason": text})

    pr = evidence(entry, "detail", validate_pr, gaps)
    if pr is None:
        pr = obj(entry.get("initial")) or obj(obj(entry.get("detail")).get("data"))
    pr = dict(pr)
    for key in ("head", "base"):
        raw = obj(pr.get(key))
        pr[key] = {"ref": text(raw.get("ref")), "sha": raw["sha"] if valid_sha(raw.get("sha")) else UNKNOWN,
                   "repo": {"full_name": text(obj(raw.get("repo")).get("full_name"))}}
    head, base = pr["head"], pr["base"]
    number = pr.get("number") if type(pr.get("number")) is int else entry.get("number", UNKNOWN)
    if type(number) is not int:
        number = UNKNOWN
    pr["number"] = number
    policy = evidence(entry, "policy", validate_policy, gaps)
    checks = evidence(entry, "checks", valid_list, gaps)
    runs = evidence(entry, "runs", validate_runs, gaps)
    statuses = evidence(entry, "statuses", valid_list, gaps)
    reviews = evidence(entry, "reviews", lambda rows: valid_list(rows) and all(
        isinstance(r["user"]["login"], str) and r["state"] in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED", "PENDING")
        and isinstance(r["submitted_at"], str) and type(r["id"]) is int for r in rows), gaps)
    thread_data = evidence(entry, "threads", lambda d: isinstance(d, dict) and "review_decision" in d
        and valid_list(d["threads"]) and all(type(t["isResolved"]) is bool and valid_list(t["comments"])
            and all(isinstance(c["body"], str) for c in t["comments"]) for t in d["threads"]), gaps)
    comments = evidence(entry, "comments", lambda rows: valid_list(rows) and all(isinstance(r["body"], str) for r in rows), gaps)
    files = evidence(entry, "files", lambda rows: valid_list(rows) and all(isinstance(r["filename"], str) for r in rows), gaps)
    alerts = evidence(entry, "code_scanning", lambda rows: valid_list(rows) and all(type(r["number"]) is int and "state" in r for r in rows), gaps)
    current_base = evidence(entry, "base_branch", lambda d: isinstance(d, dict) and valid_sha(d["sha"]), gaps)
    evidence(entry, "stable", lambda value: value is True, gaps)
    if pr.get("draft") is True:
        block("DRAFT", "DRAFT", "الطلب مسودة ولم يُعرض للمراجعة النهائية")
    elif type(pr.get("draft")) is not bool:
        gaps.append({"field": "draft", "code": "UNKNOWN"})
    mergeable = pr.get("mergeable")
    merge_state = pr.get("mergeable_state", UNKNOWN)
    if mergeable is False or merge_state == "dirty":
        block("MERGE_CONFLICT", "BASE_CONFLICT", "يوجد تعارض مع الفرع الأساسي")
    elif mergeable is not True:
        gaps.append({"field": "mergeable", "code": "UNKNOWN"})
    if merge_state not in ("clean", "dirty"):
        block("MANUAL_ACCEPTANCE_REQUIRED", "MERGE_STATE_" + str(merge_state).upper(),
              "حالة الدمج لدى GitHub تحتاج إلى حسم: " + str(merge_state))
    ci = {name: evaluate_gate(names, workflow, pr, checks, runs) for name, (names, workflow) in GATES.items()}
    for required in (policy or {}).get("required_checks", []):
        name = required["context"]
        gate = next((key for key, (names, _) in GATES.items() if names == [name]), None)
        if gate and required.get("app_id") in (None, -1, 15368):
            continue
        ci["required: " + name] = evaluate_gate([name], None, pr, checks, runs, required.get("app_id"))
        # Legacy statuses cannot prove the expected app identity. Surface them
        # for a coordinator; do not promote an unbound context to success.
        ci["required: " + name]["legacy_statuses"] = [
            {"state": s.get("state", UNKNOWN), "url": url(s.get("target_url"))}
            for s in (statuses or []) if s.get("context") == name]
    for name, result in ci.items():
        state = result["state"]
        if state == "FAILED":
            block("CI_FAILED", "CI_FAILED:" + name, name + ": فشل على HEAD الحالي")
        elif state in ("PENDING", UNKNOWN):
            block("CI_PENDING", "CI_INCOMPLETE:" + name, name + ": " + state)
            if state == UNKNOWN:
                gaps.append({"field": "ci." + name, "code": "NO_CURRENT_SUCCESS_EVIDENCE"})
        if name in ("CodeQL", "Gitleaks") and state != "SUCCESS":
            block("SECURITY_REVIEW_REQUIRED", "SECURITY_CHECK:" + name, "الفحص الأمني غير ناجح أو غير متاح: " + name)
    viewer = snapshot.get("viewer")
    excluded = {str(obj(pr.get("user")).get("login", "")).casefold(), snapshot.get("repo", "").split("/")[0].casefold()}
    if is_known(viewer) and isinstance(viewer["data"], str):
        excluded.add(viewer["data"].casefold())
    else:
        gaps.append({"field": "viewer", "code": "UNKNOWN"})
    opinionated = {}
    recorded = []
    for review in sorted(reviews or [], key=lambda r: (r["submitted_at"], r["id"])):
        login = review["user"]["login"]
        recorded.append({"reviewer": login, "state": review["state"], "commit_sha": review.get("commit_id") or UNKNOWN,
                         "url": url(review.get("html_url"))})
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            opinionated[login.casefold()] = review
    independent = []
    for login, review in opinionated.items():
        if review["state"] == "CHANGES_REQUESTED":
            block("MANUAL_ACCEPTANCE_REQUIRED", "CHANGES_REQUESTED:" + login, "توجد مراجعة تطلب تغييرات: " + login)
        if (review["state"] != "APPROVED" or login in excluded or obj(review.get("user")).get("type") != "User"
                or review.get("commit_id") != head.get("sha") or not is_known(viewer)):
            continue
        permission = obj(entry.get("permissions")).get(review["user"]["login"])
        if not is_known(permission):
            gaps.append({"field": "reviewer_permission:" + login, "code": "UNKNOWN"})
        elif permission["data"] in ("write", "maintain", "admin"):
            independent.append(review["user"]["login"])
    required_count = max(1, policy["required_approvals"]) if policy else UNKNOWN
    if required_count == UNKNOWN or len(independent) < required_count:
        block("MANUAL_ACCEPTANCE_REQUIRED", "INDEPENDENT_APPROVAL_MISSING", "تنقص موافقة مستقلة على HEAD الحالي؛ COMMENTED ومراجعة صاحب الحساب لا تُحتسب")
    decision = (thread_data or {}).get("review_decision") or UNKNOWN
    if decision in ("CHANGES_REQUESTED", "REVIEW_REQUIRED") or (policy and (policy["code_owner_review"] or policy["last_push_approval"]) and decision != "APPROVED"):
        block("MANUAL_ACCEPTANCE_REQUIRED", "REQUIRED_REVIEW_UNSATISFIED", "المراجعات المطلوبة أو موافقة آخر دفع لم تُحسم لدى GitHub")
    if policy and policy["unsupported_rules"]:
        block("MANUAL_ACCEPTANCE_REQUIRED", "ADDITIONAL_RULES", "قواعد إضافية تحتاج تحققًا بشريًا: " + ", ".join(policy["unsupported_rules"]))
    unresolved = []
    for thread in (thread_data or {}).get("threads", []):
        if thread["isResolved"] is False:
            unresolved.append({"id": thread.get("id", UNKNOWN), "is_outdated": thread.get("isOutdated", UNKNOWN),
                               "comments": [{"body": c["body"][:2000], "url": url(c.get("url")),
                                   "author": obj(c.get("author")).get("login", UNKNOWN)} for c in thread["comments"]]})
    if unresolved:
        block("MANUAL_ACCEPTANCE_REQUIRED", "UNRESOLVED_THREADS", "توجد خيوط مراجعة مفتوحة، بما فيها الخيوط المرتبطة بأسطر قديمة")
    notes = []
    texts = [{"body": pr.get("body", ""), "url": pr.get("html_url"), "source": "PR_BODY"}]
    texts += [{"body": c["body"], "url": c.get("html_url"), "source": "COMMENT"} for c in (comments or [])]
    texts += [{"body": r.get("body", ""), "url": r.get("html_url"), "source": "REVIEW"} for r in (reviews or [])]
    texts += [{"body": c["body"], "url": c.get("url"), "source": "OPEN_THREAD"} for t in unresolved for c in t["comments"]]
    for item in texts:
        body = item["body"]
        if isinstance(body, str) and SECURITY_WORDS.search(body):
            notes.append({"source": item["source"], "excerpt": body[:2000], "url": url(item["url"]),
                          "interpretation": "KEYWORD_SIGNAL_REQUIRES_HUMAN_REVIEW"})
    filenames = [r["filename"] for r in (files or [])]
    sensitive = [p for p in filenames if p.startswith(("apps/classmesh-service/", "crates/classmesh-security/",
        "crates/classmesh-identity/", "crates/classmesh-win32/", "crates/classmesh-windows-runtime/"))]
    security_checks_incomplete = any(ci[key]["state"] != "SUCCESS" for key in ("CodeQL", "Gitleaks"))
    security = {"state": "REVIEW_REQUIRED" if notes or sensitive or alerts is None or alerts or security_checks_incomplete else "NO_REPORTED_FINDINGS",
        "notes": notes, "sensitive_paths": sensitive,
        "code_scanning": {"state": UNKNOWN if alerts is None else "KNOWN",
            "alerts": [{"number": a["number"], "state": a["state"], "url": url(a.get("html_url")),
                        "rule_id": obj(a.get("rule")).get("id", UNKNOWN),
                        "severity": obj(a.get("rule")).get("security_severity_level") or obj(a.get("rule")).get("severity", UNKNOWN),
                        "observed_commit_sha": obj(a.get("most_recent_instance")).get("commit_sha", UNKNOWN)} for a in (alerts or [])]}}
    if security["state"] == "REVIEW_REQUIRED":
        block("SECURITY_REVIEW_REQUIRED", "SECURITY_EVIDENCE_REVIEW", "تحتاج الملاحظات أو الحدود الأمنية إلى حسم مستقل؛ رصد الكلمات ليس حكمًا بوجود ثغرة")
    # This tool can establish tooling/docs scope, never physical acceptance.
    manual_required = files is None or not filenames or any(not (
        p.startswith("tools/classmesh-pr-audit/") or p.startswith("docs/") or p.endswith(".md")) for p in filenames)
    manual = {"state": UNKNOWN if manual_required else "NOT_APPLICABLE",
              "reason": "يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية"
                        if manual_required else "التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة"}
    if manual_required:
        block("MANUAL_ACCEPTANCE_REQUIRED", "MANUAL_SCOPE_OR_EVIDENCE", manual["reason"])
        gaps.append({"field": "manual_acceptance", "code": "NOT_MEASURED_OR_SCOPE_UNCONFIRMED"})
    if gaps:
        block("MANUAL_ACCEPTANCE_REQUIRED", "UNKNOWN_EVIDENCE", "توجد معلومات ناقصة أو غير قابلة للتحقق؛ راجع UNKNOWN")
    return {"number": number, "title": text(pr.get("title")), "url": url(pr.get("html_url")),
        "draft": pr["draft"] if type(pr.get("draft")) is bool else UNKNOWN, "head_sha": head.get("sha", UNKNOWN),
        "head_branch": head.get("ref", UNKNOWN), "head_repo": obj(head.get("repo")).get("full_name", UNKNOWN),
        "base_branch": base.get("ref", UNKNOWN), "base_repo": obj(base.get("repo")).get("full_name", UNKNOWN),
        "base_sha": base.get("sha", UNKNOWN), "base_branch_sha": (current_base or {}).get("sha", UNKNOWN),
        "mergeable": mergeable if type(mergeable) is bool else UNKNOWN, "mergeable_state": merge_state,
        "ci": ci, "reviews": {"state": "KNOWN" if reviews is not None and thread_data is not None else UNKNOWN,
            "repository_required_approvals": policy["required_approvals"] if policy else UNKNOWN,
            "auditor_required_independent_approvals": required_count, "github_review_decision": decision,
            "requested_reviewers": [obj(r).get("login", UNKNOWN) for r in pr["requested_reviewers"]] if valid_list(pr.get("requested_reviewers")) else UNKNOWN,
            "requested_teams": [obj(t).get("slug", UNKNOWN) for t in pr["requested_teams"]] if valid_list(pr.get("requested_teams")) else UNKNOWN,
            "independent_approvals": sorted(independent), "recorded": recorded, "unresolved_threads": unresolved},
        "branch_policy": policy or UNKNOWN, "security": security, "manual_acceptance": manual,
        "blockers": blockers, "missing_evidence": gaps, "observed_at": entry.get("observed_at", snapshot.get("captured_at", UNKNOWN))}


def analyze(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1 or not isinstance(snapshot.get("pulls"), list):
        raise ValueError("INVALID_SNAPSHOT")
    prs = [analyze_entry(obj(entry), snapshot) for entry in snapshot["pulls"]]
    ids = {pr["number"]: pr for pr in prs if type(pr["number"]) is int}
    collection_gaps = []
    discovered = evidence(snapshot, "discovery", lambda rows: valid_list(rows)
        and all(type(p["number"]) is int and p["number"] > 0 for p in rows), collection_gaps)
    evidence(snapshot, "inventory_stable", lambda value: value is True, collection_gaps)
    evidence(snapshot, "viewer", lambda value: isinstance(value, str) and bool(value), collection_gaps)
    if discovered is not None and sorted(p["number"] for p in discovered) != sorted(ids):
        collection_gaps.append({"field": "discovery", "code": "INVENTORY_COUNT_MISMATCH"})
    if len(ids) != len(prs):
        collection_gaps.append({"field": "pulls", "code": "INVALID_OR_DUPLICATE_PR"})
    branches = {}
    for pr in prs:
        branches.setdefault((pr["head_repo"].casefold(), pr["head_branch"]), []).append(pr["number"])
    target = text(snapshot.get("target_branch"))
    repo = text(snapshot.get("repo"))
    for pr in prs:
        parents = branches.get((pr["base_repo"].casefold(), pr["base_branch"]), []) if pr["base_branch"] != target else []
        state = "CLEAR" if pr["base_branch"] == target and pr["base_repo"].casefold() == repo.casefold() else "BLOCKED" if len(parents) == 1 else UNKNOWN
        pr["dependencies"] = {"state": state, "parents": parents, "ancestors": [], "ancestor_blockers": []}
        if state != "CLEAR":
            pr["blockers"].append({"classification": "DEPENDENCY_BLOCKED", "code": "STACK_BASE_NOT_TARGET",
                "reason": "يعتمد الطلب على فرع غير " + target + "؛ يلزم اعتماد الأساس ثم إعادة استهداف الطلب وفحصه"})
            if state == UNKNOWN:
                pr["missing_evidence"].append({"field": "dependencies", "code": "PARENT_MISSING_OR_AMBIGUOUS"})
        if collection_gaps:
            pr["blockers"].append({"classification": "MANUAL_ACCEPTANCE_REQUIRED", "code": "INCOMPLETE_INVENTORY",
                "reason": "قائمة الطلبات أو هوية الحساب غير مكتملة أو تغيرت أثناء الفحص"})
        categories = {b["classification"] for b in pr["blockers"]}
        pr["classifications"] = [c for c in CLASSIFICATIONS if c in categories] or ["READY_FOR_FINAL_REVIEW"]
    chains = []
    for pr in prs:
        path, seen, node = [pr["number"]], {pr["number"]}, pr
        while len(node["dependencies"]["parents"]) == 1:
            parent_id = node["dependencies"]["parents"][0]
            if parent_id in seen:
                pr["dependencies"]["state"] = UNKNOWN
                pr["missing_evidence"].append({"field": "dependencies", "code": "CYCLE"})
                break
            seen.add(parent_id)
            path.insert(0, parent_id)
            node = ids[parent_id]
        pr["dependencies"]["ancestors"] = path[:-1]
        pr["dependencies"]["ancestor_blockers"] = [{"number": i, "classifications": ids[i]["classifications"]} for i in path[:-1]]
        if len(path) > 1 and path not in chains:
            chains.append(path)
    chains = [p for p in chains if not any(len(q) > len(p) and q[:len(p)] == p for q in chains)]
    # Kahn ordering: always parents first, then high-impact security/root work.
    remaining, order = set(ids), []
    while remaining:
        candidates = [ids[n] for n in remaining if not set(ids[n]["dependencies"]["parents"]) & remaining]
        if not candidates:
            candidates = [ids[n] for n in remaining]
        candidates.sort(key=lambda p: ("SECURITY_REVIEW_REQUIRED" not in p["classifications"],
            -sum(p["number"] in other["dependencies"]["ancestors"] for other in prs), p["number"]))
        number = candidates[0]["number"]
        order.append(number)
        remaining.remove(number)
    for pr in prs:
        pr["suggested_review_priority"] = order.index(pr["number"]) + 1 if pr["number"] in order else UNKNOWN
    counts = Counter(c for pr in prs for c in pr["classifications"])
    partial = bool(collection_gaps or any(pr["missing_evidence"] for pr in prs))
    return clean({"schema_version": 1, "repo": repo, "target_branch": target,
        "mode": snapshot.get("mode", "LIVE_READ_ONLY"), "captured_at": snapshot.get("captured_at", UNKNOWN),
        "finished_at": snapshot.get("finished_at", UNKNOWN), "request_count": snapshot.get("request_count", UNKNOWN),
        "collection_state": "PARTIAL" if partial else "COMPLETE", "collection_gaps": collection_gaps,
        "summary": {"total": len(prs), "by_classification": dict(counts),
            "ready_for_final_review": counts["READY_FOR_FINAL_REVIEW"], "all_ready": bool(prs) and not partial and counts["READY_FOR_FINAL_REVIEW"] == len(prs)},
        "dependency_chains": chains, "suggested_review_order": order, "pull_requests": prs,
        "limitations": ["تقرير نقطة زمنية وليس تصريح دمج أو مراجعة للشيفرة",
            "موافقة مستقلة واحدة على الأقل سياسة للمدقق، حتى إذا كانت إعدادات المستودع تتطلب صفرًا",
            "رصد الكلمات الأمنية إشارة للمراجعة وقد يشمل ملاحظات تاريخية أو نفيًا لوجود ثغرة",
            "لا تُثبت فحوص Windows أو VM قبول الأجهزة الفعلية؛ لم تُشغّل اختبارات أجهزة",
            "تغير التعليقات أو قواعد الحماية أثناء الفحص قد لا يُكتشف؛ أعد الفحص قبل القرار النهائي"]})
