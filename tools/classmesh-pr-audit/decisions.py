"""V2 decision support layered on the V1 evidence evaluator."""
from collections import Counter

from dependencies import build_dependencies, prioritize
from execution_evidence import validate_base
from policy import analyze, clean, obj
from security_notes import assess_security

STAGES = ("READY_FOR_INDEPENDENT_REVIEW", "READY_FOR_FINAL_REVIEW", "READY_FOR_MERGE", "BLOCKED", "UNKNOWN")
REVIEW_CODES = {"INDEPENDENT_APPROVAL_MISSING", "REQUIRED_REVIEW_UNSATISFIED", "SECURITY_EVIDENCE_REVIEW"}


def condition(name, state, reason):
    return {"name": name, "state": state, "required": True, "reason": reason}


def enrich(pr, entry, snapshot, collection_gaps):
    pr["merge_authorized"] = False
    pr["base_validation"] = validate_base(entry, pr)
    pr["security"] = assess_security(entry, pr, snapshot)
    # Re-evaluate these V1 aggregate decisions using V2's finer evidence states.
    pr["blockers"] = [b for b in pr["blockers"] if b["code"] not in (
        "SECURITY_EVIDENCE_REVIEW", "STACK_BASE_NOT_TARGET", "UNKNOWN_EVIDENCE")]
    pr["missing_evidence"] = [g for g in pr["missing_evidence"] if g["field"] != "dependencies"]

    def block(category, code, reason):
        pr["blockers"].append({"classification": category, "code": code, "reason": reason})

    def gap(field, code):
        item = {"field": field, "code": code}
        if item not in pr["missing_evidence"]:
            pr["missing_evidence"].append(item)

    base = pr["base_validation"]
    if base["state"] not in ("INTEGRATION_CURRENT", "HEAD_ONLY"):
        block("BASE_REVALIDATION_REQUIRED", "BASE_REVALIDATION_REQUIRED", base["reason"])
        if base["state"] != "INTEGRATION_STALE":
            gap("base_validation", base["state"])
    security = pr["security"]["assessment"]
    if security != "CLEAR":
        block("SECURITY_REVIEW_REQUIRED", "SECURITY_EVIDENCE_REVIEW",
              "مراجعة أمنية مستقلة مطلوبة؛ نوع الدليل: " + security)
        if security == "UNKNOWN":
            gap("security", "UNKNOWN_SECURITY_EVIDENCE")
    deps = pr["dependencies"]
    if deps["state"] != "CLEAR":
        block("DEPENDENCY_BLOCKED", "DEPENDENCIES_" + deps["state"],
              "يلزم معالجة الآباء ثم تحديث التابع وإعادة فحصه؛ " + deps["state"])
        if deps["unknown_parents"]:
            gap("dependencies", "UNKNOWN_PARENTS")
    branch_policy = obj(pr["branch_policy"])
    if type(branch_policy.get("strict_checks")) is not bool:
        gap("branch_policy.strict_checks", "UNKNOWN")
    if branch_policy.get("unsupported_rules"):
        gap("branch_policy.additional_rules", "UNVERIFIED_RULES")
    # GitHub may report 'blocked' solely because reviews are outstanding.
    review_decision = pr["reviews"]["github_review_decision"]
    if branch_policy.get("required_approvals", 0) > 0 and review_decision not in ("APPROVED", "REVIEW_REQUIRED", "CHANGES_REQUESTED"):
        gap("reviews.github_review_decision", "UNKNOWN")
    explained = pr["mergeable_state"] == "blocked" and review_decision == "REVIEW_REQUIRED"
    if explained:
        pr["blockers"] = [b for b in pr["blockers"] if b["code"] != "MERGE_STATE_BLOCKED"]
    elif pr["mergeable_state"] not in ("clean", "dirty"):
        gap("mergeable_state", str(pr["mergeable_state"]))
    for item in collection_gaps:
        gap("collection." + item["field"], item["code"])
    if pr["missing_evidence"]:
        block("MANUAL_ACCEPTANCE_REQUIRED", "UNKNOWN_EVIDENCE", "شروط ضرورية غير معروفة؛ لا يمكن إعلان جاهزية الدمج")
    categories = {b["classification"] for b in pr["blockers"]}
    pr["classifications"] = sorted(categories)
    technical = []
    for b in pr["blockers"]:
        category, code = b["classification"], b["code"]
        if (category in ("DRAFT", "MERGE_CONFLICT", "CI_FAILED")
                or category == "CI_PENDING" and any(g["state"] == "PENDING" for g in pr["ci"].values())
                or category == "DEPENDENCY_BLOCKED" and (deps["parents"] or deps["closed_unmerged_parents"] or deps["state"] == "CYCLE")
                or code.startswith("CHANGES_REQUESTED:") or code == "UNRESOLVED_THREADS"
                or code == "REQUIRED_REVIEW_UNSATISFIED" and review_decision == "CHANGES_REQUESTED"
                or code == "BASE_REVALIDATION_REQUIRED" and base["state"] == "INTEGRATION_STALE"
                or code == "SECURITY_EVIDENCE_REVIEW" and security == "CONFIRMED_BLOCKER"):
            technical.append(b)
    pr["technical_blockers"] = technical
    review_missing = any(b["code"] in REVIEW_CODES for b in pr["blockers"])
    independent = pr["reviews"]["independent_approvals"]
    if technical:
        stage = "BLOCKED"
    elif pr["missing_evidence"]:
        stage = "UNKNOWN"
    elif review_missing:
        stage = "READY_FOR_FINAL_REVIEW" if independent else "READY_FOR_INDEPENDENT_REVIEW"
    elif pr["blockers"]:
        stage = "UNKNOWN"
    else:
        stage = "READY_FOR_MERGE"
    pr["readiness_stage"] = stage
    if not pr["classifications"]:
        pr["classifications"] = [stage]
    ci_states = [g["state"] for g in pr["ci"].values()]
    review_state = "SATISFIED"
    if pr["reviews"]["state"] == "UNKNOWN" or not branch_policy:
        review_state = "UNKNOWN"
    elif review_decision == "CHANGES_REQUESTED" or any(b["code"].startswith("CHANGES_REQUESTED:") for b in pr["blockers"]):
        review_state = "UNSATISFIED"
    elif any(b["code"] in REVIEW_CODES - {"SECURITY_EVIDENCE_REVIEW"} for b in pr["blockers"]):
        review_state = "REVIEW_REQUIRED"
    merge_state = "SATISFIED"
    if (type(pr["draft"]) is not bool or type(pr["mergeable"]) is not bool or pr["reviews"]["state"] == "UNKNOWN"
            or pr["mergeable_state"] not in ("clean", "dirty") and not explained):
        merge_state = "UNKNOWN"
    elif pr["draft"] or not pr["mergeable"] or pr["reviews"]["unresolved_threads"]:
        merge_state = "UNSATISFIED"
    conditions = [condition("ci", "SATISFIED" if all(s == "SUCCESS" for s in ci_states) else "UNKNOWN" if "UNKNOWN" in ci_states else "UNSATISFIED", "كل فحص إلزامي مرتبط بـHEAD وتشغيله الحالي"),
        condition("base", "SATISFIED" if base["state"] in ("HEAD_ONLY", "INTEGRATION_CURRENT") else "UNSATISFIED" if base["state"] == "INTEGRATION_STALE" else "UNKNOWN", base["reason"]),
        condition("independent_reviews", review_state, "APPROVED مستقلة وحديثة؛ COMMENTED وصاحب الحساب لا يُحتسبان"),
        condition("security", "SATISFIED" if security == "CLEAR" else "UNSATISFIED" if security == "CONFIRMED_BLOCKER" else security, "الأمن: " + security),
        condition("dependencies", "SATISFIED" if deps["state"] == "CLEAR" else "UNKNOWN" if deps["state"] == "UNKNOWN" else "UNSATISFIED", "الأصل قبل التابع"),
        condition("manual_acceptance", "SATISFIED" if pr["manual_acceptance"]["state"] == "NOT_APPLICABLE" else "UNKNOWN", pr["manual_acceptance"]["reason"]),
        condition("merge_and_threads", merge_state, "Draft والتعارض والخيوط المفتوحة تمنع التقدم"),
        condition("evidence_completeness", "UNKNOWN" if pr["missing_evidence"] else "SATISFIED", "يشمل قواعد الحماية وثبات جمع البيانات والصلاحيات")]
    pr["conditions"] = conditions
    pr["required_evidence"] = [{"condition": c["name"], "state": c["state"], "description": c["reason"]} for c in conditions if c["state"] != "SATISFIED"]
    pr["required_evidence"] += [{"condition": g["field"], "state": "UNKNOWN", "description": g["code"]} for g in pr["missing_evidence"]]
    choose_action(pr)


def choose_action(pr):
    categories = set(pr["classifications"])
    codes = {b["code"] for b in pr["blockers"]}
    stage = pr["readiness_stage"]
    options = [
        (pr["security"]["confirmed_blockers"] > 0, "REQUEST_SECURITY_REVIEW", "عائق أمني مسجل على النسخة الحالية؛ اطلب تقييمًا مستقلًا قبل التقدم", "COORDINATION_LEAD"),
        ("CI_FAILED" in categories, "FIX_FAILED_CI", "حلل سجل الوظيفة الفاشلة وأصلح السبب ثم اختبر HEAD الجديد", "BRANCH_DEVELOPER"),
        ("MERGE_CONFLICT" in categories, "RESOLVE_CONFLICT", "حل تعارض الأساس في الفرع المسؤول وأعد جميع الفحوص", "BRANCH_DEVELOPER"),
        (pr["reviews"]["github_review_decision"] == "CHANGES_REQUESTED" or any(c.startswith("CHANGES_REQUESTED:") for c in codes) or "UNRESOLVED_THREADS" in codes, "RESOLVE_REVIEW_THREADS", "عالج طلبات المراجعة واحصل على حسم موثق للخيوط", "BRANCH_DEVELOPER"),
        (pr["dependencies"]["state"] != "CLEAR", "WAIT_FOR_DEPENDENCIES", "عالج الأصل أو الدورة أو الأب المجهول أولًا، ثم حدّث التابع وأعد فحصه", "COORDINATION_LEAD"),
        (pr["base_validation"]["state"] == "INTEGRATION_STALE", "REVALIDATE_BASE", "اختبر نسخة تكامل مع الأساس الحالي؛ مجرد إعادة تشغيل النسخة القديمة لا يكفي", "BRANCH_DEVELOPER"),
        ("DRAFT" in categories, "FINISH_DRAFT", "أكمل نطاق الطلب ثم اعرضه للمراجعة", "BRANCH_DEVELOPER"),
        (any(g["state"] == "PENDING" for g in pr["ci"].values()), "WAIT_FOR_CI", "انتظر الوظائف الجارية ثم اجمع الأدلة مجددًا دون تشغيل Workflow من المدقق", "BRANCH_DEVELOPER"),
        (bool(pr["missing_evidence"]), "COLLECT_MISSING_EVIDENCE", "استكمل البيانات المحددة في required_evidence؛ UNKNOWN يمنع جاهزية الدمج", "COORDINATION_LEAD"),
        (pr["security"]["assessment"] == "REVIEW_REQUIRED", "REQUEST_SECURITY_REVIEW", "اطلب مراجعة أمنية مستقلة للإشارات وحدود التغيير؛ الكلمات وحدها لا تثبت ثغرة", "COORDINATION_LEAD"),
        (stage == "READY_FOR_INDEPENDENT_REVIEW", "REQUEST_INDEPENDENT_REVIEW", "اكتملت المتطلبات الآلية؛ يلزم مراجع مستقل مخول على HEAD الحالي", "INDEPENDENT_REVIEWER"),
        (stage == "READY_FOR_FINAL_REVIEW", "COMPLETE_FINAL_REVIEW", "استكمل العدد والشروط المسجلة للموافقات النهائية", "INDEPENDENT_REVIEWER"),
        (stage == "READY_FOR_MERGE", "COORDINATOR_MERGE_DECISION", "الشروط المسجلة القابلة للتحقق مستوفاة؛ أعد التحقق ثم اترك القرار لقائد التنسيق", "COORDINATION_LEAD"),
    ]
    _, action, reason, owner = next((o for o in options if o[0]), (True, "COLLECT_MISSING_EVIDENCE", "تحتاج الحالة إلى حسم بشري موثق", "UNASSIGNED"))
    pr.update(next_action=action, action_reason=reason, suggested_owner=owner,
              can_proceed_without_dependencies=action != "WAIT_FOR_DEPENDENCIES")


def analyze_v2(snapshot):
    report = analyze(snapshot)
    prs = report["pull_requests"]
    entries = [obj(e) for e in snapshot["pulls"]]
    cycles = build_dependencies(prs, entries, report["repo"], report["target_branch"])
    for pr, entry in zip(prs, entries):
        enrich(pr, entry, snapshot, report["collection_gaps"])
    order, chains, unsortable = prioritize(prs)
    counts = Counter(pr["readiness_stage"] for pr in prs)
    categories = Counter(c for pr in prs for c in pr["classifications"])
    partial = bool(report["collection_gaps"] or any(p["missing_evidence"] for p in prs))
    ranked = sorted(prs, key=lambda p: p["priority"]["rank"] if type(p["priority"]["rank"]) is int else float("inf"))
    report.update(schema_version=2, collection_state="PARTIAL" if partial else "COMPLETE",
        dependency_cycles=cycles, dependency_order_unresolved=unsortable,
        dependency_chains=chains, suggested_review_order=order,
        summary={"total": len(prs), "by_stage": {s: counts[s] for s in STAGES}, "by_classification": dict(categories),
            "ready_for_independent_review": counts["READY_FOR_INDEPENDENT_REVIEW"],
            "ready_for_final_review": counts["READY_FOR_FINAL_REVIEW"], "merge_candidates": counts["READY_FOR_MERGE"],
            "blocked": counts["BLOCKED"], "ci_failed": categories["CI_FAILED"],
            "confirmed_security_blockers": sum(p["security"]["confirmed_blockers"] > 0 for p in prs),
            "missing_evidence": sum(bool(p["missing_evidence"]) for p in prs),
            "all_ready": bool(prs) and not partial and counts["READY_FOR_MERGE"] == len(prs),
            "top_actions": [{k: p[k] for k in ("number", "next_action", "action_reason", "suggested_owner", "priority")} for p in ranked[:5]]})
    report["limitations"] = [
        "تقرير نقطة زمنية لدعم القرار؛ READY_FOR_MERGE لا يمنح إذن الدمج، والقرار لقائد التنسيق",
        "موافقة مستقلة واحدة على الأقل على HEAD الحالي؛ لا تُحتسب موافقة صاحب PR أو الحساب المستخدم أو مالك المستودع",
        "سجلات checkout وآباء commit أدلة تنفيذ GitHub؛ ليست تصديقًا تشفيريًا أو إثبات كفاية الاختبارات، ويمكن لمؤلف Workflow التأثير في السجلات",
        "HEAD_ONLY يثبت checkout لرأس الفرع فقط؛ لا يدعي اختبار دمجه مع أحدث أساس",
        "الاختبارات وWindows CI وVM لا تثبت قبول الأجهزة الفعلية؛ الأدلة المادية وقواعد الحماية غير المدعومة تبقى UNKNOWN",
        "الملاحظة التاريخية لم تُثبت محلولة؛ RESOLVED يصف حالة GitHub المسجلة فقط",
        "المالكون المقترحون أدوار لا تكليفات فعلية؛ حجم العمل تقدير بعدد الشروط وليس بساعات",
        "تغير التعليقات والمراجعات والسياسات أثناء الجمع قد لا يُكتشف؛ أعد الفحص قبل القرار النهائي"]
    return clean(report)
