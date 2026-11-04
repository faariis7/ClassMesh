"""Concise Arabic decision report; detailed evidence remains in JSON."""
import html


def md(value):
    return html.escape(str(value), quote=True).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\n", " ").replace("\r", " ")


def render(report):
    summary = report["summary"]
    lines = ["# ClassMesh — ملخص تنفيذي لجاهزية طلبات الدمج", "",
        f"**{md(report['mode'])}** · جمع الأدلة: **{report['collection_state']}** · {md(report['repo'])}", "",
        f"الفترة: {md(report['captured_at'])} — {md(report['finished_at'])}. الهدف: {md(report['target_branch'])}.", "",
        "هذا دعم للقرار فقط؛ حتى READY_FOR_MERGE ليست إذن دمج. القرار النهائي لقائد التنسيق.", "",
        "| المؤشر | عدد PRs |", "| --- | ---: |"]
    for label, key in [("الإجمالي", "total"), ("جاهزة للمراجعة المستقلة", "ready_for_independent_review"),
        ("جاهزة للمراجعة النهائية", "ready_for_final_review"), ("مرشحة للدمج وفق الأدلة", "merge_candidates"),
        ("محجوبة", "blocked"), ("فشل CI", "ci_failed"), ("عوائق أمان مؤكدة", "confirmed_security_blockers"),
        ("لديها أدلة ناقصة", "missing_evidence")]:
        lines.append(f"| {label} | {summary[key]} |")
    lines += ["", "الأعداد متداخلة. UNKNOWN في شرط إلزامي يمنع جاهزية الدمج.", "", "## أهم خمسة إجراءات تالية", ""]
    for action in summary["top_actions"]:
        lines.append(f"{action['priority']['rank']}. **#{action['number']} — {action['next_action']}**: {md(action['action_reason'])} · المسؤول المقترح: **{action['suggested_owner']}** · يفتح {action['priority']['dependent_count']} طلبات.")
    if not summary["top_actions"]:
        lines.append("لا توجد إجراءات قابلة للاستخراج؛ تحقق من اكتمال جرد الطلبات.")
    if report["collection_gaps"]:
        lines += ["", "**جرد غير مكتمل أو متغير:** " + "؛ ".join(md(g["field"] + ": " + g["code"]) for g in report["collection_gaps"])]
    if "collection_diagnostics" in report:
        inventory = report["collection_diagnostics"].get("inventory", {})
        before, after = inventory.get("before", {}), inventory.get("after", {})
        lines += ["", "## ثبات الجرد وأداء الجمع", "",
            "الجرد الأول: **" + md(before.get("state", "UNKNOWN")) + "** · الجرد الأخير: **" + md(after.get("state", "UNKNOWN")) + "**.",
            "طلبات أضيفت: " + md(inventory.get("added", [])) + " · طلبات خرجت من الجرد: " + md(inventory.get("removed", [])) + "."]
        for label, observation in (("الأول", before), ("الأخير", after)):
            if observation.get("error"):
                lines.append("سبب تعذر الجرد " + label + ": " + md(observation["error"]))
        lines.append("ثبات القائمة لا يعني اكتمال أدلة كل طلب؛ التغيّرات المحلية موضحة تحته. الملاحظات متتابعة وليست معاملة ذرية.")
    if "collection_metrics" in report:
        metrics = report["collection_metrics"]
        lines += ["", "استدعاءات API: **" + md(metrics.get("requests", "UNKNOWN")) + "** · الزمن: **"
                  + md(metrics.get("wall_seconds", "UNKNOWN")) + " ثانية**.", "",
                  "| نوع البيانات | الاستدعاءات | ثوانٍ | محاولات لم تُرسل |", "| --- | ---: | ---: | ---: |"]
        for category, metric in metrics.get("by_category", {}).items():
            lines.append("| " + " | ".join(md(v) for v in (category, metric["requests"], metric["seconds"], metric["skipped"])) + " |")
    lines += ["", "## ترتيب التبعيات", "",
        "الأصل يسبق التابع في خطة المعالجة: `" + " → ".join("#" + str(n) for n in report["suggested_review_order"]) + "`", ""]
    lines += ["- `" + " → ".join("#" + str(n) for n in chain) + "`" for chain in report["dependency_chains"]]
    if report["dependency_cycles"]:
        lines += ["", "**دورات تمنع ترتيبًا صالحًا:** " + md(report["dependency_cycles"])]
    for pr in sorted(report["pull_requests"], key=lambda p: p["priority"]["rank"] if type(p["priority"]["rank"]) is int else float("inf")):
        lines += ["", f"## #{pr['number']} — {md(pr['title'])}", "", md(pr["url"]), "",
            f"**الحالة: {pr['readiness_stage']}** · التفاصيل: " + "، ".join(pr["classifications"]), "",
            f"**الإجراء التالي: {pr['next_action']}** — {md(pr['action_reason'])}", "",
            f"المسؤول المقترح: **{pr['suggested_owner']}** · أولوية {pr['priority']['rank']} ({pr['priority']['score']} نقطة، {pr['priority']['level']}).", "",
            "سبب الأولوية: " + "؛ ".join(md(s) for s in pr["priority"]["reasons"]), "",
            f"التبعيات: **{pr['dependencies']['state']}** · الطلبات الحاجبة: {md(pr['blocking_prs'])} · آباء مجهولون: {md(pr['dependencies']['unknown_parents'])}.", "",
            "يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **" + ("نعم" if pr["can_proceed_without_dependencies"] else "لا") + "**؛ لا يعني ذلك إمكانية دمج التابع.", "",
            f"HEAD: `{md(pr['head_sha'])}` · Base: {md(pr['base_branch'])} `{md(pr['base_branch_sha'])}`.", "",
            f"أدلة الأساس: **{pr['base_validation']['state']}** — {md(pr['base_validation']['reason'])}", "",
            "| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |", "| --- | --- | --- | --- |"]
        for name, gate in pr["ci"].items():
            links = " · ".join(item["url"] for item in gate["evidence"] if item["url"] != "UNKNOWN") or "UNKNOWN"
            scope = pr["base_validation"]["gates"].get(name, {}).get("state", "UNKNOWN")
            lines.append(f"| {md(name)} | {gate['state']} | {scope} | {md(links)} |")
        lines += ["", "**العوائق:**", ""]
        lines += ["- " + md(b["reason"]) + " (`" + md(b["code"]) + "`)" for b in pr["blockers"]] or ["لا توجد عوائق مسجلة ضمن نطاق الأدلة."]
        if "stability" in pr:
            lines += ["", "**ثبات الأدلة أثناء الجمع:** " + "؛ ".join(
                md(key) + ": " + md(value.get("error", {}).get("code", value.get("eligibility", value.get("state", "UNKNOWN"))))
                for key, value in pr["stability"].items())]
        reviews = pr["reviews"]
        lines += ["", f"موافقات مستقلة: {len(reviews['independent_approvals'])}/{reviews['auditor_required_independent_approvals']} · قرار GitHub: {reviews['github_review_decision']} · خيوط مفتوحة: {len(reviews['unresolved_threads'])}.", "",
            "القبول اليدوي/الأجهزة: **" + pr["manual_acceptance"]["state"] + "** — " + md(pr["manual_acceptance"]["reason"])]
        if pr["security"]["notes"]:
            lines += ["", "**الملاحظات الأمنية ومصادرها:**", ""]
            lines += [f"- **{n['classification']}**: {md(n['reason'])} · {md(n['url'])}" for n in pr["security"]["notes"]]
        if reviews["recorded"]:
            lines += ["", "**أدلة المراجعات:**", ""]
            lines += [f"- {md(r['reviewer'])}: {r['state']} · {md(r['url'])}" for r in reviews["recorded"]]
        if pr["required_evidence"]:
            lines += ["", "**الأدلة والإجراءات المتبقية:**", ""]
            lines += [f"- {md(e['condition'])}: **{e['state']}** — {md(e['description'])}" for e in pr["required_evidence"]]
    if "comparison" in report:
        lines += ["", "## مقارنة V1 وV2 على Snapshot واحدة", "", "SHA256: `" + report["comparison"]["snapshot_sha256"] + "`", "",
            "| PR | تصنيفات V1 | مرحلة V2 | الإجراء |", "| --- | --- | --- | --- |"]
        for pr in report["comparison"]["pull_requests"]:
            lines.append(f"| #{pr['number']} | {', '.join(pr['v1_classifications'])} | {pr['v2_stage']} | {pr['next_action']} |")
    lines += ["", "## حدود الإثبات", ""] + ["- " + md(s) for s in report["limitations"]]
    return "\n".join(lines) + "\n"
