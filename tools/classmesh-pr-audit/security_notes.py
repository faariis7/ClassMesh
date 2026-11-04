"""Classify evidence, not prose sentiment. Resolution is a GitHub state."""
from datetime import datetime

from github_source import is_known
from policy import SECURITY_WORDS, obj, url, valid_sha


def timestamp(value):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date if date.utcoffset() is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def assess_security(entry, pr, snapshot):
    notes = []
    head = obj(obj(entry.get("head_commit")).get("data"))
    committed = timestamp(obj(head.get("committer")).get("date") or obj(obj(head.get("commit")).get("committer")).get("date"))
    captured = timestamp(snapshot.get("captured_at"))
    if (not is_known(entry.get("head_commit")) or head.get("sha") != pr["head_sha"]
            or committed is None or captured is None or committed > captured):
        committed = None

    def note(kind, classification, reason, source_url, body="", **extra):
        notes.append({"source": kind, "classification": classification, "reason": reason,
                      "url": url(source_url), "excerpt": body[:1200], **extra})

    def prose(kind, item, link_key="html_url", forced=None):
        body = obj(item).get("body")
        if not isinstance(body, str) or not SECURITY_WORDS.search(body):
            return
        link = url(item.get(link_key))
        date = timestamp(item.get("created_at") or item.get("createdAt") or item.get("submitted_at"))
        edited = item.get("updated_at") or item.get("updatedAt")
        if edited is not None:
            updated = timestamp(edited)
            date = max(date, updated) if date is not None and updated is not None else None
        classification, reason = forced or ("REVIEW_REQUIRED", "إشارة نصية فقط؛ يلزم تقييم بشري، ولا تثبت ثغرة")
        if forced is None and date is not None and committed is not None and date < committed:
            classification, reason = "HISTORICAL_NOTE", "تاريخ الملاحظة يسبق تاريخ HEAD المسجل؛ لا يعني أنها حُلت"
        if link == "UNKNOWN":
            classification, reason = "UNKNOWN", "رابط مصدر الملاحظة غير متاح أو غير موثوق"
        note(kind, classification, reason, link, body)

    detail = obj(obj(entry.get("detail")).get("data"))
    prose("PR_BODY", detail)
    comments = entry.get("comments")
    if is_known(comments) and isinstance(comments["data"], list):
        for item in comments["data"]:
            prose("COMMENT", item)
    else:
        note("COMMENTS", "UNKNOWN", "بيانات التعليقات غير متاحة", pr["url"])
    threads = obj(obj(entry.get("threads")).get("data")).get("threads")
    if is_known(entry.get("threads")) and isinstance(threads, list):
        for thread in threads:
            if not isinstance(thread, dict) or not isinstance(thread.get("comments"), list):
                note("THREAD", "UNKNOWN", "خيط مراجعة غير صالح", pr["url"])
                continue
            state = thread.get("isResolved")
            forced = ("RESOLVED", "GitHub يسجل الخيط محسومًا؛ هذا لا يثبت اختبارًا ماديًا") if state is True else (
                "REVIEW_REQUIRED", "الخيط مفتوح لدى GitHub؛ قدم الأسطر أو عبارة resolved لا يحسمانه") if state is False else (
                "UNKNOWN", "حالة حسم الخيط غير معروفة")
            for comment in thread["comments"]:
                prose("REVIEW_THREAD", comment, "url", forced)
    else:
        note("THREADS", "UNKNOWN", "حالة خيوط المراجعة غير متاحة", pr["url"])
    reviews = obj(entry.get("reviews")).get("data", [])
    viewer = obj(snapshot.get("viewer")).get("data")
    excluded = {str(obj(detail.get("user")).get("login", "")).casefold(), str(viewer).casefold(), snapshot["repo"].split("/")[0].casefold()}
    if is_known(entry.get("reviews")) and isinstance(reviews, list):
        latest = {}
        for review in sorted((r for r in reviews if isinstance(r, dict)), key=lambda r: (str(r.get("submitted_at", "")), str(r.get("id", "")))):
            login = obj(review.get("user")).get("login")
            if isinstance(login, str) and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                latest[login.casefold()] = review
        for review in reviews:
            if not isinstance(review, dict):
                continue
            login = str(obj(review.get("user")).get("login", ""))
            permission = obj(entry.get("permissions")).get(login)
            forced = None
            if review.get("state") == "CHANGES_REQUESTED":
                current = latest.get(login.casefold())
                if current is not review and obj(current).get("state") in ("APPROVED", "DISMISSED"):
                    forced = ("RESOLVED", "رأي أحدث من المراجع نفسه أزال طلب التغييرات المسجل")
                elif (review.get("commit_id") == pr["head_sha"] and login.casefold() not in excluded
                      and obj(review.get("user")).get("type") == "User" and is_known(permission)
                      and permission["data"] in ("write", "maintain", "admin")):
                    forced = ("CONFIRMED_BLOCKER", "طلب تغييرات أمني مستقل على HEAD الحالي؛ يؤكد عائق المراجعة وليس إثبات استغلال")
                else:
                    forced = ("REVIEW_REQUIRED", "طلب تغييرات لم يثبت رفعه أو استقلاله على HEAD الحالي")
            prose("REVIEW", review, forced=forced)
    alerts = entry.get("code_scanning")
    if not is_known(alerts) or not isinstance(alerts["data"], list):
        note("CODE_SCANNING", "UNKNOWN", "صلاحيات أو بيانات الفحص الأمني غير متاحة", pr["url"])
    else:
        for alert in alerts["data"]:
            if not isinstance(alert, dict):
                note("CODE_SCANNING", "UNKNOWN", "تنبيه غير صالح", pr["url"])
                continue
            sha = obj(alert.get("most_recent_instance")).get("commit_sha")
            current = sha in (pr["head_sha"], detail.get("merge_commit_sha")) and valid_sha(sha)
            state = alert.get("state")
            classification = "RESOLVED" if state in ("fixed", "dismissed") else "CONFIRMED_BLOCKER" if state == "open" and current else "UNKNOWN"
            if url(alert.get("html_url")) == "UNKNOWN":
                classification = "UNKNOWN"
            note("CODE_SCANNING", classification, "حالة GitHub وربط التنبيه بالنسخة الحالية؛ الربط المفقود لا يُخمن",
                 alert.get("html_url"), number=alert.get("number", "UNKNOWN"), observed_commit_sha=sha or "UNKNOWN")
    invalid_sources = [g["field"] for g in pr["missing_evidence"] if g["field"] in
                       ("comments", "reviews", "threads", "files", "code_scanning")]
    if invalid_sources:
        note("API_SOURCE", "UNKNOWN", "مصادر التقييم غير مكتملة أو غير صالحة: " + ", ".join(invalid_sources), pr["url"])
    states = {n["classification"] for n in notes}
    incomplete = any(pr["ci"][name]["state"] != "SUCCESS" for name in ("CodeQL", "Gitleaks"))
    assessment = next((s for s in ("CONFIRMED_BLOCKER", "UNKNOWN", "REVIEW_REQUIRED") if s in states), None)
    assessment = assessment or ("REVIEW_REQUIRED" if pr["security"]["sensitive_paths"] or incomplete else "CLEAR")
    return {**pr["security"], "notes": notes, "assessment": assessment,
            "state": "REVIEW_REQUIRED" if assessment != "CLEAR" else "NO_REPORTED_FINDINGS",
            "confirmed_blockers": sum(n["classification"] == "CONFIRMED_BLOCKER" for n in notes)}
