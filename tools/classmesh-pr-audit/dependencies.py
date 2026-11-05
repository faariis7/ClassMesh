"""Branch identity and explicit declarations; never infer edges from mentions."""
from execution_evidence import declared_dependencies
from github_source import is_known
from policy import obj


def build_dependencies(prs, entries, repo, target):
    ids = {p["number"]: p for p in prs if type(p["number"]) is int}
    branches = {}
    for pr in prs:
        branches.setdefault((pr["head_repo"].casefold(), pr["head_branch"]), []).append(pr["number"])
    for pr, entry in zip(prs, entries):
        parents, unknowns, closed, cleared, reasons = set(), [], [], [], []
        base_is_target = pr["base_branch"] == target and pr["base_repo"].casefold() == repo.casefold()
        if not base_is_target:
            matches = branches.get((pr["base_repo"].casefold(), pr["base_branch"]), [])
            parents.update(n for n in matches if type(n) is int)
            if len(matches) != 1:
                unknowns.append("BASE_BRANCH:" + pr["base_branch"])
                reasons.append("PARENT_MISSING_OR_AMBIGUOUS")
        declared = declared_dependencies(obj(obj(entry.get("detail")).get("data")).get("body"))
        if len(declared) > 32:
            unknowns.append("DECLARATION_LIMIT")
            reasons.append("DEPENDENCY_LIMIT_EXCEEDED")
        for number in declared[:32]:
            if number in ids:
                parents.add(number)
                continue
            value = obj(entry.get("dependency_details")).get(str(number))
            data = obj(obj(value).get("data"))
            base = obj(data.get("base"))
            if (is_known(value) and data.get("number") == number and data.get("state") == "closed"
                    and data.get("merged") is True and base.get("ref") == target
                    and obj(base.get("repo")).get("full_name", "").casefold() == repo.casefold()):
                cleared.append(number)
            elif is_known(value) and data.get("number") == number and data.get("state") == "closed" and data.get("merged") is False:
                closed.append(number)
            else:
                unknowns.append(number)
        state = "UNKNOWN" if unknowns else "BLOCKED" if parents or closed or not base_is_target else "CLEAR"
        pr["dependencies"] = {"state": state, "parents": sorted(parents), "declared": declared,
            "unknown_parents": unknowns, "closed_unmerged_parents": closed, "merged_parents": cleared,
            "ancestors": [], "ancestor_blockers": [], "reasons": reasons}
    # Bounded iterative reachability avoids recursion limits and counts a diamond
    # only once. Every member of a cycle can reach itself.
    cycles = []
    for pr in prs:
        reachable, todo = set(), list(pr["dependencies"]["parents"])
        while todo:
            node = todo.pop()
            if node in reachable or node not in ids:
                continue
            reachable.add(node)
            todo.extend(ids[node]["dependencies"]["parents"])
        pr["dependencies"]["ancestors"] = sorted(reachable - {pr["number"]})
        if pr["number"] in reachable:
            pr["dependencies"]["state"] = "CYCLE"
            pr["dependencies"]["reasons"].append("CYCLE")
            cycles.append(pr["number"])
        pr["blocking_prs"] = sorted((reachable - {pr["number"]}) | set(pr["dependencies"]["closed_unmerged_parents"]))
    return sorted(cycles)


def prioritize(prs):
    ids = {p["number"]: p for p in prs if type(p["number"]) is int}
    for pr in prs:
        dependent_count = sum(pr["number"] in p["dependencies"]["ancestors"] for p in prs)
        unmet = sum(c["state"] != "SATISFIED" for c in pr["conditions"])
        unknown = sum(c["state"] == "UNKNOWN" for c in pr["conditions"])
        factors = {"dependents": dependent_count * 12,
            "confirmed_security": 50 if pr["security"]["confirmed_blockers"] else 0,
            "ci_failure": 15 if "CI_FAILED" in pr["classifications"] else 0,
            "tests_complete": 20 if all(g["state"] == "SUCCESS" for g in pr["ci"].values()) else 0,
            "remaining_conditions": max(0, 10 - unmet * 2),
            "multiple_dependencies": -3 * max(0, len(pr["dependencies"]["parents"]) - 1),
            "missing_evidence": -4 * unknown}
        score = sum(factors.values())
        pr["priority"] = {"score": score, "rank": "UNKNOWN", "level": "HIGH" if score >= 40 else "NORMAL",
            "dependent_count": dependent_count, "remaining_condition_count": unmet, "factors": factors,
            "reasons": [f"يفتح معالجة {dependent_count} طلبات تابعة (مباشرة وغير مباشرة)",
                f"شروط متبقية: {unmet}؛ منها غير معروف: {unknown}",
                "الدرجات: " + "، ".join(f"{key}={value:+d}" for key, value in factors.items()),
                "الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن"]}
    remaining, order, cyclic_tail = set(ids), [], []
    while remaining:
        eligible = [ids[n] for n in remaining if not set(ids[n]["dependencies"]["parents"]) & remaining]
        if not eligible:
            cyclic_tail = sorted(remaining)
            order.extend(cyclic_tail)
            break
        selected = min(eligible, key=lambda p: (-p["priority"]["score"], p["number"]))["number"]
        order.append(selected)
        remaining.remove(selected)
    for pr in prs:
        rank = order.index(pr["number"]) + 1 if pr["number"] in order else "UNKNOWN"
        pr["priority"]["rank"] = rank
        pr["suggested_review_priority"] = rank
        pr["dependencies"]["ancestor_blockers"] = [{"number": n, "classifications": ids[n]["classifications"]}
            for n in pr["dependencies"]["ancestors"] if n in ids]
    # Render only genuine edges. Expand linear chains, split at junctions;
    # never render parallel ancestors as if one depends on the other.
    chains = []
    for pr in prs:
        if pr["dependencies"]["state"] == "CYCLE":
            continue
        for parent in pr["dependencies"]["parents"]:
            path, node, seen = [parent, pr["number"]], parent, {parent, pr["number"]}
            while node in ids and len(ids[node]["dependencies"]["parents"]) == 1:
                node = ids[node]["dependencies"]["parents"][0]
                if node in seen:
                    break
                seen.add(node)
                path.insert(0, node)
            if path not in chains:
                chains.append(path)
    chains = [p for p in chains if not any(len(q) > len(p) and q[:len(p)] == p for q in chains)]
    return order, chains, cyclic_tail
