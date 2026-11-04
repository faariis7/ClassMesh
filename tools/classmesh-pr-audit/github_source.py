"""Bounded, read-only GitHub CLI transport and point-in-time collection.

No raw process output, credentials, logs, artifacts, Git writes, or disk cache.
Every unavailable/partial response is an UNKNOWN evidence envelope.
"""
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote


def known(data):
    return {"state": "KNOWN", "data": data}


def unknown(code, source="", data=None):
    result = {"state": "UNKNOWN", "error": {"code": code, "source": source}}
    if data is not None:
        result["data"] = data
    return result


def is_known(value):
    return isinstance(value, dict) and value.get("state") == "KNOWN" and "data" in value


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class GitHub:
    """Only GET REST and query-only GraphQL. Fail closed on every boundary."""

    def __init__(self, timeout=20, deadline=600, max_requests=1200, max_pages=30):
        self.timeout = timeout
        self.deadline = time.monotonic() + deadline
        self.max_requests = max_requests
        self.max_pages = max_pages
        self.requests = 0
        self.circuit = None

    def _call(self, arguments, source, text_mode=False):
        if self.circuit:
            return unknown(self.circuit, source)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= self.max_requests:
            return unknown("BUDGET_EXHAUSTED", source)
        self.requests += 1
        env = dict(os.environ)
        # GH_DEBUG=api could otherwise expose headers in captured diagnostics.
        env.pop("GH_DEBUG", None)
        env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
                   GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_PAGER="cat", NO_COLOR="1")
        try:
            process = subprocess.run(
                ["gh", "api", "--hostname", "github.com", *arguments],
                capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                timeout=min(self.timeout, remaining), env=env,
            )
        except subprocess.TimeoutExpired:
            return unknown("TIMEOUT", source)
        except (OSError, UnicodeError):
            return unknown("GH_UNAVAILABLE", source)
        if len(process.stdout) > 8 * 1024 * 1024:
            return unknown("RESPONSE_TOO_LARGE", source)
        try:
            data = json.loads(process.stdout)
        except (ValueError, TypeError):
            data = None
        if process.returncode:
            message = str(data.get("message", "")) if isinstance(data, dict) else ""
            status = str(data.get("status", "")) if isinstance(data, dict) else ""
            match = re.search(r"HTTP (\d{3})", process.stderr or "")
            status = status or (match.group(1) if match else "")
            if status == "429" or "rate limit" in message.lower():
                self.circuit = "RATE_LIMITED"
                return unknown("RATE_LIMITED", source)
            # GitHub explicitly distinguishes absent classic protection from
            # a generic 404 (which can also mean hidden/unauthorized data).
            if status == "404" and message == "Branch not protected" and source.endswith("/protection"):
                return known(None)
            code = {"401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT_FOUND_OR_HIDDEN"}.get(status, "API_FAILED")
            return unknown(code, source)
        if text_mode:
            return known(process.stdout)
        if data is None:
            return unknown("INVALID_JSON", source)
        if isinstance(data, dict) and data.get("errors"):
            return unknown("GRAPHQL_ERRORS", source)
        return known(data)

    def get(self, endpoint):
        # Endpoints are built from fixed paths and quoted IDs, never from URLs
        # supplied by comments/PR bodies or pagination links.
        if not isinstance(endpoint, str) or endpoint.startswith(("/", "-")) or "://" in endpoint:
            return unknown("INVALID_ENDPOINT")
        return self._call(["--method", "GET", endpoint], endpoint)

    def graphql(self, query):
        # All callers use static queries below. No mutations or subscriptions.
        if not isinstance(query, str) or not re.match(r"\s*query\b", query) or re.search(r"\b(mutation|subscription)\b", query):
            return unknown("READ_ONLY_VIOLATION", "graphql")
        return self._call(["--method", "POST", "graphql", "-f", "query=" + query], "graphql")

    def get_text(self, endpoint):
        # Only bounded job logs; capture, parse hashes, discard. Never terminal
        # output or a disk download. New gh versions reject ANSI without this.
        if not re.fullmatch(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/jobs/[0-9]+/logs", endpoint):
            return unknown("INVALID_LOG_ENDPOINT")
        return self._call(["--method", "GET", endpoint, "--allow-escape-sequences"], endpoint, text_mode=True)

    def pages(self, endpoint, key=None):
        items = []
        total = None
        separator = "&" if "?" in endpoint else "?"
        for page in range(1, self.max_pages + 1):
            response = self.get(f"{endpoint}{separator}per_page=100&page={page}")
            if not is_known(response):
                return dict(response, data=items)
            data = response["data"]
            batch = data.get(key) if key and isinstance(data, dict) else data
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                return unknown("INVALID_RESPONSE", endpoint, items)
            if key:
                count = data.get("total_count")
                if type(count) is not int or count < 0 or (total is not None and count != total):
                    return unknown("UNSTABLE_OR_MISSING_COUNT", endpoint, items)
                total = count
            items.extend(batch)
            if len(batch) < 100:
                if total is not None and len(items) != total:
                    return unknown("TRUNCATED_RESPONSE", endpoint, items)
                return known(items)
        return unknown("PAGE_LIMIT", endpoint, items)


def combine_policy(classic, rules):
    """Aggregate enforced branch rules with classic protection, never a 404 guess."""
    if not is_known(classic) or not is_known(rules):
        return unknown("POLICY_UNAVAILABLE", "branch protection + rulesets")
    result = {"required_approvals": 0, "code_owner_review": False,
              "last_push_approval": False, "conversation_resolution": False, "strict_checks": False,
              "required_checks": [], "unsupported_rules": []}
    strict_values = []
    try:
        protection = classic["data"]
        if protection is not None:
            if not isinstance(protection, dict) or not any(key in protection for key in
                    ("required_pull_request_reviews", "required_status_checks", "url")):
                raise ValueError
            review = protection.get("required_pull_request_reviews")
            if review is not None:
                result["required_approvals"] = review["required_approving_review_count"]
                result["code_owner_review"] = review["require_code_owner_reviews"]
                result["last_push_approval"] = review.get("require_last_push_approval", False)
            status = protection.get("required_status_checks")
            if status is not None:
                result["required_checks"].extend(status["checks"])
                strict_values.append(status.get("strict"))
            result["conversation_resolution"] = protection.get("required_conversation_resolution", {}).get("enabled", False)
        if not isinstance(rules["data"], list):
            raise ValueError
        for rule in rules["data"]:
            kind = rule["type"]
            if kind == "pull_request":
                params = rule["parameters"]
                result["required_approvals"] = max(result["required_approvals"], params["required_approving_review_count"])
                result["code_owner_review"] |= params["require_code_owner_review"]
                result["last_push_approval"] |= params["require_last_push_approval"]
                result["conversation_resolution"] |= params["required_review_thread_resolution"]
                if params.get("required_reviewers"):
                    result["unsupported_rules"].append("required_reviewers")
            elif kind == "required_status_checks":
                strict_values.append(rule["parameters"].get("strict_required_status_checks_policy"))
                for check in rule["parameters"]["required_status_checks"]:
                    result["required_checks"].append({"context": check["context"], "app_id": check.get("integration_id")})
            elif kind not in ("deletion", "non_fast_forward", "copilot_code_review"):
                result["unsupported_rules"].append(kind)
        if type(result["required_approvals"]) is not int or result["required_approvals"] < 0:
            raise ValueError
        result["strict_checks"] = True if any(v is True for v in strict_values) else False if all(v is False for v in strict_values) else "UNKNOWN"
        for field in ("code_owner_review", "last_push_approval", "conversation_resolution"):
            if type(result[field]) is not bool:
                raise ValueError
        for check in result["required_checks"]:
            if not isinstance(check.get("context"), str) or not check["context"]:
                raise ValueError
        return known(result)
    except (KeyError, TypeError, ValueError, AttributeError):
        return unknown("INVALID_POLICY", "branch protection + rulesets")


def review_threads(gh, repo, number):
    owner, name = repo.split("/")
    threads = []
    cursor = None
    seen = set()
    decision = None
    for _ in range(gh.max_pages):
        query = '''query { repository(owner: OWNER, name: NAME) { pullRequest(number: NUMBER) {
          reviewDecision reviewThreads(first: 100, after: CURSOR) {
            pageInfo { hasNextPage endCursor }
            nodes { id isResolved isOutdated comments(first: 100) {
              pageInfo { hasNextPage } nodes { body url createdAt author { login } }
            } }
          }
        } } }'''
        for marker, value in (("OWNER", owner), ("NAME", name), ("NUMBER", number), ("CURSOR", cursor)):
            query = query.replace(marker, json.dumps(value))
        response = gh.graphql(query)
        if not is_known(response):
            return dict(response, data={"review_decision": decision, "threads": threads})
        try:
            pr = response["data"]["data"]["repository"]["pullRequest"]
            decision = pr["reviewDecision"]
            connection = pr["reviewThreads"]
            for thread in connection["nodes"]:
                comments = thread["comments"]
                if comments["pageInfo"]["hasNextPage"] is not False:
                    return unknown("THREAD_COMMENTS_TRUNCATED", "reviewThreads", {"review_decision": decision, "threads": threads})
                threads.append(dict(thread, comments=comments["nodes"]))
            page = connection["pageInfo"]
            if page["hasNextPage"] is False:
                return known({"review_decision": decision, "threads": threads})
            cursor = page["endCursor"]
            if page["hasNextPage"] is not True or not isinstance(cursor, str) or cursor in seen:
                raise ValueError
            seen.add(cursor)
        except (KeyError, TypeError, ValueError):
            return unknown("INVALID_RESPONSE", "reviewThreads")
    return unknown("PAGE_LIMIT", "reviewThreads")


def fingerprint(pr):
    if not isinstance(pr, dict):
        return None
    try:
        return (pr["number"], pr["head"]["sha"], pr["base"]["ref"], pr["base"]["sha"],
                pr["draft"], pr["state"], pr["updated_at"], pr.get("merge_commit_sha"))
    except (KeyError, TypeError):
        return None


def collect(gh, repo, target_branch):
    """Keep data in memory. A second observation detects moving refs/inventory."""
    prefix = "repos/" + repo
    viewer = gh.get("user")
    if is_known(viewer) and isinstance(viewer["data"], dict) and isinstance(viewer["data"].get("login"), str):
        viewer = known(viewer["data"]["login"])
    else:
        viewer = unknown("VIEWER_UNAVAILABLE", "user")
    discovery = gh.pages(prefix + "/pulls?state=open&sort=created&direction=asc")
    snapshot = {"schema_version": 1, "repo": repo, "target_branch": target_branch,
                "captured_at": utc_now(), "viewer": viewer, "discovery": discovery, "pulls": []}
    policies, branches, permissions, commits = {}, {}, {}, {}
    for initial in discovery.get("data", []):
        number = initial.get("number")
        if type(number) is not int or number <= 0:
            snapshot["discovery"] = unknown("INVALID_PR_NUMBER", "pulls", discovery.get("data", []))
            continue
        path = f"{prefix}/pulls/{number}"
        detail = gh.get(path)
        pr = detail.get("data") if is_known(detail) else initial
        if not isinstance(pr, dict):
            pr = initial
            detail = unknown("INVALID_RESPONSE", path)
        entry = {"number": number, "detail": detail, "initial": initial, "observed_at": utc_now()}
        snapshot["pulls"].append(entry)
        head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
        base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
        sha, branch = head.get("sha"), base.get("ref")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha) or not isinstance(branch, str):
            entry["stable"] = unknown("INVALID_REFS", path)
            continue
        encoded = quote(branch, safe="")
        branch_path = f"{prefix}/branches/{encoded}"
        if branch not in branches:
            branches[branch] = gh.get(branch_path)
            policies[branch] = combine_policy(gh.get(branch_path + "/protection"), gh.pages(f"{prefix}/rules/branches/{encoded}"))
        raw_branch = branches[branch]
        try:
            entry["base_branch"] = known({"sha": raw_branch["data"]["commit"]["sha"]}) if is_known(raw_branch) else raw_branch
        except (KeyError, TypeError):
            entry["base_branch"] = unknown("INVALID_RESPONSE", branch_path)
        entry["policy"] = policies[branch]
        entry["checks"] = gh.pages(f"{prefix}/commits/{sha}/check-runs?filter=latest", "check_runs")
        entry["runs"] = gh.pages(f"{prefix}/actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
        if sha not in commits:
            commits[sha] = gh.get(f"{prefix}/git/commits/{sha}")
        entry["head_commit"] = commits[sha]
        from execution_evidence import collect_execution_proofs
        entry["execution_proofs"] = collect_execution_proofs(gh, repo, pr, entry["checks"], entry["runs"], commits, entry["policy"])
        entry["statuses"] = gh.pages(f"{prefix}/commits/{sha}/statuses")
        entry["reviews"] = gh.pages(path + "/reviews")
        entry["threads"] = review_threads(gh, repo, number)
        entry["comments"] = gh.pages(f"{prefix}/issues/{number}/comments")
        entry["files"] = gh.pages(path + "/files")
        if is_known(entry["files"]) and len(entry["files"]["data"]) != pr.get("changed_files"):
            entry["files"] = unknown("FILES_TRUNCATED", path + "/files", entry["files"]["data"])
        entry["code_scanning"] = gh.pages(f"{prefix}/code-scanning/alerts?state=open&ref=refs/pull/{number}/merge")
        entry["permissions"] = {}
        for review in entry["reviews"].get("data", []):
            user = review.get("user") if isinstance(review.get("user"), dict) else {}
            login = user.get("login")
            if review.get("state") not in ("APPROVED", "CHANGES_REQUESTED") or not isinstance(login, str):
                continue
            if login not in permissions:
                raw = gh.get(f"{prefix}/collaborators/{quote(login, safe='')}/permission")
                if is_known(raw) and isinstance(raw["data"], dict) and isinstance(raw["data"].get("permission"), str):
                    permissions[login] = known(raw["data"]["permission"])
                else:
                    permissions[login] = unknown("REVIEWER_PERMISSION_UNAVAILABLE", "collaborator permission")
            entry["permissions"][login] = permissions[login]
        after = gh.get(path)
        stable = (is_known(detail) and is_known(after) and fingerprint(pr) is not None
                  and fingerprint(pr) == fingerprint(after["data"]))
        entry["stable"] = known(True) if stable else unknown("SNAPSHOT_CHANGED_OR_UNAVAILABLE", path)
    from execution_evidence import declared_dependencies
    open_ids = {entry["number"] for entry in snapshot["pulls"]}
    dependency_cache = {}
    for entry in snapshot["pulls"]:
        pr = entry["detail"].get("data") or entry.get("initial", {})
        body = pr.get("body", "") if isinstance(pr, dict) else ""
        entry["dependency_details"] = {}
        for number in declared_dependencies(body)[:32]:
            if number not in open_ids:
                if number not in dependency_cache:
                    dependency_cache[number] = gh.get(f"{prefix}/pulls/{number}")
                entry["dependency_details"][str(number)] = dependency_cache[number]
    for branch, before in branches.items():
        after = gh.get(f"{prefix}/branches/{quote(branch, safe='')}")
        try:
            stable = is_known(before) and is_known(after) and before["data"]["commit"]["sha"] == after["data"]["commit"]["sha"]
        except (KeyError, TypeError):
            stable = False
        if not stable:
            for entry in snapshot["pulls"]:
                pr = entry["detail"].get("data") or entry.get("initial", {})
                if isinstance(pr, dict) and isinstance(pr.get("base"), dict) and pr["base"].get("ref") == branch:
                    entry["stable"] = unknown("BASE_CHANGED_OR_UNAVAILABLE", "base branch")
    last = gh.pages(prefix + "/pulls?state=open&sort=created&direction=asc")
    before_fps = [fingerprint(pr) for pr in discovery.get("data", [])]
    after_fps = [fingerprint(pr) for pr in last.get("data", [])]
    stable = is_known(discovery) and is_known(last) and None not in before_fps + after_fps and before_fps == after_fps
    snapshot["inventory_stable"] = known(True) if stable else unknown("INVENTORY_CHANGED_OR_UNAVAILABLE", "pulls")
    snapshot["finished_at"] = utc_now()
    snapshot["request_count"] = gh.requests
    return snapshot
