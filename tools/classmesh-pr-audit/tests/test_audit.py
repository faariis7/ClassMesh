"""Offline behavioral contracts. No GitHub, Windows, or third-party packages."""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def fixture():
    return json.loads((ROOT / "tests/fixtures/snapshot.json").read_text())


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.policy = importlib.import_module("policy")
        self.snapshot = fixture()
        self.entry = self.snapshot["pulls"][0]

    def result(self):
        return self.policy.analyze(self.snapshot)["pull_requests"][0]

    def test_complete_independent_evidence_is_ready_for_final_review(self):
        result = self.result()
        self.assertEqual(result["classifications"], ["READY_FOR_FINAL_REVIEW"])
        self.assertEqual(result["head_sha"], "a" * 40)
        self.assertEqual(result["base_sha"], "b" * 40)

    def test_old_commit_success_is_unknown_not_current_success(self):
        for check in self.entry["checks"]["data"]:
            check["head_sha"] = "c" * 40
        result = self.result()
        self.assertEqual(result["ci"]["Windows Build"]["state"], "UNKNOWN")
        self.assertNotIn("READY_FOR_FINAL_REVIEW", result["classifications"])
        self.assertTrue(result["ci"]["Windows Build"]["rejected_evidence"])

    def test_technically_mergeable_draft_is_not_ready(self):
        self.entry["detail"]["data"]["draft"] = True
        self.assertIn("DRAFT", self.result()["classifications"])

    def test_commented_review_is_not_an_independent_approval(self):
        self.entry["reviews"]["data"][0]["state"] = "COMMENTED"
        result = self.result()
        self.assertEqual(result["reviews"]["independent_approvals"], [])
        self.assertIn("MANUAL_ACCEPTANCE_REQUIRED", result["classifications"])

    def test_author_account_and_bots_are_not_independent(self):
        for login, kind in [("owner", "User"), ("author", "User"), ("robot", "Bot")]:
            with self.subTest(login=login):
                self.entry["reviews"]["data"][0]["user"] = {"login": login, "type": kind}
                self.assertEqual(self.result()["reviews"]["independent_approvals"], [])

    def test_approval_for_old_head_is_not_counted(self):
        self.entry["reviews"]["data"][0]["commit_id"] = "c" * 40
        self.assertEqual(self.result()["reviews"]["independent_approvals"], [])

    def test_later_changes_requested_or_dismissal_revokes_approval(self):
        review = self.entry["reviews"]["data"][0]
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            self.entry["reviews"]["data"] = [review, dict(review, id=99, state=state,
                                                        submitted_at="2026-11-04T02:00:00Z")]
            self.assertEqual(self.result()["reviews"]["independent_approvals"], [])

    def test_comment_after_approval_does_not_erase_opinionated_review(self):
        review = self.entry["reviews"]["data"][0]
        self.entry["reviews"]["data"].append(dict(review, id=99, state="COMMENTED"))
        self.assertEqual(self.result()["reviews"]["independent_approvals"], ["independent"])

    def test_stacked_pr_is_blocked_and_chains_are_parent_first(self):
        parent = self.entry
        child = copy.deepcopy(parent)
        child["detail"]["data"]["number"] = 102
        child["detail"]["data"]["head"]["ref"] = "child"
        child["detail"]["data"]["base"]["ref"] = "feature"
        self.snapshot["pulls"].append(child)
        self.snapshot["discovery"]["data"].append(child["detail"]["data"])
        report = self.policy.analyze(self.snapshot)
        result = next(p for p in report["pull_requests"] if p["number"] == 102)
        self.assertEqual(result["dependencies"]["parents"], [101])
        self.assertIn("DEPENDENCY_BLOCKED", result["classifications"])
        self.assertIn([101, 102], report["dependency_chains"])
        self.assertLess(report["suggested_review_order"].index(101),
                        report["suggested_review_order"].index(102))

    def test_non_main_without_open_parent_stays_blocked(self):
        self.entry["detail"]["data"]["base"]["ref"] = "missing-parent"
        result = self.result()
        self.assertIn("DEPENDENCY_BLOCKED", result["classifications"])
        self.assertEqual(result["dependencies"]["state"], "UNKNOWN")

    def test_base_conflict_and_ci_failure_are_both_visible(self):
        self.entry["detail"]["data"].update(mergeable=False, mergeable_state="dirty", draft=True)
        self.entry["checks"]["data"][0]["conclusion"] = "failure"
        result = self.result()
        self.assertTrue({"MERGE_CONFLICT", "CI_FAILED", "DRAFT"} <= set(result["classifications"]))

    def test_missing_or_unexpected_data_never_implies_success(self):
        for field, value in [("checks", {}), ("reviews", {"state": "KNOWN", "data": {}}),
                             ("policy", {"state": "KNOWN", "data": {}}),
                             ("detail", {"state": "KNOWN", "data": {}})]:
            with self.subTest(field=field):
                self.snapshot = fixture()
                self.snapshot["pulls"][0][field] = value
                self.assertNotIn("READY_FOR_FINAL_REVIEW", self.result()["classifications"])

    def test_unavailable_security_data_is_unknown_and_requires_review(self):
        self.entry["code_scanning"] = {"state": "UNKNOWN", "error": {"code": "FORBIDDEN"}}
        result = self.result()
        self.assertIn("SECURITY_REVIEW_REQUIRED", result["classifications"])
        self.assertEqual(result["security"]["code_scanning"]["state"], "UNKNOWN")

    def test_unresolved_outdated_thread_still_blocks(self):
        self.entry["threads"]["data"]["threads"] = [{"id": "T1", "isResolved": False,
            "isOutdated": True, "comments": [{"body": "security boundary fails", "url":
            "https://github.com/owner/project/pull/101#discussion_r1", "author": {"login": "reviewer"}}]}]
        result = self.result()
        self.assertEqual(len(result["reviews"]["unresolved_threads"]), 1)
        self.assertIn("SECURITY_REVIEW_REQUIRED", result["classifications"])

    def test_native_changes_require_manual_evidence_despite_windows_ci(self):
        self.entry["files"]["data"] = [{"filename": "apps/classmesh-teacher/src/main.rs"}]
        result = self.result()
        self.assertEqual(result["manual_acceptance"]["state"], "UNKNOWN")
        self.assertIn("MANUAL_ACCEPTANCE_REQUIRED", result["classifications"])
        self.assertIn("manual_acceptance", [g["field"] for g in result["missing_evidence"]])

    def test_missing_scanners_cannot_report_security_as_clear(self):
        self.entry["checks"]["data"] = self.entry["checks"]["data"][:2]
        self.assertEqual(self.result()["security"]["state"], "REVIEW_REQUIRED")

    def test_code_scanning_alert_retains_severity_and_unknown_commit(self):
        self.entry["code_scanning"]["data"] = [{"number": 7, "state": "open",
            "html_url": "https://github.com/owner/project/security/code-scanning/7",
            "rule": {"id": "rust/test-rule", "security_severity_level": "high"}}]
        alert = self.result()["security"]["code_scanning"]["alerts"][0]
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["observed_commit_sha"], "UNKNOWN")

    def test_newer_queued_run_overrides_old_success_on_same_head(self):
        run = copy.deepcopy(self.entry["runs"]["data"][0])
        run.update(id=300, check_suite_id=300, status="queued", conclusion=None)
        self.entry["runs"]["data"].append(run)
        self.assertEqual(self.result()["ci"]["Windows Build"]["state"], "PENDING")

    def test_finished_job_keeps_its_result_while_sibling_job_is_running(self):
        self.entry["runs"]["data"][0].update(status="in_progress", conclusion=None)
        self.entry["checks"]["data"][0].update(status="in_progress", conclusion=None)
        result = self.result()
        self.assertEqual(result["ci"]["Windows Build"]["state"], "PENDING")
        self.assertEqual(result["ci"]["Portable Rust"]["state"], "SUCCESS")
        self.entry["checks"]["data"][1]["conclusion"] = "failure"
        self.assertEqual(self.result()["ci"]["Portable Rust"]["state"], "FAILED")

    def test_in_progress_rerun_does_not_use_previous_attempts_success(self):
        self.entry["runs"]["data"][0].update(status="in_progress", conclusion=None,
            run_attempt=2, run_started_at="2026-11-04T02:00:00Z")
        self.assertEqual(self.result()["ci"]["Portable Rust"]["state"], "PENDING")

    def test_recreated_workflow_at_same_path_invalidates_old_workflow_id(self):
        run = copy.deepcopy(self.entry["runs"]["data"][0])
        run.update(id=300, workflow_id=300, check_suite_id=300, status="queued", conclusion=None)
        self.entry["runs"]["data"].append(run)
        self.assertEqual(self.result()["ci"]["Windows Build"]["state"], "PENDING")

    def test_check_from_untrusted_app_is_not_accepted(self):
        self.entry["checks"]["data"][0]["app"] = {"id": 9, "slug": "fake"}
        self.assertNotEqual(self.result()["ci"]["Windows Build"]["state"], "SUCCESS")

    def test_changed_head_during_collection_invalidates_readiness(self):
        self.entry["stable"] = {"state": "UNKNOWN", "error": {"code": "SNAPSHOT_CHANGED"}}
        self.assertNotIn("READY_FOR_FINAL_REVIEW", self.result()["classifications"])

    def test_permissionless_approval_is_unknown_not_counted(self):
        self.entry["permissions"]["independent"] = {"state": "UNKNOWN", "error": {"code": "FORBIDDEN"}}
        self.assertEqual(self.result()["reviews"]["independent_approvals"], [])

    def test_github_review_required_is_not_overridden_by_local_count(self):
        self.entry["threads"]["data"]["review_decision"] = "REVIEW_REQUIRED"
        self.assertIn("MANUAL_ACCEPTANCE_REQUIRED", self.result()["classifications"])

    def test_unstable_github_merge_state_is_not_hidden_by_named_green_checks(self):
        self.entry["detail"]["data"]["mergeable_state"] = "unstable"
        self.assertIn("MANUAL_ACCEPTANCE_REQUIRED", self.result()["classifications"])

    def test_false_inventory_stability_is_not_ready(self):
        self.snapshot["inventory_stable"]["data"] = False
        self.assertNotIn("READY_FOR_FINAL_REVIEW", self.result()["classifications"])

    def test_discovered_pr_cannot_disappear_silently(self):
        self.snapshot["discovery"]["data"].append(dict(self.entry["detail"]["data"], number=999))
        report = self.policy.analyze(self.snapshot)
        self.assertEqual(report["collection_state"], "PARTIAL")
        self.assertNotIn("READY_FOR_FINAL_REVIEW", report["pull_requests"][0]["classifications"])

    def test_required_exact_context_is_not_replaced_by_alias(self):
        self.entry["policy"]["data"]["required_checks"].append({"context": "CodeQL", "app_id": 15368})
        self.assertNotIn("READY_FOR_FINAL_REVIEW", self.result()["classifications"])

    def test_workflow_for_different_pr_does_not_certify_current_pr(self):
        for run in self.entry["runs"]["data"]:
            run["pull_requests"] = [{"number": 999}]
        self.assertEqual(self.result()["ci"]["Windows Build"]["state"], "UNKNOWN")

    def test_rerun_does_not_reuse_a_check_from_previous_attempt(self):
        self.entry["runs"]["data"][0].update(run_attempt=2, run_started_at="2026-11-04T02:00:00Z")
        self.assertEqual(self.result()["ci"]["Windows Build"]["state"], "UNKNOWN")

    def test_unexpected_nested_api_shapes_are_reported_without_crash(self):
        cases = [("runs", 0, "pull_requests"), ("runs", 0, "run_attempt"),
                 ("checks", 0, "app"), ("reviews", 0, "user")]
        for field, index, key in cases:
            for bad in (None, 42, [], "unexpected"):
                if key == "run_attempt" and bad == 42:
                    bad = 0  # A positive attempt 42 is a valid GitHub response.
                with self.subTest(field=field, key=key, bad=bad):
                    self.snapshot = fixture()
                    self.snapshot["pulls"][0][field]["data"][index][key] = bad
                    self.assertNotIn("READY_FOR_FINAL_REVIEW", self.result()["classifications"])

    def test_invalid_ref_shapes_preserve_pr_as_unknown(self):
        for key in ("head", "base", "requested_reviewers", "requested_teams"):
            for bad in (None, 42, "unexpected"):
                with self.subTest(key=key, bad=bad):
                    self.snapshot = fixture()
                    self.snapshot["pulls"][0]["detail"]["data"][key] = bad
                    report = self.policy.analyze(self.snapshot)
                    self.assertEqual(report["collection_state"], "PARTIAL")
                    self.assertNotIn("READY_FOR_FINAL_REVIEW", report["pull_requests"][0]["classifications"])

    def test_dependency_cycles_are_explicit_unknown(self):
        child = copy.deepcopy(self.entry)
        self.entry["detail"]["data"]["base"]["ref"] = "child"
        child["detail"]["data"]["number"] = 102
        child["detail"]["data"]["head"]["ref"] = "child"
        child["detail"]["data"]["base"]["ref"] = "feature"
        self.snapshot["pulls"].append(child)
        report = self.policy.analyze(self.snapshot)
        self.assertTrue(all(p["dependencies"]["state"] == "UNKNOWN" for p in report["pull_requests"]))
        self.assertTrue(all("READY_FOR_FINAL_REVIEW" not in p["classifications"] for p in report["pull_requests"]))


class GitHubBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.source = importlib.import_module("github_source")

    def test_timeout_produces_unknown_without_echoing_token(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("SECRET", 1, stderr="TOKEN")):
            result = self.source.GitHub(timeout=1).get("repos/owner/project/pulls/1")
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertEqual(result["error"]["code"], "TIMEOUT")
        self.assertNotIn("TOKEN", json.dumps(result))

    def test_permission_failure_is_unknown(self):
        output = subprocess.CompletedProcess([], 1, '{"message":"private TOKEN","status":"403"}',
                                             "gh: private TOKEN (HTTP 403)")
        with patch("subprocess.run", return_value=output):
            result = self.source.GitHub().get("repos/owner/project/code-scanning/alerts")
        self.assertEqual(result["error"]["code"], "FORBIDDEN")
        self.assertNotIn("TOKEN", json.dumps(result))

    def test_rate_limit_opens_circuit_and_does_not_retry_forever(self):
        output = subprocess.CompletedProcess([], 1, '{"message":"API rate limit exceeded","status":"403"}', "")
        with patch("subprocess.run", return_value=output) as run:
            gh = self.source.GitHub()
            first = gh.get("repos/owner/project/pulls")
            second = gh.get("repos/owner/project/pulls")
        self.assertEqual(first["error"]["code"], "RATE_LIMITED")
        self.assertEqual(second["state"], "UNKNOWN")
        self.assertEqual(run.call_count, 1)

    def test_invalid_json_is_unknown(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "not JSON", "")):
            self.assertEqual(self.source.GitHub().get("user")["error"]["code"], "INVALID_JSON")

    def test_rest_is_get_and_graphql_rejects_mutations(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "{}", "")) as run:
            gh = self.source.GitHub()
            gh.get("user")
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--method") + 1], "GET")
            self.assertNotIn("--cache", command)
            self.assertFalse(run.call_args.kwargs.get("shell", False))
            before = run.call_count
            result = gh.graphql("mutation { deleteIssue(input: {}) { clientMutationId } }")
            self.assertEqual(result["state"], "UNKNOWN")
            self.assertEqual(run.call_count, before)

    def test_pagination_does_not_drop_second_page(self):
        gh = self.source.GitHub()
        with patch.object(gh, "get", side_effect=[{"state": "KNOWN", "data": [{"id": i} for i in range(100)]},
                                                  {"state": "KNOWN", "data": [{"id": 100}]}]):
            result = gh.pages("repos/owner/project/pulls")
        self.assertEqual(len(result["data"]), 101)

    def test_pagination_failure_retains_partial_data_but_marks_unknown(self):
        gh = self.source.GitHub()
        with patch.object(gh, "get", side_effect=[{"state": "KNOWN", "data": [{"id": i} for i in range(100)]},
                                                  {"state": "UNKNOWN", "error": {"code": "TIMEOUT"}}]):
            result = gh.pages("repos/owner/project/pulls")
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertEqual(len(result["data"]), 100)

    def test_graphql_partial_errors_never_become_success(self):
        raw = '{"data":{"repository":null},"errors":[{"message":"TOKEN"}]}'
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, raw, "")):
            result = self.source.GitHub().graphql("query { viewer { login } }")
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertNotIn("TOKEN", json.dumps(result))

    def test_discovery_failure_still_generates_partial_report(self):
        gh = self.source.GitHub()
        unknown = {"state": "UNKNOWN", "error": {"code": "FORBIDDEN"}}
        with patch.object(gh, "get", return_value=unknown), patch.object(gh, "pages", return_value=unknown):
            snapshot = self.source.collect(gh, "owner/project", "main")
        report = importlib.import_module("policy").analyze(snapshot)
        self.assertEqual(report["collection_state"], "PARTIAL")
        self.assertEqual(report["summary"]["total"], 0)
        self.assertFalse(report["summary"]["all_ready"])

    def test_policy_aggregates_classic_and_rulesets(self):
        classic = {"required_pull_request_reviews": {"required_approving_review_count": 1,
            "require_code_owner_reviews": False, "require_last_push_approval": False},
            "required_status_checks": {"checks": [{"context": "Windows Build", "app_id": 15368}]},
            "required_conversation_resolution": {"enabled": True}}
        rules = [{"type": "pull_request", "parameters": {"required_approving_review_count": 2,
            "require_code_owner_review": True, "require_last_push_approval": False,
            "required_review_thread_resolution": True}}, {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "Portable Rust", "integration_id": 15368}]}}]
        result = self.source.combine_policy({"state": "KNOWN", "data": classic},
                                             {"state": "KNOWN", "data": rules})
        self.assertEqual(result["data"]["required_approvals"], 2)
        self.assertTrue(result["data"]["code_owner_review"])
        self.assertEqual(len(result["data"]["required_checks"]), 2)

    def test_missing_rules_permissions_cannot_mean_no_required_reviews(self):
        result = self.source.combine_policy({"state": "KNOWN", "data": None},
            {"state": "UNKNOWN", "error": {"code": "FORBIDDEN"}})
        self.assertEqual(result["state"], "UNKNOWN")

    def test_unexpected_pagination_shape_is_unknown(self):
        gh = self.source.GitHub()
        with patch.object(gh, "get", return_value={"state": "KNOWN", "data": {"surprise": []}}):
            self.assertEqual(gh.pages("repos/owner/project/pulls")["state"], "UNKNOWN")

    def test_request_budget_prevents_additional_api_calls(self):
        with patch("subprocess.run") as run:
            gh = self.source.GitHub(max_requests=0)
            self.assertEqual(gh.get("user")["error"]["code"], "BUDGET_EXHAUSTED")
            run.assert_not_called()

    def test_collector_handles_malformed_head_without_crashing(self):
        gh = self.source.GitHub()
        pr = fixture()["pulls"][0]["detail"]["data"]
        pr["head"] = 42
        with patch.object(gh, "get", return_value={"state": "KNOWN", "data": pr}), \
                patch.object(gh, "pages", return_value={"state": "KNOWN", "data": [pr]}):
            result = self.source.collect(gh, "owner/project", "main")
        report = importlib.import_module("policy").analyze(result)
        self.assertEqual(report["collection_state"], "PARTIAL")

    def test_null_or_empty_classic_policy_is_not_silently_unprotected(self):
        for data in ({}, {"garbage": True}):
            result = self.source.combine_policy({"state": "KNOWN", "data": data},
                                                {"state": "KNOWN", "data": []})
            self.assertEqual(result["state"], "UNKNOWN")

    def test_threads_paginate_and_partial_nested_connection_is_unknown(self):
        gh = self.source.GitHub()
        response = {"state": "KNOWN", "data": {"data": {"repository": {"pullRequest": {
            "reviewDecision": None, "reviewThreads": {"nodes": [{"id": "T", "isResolved": False,
                "isOutdated": True, "comments": {"nodes": [], "pageInfo": {"hasNextPage": True}}}],
                "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}}
        with patch.object(gh, "graphql", return_value=response):
            self.assertEqual(self.source.review_threads(gh, "owner/project", 101)["state"], "UNKNOWN")

    def test_full_mocked_collection_matches_ready_fixture(self):
        routes = json.loads((ROOT / "tests/fixtures/api_responses.json").read_text())
        calls = []

        def response(command, **kwargs):
            endpoint = command[6].split("?")[0]
            calls.append(endpoint)
            self.assertIn(endpoint, routes)
            self.assertEqual(command[5], "POST" if endpoint == "graphql" else "GET")
            if endpoint == "graphql":
                self.assertTrue(command[-1].startswith("query=query "))
            payload = routes[endpoint]
            return subprocess.CompletedProcess(command, 0, payload if endpoint.endswith("/logs") else json.dumps(payload), "")

        with patch("subprocess.run", side_effect=response):
            snapshot = self.source.collect(self.source.GitHub(), "owner/project", "main")
        report = importlib.import_module("policy").analyze(snapshot)
        self.assertEqual(report["collection_state"], "COMPLETE")
        self.assertEqual(report["pull_requests"][0]["classifications"], ["READY_FOR_FINAL_REVIEW"])
        self.assertEqual(calls.count("repos/owner/project/pulls/101"), 2)
        self.assertEqual(calls.count("repos/owner/project/branches/main"), 2)

    def test_collector_detects_head_movement_between_observations(self):
        routes = json.loads((ROOT / "tests/fixtures/api_responses.json").read_text())
        reads = 0

        def response(command, **kwargs):
            nonlocal reads
            endpoint = command[6].split("?")[0]
            value = copy.deepcopy(routes[endpoint])
            if endpoint == "repos/owner/project/pulls/101":
                reads += 1
                if reads == 2:
                    value["head"]["sha"] = "d" * 40
            return subprocess.CompletedProcess(command, 0, value if endpoint.endswith("/logs") else json.dumps(value), "")

        with patch("subprocess.run", side_effect=response):
            snapshot = self.source.collect(self.source.GitHub(), "owner/project", "main")
        self.assertEqual(snapshot["pulls"][0]["stable"]["state"], "UNKNOWN")
        report = importlib.import_module("policy").analyze(snapshot)
        self.assertNotIn("READY_FOR_FINAL_REVIEW", report["pull_requests"][0]["classifications"])

    def test_plain_server_failure_and_missing_gh_are_unknown(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "untrusted TOKEN", "HTTP 502 TOKEN")):
            result = self.source.GitHub().get("user")
            self.assertEqual(result["error"]["code"], "API_FAILED")
            self.assertNotIn("TOKEN", json.dumps(result))
        with patch("subprocess.run", side_effect=FileNotFoundError("untrusted TOKEN")):
            self.assertEqual(self.source.GitHub().get("user")["error"]["code"], "GH_UNAVAILABLE")

    def test_second_workflow_page_failure_cannot_reuse_partial_green_results(self):
        gh = self.source.GitHub()
        with patch.object(gh, "get", side_effect=[
                {"state": "KNOWN", "data": {"total_count": 101, "workflow_runs": [{"id": i} for i in range(100)]}},
                {"state": "UNKNOWN", "error": {"code": "TIMEOUT"}}]):
            result = gh.pages("repos/owner/project/actions/runs", "workflow_runs")
        self.assertEqual(result["state"], "UNKNOWN")

    def test_unknown_classic_404_cannot_mean_unprotected_branch(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1,
                '{"message":"Not Found","status":"404"}', "")):
            self.assertEqual(self.source.GitHub().get("repos/owner/project/branches/main/protection")["state"], "UNKNOWN")

    def test_check_total_count_cannot_be_silently_truncated(self):
        gh = self.source.GitHub()
        with patch.object(gh, "get", return_value={"state": "KNOWN", "data": {"check_runs": [], "total_count": 7}}):
            self.assertEqual(gh.pages("repos/owner/project/commits/sha/check-runs", "check_runs")["state"], "UNKNOWN")


class OutputBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.audit = importlib.import_module("audit")

    def test_fixture_cli_writes_only_the_two_reports_and_no_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "reports"
            proc = subprocess.run([sys.executable, str(ROOT / "audit.py"),
                "--fixture", str(ROOT / "tests/fixtures/snapshot.json"), "--output-dir", str(output)],
                capture_output=True, text=True, env=dict(os.environ, GH_TOKEN="do-not-print-this"))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(sorted(p.name for p in output.iterdir()), ["report.json", "report.md"])
            self.assertIn("تقرير", (output / "report.md").read_text())
            self.assertNotIn("do-not-print-this", proc.stdout + proc.stderr)
            self.assertEqual(list(Path(tmp).glob("**/__pycache__")), [])
            self.assertEqual(list(ROOT.glob("**/__pycache__")), [])

    def test_directory_symlink_and_hardlinked_target_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            link = root / "link"
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises((ValueError, OSError)):
                self.audit.write_reports(link, {}, "")
            target = root / "keep"
            target.write_text("keep")
            os.link(target, actual / "report.md")
            with self.assertRaises((ValueError, OSError)):
                self.audit.write_reports(actual, {}, "")
            self.assertEqual(target.read_text(), "keep")

    def test_partial_report_cli_uses_nonzero_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = fixture()
            snapshot["pulls"][0]["checks"] = {"state": "UNKNOWN", "error": {"code": "FORBIDDEN"}}
            source = root / "input.json"
            source.write_text(json.dumps(snapshot))
            proc = subprocess.run([sys.executable, str(ROOT / "audit.py"), "--fixture", str(source),
                                   "--output-dir", str(root / "reports")], capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads((root / "reports/report.json").read_text())["collection_state"], "PARTIAL")

    def test_existing_report_symlink_cannot_overwrite_outside_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "keep.txt"
            sentinel.write_text("unchanged")
            output = root / "reports"
            output.mkdir()
            (output / "report.json").symlink_to(sentinel)
            with self.assertRaises((ValueError, OSError)):
                self.audit.write_reports(output, {"hello": "world"}, "example")
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_report_redacts_token_patterns_and_escapes_markdown(self):
        snapshot = fixture()
        snapshot["pulls"][0]["detail"]["data"]["title"] = "<script>x</script> | ghp_" + "x" * 36
        report = importlib.import_module("policy").analyze(snapshot)
        output = self.audit.render_markdown(report)
        self.assertNotIn("<script>", output)
        self.assertNotIn("ghp_" + "x" * 36, output)


if __name__ == "__main__":
    unittest.main()
