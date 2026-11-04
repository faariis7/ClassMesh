"""V2 acceptance tests: the new behavior must fail against the V1 baseline."""
import copy
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import policy
import github_source as source


def snapshot():
    value = json.loads((ROOT / "tests/fixtures/snapshot.json").read_text())
    entry = value["pulls"][0]
    entry["detail"]["data"]["merge_commit_sha"] = "d" * 40
    entry["policy"]["data"]["strict_checks"] = False
    entry["head_commit"] = source.known({"sha": "a" * 40, "commit": {"committer": {"date": "2026-11-04T00:30:00Z"}}})
    entry["execution_proofs"] = {}
    for check in entry["checks"]["data"]:
        run_id = check["check_suite"]["id"]
        entry["execution_proofs"][str(check["id"])] = source.known({
            "source": "GITHUB_ACTIONS_CHECKOUT_LOG", "check_id": check["id"], "run_id": run_id,
            "run_attempt": 1, "head_sha": "a" * 40, "checkout_sha": "d" * 40,
            "parents": ["b" * 40, "a" * 40], "url": check["details_url"]})
    return value


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()
        self.entry = self.snapshot["pulls"][0]

    def report(self):
        return policy.analyze_v2(self.snapshot)

    def result(self):
        return self.report()["pull_requests"][0]

    def test_complete_verifiable_conditions_make_merge_candidate_not_permission(self):
        result = self.result()
        self.assertEqual(result["readiness_stage"], "READY_FOR_MERGE")
        self.assertFalse(result["merge_authorized"])
        self.assertEqual(self.report()["schema_version"], 2)

    def test_only_missing_independent_review_is_not_a_technical_block(self):
        self.entry["reviews"]["data"] = []
        self.assertEqual(self.result()["readiness_stage"], "READY_FOR_INDEPENDENT_REVIEW")
        self.assertEqual(self.result()["next_action"], "REQUEST_INDEPENDENT_REVIEW")
        self.assertEqual(self.result()["technical_blockers"], [])

    def test_one_approval_with_two_required_is_final_review_not_merge(self):
        self.entry["policy"]["data"]["required_approvals"] = 2
        self.assertEqual(self.result()["readiness_stage"], "READY_FOR_FINAL_REVIEW")

    def test_self_or_commented_approval_never_satisfies_merge_gate(self):
        for login, state in [("author", "APPROVED"), ("independent", "COMMENTED"), ("owner", "APPROVED")]:
            self.entry["reviews"]["data"][0].update(state=state, user={"login": login, "type": "User"})
            self.assertEqual(self.result()["readiness_stage"], "READY_FOR_INDEPENDENT_REVIEW")

    def test_unknown_required_condition_prevents_merge(self):
        for field in ("policy", "stable", "reviews", "checks", "code_scanning", "files"):
            with self.subTest(field=field):
                self.snapshot = snapshot()
                self.snapshot["pulls"][0][field] = source.unknown("FORBIDDEN")
                result = self.result()
                self.assertNotEqual(result["readiness_stage"], "READY_FOR_MERGE")
                self.assertTrue(result["required_evidence"])

    def test_ci_failure_is_actionable_technical_block(self):
        self.entry["checks"]["data"][0]["conclusion"] = "failure"
        result = self.result()
        self.assertEqual(result["readiness_stage"], "BLOCKED")
        self.assertEqual(result["next_action"], "FIX_FAILED_CI")
        self.assertEqual(result["suggested_owner"], "BRANCH_DEVELOPER")

    def test_old_head_success_is_not_reused(self):
        self.entry["checks"]["data"][0]["head_sha"] = "c" * 40
        self.assertNotEqual(self.result()["readiness_stage"], "READY_FOR_MERGE")
        self.assertEqual(self.result()["ci"]["Windows Build"]["state"], "UNKNOWN")

    def test_missing_checkout_proof_requires_base_revalidation(self):
        self.entry.pop("execution_proofs")
        result = self.result()
        self.assertEqual(result["base_validation"]["state"], "UNKNOWN")
        self.assertIn("BASE_REVALIDATION_REQUIRED", result["classifications"])

    def test_missing_strict_policy_field_is_unknown_not_false(self):
        raw = {"required_status_checks": {"checks": []}}
        result = source.combine_policy(source.known(raw), source.known([]))
        self.assertEqual(result["data"]["strict_checks"], "UNKNOWN")
        rules = [{"type": "required_status_checks", "parameters": {"required_status_checks": []}}]
        result = source.combine_policy(source.known(None), source.known(rules))
        self.assertEqual(result["data"]["strict_checks"], "UNKNOWN")

    def test_checkout_failure_reason_is_retained_in_report(self):
        self.entry["execution_proofs"]["1"] = source.unknown("FORBIDDEN", "job logs")
        observations = self.result()["base_validation"]["gates"]["Windows Build"]["observations"]
        self.assertEqual(observations[0]["reason"], "FORBIDDEN")

    def test_tested_integration_on_current_base_is_verified(self):
        result = self.result()
        self.assertEqual(result["base_validation"]["state"], "INTEGRATION_CURRENT")
        self.assertEqual(result["base_validation"]["gates"]["Windows Build"]["tested_base_sha"], "b" * 40)

    def test_base_moved_does_not_erase_head_success_but_blocks_old_integration(self):
        self.entry["base_branch"]["data"]["sha"] = "e" * 40
        result = self.result()
        self.assertEqual(result["ci"]["Windows Build"]["state"], "SUCCESS")
        self.assertEqual(result["base_validation"]["state"], "INTEGRATION_STALE")
        self.assertEqual(result["next_action"], "REVALIDATE_BASE")

    def test_rerun_timestamp_alone_does_not_refresh_integration(self):
        self.entry["base_branch"]["data"]["sha"] = "e" * 40
        for run in self.entry["runs"]["data"]:
            run["run_attempt"] = 2
        for proof in self.entry["execution_proofs"].values():
            proof["data"]["run_attempt"] = 2
        self.assertEqual(self.result()["base_validation"]["state"], "INTEGRATION_STALE")

    def test_new_attempt_with_verified_new_base_parents_refreshes_integration(self):
        self.entry["base_branch"]["data"]["sha"] = "e" * 40
        for run in self.entry["runs"]["data"]:
            run["run_attempt"] = 2
        for proof in self.entry["execution_proofs"].values():
            proof["data"].update(run_attempt=2, checkout_sha="f" * 40, parents=["e" * 40, "a" * 40])
        self.assertEqual(self.result()["base_validation"]["state"], "INTEGRATION_CURRENT")

    def test_head_only_checkout_keeps_valid_result_after_base_moves(self):
        self.entry["base_branch"]["data"]["sha"] = "e" * 40
        for proof in self.entry["execution_proofs"].values():
            proof["data"].update(checkout_sha="a" * 40, parents=["c" * 40])
        result = self.result()
        self.assertEqual(result["base_validation"]["state"], "HEAD_ONLY")
        self.assertNotIn("BASE_REVALIDATION_REQUIRED", result["classifications"])

    def test_strict_base_rule_is_not_satisfied_by_head_only_checkout(self):
        self.entry["policy"]["data"]["strict_checks"] = True
        for proof in self.entry["execution_proofs"].values():
            proof["data"].update(checkout_sha="a" * 40, parents=["c" * 40])
        self.assertIn("BASE_REVALIDATION_REQUIRED", self.result()["classifications"])

    def test_movement_during_collection_is_explicit(self):
        self.entry["stable"] = source.unknown("BASE_CHANGED_OR_UNAVAILABLE")
        self.assertEqual(self.result()["base_validation"]["state"], "CHANGED_DURING_COLLECTION")

    def test_wrong_run_attempt_or_head_in_proof_is_not_accepted(self):
        for key, value in [("run_id", 999), ("run_attempt", 99), ("head_sha", "c" * 40), ("check_id", 999)]:
            self.snapshot = snapshot()
            self.snapshot["pulls"][0]["execution_proofs"]["1"]["data"][key] = value
            self.assertIn("BASE_REVALIDATION_REQUIRED", self.result()["classifications"])

    def test_required_github_review_decision_unknown_prevents_merge(self):
        self.entry["threads"]["data"]["review_decision"] = None
        self.assertEqual(self.result()["readiness_stage"], "UNKNOWN")

    def test_untrusted_proof_url_cannot_bind_two_unknown_urls(self):
        self.entry["checks"]["data"][0]["details_url"] = "https://evil.invalid/job"
        self.entry["execution_proofs"]["1"]["data"]["url"] = "https://evil.invalid/job"
        self.assertIn("BASE_REVALIDATION_REQUIRED", self.result()["classifications"])

    def test_required_additional_job_collects_execution_proof(self):
        entry = self.entry
        entry["policy"]["data"]["required_checks"].append({"context": "Auditor tests", "app_id": 15368})
        check = copy.deepcopy(entry["checks"]["data"][0])
        check.update(id=77, name="Auditor tests")
        check["details_url"] = "https://github.com/owner/project/actions/runs/100/job/77"
        entry["checks"]["data"].append(check)
        class API:
            def get(self, endpoint):
                if "/actions/jobs/" in endpoint:
                    return source.known({"id": int(endpoint.rsplit("/", 1)[1]), "run_id": 100 if endpoint.rsplit("/", 1)[1] in ("1", "2", "77") else 200,
                        "run_attempt": 1, "head_sha": "a" * 40, "status": "completed", "conclusion": "success"})
                return source.known({"sha": "d" * 40, "parents": [{"sha": "b" * 40}, {"sha": "a" * 40}]})
            def get_text(self, endpoint):
                return source.known("##[group]Run actions/checkout@v6\n[command]/usr/bin/git log -1 --format=%H\n" + "d" * 40)
        from execution_evidence import collect_execution_proofs
        entry["execution_proofs"] = collect_execution_proofs(API(), "owner/project", entry["detail"]["data"], entry["checks"], entry["runs"], {}, entry["policy"])
        self.assertEqual(self.result()["readiness_stage"], "READY_FOR_MERGE")

    def test_security_keyword_alone_is_not_confirmed(self):
        self.entry["comments"]["data"] = [{"body": "Security was discussed", "html_url": "https://github.com/owner/project/pull/101#issuecomment-1"}]
        result = self.result()
        self.assertEqual(result["security"]["notes"][0]["classification"], "REVIEW_REQUIRED")
        self.assertEqual(result["priority"]["factors"]["confirmed_security"], 0)

    def test_old_comment_is_historical_not_a_confirmed_blocker(self):
        self.entry["comments"]["data"] = [{"body": "security note", "created_at": "2026-11-01T00:00:00Z", "html_url": "https://github.com/owner/project/pull/101#issuecomment-1"}]
        result = self.result()
        self.assertEqual(result["security"]["notes"][0]["classification"], "HISTORICAL_NOTE")
        self.assertEqual(result["priority"]["factors"]["confirmed_security"], 0)

    def test_edited_old_security_comment_needs_current_review(self):
        self.entry["comments"]["data"] = [{"body": "Security concern added today", "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2026-11-04T01:00:00Z", "html_url": "https://github.com/owner/project/pull/101#issuecomment-1"}]
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "REVIEW_REQUIRED")

    def test_unknown_or_wrong_head_timestamp_cannot_downgrade_security_note(self):
        self.entry["comments"]["data"] = [{"body": "Security", "created_at": "2020-01-01T00:00:00Z",
            "html_url": "https://github.com/owner/project/pull/101#issuecomment-1"}]
        for evidence in (source.unknown("FORBIDDEN", data={"sha": "a" * 40, "committer": {"date": "2099-01-01T00:00:00Z"}}),
                source.known({"sha": "c" * 40, "committer": {"date": "2099-01-01T00:00:00Z"}})):
            self.entry["head_commit"] = evidence
            self.assertEqual(self.result()["security"]["notes"][0]["classification"], "REVIEW_REQUIRED")

    def test_resolved_text_is_not_resolution_evidence(self):
        self.entry["threads"]["data"]["threads"] = [{"id": "T", "isResolved": False, "isOutdated": True,
            "comments": [{"body": "Security issue resolved", "url": "https://github.com/owner/project/pull/101#discussion_r1"}]}]
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "REVIEW_REQUIRED")
        self.entry["threads"]["data"]["threads"][0]["isResolved"] = True
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "RESOLVED")

    def test_current_open_scanning_alert_is_confirmed_blocker(self):
        self.entry["code_scanning"]["data"] = [{"number": 7, "state": "open", "html_url": "https://github.com/owner/project/security/code-scanning/7",
            "most_recent_instance": {"commit_sha": "a" * 40}, "rule": {"security_severity_level": "high"}}]
        result = self.result()
        self.assertEqual(result["security"]["notes"][0]["classification"], "CONFIRMED_BLOCKER")
        self.assertEqual(result["next_action"], "REQUEST_SECURITY_REVIEW")
        self.assertGreater(result["priority"]["factors"]["confirmed_security"], 0)

    def test_unbound_alert_is_review_required_not_confirmed(self):
        self.entry["code_scanning"]["data"] = [{"number": 7, "state": "open"}]
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "UNKNOWN")

    def test_independent_security_changes_requested_is_confirmed_review_blocker(self):
        self.entry["reviews"]["data"][0].update(state="CHANGES_REQUESTED", body="Security boundary needs a fix")
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "CONFIRMED_BLOCKER")
        self.entry["permissions"]["independent"] = source.unknown("FORBIDDEN")
        self.assertEqual(self.result()["security"]["notes"][0]["classification"], "REVIEW_REQUIRED")

    def test_malformed_new_evidence_is_unknown_not_a_crash(self):
        for field in ("execution_proofs", "head_commit", "dependency_details"):
            for value in (None, [], "bad", {"state": "KNOWN", "data": []}):
                with self.subTest(field=field, value=value):
                    data = snapshot()
                    data["pulls"][0][field] = value
                    self.assertIn(policy.analyze_v2(data)["pull_requests"][0]["readiness_stage"], ("READY_FOR_MERGE", "UNKNOWN"))

    def test_hardware_evidence_is_never_inferred_from_ci(self):
        self.entry["files"]["data"] = [{"filename": "apps/classmesh-worker/src/main.rs"}]
        result = self.result()
        self.assertEqual(result["manual_acceptance"]["state"], "UNKNOWN")
        self.assertNotEqual(result["readiness_stage"], "READY_FOR_MERGE")

    def test_owners_are_roles_not_guessed_people(self):
        self.entry["detail"]["data"]["body"] = "Assign this to Alice, our security expert."
        result = self.result()
        self.assertNotIn("Alice", result["suggested_owner"])
        self.assertEqual(result["suggested_owner"], "COORDINATION_LEAD")

    def test_same_snapshot_comparison_is_hashed_and_does_not_mutate_input(self):
        before = copy.deepcopy(self.snapshot)
        self.entry["reviews"]["data"] = []
        before = copy.deepcopy(self.snapshot)
        comparison = policy.compare_versions(self.snapshot)
        self.assertEqual(self.snapshot, before)
        self.assertEqual(len(comparison["snapshot_sha256"]), 64)
        self.assertEqual(comparison["pull_requests"][0]["v2_stage"], "READY_FOR_INDEPENDENT_REVIEW")
        self.assertIn("MANUAL_ACCEPTANCE_REQUIRED", comparison["pull_requests"][0]["v1_classifications"])


class BaseCollectionTests(unittest.TestCase):
    def module(self):
        return importlib.import_module("execution_evidence")

    def test_checkout_parser_accepts_one_observed_checkout_hash(self):
        raw = "2026-11-04T00:00:00Z ##[group]Run actions/checkout@v6\n2026-11-04T00:00:01Z [command]/usr/bin/git log -1 --format=%H\n2026-11-04T00:00:02Z " + "d" * 40 + "\n"
        self.assertEqual(self.module().checkout_commit(raw)["data"], "d" * 40)

    def test_windows_quoted_git_path_is_a_valid_checkout_marker(self):
        raw = '##[group]Run actions/checkout@v5\n[command]"C:\\Program Files\\Git\\cmd\\git.exe" log -1 --format=%H\n' + 'd' * 40 + '\n'
        self.assertEqual(self.module().checkout_commit(raw).get("data"), "d" * 40)

    def test_windows_quoted_git_mutation_after_checkout_is_rejected(self):
        raw = '##[group]Run actions/checkout@v5\n[command]/usr/bin/git log -1 --format=%H\n' + 'd' * 40 + '\n'
        raw += '[command]"C:\\Program Files\\Git\\cmd\\git.exe" checkout other\n'
        self.assertEqual(self.module().checkout_commit(raw)["state"], "UNKNOWN")

    def test_full_collection_binds_proof_and_detects_base_or_merge_movement(self):
        routes = json.loads((ROOT / "tests/fixtures/api_responses.json").read_text())
        for moving in (None, "base", "merge"):
            reads = {}
            def respond(command, **kwargs):
                endpoint = command[6].split("?")[0]
                data = copy.deepcopy(routes[endpoint])
                reads[endpoint] = reads.get(endpoint, 0) + 1
                if moving == "base" and endpoint.endswith("/branches/main") and reads[endpoint] == 2:
                    data["commit"]["sha"] = "e" * 40
                if moving == "merge" and endpoint.endswith("/pulls/101") and reads[endpoint] == 2:
                    data["merge_commit_sha"] = "e" * 40
                return subprocess.CompletedProcess(command, 0, data if endpoint.endswith("/logs") else json.dumps(data), "")
            with patch("subprocess.run", side_effect=respond):
                value = source.collect(source.GitHub(), "owner/project", "main")
            result = policy.analyze_v2(value)["pull_requests"][0]
            self.assertEqual(result["base_validation"]["state"], "CHANGED_DURING_COLLECTION" if moving else "INTEGRATION_CURRENT")

    def test_denied_job_logs_do_not_accept_head_success_as_integration(self):
        routes = json.loads((ROOT / "tests/fixtures/api_responses.json").read_text())
        def respond(command, **kwargs):
            endpoint = command[6].split("?")[0]
            if endpoint.endswith("/logs"):
                return subprocess.CompletedProcess(command, 1, "", "HTTP 403 forbidden")
            return subprocess.CompletedProcess(command, 0, json.dumps(routes[endpoint]), "")
        with patch("subprocess.run", side_effect=respond):
            value = source.collect(source.GitHub(), "owner/project", "main")
        result = policy.analyze_v2(value)["pull_requests"][0]
        self.assertEqual(result["ci"]["Windows Build"]["state"], "SUCCESS")
        self.assertEqual(result["base_validation"]["state"], "UNKNOWN")
        self.assertNotEqual(result["readiness_stage"], "READY_FOR_MERGE")

    def test_ambiguous_or_subsequently_changed_checkout_is_unknown(self):
        raw = "##[group]Run actions/checkout@v6\n[command]/usr/bin/git log -1 --format=%H\n" + "d" * 40 + "\n"
        for bad in (raw + raw, raw + "git checkout other\n", "an arbitrary success claim", raw.replace("d" * 40, "missing")):
            self.assertEqual(self.module().checkout_commit(bad)["state"], "UNKNOWN")

    def test_text_api_failure_never_leaks_logs_or_credentials(self):
        gh = source.GitHub()
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "secret body", "HTTP 403 secret")):
            result = gh.get_text("repos/owner/project/actions/jobs/1/logs")
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertNotIn("secret", json.dumps(result))


class DependencyPriorityTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()

    def add(self, number, base="main", body=""):
        entry = copy.deepcopy(self.snapshot["pulls"][0])
        entry["number"] = number
        detail = entry["detail"]["data"]
        detail.update(number=number, body=body)
        detail["head"]["ref"] = "feature-" + str(number)
        detail["base"]["ref"] = base
        for run in entry["runs"]["data"]:
            run["pull_requests"] = [{"number": number}]
        self.snapshot["pulls"].append(entry)
        self.snapshot["discovery"]["data"].append(detail)
        return entry

    def report(self):
        return policy.analyze_v2(self.snapshot)

    def test_branch_chain_is_parent_first_and_counts_transitive_dependents(self):
        self.add(102, "feature")
        self.add(103, "feature-102")
        report = self.report()
        self.assertEqual(report["suggested_review_order"], [101, 102, 103])
        self.assertEqual(report["pull_requests"][0]["priority"]["dependent_count"], 2)
        child = report["pull_requests"][2]
        self.assertEqual(child["blocking_prs"], [101, 102])
        self.assertFalse(child["can_proceed_without_dependencies"])
        self.assertEqual(child["readiness_stage"], "BLOCKED")

    def test_multiple_explicit_dependencies_and_unknown_parent(self):
        self.add(102)
        self.add(103, body="Depends-On: #101, #102, #999")
        pr = self.report()["pull_requests"][2]
        self.assertEqual(pr["dependencies"]["parents"], [101, 102])
        self.assertEqual(pr["dependencies"]["unknown_parents"], [999])
        self.assertNotEqual(pr["readiness_stage"], "READY_FOR_MERGE")

    def test_merged_explicit_dependency_clears_but_closed_unmerged_does_not(self):
        entry = self.add(102, body="Depends-On: #99")
        entry["dependency_details"] = {"99": source.known({"number": 99, "state": "closed", "merged": True,
            "base": {"ref": "main", "repo": {"full_name": "owner/project"}}})}
        self.assertEqual(self.report()["pull_requests"][1]["dependencies"]["state"], "CLEAR")
        entry["dependency_details"]["99"]["data"]["merged"] = False
        self.assertEqual(self.report()["pull_requests"][1]["dependencies"]["state"], "BLOCKED")

    def test_cycles_are_explicit_and_never_merge_ready(self):
        self.snapshot["pulls"][0]["detail"]["data"]["body"] = "Depends-On: #102"
        self.add(102, body="Depends-On: #101")
        report = self.report()
        self.assertTrue(report["dependency_cycles"])
        for pr in report["pull_requests"]:
            self.assertEqual(pr["dependencies"]["state"], "CYCLE")
            self.assertNotEqual(pr["readiness_stage"], "READY_FOR_MERGE")

    def test_random_references_are_not_dependencies(self):
        self.add(102, body="Mention #101. Security reviewed in #99.")
        self.assertEqual(self.report()["pull_requests"][1]["dependencies"]["parents"], [])

    def test_diamond_paths_never_invent_an_edge_between_siblings(self):
        self.add(102)
        self.add(103, body="Depends-On: #101, #102")
        report = self.report()
        self.assertNotIn([101, 102, 103], report["dependency_chains"])
        self.assertIn([101, 103], report["dependency_chains"])
        self.assertIn([102, 103], report["dependency_chains"])

    def test_unknown_or_wrong_target_merged_parent_never_clears(self):
        entry = self.add(102, body="Depends-On: #99")
        for value in (source.unknown("FORBIDDEN"), source.known({"number": 99, "state": "closed", "merged": True,
                "base": {"ref": "other", "repo": {"full_name": "owner/project"}}})):
            entry["dependency_details"] = {"99": value}
            self.assertEqual(self.report()["pull_requests"][1]["dependencies"]["state"], "UNKNOWN")

    def test_declaration_limit_is_visible(self):
        self.add(102, body="Depends-On: " + ", ".join("#" + str(n) for n in range(200, 234)))
        self.assertIn("DECLARATION_LIMIT", self.report()["pull_requests"][1]["dependencies"]["unknown_parents"])

    def test_security_history_has_no_priority_bonus(self):
        self.add(102)
        self.snapshot["pulls"][0]["comments"]["data"] = [{"body": "Security", "created_at": "2020-01-01T00:00:00Z",
            "html_url": "https://github.com/owner/project/pull/101#issuecomment-1"}]
        a, b = self.report()["pull_requests"]
        self.assertEqual(a["priority"]["score"], b["priority"]["score"])

    def test_child_ci_fix_can_proceed_while_parent_is_blocked(self):
        entry = self.add(102, "feature")
        entry["checks"]["data"][0]["conclusion"] = "failure"
        child = self.report()["pull_requests"][1]
        self.assertEqual(child["next_action"], "FIX_FAILED_CI")
        self.assertTrue(child["can_proceed_without_dependencies"])
        self.assertEqual(child["blocking_prs"], [101])

    def test_unknown_inventory_prevents_every_merge_candidate(self):
        self.snapshot["inventory_stable"] = source.unknown("INVENTORY_CHANGED")
        self.assertEqual(self.report()["pull_requests"][0]["readiness_stage"], "UNKNOWN")

    def test_extra_rules_and_unexplained_merge_state_remain_unknown(self):
        entry = self.snapshot["pulls"][0]
        entry["policy"]["data"]["unsupported_rules"] = ["required_deployments"]
        self.assertEqual(self.report()["pull_requests"][0]["readiness_stage"], "UNKNOWN")

    def test_github_blocked_by_only_missing_reviews_is_review_stage(self):
        entry = self.snapshot["pulls"][0]
        entry["reviews"]["data"] = []
        entry["detail"]["data"]["mergeable_state"] = "blocked"
        entry["threads"]["data"]["review_decision"] = "REVIEW_REQUIRED"
        self.assertEqual(self.report()["pull_requests"][0]["readiness_stage"], "READY_FOR_INDEPENDENT_REVIEW")


class OutputVerificationTests(unittest.TestCase):
    def test_arabic_executive_summary_actions_and_evidence(self):
        import audit
        report = policy.analyze_v2(snapshot())
        md = audit.render_markdown(report)
        for required in ("ملخص تنفيذي", "أهم خمسة إجراءات", "المسؤول المقترح", "INTEGRATION_CURRENT", "READY_FOR_MERGE", "github.com/owner/project/actions/runs/100/job/1"):
            self.assertIn(required, md)

    def test_cli_comparison_and_optional_snapshot_stay_inside_output(self):
        with tempfile.TemporaryDirectory() as root:
            fixture = Path(root) / "input.json"
            fixture.write_text(json.dumps(snapshot()))
            out = Path(root) / "out"
            result = subprocess.run([sys.executable, "-B", str(ROOT / "audit.py"), "--fixture", str(fixture),
                "--compare-v1", "--save-snapshot", "--output-dir", str(out)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({p.name for p in out.iterdir()}, {"snapshot.json", "report.md", "report.json"})
            saved = json.loads((out / "snapshot.json").read_text())
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["comparison"], policy.compare_versions(saved))

    def test_sample_matches_checked_in_outputs(self):
        verifier = importlib.import_module("verify")
        self.assertEqual(verifier.verify_example(ROOT), [])

    def test_scope_check_rejects_source_ci_and_path_traversal(self):
        verifier = importlib.import_module("verify")
        good = ["tools/classmesh-pr-audit/audit.py", ".github/workflows/classmesh-pr-audit.yml"]
        self.assertEqual(verifier.validate_paths(good), [])
        bad = ["Cargo.toml", "apps/teacher/main.rs", ".github/workflows/ci.yml", "tools/classmesh-pr-audit/../escape"]
        self.assertEqual(verifier.validate_paths(bad), bad)

    def test_syntax_verification_does_not_write_bytecode(self):
        verifier = importlib.import_module("verify")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "ok.py").write_text("x = 1\n")
            self.assertEqual(verifier.verify_syntax(path), [])
            (path / "broken.py").write_text("def (:invalid\n")
            self.assertEqual(len(verifier.verify_syntax(path)), 1)
            self.assertFalse(list(path.rglob("__pycache__")))


if __name__ == "__main__":
    unittest.main()
