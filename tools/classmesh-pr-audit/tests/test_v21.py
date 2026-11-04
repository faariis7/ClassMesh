"""V2.1 regression contracts at the read-only GitHub boundary."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from collections import Counter
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import github_source as source
import policy


def routes():
    return json.loads((ROOT / 'tests/fixtures/api_responses.json').read_text())


def collect(mutate=None, **limits):
    payloads = routes()
    calls = Counter()

    def run(command, **kwargs):
        endpoint = command[6].split('?')[0]
        calls[endpoint] += 1
        data = copy.deepcopy(payloads[endpoint])
        if mutate:
            data = mutate(endpoint, calls[endpoint], data)
        if isinstance(data, Exception):
            raise data
        if isinstance(data, subprocess.CompletedProcess):
            return data
        return subprocess.CompletedProcess(command, 0, data if endpoint.endswith('/logs') else json.dumps(data), '')

    with patch('github_source.subprocess.run', side_effect=run):
        result = source.collect(source.GitHub(**limits), 'owner/project', 'main')
    return result, calls


class StabilityTests(unittest.TestCase):
    def test_title_and_timestamp_change_does_not_invalidate_complete_inventory(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls') and count == 2:
                data[0].update(title='Editorial title', updated_at='2026-11-04T03:00:00Z')
            if ep.endswith('/pulls/101') and count == 2:
                data.update(title='Editorial title', updated_at='2026-11-04T03:00:00Z')
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertEqual(snap['pulls'][0]['stable'], source.known(True))

    def test_head_change_is_local_and_never_merge_ready(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls') and count == 2:
                data[0]['head']['sha'] = 'e' * 40
            if ep.endswith('/pulls/101') and count == 2:
                data['head']['sha'] = 'e' * 40
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertEqual(snap['pulls'][0]['stable'].get('error', {}).get('code'), 'REFS_CHANGED')
        result = policy.analyze_v2(snap)['pull_requests'][0]
        self.assertNotEqual(result['readiness_stage'], 'READY_FOR_MERGE')
        self.assertFalse(result['merge_authorized'])

    def test_added_or_removed_pr_is_membership_change(self):
        for added in (False, True):
            def mutate(ep, count, data):
                if ep.endswith('/pulls') and count == 2:
                    if not added:
                        return []
                    data.append(dict(data[0], number=102))
                return data
            snap, _ = collect(mutate)
            self.assertEqual(snap['inventory_stable']['error']['code'], 'INVENTORY_MEMBERSHIP_CHANGED')

    def test_closing_inventory_failure_keeps_original_api_cause(self):
        for error, code in [(subprocess.TimeoutExpired('gh', 1), 'TIMEOUT'),
                (subprocess.CompletedProcess([], 1, '{"status":"403"}', ''), 'FORBIDDEN'),
                (subprocess.CompletedProcess([], 1, '', ''), 'API_FAILED')]:
            def mutate(ep, count, data):
                return error if ep.endswith('/pulls') and count == 2 else data
            snap, _ = collect(mutate)
            self.assertEqual(snap['inventory_stable']['error']['code'], 'INVENTORY_UNAVAILABLE')
            self.assertEqual(snap['collection_diagnostics']['inventory']['after']['error']['code'], code)

    def test_missing_ref_is_local_unknown_not_inventory_disappearance(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls') and count == 2:
                data[0].pop('head')
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertEqual(snap['pulls'][0]['stable']['state'], 'UNKNOWN')

    def test_review_dismissal_with_unchanged_updated_at_is_detected(self):
        def mutate(ep, count, data):
            if ep == 'graphql' and count == 2:
                data['data']['repository']['pullRequest']['reviews']['nodes'][0]['state'] = 'DISMISSED'
            return data
        snap, calls = collect(mutate)
        result = policy.analyze_v2(snap)['pull_requests'][0]
        self.assertNotEqual(result['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(result['reviews']['independent_approvals'], [])
        self.assertEqual(snap['pulls'][0]['stable'].get('error', {}).get('code'), 'REVIEWS_CHANGED')
        self.assertEqual(calls['graphql'], 2)

    def test_new_comment_is_scoped_unknown_and_keeps_base_proof(self):
        def mutate(ep, count, data):
            if ep == 'graphql' and count == 2:
                pr = data['data']['repository']['pullRequest']
                pr['comments']['nodes'] = [{'databaseId': 89, 'body': 'security concern',
                    'url': 'https://github.com/owner/project/pull/101#issuecomment-89',
                    'createdAt': '2026-11-04T01:00:00Z', 'updatedAt': '2026-11-04T01:00:00Z',
                    'author': {'login': 'reviewer', '__typename': 'User'}}]
                pr['comments']['totalCount'] = 1
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertEqual(snap['pulls'][0]['stable'].get('error', {}).get('code'), 'DISCUSSION_CHANGED')
        result = policy.analyze_v2(snap)['pull_requests'][0]
        self.assertEqual(result['base_validation']['state'], 'INTEGRATION_CURRENT')
        self.assertNotEqual(result['readiness_stage'], 'READY_FOR_MERGE')

    def test_closing_review_timeout_does_not_reuse_approval(self):
        def mutate(ep, count, data):
            return subprocess.TimeoutExpired('gh', 1) if ep == 'graphql' and count == 2 else data
        snap, _ = collect(mutate)
        result = policy.analyze_v2(snap)['pull_requests'][0]
        self.assertEqual(result['reviews']['independent_approvals'], [])
        self.assertNotEqual(result['readiness_stage'], 'READY_FOR_MERGE')

    def test_late_change_after_per_pr_closeout_is_not_ignored(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls') and count == 2:
                data[0]['updated_at'] = '2026-11-04T03:00:00Z'
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertEqual(snap['pulls'][0]['stable'].get('error', {}).get('code'), 'LATE_PR_CHANGE')

    def test_body_edit_is_material_even_when_timestamp_does_not_change(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls/101') and count == 2:
                data['body'] = 'Depends-On: #102'
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['pulls'][0]['stable'].get('error', {}).get('code'), 'METADATA_CHANGED')


class ReliabilityTests(unittest.TestCase):
    def test_batched_job_metadata_preserves_each_log_and_reduces_calls(self):
        snap, calls = collect()
        self.assertEqual(sum(v for k, v in calls.items() if '/actions/jobs/' in k and not k.endswith('/logs')), 0)
        self.assertEqual(sum(v for k, v in calls.items() if '/attempts/' in k), 2)
        self.assertEqual(sum(v for k, v in calls.items() if k.endswith('/logs')), 4)
        self.assertEqual(len(snap['pulls'][0]['execution_proofs']), 4)
        self.assertEqual(policy.analyze_v2(snap)['pull_requests'][0]['readiness_stage'], 'READY_FOR_MERGE')

    def test_wrong_attempt_in_batched_job_metadata_is_rejected(self):
        def mutate(ep, count, data):
            if '/attempts/' in ep:
                data['jobs'][0]['run_attempt'] = 99
            return data
        snap, _ = collect(mutate)
        self.assertNotEqual(policy.analyze_v2(snap)['pull_requests'][0]['readiness_stage'], 'READY_FOR_MERGE')

    def test_incomplete_job_list_cannot_supply_success_proofs(self):
        def mutate(ep, count, data):
            if '/attempts/' in ep:
                data['total_count'] += 1
            return data
        snap, _ = collect(mutate)
        self.assertTrue(all(v['state'] == 'UNKNOWN' for v in snap['pulls'][0]['execution_proofs'].values()))

    def test_request_reserve_keeps_closing_inventory_available(self):
        snap, calls = collect(max_requests=23)
        self.assertEqual(calls['repos/owner/project/pulls'], 2)
        self.assertEqual(snap['inventory_stable'], source.known(True))
        self.assertTrue(any(v.get('error', {}).get('code') == 'EXECUTION_BUDGET_RESERVED'
                            for v in snap['pulls'][0]['execution_proofs'].values()))
        self.assertNotEqual(policy.analyze_v2(snap)['pull_requests'][0]['readiness_stage'], 'READY_FOR_MERGE')

    def test_metrics_count_actual_requests_and_do_not_contain_payloads(self):
        snap, calls = collect()
        metrics = snap.get('collection_metrics', {})
        self.assertEqual(metrics.get('requests'), sum(calls.values()))
        self.assertEqual(sum(v['requests'] for v in metrics['by_category'].values()), snap['request_count'])
        self.assertNotIn('body', json.dumps(metrics))

    def test_budget_diagnostics_distinguish_deadline_and_request_limit(self):
        for settings, cause in [({'max_requests': 0}, 'REQUEST_LIMIT'), ({'deadline': 0}, 'DEADLINE')]:
            result = source.GitHub(**settings).get('user')
            self.assertEqual(result.get('error', {}).get('cause'), cause)

    def test_review_bundle_missing_connection_and_partial_errors_fail_closed(self):
        for broken in ('missing', 'partial', 'count', 'duplicate'):
            def mutate(ep, count, data):
                if ep == 'graphql':
                    pr = data['data']['repository']['pullRequest']
                    if broken == 'missing':
                        pr.pop('reviews')
                    elif broken == 'partial':
                        data['errors'] = [{'message': 'hidden'}]
                    elif broken == 'count':
                        pr['reviews']['totalCount'] += 1
                    else:
                        pr['reviews']['nodes'] *= 2
                        pr['reviews']['totalCount'] = 2
                return data
            snap, _ = collect(mutate)
            self.assertNotEqual(policy.analyze_v2(snap)['pull_requests'][0]['readiness_stage'], 'READY_FOR_MERGE')

    def test_two_collections_do_not_share_cached_evidence(self):
        _, first = collect()
        _, second = collect()
        self.assertEqual(first, second)
        self.assertEqual(second['graphql'], 2)


class ReportDiagnosticsTests(unittest.TestCase):
    def test_report_exposes_scoped_reasons_and_metrics_without_changing_schema(self):
        def mutate(ep, count, data):
            if ep == 'graphql' and count == 2:
                data['data']['repository']['pullRequest']['reviews']['nodes'][0]['state'] = 'DISMISSED'
            return data
        snap, _ = collect(mutate)
        result = policy.analyze_v2(snap)
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result.get('collection_diagnostics'), snap['collection_diagnostics'])
        self.assertEqual(result.get('collection_metrics'), snap['collection_metrics'])
        self.assertEqual(result['pull_requests'][0].get('stability'), snap['pulls'][0]['stability'])
        import reporting
        rendered = reporting.render(result)
        self.assertIn('REVIEWS_CHANGED', rendered)
        self.assertIn('استدعاءات API', rendered)

    def test_inventory_order_only_is_not_a_change(self):
        from stability import inventory_observation
        self.assertEqual(inventory_observation(source.known([{'number': 2}, {'number': 1}])),
                         inventory_observation(source.known([{'number': 1}, {'number': 2}])))

    def test_duplicate_inventory_numbers_are_not_a_complete_inventory(self):
        def mutate(ep, count, data):
            if ep.endswith('/pulls') and count == 2:
                data *= 2
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable']['state'], 'UNKNOWN')

    def test_rate_limit_stops_requests_and_never_authorizes_merge(self):
        def mutate(ep, count, data):
            if ep == 'graphql':
                return subprocess.CompletedProcess([], 1, '{"message":"API rate limit exceeded","status":"403"}', '')
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['inventory_stable']['state'], 'UNKNOWN')
        result = policy.analyze_v2(snap)
        self.assertTrue(all(not p['merge_authorized'] and p['readiness_stage'] != 'READY_FOR_MERGE'
                            for p in result['pull_requests']))


class BoundaryTests(unittest.TestCase):
    def test_review_bundle_paginates_and_rejects_cursor_cycles(self):
        from review_evidence import collect_reviews
        raw = routes()['graphql']
        first = copy.deepcopy(raw)
        connection = first['data']['repository']['pullRequest']['reviews']
        connection.update(totalCount=2, pageInfo={'hasNextPage': True, 'endCursor': 'cursor-1'})
        second = copy.deepcopy(raw)
        connection = second['data']['repository']['pullRequest']['reviews']
        connection.update(totalCount=2)
        connection['nodes'][0]['databaseId'] += 1
        gh = source.GitHub()
        with patch.object(gh, 'graphql', side_effect=[source.known(first), source.known(second)]) as call:
            result = collect_reviews(gh, 'owner/project', 101)
            self.assertEqual(len(result['data']['reviews']), 2)
            self.assertNotIn('reviewThreads(', call.call_args_list[1].args[0])
        with patch.object(gh, 'graphql', return_value=source.known(first)):
            self.assertEqual(collect_reviews(gh, 'owner/project', 101)['state'], 'UNKNOWN')

    def test_unreadable_nested_thread_never_becomes_clear(self):
        def mutate(ep, count, data):
            if ep == 'graphql':
                connection = data['data']['repository']['pullRequest']['reviewThreads']
                connection.update(totalCount=1, nodes=[{'id': 't', 'isResolved': False, 'isOutdated': False,
                    'comments': {'pageInfo': {'hasNextPage': True}, 'nodes': []}}])
            return data
        snap, _ = collect(mutate)
        self.assertEqual(snap['pulls'][0]['threads']['state'], 'UNKNOWN')
        self.assertNotEqual(policy.analyze_v2(snap)['pull_requests'][0]['readiness_stage'], 'READY_FOR_MERGE')

    def test_duplicate_jobs_and_denied_batch_never_fall_back_to_cached_success(self):
        for mode in ('duplicate', 'denied'):
            def mutate(ep, count, data):
                if '/attempts/' in ep:
                    if mode == 'denied':
                        return subprocess.CompletedProcess([], 1, '{"status":"403"}', '')
                    data['jobs'].append(data['jobs'][0])
                    data['total_count'] += 1
                return data
            snap, calls = collect(mutate)
            self.assertTrue(all(p['state'] == 'UNKNOWN' for p in snap['pulls'][0]['execution_proofs'].values()))
            self.assertEqual(sum(v for k, v in calls.items() if k.endswith('/logs')), 0)

    def test_deadline_reserve_limits_timeout_and_is_released_for_closeout(self):
        gh = source.GitHub(timeout=20, deadline=100)
        gh.reserve_seconds = 10
        with patch('github_source.time.monotonic', return_value=gh.deadline - 12), patch(
                'github_source.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            gh.get('user')
            self.assertEqual(run.call_args.kwargs['timeout'], 2)
        with patch('github_source.time.monotonic', return_value=gh.deadline - 8), patch(
                'github_source.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            self.assertEqual(gh.get('user')['error']['code'], 'EXECUTION_BUDGET_RESERVED')
            run.assert_not_called()
            gh.reserve_seconds = 0
            self.assertEqual(gh.get('user')['state'], 'KNOWN')

    def test_one_changed_pr_does_not_revoke_unrelated_candidate(self):
        from test_v2 import snapshot
        from stability import close_inventory
        snap = snapshot()
        entry = snap['pulls'][0]
        entry['number'] = 101
        entry['closing_detail'] = copy.deepcopy(entry['detail'])
        sibling = copy.deepcopy(entry)
        sibling['number'] = sibling['detail']['data']['number'] = 102
        sibling['detail']['data']['head']['ref'] = 'other'
        for run in sibling['runs']['data']:
            run['pull_requests'] = [{'number': 102}]
        sibling['closing_detail'] = copy.deepcopy(sibling['detail'])
        snap['pulls'].append(sibling)
        snap['discovery'] = source.known([copy.deepcopy(e['detail']['data']) for e in snap['pulls']])
        final = copy.deepcopy(snap['discovery'])
        final['data'][0]['head']['sha'] = 'f' * 40
        close_inventory(snap, final)
        by_id = {p['number']: p for p in policy.analyze_v2(snap)['pull_requests']}
        self.assertNotEqual(by_id[101]['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(by_id[102]['readiness_stage'], 'READY_FOR_MERGE')
        self.assertFalse(by_id[102]['merge_authorized'])


class CauseTests(unittest.TestCase):
    def test_base_change_and_unavailable_base_are_distinct(self):
        for failure in (False, True):
            def mutate(ep, count, data):
                if ep.endswith('/branches/main') and count == 2:
                    if failure:
                        return subprocess.TimeoutExpired('gh', 1)
                    data['commit']['sha'] = 'e' * 40
                return data
            snap, _ = collect(mutate)
            self.assertEqual(snap['pulls'][0]['stable']['error']['code'],
                             'BASE_BRANCH_UNAVAILABLE' if failure else 'BASE_BRANCH_CHANGED')

    def test_closing_pr_failure_retains_endpoint_cause(self):
        def mutate(ep, count, data):
            return subprocess.TimeoutExpired('gh', 1) if ep.endswith('/pulls/101') and count == 2 else data
        snap, _ = collect(mutate)
        result = snap['pulls'][0]['stable']
        self.assertEqual(result['error']['code'], 'REFS_UNAVAILABLE')
        self.assertEqual(result.get('observations', {}).get('after', {}).get('error', {}).get('code'), 'TIMEOUT')


if __name__ == '__main__':
    unittest.main()
