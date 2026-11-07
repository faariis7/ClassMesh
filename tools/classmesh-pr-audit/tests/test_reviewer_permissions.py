"""A stable APPROVED review cannot reuse an opening permission observation."""
import copy
import subprocess
import unittest
from unittest.mock import patch

import test_v21
from test_v21 import collect, routes, source, policy

PERMISSION = 'repos/owner/project/collaborators/independent/permission'


def result(snapshot):
    return policy.analyze_v2(snapshot)['pull_requests'][0]


def permission_state(snapshot, login='independent'):
    return snapshot['pulls'][0].get('stability', {}).get('reviewer_permission:' + login, {})


def two_reviewers(second='second'):
    data = routes()
    connection = data['graphql']['data']['repository']['pullRequest']['reviews']
    review = copy.deepcopy(connection['nodes'][0])
    review['databaseId'] += 1
    review['author']['login'] = second
    connection['nodes'].append(review)
    connection['totalCount'] = 2
    data['repos/owner/project/collaborators/' + second + '/permission'] = {'permission': 'write'}
    return data


class ReviewerPermissionTests(unittest.TestCase):
    def test_write_to_read_with_same_head_and_approved_review_cannot_merge(self):
        def mutate(ep, count, data):
            if ep == PERMISSION and count == 2:
                data['permission'] = 'read'
            return data
        snapshot, calls = collect(mutate)
        pr = result(snapshot)
        self.assertNotEqual(pr['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(pr['reviews']['independent_approvals'], [])
        self.assertFalse(pr['merge_authorized'])
        self.assertEqual(calls[PERMISSION], 2)
        state = permission_state(snapshot)
        self.assertEqual(state['error']['code'], 'REVIEWER_PERMISSION_CHANGED')
        self.assertEqual(state['observations']['before']['data'], 'write')
        self.assertEqual(state['observations']['after']['data'], 'read')
        self.assertEqual(pr['base_validation']['state'], 'INTEGRATION_CURRENT')

    def test_closing_api_failure_retains_cause_and_never_uses_opening_permission(self):
        for failure, code in [(subprocess.TimeoutExpired('gh', 1), 'TIMEOUT'),
                (subprocess.CompletedProcess([], 1, '{"status":"403"}', ''), 'FORBIDDEN')]:
            with self.subTest(code=code):
                def mutate(ep, count, data):
                    return failure if ep == PERMISSION and count == 2 else data
                snapshot, calls = collect(mutate)
                self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')
                self.assertEqual(result(snapshot)['reviews']['independent_approvals'], [])
                state = permission_state(snapshot)
                self.assertEqual(state['error']['code'], 'REVIEWER_PERMISSION_UNAVAILABLE')
                self.assertEqual(state['observations']['after']['error']['code'], code)
                self.assertEqual(calls[PERMISSION], 2)

    def test_unchanged_write_is_revalidated_and_still_counts(self):
        snapshot, calls = collect()
        self.assertEqual(calls[PERMISSION], 2)
        self.assertEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')
        self.assertFalse(result(snapshot)['merge_authorized'])
        self.assertEqual(permission_state(snapshot).get('eligibility'), 'ELIGIBLE')

    def test_unchanged_insufficient_permission_is_distinct_from_unknown(self):
        def mutate(ep, count, data):
            return {'permission': 'read'} if ep == PERMISSION else data
        snapshot, _ = collect(mutate)
        pr = result(snapshot)
        self.assertEqual(pr['reviews']['independent_approvals'], [])
        self.assertNotEqual(pr['readiness_stage'], 'READY_FOR_MERGE')
        state = permission_state(snapshot)
        self.assertEqual(state.get('state'), 'KNOWN')
        self.assertEqual(state.get('eligibility'), 'INSUFFICIENT')
        self.assertNotIn('error', state)
        import reporting
        self.assertIn('INSUFFICIENT', reporting.render(policy.analyze_v2(snapshot)))

    def test_changed_permission_is_unknown_even_if_both_roles_allow_approval(self):
        def mutate(ep, count, data):
            return {'permission': 'admin'} if ep == PERMISSION and count == 2 else data
        snapshot, _ = collect(mutate)
        self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(permission_state(snapshot).get('eligibility'), 'UNKNOWN')

    def test_multiple_reviewers_revalidate_separately_without_reviving_revoked_approval(self):
        def mutate(ep, count, data):
            return {'permission': 'read'} if ep == PERMISSION and count == 2 else data
        with patch.object(test_v21, 'routes', return_value=two_reviewers()):
            snapshot, calls = collect(mutate)
        pr = result(snapshot)
        self.assertEqual(pr['reviews']['independent_approvals'], ['second'])
        self.assertNotEqual(pr['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(calls[PERMISSION], 2)
        self.assertEqual(calls['repos/owner/project/collaborators/second/permission'], 2)

    def test_shared_reviewer_across_prs_has_one_request_per_phase(self):
        payloads = routes()
        pr = copy.deepcopy(payloads['repos/owner/project/pulls/101'])
        pr['number'] = 102
        pr['head']['ref'] = 'another-feature'
        pr['html_url'] = 'https://github.com/owner/project/pull/102'
        payloads['repos/owner/project/pulls'].append(pr)
        payloads['repos/owner/project/pulls/102'] = pr
        payloads['repos/owner/project/pulls/102/files'] = payloads['repos/owner/project/pulls/101/files']
        for run in payloads['repos/owner/project/actions/runs']['workflow_runs']:
            run['pull_requests'].append({'number': 102})
        def mutate(ep, count, data):
            return {'permission': 'read'} if ep == PERMISSION and count == 2 else data
        with patch.object(test_v21, 'routes', return_value=payloads):
            snapshot, calls = collect(mutate)
        self.assertEqual(calls[PERMISSION], 2)
        prs = policy.analyze_v2(snapshot)['pull_requests']
        self.assertEqual(len(prs), 2)
        self.assertTrue(all(p['readiness_stage'] != 'READY_FOR_MERGE' and not p['merge_authorized'] for p in prs))
        self.assertTrue(all(p['reviews']['independent_approvals'] == [] for p in prs))

    def test_case_variants_share_phase_cache(self):
        with patch.object(test_v21, 'routes', return_value=two_reviewers('Independent')):
            snapshot, calls = collect()
        permission_calls = sum(count for ep, count in calls.items() if '/collaborators/' in ep)
        self.assertEqual(permission_calls, 2)
        self.assertEqual(permission_state(snapshot).get('eligibility'), 'ELIGIBLE')
        self.assertEqual(permission_state(snapshot, 'Independent').get('eligibility'), 'ELIGIBLE')

    def test_initial_failure_cannot_be_erased_by_successful_closing_read(self):
        def mutate(ep, count, data):
            return subprocess.CompletedProcess([], 1, '{"status":"403"}', '') if ep == PERMISSION and count == 1 else data
        snapshot, calls = collect(mutate)
        self.assertEqual(calls[PERMISSION], 2)
        self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')
        self.assertEqual(permission_state(snapshot)['observations']['before']['error']['code'], 'FORBIDDEN')

    def test_malformed_closing_permission_is_unknown(self):
        for payload in ({}, {'permission': 'new-unrecognized-role'}, {'permission': None}):
            def mutate(ep, count, data):
                return payload if ep == PERMISSION and count == 2 else data
            snapshot, _ = collect(mutate)
            self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')
            self.assertEqual(permission_state(snapshot)['observations']['after']['error']['code'], 'INVALID_REVIEWER_PERMISSION')

    def test_reserved_budget_includes_permission_closeout(self):
        snapshot, calls = collect(max_requests=23)
        self.assertEqual(calls[PERMISSION], 2)
        self.assertEqual(snapshot['inventory_stable'], source.known(True))
        self.assertEqual(permission_state(snapshot).get('eligibility'), 'ELIGIBLE')
        self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')

    def test_permission_cache_does_not_survive_collection(self):
        _, first_calls = collect()
        def mutate(ep, count, data):
            return {'permission': 'read'} if ep == PERMISSION else data
        snapshot, second_calls = collect(mutate)
        self.assertEqual((first_calls[PERMISSION], second_calls[PERMISSION]), (2, 2))
        self.assertEqual(permission_state(snapshot).get('eligibility'), 'INSUFFICIENT')
        self.assertNotEqual(result(snapshot)['readiness_stage'], 'READY_FOR_MERGE')


if __name__ == '__main__':
    unittest.main()
