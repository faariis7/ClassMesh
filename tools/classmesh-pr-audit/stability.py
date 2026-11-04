"""Scoped stability checks. Membership is separate from evidence freshness."""
import re

from github_source import is_known, known, unknown


def refs(pr):
    try:
        result = tuple(pr[k][f] for k in ('head', 'base') for f in ('ref', 'sha'))
        if any(not isinstance(v, str) or not v for v in result):
            return None
        if any(not re.fullmatch('[0-9a-f]{40}', pr[k]['sha']) for k in ('head', 'base')):
            return None
        return result + (pr['head']['repo']['full_name'], pr['base']['repo']['full_name'], pr.get('merge_commit_sha'))
    except (KeyError, TypeError):
        return None


def status(before, after, signature, changed, unavailable):
    if not is_known(before) or not is_known(after):
        result = unknown(unavailable, 'stability')
        result['observations'] = {key: {k: v for k, v in (value or {}).items() if k != 'data'}
                                  for key, value in [('before', before), ('after', after)]}
        return result
    left, right = signature(before['data']), signature(after['data'])
    if left is None or right is None:
        return unknown(unavailable, 'stability')
    return known(True) if left == right else unknown(changed, 'stability')


def branch_sha(value):
    try:
        sha = value['commit']['sha']
        return sha if isinstance(sha, str) and re.fullmatch('[0-9a-f]{40}', sha) else None
    except (KeyError, TypeError):
        return None


def metadata(pr):
    if not isinstance(pr, dict) or type(pr.get('draft')) is not bool or pr.get('state') not in ('open', 'closed'):
        return None
    # Title is presentation. Body can carry dependencies/security claims.
    return [pr.get(k) for k in ('body', 'draft', 'state', 'mergeable', 'mergeable_state',
                               'requested_reviewers', 'requested_teams', 'labels')]


def close_entry(entry, after, bundle):
    before = entry['detail']
    ref_state = status(before, after, refs, 'REFS_CHANGED', 'REFS_UNAVAILABLE')
    initial_refs = refs(entry['initial'])
    if initial_refs is None or (is_known(before) and initial_refs != refs(before['data'])):
        ref_state = unknown('REFS_CHANGED_OR_UNAVAILABLE', 'initial inventory')
    changes = {'refs': ref_state,
               'metadata': status(before, after, metadata, 'METADATA_CHANGED', 'METADATA_UNAVAILABLE')}
    for key, code in [('reviews', 'REVIEWS_CHANGED'), ('threads', 'REVIEWS_CHANGED'), ('comments', 'DISCUSSION_CHANGED')]:
        later = known(bundle['data'][key]) if is_known(bundle) else bundle
        changes[key] = status(entry[key], later, lambda data: data, code, 'REVIEW_DATA_UNAVAILABLE')
        if not is_known(changes[key]):
            # Retain the latest observation for diagnostics, never count it as a
            # stable approval/security clearance when it changed mid-collection.
            entry[key] = unknown(code if is_known(later) else later['error']['code'], key, later.get('data'))
    entry['stability'] = changes
    entry['refs_stable'] = ref_state
    entry['stable'] = next((s for s in changes.values() if not is_known(s)), known(True))
    entry['closing_detail'] = after


def inventory_observation(value):
    if not is_known(value):
        return {k: v for k, v in value.items() if k != 'data'}
    rows = value['data']
    if (not isinstance(rows, list) or any(not isinstance(p, dict) or type(p.get('number')) is not int
            or p['number'] <= 0 for p in rows)):
        return unknown('INVALID_INVENTORY', 'pulls')
    ids = [p['number'] for p in rows]
    if len(ids) != len(set(ids)):
        return unknown('DUPLICATE_PR_NUMBER', 'pulls')
    return known(sorted(ids))


def close_inventory(snapshot, last):
    before = inventory_observation(snapshot['discovery'])
    after = inventory_observation(last)
    diagnostics = {'before': before, 'after': after, 'added': [], 'removed': []}
    if not is_known(before) or not is_known(after):
        stable = unknown('INVENTORY_UNAVAILABLE', 'pulls')
    else:
        diagnostics.update(added=sorted(set(after['data']) - set(before['data'])),
                           removed=sorted(set(before['data']) - set(after['data'])))
        stable = (unknown('INVENTORY_MEMBERSHIP_CHANGED', 'pulls') if diagnostics['added'] or diagnostics['removed']
                  else known(True))
        closing = {p['number']: p for p in last['data']}
        for entry in snapshot['pulls']:
            observed = entry.get('closing_detail', {})
            final = closing.get(entry['number'])
            if not is_known(observed) or final is None:
                continue
            ref_state = status(observed, known(final), refs, 'REFS_CHANGED', 'REFS_UNAVAILABLE')
            if not is_known(ref_state):
                entry['refs_stable'] = entry['stable'] = ref_state
                entry.setdefault('stability', {})['final_refs'] = ref_state
            elif (not isinstance(final.get('updated_at'), str)
                    or final['updated_at'] != observed['data'].get('updated_at')
                    or any(final.get(k) != observed['data'].get(k) for k in ('body', 'draft', 'state'))):
                late = unknown('LATE_PR_CHANGE', 'closing inventory')
                entry.setdefault('stability', {})['late_change'] = late
                if is_known(entry.get('stable')):
                    entry['stable'] = late
    snapshot['inventory_stable'] = stable
    snapshot['collection_diagnostics'] = {'inventory': diagnostics}
