"""One paginated GraphQL observation of reviews, threads and issue comments.

No cache: the closing observation must reach GitHub again. Connections are
bounded separately; a partial/hidden/malformed connection invalidates the bundle.
"""
import json

from github_source import is_known, known, unknown

FIELDS = {
    'reviews': 'databaseId state body url submittedAt updatedAt commit { oid } author { login __typename }',
    'comments': 'databaseId body url createdAt updatedAt author { login __typename }',
    'reviewThreads': '''id isResolved isOutdated comments(first: 100) {
        pageInfo { hasNextPage } nodes { body url createdAt updatedAt author { login } }
    }''',
}


def collect_reviews(gh, repo, number):
    owner, name = repo.split('/')
    rows = {key: [] for key in FIELDS}
    cursors = {key: None for key in FIELDS}
    seen = {key: set() for key in FIELDS}
    counts = {}
    decision = None
    for page_number in range(gh.max_pages):
        parts = [f'{key}(first: 100, after: {json.dumps(cursor)}) {{ totalCount '
                 f'pageInfo {{ hasNextPage endCursor }} nodes {{ {FIELDS[key]} }} }}'
                 for key, cursor in cursors.items()]
        query = ('query { repository(owner: ' + json.dumps(owner) + ', name: ' + json.dumps(name)
                 + ') { pullRequest(number: ' + str(number) + ') { reviewDecision '
                 + ' '.join(parts) + ' } } }')
        response = gh.graphql(query)
        if not is_known(response):
            return response
        try:
            pr = response['data']['data']['repository']['pullRequest']
            if page_number and decision != pr['reviewDecision']:
                return unknown('REVIEW_DECISION_CHANGED', 'review bundle')
            decision = pr['reviewDecision']
            for key in list(cursors):
                connection = pr[key]
                count, nodes, page = connection['totalCount'], connection['nodes'], connection['pageInfo']
                if (type(count) is not int or count < 0 or counts.get(key, count) != count
                        or not isinstance(nodes, list) or any(not isinstance(n, dict) for n in nodes)):
                    raise ValueError
                counts[key] = count
                rows[key].extend(nodes)
                if len(rows[key]) > count:
                    raise ValueError
                if page['hasNextPage'] is False:
                    if len(rows[key]) != count:
                        return unknown('TRUNCATED_RESPONSE', key)
                    del cursors[key]
                else:
                    cursor = page['endCursor']
                    if (page['hasNextPage'] is not True or not nodes or not isinstance(cursor, str)
                            or not cursor or cursor in seen[key]):
                        raise ValueError
                    seen[key].add(cursor)
                    cursors[key] = cursor
            if not cursors:
                return normalize(rows, decision)
        except (KeyError, TypeError, ValueError, AttributeError):
            return unknown('INVALID_RESPONSE', 'review bundle')
    return unknown('PAGE_LIMIT', 'review bundle')


def normalize(rows, decision):
    try:
        # Duplicate IDs can hide a missing approval/dismissal across pages.
        for key, items in rows.items():
            ids = [n['id' if key == 'reviewThreads' else 'databaseId'] for n in items]
            if any(i is None for i in ids) or len(ids) != len(set(ids)):
                raise ValueError
        reviews, comments, threads = [], [], []
        for key, target in [('reviews', reviews), ('comments', comments)]:
            for node in rows[key]:
                if not isinstance(node['body'], str) or not isinstance(node['updatedAt'], str):
                    raise ValueError
                author = node['author'] or {}
                row = {'id': node['databaseId'], 'body': node['body'], 'html_url': node['url'],
                       'updated_at': node['updatedAt'],
                       'user': {'login': author.get('login'), 'type': author.get('__typename')}}
                if key == 'reviews':
                    row.update(state=node['state'], submitted_at=node['submittedAt'],
                               commit_id=(node['commit'] or {}).get('oid'))
                else:
                    row['created_at'] = node['createdAt']
                target.append(row)
        for node in rows['reviewThreads']:
            if node['comments']['pageInfo']['hasNextPage'] is not False:
                return unknown('THREAD_COMMENTS_TRUNCATED', 'review bundle')
            threads.append(dict(node, comments=node['comments']['nodes']))
        # Order of API pages is not evidence of a semantic change.
        return known({'reviews': sorted(reviews, key=lambda r: r['id']),
                      'comments': sorted(comments, key=lambda r: r['id']),
                      'threads': {'review_decision': decision, 'threads': sorted(threads, key=lambda t: t['id'])}})
    except (KeyError, TypeError, ValueError, AttributeError):
        return unknown('INVALID_RESPONSE', 'review bundle')
