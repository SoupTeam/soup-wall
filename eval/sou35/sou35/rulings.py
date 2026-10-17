"""Pool-bound semantic decision register. Recorded decisions are NOT authenticated signatures.

The register is private custodian material. Only an externally verifiable human decision may
be entered as ``accepted``. This file is NOT a Gold addendum and does not promote labels.
"""
from . import adapters, custody

VERSION = 'sou35-semantic-rulings-v1'
SCOPE = 'sou35_synthetic_candidate_pool'
STATUSES = frozenset({'accepted', 'pending', 'rejected'})


def digest(register):
    return adapters.sha(register)


def errors(register, decls):
    if not isinstance(register, dict):
        return ['semantic rulings register is required']
    e = []
    if register.get('version') != VERSION or register.get('scope') != SCOPE:
        e.append('semantic rulings register version/scope mismatch')
    if register.get('pool_digest') != custody.pool_digest(decls):
        e.append('semantic rulings register is not bound to the current pool')
    ds = register.get('decisions')
    if not isinstance(ds, list):
        return e + ['decisions must be a list']
    seen = set()
    for d in ds:
        if not isinstance(d, dict) or not isinstance(d.get('question_id'), str) or not d['question_id']:
            e.append('invalid semantic question entry')
            continue
        question = d['question_id']
        if question in seen:
            e.append('duplicate semantic question decision')
        seen.add(question)
        if d.get('status') not in STATUSES:
            e.append('invalid semantic decision status')
        if d.get('status') == 'accepted':
            fields = ('reviewed_by', 'reviewed_at', 'decision_ref')
            if not all(isinstance(d.get(k), str) and d[k].strip() for k in fields):
                e.append('accepted decision requires external human decision metadata')
            elif d['reviewed_by'].lower().startswith('ai_assisted'):
                e.append('AI assistant cannot accept a semantic ruling')
    reviews = register.get('reviewed_cases')
    if not isinstance(reviews, list):
        e.append('case-level evidence review attestations are required')
    else:
        ids = set()
        for item in reviews:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
                e.append('invalid reviewed case entry')
                continue
            if item['id'] in ids:
                e.append('duplicate reviewed case id')
            ids.add(item['id'])
            if item.get('status') != 'accepted':
                e.append('reviewed case entry must be accepted')
            if not (isinstance(item.get('row_sha256'), str) and custody.HEX64.match(item['row_sha256'])):
                e.append('reviewed case is missing its exact record digest')
            fields = ('reviewed_by', 'reviewed_at', 'decision_ref')
            if not all(isinstance(item.get(k), str) and item[k].strip() for k in fields):
                e.append('reviewed case needs an external reviewer decision reference')
            elif item['reviewed_by'].lower().startswith('ai_assisted'):
                e.append('AI assistant cannot independently review case evidence')
    return e


def unresolved(record, register):
    """Return unresolved question IDs; output must remain owner-only when it names questions."""
    decisions = {d['question_id']: d for d in register['decisions']}
    issues = [q for q in record['open_questions']
              if q not in decisions or decisions[q]['status'] != 'accepted']
    by_id = {d['id']: d for d in register.get('reviewed_cases', [])}
    case_review = by_id.get(record['id'], {})
    if case_review.get('row_sha256') != adapters.sha(record) or case_review.get('status') != 'accepted':
        issues.append('unreviewed_case_evidence')
    return issues


def is_admissible(record, register):
    return not unresolved(record, register)


def excluded_from_primary_scoring(record):
    """V3 P0: unmodelled-mode *full* unknown stays diagnostic, never primary-scored.

    Do not exclude partial unknowns with established actions. This predicate is an
    eligibility safeguard, NOT a human semantic ruling or a declaration of Gold.
    Private candidate coverage is verified by an owner-only preflight, not embedded here.
    Future equivalent cases are deliberately fail-closed pending their own adjudication.
    """
    if record.get('expected_outcome') != 'classification':
        return False
    if 'Q-S35-UNMODELLED-MODE' not in record.get('open_questions', ()):
        return False
    if 'unmodelled_mode' not in record.get('scenario_tags', ()):
        return False
    annotation = record.get('annotation') or {}
    targets = annotation.get('per_action_targets')
    actions = ('read', 'write', 'delete', 'send_data', 'change_permissions')
    return (annotation.get('unknown') is True and isinstance(targets, dict)
            and set(targets) == set(actions)
            and all(targets[action] is None for action in actions))


def primary_scoring_admissible(record, register):
    """Requires independent human case evidence AND the SOU-35 primary-scoring policy."""
    return not excluded_from_primary_scoring(record) and is_admissible(record, register)
