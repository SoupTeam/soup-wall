"""Explicit, private import of an already approved family-rule review.

Prepare validates the original SHA-pinned handoff and exact record mappings; it
does NOT approve anything. Apply needs one external human attestation covering
the plan, evidence profile and independence from generation. It transcribes
group decisions into a NEW v2 ledger, without claiming manual per-record review.
No split, draw, freeze, scoring, export or training is performed.

Digests bind recorded claims; they do not authenticate a human or replace the
custodian's verification of the external decision reference.
"""
import argparse
import copy
import io
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

from . import adapters, check_pool, custody, families, records, rulings
from .manifest import record_inventory_digest

PLAN_VERSION = 'sou35-group-review-plan-v1'
AUTH_VERSION = 'sou35-group-review-authorization-v1'
METHOD = 'human_family_rules_with_exact_record_mapping'
MAX_JSON = 4 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MEMBERS = 128


class GroupReviewError(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise GroupReviewError(message)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _json(data):
    _require(len(data) <= MAX_JSON, 'JSON exceeds size limit')
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(GroupReviewError('non-finite JSON')))


def _read(path, limit=MAX_JSON):
    with Path(path).open('rb') as file:
        data = file.read(limit + 1)
    _require(len(data) <= limit, 'input exceeds size limit')
    return data


def _signed(body, key='plan_sha256'):
    return {**body, key: adapters.sha(body)}


def _valid_digest(value):
    return isinstance(value, str) and custody.HEX64.fullmatch(value) is not None


def prepare(register, decls, recs, package_bytes, expected_sha256, *, policy=rulings.ELIGIBILITY_POLICY):
    """Return an exact, counts-only-by-default import plan. All case detail is PRIVATE.

    The real handoff's AI mapping is a proposal until explicitly adopted by the
    human authorization in apply. Preparing this plan never sets independence.
    """
    _require(policy in rulings.ELIGIBILITY_POLICIES, 'unknown evidence profile')
    _require(register.get('version') == rulings.VERSION_V2, 'group import requires a v2 source ledger')
    _require('group_review_import' not in register, 'start from the preserved source ledger, not a prior import')
    rulings.load(register, decls, recs)
    _require(not records.dataset_errors(recs, decls), 'records do not validate against the pool')
    _require(len(package_bytes) <= MAX_ARCHIVE and _valid_digest(expected_sha256)
             and adapters.sha_bytes(package_bytes) == expected_sha256, 'review package digest/size mismatch')
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
        members = archive.infolist()
        names = [m.filename for m in members]
        _require(len(members) <= MAX_MEMBERS and len(names) == len(set(names))
                 and sum(m.file_size for m in members) <= MAX_ARCHIVE, 'ambiguous or oversized review archive')

        def member(basename):
            matches = [m for m in members if Path(m.filename).name == basename and not m.is_dir()]
            _require(len(matches) == 1 and matches[0].file_size <= MAX_JSON, 'missing/ambiguous review document')
            return archive.read(matches[0])

        packet = _json(member('SOU35-completed-human-family-review.private.json'))
        _require(packet.get('format') == 'sou35-completed-human-family-review/1'
                 and packet.get('status') == 'human_family_rule_review_complete'
                 and packet.get('reviewer_kind') == 'human'
                 and not rulings.is_ai_identity(packet.get('reviewer')), 'not an accepted human family-rule handoff')
        _require(packet.get('source', {}).get('record_inventory_sha256') == record_inventory_digest(recs),
                 'handoff inventory differs from current records')
        files = packet.get('group_decision_files')
        _require(isinstance(files, dict) and bool(files), 'handoff has no group decision inventory')
        by_id = {r['id']: r for r in recs}
        bound, documents = {}, {}
        for basename, sha in files.items():
            _require(isinstance(basename, str) and basename == Path(basename).name
                     and _valid_digest(sha), 'invalid review document inventory')
            data = member(basename)
            _require(adapters.sha_bytes(data) == sha, 'review document digest mismatch')
            doc = _json(data)
            _require(doc.get('format') == 'sou35-human-family-rule-decision/1'
                     and doc.get('status') == 'accepted_family_rules'
                     and doc.get('reviewer') == packet['reviewer'] and doc.get('reviewer_kind') == 'human',
                     'invalid or differently attributed family decision')
            did = doc.get('decision_id')
            _require(isinstance(did, str) and did and did not in documents, 'duplicate/invalid group decision')
            _require(isinstance(doc.get('decision_ref'), dict) and doc['decision_ref'].get('human_reply')
                     and isinstance(doc.get('rules'), list) and bool(doc['rules']), 'missing recorded human rule approval')
            documents[did] = {'sha256': sha, 'decision_ref': doc['decision_ref']}
            bindings = doc.get('record_bindings')
            _require(isinstance(bindings, list) and bindings, 'group has no exact record bindings')
            for binding in bindings:
                rid = binding.get('id') if isinstance(binding, dict) else None
                _require(isinstance(rid, str) and rid in by_id and rid not in bound,
                         'missing, duplicate or overlapping group record')
                row = by_id[rid]
                _require(row['family_id'] == doc.get('family_id')
                         and binding.get('row_sha256') == adapters.sha(row)
                         and binding.get('outcome') == row['expected_outcome']
                         and adapters.sha(binding.get('original_target_unchanged')) == adapters.sha(row['annotation']['contract_view']),
                         'group record, family, outcome or target mismatch')
                bound[rid] = did
    _require(set(bound) == set(by_id), 'handoff does not bind the complete current inventory')
    mappings = packet.get('case_mapping')
    _require(isinstance(mappings, list) and len(mappings) == len(by_id), 'missing complete case mapping')
    entries, seen = [], set()
    for mapping in mappings:
        rid = mapping.get('id') if isinstance(mapping, dict) else None
        _require(isinstance(rid, str) and rid in by_id and rid not in seen, 'invalid/duplicate case mapping')
        seen.add(rid)
        row = by_id[rid]
        _require(mapping.get('row_sha256') == adapters.sha(row)
                 and mapping.get('family_id') == row['family_id']
                 and mapping.get('human_decision_id') == bound[rid]
                 and mapping.get('outcome') == row['expected_outcome'], 'case mapping identity mismatch')
        prefix = 'strict_D04_ai' if policy == rulings.ELIGIBILITY_POLICY else 'selected_separate_profile'
        disposition = mapping.get(prefix + '_disposition')
        basis = mapping.get('strict_D04_ai_basis' if policy == rulings.ELIGIBILITY_POLICY
                            else 'selected_separate_profile_basis')
        if basis == 'interface_supported_only_under_separate_schema_semantics_profile':
            _require(policy == rulings.SCHEMA_SEMANTICS_POLICY, 'schema-only evidence cannot enter strict D04')
            basis = 'interface_supported'
        status = 'disputed' if disposition == rulings.DISPUTED else 'accepted'
        if row['expected_outcome'] == 'technical_error':
            _require(disposition == rulings.TECHNICAL and basis is None, 'technical row has semantic evidence')
        else:
            expected = {'primary_candidate': 'interface_supported', rulings.PROGRAM_ONLY: 'program_only',
                        rulings.INFORMATION_LIMITED: 'information_limited', rulings.DISPUTED: None}
            consistent = (basis in (None, 'information_limited') if disposition == rulings.DISPUTED
                          else disposition in expected and basis == expected[disposition])
            _require(consistent, 'unknown or inconsistent evidence disposition')
        entries.append({'id': rid, 'row_sha256': adapters.sha(row), 'group_decision_id': bound[rid],
                        'status': status, 'evidence_basis': basis,
                        'questions_considered': list(row['open_questions'])})
    return _signed({'version': PLAN_VERSION, 'review_method': METHOD, 'reviewer': packet['reviewer'],
                    'source_rulings_sha256': rulings.digest(register), 'review_package_sha256': expected_sha256,
                    'pool_digest': custody.pool_digest(decls), 'record_inventory_sha256': record_inventory_digest(recs),
                    'eligibility_policy': policy, 'group_decisions': documents,
                    'source_pending_ids': sorted(c['id'] for c in register['reviewed_cases'] if c['status'] == 'pending'),
                    'source_mapping_sha256': adapters.sha(mappings), 'entries': sorted(entries, key=lambda x: x['id']),
                    'limits': {'manual_per_record_human_review_claimed': False,
                               'freeze_draw_scoring_export_training_authorized': False}})


def authorization_errors(plan, auth):
    """Same human/independence requirements as v2; an AI import never invents them."""
    if not isinstance(auth, dict) or auth.get('version') != AUTH_VERSION:
        return ['external grouped-review authorization is required']
    if not isinstance(plan, dict):
        return ['invalid group import plan']
    e = rulings._human_decision_errors(auth, 'group review authorization')
    if (plan.get('version') != PLAN_VERSION or plan.get('plan_sha256') !=
            adapters.sha({k: v for k, v in plan.items() if k != 'plan_sha256'})):
        e.append('invalid group import plan')
    if auth.get('plan_sha256') != plan.get('plan_sha256'):
        e.append('authorization is not bound to the exact import plan')
    if auth.get('reviewed_by') != plan.get('reviewer'):
        e.append('authorization reviewer differs from group reviewer')
    if auth.get('independent_of_generation') is not True:
        e.append('group reviewer independence from generation must be explicitly attested')
    if auth.get('adopt_exact_group_mapping') is not True or auth.get('review_method') != METHOD:
        e.append('human adoption of this exact grouped mapping is required')
    if auth.get('eligibility_policy') != plan.get('eligibility_policy'):
        e.append('authorization does not acknowledge the evidence profile')
    return e


def apply(register, decls, recs, plan, authorization):
    """Transcribe into a distinct validated ledger; never edit inputs or override a prior decision."""
    rulings.load(register, decls, recs)
    _require(isinstance(plan, dict), 'invalid group import plan')
    _require(plan.get('source_rulings_sha256') == rulings.digest(register)
             and plan.get('pool_digest') == custody.pool_digest(decls)
             and plan.get('record_inventory_sha256') == record_inventory_digest(recs), 'stale import plan')
    errors = authorization_errors(plan, authorization)
    _require(not errors, '; '.join(errors))
    result = copy.deepcopy(register)
    result['eligibility_policy'] = plan['eligibility_policy']
    entries = {c['id']: c for c in result['reviewed_cases']}
    _require(len(plan['entries']) == len(entries) and {r['id'] for r in plan['entries']} == set(entries),
             'import plan inventory mismatch')
    _require(plan.get('source_pending_ids') == sorted(c['id'] for c in register['reviewed_cases'] if c['status'] == 'pending'),
             'import plan source statuses changed')
    for row in plan['entries']:
        entry = entries[row['id']]
        _require(entry['row_sha256'] == row['row_sha256'], 'import plan record changed')
        if entry['status'] != 'pending':
            # A new grouped import must not override an accepted, rejected or disputed adjudication.
            continue
        entry.update({k: row[k] for k in ('status', 'evidence_basis', 'questions_considered')})
        entry.update({k: authorization[k] for k in ('reviewed_by', 'reviewed_at', 'reviewer_kind',
                                                    'independent_of_generation', 'decision_ref')})
        entry.update(review_method=METHOD, group_decision_id=row['group_decision_id'],
                     group_review_plan_sha256=plan['plan_sha256'])
    # Semantic questions remain independent of case review. Only explicitly supplied
    # external human decisions may resolve them; no DATA-USE or HUMAN-REVIEW is inferred.
    updates = authorization.get('semantic_decisions', [])
    _require(isinstance(updates, list), 'invalid semantic decisions')
    decisions = {d['question_id']: d for d in result['decisions']}
    seen = set()
    for decision in updates:
        qid = decision.get('question_id') if isinstance(decision, dict) else None
        _require(isinstance(qid, str) and qid in decisions and qid not in seen,
                 'unknown/duplicate semantic decision')
        seen.add(qid)
        _require(decisions[qid]['status'] == 'pending' and decision.get('status') in ('accepted', 'rejected')
                 and not rulings._human_decision_errors(decision, 'semantic decision'),
                 'semantic decision cannot override existing ruling or lacks human evidence')
        decisions[qid].update(copy.deepcopy(decision))
    result['group_review_import'] = {'plan': copy.deepcopy(plan), 'authorization': copy.deepcopy(authorization)}
    rulings.load(result, decls, recs)
    return result


def import_errors(register):
    """Revalidate the serialized receipt so profile/method reporting survives reload."""
    receipt = register.get('group_review_import')
    grouped = [r for r in register.get('reviewed_cases', []) if isinstance(r, dict) and r.get('review_method') == METHOD]
    if receipt is None:
        return ['grouped review requires its import receipt'] if grouped or register.get('eligibility_policy') == rulings.SCHEMA_SEMANTICS_POLICY else []
    if not isinstance(receipt, dict) or not isinstance(receipt.get('plan'), dict):
        return ['invalid group import receipt']
    plan, auth = receipt['plan'], receipt.get('authorization')
    e = authorization_errors(plan, auth)
    if e:
        return e
    if (plan.get('eligibility_policy') != register.get('eligibility_policy')
            or plan.get('pool_digest') != register.get('pool_digest')
            or plan.get('record_inventory_sha256') != register.get('record_inventory_sha256')):
        e.append('group import profile/pool/inventory mismatch')
    rows = plan.get('entries')
    if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get('id'), str) for r in rows):
        return e + ['invalid group import mapping']
    by_id = {r['id']: r for r in rows}
    if len(by_id) != len(rows):
        e.append('duplicate group import mapping')
    pending = plan.get('source_pending_ids')
    if (not isinstance(pending, list) or not all(isinstance(r, str) for r in pending)
            or len(pending) != len(set(pending)) or not set(pending) <= set(by_id)):
        return e + ['invalid source pending inventory']
    actual = {r.get('id'): r for r in register.get('reviewed_cases', []) if isinstance(r, dict)}
    if not set(pending) <= set(actual):
        e.append('missing imported case review')
    check = {r['id']: r for r in grouped}
    check.update({rid: actual[rid] for rid in pending if rid in actual})
    for entry in check.values():
        bound = by_id.get(entry['id'])
        if (entry.get('review_method') != METHOD or bound is None
                or any(entry.get(k) != bound.get(k) for k in ('row_sha256', 'status', 'evidence_basis',
                                                                      'questions_considered', 'group_decision_id'))
                or entry.get('group_review_plan_sha256') != plan.get('plan_sha256')
                or any(entry.get(k) != auth.get(k) for k in ('reviewed_by', 'reviewed_at', 'reviewer_kind',
                                                            'independent_of_generation', 'decision_ref'))):
            e.append('grouped entry differs from approved import mapping')
    return e


def _write_new(path, value):
    target = Path(path)
    check_pool.ensure_private_out(target.parent)
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    # create_new preserves both the source ledger and previous outputs.
    import os
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=('prepare', 'apply'))
    for name in ('pool', 'records', 'rulings', 'out'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--review-package')
    parser.add_argument('--review-package-sha256')
    parser.add_argument('--profile', choices=sorted(rulings.ELIGIBILITY_POLICIES), default=rulings.ELIGIBILITY_POLICY)
    parser.add_argument('--plan')
    parser.add_argument('--authorization')
    args = parser.parse_args(argv)
    try:
        check_pool.ensure_private_out(Path(args.out).parent)
        decls = families.load_dir(args.pool)
        recs = [_json(line) for line in _read(args.records).splitlines() if line]
        register = _json(_read(args.rulings))
        if args.command == 'prepare':
            _require(args.review_package and args.review_package_sha256, 'review package and its digest are required')
            result = prepare(register, decls, recs, _read(args.review_package, MAX_ARCHIVE),
                             args.review_package_sha256, policy=args.profile)
            counts = dict(Counter(x['status'] for x in result['entries']))
        else:
            _require(args.plan and args.authorization, 'plan and external authorization are required')
            result = apply(register, decls, recs, _json(_read(args.plan)), _json(_read(args.authorization)))
            ledger = rulings.load(result, decls, recs)
            counts = dict(Counter(rulings.evidence_stratum(r, ledger) for r in recs))
        _write_new(args.out, result)
        print(json.dumps({'result': 'prepared_not_approved' if args.command == 'prepare' else 'imported_not_frozen',
                          'counts': counts, 'eligibility_policy': result['eligibility_policy']}))
        return 0
    except (GroupReviewError, rulings.RulingsError, check_pool.PrivacyError, OSError, ValueError, KeyError, TypeError):
        print('group review refused: invalid input, evidence, authorization or private destination', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
