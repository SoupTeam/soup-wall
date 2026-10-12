#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone verifier for a SOU-13 gold development export (Python 3 standard library; ssh-keygen only for a
signed digest). Shipped verbatim inside every export; run it from anywhere:

  python -I verify_gold_export.py [EXPORT_DIR] --expect-manifest-sha256 HEX
  python -I verify_gold_export.py [EXPORT_DIR] --statement NAME.digest.json [--statement-sig F.sig] \
      --allowed-signers F --trusted-key-fpr SHA256:... --signer ID

EXPORT_DIR defaults to the folder containing this script. Separate results:

  self_consistency    every file matches GOLD_EXPORT_MANIFEST.json and nothing else is present; no test or
                      custodian material; only train/validation/calibration; family, leakage-group and input
                      digests never span two splits; model inputs reproduce their digests; every gold label digest
                      recomputes; the addendum hash chain is complete and approved; every exported row is the
                      final, independently confirmed state of its case (reviewer labels equal the exported
                      labels, evidence digests bind the frozen row) and every confirmed case in an authorised
                      split is exported; the authorization is approved, authorises training use, names exactly
                      this base, chain, gold set and counts, and cites, for every open question of the exported
                      rows and for Q-CP2-DECL-EVIDENCE when an exported label is false, decision ids that exist as
                      approval records in the export (the manifest repeats them). NOTE: an attacker who rewrites every
                      file and the manifest consistently passes this check; it is not authentication.
  anchored_integrity  sha256(GOLD_EXPORT_MANIFEST.json) equals a digest obtained from OUTSIDE the export: either
                      --expect-manifest-sha256, or the owner-signed digest statement verified with ssh-keygen
                      against the pinned owner key (namespace sou13-gold-export; trust files outside the export).
                      The namespace is technical domain separation from the freeze anchor, not an approval.
                      This authenticates the manifest as the one the owner signed or published; approval records
                      inside the export are unsigned text and their approvers are not authenticated here.
  release_blockers    CITED_ONLY: every release question cites ids of approval records present in the export. The
                      content of those decisions is NOT verified; whether each resolves its question is a
                      mandatory human release check.
  label_correctness   NOT VERIFIED here: labels are bound by digest to the recorded independent-reviewer
                      confirmations; their correctness rests on that human review. Rows confirmed by a batch
                      attestation (PROPOSED) carry no per-case reviewer labels: the verifier checks the attested
                      case set and artifact digest, and `confirmation_channels` counts them separately.

Exit codes: 0 = self-consistent AND anchored PASS; 3 = self-consistent but anchored UNVERIFIED; 1 = FAIL.
Only counts and error messages are printed, never label values.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
DEV_SPLITS = ('train', 'validation', 'calibration')
MODEL_INPUT_KEYS = ('id', 'split', 'input_profile', 'input', 'hashes')
ALLOWED_INPUT_KEYS = {'server_id', 'tool_name', 'tool_description', 'tool_schema', 'pinned_schema', 'raw_arguments'}
MANIFEST = 'GOLD_EXPORT_MANIFEST.json'
EXPORT_KIND = 'sou13_gold_dev_export'
STATUS = 'AUTHORIZED_DEVELOPMENT_EXPORT'
NAMESPACE = 'sou13-gold-export'
STATEMENT_KIND = 'sou13_gold_export_digest'
DECL_EVIDENCE_QUESTION = 'Q-CP2-DECL-EVIDENCE'
BATCH = 'independent_human_batch'  # PROPOSED batch attestation (pending maintainer review)
TEST_NAMES = {'test.jsonl', 'test_labels.jsonl', 'model_inputs_test.jsonl', 'candidates_test.jsonl',
              'test_candidates.jsonl', 'test_families.json', 'test_review_queue.csv', 'coverage_test.json',
              'case_ids.test.json', 'split_manifest.full.json', 'taxonomy.full.json', 'test_review_package.md'}
TEST_DIRS = {'cp2_sealed', 'restricted_test_custodian', 'restricted', 'sealed', 'sealed_test', 'test_gold'}
KEY_RE = re.compile(r'((?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.\-]+)\s+([A-Za-z0-9+/=]{40,})')


def sha(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
                          .encode('utf-8')).hexdigest()


def fsha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def defn(i):
    v = {'tool_name': i['tool_name'], 'tool_description': i.get('tool_description'), 'tool_schema': i['tool_schema']}
    if 'pinned_schema' in i:
        v['pinned_schema'] = i['pinned_schema']
    return sha(v)


def jsonl(p):
    return [json.loads(x) for x in Path(p).read_text(encoding='utf-8').splitlines() if x.strip()]


def inside(p, root):
    p, root = Path(p).resolve(), Path(root).resolve()
    return p == root or root in p.parents


def mask_ok(labels):
    return all(labels['known_mask'][a] == int(labels['per_action_targets'][a] is not None) for a in ACTIONS)


def file_errors(root, man):
    e = []
    listed = man.get('files_sha256') or {}
    present = {p.relative_to(root).as_posix() for p in root.rglob('*')
               if p.is_file() and '__pycache__' not in p.parts}
    for rel in sorted(present | set(listed)):
        parts = [x.lower() for x in Path(rel).parts]
        if parts[-1] in TEST_NAMES or set(parts[:-1]) & TEST_DIRS:
            e.append(f'{rel}: test or custodian material')
    for rel in sorted(present - set(listed) - {MANIFEST}):
        e.append(f'{rel}: not listed in {MANIFEST}')
    for rel, digest in sorted(listed.items()):
        if not (root / rel).is_file() or fsha(root / rel) != digest:
            e.append(f'{rel}: missing or digest mismatch')
    return e


def row_errors(root, man):
    """(errors, gold rows by id)."""
    e, gold = [], {}
    fam_split, group_split, input_split = {}, {}, {}
    for s in man['splits']:
        labels, inputs = root / 'labels' / f'{s}.jsonl', root / 'model_inputs' / f'{s}.jsonl'
        if not labels.is_file() or not inputs.is_file():
            e.append(f'{s}: labels or model inputs missing')
            continue
        rows = jsonl(labels)
        if len(rows) != man['counts'].get(s):
            e.append(f'{s}: {len(rows)} rows, manifest counts {man["counts"].get(s)}')
        for r in rows:
            rid, where = r.get('id'), f'labels/{s}.jsonl {r.get("id")}'
            if rid in gold:
                e.append(f'{where}: duplicate case id')
            gold[rid] = r
            if r.get('split') != s or r.get('label_status') != 'confirmed':
                e.append(f'{where}: split or status is wrong')
            core = {k: r.get(k) for k in ('per_action_targets', 'known_mask', 'unknown')}
            try:
                if not mask_ok(core):
                    e.append(f'{where}: known_mask does not match the targets')
            except (KeyError, TypeError):
                e.append(f'{where}: malformed labels')
                continue
            if sha({'id': rid, **core}) != r.get('gold_label_sha256'):
                e.append(f'{where}: gold_label_sha256 does not recompute')
            for key, table, value in (('family', fam_split, r.get('family_id')),
                                      ('leakage group', group_split, r.get('leakage_group_id')),
                                      ('input', input_split, (r.get('hashes') or {}).get('input_sha256'))):
                if table.setdefault(value, s) != s:
                    e.append(f'{where}: {key} spans two splits')
        by_id = {r.get('id'): r for r in rows}
        seen = set()
        for m in jsonl(inputs):
            mid, where = m.get('id'), f'model_inputs/{s}.jsonl {m.get("id")}'
            if mid in seen or mid not in by_id:
                e.append(f'{where}: duplicate or without a gold label row')
                continue
            seen.add(mid)
            if tuple(sorted(m)) != tuple(sorted(MODEL_INPUT_KEYS)) or set(m['input']) - ALLOWED_INPUT_KEYS:
                e.append(f'{where}: carries fields beyond the label-free model input')
                continue
            i, h = m['input'], m['hashes']
            if m['split'] != s or h != by_id[mid].get('hashes'):
                e.append(f'{where}: split or digests differ from the label row')
            if (sha(i), sha(i.get('raw_arguments')), defn(i)) != (h.get('input_sha256'), h.get('arguments_sha256'),
                                                                  h.get('definition_sha256')):
                e.append(f'{where}: input does not reproduce its digests')
        for rid in sorted(set(by_id) - seen):
            e.append(f'labels/{s}.jsonl {rid}: no model input')
    gold_set = sorted(({'id': r['id'], 'split': r['split'], 'gold_label_sha256': r['gold_label_sha256']}
                       for r in gold.values()), key=lambda x: x['id'])
    if sha(gold_set) != man.get('gold_set_sha256'):
        e.append('gold_set_sha256 does not recompute from the exported rows')
    return e, gold


def chain_errors(root, man, gold):
    """(errors, addenda) for the addendum chain and the binding of every exported row to it."""
    e, addenda = [], []
    for n, item in enumerate(man.get('addenda') or [], 1):
        a = json.loads((root / item['file']).read_text(encoding='utf-8'))
        addenda.append(a)
        where = f'addendum v{n}'
        if item.get('version') != n or a.get('addendum_version') != n or sha(a) != item.get('sha256'):
            e.append(f'{where}: version or digest differs from the manifest')
        if a.get('previous_addendum_sha256') != (sha(addenda[-2]) if n > 1 else None):
            e.append(f'{where}: does not chain to its predecessor')
        if a.get('status') != 'approved':
            e.append(f'{where}: not an approved addendum')
        if a.get('base') != man.get('base'):
            e.append(f'{where}: base differs from the export')
    if not addenda:
        return e + ['no addendum'], addenda
    final, history = {}, {}
    for a in addenda:
        roles = {x['decision_id']: x['role'] for x in a.get('approvals', [])}
        for entry in a.get('entries', []):
            cid = entry['case_id']
            final[cid] = (a, entry, roles)
            history.setdefault(cid, []).append({'version': a['addendum_version'], 'sha256': sha(a),
                                                'decision_ids': list(entry['decision_ids']),
                                                'adjudication': entry['adjudication'],
                                                'to_status': entry['to_status']})
    for rid, r in sorted(gold.items()):
        where = f'gold row {rid}'
        if rid not in final:
            e.append(f'{where}: no addendum entry')
            continue
        a, entry, roles = final[rid]
        core = {k: r.get(k) for k in ('per_action_targets', 'known_mask', 'unknown')}
        if entry['to_status'] != 'confirmed' or entry['adjudication'] not in ('independent_human', BATCH):
            e.append(f'{where}: final addendum state is not an independent confirmation')
        if not any(roles.get(d) == 'independent_reviewer' for d in entry['decision_ids']):
            e.append(f'{where}: confirmation references no independent_reviewer approval')
        if entry['adjudication'] == BATCH:
            # Batch attestation (PROPOSED contract change): no per-case reviewer labels and no label change; the
            # case belongs to the attested case set, which recomputes from the addendum's batch entries.
            attested = {x['decision_id']: x for x in a.get('batch_attestations', [])}
            cited = [d for d in entry['decision_ids'] if d in attested]
            if entry.get('reviewer_labels') is not None or entry.get('label_change') is not None or len(cited) != 1:
                e.append(f'{where}: batch confirmation must cite one attestation, without reviewer labels or changes')
            elif roles.get(cited[0]) != 'independent_reviewer':
                e.append(f'{where}: batch attestation is not an independent_reviewer decision')
        elif entry.get('reviewer_labels') != core:
            e.append(f'{where}: exported labels differ from the independent reviewer\'s labels')
        if entry['evidence'].get('label_sha256') != r.get('frozen_label_sha256') or any(
                entry['evidence'].get(k) != (r.get('hashes') or {}).get(k)
                for k in ('input_sha256', 'arguments_sha256', 'definition_sha256')):
            e.append(f'{where}: evidence digests do not bind the frozen row')
        if entry['split'] != r.get('split'):
            e.append(f'{where}: split differs from the addendum entry')
        if r.get('addenda') != history[rid]:
            e.append(f'{where}: addenda history differs from the chain')
    for cid, (a, entry, roles) in sorted(final.items()):
        if entry['to_status'] == 'confirmed' and entry['split'] in man['splits'] and cid not in gold:
            e.append(f'confirmed case {cid} is missing from the export')
    package = (man.get('source') or {}).get('dev_package_manifest_sha256')
    for a in addenda:
        for att in a.get('batch_attestations', []):
            where = f'addendum v{a["addendum_version"]} batch attestation {att.get("decision_id")}'
            entries = [x for x in a.get('entries', []) if x.get('adjudication') == BATCH
                       and x.get('to_status') == 'confirmed' and att.get('decision_id') in x.get('decision_ids', [])]
            case_set = sha(sorted(({'id': x['case_id'], 'label_sha256': x['evidence']['label_sha256']}
                                   for x in entries), key=lambda x: x['id']))
            if len(entries) != att.get('case_count') or case_set != att.get('case_set_sha256'):
                e.append(f'{where}: confirmed cases differ from the attested case set')
            if package not in {x.get('sha256') for x in att.get('reviewed_artifacts', [])}:
                e.append(f'{where}: the source development package is not among the reviewed artifacts')
    channels = {}
    for rid in gold:
        if rid in final:
            k = final[rid][1]['adjudication']
            channels[k] = channels.get(k, 0) + 1
    if man.get('confirmation_channels') != dict(sorted(channels.items())):
        e.append('manifest: confirmation channels differ from the addenda')
    return e, addenda


def authorization_errors(root, man, addenda, gold):
    e = []
    item = man.get('authorization') or {}
    auth = json.loads((root / item.get('file', 'authorization/EXPORT_AUTHORIZATION.json')).read_text(encoding='utf-8'))
    if sha(auth) != item.get('sha256'):
        e.append('authorization: digest differs from the manifest')
    if auth.get('status') != 'approved':
        e.append('authorization: not approved')
    use = auth.get('permitted_use') or {}
    if use.get('training_use_authorized') is not True:
        e.append('authorization: training use is not authorised')
    if auth.get('base') != man.get('base'):
        e.append('authorization: base differs from the export')
    if addenda and auth.get('addendum_chain') != {'length': len(addenda), 'head_sha256': sha(addenda[-1])}:
        e.append('authorization: names a different addendum chain')
    if (auth.get('gold_set') or {}).get('sha256') != man.get('gold_set_sha256'):
        e.append('authorization: names a different gold set')
    counts = {s: sum(r.get('split') == s for r in gold.values()) for s in DEV_SPLITS}
    if (auth.get('gold_set') or {}).get('counts') != counts:
        e.append('authorization: gold counts differ from the exported rows')
    if not set(man.get('splits') or ()) <= set(use.get('splits') or ()):
        e.append('authorization: the export contains a split that is not authorised')
    roles = {a.get('decision_id'): a.get('role') for a in auth.get('approvals', [])}
    for key, role in (('license_decision_ids', 'license_owner'), ('release_decision_ids', 'dataset_owner')):
        ids = auth.get(key) or []
        if not ids or any(roles.get(d) != role for d in ids):
            e.append(f'authorization: {key} must reference recorded {role} approvals')
    # Release blockers: every open question of an exported row, and Q-CP2-DECL-EVIDENCE for a false label, must
    # cite decision ids recorded in the addenda or the authorization; nothing is approved by default.
    records = {a.get('decision_id') for x in addenda for a in x.get('approvals', [])} | set(roles)
    resolved = auth.get('release_blockers_resolved') or {}
    questions = {}
    for r in gold.values():
        qs = set(r.get('open_questions') or ())
        if any(v is False for v in (r.get('per_action_targets') or {}).values()):
            qs.add(DECL_EVIDENCE_QUESTION)
        for q in qs:
            questions[q] = questions.get(q, 0) + 1
    for q in sorted(questions):
        cited = resolved.get(q) or []
        if not cited or any(d not in records for d in cited):
            e.append(f'authorization: release blocker {q} ({questions[q]} exported rows) cites no decision id '
                     f'that is a recorded approval')
    if man.get('release_questions') != dict(sorted(questions.items())) or \
            man.get('release_blockers_resolved') != {q: sorted(v) for q, v in sorted(resolved.items())}:
        e.append('manifest: release questions or their cited decisions differ from the rows and the authorization')
    return e


def statement_digest(a):
    """Expected manifest digest from an owner-signed statement verified against the pinned key (or error)."""
    exe = shutil.which('ssh-keygen')
    if not exe:
        return None, 'ssh-keygen not available to verify the signed statement'
    if inside(a.allowed_signers, a.root):
        return None, 'allowed_signers must not come from inside the export being verified'
    with tempfile.TemporaryDirectory() as tmp:
        fprs = []
        for n, (kt, blob) in enumerate(KEY_RE.findall(Path(a.allowed_signers).read_text(encoding='utf-8'))):
            pub = Path(tmp) / f'k{n}.pub'
            pub.write_text(f'{kt} {blob}\n', encoding='utf-8')
            out = subprocess.run([exe, '-l', '-E', 'sha256', '-f', str(pub)], capture_output=True, text=True)
            fprs.append(out.stdout.split()[1] if out.returncode == 0 else None)
    if not fprs or any(f != a.trusted_key_fpr for f in fprs):
        return None, 'allowed_signers keys do not match the pinned owner key'
    sig = a.statement_sig or a.statement + '.sig'
    with open(a.statement, 'rb') as msg:
        res = subprocess.run([exe, '-Y', 'verify', '-f', a.allowed_signers, '-I', a.signer, '-n', NAMESPACE,
                              '-s', sig], stdin=msg, capture_output=True, text=True)
    if res.returncode:
        return None, 'statement signature does not verify against the pinned owner key'
    doc = json.loads(Path(a.statement).read_text(encoding='utf-8'))
    if doc.get('statement_kind') != STATEMENT_KIND or doc.get('namespace') != NAMESPACE:
        return None, 'signed document is not a SOU-13 gold export digest statement'
    return doc.get('gold_export_manifest_sha256'), None


def verify(root, expect_manifest_sha256=None, statement_args=None):
    root = Path(root)
    mpath = root / MANIFEST
    if not mpath.is_file():
        return {'result': 'FAIL', 'errors': [f'missing {MANIFEST}'], 'self_consistency': 'FAIL',
                'anchored_integrity': 'FAIL'}
    man_bytes = mpath.read_bytes()
    man = json.loads(man_bytes)
    errors = []
    if man.get('export_kind') != EXPORT_KIND or man.get('status') != STATUS:
        errors.append('manifest: not an authorised SOU-13 gold development export')
    if not man.get('splits') or not set(man['splits']) <= set(DEV_SPLITS):
        errors.append('manifest: splits must be a subset of train/validation/calibration')
    errors += file_errors(root, man)
    gold, addenda = {}, []
    if not errors:
        try:
            e, gold = row_errors(root, man)
            errors += e
            e, addenda = chain_errors(root, man, gold)
            errors += e
            errors += authorization_errors(root, man, addenda, gold)
        except (KeyError, TypeError, ValueError, OSError) as exc:
            errors.append(f'malformed export: {type(exc).__name__}')
    actual = hashlib.sha256(man_bytes).hexdigest()
    expected, anchor_error = expect_manifest_sha256, None
    if statement_args is not None and statement_args.statement:
        if not (statement_args.allowed_signers and statement_args.trusted_key_fpr and statement_args.signer):
            anchor_error = '--statement needs --allowed-signers, --trusted-key-fpr and --signer'
        else:
            expected, anchor_error = statement_digest(statement_args)
    if anchor_error:
        anchored = 'FAIL'
    elif expected is None:
        anchored = 'UNVERIFIED'
    else:
        anchored = 'PASS' if actual == str(expected).lower() else 'FAIL'
    self_ok = not errors
    result = 'PASS' if self_ok and anchored == 'PASS' else ('FAIL' if not self_ok or anchored == 'FAIL'
                                                            else 'UNVERIFIED')
    return {'result': result, 'self_consistency': 'PASS' if self_ok else 'FAIL', 'anchored_integrity': anchored,
            'anchor_error': anchor_error, 'manifest_sha256': actual, 'counts': man.get('counts'),
            'addenda': len(addenda),
            'release_blockers': 'CITED_ONLY: decision ids are present as approval records; their content is not '
                                'verified (mandatory human release check)',
            'label_correctness': 'NOT VERIFIED here: bound by digest to recorded independent-reviewer confirmations',
            'errors': errors}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument('--expect-manifest-sha256')
    for opt in ('statement', 'statement-sig', 'allowed-signers', 'trusted-key-fpr', 'signer'):
        ap.add_argument('--' + opt)
    a = ap.parse_args(argv)
    report = verify(a.root, a.expect_manifest_sha256, a)
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return {'PASS': 0, 'UNVERIFIED': 3}.get(report['result'], 1)


if __name__ == '__main__':
    sys.exit(main())
