# SPDX-License-Identifier: Apache-2.0
"""Gold development export: train/validation/calibration rows confirmed by an approved, export-grade addendum
chain (schema/gold_addendum.schema.json) and covered by an approved export authorization.
Deterministic; fail-closed; no test material.

Source (owner workstation): the CP2 development review package (`dev_review_package/`), authenticated through
the owner-signed freeze anchor (sou13cp2.anchor, namespace sou13-cp2-freeze) verified against an independently
pinned owner key:
  * sha256(MANIFEST.json) of the package equals the anchor's package_manifest_sha256.dev_review_package;
  * every package file the export reads matches MANIFEST.json, and every export label/input file matches
    exports/EXPORT_MANIFEST.json;
  * the public split view is internally consistent, FROZEN, and equals the anchor's public_view_sha256 and the
    package's public_view_sha256;
  * base.split_manifest_sha256 of every addendum and of the authorization equals the anchor's full_manifest_sha256.
The sealed test split is never read. Leakage safety rests on positive, anchored evidence: every row's family
must be assigned by the frozen public view to that row's split, its leakage group must match the view, groups,
families and input digests never span two splits, and any test or custodian file name in the package fails the
build. Each row's model input must reproduce its input, argument and definition digests.

Reviewer evidence: every individual confirmation must carry exactly the labels of the independent reviewer's
own submission files (sou13gold.draft.submission_binding_errors), which the owner supplies to `plan` and `build`.
A batch confirmation (PROPOSED, pending maintainer review) instead needs its attestation to list the anchored
development package among the reviewed artifacts (sou13gold.addendum.batch_artifact_errors). The manifest counts
gold rows per confirmation channel.

Authorization (schema/gold_export_authorization.schema.json) is the only source of training-use permission; no
addendum approval grants it, whatever its role. It must be approved, set training_use_authorized, reference
license_owner and dataset_owner approvals, and be bound to the addendum chain head and to the exact gold set and
counts this module computes (`plan`). Its `release_blockers_resolved` must cite, for every release question
(sou13gold.addendum.release_questions: each frozen open question of a gold row, and Q-CP2-DECL-EVIDENCE for
every gold row with a false action label), decision ids recorded in the chain or the authorization. A question
without a cited, recorded decision blocks the build; nothing is treated as approved by default. The citation is
traceability only: whether a cited decision actually resolves its question is a mandatory human release check.

Output, built in a hidden `.<name>.partial` sibling, verified with verify_gold_export.py, then renamed; an
interrupted build never leaves a directory under the final name:
  labels/<split>.jsonl, model_inputs/<split>.jsonl, addenda/addendum-v<n>.json, authorization/
  EXPORT_AUTHORIZATION.json, verify_gold_export.py, README.md, GOLD_EXPORT_MANIFEST.json
plus `<name>.digest.json` next to it: the statement the owner signs (ssh-keygen -Y sign -n sou13-gold-export) so
that the receiving team can authenticate GOLD_EXPORT_MANIFEST.json. The namespace only separates export
attestations from freeze-anchor signatures (sou13-cp2-freeze); it is not a governance approval.
"""
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

from sou13.build import definition_hash
from sou13.cases import CONTRACT
from sou13.hashing import file_sha, sha

from .addendum import (CONFIRMING_ADJUDICATION, DATASET_OWNER_ROLE, DEV_SPLITS, LICENSE_ROLE, AddendumError,
                       addendum_sha, apply_addenda_strict, batch_artifact_errors, chain_records, confirmation_channels,
                       dataset_version_errors, gold_rows, gold_set, placeholder_errors, release_blocker_errors,
                       release_questions)
from .draft import submission_binding_errors
from .files import (GoldFileError, dumps, dumps_jsonl, export_input_files, export_label_files, inside,
                    inside_git_worktree, read_export, test_material, write_new)

PACKAGE = 'dev_review_package'
PUBLIC_VIEW = 'manifest/split_manifest.PUBLIC_VIEW.json'
AUTH_SCHEMA = 'schema/gold_export_authorization.schema.json'
MODEL_INPUT_KEYS = ('id', 'split', 'input_profile', 'input', 'hashes')  # sou13cp2.exports.MODEL_INPUT_KEYS
ALLOWED_INPUT_KEYS = {'server_id', 'tool_name', 'tool_description', 'tool_schema', 'pinned_schema', 'raw_arguments'}
EXPORT_KIND = 'sou13_gold_dev_export'
STATUS = 'AUTHORIZED_DEVELOPMENT_EXPORT'
DIGEST_NAMESPACE = 'sou13-gold-export'
DIGEST_KIND = 'sou13_gold_export_digest'
VERIFIER = Path(__file__).resolve().parents[1] / 'scripts_cp2' / 'verify_gold_export.py'
README = """# SOU-13 gold development export

Train / validation / calibration rows whose labels were confirmed by an independent human reviewer through the
versioned gold addenda in `addenda/`, released under the licensing and release decisions in
`authorization/EXPORT_AUTHORIZATION.json`. The sealed test split, its inputs and its labels are not included and
must not be requested or reconstructed.

- `labels/<split>.jsonl`: one gold row per case: tri-state `per_action_targets` (`null` is masked, never
  `false`), `known_mask`, separate `unknown`, the gold and frozen label digests, input digests and the addendum
  decisions that confirmed it.
- `model_inputs/<split>.jsonl`: the label-free model input for the same cases.
- `GOLD_EXPORT_MANIFEST.json`: digests of every file, counts, the gold-set digest, the dataset base, every
  decision id, and the recorded decisions cited for each open question of the exported rows.

Verify before use (Python 3, standard library; `ssh-keygen` only for a signed digest):

    python -I verify_gold_export.py --expect-manifest-sha256 <digest published by the dataset owner>

or with the owner-signed digest statement and the independently pinned owner key:

    python -I verify_gold_export.py --statement <name>.digest.json --allowed-signers <file outside this folder> \\
        --trusted-key-fpr SHA256:... --signer <owner identity>

Exit code 0 = PASS, 3 = self-consistent but not authenticated, 1 = FAIL. Use is limited to the terms named in the
authorization.
"""


class ExportError(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors[:5]) + (f' (+{len(errors) - 5} more)' if len(errors) > 5 else ''))
        self.errors = errors


def _json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _schema(doc, rel, label):
    from sou13cp2.schemas import errors
    return [f'{label}: schema: {e}' for e in errors(doc, rel)]


def view_errors(view, anchor, package_manifest):
    e = []
    body = {k: v for k, v in view.items() if k != 'manifest_sha256'}
    if view.get('manifest_sha256') != sha(body):
        e.append('public split view: internal digest mismatch')
    if view.get('manifest_sha256') != anchor.get('public_view_sha256'):
        e.append('public split view differs from the owner-signed anchor')
    if view.get('manifest_sha256') != package_manifest.get('public_view_sha256'):
        e.append('public split view differs from the one the package manifest names')
    if view.get('status') != 'FROZEN' or view.get('frozen') is not True:
        e.append('public split view is not FROZEN')
    if view.get('labels_in_manifest') is not False:
        e.append('public split view must not carry labels')
    if any(s not in DEV_SPLITS for s in (view.get('family_split') or {}).values()):
        e.append('public split view assigns a public family outside train/validation/calibration')
    return e


def row_errors(rows, inputs, view):
    """Family separation, leakage groups, duplicates and model-input binding for every development row."""
    e = []
    fam_split, fam_group = view.get('family_split') or {}, view.get('family_group') or {}
    ids, group_split, input_split = set(), {}, {}
    for r in rows:
        rid, where = r.get('id'), f'label row {r.get("id")}'
        if rid in ids:
            e.append(f'{where}: duplicate case id')
        ids.add(rid)
        if r.get('split') not in DEV_SPLITS:
            e.append(f'{where}: split {r.get("split")!r} is not a development split')
            continue
        fam = r.get('family_id')
        if fam_split.get(fam) != r['split']:
            e.append(f'{where}: family is not assigned to {r["split"]} by the frozen public split view')
        if fam_group.get(fam) != r.get('leakage_group_id'):
            e.append(f'{where}: leakage group differs from the frozen public split view')
        g = r.get('leakage_group_id')
        if group_split.setdefault(g, r['split']) != r['split']:
            e.append(f'{where}: leakage group spans two splits')
        h = (r.get('hashes') or {}).get('input_sha256')
        if input_split.setdefault(h, r['split']) != r['split']:
            e.append(f'{where}: the same input appears in two splits')
    by_id = {r.get('id'): r for r in rows}
    seen = set()
    for m in inputs:
        mid, where = m.get('id'), f'model input {m.get("id")}'
        if mid in seen:
            e.append(f'{where}: duplicate')
        seen.add(mid)
        r = by_id.get(mid)
        if r is None:
            e.append(f'{where}: no label row')
            continue
        if tuple(sorted(m)) != tuple(sorted(MODEL_INPUT_KEYS)) or set(m['input']) - ALLOWED_INPUT_KEYS:
            e.append(f'{where}: carries fields beyond the label-free model input')
            continue
        if m['split'] != r['split'] or m['hashes'] != r['hashes']:
            e.append(f'{where}: split or digests differ from the label row')
        inp = m['input']
        if (sha(inp), sha(inp.get('raw_arguments')), definition_hash(inp)) != (
                m['hashes'].get('input_sha256'), m['hashes'].get('arguments_sha256'),
                m['hashes'].get('definition_sha256')):
            e.append(f'{where}: input does not reproduce its digests')
    for rid in sorted(set(by_id) - seen):
        e.append(f'label row {rid}: no model input')
    return e


def load_sources(dev_package, anchor_cfg, untrusted_roots=()):
    """Authenticated development sources. Raises ExportError on any failed check."""
    from sou13cp2.anchor import verify_anchor
    pkg = Path(dev_package)
    anchor, e = verify_anchor(anchor_cfg, untrusted_roots=[pkg, *untrusted_roots])
    if e:
        raise ExportError([f'anchor: {x}' for x in e])
    e = [f'package: {rel}: test or custodian material' for rel in test_material(pkg)]
    mpath = pkg / 'MANIFEST.json'
    if not mpath.is_file():
        raise ExportError(e + ['package: missing MANIFEST.json'])
    pman = _json(mpath)
    want = (anchor.get('package_manifest_sha256') or {}).get(PACKAGE)
    if not want:
        e.append(f'anchor: the signed anchor records no digest for {PACKAGE}')
    elif file_sha(mpath) != want:
        e.append('package: MANIFEST.json differs from the owner-signed anchor')
    if pman.get('package') != PACKAGE or not set(pman.get('splits') or ()) <= set(DEV_SPLITS):
        e.append(f'package: not a {PACKAGE} limited to development splits')
    listed = pman.get('files_sha256') or {}
    for rel in [PUBLIC_VIEW, 'exports/EXPORT_MANIFEST.json'] + [f'exports/{x}' for x in
                                                                  export_label_files() + export_input_files()]:
        if not (pkg / rel).is_file() or listed.get(rel) != file_sha(pkg / rel):
            e.append(f'package: {rel} is missing or differs from MANIFEST.json')
    if e:
        raise ExportError(e)
    export_manifest, rows, inputs, read_errors = read_export(pkg / 'exports', need_inputs=True)
    view = _json(pkg / PUBLIC_VIEW)
    e = [f'exports: {x}' for x in read_errors] + view_errors(view, anchor, pman) + row_errors(rows, inputs, view)
    if not anchor.get('full_manifest_sha256'):
        e.append('anchor: no full_manifest_sha256')
    base = {'dataset_version': export_manifest.get('cp2_version'),
            'export_manifest_sha256': file_sha(pkg / 'exports' / 'EXPORT_MANIFEST.json'),
            'split_manifest_sha256': anchor.get('full_manifest_sha256'), 'contract_sha256': CONTRACT['sha256']}
    e += dataset_version_errors(base)
    if e:
        raise ExportError(e)
    return {'rows': rows, 'inputs': inputs, 'view': view, 'base': base, 'package_manifest_sha256': file_sha(mpath),
            'public_view_sha256': view['manifest_sha256']}


def authorization_errors(auth, base, addenda, gold_sha, counts, questions):
    e = _schema(auth, AUTH_SCHEMA, 'authorization')
    if e:
        return e
    if auth['status'] != 'approved':
        e.append(f'authorization: status {auth["status"]} cannot release an export')
    use = auth['permitted_use']
    if use['training_use_authorized'] is not True:
        e.append('authorization: training use is not authorised by the license owner; nothing is exported')
    if auth['base'] != base:
        e.append('authorization: base differs from the files being exported')
    if auth['addendum_chain'] != {'length': len(addenda), 'head_sha256': addendum_sha(addenda[-1])}:
        e.append('authorization: names a different addendum chain')
    if auth['gold_set'] != {'sha256': gold_sha, 'counts': counts}:
        e.append('authorization: names a different gold set or counts than the addendum chain confirms')
    for s in DEV_SPLITS:
        if counts[s] and s not in use['splits']:
            e.append(f'authorization: {counts[s]} gold row(s) in {s}, which is not authorised')
    approvals = {}
    for a in auth['approvals']:
        if a['decision_id'] in approvals:
            e.append(f'authorization: approval {a["decision_id"]} recorded twice')
        approvals[a['decision_id']] = a
        e += placeholder_errors('authorization', a)
    for key, role in (('license_decision_ids', LICENSE_ROLE), ('release_decision_ids', DATASET_OWNER_ROLE)):
        for d in auth[key]:
            if approvals.get(d, {}).get('role') != role:
                e.append(f'authorization: {key} {d} is not a recorded {role} approval in this authorization')
    cited = {d for ids in auth['release_blockers_resolved'].values() for d in ids}
    unused = set(approvals) - set(auth['license_decision_ids']) - set(auth['release_decision_ids']) - cited
    if unused:
        e.append(f'authorization: approvals recorded but not referenced {sorted(unused)}')
    records = chain_records(addenda)
    for d, a in approvals.items():
        if d in records and records[d] != a:
            e.append(f'authorization: decision id {d} names a different record than in the addendum chain')
    e += [f'authorization: {x}' for x in
          release_blocker_errors(questions, auth['release_blockers_resolved'], {**records, **approvals})]
    if not sum(counts.values()):
        e.append('authorization: the addendum chain confirms no gold row; nothing to export')
    return e


def plan(src, addenda, submissions):
    """Gold view, gold-set digest, counts and release questions for an approved, export-grade addendum chain whose
    confirmations carry exactly the labels of the supplied reviewer submissions (nothing written)."""
    if not addenda:
        raise ExportError(['no addendum given'])
    individual = any(x['to_status'] == 'confirmed' and x['adjudication'] == CONFIRMING_ADJUDICATION
                     for a in addenda for x in a.get('entries', []))
    if individual and not submissions:
        raise ExportError(['no reviewer submission given; individual confirmations must be proven against the '
                           'reviewer\'s own submission files'])
    try:
        view = apply_addenda_strict(src['rows'], addenda, src['base'])
    except AddendumError as exc:
        raise ExportError([f'addenda: {x}' for x in exc.errors]) from None
    e = submission_binding_errors(addenda, submissions, src['rows'])
    e += batch_artifact_errors(addenda, src['package_manifest_sha256'])
    if e:
        raise ExportError([f'reviewer evidence: {x}' for x in e])
    gold_sha, counts = gold_set(view)
    questions = release_questions(view, src['rows'])
    return {'view': view, 'gold_set_sha256': gold_sha, 'counts': counts,
            'addendum_chain': {'length': len(addenda), 'head_sha256': addendum_sha(addenda[-1])},
            'base': src['base'], 'release_questions': {q: len(ids) for q, ids in questions.items()},
            'questions': questions, 'confirmation_channels': confirmation_channels(view)}


def _gold_label_rows(src, gold):
    by_id = {r['id']: r for r in src['rows']}
    out = {s: [] for s in DEV_SPLITS}
    for v in gold:
        r = by_id[v['id']]
        out[v['split']].append({'id': v['id'], 'split': v['split'], 'family_id': r['family_id'],
                                'leakage_group_id': r['leakage_group_id'], 'label_status': 'confirmed',
                                **{k: v['labels'][k] for k in ('per_action_targets', 'known_mask', 'unknown')},
                                'gold_label_sha256': v['gold_label_sha256'],
                                'frozen_label_sha256': v['frozen_label_sha256'], 'hashes': r['hashes'],
                                'open_questions': sorted(r.get('open_questions') or []), 'addenda': v['addenda']})
    return out


def build(src, addendum_paths, submissions, authorization_path, out_dir, repo_root=None):
    """Write the export. Returns the manifest digest and counts. Raises ExportError / GoldFileError."""
    out = Path(out_dir).resolve()
    statement_path = out.parent / f'{out.name}.digest.json'
    partial = out.parent / f'.{out.name}.partial'
    for p, what in ((out, 'export directory'), (statement_path, 'digest statement'), (partial, 'partial build')):
        if p.exists():
            raise GoldFileError(f'refusing: {what} {p.name} already exists (an earlier build or an interrupted one; '
                                f'inspect and remove it yourself)')
    if inside_git_worktree(out) or (repo_root and inside(out, repo_root)):
        raise GoldFileError('refusing to write an export inside a Git work tree or the repository')
    raw_addenda = [Path(p).read_bytes() for p in addendum_paths]
    addenda = [json.loads(b) for b in raw_addenda]
    raw_auth = Path(authorization_path).read_bytes()
    auth = json.loads(raw_auth)
    p = plan(src, addenda, submissions)
    e = authorization_errors(auth, src['base'], addenda, p['gold_set_sha256'], p['counts'], p['questions'])
    if e:
        raise ExportError(e)
    splits = [s for s in DEV_SPLITS if s in auth['permitted_use']['splits']]
    gold = gold_rows(p['view'])
    labels = _gold_label_rows(src, gold)
    gold_ids = {s: {g['id'] for g in labels[s]} for s in DEV_SPLITS}
    inputs = {s: sorted((m for m in src['inputs'] if m['id'] in gold_ids[s]), key=lambda m: m['id'])
              for s in DEV_SPLITS}
    files = {}
    for s in splits:
        files[f'labels/{s}.jsonl'] = dumps_jsonl(labels[s]).encode('utf-8')
        files[f'model_inputs/{s}.jsonl'] = dumps_jsonl(inputs[s]).encode('utf-8')
    for a, raw in zip(addenda, raw_addenda):
        files[f'addenda/addendum-v{a["addendum_version"]}.json'] = raw
    files['authorization/EXPORT_AUTHORIZATION.json'] = raw_auth
    files['verify_gold_export.py'] = VERIFIER.read_bytes()
    files['README.md'] = README.encode('utf-8')
    decisions = sorted({a['decision_id'] for x in addenda for a in x['approvals']}
                       | {a['decision_id'] for a in auth['approvals']})
    manifest = {'export_kind': EXPORT_KIND, 'format_version': 1, 'status': STATUS, 'splits': splits,
                'counts': {s: len(labels[s]) for s in splits}, 'gold_set_sha256': p['gold_set_sha256'],
                'base': src['base'],
                'source': {'dev_package_manifest_sha256': src['package_manifest_sha256'],
                           'public_view_sha256': src['public_view_sha256'],
                           'binding': 'owner-signed freeze anchor (namespace sou13-cp2-freeze)'},
                'addenda': [{'version': a['addendum_version'], 'sha256': addendum_sha(a),
                             'file': f'addenda/addendum-v{a["addendum_version"]}.json'} for a in addenda],
                'authorization': {'file': 'authorization/EXPORT_AUTHORIZATION.json', 'sha256': sha(auth),
                                  'license_id': auth['permitted_use']['license_id'],
                                  'recipient': auth['recipient']},
                'decision_ids': decisions,
                'confirmation_channels': p['confirmation_channels'],
                'release_questions': p['release_questions'],
                'release_blockers_resolved': {q: sorted(ids) for q, ids in
                                              sorted(auth['release_blockers_resolved'].items())},
                'test': 'not included: the sealed test split, its inputs and its labels are custodian-only',
                'label_scope': 'per_action_targets (true/false/null; null is masked, never false), known_mask and '
                               'unknown under the SOU-10 contract named by base.contract_sha256',
                'files_sha256': {rel: sha_bytes(data) for rel, data in sorted(files.items())}}
    files['GOLD_EXPORT_MANIFEST.json'] = dumps(manifest).encode('utf-8')
    manifest_sha = sha_bytes(files['GOLD_EXPORT_MANIFEST.json'])
    created = False
    try:
        partial.mkdir(parents=True)
        created = True
        for rel, data in sorted(files.items()):
            target = partial / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, 'xb') as f:
                f.write(data)
        report = load_verifier().verify(partial, expect_manifest_sha256=manifest_sha)
        if report['result'] != 'PASS':
            raise ExportError([f'self-verification: {x}' for x in report['errors']] or ['self-verification failed'])
        partial.rename(out)
        created = False
    finally:
        if created and partial.exists():
            shutil.rmtree(partial)  # only the partial directory this call created
    write_new(statement_path, dumps({'statement_kind': DIGEST_KIND, 'namespace': DIGEST_NAMESPACE,
                                     'export': out.name, 'gold_export_manifest_sha256': manifest_sha}))
    return {'result': 'PASS', 'export': out.name, 'gold_export_manifest_sha256': manifest_sha,
            'counts': manifest['counts'], 'addenda': len(addenda), 'gold_set_sha256': p['gold_set_sha256'],
            'statement': statement_path.name, 'sign_with': f'ssh-keygen -Y sign -n {DIGEST_NAMESPACE} -f <owner key> '
                                                            f'{statement_path.name}'}


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_verifier():
    """The standalone verifier module, loaded from the exact file that is shipped in every export."""
    spec = importlib.util.spec_from_file_location('sou13_verify_gold_export', VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
