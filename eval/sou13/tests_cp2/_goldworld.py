# SPDX-License-Identifier: Apache-2.0
"""SYNTHETIC gold-export world for tests (test-only). No real case, label, decision, package or anchor.

Case ids are assembled at run time; family ids are synthetic and outside the taxonomy naming scheme; every
approval names a SYN- decision and says that it is not a decision. Keys are generated in temporary folders."""
import copy
import json
from pathlib import Path

from sou13.build import definition_hash
from sou13.cases import CONTRACT
from sou13.hashing import file_sha, sha

DATASET_VERSION = '0.4-cp2-phase1-draft'
SPLIT_SHA = sha('synthetic full split manifest')
ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
FAMILY = {'train-1': 'train', 'train-2': 'train', 'validation-1': 'validation', 'calibration-1': 'calibration'}
STATEMENT = 'Synthetic fixture: not a real decision.'
REV = {'decision_id': 'SYN-REV-1', 'approver': 'Synthetic Reviewer', 'role': 'independent_reviewer',
       'approved_at': '2026-10-11', 'statement': STATEMENT}
OWN = {'decision_id': 'SYN-OWN-1', 'approver': 'Synthetic Owner', 'role': 'dataset_owner',
       'approved_at': '2026-10-11', 'statement': STATEMENT}
# Release-level resolutions recorded in the export authorization (synthetic; who decides is not modelled).
ADM = {'decision_id': 'SYN-ADM-1', 'approver': 'Synthetic Contract Owner', 'role': 'contract_owner',
       'approved_at': '2026-10-12', 'statement': STATEMENT}
DECL = {'decision_id': 'SYN-DECL-1', 'approver': 'Synthetic Contract Owner', 'role': 'contract_owner',
        'approved_at': '2026-10-12', 'statement': STATEMENT}
# Q-FUTURE is resolved by citing the existing reviewer decision; no new adjudication.
RESOLVED = {'Q-ADMISSION': ['SYN-ADM-1'], 'Q-CP2-DECL-EVIDENCE': ['SYN-DECL-1'], 'Q-FUTURE': ['SYN-REV-1']}
LIC = {'decision_id': 'SYN-LIC-1', 'approver': 'Synthetic License Owner', 'role': 'license_owner',
       'approved_at': '2026-10-12', 'statement': STATEMENT}
REL = {'decision_id': 'SYN-REL-1', 'approver': 'Synthetic Owner', 'role': 'dataset_owner',
       'approved_at': '2026-10-12', 'statement': STATEMENT}
T, F, N = True, False, None
# n, split, family, targets (read, write, delete, send_data, change_permissions), status, open questions, role
SPEC = [
    (1, 'train', 'train-1', (T, F, F, N, F), 'provisional', ['Q-ADMISSION'], 'classification'),
    (2, 'train', 'train-1', (T, T, T, T, T), 'provisional', ['Q-ADMISSION'], 'classification'),
    (3, 'train', 'train-2', (T, T, T, F, F), 'pending', ['Q-ADMISSION', 'Q-FUTURE'], 'classification'),
    (4, 'validation', 'validation-1', (T, F, N, F, F), 'provisional', ['Q-ADMISSION'], 'classification'),
    (5, 'calibration', 'calibration-1', (F, T, F, F, F), 'provisional', ['Q-ADMISSION'], 'classification'),
    (6, 'train', 'train-2', (N, N, N, N, N), 'provisional', ['Q-ADMISSION'], 'technical_error_check'),
]
GOLD = (1, 2, 3, 4, 5)


def case(n):
    return 'S13C2-' + format(0xC0DE0000 + n, '032X')


def cp1_case(n):
    return 'S13V03-' + f'DEV-{n:02d}'  # assembled at run time, like case()


def family(key):
    return f'syn-family-{key}'


def group(key):
    return f'syn-group-{key}'


def model_input(n, split, cid=None):
    inp = {'server_id': f'syn-server-{n}', 'tool_name': f'syn_tool_{n}', 'tool_description': 'synthetic tool',
           'tool_schema': {'type': 'object', 'properties': {'n': {'type': 'integer'}}}, 'raw_arguments': {'n': n}}
    return {'id': cid or case(n), 'split': split, 'input_profile': 'synthetic', 'input': inp,
            'hashes': {'input_sha256': sha(inp), 'arguments_sha256': sha(inp['raw_arguments']),
                       'definition_sha256': definition_hash(inp)}}


def label_row(n, split, fam, targets, status, questions, role, cid=None):
    cid = cid or case(n)
    tech = role == 'technical_error_check'
    t = dict(zip(ACTIONS, targets))
    core = {'expected_outcome': 'technical_error' if tech else 'classification',
            'technical_error': 'synthetic-timeout' if tech else None, 'per_action_targets': t,
            'known_mask': {a: int(v is not None) for a, v in t.items()}, 'unknown': any(v is None for v in targets),
            'contract_view': {'synthetic': True}}
    return {'id': cid, 'split': split, 'family_id': family(fam), 'template_id': f'syn-template-{fam}',
            'leakage_group_id': group(fam), **core, 'label_status': status, 'evidence_strength': 'synthetic',
            'open_questions': list(questions), 'hashes': model_input(n, split, cid)['hashes'],
            'provenance': {'kind': 'synthetic'}, 'source_material': {'kind': 'synthetic'},
            'evaluation': {'role': role, 'in_semantic_accuracy': not tech,
                           'in_pilot_export': role == 'classification' and status == 'provisional'},
            'label_sha256': sha({'id': cid, **core})}


def rows_and_inputs(spec=SPEC, cp1=()):
    """Rows and model inputs; case numbers in `cp1` get historical CP1-style ids."""
    ids = {s[0]: cp1_case(s[0]) if s[0] in cp1 else case(s[0]) for s in spec}
    rows = [label_row(*s, cid=ids[s[0]]) for s in spec]
    return rows, [model_input(s[0], s[1], ids[s[0]]) for s in spec]


def labels_of(row):
    return {k: copy.deepcopy(row[k]) for k in ('per_action_targets', 'known_mask', 'unknown')}


def _jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')
    return path


def write_exports(exports, rows, inputs, extra_manifest=None):
    """A CP2-style export directory (labels/, model_inputs/, non_pilot/..., EXPORT_MANIFEST.json)."""
    exports = Path(exports)
    files = {}
    for prefix, pilot in (('', True), ('non_pilot/', False)):
        for s in ('train', 'validation', 'calibration'):
            keep = [r for r in rows if r['split'] == s and r['evaluation']['in_pilot_export'] == pilot]
            ids = {r['id'] for r in keep}
            for kind, data in (('labels', keep), ('model_inputs', [m for m in inputs if m['id'] in ids])):
                rel = f'{prefix}{kind}/{s}.jsonl'
                files[rel] = file_sha(write(exports / rel, _jsonl(data)))
    manifest = {'export_kind': 'sou13_cp2_label_separated_exports', 'status': 'DRAFT', 'cp2_version': DATASET_VERSION,
                'files_sha256': files, **(extra_manifest or {})}
    write(exports / 'EXPORT_MANIFEST.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return exports


def public_view(rows, family_split=None):
    fs = family_split or {family(k): s for k, s in FAMILY.items()}
    body = {'manifest_kind': 'sou13_cp2_split_manifest_PUBLIC_VIEW', 'status': 'FROZEN', 'frozen': True,
            'family_split': dict(sorted(fs.items())),
            'family_group': {family(k): group(k) for k in sorted(FAMILY)},
            'test': {'families': 1, 'cases': 1, 'identities': 'withheld'},
            'commitments': {'synthetic_commitment_sha256': sha('synthetic commitment')}, 'labels_in_manifest': False}
    return {**body, 'manifest_sha256': sha(body)}


def write_package(pkg, rows, inputs, view=None):
    """A synthetic dev_review_package with MANIFEST.json over every file."""
    pkg = Path(pkg)
    write_exports(pkg / 'exports', rows, inputs)
    view = view or public_view(rows)
    write(pkg / 'manifest' / 'split_manifest.PUBLIC_VIEW.json', json.dumps(view, indent=2, sort_keys=True) + '\n')
    write(pkg / 'README_RU.md', 'synthetic package\n')
    reseal_package(pkg, view['manifest_sha256'])
    return pkg


def reseal_package(pkg, public_view_sha=None):
    pkg = Path(pkg)
    old = json.loads((pkg / 'MANIFEST.json').read_text(encoding='utf-8')) if (pkg / 'MANIFEST.json').exists() else {}
    files = {p.relative_to(pkg).as_posix(): file_sha(p) for p in sorted(pkg.rglob('*'))
             if p.is_file() and p.name != 'MANIFEST.json'}
    m = {'package': 'dev_review_package', 'status': 'DRAFT', 'splits': ['train', 'validation', 'calibration'],
         'files_sha256': files, 'public_view_sha256': public_view_sha or old.get('public_view_sha256')}
    write(pkg / 'MANIFEST.json', json.dumps(m, indent=2, sort_keys=True) + '\n')


def base_for(exports_dir, split_sha=SPLIT_SHA):
    return {'dataset_version': DATASET_VERSION,
            'export_manifest_sha256': file_sha(Path(exports_dir) / 'EXPORT_MANIFEST.json'),
            'split_manifest_sha256': split_sha, 'contract_sha256': CONTRACT['sha256']}


def submission(rows, cases=GOLD, reviewer='Synthetic Reviewer', decision='SYN-REV-1'):
    by_id = {r['id']: r for r in rows}
    return {'submission_kind': 'sou13_gold_reviewer_submission', 'reviewer': reviewer, 'decision_id': decision,
            'submitted_at': '2026-10-11',
            'cases': [{'case_id': case(n), 'split': by_id[case(n)]['split'],
                       'reviewer_labels': labels_of(by_id[case(n)])} for n in cases]}


def decisions(rows, confirm=GOLD, status='approved', approvals=(REV, OWN), exclude=()):
    by_id = {r['id']: r for r in rows}
    transitions = [{'case_id': case(n), 'split': by_id[case(n)]['split'], 'to_status': 'confirmed',
                    'adjudication': 'independent_human', 'decision_ids': ['SYN-REV-1'],
                    'rationale': 'synthetic', 'label_change': None} for n in confirm]
    transitions += [{'case_id': case(n), 'split': by_id[case(n)]['split'], 'to_status': 'excluded',
                     'adjudication': 'owner_inspected', 'decision_ids': ['SYN-OWN-1'],
                     'rationale': 'synthetic', 'label_change': None} for n in exclude]
    return {'decisions_kind': 'sou13_gold_owner_decisions', 'status': status, 'created_at': '2026-10-12',
            'scope': {'splits': ['train', 'validation', 'calibration']},
            'approvals': [copy.deepcopy(a) for a in approvals], 'transitions': transitions}


def authorization(plan, **overrides):
    doc = {'authorization_kind': 'sou13_gold_dev_export_authorization', 'authorization_version': 1,
           'status': 'approved', 'created_at': '2026-10-12', 'base': dict(plan['base']),
           'addendum_chain': dict(plan['addendum_chain']),
           'gold_set': {'sha256': plan['gold_set_sha256'], 'counts': dict(plan['counts'])},
           'recipient': {'team': 'Synthetic recipient', 'reference': 'synthetic'},
           'permitted_use': {'training_use_authorized': True, 'splits': ['train', 'validation', 'calibration'],
                             'license_id': 'SYNTHETIC-LICENSE', 'terms_reference': 'synthetic',
                             'restrictions': ['synthetic fixture']},
           'license_decision_ids': ['SYN-LIC-1'], 'release_decision_ids': ['SYN-REL-1'],
           'release_blockers_resolved': copy.deepcopy(RESOLVED),
           'approvals': [copy.deepcopy(x) for x in (LIC, REL, ADM, DECL)]}
    for k, v in overrides.items():
        doc[k] = v
    return doc
