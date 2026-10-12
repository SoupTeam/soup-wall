"""Adversarial public-leak audit (run by the owner/custodian; needs the restricted materials to score).

1. Copy the repository WITHOUT custodian material (cp2_sealed/, handoff/RESTRICTED_*) to a temp directory.
2. In a separate `python -I` process on that copy (it cannot see the real repository), an attacker:
   a) loads the public code and looks for any test family, catalog entry or record;
   b) receives the test model inputs (as an evaluated system would at evaluation time) and tries to map each
      input to public semantics by identity, server, normalised tool name, normalised description, and
      structural signature (schema fingerprint + argument keys) of public templates;
   c) predicts labels from every match;
   d) runs the public-mode validator on the copy.
3. The auditor scores the predictions against the sealed test labels and scans the public copy for test
   fingerprints (strong and weak).
Expected: no test family visible, 0/54 inputs mapped, 0 labels reconstructed, public validator PASS."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import ROOT
from .handoff import NON_PUBLIC, scan, split_strength, test_fingerprints, _full_state
from .pipeline import SEALED_DIR

ATTACKER = r'''
import json, sys
from pathlib import Path
copy_root, inputs_file = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(copy_root))
from sou13cp2 import restricted
from sou13cp2.catalog import get_catalog
from sou13cp2.identity import normalized_description, normalized_name, schema_fingerprint
from sou13cp2.taxonomy import families
ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
fams = families()
out = {'restricted_available_in_copy': restricted.available(),
       'restricted_families_visible': sum(f['exposure'] == 'restricted_test' for f in fams),
       'catalog_entries': len(get_catalog()), 'public_families': len(fams)}
idx = {'identity': {}, 'server': {}, 'name': {}, 'description': {}, 'structure': {}}
for f in fams:
    for s, t in f['identities']:
        idx['identity'][(s, t)] = f
        idx['server'][s] = f
        idx['name'][normalized_name(t)] = f
    for d in f['descriptions']:
        if normalized_description(d):
            idx['description'][normalized_description(d)] = f
    for t in f['templates']:
        idx['structure'][(schema_fingerprint(t['schema']), tuple(sorted(t['arg_keys'])))] = (f, t)
def labels(t):
    acts, unk = set(t['established_actions']), t['unknown_profile'] != 'none'
    return {a: True if a in acts else (None if unk else False) for a in ACTIONS}, unk
preds = {}
matched = {k: 0 for k in idx}
for line in inputs_file.read_text(encoding='utf-8').splitlines():
    row = json.loads(line); i = row['input']
    keys = {'identity': (i.get('server_id'), i['tool_name']), 'server': i.get('server_id'),
            'name': normalized_name(i['tool_name']), 'description': normalized_description(i.get('tool_description')),
            'structure': (schema_fingerprint(i['tool_schema']), tuple(sorted(i['raw_arguments'] or {})))}
    for kind, key in keys.items():
        hit = idx[kind].get(key)
        if hit is None:
            continue
        matched[kind] += 1
        f, t = hit if kind == 'structure' else (hit, [x for x in hit['templates'] if x['evidence_kind'] != 'input_validation'][0])
        preds.setdefault(row['id'], {})[kind] = labels(t)
out['inputs_matched_by'] = matched
out['predictions'] = {k: {kind: [p[0], p[1]] for kind, p in v.items()} for k, v in preds.items()}
print(json.dumps(out))
'''


def public_copy(root, dst):
    ignore_top = {p.rstrip('/').split('/')[0] for p in NON_PUBLIC if '/' not in p.rstrip('/')}

    def ignore(directory, names):
        rel = Path(directory).relative_to(root).as_posix()
        out = {n for n in names if n == '__pycache__'}
        if rel == '.':
            out |= {n for n in names if n in ignore_top or n == SEALED_DIR}
        if rel == 'handoff':
            out |= {n for n in names if n.startswith('RESTRICTED')}
        return out
    shutil.copytree(root, dst, ignore=ignore)
    return dst


def run(root=ROOT):
    root = Path(root)
    fams, manifest, records = _full_state(root)
    test = {r['id']: r for r in records if r['split'] == 'test'}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        copy = public_copy(root, tmp / 'public_copy')
        sealed_in_copy = sorted(p.relative_to(copy).as_posix() for p in copy.rglob('*')
                                if SEALED_DIR in p.parts or 'RESTRICTED' in p.as_posix())
        inputs = tmp / 'test_inputs.jsonl'  # handed to the attacker; NOT placed in the copy
        inputs.write_text(''.join(json.dumps({'id': i, 'input': r['input']}) + '\n' for i, r in sorted(test.items())),
                          encoding='utf-8')
        script = tmp / 'attacker.py'
        script.write_text(ATTACKER, encoding='utf-8')
        att = subprocess.run([sys.executable, '-I', '-B', str(script), str(copy), str(inputs)], capture_output=True,
                             text=True, encoding='utf-8', cwd=str(tmp), timeout=600)
        if att.returncode:
            raise RuntimeError(f'attacker failed: {att.stderr[-2000:]}')
        attack = json.loads(att.stdout.strip().splitlines()[-1])
        val = subprocess.run([sys.executable, '-I', '-B', str(copy / 'scripts_cp2' / 'validate_cp2.py')],
                             capture_output=True, text=True, encoding='utf-8', cwd=str(copy), timeout=900)
        try:
            public_validation = json.loads(val.stdout)
        except ValueError:
            public_validation = {'result': 'ERROR', 'stderr': val.stderr[-2000:]}
        strong, weak = split_strength(test_fingerprints(fams, manifest, records))
        strong_hits, weak_hits = scan(copy, strong), scan(copy, weak)
    correct = 0
    for rid, kinds in attack['predictions'].items():
        truth = (test[rid]['annotation']['per_action_targets'], test[rid]['annotation']['unknown'])
        correct += any((p[0], p[1]) == truth for p in kinds.values())
    return {
        'audit_kind': 'sou13_cp2_adversarial_public_leak_audit',
        'public_copy_contains_restricted_paths': sealed_in_copy,
        'attacker': {k: v for k, v in attack.items() if k != 'predictions'},
        'test_inputs_given_to_attacker': len(test),
        'test_inputs_mapped_to_public_semantics': len(attack['predictions']),
        'test_labels_reconstructed_exactly': correct,
        'public_mode_validation': {'result': public_validation.get('result'), 'mode': public_validation.get('mode'),
                                   'errors': public_validation.get('errors', [])[:10],
                                   'stderr': public_validation.get('stderr')},
        'strong_fingerprints': len(strong), 'strong_fingerprint_hits': strong_hits,
        'weak_word_fingerprints': len(weak), 'weak_word_hits_for_human_review': weak_hits,
        'passed': (not sealed_in_copy and attack['restricted_families_visible'] == 0
                   and not attack['predictions'] and correct == 0 and not strong_hits
                   and public_validation.get('result') == 'PASS'),
    }
