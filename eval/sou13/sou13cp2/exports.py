"""Label-separated exports.

  <out>/model_inputs/{train,validation,calibration}.jsonl   id, split, input_profile, input, hashes (no labels,
                                     no family ids, no scenario tags: they encode the answer)
  <out>/labels/{train,validation,calibration}.jsonl   labels for development/tuning/calibration
  <sealed>/test_labels.jsonl, <sealed>/model_inputs_test.jsonl   test labels AND inputs, custodian only
                                     (Q-CUSTODIAN): test inputs + the admitted registry would reveal labels
  <out>/EXPORT_MANIFEST.json         sha256 of every exported file; no test information
"""
import json
from pathlib import Path

from sou13.hashing import file_sha, sha

from . import VERSION

SPLITS = ('train', 'validation', 'calibration', 'test')
LABEL_SPLITS = ('train', 'validation', 'calibration')
MODEL_INPUT_KEYS = ('id', 'split', 'input_profile', 'input', 'hashes')
# Record keys that carry or encode the answer; none may reach a model-input row.
LABEL_BEARING_KEYS = frozenset({'annotation', 'evidence', 'evidence_strength', 'label_status', 'expected_outcome',
                                'technical_error', 'open_questions', 'review', 'scenario_tags', 'evaluation_group',
                                'family_id', 'template_id', 'alias_group_id', 'leakage_group_id', 'exposure',
                                'per_action_targets', 'known_mask', 'unknown', 'contract_view', 'label_evidence',
                                'forbidden_actions', 'rationale', 'source_material', 'evaluation',
                                'technical_reviews'})
ALLOWED_INPUT_KEYS = {'server_id', 'tool_name', 'tool_description', 'tool_schema', 'pinned_schema', 'raw_arguments'}
LABEL_CORE = ('expected_outcome', 'technical_error', 'per_action_targets', 'known_mask', 'unknown', 'contract_view')
SEALED_NAME = 'test_labels.jsonl'
SEALED_INPUTS = 'model_inputs_test.jsonl'


class ExportError(ValueError):
    pass


assert not LABEL_BEARING_KEYS & set(MODEL_INPUT_KEYS)


def model_input(r):
    return {k: r[k] for k in MODEL_INPUT_KEYS}


def label_core(r):
    a = r['annotation']
    core = {'expected_outcome': r['expected_outcome'], 'technical_error': r['technical_error'],
            'per_action_targets': a['per_action_targets'], 'known_mask': a['known_mask'], 'unknown': a['unknown'],
            'contract_view': a['contract_view']}
    if 'forbidden_actions' in a:
        core['forbidden_actions'] = a['forbidden_actions']
    return core


def label_row(r):
    core = label_core(r)
    return {'id': r['id'], 'split': r['split'], 'family_id': r['family_id'], 'template_id': r['template_id'],
            'leakage_group_id': r['leakage_group_id'], **core, 'label_status': r['label_status'],
            'evidence_strength': r['evidence_strength'], 'open_questions': r['open_questions'],
            'hashes': r['hashes'], 'provenance': r['provenance'], 'source_material': r['source_material'],
            'evaluation': r['evaluation'],
            'label_sha256': sha({'id': r['id'], **core})}  # bound to the record: equal label vectors differ


def pilot(r):
    """Pilot export = provisional plain-classification records (technical review 2026-10-10: pending disputes,
    technical-error rows, admission tests and set-valued oracles stay outside the pilot export)."""
    return bool(r['evaluation']['in_pilot_export'])


def _jsonl(rows):
    return ''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in rows)


def _inside(a, b):
    a, b = Path(a).resolve(), Path(b).resolve()
    return a == b or b in a.parents


def write_exports(records, out_dir, sealed_dir):
    out_dir, sealed_dir = Path(out_dir), Path(sealed_dir)
    if _inside(sealed_dir, out_dir) or _inside(out_dir, sealed_dir):
        raise ExportError('sealed test-label directory must be outside the export directory (and vice versa)')
    records = sorted(records, key=lambda r: r['id'])
    files = {}
    for s in LABEL_SPLITS:
        files[f'model_inputs/{s}.jsonl'] = _jsonl(model_input(r) for r in records if r['split'] == s and pilot(r))
        files[f'labels/{s}.jsonl'] = _jsonl(label_row(r) for r in records if r['split'] == s and pilot(r))
        files[f'non_pilot/model_inputs/{s}.jsonl'] = _jsonl(model_input(r) for r in records
                                                            if r['split'] == s and not pilot(r))
        files[f'non_pilot/labels/{s}.jsonl'] = _jsonl(label_row(r) for r in records if r['split'] == s and not pilot(r))
    for rel, text in files.items():
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode('utf-8'))
    test = [r for r in records if r['split'] == 'test']
    if test:  # full mode only: test inputs AND labels are custodian-only (inputs + registry reveal labels)
        sealed_dir.mkdir(parents=True, exist_ok=True)
        (sealed_dir / SEALED_NAME).write_bytes(_jsonl(label_row(r) for r in test).encode('utf-8'))
        (sealed_dir / SEALED_INPUTS).write_bytes(_jsonl(model_input(r) for r in test).encode('utf-8'))
    # The public export manifest carries no test information at all (identical in full and public mode).
    manifest = {'export_kind': 'sou13_cp2_label_separated_exports', 'status': 'DRAFT', 'cp2_version': VERSION,
                'files_sha256': {rel: file_sha(out_dir / rel) for rel in sorted(files)},
                'test': 'withheld: inputs and labels are in the restricted custodian materials',
                'pilot_rule': 'labels/ and model_inputs/ hold only provisional classification records; non_pilot/ holds '
                              'pending, technical-error, admission-rejection and set-valued-oracle records',
                'record_counts': {s: {'pilot': sum(r['split'] == s and pilot(r) for r in records),
                                      'non_pilot': sum(r['split'] == s and not pilot(r) for r in records)}
                                  for s in LABEL_SPLITS}}
    (out_dir / 'EXPORT_MANIFEST.json').write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8'))
    return manifest


QUEUE_FIELDS = ['case_id', 'split', 'label_status', 'evaluation_group', 'family_id', 'server_id', 'tool_name',
                'tool_description', 'raw_arguments'] + [f'proposed_{a}' for a in
                                                        ('read', 'write', 'delete', 'send_data', 'change_permissions')] + \
               ['proposed_unknown', 'evidence_strength', 'open_questions', 'rationale']


def _fmt(v):
    return 'null' if v is None else str(v).lower()


def review_queue(records):
    """Review worksheet (decisions go into the empty columns; proposed values are never edited)."""
    import csv
    import io
    from sou13.build import REVIEW_FIELDS
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(QUEUE_FIELDS + REVIEW_FIELDS)
    for r in sorted(records, key=lambda r: r['id']):
        t, inp = r['annotation']['per_action_targets'], r['input']
        w.writerow([r['id'], r['split'], r['label_status'], r['evaluation_group'], r['family_id'],
                    inp.get('server_id'), inp['tool_name'], _fmt(inp.get('tool_description')) if
                    inp.get('tool_description') is None else inp['tool_description'],
                    json.dumps(inp['raw_arguments'], ensure_ascii=False, sort_keys=True)]
                   + [_fmt(t[a]) for a in ('read', 'write', 'delete', 'send_data', 'change_permissions')]
                   + [_fmt(r['annotation']['unknown']), r['evidence_strength'], ';'.join(r['open_questions']),
                      r['annotation']['rationale']] + [''] * len(REVIEW_FIELDS))
    return buf.getvalue()


PUBLIC_TEST_ID_ALLOWED = ()  # no public file may name a test record


def public_leak_errors(root, records, public_globs=('cp2/**/*', 'docs/CP2_*.md', 'schema/cp2_*.json')):
    """No public handoff artefact may carry test labels: test ids appear only in the label-free test model
    inputs; test label digests and test record ids never appear anywhere else."""
    root = Path(root)
    test = [r for r in records if r['split'] == 'test']
    ids = {r['id'] for r in test}
    digests = {label_row(r)['label_sha256'] for r in test}
    e = []
    files = sorted({p for g in public_globs for p in root.glob(g) if p.is_file()})
    for p in files:
        rel = p.relative_to(root).as_posix()
        text = p.read_bytes().decode('utf-8', errors='replace')
        hit_ids = sorted(i for i in ids if i in text)
        if hit_ids and rel not in PUBLIC_TEST_ID_ALLOWED:
            e.append(f'{rel}: contains test record ids {hit_ids[:3]}')
        if any(d in text for d in digests):
            e.append(f'{rel}: contains test label digests')
    return e


def _read(path):
    return [json.loads(x) for x in Path(path).read_text(encoding='utf-8').splitlines() if x.strip()]


def export_errors(out_dir, sealed_dir, records):
    """Isolation of test labels and absence of labels from model inputs (empty list = OK)."""
    out_dir, sealed_dir = Path(out_dir), Path(sealed_dir)
    e = []
    if _inside(sealed_dir, out_dir) or _inside(out_dir, sealed_dir):
        e.append('sealed directory overlaps the export directory')
    by_id = {r['id']: r for r in records}
    test_ids = {r['id'] for r in records if r['split'] == 'test'}
    test_inputs = {r['hashes']['input_sha256'] for r in records if r['split'] == 'test'}
    for p in sorted(out_dir.rglob('*')):
        if p.is_file() and p.name == SEALED_NAME:
            e.append(f'{p}: sealed test labels found inside the export directory')
    allowed_files = {f'{s}.jsonl' for s in LABEL_SPLITS}
    for prefix, want_pilot in (('', True), ('non_pilot/', False)):
        labels_dir = out_dir / f'{prefix}labels'
        if labels_dir.exists():
            extra = sorted(p.name for p in labels_dir.iterdir() if p.name not in allowed_files)
            if extra:
                e.append(f'{prefix}labels/: unexpected files {extra} (test labels are never exported)')
        for s in LABEL_SPLITS:
            p = labels_dir / f'{s}.jsonl'
            if not p.exists():
                e.append(f'missing {prefix}labels/{s}.jsonl')
                continue
            for row in _read(p):
                where = f'{prefix}labels/{s}.jsonl: {row.get("id")}'
                if row.get('split') != s:
                    e.append(f'{where} has split {row.get("split")}')
                if row.get('id') in test_ids or row.get('hashes', {}).get('input_sha256') in test_inputs:
                    e.append(f'{where} is a test record or duplicates a test input')
                r = by_id.get(row.get('id'))
                if r is None or row != label_row(r):
                    e.append(f'{where} does not match its record')
                elif pilot(r) != want_pilot:
                    e.append(f'{where} is in the wrong export (pilot={pilot(r)}: {r["evaluation"]["role"]}, '
                             f'{r["label_status"]})')
        if (out_dir / f'{prefix}model_inputs' / 'test.jsonl').exists():
            e.append(f'{prefix}model_inputs/test.jsonl must not be exported (test inputs are custodian-only)')
        for s in LABEL_SPLITS:
            p = out_dir / f'{prefix}model_inputs' / f'{s}.jsonl'
            if not p.exists():
                e.append(f'missing {prefix}model_inputs/{s}.jsonl')
                continue
            for row in _read(p):
                where = f'{prefix}model_inputs/{s}.jsonl: {row.get("id")}'
                if tuple(sorted(row)) != tuple(sorted(MODEL_INPUT_KEYS)):
                    e.append(f'{where} has keys {sorted(set(row) - set(MODEL_INPUT_KEYS))} beyond the label-free view')
                elif set(row['input']) - ALLOWED_INPUT_KEYS:
                    e.append(f'{where} input carries non-input fields')
                if row.get('split') != s:
                    e.append(f'{where} has split {row.get("split")}')
                if row.get('id') in by_id and pilot(by_id[row['id']]) != want_pilot:
                    e.append(f'{where} is in the wrong export')
    if test_ids:  # full mode
        for name in (SEALED_NAME, SEALED_INPUTS):
            sealed = sealed_dir / name
            if not sealed.exists():
                e.append(f'test records exist but sealed {name} is missing')
                continue
            rows = _read(sealed)
            if any(x.get('split') != 'test' for x in rows) or {x['id'] for x in rows} != test_ids:
                e.append(f'sealed {name} must contain exactly the test records')
    mpath = out_dir / 'EXPORT_MANIFEST.json'
    if mpath.exists():
        m = json.loads(mpath.read_text(encoding='utf-8'))
        for rel, digest in m['files_sha256'].items():
            if not (out_dir / rel).exists() or file_sha(out_dir / rel) != digest:
                e.append(f'EXPORT_MANIFEST: digest mismatch for {rel}')
    else:
        e.append('missing EXPORT_MANIFEST.json')
    return e
