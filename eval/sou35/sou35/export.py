"""Deterministic, label-separated DEVELOPMENT export, gated on a valid FROZEN manifest and an explicit authorization.

    <out>/model_inputs/{train,validation,calibration}.jsonl   id, split, input_profile, input, hashes only
    <out>/labels/{split}.jsonl                                 reviewed cases with accepted semantic rulings only
    Unapproved and technical-error rows are EXCLUDED entirely (private owner review only).
    <out>/EXPORT_MANIFEST.json                                 file digests, counts, manifest and authorization refs

Rows come from the reused SOU-13 helpers (sou13cp2.exports.model_input / label_row). Test records are never
written. Output goes only to the ignored private/ or sealed/ workspace. Byte-identical for identical inputs."""
import json
from pathlib import Path

from . import adapters, manifest as M, rulings
from .check_pool import ensure_private_out

EXPORT_SCOPE = 'sou35_internal_dev_export'
AUTH_FIELDS = ('scope', 'authorized_by', 'authorized_at', 'decision_ref', 'manifest_sha256', 'rulings_sha256')


class ExportError(ValueError):
    pass


def authorization_errors(auth, m):
    if not isinstance(auth, dict):
        return ['explicit export authorization is required']
    e = [f'authorization.{k} missing' for k in AUTH_FIELDS if not (isinstance(auth.get(k), str) and auth[k].strip())]
    if not e:
        if auth['scope'] != EXPORT_SCOPE:
            e.append(f'authorization scope must be {EXPORT_SCOPE!r}')
        if auth['rulings_sha256'] != m.get('rulings_sha256'):
            e.append('authorization is not bound to semantic rulings')
        if auth['manifest_sha256'] != m.get('manifest_sha256'):
            e.append('authorization is not bound to this manifest')
        if auth['authorized_by'].startswith('ai_assisted'):
            e.append('an AI-assisted annotator cannot authorize an export')
    return e


def _jsonl(rows):
    return ''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in rows).encode('utf-8')


def scored(r, rulings_register):
    # Mechanical statuses are retained; a separately recorded human ruling determines admissibility.
    return r['expected_outcome'] == 'classification' and rulings.primary_scoring_admissible(r, rulings_register)


def plan_export(records, decls, m, custody_state, authorization, *, test_families, nonce, rulings_register):
    """Validated in-memory export {relative path: bytes}; raises ExportError before anything is written."""
    if m.get('status') != 'FROZEN':
        raise ExportError('export requires a FROZEN manifest')
    errs = M.manifest_errors(m, decls, records, custody_state, test_families, nonce,
                             rulings_register=rulings_register) + authorization_errors(authorization, m)
    if errs:
        raise ExportError(f'export refused: {errs}')
    ex = adapters.sou13_exports()
    split = m['family_split']
    dev = []
    for r in sorted(records, key=lambda r: r['id']):
        if split[r['family_id']] in M.DEV_SPLITS:
            dev.append(dict(r, split=split[r['family_id']], leakage_group_id=m['family_group'][r['family_id']]))
    files = {}
    for s in M.DEV_SPLITS:
        rows = [r for r in dev if r['split'] == s]
        files[f'model_inputs/{s}.jsonl'] = _jsonl(ex.model_input(r) for r in rows if scored(r, rulings_register))
        files[f'labels/{s}.jsonl'] = _jsonl(ex.label_row(r) for r in rows if scored(r, rulings_register))
    summary = {
        'export_kind': EXPORT_SCOPE, 'status': 'INTERNAL_DEVELOPMENT_EXPORT',
        'labels': 'mechanical source labels with external semantic/case-evidence review; not a Gold addendum',
        'manifest_sha256': m['manifest_sha256'],
        'rulings_sha256': m['rulings_sha256'],
        'record_inventory_sha256': m['record_inventory_sha256'],
        'authorization': {k: authorization[k] for k in ('authorized_by', 'authorized_at', 'decision_ref')},
        'test': 'withheld: test inputs and labels stay in sealed custody',
        'files_sha256': {rel: adapters.sha_bytes(b) for rel, b in sorted(files.items())},
        'record_counts': {s: {'scored': sum(r['split'] == s and scored(r, rulings_register) for r in dev),
                              'not_scored': sum(r['split'] == s and not scored(r, rulings_register) for r in dev)} for s in M.DEV_SPLITS},
    }
    files['EXPORT_MANIFEST.json'] = (json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')
    return files


def write_export(records, decls, m, custody_state, authorization, out_dir, *, test_families, nonce, rulings_register):
    files = plan_export(records, decls, m, custody_state, authorization,
                        test_families=test_families, nonce=nonce, rulings_register=rulings_register)
    out = ensure_private_out(out_dir)
    if out.exists() and any(out.iterdir()):
        raise ExportError('export destination must be empty (stale/extra files are unsafe)')
    for rel, data in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return json.loads(files['EXPORT_MANIFEST.json'])


def verify_export(out_dir, test_ids=()):
    """Digests match, model inputs carry no label-bearing key, and no listed test id appears anywhere."""
    out = Path(out_dir)
    e = []
    summary = json.loads((out / 'EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
    expected = set(summary['files_sha256']) | {'EXPORT_MANIFEST.json'}
    actual = {str(p.relative_to(out)).replace('\\', '/') for p in out.rglob('*') if p.is_file()}
    if actual != expected:
        e.append('export directory contains missing or unexpected files')
    ex = adapters.sou13_exports()
    for rel, digest in summary['files_sha256'].items():
        data = (out / rel).read_bytes()
        if adapters.sha_bytes(data) != digest:
            e.append(f'{rel}: digest mismatch')
        text = data.decode('utf-8')
        if any(t in text for t in test_ids):
            e.append(f'{rel}: contains a test record')
        if 'model_inputs' in rel:
            for line in text.splitlines():
                bad = set(json.loads(line)) & ex.LABEL_BEARING_KEYS
                if bad:
                    e.append(f'{rel}: model input carries label-bearing keys {sorted(bad)}')
    return e
