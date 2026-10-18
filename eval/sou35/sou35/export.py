"""Deterministic, label-separated DEVELOPMENT export, gated on a valid FROZEN manifest and an explicit authorization.

    <out>/model_inputs/{train,validation,calibration}.jsonl   id, split, input_profile, input, hashes only
    <out>/labels/{split}.jsonl                                 PRIMARY evidence stratum only (rulings.evidence_stratum)
    Every other stratum (diagnostic disputed / program-only / information-limited, unresolved, rejected, unreviewed,
    basis unrecorded) and technical-error rows are EXCLUDED entirely; only their counts are reported.
    <out>/EXPORT_MANIFEST.json                                 file digests, per-stratum counts, manifest and
                                                               authorization refs, original generation provenance,
                                                               human case-review references, AI technical reviews

Rows come from the reused SOU-13 helpers (sou13cp2.exports.model_input / label_row). Test records are never
written. No diagnostic data export exists. Output goes only to the ignored private/ or sealed/ workspace.
Byte-identical for identical inputs."""
import json
import re
from pathlib import Path

from . import adapters, custody, generate, manifest as M, rulings
from .check_pool import ensure_private_out

EXPORT_SCOPE = 'sou35_internal_dev_export'
AUTH_FIELDS = ('scope', 'authorized_by', 'authorized_at', 'decision_ref', 'manifest_sha256', 'rulings_sha256')
PROVENANCE_VERSION = 'sou35-generation-provenance-v1'
_COMMIT = re.compile(r'^([0-9a-f]{40}|[0-9a-f]{64})$')


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
        if rulings.is_ai_identity(auth['authorized_by']):
            e.append('an AI-assisted annotator cannot authorize an export')
    return e


def provenance_errors(prov, decls, records, id_map_bytes=None):
    """The ORIGINAL generation identity, recorded by the owner. It is never derived from the current Git HEAD.

    LIMITS: these checks bind the declared provenance to the current pool, the exact record inventory and the
    records' generator version. They cannot authenticate `source_commit` or `command`: those remain owner
    attestations, and the current HEAD is never compared with or substituted for them. A declared `id_map_sha256`
    is verified against the supplied id-map file bytes (digest, and that it maps every declared case to its record
    id); without those bytes the export is refused rather than claiming an unverified id map."""
    if not isinstance(prov, dict) or prov.get('provenance_version') != PROVENANCE_VERSION:
        return ['original generation provenance is required']
    g = prov.get('original_generation')
    if not isinstance(g, dict):
        return ['original generation provenance is required']
    e = [f'original_generation.{k} missing' for k in ('generator_version', 'source_commit', 'command',
                                                      'generated_at', 'recorded_by')
         if not (isinstance(g.get(k), str) and g[k].strip())]
    if e:
        return e
    if not _COMMIT.match(g['source_commit']):
        e.append('original_generation.source_commit must be a full lowercase commit id')
    if {r['source_material']['generator'] for r in records} != {g['generator_version']}:
        e.append('original generation version differs from the records')
    if g.get('pool_digest') != custody.pool_digest(decls):
        e.append('original generation provenance is not bound to the current pool')
    if g.get('record_inventory_sha256') != M.record_inventory_digest(records):
        e.append('original generation provenance is not bound to the current record inventory')
    if 'id_map_sha256' in g:
        e += _id_map_errors(g['id_map_sha256'], id_map_bytes, records)
    return e


def _id_map_errors(declared, data, records):
    if not (isinstance(declared, str) and custody.HEX64.match(declared)):
        return ['original_generation.id_map_sha256 must be a sha256']
    if data is None:
        return ['declared id map digest cannot be verified without the id map file']
    if adapters.sha_bytes(data) != declared:
        return ['id map file does not match the declared id_map_sha256']
    try:
        id_map = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return ['id map file is not valid JSON']
    expected = {generate.id_key(r['family_id'], r['source_material']['case_kind'], r['source_material']['case_index']):
                r['id'] for r in records}
    # The persisted map is append-only (generate.generate), so keys of no current case are tolerated; every current
    # case must map to its exact record id and no other key may claim a current id.
    if not isinstance(id_map, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in id_map.items()):
        return ['id map file must map string case keys to string record ids']
    ids = set(expected.values())
    if any(id_map.get(k) != v for k, v in expected.items()) or \
            sum(v in ids for v in id_map.values()) != len(ids):
        return ['id map file does not map the declared cases to the current record ids']
    return []


def tooling_errors(tooling):
    """The CURRENT export tooling revision; kept separate from (and never substituted for) the original
    generation source in `generation_provenance`."""
    if not isinstance(tooling, dict):
        return ['current export tooling identity is required']
    e = []
    if not (isinstance(tooling.get('tooling_commit'), str) and _COMMIT.match(tooling['tooling_commit'])):
        e.append('export_tooling.tooling_commit must be a full lowercase commit id')
    if not isinstance(tooling.get('tooling_source_dirty'), bool):
        e.append('export_tooling.tooling_source_dirty must be recorded as true or false')
    return e


def _jsonl(rows):
    return ''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in rows).encode('utf-8')


def scored(r, ledger):
    # Mechanical statuses are retained; the evidence stratum (human review + basis + safeguards) decides.
    # `ledger` must be a validated rulings.Ledger; a raw register dict is refused.
    return rulings.evidence_stratum(r, ledger) == rulings.PRIMARY


def _case_review_ref(r, ledger):
    entry = ledger.entry(r['id'])
    return {k: entry.get(k) for k in ('row_sha256', 'status', 'evidence_basis', 'reviewed_by', 'reviewer_kind',
                                      'reviewed_at', 'decision_ref', 'review_method', 'group_decision_id',
                                      'group_review_plan_sha256', 'independent_of_generation')}


def _ai_reviews(r, ledger):
    entry = ledger.entry(r['id'])
    reviews = [{k: t[k] for k in ('review_kind', 'reviewer', 'reviewed_at', 'decision', 'source_file_sha256')}
               for t in r['technical_reviews']]
    return {'record_technical_reviews': reviews, 'ledger_refs': list(entry.get('ai_technical_review_refs', [])),
            'confirms_labels': False}


def plan_export(records, decls, m, custody_state, authorization, *, test_families, nonce, rulings_register,
                generation_provenance, export_tooling, id_map_bytes=None):
    """Validated in-memory export {relative path: bytes}; raises ExportError before anything is written."""
    if m.get('status') != 'FROZEN':
        raise ExportError('export requires a FROZEN manifest')
    errs = M.manifest_errors(m, decls, records, custody_state, test_families, nonce,
                             rulings_register=rulings_register) + authorization_errors(authorization, m) \
        + provenance_errors(generation_provenance, decls, records, id_map_bytes)
    errs += tooling_errors(export_tooling)
    if errs:
        raise ExportError(f'export refused: {errs}')
    ledger = rulings.load(rulings_register, decls, records)  # validated once; already checked by manifest_errors
    ex = adapters.sou13_exports()
    split = m['family_split']
    dev = []
    for r in sorted(records, key=lambda r: r['id']):
        if split[r['family_id']] in M.DEV_SPLITS:
            dev.append(dict(r, split=split[r['family_id']], leakage_group_id=m['family_group'][r['family_id']]))
    # Strata are computed on the stored record (the split fields above are export-time additions).
    by_id = {r['id']: r for r in records}
    stratum = {r['id']: rulings.evidence_stratum(by_id[r['id']], ledger) for r in dev}
    primary = [r for r in dev if stratum[r['id']] == rulings.PRIMARY]
    files = {}
    for s in M.DEV_SPLITS:
        rows = [r for r in primary if r['split'] == s]
        files[f'model_inputs/{s}.jsonl'] = _jsonl(ex.model_input(r) for r in rows)
        files[f'labels/{s}.jsonl'] = _jsonl(ex.label_row(r) for r in rows)
    counts = {}
    for s in M.DEV_SPLITS:
        in_split = [r for r in dev if r['split'] == s]
        by = {k: sum(stratum[r['id']] == k for r in in_split) for k in rulings.STRATA}
        counts[s] = {'scored': by[rulings.PRIMARY], 'not_scored': len(in_split) - by[rulings.PRIMARY],
                     'by_stratum': by}
    summary = {
        'export_kind': EXPORT_SCOPE, 'status': 'INTERNAL_DEVELOPMENT_EXPORT',
        'labels': 'mechanical synthetic labels in the primary evidence stratum (external human case review, '
                  'interface-supported synthetic basis); not real-tool evidence and not a Gold addendum',
        'eligibility_policy': ledger.eligibility_policy,
        'manifest_sha256': m['manifest_sha256'],
        'rulings_sha256': m['rulings_sha256'],
        'record_inventory_sha256': m['record_inventory_sha256'],
        'authorization': {k: authorization[k] for k in ('authorized_by', 'authorized_at', 'decision_ref')},
        'test': 'withheld: test inputs and labels stay in sealed custody',
        'diagnostic': 'withheld: no diagnostic data export is authorized; counts only',
        'generation_provenance': generation_provenance,
        'generation_provenance_limits': 'bound to pool, record inventory and generator version; source_commit and '
                                        'command are owner attestations, not authenticated',
        'id_map_verified': 'id_map_sha256' in generation_provenance['original_generation'],
        'export_tooling': export_tooling,
        'case_reviews': {r['id']: _case_review_ref(by_id[r['id']], ledger) for r in primary},
        'ai_technical_reviews': {r['id']: _ai_reviews(by_id[r['id']], ledger) for r in primary},
        'files_sha256': {rel: adapters.sha_bytes(b) for rel, b in sorted(files.items())},
        'record_counts': counts,
    }
    files['EXPORT_MANIFEST.json'] = (json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')
    return files


def write_export(records, decls, m, custody_state, authorization, out_dir, *, test_families, nonce, rulings_register,
                 generation_provenance, export_tooling, id_map_bytes=None):
    files = plan_export(records, decls, m, custody_state, authorization,
                        test_families=test_families, nonce=nonce, rulings_register=rulings_register,
                        generation_provenance=generation_provenance, export_tooling=export_tooling,
                        id_map_bytes=id_map_bytes)
    out = ensure_private_out(out_dir)
    if out.exists() and any(out.iterdir()):
        raise ExportError('export destination must be empty (stale/extra files are unsafe)')
    for rel, data in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return json.loads(files['EXPORT_MANIFEST.json'])


def verify_export(out_dir, test_ids=(), excluded_ids=()):
    """Digests match, model inputs carry no label-bearing key, no listed test id or excluded (non-primary) id appears
    anywhere (data files and EXPORT_MANIFEST), and exported labels and human case-review references correspond."""
    out = Path(out_dir)
    e = []
    summary_text = (out / 'EXPORT_MANIFEST.json').read_text(encoding='utf-8')
    summary = json.loads(summary_text)
    expected = set(summary['files_sha256']) | {'EXPORT_MANIFEST.json'}
    actual = {str(p.relative_to(out)).replace('\\', '/') for p in out.rglob('*') if p.is_file()}
    if actual != expected:
        e.append('export directory contains missing or unexpected files')
    ex = adapters.sou13_exports()
    if any(t in summary_text for t in test_ids):
        e.append('EXPORT_MANIFEST.json: contains a test record')
    if any(t in summary_text for t in excluded_ids):
        e.append('EXPORT_MANIFEST.json: contains a non-primary record')
    label_ids = set()
    for rel, digest in summary['files_sha256'].items():
        data = (out / rel).read_bytes()
        if adapters.sha_bytes(data) != digest:
            e.append(f'{rel}: digest mismatch')
        text = data.decode('utf-8')
        if any(t in text for t in test_ids):
            e.append(f'{rel}: contains a test record')
        if any(t in text for t in excluded_ids):
            e.append(f'{rel}: contains a non-primary record')
        if 'model_inputs' in rel:
            for line in text.splitlines():
                bad = set(json.loads(line)) & ex.LABEL_BEARING_KEYS
                if bad:
                    e.append(f'{rel}: model input carries label-bearing keys {sorted(bad)}')
        if rel.startswith('labels/'):
            label_ids |= {json.loads(line)['id'] for line in text.splitlines()}
    if label_ids != set(summary.get('case_reviews', {})):
        e.append('exported labels and human case-review references differ')
    return e
