"""Build and validate the CP2 artefacts (deterministic; no clock, no randomness).

FULL mode (owner/custodian: cp2_sealed/restricted/test_families.json present):
  - the authoritative manifest is cp2_sealed/manifest/split_manifest.FULL.json. A DRAFT is regenerated on every
    build; a FROZEN manifest is loaded and never regenerated (splits.freeze/amend).
  - test records, labels, inputs, review queue and coverage are written under cp2_sealed/ only.
  - the public manifest view (no test family named; SHA-256 commitments to the restricted materials) is derived.
PUBLIC mode (any copy without cp2_sealed/): assignments come from the public manifest view; only
  train/validation/calibration artefacts are built and validated. Public artefacts are byte-identical in
  both modes."""
import json
import tempfile
from collections import Counter
from pathlib import Path

from sou13.hashing import file_sha

from . import ROOT, restricted
from .coverage import reports
from .exports import SEALED_INPUTS, SEALED_NAME, export_errors, public_leak_errors, review_queue, write_exports
from .generate import generate
from .leakage import leakage_errors, record_item, taxonomy_items
from .records import cp1_view_records, record_errors
from .case_ids import PUBLIC_MAP as PUBLIC_ID_MAP
from .case_ids import TEST_MAP as TEST_ID_MAP
from .case_ids import map_errors as case_id_map_errors
from .splits import (DEFAULT_SALT, build_manifest, is_frozen, manifest_errors, public_view, public_view_errors)
from .taxonomy import CP1_TEMPLATES, families, taxonomy_document, taxonomy_errors

# public artefacts
TAXONOMY_FILE = 'cp2/taxonomy/families.PUBLIC.json'
PUBLIC_VIEW_FILE = 'cp2/manifests/split_manifest.PUBLIC_VIEW.json'
COVERAGE_FILE = 'cp2/reports/coverage.PUBLIC.json'
CANDIDATES_FILE = 'cp2/data/candidates.jsonl'
QUEUE_FILE = 'cp2/review/CANDIDATE_REVIEW_QUEUE.csv'
EXPORT_DIR = 'cp2/exports'
PUBLIC_ARTEFACTS = (TAXONOMY_FILE, COVERAGE_FILE, CANDIDATES_FILE, QUEUE_FILE, EXPORT_DIR)
# restricted artefacts (custodian only)
SEALED_DIR = 'cp2_sealed'
FULL_MANIFEST_FILE = 'cp2_sealed/manifest/split_manifest.FULL.json'
FULL_TAXONOMY_FILE = 'cp2_sealed/manifest/taxonomy.FULL.json'
SEALED_CANDIDATES = 'cp2_sealed/candidates_test.jsonl'
SEALED_QUEUE = 'cp2_sealed/TEST_REVIEW_QUEUE.csv'
SEALED_COVERAGE = 'cp2_sealed/coverage_test.json'
SEALED_ARTEFACTS = (FULL_TAXONOMY_FILE, SEALED_CANDIDATES, SEALED_QUEUE, SEALED_COVERAGE,
                    f'{SEALED_DIR}/{SEALED_NAME}', f'{SEALED_DIR}/{SEALED_INPUTS}')
SPLITS = ('train', 'validation', 'calibration', 'test')


def dump(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n' for r in rows).encode('utf-8')


def full_mode():
    return restricted.available()


def _read_json(p):
    p = Path(p)
    return json.loads(p.read_text(encoding='utf-8')) if p.exists() else None


def authoritative_manifest(root, fams, salt=DEFAULT_SALT):
    """FULL mode: a persisted FROZEN manifest is authoritative; otherwise the DRAFT is regenerated."""
    stored = _read_json(Path(root) / FULL_MANIFEST_FILE)
    if stored is not None and is_frozen(stored):
        return stored
    return build_manifest(fams, salt)


def commitments(root):
    root = Path(root)
    return {'full_split_manifest_sha256': _read_json(root / FULL_MANIFEST_FILE)['manifest_sha256'],
            'restricted_semantics_file_sha256': file_sha(root / restricted.RESTRICTED_FILE),
            'test_candidates_file_sha256': file_sha(root / SEALED_CANDIDATES),
            'test_labels_file_sha256': file_sha(root / SEALED_DIR / SEALED_NAME),
            'test_inputs_file_sha256': file_sha(root / SEALED_DIR / SEALED_INPUTS),
            'test_case_id_map_sha256': file_sha(root / TEST_ID_MAP),
            'note': 'Commitments to custodian-only files; a custodian nonce may be added at freeze time.'}


# Files whose digests an owner-signed freeze anchor records (those present are compared at verification time).
ANCHOR_ARTEFACTS = ('cp2/manifests/split_manifest.PUBLIC_VIEW.json', 'cp2/ids/case_ids.PUBLIC.json',
                    'cp2/data/candidates.jsonl', 'cp2/exports/EXPORT_MANIFEST.json', 'handoff/PACKAGE_DIGESTS.json',
                    'cp2_sealed/manifest/split_manifest.FULL.json', 'cp2_sealed/ids/case_ids.TEST.json',
                    'cp2_sealed/candidates_test.jsonl', 'cp2_sealed/restricted/test_families.json')


def current_artefact_digests(root):
    return {rel: file_sha(Path(root) / rel) for rel in ANCHOR_ARTEFACTS if (Path(root) / rel).is_file()}


def public_families(fams):
    return [f for f in fams if f['exposure'] != restricted.EXPOSURE]


def assemble(root=ROOT, salt=DEFAULT_SALT):
    """(families, manifest-like assignment, CP1 records, new records). In public mode the manifest-like object is
    the public view and only public families/records exist."""
    fams = families()
    errs = taxonomy_errors(fams)
    if errs:
        raise ValueError(f'taxonomy invalid: {errs}')
    if full_mode():
        manifest = authoritative_manifest(root, fams, salt)
    else:
        manifest = _read_json(Path(root) / PUBLIC_VIEW_FILE)
        if manifest is None:
            raise ValueError('public mode needs the public manifest view')
    return fams, manifest, cp1_view_records(root, fams, manifest), generate(fams, manifest)


def build(root=ROOT, salt=DEFAULT_SALT, out_root=None):
    """Write artefacts under out_root (default: root). CP1 data is read from root, never written."""
    root = Path(root)
    out_root = Path(out_root or root)
    fams, manifest, cp1, new = assemble(root, salt)
    records = cp1 + new
    public, sealed_cov, _ = reports(records, manifest, fams)
    outputs = {TAXONOMY_FILE: dump(taxonomy_document(public_families(fams))), COVERAGE_FILE: dump(public),
               CANDIDATES_FILE: jsonl(r for r in new if r['split'] != 'test'),
               QUEUE_FILE: review_queue([r for r in new if r['split'] != 'test']).encode('utf-8-sig')}
    if full_mode():
        outputs.update({FULL_MANIFEST_FILE: dump(manifest), FULL_TAXONOMY_FILE: dump(taxonomy_document(fams)),
                        SEALED_CANDIDATES: jsonl(r for r in new if r['split'] == 'test'),
                        SEALED_QUEUE: review_queue([r for r in new if r['split'] == 'test']).encode('utf-8-sig'),
                        SEALED_COVERAGE: dump(sealed_cov)})
    for rel, data in outputs.items():
        p = out_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    if full_mode() and out_root != root:  # commitments need the restricted sources next to the sealed outputs
        for rel in (restricted.RESTRICTED_FILE, TEST_ID_MAP):
            src = out_root / rel
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_bytes((root / rel).read_bytes())
    export_manifest = write_exports(records, out_root / EXPORT_DIR, out_root / SEALED_DIR)
    if full_mode():
        view = public_view(manifest, fams, commitments(out_root))
        p = out_root / PUBLIC_VIEW_FILE
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(dump(view))
    return {'mode': 'full' if full_mode() else 'public', 'manifest_status': manifest['status'],
            'manifest_sha256': manifest['manifest_sha256'], 'records': len(records), 'new_records': len(new),
            'export_files': len(export_manifest['files_sha256'])}


def _tree(base, rels):
    out = {}
    for rel in rels:
        p = Path(base) / rel
        files = [p] if p.is_file() else sorted(x for x in p.rglob('*') if x.is_file()) if p.exists() else []
        for f in files:
            out[f.relative_to(base).as_posix()] = f.read_bytes()
    return out


def rebuild_differences(root=ROOT):
    """Rebuild into a temporary directory and list artefacts that differ from the stored ones."""
    rels = PUBLIC_ARTEFACTS + ((PUBLIC_VIEW_FILE, FULL_MANIFEST_FILE) + SEALED_ARTEFACTS if full_mode() else ())
    with tempfile.TemporaryDirectory() as tmp:
        if not full_mode():
            dst = Path(tmp) / PUBLIC_VIEW_FILE  # public mode reads the view; it cannot regenerate it
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((Path(root) / PUBLIC_VIEW_FILE).read_bytes())
        build(root, out_root=tmp)
        fresh, stored = _tree(tmp, rels), _tree(root, rels)
    return sorted(k for k in set(fresh) | set(stored) if fresh.get(k) != stored.get(k))


def _read_jsonl(p):
    p = Path(p)
    return [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()] if p.exists() else []


def load_records(root, fams, manifest):
    """Stored records: CP1 (lifted in memory) + public CP2 candidates + sealed test candidates (full mode)."""
    root = Path(root)
    out = cp1_view_records(root, fams, manifest) + _read_jsonl(root / CANDIDATES_FILE)
    if full_mode():
        out += _read_jsonl(root / SEALED_CANDIDATES)
    return out


def _compute_fns(program):
    for step in program:
        if step['op'] == 'compute':
            yield step['fn']
        for key in ('then', 'else', 'do'):
            yield from _compute_fns(step.get(key, []))
        for sub in step.get('cases', {}).values():
            yield from _compute_fns(sub)


def restricted_hint_errors():
    """Restricted programs may only use compute functions that public programs also use, so the public code
    contains no function that exists only for a hidden family."""
    from .catalog import CATALOG
    public_fns = {fn for e in CATALOG.values() for fn in _compute_fns(e['program'])}
    hidden = {fn for e in restricted.catalog_entries().values() for fn in _compute_fns(e['program'])}
    return [f'restricted programs use compute functions absent from public programs: {sorted(hidden - public_fns)}'] \
        if hidden - public_fns else []


def trust_anchor_check(root, mode, manifest, view, anchor_cfg=None):
    """(status, errors). A FROZEN manifest must be authenticated by an owner-signed anchor verified against a pinned
    owner key supplied from outside the repository (audit F2). DRAFT manifests are reported as unanchored."""
    from .anchor import anchor_digest_errors, config_from_env, verify_anchor
    cfg = anchor_cfg if anchor_cfg is not None else config_from_env()
    configured = any(cfg.get(k) for k in ('anchor', 'allowed_signers', 'trusted_key_fpr'))
    frozen_now = is_frozen(manifest) if mode == 'full' else bool(view.get('frozen'))
    if not (frozen_now or configured):
        return 'unanchored DRAFT (internal hashes only; they do not authenticate the owner)', []
    anchor, errs = verify_anchor(cfg, [root])
    if anchor is not None:
        errs = anchor_digest_errors(anchor, full_manifest=manifest if mode == 'full' else None, public_view=view,
                                    artefact_digests=current_artefact_digests(root))
    if cfg.get('anchor'):  # every attempt with a configured anchor is recorded, failed ones included
        from .anchor import record_attempt
        _, log_errs = record_attempt(cfg, not errs, errs, [root, ROOT])
        errs = errs + log_errs
    if frozen_now and errs:
        errs = ['FROZEN manifest is not authenticated: '] + errs
    return ('verified against the pinned owner key' if not errs else 'FAILED'), errs


def validate(root=ROOT, run_cp1=True, rebuild=True, anchor_cfg=None):
    root = Path(root)
    mode = 'full' if full_mode() else 'public'
    errors = []
    errors += [f'case ids: {x}' for x in case_id_map_errors(root)]
    fams = families()
    pub_fams = public_families(fams)
    errors += [f'taxonomy: {x}' for x in taxonomy_errors(fams)]
    if json.loads((root / TAXONOMY_FILE).read_text(encoding='utf-8')) != taxonomy_document(pub_fams):
        errors.append(f'{TAXONOMY_FILE} differs from the public taxonomy')
    view = _read_json(root / PUBLIC_VIEW_FILE)
    if view is None:
        return {'result': 'FAIL', 'mode': mode, 'errors': errors + ['missing public manifest view']}
    errors += [f'public view: {x}' for x in public_view_errors(view, pub_fams)]
    if mode == 'full':
        manifest = _read_json(root / FULL_MANIFEST_FILE)
        if manifest is None:
            return {'result': 'FAIL', 'mode': mode, 'errors': errors + ['missing full manifest']}
        errors += [f'manifest: {x}' for x in manifest_errors(manifest, fams)]
        errors += restricted_hint_errors()
        if view != public_view(manifest, fams, commitments(root)):
            errors.append('public view is not derived from the full manifest and the restricted materials')
    else:
        manifest = view
    trust_status, trust_errors = trust_anchor_check(root, mode, manifest, view, anchor_cfg)
    errors += [f'trust anchor: {x}' for x in trust_errors]
    if errors:
        return {'result': 'FAIL', 'mode': mode, 'errors': errors, 'trust_anchor': trust_status}
    records = load_records(root, fams, manifest)
    cp1_ids = [r['id'] for r in records if r['source_material']['kind'] in ('sou13_v03_cp1_record', 'cp1_record_revised')]
    if sorted(cp1_ids) != sorted(CP1_TEMPLATES):
        errors.append('every CP1 record must map to exactly one family/template')
    ids = [r['id'] for r in records]
    dup_ids = sorted(i for i, n in Counter(ids).items() if n > 1)
    if dup_ids:
        errors.append(f'duplicate record ids {dup_ids[:3]} (a record is stored in more than one place)')
        seen = set()
        records = [r for r in records if not (r['id'] in seen or seen.add(r['id']))]
    dup_inputs = [h for h, n in Counter(r['hashes']['input_sha256'] for r in records).items() if n > 1]
    if dup_inputs:
        errors.append(f'{len(dup_inputs)} exact duplicate inputs (superficial duplicates are not allowed)')
    if any(r['split'] == 'test' for r in _read_jsonl(root / CANDIDATES_FILE)):
        errors.append(f'{CANDIDATES_FILE} contains test records (test labels must stay sealed)')
    by_id = {f['family_id']: f for f in fams}
    per_family = Counter(r['family_id'] for r in records)
    for f in fams:
        if per_family.get(f['family_id'], 0) != f['planned_cases']:
            errors.append(f"{f['family_id']}: {per_family.get(f['family_id'], 0)} records, taxonomy declares "
                          f"{f['planned_cases']}")
    for r in records:
        errors += [f'record: {x}' for x in record_errors(r, by_id, manifest)]
    try:
        from .records import load_cp1_records
        from .schemas import validate_records
        errors += [f'json schema: {x}' for x in validate_records(records, [r for _, r in load_cp1_records(root)])]
    except ImportError as exc:
        errors.append(f'json schema: jsonschema is required for Draft 2020-12 validation ({exc}); see requirements-cp2.txt')
    errors += leakage_errors(taxonomy_items(fams, manifest) + [record_item(r) for r in records])
    errors += [f'exports: {x}' for x in export_errors(root / EXPORT_DIR, root / SEALED_DIR, records)]
    errors += [f'public: {x}' for x in public_leak_errors(root, records)]
    if mode == 'full':
        from .handoff import public_fingerprint_hits
        errors += [f'public fingerprint: {rel}: {hits[:3]}' for rel, hits in public_fingerprint_hits(root).items()]
    public_rep, _, gates = reports(records, manifest, fams)
    errors += [f'coverage gate {s}: {x}' for s, fails in gates.items() for x in fails]
    if rebuild:
        errors += [f'stale artefact (rebuild differs): {x}' for x in rebuild_differences(root)]
    cp1 = None
    if run_cp1:
        from sou13.validate import validate as cp1_validate
        cp1 = cp1_validate(root)['result']
        if cp1 != 'PASS':
            errors.append('Checkpoint 1 validator no longer passes')
    return {
        'result': 'PASS' if not errors else 'FAIL', 'mode': mode, 'errors': errors,
        'status': manifest['status'], 'frozen': manifest['frozen'], 'manifest_sha256': manifest['manifest_sha256'],
        'taxonomy': {'families': len(fams), 'public_families': len(pub_fams),
                     'templates': sum(len(f['templates']) for f in fams),
                     'cases': sum(f['planned_cases'] for f in fams)},
        'records': {'total': len(records), 'cp1': len(cp1_ids), 'new': len(records) - len(cp1_ids),
                    'by_split': {s: sum(r['split'] == s for r in records) for s in SPLITS},
                    'label_status': dict(Counter(r['label_status'] for r in records)),
                    'confirmed': sum(r['label_status'] == 'confirmed' for r in records)},
        'coverage_gate_passed': {s: not f for s, f in gates.items()},
        'cp1_validator': cp1,
        'trust_anchor': trust_status,
        'note': 'DRAFT structure/leakage/coverage QA only. Labels remain provisional/pending; no human review.',
    }
