# SPDX-License-Identifier: Apache-2.0
"""File handling shared by the gold-addendum validator, drafting tool and development exporter.

Fail-closed helpers only: reading development label rows checked against EXPORT_MANIFEST.json, detecting any
test or custodian material by name (contents are never read), keeping outputs out of Git work trees, and
writing new files without overwriting."""
import json
from pathlib import Path

from sou13.hashing import file_sha

from .addendum import DEV_SPLITS

EXPORT_PREFIXES = ('', 'non_pilot/')
EXPORT_KIND = 'sou13_cp2_label_separated_exports'
# Names and folders that only test or custodian material uses (sou13cp2.exports, sou13cp2.handoff, pipeline).
TEST_FILE_NAMES = frozenset({'test.jsonl', 'test_labels.jsonl', 'model_inputs_test.jsonl', 'candidates_test.jsonl',
                             'test_candidates.jsonl', 'test_families.json', 'test_review_queue.csv',
                             'coverage_test.json', 'case_ids.test.json', 'split_manifest.full.json',
                             'taxonomy.full.json', 'test_review_package.md'})
TEST_DIR_NAMES = frozenset({'cp2_sealed', 'restricted_test_custodian', 'restricted', 'sealed', 'sealed_test',
                            'test_gold'})


class GoldFileError(ValueError):
    pass


def test_material(directory):
    """Relative paths below `directory` whose name or folder marks test/custodian material (names only)."""
    directory = Path(directory)
    hits = []
    for p in sorted(directory.rglob('*')):
        rel = p.relative_to(directory)
        parts = [x.lower() for x in rel.parts]
        if parts[-1] in TEST_FILE_NAMES or set(parts[:-1] if p.is_file() else parts) & TEST_DIR_NAMES:
            hits.append(rel.as_posix())
    return hits


def read_jsonl(path):
    return [json.loads(x) for x in Path(path).read_text(encoding='utf-8').splitlines() if x.strip()]


def export_label_files():
    return [f'{prefix}labels/{split}.jsonl' for prefix in EXPORT_PREFIXES for split in DEV_SPLITS]


def export_input_files():
    return [f'{prefix}model_inputs/{split}.jsonl' for prefix in EXPORT_PREFIXES for split in DEV_SPLITS]


def read_export(exports, need_inputs=False):
    """(export manifest, label rows, model-input rows, errors) for a CP2 export directory. Every file used must be
    listed in EXPORT_MANIFEST.json with its digest; any test material makes the whole directory unusable."""
    exports = Path(exports)
    errors = [f'{rel}: test or custodian material in the export directory' for rel in test_material(exports)]
    manifest_path = exports / 'EXPORT_MANIFEST.json'
    if not manifest_path.is_file():
        return None, [], [], errors + ['missing EXPORT_MANIFEST.json']
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('export_kind') != EXPORT_KIND:
        errors.append(f'EXPORT_MANIFEST.json: export_kind {manifest.get("export_kind")!r} is not {EXPORT_KIND!r}')
    listed = manifest.get('files_sha256') or {}
    for rel in sorted(listed):
        if Path(rel).name.lower() in TEST_FILE_NAMES:
            errors.append(f'EXPORT_MANIFEST.json lists test material {rel}')
    rows, inputs = [], []
    for rel in export_label_files() + (export_input_files() if need_inputs else []):
        p = exports / rel
        if not p.is_file():
            errors.append(f'{rel}: missing')
            continue
        if listed.get(rel) != file_sha(p):
            errors.append(f'{rel}: digest differs from EXPORT_MANIFEST.json')
        (rows if '/labels/' in f'/{rel}' else inputs).extend(read_jsonl(p))
    return manifest, rows, inputs, errors


def inside_git_worktree(path):
    """True when `path` (existing or not) lies inside a Git work tree."""
    p = Path(path).resolve()
    return any((q / '.git').exists() for q in (p, *p.parents))


def inside(path, root):
    p, r = Path(path).resolve(), Path(root).resolve()
    return p == r or r in p.parents


def dumps(obj):
    """Deterministic JSON text (sorted keys, UTF-8, LF)."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + '\n'


def dumps_jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n' for r in rows)


def write_new(path, text):
    """Write a new file outside any Git work tree; never overwrite."""
    path = Path(path)
    if inside_git_worktree(path):
        raise GoldFileError(f'refusing to write {path.name} inside a Git work tree (private material stays out of '
                            f'repositories)')
    if path.exists():
        raise GoldFileError(f'refusing to overwrite existing {path.name}')
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'xb') as f:
        f.write(text.encode('utf-8'))
