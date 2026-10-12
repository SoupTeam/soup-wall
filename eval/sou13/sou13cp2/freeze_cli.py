"""Freeze command logic (scripts_cp2/freeze_manifest.py). DRY-RUN BY DEFAULT; writes only with execute=True.

Safety properties (each covered by tests_cp2/test_freeze_cli.py):
  * approvals are validated (approved_by '@login', approved_at ISO-8601 with timezone and not in the future,
    decision_ref non-trivial); nothing is written on any refusal;
  * refuses an already FROZEN manifest (repeated execution), an invalid/incomplete manifest (manifest_errors,
    including the deterministic-rebuild check for DRAFT), a public copy without restricted materials, and a backup
    directory inside the repository;
  * execute: byte-verified backup OUTSIDE the repository -> temp file + fsync + atomic os.replace -> re-read and
    verify (FROZEN, no manifest errors, family_split identical); on any failure the original bytes are restored;
  * every attempt (dry-run, refused, failed, frozen) is APPENDED to a JSONL audit log; entries are never rewritten.
Freezing does not sign anything: the owner signs the external trust anchor separately (docs/CP2_TRUST_ANCHOR.md)."""
import datetime as dt
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

from . import ROOT, restricted
from .anchor import _inside
from .splits import freeze, is_frozen, manifest_errors
from .taxonomy import families

FULL_MANIFEST_FILE = 'cp2_sealed/manifest/split_manifest.FULL.json'
APPROVED_BY_RE = re.compile(r'^@[A-Za-z0-9_.\-]{2,}$')
LOG_NAME = 'freeze_attempts.jsonl'


def _now():
    return dt.datetime.now(dt.timezone.utc)


def approval_errors(approved_by, approved_at, decision_ref, now=None):
    e = []
    if not approved_by or not APPROVED_BY_RE.match(approved_by):
        e.append('approved_by must be an @login')
    try:
        t = dt.datetime.fromisoformat(approved_at or '')
        if t.tzinfo is None:
            e.append('approved_at must include a timezone offset (ISO-8601)')
        elif t > (now or _now()) + dt.timedelta(minutes=5):
            e.append('approved_at is in the future')
    except ValueError:
        e.append('approved_at must be ISO-8601 (e.g. 2026-10-11T12:00:00+05:00)')
    if not decision_ref or len(decision_ref.strip()) < 6:
        e.append('decision_ref must reference the recorded owner decision (>= 6 characters)')
    return e


def append_log(log_path, entry):
    """Append-only audit record (never rewrites earlier lines)."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + '\n')
        f.flush()
        os.fsync(f.fileno())


def dump(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')


def _post_write_check(path, original, fams):
    """Raises if the written manifest is not the expected FROZEN manifest."""
    new = json.loads(Path(path).read_text(encoding='utf-8'))
    if not is_frozen(new):
        raise RuntimeError('written manifest is not FROZEN')
    errs = manifest_errors(new, fams)
    if errs:
        raise RuntimeError(f'written manifest invalid: {errs[:3]}')
    if new['family_split'] != original['family_split']:
        raise RuntimeError('family_split changed during freeze')
    return new


def run(*, approved_by, approved_at, decision_ref, execute=False, backup_dir=None, log_path=None, root=ROOT,
        now=None):
    """Returns (exit_code, report). 0 = dry-run plan OK or frozen; 2 = refused (nothing written); 1 = failed
    during write (original restored)."""
    root = Path(root)
    path = root / FULL_MANIFEST_FILE
    now = now or _now()
    report = {'time': now.isoformat(), 'mode': 'execute' if execute else 'dry-run', 'approved_by': approved_by,
              'approved_at': approved_at, 'decision_ref': decision_ref, 'manifest': FULL_MANIFEST_FILE}
    errors = approval_errors(approved_by, approved_at, decision_ref, now)
    if execute and not backup_dir:
        errors.append('--execute requires --backup-dir outside the repository')
    def in_repo(p):
        return _inside(p, root) or _inside(p, ROOT)

    if backup_dir and in_repo(backup_dir):
        errors.append(f'backup_dir must be outside the repository ({backup_dir})')
        backup_dir = None
    log = Path(backup_dir) / LOG_NAME if backup_dir else (Path(log_path) if log_path else None)
    if log is not None and in_repo(log):
        errors.append(f'audit log must be outside the repository ({log})')
        log = None  # never write audit records into the repository
    if not restricted.available():
        errors.append('restricted materials not available (public copy): the full manifest cannot be frozen here')
    if not path.is_file():
        errors.append(f'{FULL_MANIFEST_FILE} not found')

    def finish(code, result, extra=None):
        report.update({'result': result, 'exit_code': code, **(extra or {})})
        if log is not None:
            append_log(log, report)
        report['audit_log'] = str(log) if log is not None else None
        return code, report

    if errors:
        return finish(2, 'refused', {'errors': errors})
    original_bytes = path.read_bytes()
    before_sha = hashlib.sha256(original_bytes).hexdigest()
    manifest = json.loads(original_bytes)
    if is_frozen(manifest):
        return finish(2, 'refused', {'errors': ['manifest is already FROZEN (repeated execution refused)'],
                                     'before_file_sha256': before_sha})
    fams = families()
    me = manifest_errors(manifest, fams)
    if me:
        return finish(2, 'refused', {'errors': ['manifest is invalid or incomplete'] + me[:10],
                                     'before_file_sha256': before_sha})
    frozen = freeze(manifest, fams, approved_by=approved_by, approved_at=approved_at, decision_ref=decision_ref)
    new_bytes = dump(frozen)
    plan = {'before_file_sha256': before_sha, 'before_manifest_sha256': manifest['manifest_sha256'],
            'after_manifest_sha256': frozen['manifest_sha256'],
            'after_file_sha256': hashlib.sha256(new_bytes).hexdigest(),
            'frozen_assignment_sha256': frozen['freeze_record']['frozen_assignment_sha256'],
            'families_per_split': dict(sorted(Counter(frozen['family_split'].values()).items())),
            'family_split_unchanged': frozen['family_split'] == manifest['family_split']}
    if not execute:
        return finish(0, 'dry-run: would_freeze (nothing written)', plan)
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f'split_manifest.FULL.DRAFT.{before_sha[:16]}.json'
    backup.write_bytes(original_bytes)
    if backup.read_bytes() != original_bytes:
        return finish(2, 'refused', {**plan, 'errors': ['backup verification failed; nothing written']})
    plan['backup'] = str(backup)
    tmp = path.with_name(path.name + '.freeze-tmp')
    try:
        with open(tmp, 'wb') as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _post_write_check(path, manifest, fams)
    except Exception as exc:  # restore the original bytes; never leave a partial or unverified manifest
        path.write_bytes(original_bytes)
        if tmp.exists():
            tmp.unlink()
        restored = hashlib.sha256(path.read_bytes()).hexdigest() == before_sha
        return finish(1, 'failed', {**plan, 'errors': [f'{type(exc).__name__}: {exc}'], 'original_restored': restored})
    return finish(0, 'frozen', plan)
