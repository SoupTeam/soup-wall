"""External trust anchor for the authoritative manifest and owner approval (audit finding F2).

Internal self-hashes (manifest_sha256, frozen_assignment_sha256, the public view sha) only prove internal
consistency: an attacker who edits assignments and recomputes every hash passes them. They do NOT authenticate
the owner. Authentication comes from an anchor document signed with the OWNER's SSH key
(`ssh-keygen -Y sign -n sou13-cp2-freeze`) and verified against an independently PINNED owner key:

  * allowed_signers   path supplied by the verifier; it must lie OUTSIDE every untrusted root (the repository or
                      package being verified), so the package can never vouch for itself;
  * trusted key pin   SHA256 fingerprint of the owner's public key, supplied by the verifier from an owner-controlled
                      channel (e.g. the owner's published GitHub keys); every key in allowed_signers must match it.
The anchor records the digests that must hold at verification time (full manifest, public view, frozen
assignment, key artefacts, package manifests). See docs/CP2_TRUST_ANCHOR.md (ownership, signing, rotation)."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

NAMESPACE = 'sou13-cp2-freeze'
ANCHOR_KIND = 'sou13_cp2_freeze_anchor'
ENV = {'anchor': 'SOU13_CP2_ANCHOR', 'signature': 'SOU13_CP2_ANCHOR_SIG', 'allowed_signers': 'SOU13_CP2_ALLOWED_SIGNERS',
       'trusted_key_fpr': 'SOU13_CP2_TRUSTED_KEY_FPR', 'signer': 'SOU13_CP2_SIGNER',
       'attempt_log': 'SOU13_CP2_ANCHOR_ATTEMPT_LOG'}
ATTEMPT_LOG_NAME = 'anchor_attempts.jsonl'


def attempt_log_path(cfg):
    """Where verification attempts are recorded: explicit setting, else next to the anchor (outside the repo)."""
    if cfg.get('attempt_log'):
        return Path(cfg['attempt_log'])
    return Path(cfg['anchor']).parent / ATTEMPT_LOG_NAME if cfg.get('anchor') else None


def record_attempt(cfg, ok, errors, untrusted_roots, now=None):
    """Append one verification attempt (successful OR failed) to the anchor attempt log. Failed anchors/signatures
    are never silently discarded: the record keeps their digests and the errors. Returns (path, [errors])."""
    import datetime as dt
    path = attempt_log_path(cfg)
    if path is None:
        return None, []
    if any(_inside(path, r) for r in untrusted_roots):
        return None, [f'anchor attempt log must be outside the repository/package ({path})']

    def digest(k):
        p = cfg.get(k)
        return file_digest(p) if p and Path(p).is_file() else None
    entry = {'time': (now or dt.datetime.now(dt.timezone.utc)).isoformat(), 'ok': bool(ok), 'errors': list(errors),
             'anchor': cfg.get('anchor'), 'anchor_sha256': digest('anchor'), 'signature_sha256': digest('signature'),
             'signer': cfg.get('signer'), 'trusted_key_fpr': cfg.get('trusted_key_fpr'),
             'allowed_signers': cfg.get('allowed_signers')}
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + '\n')
        f.flush()
        os.fsync(f.fileno())
    return path, []
KEY_RE = re.compile(r'((?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.\-]+)\s+([A-Za-z0-9+/=]{40,})')


class AnchorError(ValueError):
    pass


def ssh_keygen():
    exe = shutil.which('ssh-keygen')
    if not exe:
        raise AnchorError('ssh-keygen (OpenSSH >= 8.2 with -Y sign/verify) is required to verify the trust anchor')
    return exe


def _inside(path, root):
    p, r = Path(path).resolve(), Path(root).resolve()
    return p == r or r in p.parents


def key_fingerprints(allowed_signers):
    """SHA256 fingerprints of every public key listed in an allowed_signers file."""
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for n, (ktype, blob) in enumerate(KEY_RE.findall(Path(allowed_signers).read_text(encoding='utf-8'))):
            pub = Path(tmp) / f'k{n}.pub'
            pub.write_text(f'{ktype} {blob}\n', encoding='utf-8')
            res = subprocess.run([ssh_keygen(), '-l', '-E', 'sha256', '-f', str(pub)], capture_output=True, text=True)
            if res.returncode:
                raise AnchorError(f'unreadable key in allowed_signers: {res.stderr.strip()}')
            out.append(res.stdout.split()[1])
    return out


def config_from_env(**overrides):
    cfg = {k: overrides.get(k) or os.environ.get(v) for k, v in ENV.items()}
    if cfg['anchor'] and not cfg['signature']:
        cfg['signature'] = cfg['anchor'] + '.sig'
    return cfg


def verify_anchor(cfg, untrusted_roots):
    """(anchor dict, []) when the signature verifies against the pinned owner key; (None, [errors]) otherwise."""
    missing = [k for k in ('anchor', 'signature', 'allowed_signers', 'trusted_key_fpr', 'signer') if not cfg.get(k)]
    if missing:
        return None, [f'trust anchor not configured: missing {missing} (internal hashes do not authenticate the owner)']
    e = []
    for k in ('allowed_signers',):
        for root in untrusted_roots:
            if _inside(cfg[k], root):
                e.append(f'{k} must not come from the repository/package being verified ({cfg[k]})')
    for k in ('anchor', 'signature', 'allowed_signers'):
        if not Path(cfg[k]).is_file():
            e.append(f'{k} file not found: {cfg[k]}')
    if e:
        return None, e
    try:
        fprs = key_fingerprints(cfg['allowed_signers'])
    except AnchorError as exc:
        return None, [str(exc)]
    if not fprs or any(f != cfg['trusted_key_fpr'] for f in fprs):
        return None, [f'allowed_signers keys {fprs} do not match the pinned owner key {cfg["trusted_key_fpr"]}']
    with open(cfg['anchor'], 'rb') as msg:
        res = subprocess.run([ssh_keygen(), '-Y', 'verify', '-f', str(cfg['allowed_signers']), '-I', cfg['signer'],
                              '-n', NAMESPACE, '-s', str(cfg['signature'])], stdin=msg, capture_output=True, text=True)
    if res.returncode:
        return None, [f'anchor signature does not verify against the pinned owner key: {(res.stderr or res.stdout).strip()}']
    anchor = json.loads(Path(cfg['anchor']).read_text(encoding='utf-8'))
    if anchor.get('anchor_kind') != ANCHOR_KIND:
        return None, ['signed document is not a SOU-13 CP2 freeze anchor']
    return anchor, []


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def anchor_document(*, full_manifest, public_view, artefact_digests, approved_by, approved_at, decision_ref,
                    custodian_commitment=None, package_manifest_sha256=None):
    """Unsigned anchor content for the owner to sign at freeze time (nothing is frozen here)."""
    fr = full_manifest.get('freeze_record') or {}
    return {'anchor_kind': ANCHOR_KIND, 'namespace': NAMESPACE,
            'full_manifest_sha256': full_manifest['manifest_sha256'],
            'public_view_sha256': public_view['manifest_sha256'],
            'frozen_assignment_sha256': fr.get('frozen_assignment_sha256'),
            'artefact_sha256': dict(sorted(artefact_digests.items())),
            'custodian_commitment': custodian_commitment,
            'package_manifest_sha256': dict(sorted((package_manifest_sha256 or {}).items())),
            'approved_by': approved_by, 'approved_at': approved_at, 'decision_ref': decision_ref}


def anchor_digest_errors(anchor, *, full_manifest=None, public_view=None, artefact_digests=None):
    """Compare current digests with the authenticated anchor (only the fields available to this verifier)."""
    e = []
    if full_manifest is not None:
        if anchor.get('full_manifest_sha256') != full_manifest['manifest_sha256']:
            e.append('full manifest differs from the owner-signed anchor')
        fr = full_manifest.get('freeze_record') or {}
        if anchor.get('frozen_assignment_sha256') != fr.get('frozen_assignment_sha256'):
            e.append('frozen assignment differs from the owner-signed anchor')
    if public_view is not None and anchor.get('public_view_sha256') != public_view['manifest_sha256']:
        e.append('public manifest view differs from the owner-signed anchor')
    for rel, digest in (artefact_digests or {}).items():
        want = anchor.get('artefact_sha256', {}).get(rel)
        if want is not None and want != digest:
            e.append(f'{rel} differs from the owner-signed anchor')
    return e
