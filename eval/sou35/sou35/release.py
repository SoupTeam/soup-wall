"""Thin CLI over the validated custody, manifest and export functions (no logic of its own).

    python -m sou35.release <command> --workspace sealed/<name> --pool <decl dir> --records <candidates.jsonl> ...

    declare          --custodian NAME --counts T/V/C/S [--held-out-features f1,f2]   (default: full requirements)
    commit           custodian seed generated here and written ONLY to the workspace (never printed)
    draw             --confirm                                    opens the commitment and selects the test set
    accept           --custodian NAME --accepted-at T --decision-ref R
    build-manifest   --salt SALT
    freeze           --approved-by A --approved-at T --decision-ref R --confirm
    validate-manifest
    public-view                                                   writes manifest.public.json after a leak check
    export           --authorization auth.json --generation-provenance private/<file>.json
                     [--id-map private/ids/id_map.json] --out private/<dir>   (--id-map required if its digest is declared)

    All commands require --test-exclusions private/<policy>.json (verified private review package).
    After declare, commands also require --rulings sealed/<name>/rulings.json (external human decisions; private).
    Primary scoring needs a v2 rulings register (case-level status and evidence basis); a v1 register still
    validates but makes no case primary. Export also needs the owner-recorded ORIGINAL generation provenance;
    the current tooling commit is recorded separately and never substitutes for it.

ROLES AND TRUST BOUNDARY. The workspace holds the custodian's private material (seed, nonce, test families) and the
FULL manifest, which names test families: only the sealed-test custodian may hold it, so draw, accept, freeze and the
development export are run by the custodian. Only manifest.public.json and the export directory leave custody.
Approver, custodian and authorizer fields are text supplied by the operator and bound into sha256-digested documents:
they record who is CLAIMED to have decided; they do not authenticate a person, and nothing here is signed.

Every command re-validates the pool and records first. Exit 0 = success, 1 = refused (reason on stderr), 2 = usage.
Standard output never prints a seed, nonce, case id or test family id; refusals print only an error category unless
--verbose-errors is given (custodian console only)."""
import argparse
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from . import ROOT, check_pool, custody, export, families, feasibility, records
from . import manifest as M, rulings

STATE, PRIVATE, FULL, PUBLIC = 'custody_state.json', 'custody_private.json', 'manifest.full.json', 'manifest.public.json'


class Refused(Exception):
    pass


def _read(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise Refused(f'missing required file: {Path(path).name}')


def _write(path, obj):
    Path(path).write_text(json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')


def _rule(state):
    rule = state.get('rule') or {}
    req = {s: frozenset(r) for s, r in rule.get('requirements', {}).items()}
    counts = rule.get('counts')
    if not req or not counts or custody.rule_digest(req, counts) != state.get('rule_digest'):
        raise Refused('split rule missing or does not match the custody rule digest')
    return req, counts


def _pool(args):
    decls = families.load_dir(args.pool)
    recs = [json.loads(line) for line in Path(args.records).read_text(encoding='utf-8').splitlines() if line]
    errors = records.dataset_errors(recs, decls)
    expected = sum(len(d['cases']) + len(d['technical_error_cases']) for d in decls)
    if errors or len(recs) != expected:
        raise Refused(f'records do not validate against the pool ({len(errors)} errors, {len(recs)}/{expected} records)')
    return decls, recs


def _rulings(args, decls, recs):
    if not args.rulings:
        raise Refused('semantic rulings register is required')
    reg = _read(args.rulings)
    ledger, _ = rulings.validate(reg, decls, recs)
    if ledger is None:
        raise Refused('semantic rulings register is invalid or out of scope')
    return reg, ledger


def _test_exclusions(args, decls, recs):
    """Private, pool-bound policy. Mandatory for every CLI custody operation.

    The public code knows nothing about real family identities; group bans are
    derived only from the verified candidate records and private policy.
    """
    if not args.test_exclusions:
        raise Refused('private test-exclusions policy is mandatory')
    policy_path = Path(args.test_exclusions).resolve()
    check_pool.ensure_private_out(policy_path.parent)
    policy = _read(policy_path)
    if not isinstance(policy, dict) or policy.get('policy_version') != 'sou35-test-exclusions-v1':
        raise Refused('unrecognized private test-exclusions policy')
    if policy.get('pool_digest') != custody.pool_digest(decls):
        raise Refused('test exclusions not bound to current pool')
    if not (isinstance(policy.get('source_review_package_sha256'), str)
            and custody.HEX64.match(policy['source_review_package_sha256'])):
        raise Refused('test exclusions missing review-package digest')
    banned = policy.get('excluded_family_ids')
    fids = {d['family_id'] for d in decls}
    if (not isinstance(banned, list) or any(not isinstance(f, str) for f in banned)
            or len(banned) != len(set(banned)) or not set(banned) <= fids):
        raise Refused('invalid family exclusions; no operation permitted')
    family_group = {}
    for r in recs:
        old = family_group.setdefault(r['family_id'], r['leakage_group_id'])
        if old != r['leakage_group_id']:
            raise Refused('candidate leakage group mismatch')
    if set(family_group) != fids:
        raise Refused('test-exclusion pool records are incomplete')

    # The policy is not itself proof of which families the reviewer restricted. Cross-check
    # it against the actual, SHA-pinned private review supplement before any CLI
    # custody operation. A forged/empty list in an otherwise well-formed JSON
    # policy is refused, even before the seed has been committed.
    review_path = policy.get('source_review_package_path')
    if not isinstance(review_path, str) or not review_path.strip():
        raise Refused('test exclusions missing original private review package path')
    try:
        review_bytes = Path(review_path).read_bytes()
        review_sha256 = hashlib.sha256(review_bytes).hexdigest()
        if review_sha256 != policy['source_review_package_sha256']:
            raise Refused('test-exclusion review package SHA-256 mismatch')
        with zipfile.ZipFile(io.BytesIO(review_bytes)) as archive:
            members = [name for name in archive.namelist()
                       if name.endswith('near_transfer_test_exclusions.PRIVATE.json')]
            if len(members) != 1:
                raise Refused('verified review package lacks a unique private restriction list')
            source = json.loads(archive.read(members[0]))
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, UnicodeError) as exc:
        raise Refused('private test-exclusion review package unavailable or invalid') from exc
    if not isinstance(source, dict) or source.get('test_allowed') is not False:
        raise Refused('private review package has no valid closed-test restriction')
    entries = source.get('families')
    if not isinstance(entries, list) or not entries:
        raise Refused('private review package restriction list is empty or invalid')
    reviewed = {}
    for entry in entries:
        if (not isinstance(entry, dict)
                or not isinstance(entry.get('family_id'), str)
                or not isinstance(entry.get('leakage_group_id'), str)
                or entry['family_id'] in reviewed):
            raise Refused('invalid or duplicate private review-package family')
        reviewed[entry['family_id']] = entry['leakage_group_id']
    if (set(reviewed) != set(banned) or source.get('family_count') != len(reviewed)
            or source.get('leakage_group_count') != len(set(reviewed.values()))
            or any(family_group.get(fid) != gid for fid, gid in reviewed.items())):
        raise Refused('test-exclusion policy does not match the reviewed private restrictions')
    return frozenset(family_group[f] for f in banned)


def _provenance(args):
    """Owner-recorded ORIGINAL generation provenance (private file); validated by export.provenance_errors."""
    if not args.generation_provenance:
        raise Refused('original generation provenance is required for export')
    path = Path(args.generation_provenance).resolve()
    check_pool.ensure_private_out(path.parent)
    return _read(path)


def _id_map(args):
    """Bytes of the private id map, read only when supplied; a declared id_map_sha256 without it is refused."""
    if not args.id_map:
        return None
    path = Path(args.id_map).resolve()
    check_pool.ensure_private_out(path.parent)
    try:
        return path.read_bytes()
    except OSError:
        raise Refused(f'missing required file: {path.name}')


def _tooling():
    """CURRENT export tooling identity, recorded separately from the original generation source."""
    def git(*a):
        try:
            done = subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout.strip() if done.returncode == 0 else None
    status = git('status', '--porcelain', '--', str(ROOT / 'sou35'))
    return {'tooling_commit': git('rev-parse', 'HEAD'), 'tooling_source_dirty': None if status is None else bool(status),
            'note': 'current export tooling; NOT the original generation source'}


def _private(ws):
    p = _read(ws / PRIVATE)
    return p.get('test_families'), p.get('nonce')


def run(args):
    ws = check_pool.ensure_private_out(args.workspace)
    ws.mkdir(parents=True, exist_ok=True)
    decls, recs = _pool(args)
    test_exclusions = _test_exclusions(args, decls, recs)
    reg, ledger = _rulings(args, decls, recs) if args.command != 'declare' else (None, None)
    # Coverage always comes from the validated ledger; `declare` builds no table-dependent state.
    table = feasibility.group_table(recs, ledger) if ledger else None
    groups = M._groups(recs)
    cmd = args.command
    if cmd == 'declare':
        if (ws / STATE).exists():
            raise Refused('custody already declared in this workspace')
        req = feasibility.default_requirements(set(args.held_out_features.split(','))) if args.held_out_features \
            else feasibility.default_requirements()
        counts = dict(zip(feasibility.SPLITS, (int(x) for x in args.counts.split('/'))))
        state = custody.declare(decls, args.custodian, req, counts)
        state['rule'] = {'counts': counts, 'requirements': {s: sorted(r) for s, r in req.items()}}
        _write(ws / STATE, state)
        return {'state': state['state'], 'requirements_profile': M._profile(req)}
    state = _read(ws / STATE)
    req, counts = _rule(state)
    if state.get('state') != 'declared' and state.get('rulings_sha256') != rulings.digest(reg):
        raise Refused('rulings changed since custody commitment; new custody workflow required')
    if state['state'] in ('committed', 'drawn', 'custody_accepted'):
        private_seed = _read(ws / PRIVATE).get('seed')
        if (not isinstance(private_seed, str) or not custody.HEX64.match(private_seed)
                or custody._exclusions_commitment(private_seed, test_exclusions)
                != state['test_exclusions_commitment']):
            raise Refused('private test-exclusion policy changed after commitment')
    if cmd == 'commit':
        state, private = custody.commit(state, table, req, counts, custody.new_seed(),
                                        rulings_sha256=rulings.digest(reg),
                                        test_exclusions=test_exclusions)
        _write(ws / PRIVATE, private)
        _write(ws / STATE, state)
        return {'state': state['state'], 'n_feasible_sets': state['n_feasible_sets']}
    if cmd == 'draw':
        if not args.confirm:
            raise Refused('draw is irreversible: re-run with --confirm (custodian only)')
        state, private = custody.draw(state, table, req, counts, _read(ws / PRIVATE).get('seed'), groups,
                                      test_exclusions=test_exclusions)
        _write(ws / PRIVATE, private)
        _write(ws / STATE, state)
        return {'state': state['state'], 'test_family_count': state['test_family_count']}
    if cmd == 'accept':
        state = custody.accept(state, custodian=args.custodian, accepted_at=args.accepted_at,
                               decision_ref=args.decision_ref)
        _write(ws / STATE, state)
        return {'state': state['state']}
    test_families, nonce = _private(ws)
    if test_families is not None and any(
            f in set(test_families) for g in test_exclusions for f in groups[g]):
        raise Refused('restricted family was present in the test selection')
    if cmd == 'build-manifest':
        m = M.build_draft(decls, recs, state, test_families, nonce, counts, req, args.salt, rulings_register=reg)
        _write(ws / FULL, m)
        return {'status': m['status'], 'requirements_profile': m['requirements_profile']}
    m = _read(ws / FULL)
    if cmd == 'freeze':
        if not args.confirm:
            raise Refused('freeze is final for this manifest version: re-run with --confirm')
        m = M.freeze(m, decls, recs, state, test_families, nonce, approved_by=args.approved_by,
                     approved_at=args.approved_at, decision_ref=args.decision_ref, rulings_register=reg)
        _write(ws / FULL, m)
        return {'status': m['status']}
    errors = M.manifest_errors(m, decls, recs, state, test_families, nonce, rulings_register=reg)
    if cmd == 'validate-manifest':
        if errors:
            raise Refused(f'manifest invalid: {len(errors)} error(s)')
        return {'status': m['status'], 'errors': 0}
    if errors:
        raise Refused(f'manifest invalid: {len(errors)} error(s)')
    if cmd == 'public-view':
        view = M.public_view(m, decls, recs, state, test_families, nonce, rulings_register=reg)
        secret = list(test_families) + [nonce, _read(ws / PRIVATE).get('seed')]
        secret += [x for d in decls if d['family_id'] in test_families for i in d['identities'] for x in i]
        if M.public_view_errors(view, forbidden=[s for s in secret if s]):
            raise Refused('public view failed its leak check; nothing written')
        _write(ws / PUBLIC, view)
        return {'written': PUBLIC, 'status': view['status']}
    if cmd == 'export':
        summary = export.write_export(recs, decls, m, state, _read(args.authorization), args.out,
                                      test_families=test_families, nonce=nonce, rulings_register=reg,
                                      generation_provenance=_provenance(args), export_tooling=_tooling(),
                                      id_map_bytes=_id_map(args))
        test_ids = [r['id'] for r in recs if r['family_id'] in set(test_families)]
        excluded = [r['id'] for r in recs if r['family_id'] not in set(test_families)
                    and rulings.evidence_stratum(r, ledger) != rulings.PRIMARY]
        if export.verify_export(args.out, test_ids, excluded):
            raise Refused('export failed verification')
        return {'exported': summary['record_counts']}
    raise Refused(f'unknown command {cmd}')


def parser():
    ap = argparse.ArgumentParser(prog='python -m sou35.release', description=__doc__.splitlines()[0])
    ap.add_argument('command', choices=['declare', 'commit', 'draw', 'accept', 'build-manifest', 'freeze',
                                        'validate-manifest', 'public-view', 'export'])
    ap.add_argument('--workspace', required=True)
    ap.add_argument('--rulings', help='private, pool-bound external human decisions (required after declare)')
    ap.add_argument('--test-exclusions', help='mandatory private pool-bound closed-test exclusion policy')
    ap.add_argument('--pool', required=True)
    ap.add_argument('--records', required=True)
    for opt in ('--custodian', '--counts', '--held-out-features', '--accepted-at', '--decision-ref', '--salt',
                '--approved-by', '--approved-at', '--authorization', '--generation-provenance', '--id-map',
                '--out'):
        ap.add_argument(opt)
    ap.add_argument('--confirm', action='store_true')
    ap.add_argument('--verbose-errors', action='store_true',
                    help='print full validator details on refusal; may name families (custodian console only)')
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        out = run(args)
    except (Refused, custody.CustodyError, M.ManifestError, export.ExportError, check_pool.PrivacyError,
            families.DeclarationError) as exc:
        # validator messages can name families; by default print only the category before the detail list
        detail = str(exc) if args.verbose_errors else str(exc).split(': [')[0].split(': {')[0]
        print(f'REFUSED ({type(exc).__name__}): {detail}', file=sys.stderr)
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
