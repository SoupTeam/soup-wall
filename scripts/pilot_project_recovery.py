# SPDX-License-Identifier: Apache-2.0
"""Private declarative project export and exact-plan atomic catalog recovery.

Imported metadata grants no authority. Current inputs are resolved by the
accepted preset validator and every later run independently validates again.
"""
from __future__ import annotations
import argparse
import copy
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

FORMAT = 'sw-pilot-project-export/1'
BINDINGS = 'sw-pilot-project-import-bindings/1'
PLAN = 'sw-pilot-project-import-plan/1'
REPORT = 'sw-pilot-project-recovery/1'
SCOPE = 'declarative-project-references-only'
MAX_ARCHIVE = 512 * 1024
MEMBERS = ('manifest.json', 'projects.json')
EXCLUDED = ('credentials', 'provider-profile-bodies', 'grants', 'approvals', 'keys',
            'run-and-session-state', 'workspace-contents', 'executables', 'configuration-bodies')


def report(status, **values):
    return {'format': REPORT, 'scope': SCOPE, 'status': status, 'executed': False,
            'authority': False, 'observed_protection': 'not-observed',
            'excluded': list(EXCLUDED), **values}


def private_file(path, profiles, presets, cap):
    path = Path(path)
    presets.require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_input_required')
    parent = profiles._open_absolute_directory(path.parent)
    try:
        presets.directory_identity(path.parent, profiles)
        raw = presets.read_at(parent, path.name, cap)
        presets.require(raw is not None, 'input_missing')
        info = list(presets.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
        presets.require(presets.read_at(parent, path.name, cap) == raw, 'input_changed')
        return raw, {'path': str(path), 'identity': info, 'sha256': presets.digest(raw)}
    finally:
        os.close(parent)


def document(records, presets, profiles):
    presets.require(type(records) is dict and 1 <= len(records) <= 16, 'export_records_required')
    presets.validate_catalog(presets.encoded({'format': presets.FORMAT, 'records': records}), profiles)
    return {'format': FORMAT, 'scope': SCOPE, 'excluded': list(EXCLUDED), 'records': records}


def archive_bytes(doc, presets):
    body = presets.encoded(doc)
    presets.require(len(body) <= presets.CAP, 'export_record_limit')
    manifest = {'format': FORMAT, 'scope': SCOPE, 'members': [
        {'name': 'projects.json', 'bytes': len(body), 'sha256': presets.digest(body)}]}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in zip(MEMBERS, (presets.encoded(manifest), body)):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid, member.mtime = len(raw), 0o600, 0, 0, 0
            archive.addfile(member, io.BytesIO(raw))
    raw = output.getvalue()
    presets.require(len(raw) <= MAX_ARCHIVE, 'archive_limit')
    return raw


def load_archive(path, profiles, presets):
    raw, selected = private_file(path, profiles, presets, MAX_ARCHIVE)
    presets.require(len(raw) >= 1024 and len(raw) % 512 == 0, 'archive_invalid')
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for number, member in enumerate(archive):
            presets.require(number < 2 and member.name == MEMBERS[number]
                and member.type == tarfile.REGTYPE and not member.linkname and not member.pax_headers
                and member.mode == 0o600 and 0 < member.size <= presets.CAP, 'archive_inventory_invalid')
            body = archive.extractfile(member).read(presets.CAP + 1)
            presets.require(len(body) == member.size, 'archive_invalid')
            bodies[member.name] = body
        end = archive.offset
    presets.require(tuple(bodies) == MEMBERS and not any(raw[end:]), 'archive_inventory_invalid')
    doc = presets.strict_record(bodies['projects.json'], profiles)
    presets.require(set(doc) == {'format', 'scope', 'excluded', 'records'}, 'archive_schema_invalid')
    expected = document(doc['records'], presets, profiles)
    presets.require(doc == expected and raw == archive_bytes(expected, presets), 'archive_noncanonical')
    return doc, selected


def export(home, archive, consent, front, profiles, presets):
    presets.require(consent is True, 'private_export_consent_required')
    archive = Path(archive)
    presets.require(archive.is_absolute() and '..' not in archive.parts, 'canonical_input_required')
    with presets.Store(home, profiles) as store:
        value = store.read()
        doc = document(value['records'], presets, profiles)
        roots = [Path(home)]
        for record in doc['records'].values():
            b = record['binding']
            roots += [Path(b['selection']['path']).parent, Path(b['state_root']['path'])]
            roots += [Path(w['path']) for w in b['workspaces'].values()]
        def outside_preserved_roots():
            presets.require(all(not archive.is_relative_to(root)
                and not archive.is_relative_to(root.resolve()) for root in roots),
                'export_overlaps_preserved_state')
        outside_preserved_roots()
        destination = presets.directory_identity(archive.parent, profiles)
        # Retain this inode while the publisher independently opens the parent.
        pinned = profiles._open_absolute_directory(archive.parent)
        try:
            def verify_directory(fd):
                current = presets.directory_identity(archive.parent, profiles)
                for descriptor in (pinned, fd):
                    info = os.fstat(descriptor)
                    presets.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o700
                        and [info.st_dev, info.st_ino, info.st_uid] == destination == current,
                        'export_destination_changed')
                outside_preserved_roots()
            verify_directory(pinned)
            raw = archive_bytes(doc, presets)
            def verify():
                store.check()
                presets.require(store.read() == value, 'export_catalog_changed')
            exchange = front.load('project_export_private_publication', 'pilot_prerequisite_cache_exchange.py')
            class Claim:
                pass
            claim = Claim(); claim.verify = verify
            def writer(fd):
                pending = memoryview(raw)
                while pending:
                    count = os.write(fd, pending)
                    presets.require(count > 0, 'export_write_incomplete')
                    pending = pending[count:]
            exchange._publish_private(archive.parent, archive.name, writer, claim,
                                      verify_directory=verify_directory)
        finally:
            os.close(pinned)
    return report('exported', archive_sha256=presets.digest(raw), records=len(doc['records']))


def specifications(path, names, profiles, presets):
    if path is None:
        return {}, None
    raw, selected = private_file(path, profiles, presets, presets.CAP)
    value = presets.strict_record(raw, profiles)
    presets.require(set(value) == {'format', 'projects'} and value['format'] == BINDINGS
        and type(value['projects']) is dict and set(value['projects']) <= set(names), 'import_bindings_invalid')
    for spec in value['projects'].values():
        presets.require(type(spec) is dict and set(spec) == {'selection', 'provider_name', 'provider_version',
            'state_root', 'linux_budget', 'budget_preset'}, 'import_bindings_invalid')
        presets.require(all(type(spec[k]) is str for k in ('selection','provider_name','provider_version','state_root'))
            and all(spec[k] is None or type(spec[k]) is str for k in ('linux_budget','budget_preset')),
            'import_bindings_invalid')
    return value['projects'], selected


def resolve(doc, specs, home, front, profiles, presets):
    rows, candidates = [], {}
    for name, record in sorted(doc['records'].items()):
        original = record['binding']
        args = presets.binding_args(original, home)
        supplied = name in specs
        if supplied:
            args = argparse.Namespace(**specs[name], agent_home=home)
            for key in ('selection', 'state_root', 'linux_budget'):
                if getattr(args, key) is not None:
                    setattr(args, key, Path(getattr(args, key)))
        row = {'name': name, 'resolved': False, 'explicit_binding': supplied, 'inputs': {}}
        # Independently diagnose each category; these observations grant nothing.
        probes = {
            'selection': lambda: presets.reference(args.selection, profiles),
            'provider': lambda: presets.provider_reference(home, args.provider_name, args.provider_version, None, profiles)[1],
            'state_root': lambda: {'path': str(args.state_root), 'identity': presets.directory_identity(args.state_root, profiles)},
            'workspaces': lambda: {kind: front.PREP.root_identity(Path(root['path']))
                for kind, root in original['workspaces'].items()},
            'budget': lambda: (presets.budgets().reference(home, args.budget_preset) if args.budget_preset else
                presets.reference(args.linux_budget, profiles, 16384) if args.linux_budget else None),
        }
        for category, probe in probes.items():
            try:
                row['inputs'][category] = 'unchanged' if probe() == original[category] else 'changed'
            except Exception:
                row['inputs'][category] = 'unavailable'
        try:
            current = presets.snapshot(args, front, profiles)
            presets.verify(current, home, front, profiles)
            row['inputs']['workspaces'] = 'unchanged' if current['workspaces'] == original['workspaces'] else 'changed'
            row['inputs']['current_source'] = 'unchanged' if all(current[k] == original[k] for k in
                ('commit','tree','runtime_profiles_sha256','snapshot_sha256')) else 'changed'
            if supplied:
                candidates[name] = current
                row['resolved'] = True
        except Exception:
            row['inputs']['current_source'] = 'unverified'
        rows.append(row)
    return rows, candidates


def inputs(archive, bindings, home, front, profiles, presets):
    doc, archive_ref = load_archive(archive, profiles, presets)
    specs, binding_ref = specifications(bindings, doc['records'], profiles, presets)
    rows, candidates = resolve(doc, specs, home, front, profiles, presets)
    return {'archive': archive_ref, 'bindings': binding_ref, 'candidates': candidates,
            'destination_home': str(Path(home))}, doc, rows


def core(selected, home_id, store_id, catalog, presets):
    return {'format': PLAN, **selected, 'destination_home_identity': home_id,
            'destination_store_identity': store_id, 'catalog_sha256': presets.digest(presets.encoded(catalog))}


def store_identity(store):
    if store.fd is None:
        return None
    info = os.fstat(store.fd)
    return [info.st_dev, info.st_ino, info.st_uid]


def preview(archive, bindings, home, front, profiles, presets):
    selected, doc, rows = inputs(archive, bindings, home, front, profiles, presets)
    with presets.Store(home, profiles) as store:
        catalog = store.read()
        home_id = presets.directory_identity(home, profiles)
        ready = len(selected['candidates']) == len(doc['records'])
        for row in rows:
            old = catalog['records'].get(row['name'])
            row['conflict'] = None if old is None else 'duplicate' if old['binding'] == doc['records'][row['name']]['binding'] else 'name_conflict'
            ready = ready and old is None
        ready = ready and len(catalog['records']) + len(doc['records']) <= 16
        value = core(selected, home_id, store_identity(store), catalog, presets)
    return report('preview', ready=ready, projects=rows,
        capacity_available=len(catalog['records']) + len(doc['records']) <= 16,
        plan_sha256=presets.digest(presets.encoded(value)), write_attempts=0), value


def new_catalog(base, selected, token, doc, presets):
    value = copy.deepcopy(base)
    used = {r['version'] for r in base['records'].values()} | {r['version'] for r in doc['records'].values()}
    for name, binding in sorted(selected['candidates'].items()):
        presets.require(name not in value['records'] and len(value['records']) < 16, 'import_conflict_or_limit')
        version = presets.digest(presets.encoded([PLAN, token, name]))[:32]
        presets.require(version not in used, 'import_version_collision')
        used.add(version)
        value['records'][name] = {'version': version, 'binding': binding}
    raw = presets.encoded(value)
    presets.require(len(raw) <= presets.CAP, 'store_limit')
    return value, raw


def fault(_point):
    """In-process regression injection only; no CLI or environment fault switch."""


def apply(archive, bindings, home, token, front, profiles, presets, *, recovery=False):
    presets.require(type(token) is str and presets.HEX.fullmatch(token), 'current_import_plan_required')
    selected, doc, rows = inputs(archive, bindings, home, front, profiles, presets)
    presets.require(len(selected['candidates']) == len(doc['records']), 'import_inputs_unresolved')
    home_id = presets.directory_identity(home, profiles)
    stage = '.import-next-' + token
    # Check the plan without any mutation, then repeat under the shared store lock.
    if not recovery:
        shown, prepared = preview(archive, bindings, home, front, profiles, presets)
        presets.require(shown['ready'] and shown['plan_sha256'] == token, 'current_import_plan_required')
    with presets.Store(home, profiles, create=not recovery) as store:
        presets.require(store.fd is not None, 'recovery_store_missing')
        presets.fcntl.flock(store.fd, presets.fcntl.LOCK_EX | presets.fcntl.LOCK_NB)
        try:
            current = store.read(pending=stage if recovery else None, allow_empty=recovery)
            candidates = [(current, False)]
            # Publication can complete immediately before interruption. Reconstruct
            # its base only if every imported record has the exact plan-derived ID.
            base = copy.deepcopy(current)
            for name, binding in selected['candidates'].items():
                version = presets.digest(presets.encoded([PLAN, token, name]))[:32]
                if base['records'].get(name) != {'version': version, 'binding': binding}:
                    break
                del base['records'][name]
            else:
                candidates.append((base, True))
            matches = []
            for base, published in candidates:
                identities = [store_identity(store)]
                if not base['records']:
                    identities.append(None)
                for original_id in identities:
                    value = core(selected, home_id, original_id, base, presets)
                    if presets.digest(presets.encoded(value)) == token:
                        if not recovery:
                            presets.require(original_id == prepared['destination_store_identity']
                                and (original_id is not None or store.new), 'import_destination_changed')
                        matches.append((base, published))
            presets.require(len(matches) == 1, 'current_import_plan_required')
            base, published = matches[0]
            value, raw = new_catalog(base, selected, token, doc, presets)
            retained = presets.read_at(store.fd, stage)
            if retained is not None:
                presets.require(recovery and retained == raw, 'recovery_stage_changed')
            # Resolve all inputs again while the accepted catalog lock is held.
            def revalidate():
                again, _, _ = inputs(archive, bindings, home, front, profiles, presets)
                presets.require(again == selected, 'import_inputs_changed')
                presets.require(presets.directory_identity(home, profiles) == home_id, 'import_destination_changed')
                store.check()
                presets.require(store.read(pending=stage, allow_empty=recovery) == (value if published else base), 'import_catalog_changed')
            revalidate()
            if published:
                presets.require(retained is None, 'recovery_stage_changed')
                presets.require(current == value, 'import_catalog_changed')
                return report('imported', recovered=True, plan_sha256=token, records=len(doc['records']))
            try:
                if retained is None:
                    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=store.fd)
                    with os.fdopen(fd, 'wb') as output:
                        output.write(raw); output.flush(); os.fsync(output.fileno())
                    os.fsync(store.fd)
                fault('stage_published')
                revalidate()
                presets.require(presets.read_at(store.fd, stage) == raw, 'recovery_stage_changed')
                fault('before_publication')
                revalidate()
                presets.require(presets.read_at(store.fd, stage) == raw, 'recovery_stage_changed')
                store.check()
                os.replace(stage, 'catalog.json', src_dir_fd=store.fd, dst_dir_fd=store.fd)
                os.fsync(store.fd)
                store.new = False
                fault('after_publication')
                presets.require(store.read() == value, 'import_catalog_changed')
                return report('imported', recovered=recovery, plan_sha256=token, records=len(doc['records']))
            except Exception:
                return report('incomplete', plan_sha256=token, reason='project_import_interrupted_or_changed',
                    recovery='preserve_state_and_repeat_import_recover_with_same_inputs_and_plan')
        finally:
            presets.fcntl.flock(store.fd, presets.fcntl.LOCK_UN)


def main(argv, front, presets):
    parser = argparse.ArgumentParser(prog=front.PROG + ' project', description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('export', 'import-preview', 'import', 'import-recover'):
        command = commands.add_parser(action)
        command.add_argument('--archive', required=True, type=Path)
        if action == 'export':
            command.add_argument('--consent', action='store_true', help='acknowledge private path/identity metadata')
        else:
            command.add_argument('--bindings', type=Path, required=action != 'import-preview')
        if action in ('import', 'import-recover'):
            command.add_argument('--apply', action='store_true')
            command.add_argument('--confirm-plan', required=True)
    args = parser.parse_args(argv)
    try:
        presets.require(os.name == 'posix' and front.platform_reason() is None, 'unsupported_platform')
        profiles, home = front.provider_profiles(), front.PROJECT_HOME
        if args.action == 'export':
            result = export(home, args.archive, args.consent, front, profiles, presets)
        elif args.action == 'import-preview':
            result, _ = preview(args.archive, args.bindings, home, front, profiles, presets)
        else:
            presets.require(args.apply, 'import_apply_required')
            result = apply(args.archive, args.bindings, home, args.confirm_plan, front, profiles, presets,
                           recovery=args.action == 'import-recover')
        print(json.dumps(result, sort_keys=True))
        return 4 if result['status'] == 'incomplete' else 0
    except Exception as error:
        reason = str(error)
        safe = reason if re.fullmatch(r'project_[a-z_]{1,80}', reason) else 'project_import_input_unavailable'
        print(json.dumps(report('refused', reason=safe,
            action='Review explicit current bindings and catalog; preserve any interrupted stage before recovery.'), sort_keys=True))
        return 2
