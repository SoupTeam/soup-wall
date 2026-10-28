#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit sanitized archival and acknowledged cleanup of one completed edit run.

Uses the accepted SOU-149 descriptor, publication and removal primitives. Local
owner-editable terminal evidence is a cleanup selection, never execution proof.
"""
import argparse
import base64
from contextlib import contextmanager, ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import time
import zipfile

if sys.platform.startswith('linux'):
    import fcntl

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import pilot_run_state as S

spec = importlib.util.spec_from_file_location('edit_archive_primitives', ROOT / 'scripts/pilot-run-archive.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
REPORT = S.AUDIT.REPORT
FORMAT = 'sw-installed-edit-archive-plan/1'
ARCHIVE = 'sw-installed-edit-sanitized-archive/1'
JOURNAL = 'sw-installed-edit-cleanup-journal/1'
OUTCOME = 'sw-installed-edit-archive-result/1'
RUN = re.compile(r'edit-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
HOME = re.compile(r'[A-Za-z0-9_-]{43}\Z')
MAX_FILE = 16 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 256
MAX_DEPTH = 8
MAX_PLAN = 256 * 1024
MODES = {'file_modes': (0o400, 0o600, 0o644), 'directory_modes': (0o700, 0o755)}
EXCLUDED = ['credentials_and_authority', 'raw_audit', 'raw_host_state', 'raw_prompts_and_tool_payloads',
            'provider_inputs', 'environment', 'absolute_paths', 'unprojected_audit_fields']
PRESERVED = ['output_targets', 'immutable_plans', 'project', 'shared_assets', 'other_runs']


@contextmanager
def selected(path):
    S.require(path.is_absolute() and RUN.fullmatch(path.name), 'exact_edit_run_required')
    with S.Directory(path.parent) as parent, S.Directory(path, file_modes=MODES['file_modes'],
            directory_modes=MODES['directory_modes']) as run:
        S.require(stat.S_IMODE(os.fstat(run.fd).st_mode) == 0o700, 'private_run_required')
        # New launchers hold this exact inode from creation through terminal
        # publication. Legacy state still requires every accepted terminal fact.
        try:
            fcntl.flock(run.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise S.Refusal('edit_run_active') from None
        try:
            yield parent, run
        finally:
            fcntl.flock(run.fd, fcntl.LOCK_UN)


def terminal(run):
    record = run.json('run.json')
    keys = {'format', 'run', 'home', 'profile_sha256', 'host_session', 'instance_id'}
    S.require(type(record) is dict and set(record) == keys and record['format'] == 'sw-installed-edit-session/1'
              and record['run'] == str(run.path) and S.SHA.fullmatch(record['profile_sha256'])
              and type(record['host_session']) is str and RUN.fullmatch('edit-' + record['host_session'])
              and type(record['instance_id']) is str and HOME.fullmatch(record['instance_id']), 'edit_run_record_invalid')
    home = Path(record['home'])
    S.require(home.parent == run.path and HOME.fullmatch(home.name), 'edit_home_binding_invalid')
    # Cross-check the accepted persisted transport selection. These are local
    # owner-editable claims, never authenticated grant or execution evidence.
    transport = run.json('mcp.json')
    S.require(type(transport) is dict and set(transport) == {'mcpServers'}
              and type(transport['mcpServers']) is dict and set(transport['mcpServers']) == {'private-output'},
              'edit_transport_binding_invalid')
    server = transport['mcpServers']['private-output']
    S.require(type(server) is dict and set(server) == {'command', 'args', 'env'} and server['env'] == {}
              and type(server['command']) is str and Path(server['command']).is_absolute(), 'edit_transport_binding_invalid')
    args = server['args']
    S.require(type(args) is list and len(args) == 10 and args[:3] == ['edit-session', 'relay', '--home']
              and args[3] == record['home'] and args[4:7] == ['--host-session', record['host_session'], '--child-authority']
              and args[8:] == ['--profile-sha256', record['profile_sha256']]
              and type(args[7]) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,65536}', args[7]), 'edit_transport_binding_invalid')
    claim = S.strict(base64.urlsafe_b64decode(args[7] + '=' * (-len(args[7]) % 4)))
    S.require(type(claim) is dict and claim.get('contract_version') == 'sw-child-authority/1'
              and claim.get('host_session') == record['host_session'] and claim.get('server_id') == 'private-output'
              and type(claim.get('nonce')) is str and claim['nonce'].startswith(record['instance_id'] + '.'),
              'edit_instance_binding_invalid')
    resources = claim.get('granted_resources')
    S.require(type(resources) is list and 1 <= len(resources) <= 8
              and all(type(value) is str and len(value.encode()) <= 4096 and Path(value).is_absolute()
                      and '..' not in Path(value).parts for value in resources), 'edit_output_binding_invalid')
    roots = {Path(value).parent for value in resources}
    S.require(len(roots) == 1 and all(not root.is_relative_to(run.path.parent)
              and not run.path.parent.is_relative_to(root) for root in roots), 'edit_output_state_overlap')
    ended = run.json('terminal.json')
    S.require(type(ended) is dict and set(ended) == {'format', 'state', 'reason', 'run', 'profile_sha256',
              'cleanup', 'daemon_clean', 'mutation_dispatches', 'effect_status'}
              and ended['format'] == record['format'] and ended['run'] == record['run']
              and ended['profile_sha256'] == record['profile_sha256'] and ended['daemon_clean'] is True
              and type(ended['mutation_dispatches']) is int and ended['mutation_dispatches'] == 0,
              'terminal_cleanup_unconfirmed')
    cleanup = ended['cleanup']
    S.require(type(cleanup) is dict and set(cleanup) == {'cleaned', 'reaped', 'exit_success', 'graceful_observed', 'ownership', 'failure'}
              and cleanup['cleaned'] is True and cleanup['reaped'] is True and cleanup['failure'] is None
              and cleanup['ownership'] == 'unix_process_group' and type(cleanup['exit_success']) is bool
              and type(cleanup['graceful_observed']) is bool, 'owned_cleanup_unconfirmed')
    reasons = {'host_completed', 'cancelled', 'deadline', 'provider_child_environment_unavailable', 'host_stream_failure', 'daemon_lost'}
    S.require(ended['reason'] in reasons and ended['state'] in ('host_completed', 'failed')
              and (ended['state'] != 'host_completed' or ended['reason'] == 'host_completed' and cleanup['exit_success'] is True),
              'terminal_state_inconsistent')
    S.require(ended['effect_status'] == 'consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry',
              'terminal_effect_contract_invalid')
    return record, ended, home.name


def inventory(run):
    record, ended, home = terminal(run)
    root_files = {'run.json', 'terminal.json', 'mcp.json', 'host-settings.json', 'host-bun.toml',
                  'host-stdout.json', 'host-stderr.json'}
    root_dirs = {home, 'host-home', 'host-tmp', 'host-path'}
    S.require(set(run.names(MAX_ENTRIES)) == root_files | root_dirs, 'unexpected_edit_run_layout')
    files, dirs, bodies = {}, {'': S.identity(os.fstat(run.fd))}, {}
    total = 0
    def walk(directory, prefix, depth):
        nonlocal total
        S.require(depth <= MAX_DEPTH, 'edit_inventory_depth_limit')
        for name in directory.names(MAX_ENTRIES):
            S.safe_component(name)
            S.require(name not in ('.git', 'profile.json', 'profile.sha256'), 'project_or_immutable_plan_retained')
            key = prefix + name
            S.require(len(key.encode()) <= 1024 and len(files) + len(dirs) < MAX_ENTRIES, 'edit_inventory_entry_limit')
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            S.require(info.st_dev == os.fstat(run.fd).st_dev and info.st_uid == os.getuid(), 'edit_foreign_member')
            if stat.S_ISDIR(info.st_mode):
                with directory.child(name) as child:
                    dirs[key] = S.identity(os.fstat(child.fd))
                    walk(child, key + '/', depth + 1)
                    S.require(S.identity(os.fstat(child.fd)) == dirs[key], 'edit_directory_generation_changed')
            else:
                body, identity = directory.read(name, MAX_FILE)
                total += len(body)
                S.require(total <= MAX_BYTES, 'edit_inventory_byte_limit')
                files[key] = {'identity': identity, 'bytes': len(body), 'sha256': S.sha(body)}
                if key in ('run.json', 'terminal.json', home + '/audit.jsonl'):
                    bodies[key] = body
        directory.check()
    walk(run, '', 0)
    S.require(dirs[''] == S.identity(os.fstat(run.fd)), 'edit_run_generation_changed')
    S.require(home + '/audit.jsonl' in bodies, 'native_audit_missing')
    return record, ended, {'files': files, 'directories': dirs, 'bytes': total}, bodies


def projection(raw):
    S.require(len(raw) <= REPORT.MAX_INPUT_BYTES, 'audit_export_byte_limit')
    aliases = [{} for _ in range(7)]
    events, unsupported = [], 0
    lines = raw.splitlines(keepends=True)
    S.require(len(lines) <= REPORT.MAX_RECORDS, 'audit_export_record_limit')
    for ordinal, line in enumerate(lines, 1):
        S.require(len(line) <= REPORT.MAX_LINE_BYTES and line.endswith(b'\n'), 'audit_partial_or_oversized_record')
        value = S.strict(line)
        S.require(type(value) is dict, 'audit_record_invalid')
        item = None if any(k in value for k in ('version', 'format_version', 'contract_version')) else REPORT._project(value, ordinal, *aliases)
        if item is None:
            unsupported += 1
        else:
            events.append(item)
    return {'format': 'sw-installed-edit-sanitized-audit/1', 'evidence_source': 'local_owner_editable_audit',
            'execution_proven': False, 'full_forensic_backup': False, 'raw_sha256': S.sha(raw),
            'counts': {'records': len(lines), 'projected': len(events), 'unsupported': unsupported}, 'events': events}


def preview(path, destination):
    S.require(not destination.is_relative_to(path) and not path.is_relative_to(destination), 'archive_source_overlap')
    with selected(path) as (parent, run), S.Directory(destination) as output:
        record, ended, entries, bodies = inventory(run)
        export = projection(bodies[Path(record['home']).name + '/audit.jsonl'])
        plan = {'format': FORMAT, 'created_at_ms': int(time.time() * 1000), 'run': str(path),
                'parent_identity': parent.object, 'destination': str(destination), 'output_identity': output.object,
                'run_record': record, 'terminal': ended, 'inventory': entries,
                'projection_sha256': S.sha(S.encoded(export)), 'excluded_raw_evidence': EXCLUDED,
                'preserved': PRESERVED, 'full_forensic_backup': False,
                'evidence_source': 'local_owner_editable_terminal_cleanup', 'execution_proven': False}
        plan['plan_sha256'] = S.sha(S.encoded(plan))
        S.require(len(S.encoded(plan)) <= MAX_PLAN, 'edit_plan_size_limit')
        return plan


def load_plan(path, confirmation, fresh=True):
    with S.Directory(path.parent) as directory:
        plan = directory.json(path.name, MAX_PLAN)
    keys = {'format', 'created_at_ms', 'run', 'parent_identity', 'destination', 'output_identity', 'run_record',
            'terminal', 'inventory', 'projection_sha256', 'excluded_raw_evidence', 'preserved', 'full_forensic_backup',
            'evidence_source', 'execution_proven', 'plan_sha256'}
    S.require(type(plan) is dict and set(plan) == keys and plan['format'] == FORMAT
              and confirmation == plan['plan_sha256'] == S.sha(S.encoded({k: v for k, v in plan.items() if k != 'plan_sha256'})),
              'edit_plan_confirmation_mismatch')
    S.require(plan['excluded_raw_evidence'] == EXCLUDED and plan['preserved'] == PRESERVED
              and plan['full_forensic_backup'] is False and plan['execution_proven'] is False, 'edit_plan_contract_invalid')
    S.require(type(plan['created_at_ms']) is int and (not fresh or 0 <= int(time.time() * 1000) - plan['created_at_ms'] <= 900000),
              'edit_plan_expired')
    S.require(RUN.fullmatch(Path(plan['run']).name) and Path(plan['run']).is_absolute()
              and Path(plan['destination']).is_absolute(), 'edit_plan_path_invalid')
    return plan


def current(run, plan, renamed=False):
    record, ended, entries, bodies = inventory(run)
    if renamed:
        # Directory detachment changes only its ctime; keep original logical
        # run.path for terminal consistency and verify the held inode instead.
        S.require(entries['directories'][''][:7] == plan['inventory']['directories'][''][:7], 'edit_run_replaced')
        entries['directories'][''] = plan['inventory']['directories']['']
    S.require(record == plan['run_record'] and ended == plan['terminal'] and entries == plan['inventory'], 'edit_plan_changed')
    return bodies


def archive_name(plan):
    return 'edit-' + plan['plan_sha256'] + '.zip'


def manifest(plan):
    # No source bytes or arbitrary names enter the sanitized archive.
    return {'format': ARCHIVE, 'plan_sha256': plan['plan_sha256'],
                'profile_sha256': plan['run_record']['profile_sha256'],
                'instance_sha256': S.sha(plan['run_record']['instance_id'].encode()),
                'run_record_sha256': plan['inventory']['files']['run.json']['sha256'],
                'terminal_sha256': plan['inventory']['files']['terminal.json']['sha256'],
                'terminal': {'state': plan['terminal']['state'], 'reason': plan['terminal']['reason'],
                             'owned_cleanup_confirmed': True, 'daemon_cleanup_confirmed': True,
                             'effects_may_remain_committed': True, 'automatic_retry': False},
                'inventory': [{'path_sha256': S.sha(name.encode()), 'bytes': row['bytes'], 'sha256': row['sha256']}
                              for name, row in sorted(plan['inventory']['files'].items())],
                'reclaimed_bytes': plan['inventory']['bytes'], 'excluded_raw_evidence': EXCLUDED,
                'preserved': PRESERVED, 'full_forensic_backup': False, 'execution_proven': False,
                'evidence_completeness': 'allowlisted_projection_only_raw_evidence_excluded',
                'audit_sha256': plan['projection_sha256']}


def package(meta, export):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in (('manifest.json', S.encoded(meta)), ('sanitized-audit.json', export)):
            info = zipfile.ZipInfo(name);info.create_system = 3;info.external_attr = 0o100600 << 16
            archive.writestr(info, raw)
    raw = output.getvalue()
    S.require(len(raw) <= A.MAX_ARCHIVE, 'sanitized_archive_size_limit')
    return raw


def archive_bytes(plan, bodies):
    home = Path(plan['run_record']['home']).name
    export = S.encoded(projection(bodies[home + '/audit.jsonl']))
    S.require(S.sha(export) == plan['projection_sha256'], 'edit_projection_changed')
    return package(manifest(plan), export)


def verify_archive(raw, plan):
    S.require(len(raw) <= A.MAX_ARCHIVE, 'sanitized_archive_size_limit')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            S.require(len(infos) == 2 and {v.filename for v in infos} == {'manifest.json', 'sanitized-audit.json'}
                      and all(v.compress_type == zipfile.ZIP_STORED and v.file_size <= A.MAX_ARCHIVE for v in infos)
                      and sum(v.file_size for v in infos) <= A.MAX_ARCHIVE, 'sanitized_archive_members_invalid')
            meta = S.strict(archive.read('manifest.json'))
            exported = archive.read('sanitized-audit.json')
            S.require(meta == manifest(plan) and S.sha(exported) == plan['projection_sha256']
                      and raw == package(meta, exported), 'sanitized_archive_binding_invalid')
            return meta
    except (zipfile.BadZipFile, KeyError, RuntimeError, EOFError):
        raise S.Refusal('sanitized_archive_invalid') from None


@contextmanager
def output_for(plan):
    path = Path(plan['destination'])
    run = Path(plan['run'])
    S.require(not path.is_relative_to(run) and not run.is_relative_to(path), 'archive_source_overlap')
    with S.Directory(path) as output:
        S.require(output.object == plan['output_identity'], 'archive_destination_changed')
        yield output


def source_for(plan):
    return selected(Path(plan['run']))


def check_parent(parent, plan):
    S.require(parent.object == plan['parent_identity'], 'archive_parent_changed')


def archive(plan):
    with source_for(plan) as (parent, run), output_for(plan) as output:
        check_parent(parent, plan)
        bodies = current(run, plan)
        raw = archive_bytes(plan, bodies)
        current(run, plan)
        name = archive_name(plan)
        try:
            existing = output.read(name, A.MAX_ARCHIVE)[0]
        except FileNotFoundError:
            A.publish(output, name, raw)
            existing = output.read(name, A.MAX_ARCHIVE)[0]
        S.require(existing == raw, 'sanitized_archive_changed')
        with A.durable_file(output, name, A.MAX_ARCHIVE, lambda body: verify_archive(body, plan)):
            current(run, plan)
        return {'outcome': 'archived_source_retained', 'archive': name, 'archive_sha256': S.sha(raw),
                'raw_evidence_retained': True, 'full_forensic_backup': False}


def journal_name(plan):
    return 'edit-cleanup-' + plan['plan_sha256'] + '.json'


def read_journal(output, plan):
    journal = output.json(journal_name(plan), MAX_PLAN)
    S.require(type(journal) is dict and set(journal) == {'format', 'plan_sha256', 'state', 'quarantine', 'archive_sha256'}
              and journal['format'] == JOURNAL and journal['plan_sha256'] == plan['plan_sha256']
              and journal['state'] == 'prepared'
              and re.fullmatch(r'\.edit-cleanup-[0-9a-f]{32}', journal['quarantine']), 'edit_cleanup_journal_invalid')
    complete = journal_name(plan) + '.complete'
    if not missing(output, complete):
        committed = output.json(complete, MAX_PLAN)
        S.require(committed == dict(journal, state='cleaned'), 'edit_cleanup_commit_invalid')
        return committed
    return journal


def missing(parent, name):
    try:
        os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def completed(plan, output, parent):
    journal = read_journal(output, plan)
    with A.durable_file(output, archive_name(plan), A.MAX_ARCHIVE, lambda raw: verify_archive(raw, plan)) as (raw, guard):
        S.require(S.sha(raw) == journal['archive_sha256'], 'cleanup_archive_changed')
        S.require(journal['state'] == 'cleaned' and missing(parent, Path(plan['run']).name)
                  and missing(parent, journal['quarantine']), 'cleanup_completion_unconfirmed')
        guard()
        return {'outcome': 'already_cleaned', 'archive_sha256': S.sha(raw), 'raw_evidence_removed': True}


def remaining(run, plan, files, dirs):
    found_files, found_dirs = {}, {}
    def walk(directory, key):
        found_dirs[key] = directory.object
        for name in directory.names(MAX_ENTRIES):
            relative = key + ('/' if key else '') + name
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                S.require(relative in dirs, 'cleanup_unexpected_directory')
                with directory.child(name) as child:
                    walk(child, relative)
            else:
                S.require(relative in files, 'cleanup_unexpected_member')
                raw, identity = directory.read(name, MAX_FILE)
                expected = files[relative]
                S.require(identity == expected['identity'] and len(raw) == expected['bytes']
                          and S.sha(raw) == expected['sha256'], 'cleanup_member_changed')
                found_files[relative] = True
    walk(run, '')
    S.require(set(found_files) == set(files) and set(found_dirs) == set(dirs)
              and all(found_dirs[key] == dirs[key][:4] for key in dirs), 'cleanup_remaining_changed')


@contextmanager
def descendant(root, key):
    with ExitStack() as held:
        directory = root
        for part in key.split('/') if key else []:
            directory = held.enter_context(directory.child(part))
        yield directory


def remove_directory(directory, leaf, quarantine, expected, guard):
    """Stage even empty directories before removal, as for SOU-149 members."""
    with directory.child(leaf) as child:
        S.require(child.object == expected[:4] and not child.names(MAX_ENTRIES), 'cleanup_directory_changed')
        staged = 'directory-' + secrets.token_hex(16)
        guard()
        A.rename_exclusive(directory.fd, leaf, quarantine.fd, staged)
        os.fsync(directory.fd);os.fsync(quarantine.fd)
        with quarantine.child(staged) as moved:
            S.require(moved.object == child.object and not moved.names(MAX_ENTRIES), 'cleanup_staged_directory_changed')
            guard();os.rmdir(staged, dir_fd=quarantine.fd);os.fsync(quarantine.fd)


def cleanup(plan, acknowledged):
    S.require(acknowledged is True, 'explicit_raw_evidence_loss_consent_required')
    path = Path(plan['run'])
    with S.Directory(path.parent) as parent, output_for(plan) as output:
        check_parent(parent, plan)
        if not missing(output, journal_name(plan)):
            return completed(plan, output, parent)
    with source_for(plan) as (parent, run), output_for(plan) as output:
        check_parent(parent, plan)
        current(run, plan)
        with A.durable_file(output, archive_name(plan), A.MAX_ARCHIVE, lambda raw: verify_archive(raw, plan)) as (raw, archive_guard):
            quarantine_name = '.edit-cleanup-' + secrets.token_hex(16)
            journal = {'format': JOURNAL, 'plan_sha256': plan['plan_sha256'], 'state': 'prepared',
                       'quarantine': quarantine_name, 'archive_sha256': S.sha(raw)}
            # Output journal is durable before any source namespace changes.
            A.publish(output, journal_name(plan), S.encoded(journal))
            moved = False
            def guard():
                archive_guard()
                parent.check()
                if moved:
                    S.require(missing(parent, path.name), 'edit_run_name_reappeared')
            try:
                current(run, plan)
                os.mkdir(quarantine_name, mode=0o700, dir_fd=parent.fd)
                os.fsync(parent.fd)
                with S.Directory(parent.path / quarantine_name, parent, quarantine_name, **MODES) as quarantine:
                    A.publish(quarantine, 'cleanup.json', S.encoded(journal))
                    guard()
                    A.rename_exclusive(parent.fd, path.name, quarantine.fd, 'run')
                    moved = True
                    os.fsync(parent.fd);os.fsync(quarantine.fd)
                    run.parent, run.name = quarantine, 'run'
                    current(run, plan, renamed=True)
                    files = dict(plan['inventory']['files'])
                    dirs = dict(plan['inventory']['directories'])
                    for key in sorted(files):
                        remaining(run, plan, files, dirs)
                        parent_key, _, leaf = key.rpartition('/')
                        with descendant(run, parent_key) as directory:
                            A.remove_member(directory, leaf, quarantine, files[key], guard, maximum=MAX_FILE)
                        del files[key]
                    for key in sorted((key for key in dirs if key), key=lambda k: (k.count('/'), k), reverse=True):
                        remaining(run, plan, files, dirs)
                        parent_key, _, leaf = key.rpartition('/')
                        with descendant(run, parent_key) as directory:
                            remove_directory(directory, leaf, quarantine, dirs[key], guard)
                        del dirs[key]
                    remaining(run, plan, files, dirs)
                    remove_directory(quarantine, 'run', quarantine, dirs[''], guard)
                    S.require(quarantine.names(MAX_ENTRIES) == ['cleanup.json'], 'cleanup_quarantine_changed')
                    guard();os.unlink('cleanup.json', dir_fd=quarantine.fd);os.fsync(quarantine.fd)
                os.rmdir(quarantine_name, dir_fd=parent.fd);os.fsync(parent.fd)
                guard()
                # Absence becomes a completion only after this distinct durable
                # commit. A crash in the gap remains unknown to recover/retry.
                S.require(read_journal(output, plan)['state'] == 'prepared', 'cleanup_journal_changed')
                # Never replace a journal pathname. Commit is a second bounded
                # create-new durable record linked to the immutable intent.
                A.publish(output, journal_name(plan) + '.complete', S.encoded(dict(journal, state='cleaned')))
                return completed(plan, output, parent) | {'outcome': 'archived_and_cleaned'}
            except (OSError, ValueError, KeyError, TypeError):
                return {'outcome': 'incomplete', 'source': 'quarantined' if moved else 'retained',
                        'journal': journal_name(plan), 'quarantine': quarantine_name,
                        'reason': 'cleanup_completion_unconfirmed', 'raw_evidence_removed': 'unknown'}


def recover(plan, requested):
    S.require(requested == journal_name(plan), 'exact_cleanup_journal_required')
    with S.Directory(Path(plan['run']).parent) as parent, output_for(plan) as output:
        check_parent(parent, plan)
        journal = read_journal(output, plan)
        if journal['state'] == 'cleaned':
            return completed(plan, output, parent)
        raw = output.read(archive_name(plan), A.MAX_ARCHIVE)[0]
        verify_archive(raw, plan)
        S.require(S.sha(raw) == journal['archive_sha256'], 'cleanup_archive_changed')
        result = {'outcome': 'incomplete', 'reason': 'completion_not_committed', 'archive_verified': True,
                  'raw_evidence_removed': 'unknown', 'recovery': 'read_only_retain_for_review',
                  'journal': requested, 'quarantine': journal['quarantine']}
        if not missing(parent, Path(plan['run']).name):
            with source_for(plan) as (_, run):
                current(run, plan)
            result.update(source='retained', reason='source_intact_before_detachment')
        elif not missing(parent, journal['quarantine']):
            # No recursive repair or deletion; unexpected state remains unknown.
            with S.Directory(parent.path / journal['quarantine'], parent, journal['quarantine'], **MODES) as quarantine:
                S.require(quarantine.json('cleanup.json', MAX_PLAN) == journal, 'quarantine_journal_changed')
                result['remaining_root_entries'] = len(quarantine.names(MAX_ENTRIES))
                result['source'] = 'quarantined'
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    command = sub.add_parser('preview')
    command.add_argument('--run', type=Path, required=True)
    command.add_argument('--destination', type=Path, required=True)
    for action in ('archive', 'cleanup', 'recover'):
        command = sub.add_parser(action)
        command.add_argument('--plan', type=Path, required=True)
        command.add_argument('--confirm', required=True)
        if action == 'cleanup': command.add_argument('--acknowledge-evidence-loss', action='store_true')
        if action == 'recover': command.add_argument('--journal', required=True)
    args = parser.parse_args(argv)
    def interrupted(_signum, _frame):
        raise InterruptedError('operator_interrupted')
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupted)
    try:
        S.platform()
        if args.action == 'preview':
            result = preview(args.run, args.destination)
        else:
            plan = load_plan(args.plan, args.confirm, fresh=args.action != 'recover')
            result = (archive(plan) if args.action == 'archive' else cleanup(plan, args.acknowledge_evidence_loss)
                      if args.action == 'cleanup' else recover(plan, args.journal))
            result = {'format': OUTCOME, 'action': args.action, **result}
        success = result.get('outcome') != 'incomplete'
        code = 0 if success else 2
    except S.Refusal as error:
        result, code = {'format': OUTCOME, 'action': args.action, 'outcome': 'refused', 'reason': str(error)}, 1
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        result, code = {'format': OUTCOME, 'action': args.action, 'outcome': 'incomplete', 'reason': 'operation_unavailable'}, 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
