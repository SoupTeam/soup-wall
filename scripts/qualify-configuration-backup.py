#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-source installed configuration recovery with owned Linux witnesses.

The operator commands execute from a verified installed component outside the
checkout. The qualification driver alone uses the existing original-server
observers and owned scripted provider. No paid inference or real user data.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECOVERY = load('configuration_recovery_qualified', 'pilot_configuration_backup.py')
QUAL = load('configuration_original_runtime', 'qualify-installed-pilot.py')
DOOR = load('configuration_installed_door', 'qualify-installed-front-door.py')
BASE, require = QUAL.BASE, QUAL.require
FORMAT = 'sw-pilot-configuration-backup-qualification/1'
CASES = ('exact-installed-inputs', 'inventory-zero-effects', 'private-secret-free-backup',
         'invalid-archives-refused', 'restore-preview-no-authority', 'confirmed-fresh-restore',
         'fresh-daemon-authority', 'original-server-calibration', 'genuine-host-useful-read',
         'calibrated-refusal-zero-effects', 'old-authority-refused', 'active-sibling-preserved',
         'concurrent-source-change-refused', 'interrupted-restore-recovered',
         'published-restore-recovered', 'source-workspace-preservation', 'owned-cleanup')
MAX_REPORT = 128 * 1024
CANARY = b'owned-configuration-recovery-excluded-marker-198'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def private_bytes(path, raw):
    with Path(path).open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def snapshot(path):
    return BASE.snapshot(path)


def unchanged_live_source(home, baseline, audit_prefix):
    """Allow only the active sibling's authenticated lease renewals to append."""
    observed = snapshot(home)
    before = dict(baseline)
    old_audit, new_audit = before.pop('audit.jsonl'), observed.pop('audit.jsonl')
    require(observed == before, 'source_state_changed')
    require({key: value for key, value in old_audit.items() if key not in ('sha256', 'size')}
            == {key: value for key, value in new_audit.items() if key not in ('sha256', 'size')},
            'source_audit_identity_changed')
    raw = (home / 'audit.jsonl').read_bytes()
    require(raw.startswith(audit_prefix) and raw.endswith(b'\n'), 'retained_evidence_rewritten')
    initial = [QUAL.strict_json(line) for line in audit_prefix.splitlines()]
    enrolled = {row['session_id']: row['session'] for row in initial
                if row.get('event') == 'native_liveness_enrolled'}
    last = {key: 0 for key in enrolled}
    for row in initial:
        if row.get('event') == 'native_liveness_renewed':
            last[row['session_id']] = row['lease_seq']
    added = [QUAL.strict_json(line) for line in raw[len(audit_prefix):].splitlines()]
    for row in added:
        require(set(row) == {'at_ms', 'event', 'session', 'session_id', 'lease_seq', 'released'}
                and row['event'] == 'native_liveness_renewed' and row['released'] is True
                and row['session_id'] in enrolled and row['session'] == enrolled[row['session_id']]
                and type(row['lease_seq']) is int and row['lease_seq'] > last[row['session_id']],
                'unexpected_source_audit_activity')
        last[row['session_id']] = row['lease_seq']
    return len(added)


def evidence_digest(value):
    return sha(encoded(value))


def verified_external_paths(current, selection):
    """Keep accepted preparation's exact identities and require external inputs."""
    files = current['binding']['files']
    paths = {name: Path(value['path']) for name, value in files.items()}
    selected = Path(selection)
    profile_paths = [Path(value['profile']['path'])
                     for value in current['binding']['profiles'].values()]
    inputs = [selected, *paths.values(), *profile_paths]
    require(all(path.is_absolute() and path.resolve(strict=True) == path
                and not path.is_relative_to(ROOT) for path in inputs),
            'installed_runtime_outside_checkout_required')
    for role, source in (
            ('filesystem_classifier', ROOT / 'rule_baseline/rule_baseline.py'),
            ('git_classifier', ROOT / 'rule_baseline/git_readonly_v1/rule_baseline.py')):
        require(sha(paths[role].read_bytes()) == files[role]['sha256']
                == sha(source.read_bytes()), 'selected_classifier_not_exact_source')
    require(paths['policy'].read_bytes() == current['policy_raw'] == QUAL.PILOT_POLICY.encode(),
            'selected_policy_not_exact_qualification_policy')
    return paths


def passed(report):
    """Strict independent report grading; an aggregate passed label is not proof."""
    try:
        rows = report['cases']
        by = {row['id']: row['evidence'] for row in rows}
        return (report['format'] == FORMAT and report['status'] == 'passed'
            and [row['id'] for row in rows] == list(CASES)
            and all(row['status'] == 'passed' and type(row['evidence']) is dict
                    and row['evidence'] for row in rows)
            and report['source_before'] == report['source_after']
            and report['source_before']['dirty'] is False
            and report['counts'] == {'passed': len(CASES), 'failed': 0, 'incomplete': 0}
            and report['provider'] == 'owned-scripted-loopback'
            and type(report['paid_api_calls']) is int and report['paid_api_calls'] == 0
            and type(report['actual_publication_attempts']) is int and report['actual_publication_attempts'] == 0
            and report['fresh_authority_created'] is True
            and report['old_authority_accepted'] is False
            and type(report['forbidden_effects']) is int and report['forbidden_effects'] == 0
            and report['old_installation_preserved'] is True
            and report['operator_commands_outside_checkout'] is True
            and report['all_owned_processes_stopped'] is True
            and by['exact-installed-inputs']['installed_component_verified'] is True
            and by['exact-installed-inputs']['accepted_external_selection'] is True
            and by['exact-installed-inputs']['exact_source_classifiers'] is True
            and by['inventory-zero-effects']['writes'] == 0
            and by['private-secret-free-backup']['secret_canaries_present'] == 0
            and by['private-secret-free-backup']['old_tokens_present'] == 0
            and by['restore-preview-no-authority']['writes'] == 0
            and by['restore-preview-no-authority']['redirected_destination_refused'] is True
            and by['confirmed-fresh-restore']['authority'] == 'not_restored'
            and by['fresh-daemon-authority']['actual_restored_config_consumed'] is True
            and by['original-server-calibration']['actual_original_write'] is True
            and by['original-server-calibration']['fifo_reader_observed'] is True
            and by['genuine-host-useful-read']['actual_host'] is True
            and by['genuine-host-useful-read']['actual_original_server_read'] is True
            and by['genuine-host-useful-read']['owned_host_processes_stopped'] is True
            and by['calibrated-refusal-zero-effects']['calibrated_fifo_reader_seen'] is False
            and by['calibrated-refusal-zero-effects']['forbidden_bytes'] == 0
            and by['calibrated-refusal-zero-effects']['useful_continuation'] is True
            and by['old-authority-refused']['old_bearer_http'] == 401
            and by['old-authority-refused']['old_grant_http'] == 409
            and by['old-authority-refused']['old_grant_error'] == 'native_child_authority_bad_signature'
            and by['active-sibling-preserved']['same_active_sibling_useful'] is True
            and by['concurrent-source-change-refused']['published_archives'] == 0
            and by['interrupted-restore-recovered']['initial_status'] == 'incomplete'
            and by['interrupted-restore-recovered']['recovery'] == 'restored'
            and by['published-restore-recovered']['recovery'] == 'restored'
            and by['source-workspace-preservation']['workspaces_unchanged'] is True
            and by['owned-cleanup']['private_test_state_removed'] is True)
    except (KeyError, TypeError):
        return False


def command(args, component_home, action, *words):
    """The tested operator path: verified Agent -> pinned installed helper."""
    supplied = [str(args.agentfw), 'pilot', '--home', str(component_home), 'configuration', action]
    supplied += [str(word) for word in words]
    process = subprocess.run(supplied, cwd=args.work, env=args.operator_env,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    require(len(process.stdout) <= 65536 and len(process.stderr) <= 65536,
            'operator_result_byte_limit')
    try:
        result = RECOVERY.strict(process.stdout)
    except (ValueError, UnicodeError):
        raise ValueError('operator_result_invalid') from None
    return process.returncode, result


def stage_pilot(private, output, paths, current, home=None):
    private.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    pilot = QUAL.Pilot(private, output, paths, {})
    if home is not None:
        pilot.home = home
        pilot.env = BASE.environment(home)
        pilot.env.update(PATH=str(paths['node'].parent) + os.pathsep + os.defpath,
            GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
            GIT_PYTHON_GIT_EXECUTABLE=str(paths['git']), GIT_OPTIONAL_LOCKS='0')
    pilot.binary = paths['agentfw']
    pilot.launcher = paths['git_launcher']
    pilot.installs = {kind: Path(current['binding']['profiles'][kind]['profile']['path']).parent
                      for kind in ('filesystem', 'git')}
    pilot.classifiers = {kind: paths[kind + '_classifier'] for kind in ('filesystem', 'git')}
    roots = RECOVERY.PREP.workspace_paths(current['selection'],
        Path(current['binding']['selection_path']).parent)
    pilot.workspace, pilot.git_workspace = roots['filesystem'], roots['git']
    return pilot


def stop_pilot(pilot):
    if pilot is None:
        return True
    stopped = True
    for client in reversed(pilot.clients):
        try:
            client.close()
            client.validate_capture()
            stopped &= not client.forced_cleanup and client.process_witness.final['all_stopped']
        except Exception:
            stopped = False
    if pilot.daemon is not None:
        BASE.DEMO.stop(pilot.daemon)
        pilot.daemon.wait(timeout=10)
        stopped &= pilot.daemon_witness.finish()['all_stopped']
    pilot.receiver.close()
    for stream in pilot.logs:
        stream.close()
    return bool(stopped)


def native_request(pilot, route, token, body=None):
    payload = None if body is None else encoded(body)
    request = urllib.request.Request('http://127.0.0.1:' + str(pilot.port) + route, payload,
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            status, raw = response.status, response.read(65537)
    except urllib.error.HTTPError as error:
        with error:
            status, raw = error.code, error.read(65537)
    require(len(raw) <= 65536, 'native_response_byte_limit')
    return status, raw


def qualify(args, report):
    source, restored, sibling = None, None, None
    private = args.output / 'private'
    private.mkdir(mode=0o700)
    state = {}
    rows = {row['id']: row for row in report['cases']}

    def step(name, action):
        started = time.monotonic()
        try:
            evidence = action()
            require(type(evidence) is dict and bool(evidence), 'missing_qualification_witness')
            rows[name].update(status='passed', evidence=evidence,
                              elapsed_ms=round((time.monotonic() - started) * 1000, 3))
            rows[name].pop('reason', None)
            return evidence
        except Exception as error:
            label = str(error)
            rows[name].update(status='failed', reason=label if re.fullmatch('[a-z0-9_]{1,100}', label)
                              else type(error).__name__, elapsed_ms=round((time.monotonic() - started) * 1000, 3))
            raise

    try:
        def prepare():
            nonlocal source, sibling
            require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
                    and os.geteuid() != 0 and 'microsoft' not in platform.release().lower(),
                    'native_linux_x86_64_required')
            report['source_before'] = BASE.source()
            require(report['source_before']['commit'] == args.expected_commit
                    and report['source_before']['dirty'] is False, 'exact_clean_source_required')
            current = RECOVERY.runtime(args.selection, args.agentfw, args.expected_commit)
            paths = verified_external_paths(current, args.selection)
            require('prepared_workspaces' not in current['selection'], 'owned_generated_workspaces_required')
            component_home = private / 'component-home'
            component_home.mkdir(mode=0o700)
            build_env = BASE.environment(private)
            built = DOOR.build(ROOT, private / 'component.tar', build_env)
            require(built['commit'] == args.expected_commit, 'component_source_mismatch')
            component_args = SimpleNamespace(agentfw=args.agentfw, component_python=args.python,
                                            work=args.work, output=args.output)
            code, value, _ = DOOR.component(component_args, component_home, private / 'component.tar',
                built['archive_sha256'], 'install', env=build_env)
            require(code == 0 and value.get('component') == built['component'], 'component_install_failed')
            source = stage_pilot(private / 'source', private / 'source-evidence', paths, current)
            home = source.home / '.agentfw'
            home.mkdir(mode=0o700)
            registry = home / 'registry.json'
            private_bytes(registry, RECOVERY.merged_registry(current, 'prepared-pilot-v1'))
            source.registry_sha256 = sha(registry.read_bytes())
            source.port = BASE.DEMO.free_port()
            config = {'bind': '127.0.0.1', 'port': source.port, 'enforce': True,
                'policy': str(paths['policy']), 'max_record_bytes': 1048576,
                'native': {'registry_path': str(registry), 'registry_sha256': source.registry_sha256,
                           'liveness': {'default_lease_seconds': 4, 'max_lease_seconds': 4,
                                        'maintenance_interval_ms': 250}}}
            private_bytes(home / 'config.yaml', encoded(config) + b'\n')
            # Owned fixture data are seeded before preservation snapshots.
            state['unseeded_workspaces'] = {kind: snapshot(path) for kind, path in (
                ('filesystem', source.workspace), ('git', source.git_workspace))}
            state['owned_seeds'] = []
            for name, raw in (('guide.txt', BASE.TEXT.encode()), ('source.txt', QUAL.POINTER.encode())):
                target = source.workspace / name
                require(not target.exists(), 'qualification_fixture_already_populated')
                private_bytes(target, raw)
                info = target.lstat()
                state['owned_seeds'].append((target, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
            fifo = source.workspace / 'forbidden.fifo'
            require(not fifo.exists(), 'qualification_fixture_already_populated')
            os.mkfifo(fifo, 0o600)
            info = fifo.lstat()
            state['owned_seeds'].append((fifo, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
            source.start_daemon()
            # Known synthetic canaries stand for excluded stores, never credentials.
            for name in ('provider-key', 'enrollment-key', 'old-approval', 'retained-output'):
                private_bytes(home / name, CANARY + b'-' + name.encode())
            old_host = str(uuid.uuid4())
            old_grant = source.mint(old_host, 'filesystem', 'old-source-context')
            sibling = source.client('filesystem', old_host, 'old-source-context', proof=old_grant)
            active = sibling.__enter__()
            response, _ = active.exchange(QUAL.frame(50, 'filesystem', 'read_text_file',
                                                     {'path': '/workspace/guide.txt'}))
            require(BASE.result_text(response) == BASE.TEXT, 'source_sibling_not_useful')
            audit = home / 'audit.jsonl'
            source_baseline = snapshot(home)
            workspace_baseline = {kind: snapshot(path) for kind, path in (
                ('filesystem', source.workspace), ('git', source.git_workspace))}
            sentinel = private / 'retained-evidence.json'
            private_bytes(sentinel, b'{"owned":"retained-sentinel"}\n')
            state.update(current=current, paths=paths, component_home=component_home, home=home,
                source_baseline=source_baseline, workspace_baseline=workspace_baseline,
                retained_sentinel=sha(sentinel.read_bytes()), sentinel=sentinel,
                archive=private / 'configuration.tar', active=active, old_host=old_host,
                old_grant=old_grant, old_token=source.native_token,
                old_hook_token=(home / 'token').read_bytes(), source_audit=audit.read_bytes())
            report['operator_commands_outside_checkout'] = True
            report['identities'] = {'source': current['binding']['source_commit'],
                'selection_sha256': current['binding']['selection_sha256'],
                'agentfw_sha256': current['binding']['files']['agentfw']['sha256'],
                'component': built['component'], 'component_archive_sha256': built['archive_sha256'],
                'driver_sha256': sha(Path(__file__).read_bytes())}
            return {'installed_component_verified': True, 'native_source_started': True,
                    'accepted_external_selection': True, 'exact_source_classifiers': True,
                    'active_sibling_original_read': True, 'runtime_binding_sha256': RECOVERY.digest(current['binding'])}
        step('exact-installed-inputs', prepare)
        common = ['--selection', args.selection, '--agentfw', args.agentfw,
                  '--expected-commit', args.expected_commit]
        capture_args = ['--source-home', state['home'], *common]

        def inventory():
            code, result = command(args, state['component_home'], 'inventory', *capture_args)
            require(code == 0 and result['status'] == 'inventoried', 'installed_inventory_failed')
            renewals = unchanged_live_source(state['home'], state['source_baseline'], state['source_audit'])
            require(not state['archive'].exists(), 'inventory_had_effect')
            require(result['authority'] == 'not_restored' and result['observed_protection'] == 'unverified',
                    'inventory_claimed_protection')
            return {'writes': 0, 'source_unchanged': True, 'authority': result['authority'],
                    'active_sibling_audit_renewals': renewals}
        step('inventory-zero-effects', inventory)

        def backup():
            code, result = command(args, state['component_home'], 'backup', *capture_args,
                                   '--archive', state['archive'], '--consent')
            require(code == 0 and result['status'] == 'backed-up', 'installed_backup_failed')
            raw = state['archive'].read_bytes()
            require(CANARY not in raw and state['old_token'].encode() not in raw
                    and state['old_hook_token'].strip() not in raw, 'excluded_authority_in_backup')
            require(state['archive'].stat().st_mode & 0o777 == 0o600, 'backup_not_private')
            document, digest, _ = RECOVERY.load_archive(state['archive'])
            require(document['runtime_binding'] == state['current']['binding'], 'backup_identity_changed')
            renewals = unchanged_live_source(state['home'], state['source_baseline'], state['source_audit'])
            return {'archive_sha256': digest, 'members': 2, 'secret_canaries_present': 0,
                    'old_tokens_present': 0, 'source_unchanged': True,
                    'active_sibling_audit_renewals': renewals}
        step('private-secret-free-backup', backup)

        def invalid_archives():
            raw = bytearray(state['archive'].read_bytes())
            raw[512] ^= 1
            corrupt = private / 'corrupt.tar'
            private_bytes(corrupt, raw)
            missing = private / 'missing.tar'
            with missing.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    entry = tarfile.TarInfo('configuration.json')
                    entry.mode, entry.size = 0o600, 2
                    archive.addfile(entry, io.BytesIO(b'{}'))
            for path in (corrupt, missing):
                code, value = command(args, state['component_home'], 'inspect', '--archive', path)
                require(code != 0 and value['status'] == 'refused', 'invalid_archive_was_accepted')
            return {'invalid_manifests_refused': 2, 'restores_attempted': 0}
        step('invalid-archives-refused', invalid_archives)

        restored_os_home = private / 'restored-home'
        restored_os_home.mkdir(mode=0o700)
        destination = restored_os_home / '.agentfw'
        new_port = BASE.DEMO.free_port()
        while new_port == source.port:
            new_port = BASE.DEMO.free_port()
        restore_args = ['--archive', state['archive'], *common, '--destination', destination, '--port', new_port]

        def preview():
            code, value = command(args, state['component_home'], 'restore-preview', *restore_args)
            require(code == 0 and value['status'] == 'preview' and not destination.exists(),
                    'restore_preview_had_effect')
            state['restore_plan'] = value['plan_sha256']
            require(value['changes']['old_port'] == source.port and value['changes']['new_port'] == new_port,
                    'explicit_port_rebinding_missing')
            require(value['authority'] == 'not_restored' and value['launch_readiness'] == 'unverified',
                    'restore_preview_claimed_authority')
            redirect = private / 'redirected'
            redirect.symlink_to(restored_os_home, target_is_directory=True)
            code, refused = command(args, state['component_home'], 'restore-preview',
                '--archive', state['archive'], *common, '--destination', redirect / '.agentfw')
            require(code != 0 and refused['status'] == 'refused' and not destination.exists(),
                    'redirected_destination_accepted')
            redirect.unlink()
            return {'writes': 0, 'redirected_destination_refused': True,
                    'binding_plan_sha256': state['restore_plan']}
        step('restore-preview-no-authority', preview)

        def restore():
            code, value = command(args, state['component_home'], 'restore', *restore_args,
                                  '--confirm-plan', state['restore_plan'])
            require(code == 0 and value['status'] == 'restored', 'installed_restore_failed')
            require(value['authority'] == 'not_restored' and value['enrollment'] == 'unverified'
                    and value['launch_readiness'] == 'unverified'
                    and value['observed_protection'] == 'unverified', 'restore_claimed_live_authority')
            require(not any((destination / name).exists() for name in
                            ('token', 'native-token', 'grants', 'sessions', 'old-approval', 'provider-key')),
                    'authority_restored')
            renewals = unchanged_live_source(state['home'], state['source_baseline'], state['source_audit'])
            state['restored_config'] = sha((destination / 'config.yaml').read_bytes())
            return {'configuration': 'restored', 'authority': 'not_restored', 'source_unchanged': True,
                    'restored_config_sha256': state['restored_config'],
                    'active_sibling_audit_renewals': renewals}
        step('confirmed-fresh-restore', restore)

        def launch():
            nonlocal restored
            restored = stage_pilot(private / 'restored-runtime', private / 'restored-evidence',
                                    state['paths'], state['current'], restored_os_home)
            restored.port, restored.registry_sha256 = new_port, source.registry_sha256
            require(not (destination / 'token').exists() and not (destination / 'native-token').exists(),
                    'authority_preexisted_launch')
            old_instance = source.http('/native/v1/instance')['instance_id']
            new_instance = restored.start_daemon()
            require(new_instance != old_instance and restored.native_token != state['old_token']
                    and (destination / 'token').read_bytes() != state['old_hook_token'],
                    'old_authority_reused')
            require(sha((destination / 'config.yaml').read_bytes()) == state['restored_config'],
                    'restored_config_not_consumed')
            report['fresh_authority_created'] = True
            return {'fresh_instance': True, 'fresh_native_token': True, 'fresh_hook_token': True,
                    'actual_restored_config_consumed': True}
        step('fresh-daemon-authority', launch)

        def calibration():
            target = restored.workspace / 'owned-write-calibration.txt'
            with restored.client('filesystem', direct=True) as client:
                response, _ = client.exchange(BASE.call(71, {'path': str(restored.workspace / 'guide.txt')}, 'read_text_file'))
                require(BASE.result_text(response) == BASE.TEXT, 'original_read_calibration_failed')
                response, _ = client.exchange(BASE.call(72, {'path': str(target), 'content': 'owned controlled write'}, 'write_file'))
                require(not BASE.refused(response) and target.read_text() == 'owned controlled write',
                        'original_write_calibration_failed')
            target.unlink()
            probe = QUAL.SHARED.FifoProbe(restored.workspace / 'forbidden.fifo')
            try:
                with restored.client('filesystem') as client:
                    response, _ = client.exchange(QUAL.frame(73, 'filesystem', 'read_text_file',
                                                              {'path': '/workspace/forbidden.fifo'}))
                    require(BASE.result_text(response) == BASE.FIFO_TEXT, 'fifo_calibration_failed')
            finally:
                observed = probe.finish()
            require(observed['reader_seen'] and observed['bytes_written'] == len(BASE.FIFO_TEXT.encode()),
                    'fifo_observer_not_calibrated')
            return {'actual_original_read': True, 'actual_original_write': True,
                    'fifo_reader_observed': True, 'fifo_bytes': observed['bytes_written']}
        step('original-server-calibration', calibration)

        def useful_host():
            evidence, results = restored.host('restored-useful', [[('filesystem', 'read_text_file',
                                                                   {'path': '/workspace/guide.txt'})]])
            require(QUAL.host_text(results['toolu_pilot_0'], 'filesystem') == BASE.TEXT,
                    'restored_original_read_not_useful')
            return {'actual_host': evidence['actual_host'], 'actual_original_server_read': True,
                    'returned_bytes_sha256': sha(BASE.TEXT.encode()),
                    'owned_host_processes_stopped': evidence['process_cleanup']['all_stopped'],
                    'provider_requests': evidence['provider_requests']}
        step('genuine-host-useful-read', useful_host)

        def refusal():
            probe = QUAL.SHARED.FifoProbe(restored.workspace / 'forbidden.fifo')
            try:
                evidence, results = restored.host('restored-refusal', [
                    [('filesystem', 'read_text_file', {'path': '/workspace/source.txt'})],
                    [('filesystem', 'read_text_file', {'path': '/workspace/forbidden.fifo'})],
                    [('filesystem', 'read_text_file', {'path': '/workspace/guide.txt'})]])
                require(QUAL.host_text(results['toolu_pilot_0'], 'filesystem') == QUAL.POINTER,
                        'tainted_source_not_encountered')
                refused = results['toolu_pilot_1']
                require(refused['is_error'] is True and QUAL.SHARED.RULE in json.dumps(refused)
                        and BASE.FIFO_TEXT not in json.dumps(refused), 'calibrated_call_not_refused')
                require(QUAL.host_text(results['toolu_pilot_2'], 'filesystem') == BASE.TEXT,
                        'refusal_broke_useful_continuation')
            finally:
                observed = probe.finish()
            require(not observed['reader_seen'] and observed['bytes_written'] == 0,
                    'forbidden_original_read_effect')
            report['forbidden_effects'] = 0
            return {'calibrated_fifo_reader_seen': False, 'forbidden_bytes': 0,
                    'actual_host': evidence['actual_host'], 'useful_continuation': True}
        step('calibrated-refusal-zero-effects', refusal)

        def old_authority():
            status, _ = native_request(restored, '/native/v1/instance', state['old_token'])
            require(status == 401, 'old_bearer_was_accepted')
            body = {'contract_version': 'sw-native/1', 'registry_sha256': restored.registry_sha256,
                    'session_id': 'old-grant-' + uuid.uuid4().hex, 'event': 'session_start',
                    'host_session': state['old_host'], 'server_id': 'filesystem',
                    'child_authority': state['old_grant']}
            status, raw = native_request(restored, '/native/v1', restored.native_token, body)
            reply = QUAL.strict_json(raw)
            require(status == 409 and reply.get('release') is False
                    and reply.get('error_code') == 'native_child_authority_bad_signature',
                    'old_grant_was_accepted_or_not_cryptographically_refused')
            report['old_authority_accepted'] = False
            return {'old_bearer_http': 401, 'old_grant_http': 409,
                    'old_grant_error': 'native_child_authority_bad_signature', 'release': False}
        step('old-authority-refused', old_authority)

        def sibling_preserved():
            require(source.daemon.poll() is None, 'old_installation_changed')
            renewals = unchanged_live_source(state['home'], state['source_baseline'], state['source_audit'])
            response, _ = state['active'].exchange(QUAL.frame(74, 'filesystem', 'read_text_file',
                                                             {'path': '/workspace/guide.txt'}))
            require(BASE.result_text(response) == BASE.TEXT, 'active_sibling_broken')
            audit = state['home'] / 'audit.jsonl'
            require(audit.read_bytes().startswith(state['source_audit']), 'retained_evidence_rewritten')
            sibling.__exit__(None, None, None)
            state['active'] = None
            return {'same_source_daemon_live': True, 'same_active_sibling_useful': True,
                    'retained_audit_prefix_unchanged': True,
                    'active_sibling_audit_renewals': renewals}
        step('active-sibling-preserved', sibling_preserved)

        def source_race():
            path = state['home'] / 'config.yaml'
            original = path.read_bytes()
            target = private / 'racing-backup.tar'
            publish = RECOVERY.EXCHANGE._publish_private
            def changed(*words, **options):
                path.write_bytes(original + b'\n')
                return publish(*words, **options)
            refused = False
            try:
                with patch.object(RECOVERY.EXCHANGE, '_publish_private', side_effect=changed):
                    RECOVERY.backup(state['home'], args.selection, args.agentfw, args.expected_commit,
                                    target, consent=True)
            except (ValueError, OSError):
                refused = True
            finally:
                path.write_bytes(original)
                path.chmod(0o600)
            require(refused and not target.exists() and path.read_bytes() == original,
                    'concurrent_capture_was_published')
            return {'source_change_refused': True, 'published_archives': 0,
                    'owned_fixture_original_bytes_restored': True}
        step('concurrent-source-change-refused', source_race)

        def interrupted(point, name):
            target_home = private / name
            target_home.mkdir(mode=0o700)
            target = target_home / '.agentfw'
            port = BASE.DEMO.free_port()
            preview = RECOVERY.restore_preview(state['archive'], args.selection, args.agentfw,
                                               args.expected_commit, target, port)
            token = preview['plan_sha256']
            def fail(selected):
                if selected == point:
                    raise OSError('owned interruption')
            with patch.object(RECOVERY, 'fault', side_effect=fail):
                result = RECOVERY.restore(state['archive'], args.selection, args.agentfw,
                    args.expected_commit, target, confirm_plan=token, port=port)
            require(result['status'] == 'incomplete', 'interrupted_restore_claimed_complete')
            require(target.exists() == (point == 'after_publication'), 'interrupted_publication_state_wrong')
            code, result = command(args, state['component_home'], 'recover', '--archive', state['archive'],
                *common, '--destination', target, '--port', port, '--confirm-plan', token)
            require(code == 0 and result['status'] == 'restored' and result.get('recovered') is True,
                    'bounded_recovery_failed')
            require(not (target / 'token').exists() and not (target / 'native-token').exists(),
                    'recovery_restored_authority')
            return {'injected_at': point, 'initial_status': 'incomplete', 'recovery': 'restored',
                    'replayed_authority': False}
        step('interrupted-restore-recovered', lambda: interrupted('before_publication', 'interrupted-home'))
        step('published-restore-recovered', lambda: interrupted('after_publication', 'published-home'))

        def preservation():
            for kind, path in (('filesystem', source.workspace), ('git', source.git_workspace)):
                require(snapshot(path) == state['workspace_baseline'][kind], 'workspace_changed')
            for name in ('config.yaml', 'registry.json', 'token', 'native-token',
                         'provider-key', 'enrollment-key', 'old-approval', 'retained-output'):
                before = state['source_baseline'][name]
                require(sha((state['home'] / name).read_bytes()) == before['sha256'], 'source_state_changed')
            require(sha(state['sentinel'].read_bytes()) == state['retained_sentinel'], 'retained_evidence_changed')
            require(source.daemon.poll() is None, 'source_daemon_lost')
            report['old_installation_preserved'] = True
            return {'source_declarative_and_authority_bytes_unchanged': True,
                    'workspaces_unchanged': True, 'retained_sentinel_unchanged': True}
        step('source-workspace-preservation', preservation)
    finally:
        def cleanup():
            nonlocal sibling
            if state.get('active') is not None and sibling is not None:
                sibling.__exit__(None, None, None)
                state['active'] = None
            stopped = stop_pilot(restored) & stop_pilot(source)
            report['all_owned_processes_stopped'] = stopped
            require(stopped, 'owned_process_cleanup_incomplete')
            for path, device, inode, kind in state.get('owned_seeds', []):
                current = path.lstat()
                require((current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)) ==
                        (device, inode, kind), 'owned_fixture_replaced_before_cleanup')
                path.unlink()
            if source is not None and 'unseeded_workspaces' in state:
                for kind, path in (('filesystem', source.workspace), ('git', source.git_workspace)):
                    require(snapshot(path) == state['unseeded_workspaces'][kind],
                            'original_fixture_workspace_not_restored')
            # Private backup/config/authority and wire files are never artifacts.
            shutil.rmtree(private)
            return {'all_owned_processes_stopped': True, 'private_test_state_removed': True}
        try:
            step('owned-cleanup', cleanup)
        finally:
            report['source_after'] = BASE.source()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--selection', required=True, type=Path)
    parser.add_argument('--agentfw', required=True, type=Path)
    parser.add_argument('--python', required=True, type=Path, help='explicit installed component interpreter')
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({'format': FORMAT, 'status': 'not_executed', 'writes': 0}))
        return 0
    args.output = args.output.absolute()
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_relative_to(ROOT),
            'new_external_qualification_output_required')
    args.output.mkdir(mode=0o700)
    args.work = args.output / 'outside-checkout'
    args.work.mkdir(mode=0o700)
    args.operator_env = BASE.environment(args.work)
    report = {'format': FORMAT, 'status': 'incomplete', 'provider': 'owned-scripted-loopback',
        'paid_api_calls': 0, 'actual_publication_attempts': 0, 'fresh_authority_created': False,
        'old_authority_accepted': None, 'forbidden_effects': None, 'old_installation_preserved': False,
        'operator_commands_outside_checkout': False, 'all_owned_processes_stopped': False,
        'source_before': None, 'source_after': None,
        'platform': {'os': platform.system(), 'architecture': platform.machine(), 'kernel': platform.release()},
        'cases': [{'id': name, 'status': 'incomplete', 'reason': 'not_executed', 'evidence': {}} for name in CASES],
        'limits': {'host_seconds': 150, 'operator_command_seconds': 120,
                   'public_report_bytes': MAX_REPORT, 'private_archive_bytes': RECOVERY.MAX_ARCHIVE}}
    try:
        qualify(args, report)
    except Exception:
        pass  # Finite failed case plus untouched incomplete cases remain authoritative.
    report['counts'] = {name: sum(row['status'] == name for row in report['cases'])
                        for name in ('passed', 'failed', 'incomplete')}
    report['status'] = 'passed' if report['counts']['passed'] == len(CASES) else 'failed'
    if report['cases'][0].get('reason') == 'native_linux_x86_64_required':
        report['status'] = 'unsupported'
    if report['status'] == 'passed' and not passed(report):
        report['status'] = 'failed'
    raw = encoded(report) + b'\n'
    require(len(raw) <= MAX_REPORT and CANARY not in raw, 'qualification_report_limit_or_privacy')
    private_bytes(args.output / 'report.json', raw)
    print(json.dumps({'status': report['status'], 'counts': report['counts'], 'report_sha256': sha(raw)}))
    return 0 if passed(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
