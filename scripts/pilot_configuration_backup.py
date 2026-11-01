#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owner-private declarative configuration recovery; never restore authority.

Only normalized supported configuration is retained. Current runtime inputs are
independently verified for every capture and restore. Preview never writes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile

import pilot_run_state as S
import pilot_update as UPDATE
import pilot_prerequisite_cache_exchange as EXCHANGE

ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'sw-pilot-configuration-backup/1'
CONFIGURATION = 'sw-pilot-configuration-declarative/1'
REPORT = 'sw-pilot-configuration-recovery/1'
JOURNAL = 'sw-pilot-configuration-restore/1'
PROJECTION = 'sw-pilot-configuration-projection/1'
SCOPE = 'linux-declarative-configuration-only'
LIMIT = 65536
MAX_ARCHIVE = 256 * 1024
MEMBERS = ('manifest.json', 'configuration.json')
EXCLUDED = ('credentials', 'enrollment', 'keys', 'grants-and-approvals', 'session-authority',
            'run-state', 'taint-and-provenance-history', 'audit-payloads', 'edit-outputs',
            'workspaces', 'executables', 'source-and-download-caches', 'provider-profiles')
PROJECTOR_REASONS = frozenset(('configuration_invalid', 'configuration_raw_capture_unsupported',
    'configuration_judge_unsupported', 'configuration_legacy_audit_unsupported',
    'configuration_execution_unsupported', 'configuration_policy_reference_required',
    'configuration_reference_unsupported', 'configuration_schema_unsupported',
    'configuration_provenance_schema_unsupported', 'configuration_native_schema_unsupported',
    'configuration_audit_schema_unsupported', 'configuration_policy_invalid',
    'configuration_policy_baseline_unavailable', 'configuration_policy_unsupported',
    'configuration_input_limit', 'configuration_input_invalid', 'configuration_input_unreadable',
    'configuration_projection_platform_unsupported'))
PUBLIC_REASONS = PROJECTOR_REASONS | frozenset(('linux_required', 'native_linux_x86_64_required',
    'non_root_operator_required', 'native_ubuntu_required_wsl_is_separate', 'ubuntu_24_04_required',
    'private_export_consent_required', 'fresh_destination_required', 'explicit_current_plan_required',
    'configuration_source_changed', 'configuration_policy_not_selected', 'configuration_registry_not_selected',
    'configuration_registry_digest_mismatch', 'unsupported_audit_directory_role', 'policy_floor_changed',
    'registry_scope_changed', 'selected_binary_required', 'configuration_record_limit',
    'configuration_schema_invalid', 'configuration_archive_invalid', 'configuration_archive_noncanonical',
    'configuration_archive_inventory_invalid', 'configuration_archive_member_missing',
    'configuration_manifest_mismatch', 'compressed_configuration_archive_refused', 'configuration_archive_limit',
    'exchange_destination_exists', 'exchange_filesystem_unsupported', 'exchange_publication_unavailable',
    'private_owner_required', 'private_regular_file_required', 'directory_changed', 'record_changed',
    'configuration_projection_invalid', 'unsupported_secret_bearing_configuration',
    'configuration_runtime_changed', 'restore_overlaps_source', 'restore_parent_changed',
    'restore_overlaps_runtime_or_workspace', 'restore_overlaps_installed_component',
    'backup_destination_overlaps_source', 'backup_overlaps_runtime_or_workspace',
    'backup_overlaps_installed_component',
    'restore_stage_inventory_changed', 'restore_stage_content_changed', 'restore_destination_substituted',
    'restore_stage_substituted', 'restore_journal_changed', 'restore_retirement_state_changed',
    'removal_state_changed', 'staged_member_changed', 'restore_archive_changed', 'restore_runtime_changed',
    'absolute_canonical_path_required', 'selected_configuration_binary_changed',
    'sealed_configuration_parser_unavailable', 'authoritative_configuration_refused'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load('configuration_preparation', 'prepare-installed-pilot.py')
ARCHIVE = load('configuration_archive_publication', 'pilot-run-archive.py')


class Refusal(ValueError):
    pass


def require(value, code):
    if not value:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        require(type(written) is int and 0 < written <= len(view), 'configuration_write_incomplete')
        view = view[written:]


def exact(value, keys, code='configuration_schema_invalid'):
    require(type(value) is dict and set(value) == set(keys), code)


def strict(raw):
    require(len(raw) <= LIMIT, 'configuration_record_limit')
    value = S.strict(raw)
    require(type(value) is dict, 'configuration_schema_invalid')
    return value


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(str(path)) <= 4096
            and all(ord(c) >= 32 and ord(c) != 127 for c in str(path)), 'absolute_canonical_path_required')
    return path


def read(path, limit=LIMIT):
    path = absolute(path)
    with S.Directory(path.parent, file_modes=(0o400, 0o500, 0o600, 0o644, 0o700, 0o755),
                     directory_modes=(0o700, 0o755)) as parent:
        raw, identity = parent.read(path.name, limit)
    return raw, identity


def private_read(path, limit=LIMIT):
    path = absolute(path)
    with S.Directory(path.parent) as parent:
        return parent.read(path.name, limit)


def projection(binary, raw, *, policy=False, expected_sha256):
    """Run a sealed in-memory copy of the selected bytes, without ambient secrets."""
    require(len(raw) <= LIMIT, 'configuration_input_limit')
    binary = absolute(binary)
    parent_fd = UPDATE.open_directory(binary.parent)
    fd = executable = None
    try:
        fd = os.open(binary.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022,
                'configuration_binary_unsafe')
        named = os.stat(binary.name, dir_fd=parent_fd, follow_symlinks=False)
        require(S.identity(before) == S.identity(named), 'configuration_binary_changed')
        require(0 < before.st_size <= UPDATE.MAX_BINARY, 'configuration_binary_limit')
        # A named executable can be modified after a hash check. Linux seals
        # the exact verified parser bytes instead of executing a mutable path.
        import fcntl
        require(hasattr(os, 'memfd_create'), 'sealed_configuration_parser_unavailable')
        executable = os.memfd_create('configuration-parser', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        binary_hash, total = hashlib.sha256(), 0
        while block := os.read(fd, 65536):
            total += len(block)
            require(total <= UPDATE.MAX_BINARY, 'configuration_binary_limit')
            binary_hash.update(block)
            view = memoryview(block)
            while view:
                count = os.write(executable, view)
                require(count > 0, 'configuration_parser_copy_incomplete')
                view = view[count:]
        require(total == before.st_size and binary_hash.hexdigest() == expected_sha256,
                'selected_configuration_binary_changed')
        require(S.identity(before) == S.identity(os.fstat(fd))
                == S.identity(os.stat(binary.name, dir_fd=parent_fd, follow_symlinks=False)),
                'configuration_binary_changed')
        os.fchmod(executable, 0o500)
        fcntl.fcntl(executable, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        command = ['/proc/self/fd/' + str(executable), 'configuration-project']
        if policy:
            command.append('--policy')
        result = subprocess.run(command, input=raw, capture_output=True, timeout=5,
            pass_fds=(executable,), cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        require(S.identity(before) == S.identity(os.fstat(fd))
                == S.identity(os.stat(binary.name, dir_fd=parent_fd, follow_symlinks=False)),
                'configuration_binary_changed')
        return projected_result(result, policy)
    finally:
        if fd is not None:
            os.close(fd)
        if executable is not None:
            os.close(executable)
        os.close(parent_fd)


def projected_result(result, policy=False):
    require(len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT,
            'authoritative_configuration_refused')
    value = strict(result.stdout)
    require(value.get('version') == PROJECTION and value.get('kind') == ('policy' if policy else 'config'),
            'configuration_projection_invalid')
    if result.returncode != 0:
        reason = value.get('reason')
        require(value.get('status') in ('refused', 'unsupported') and reason in PROJECTOR_REASONS,
                'authoritative_configuration_refused')
        raise Refusal(reason)
    require(value.get('status') == 'projected', 'configuration_projection_invalid')
    return value


def runtime(selection, binary, expected_commit):
    S.platform()
    PREP.supported_platform()
    selection, binary = absolute(selection), absolute(binary)
    require(re.fullmatch('[0-9a-f]{40}', expected_commit or '') is not None,
            'explicit_source_commit_required')
    raw, selected_inode = read(selection)
    verified, profiles = PREP.verify_generation(selection.parent, expected_commit, probe_native=False)
    require(verified == selection and selection.name == 'selection.json', 'explicit_selection_changed')
    selected = strict(raw)
    require(read(selection) == (raw, selected_inode), 'selection_changed')
    files = selected['files']
    require(set(files) == set(PREP.PILOT.ROLES), 'runtime_inventory_invalid')
    require(Path(files['agentfw']['path']) == binary, 'selected_binary_required')
    binding = {'source_commit': expected_commit, 'selection_sha256': sha(raw),
               'source': selected['source'], 'selection_path': str(selection),
               'files': files, 'profiles': profiles}
    policy_raw, policy_inode = read(files['policy']['path'])
    require(sha(policy_raw) == files['policy']['sha256'], 'selected_policy_changed')
    projected_policy = projection(binary, policy_raw, policy=True,
                                  expected_sha256=files['agentfw']['sha256'])
    require(re.fullmatch('[0-9a-f]{64}', projected_policy.get('policy_sha256', '')) is not None,
            'policy_projection_invalid')
    registries = []
    for kind in ('filesystem', 'git'):
        path = Path(profiles[kind]['profile']['path']).parent / 'registry.json'
        registry_raw, _ = read(path)
        require(sha(registry_raw) == profiles[kind]['registry_sha256'], 'selected_registry_changed')
        registries.extend(strict(registry_raw)['tools'])
    roots = [selection.parent, ROOT]
    roots.extend(Path(item['path']) for item in files.values())
    roots.extend(PREP.workspace_paths(selected, selection.parent, revalidate=False).values())
    roots.extend(Path(item['profile']['path']).parent for item in profiles.values())
    for profile in profiles.values():
        profile_raw = read(profile['profile']['path'])[0]
        require(sha(profile_raw) == profile['profile']['sha256'], 'selected_profile_changed')
        body = strict(profile_raw)
        roots.append(Path(body['packageRoot']))
    return {'binding': binding, 'selection': selected, 'policy_raw': policy_raw,
            'policy_identity': policy_inode, 'policy_projection': projected_policy,
            'tools': registries, 'binary': binary, 'selection_raw': raw,
            'preserved_roots': sorted({str(absolute(root)) for root in roots})}


def merged_registry(current, registry_id):
    require(registry_id in ('prepared-pilot-v1', 'installed-development-pilot-v1'),
            'unsupported_registry_scope')
    return (json.dumps({'contract_version': 'sw-native/1', 'registry_id': registry_id,
                        'tools': current['tools']}, sort_keys=True, indent=2) + '\n').encode()


def validate_projection(value):
    exact(value, ('version', 'kind', 'status', 'config', 'references'))
    require(value['version'] == PROJECTION and value['kind'] == 'config'
            and value['status'] == 'projected', 'configuration_projection_invalid')
    cfg = value['config']
    exact(cfg, ('bind', 'port', 'enforce', 'audit', 'capture_unknown_raw', 'max_record_bytes',
                'provenance', 'deterministic_timeout_ms', 'max_body_bytes', 'native', 'audit_retention'))
    require(cfg['audit'] is None and cfg['capture_unknown_raw'] is False,
            'unsupported_secret_bearing_configuration')
    require(cfg['bind'] in ('127.0.0.1', '::1', 'localhost')
            and type(cfg['port']) is int and 1 <= cfg['port'] <= 65535
            and type(cfg['enforce']) is bool, 'configuration_scalar_invalid')
    for key in ('max_record_bytes', 'deterministic_timeout_ms', 'max_body_bytes'):
        require(type(cfg[key]) is int and 0 <= cfg[key] <= (1 << 63) - 1,
                'configuration_scalar_invalid')
    exact(cfg['provenance'], ('per_session_bytes', 'total_bytes', 'max_sessions', 'max_input_bytes',
                              'max_source_bytes', 'max_literal_bytes', 'max_session_id_bytes'))
    require(all(type(v) is int and 0 <= v <= (1 << 63) - 1 for v in cfg['provenance'].values()),
            'configuration_provenance_invalid')
    if cfg['native'] is not None:
        native = cfg['native']
        require(type(native) is dict and {'registry_sha256'} <= set(native)
                <= {'registry_sha256', 'approval', 'liveness'}, 'configuration_native_invalid')
        require(type(native['registry_sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', native['registry_sha256']), 'configuration_native_invalid')
        if 'approval' in native:
            exact(native['approval'], ('ttl_seconds',))
            require(type(native['approval']['ttl_seconds']) is int
                    and 1 <= native['approval']['ttl_seconds'] <= 300, 'configuration_approval_invalid')
        if 'liveness' in native:
            exact(native['liveness'], ('default_lease_seconds', 'max_lease_seconds', 'maintenance_interval_ms'))
            require(all(type(v) is int and 0 < v <= (1 << 63) - 1
                        for v in native['liveness'].values()), 'configuration_liveness_invalid')
    if cfg['audit_retention'] is not None:
        exact(cfg['audit_retention'], ('version', 'segment_size_bytes', 'segment_count',
                                       'total_disk_bytes', 'max_record_bytes'))
        require(all(type(v) is int and 0 < v <= (1 << 63) - 1
                    for v in cfg['audit_retention'].values())
                and cfg['audit_retention']['version'] == 1, 'configuration_audit_limits_invalid')
    exact(value['references'], ('policy', 'registry', 'audit_directory'))
    absolute(value['references']['policy'])
    for key in ('registry', 'audit_directory'):
        if value['references'][key] is not None:
            absolute(value['references'][key])
    require((cfg['native'] is None) == (value['references']['registry'] is None)
            and (cfg['audit_retention'] is None) == (value['references']['audit_directory'] is None),
            'configuration_reference_mismatch')
    return value


def validate_document(document):
    exact(document, ('format', 'projection', 'source_home', 'source_config', 'runtime_binding',
                     'policy', 'registry', 'audit_directory_role'))
    require(document['format'] == CONFIGURATION, 'configuration_schema_version')
    validate_projection(document['projection'])
    absolute(document['source_home'])
    exact(document['source_config'], ('sha256', 'bytes'))
    require(type(document['source_config']['bytes']) is int and 0 < document['source_config']['bytes'] <= LIMIT
            and type(document['source_config']['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', document['source_config']['sha256']),
            'source_config_identity_invalid')
    binding = document['runtime_binding']
    exact(binding, ('source_commit', 'source', 'selection_sha256', 'selection_path', 'files', 'profiles'))
    require(type(binding['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', binding['source_commit'])
            and type(binding['selection_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', binding['selection_sha256']), 'source_runtime_identity_invalid')
    absolute(binding['selection_path'])
    exact(binding['source'], ('commit', 'tree', 'dirty', 'files_sha256'))
    require(binding['source']['commit'] == binding['source_commit']
            and type(binding['source']['tree']) is str and re.fullmatch('[0-9a-f]{40}', binding['source']['tree'])
            and binding['source']['dirty'] is False and type(binding['source']['files_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', binding['source']['files_sha256']), 'source_runtime_identity_invalid')
    exact(binding['files'], PREP.PILOT.ROLES)
    for record in binding['files'].values():
        exact(record, ('path', 'sha256'))
        absolute(record['path'])
        require(type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['sha256']),
                'source_runtime_identity_invalid')
    exact(binding['profiles'], ('filesystem', 'git'))
    for profile in binding['profiles'].values():
        require(type(profile) is dict and set(profile) in (
            {'profile', 'registry_sha256', 'package_tree_sha256'},
            {'profile', 'registry_sha256', 'package_tree_sha256', 'format',
             'policy_sha256', 'installation_sha256'}), 'source_profile_identity_invalid')
        exact(profile['profile'], ('path', 'sha256'))
        absolute(profile['profile']['path'])
        for key, value in profile.items():
            if key not in ('profile', 'format'):
                require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                        'source_profile_identity_invalid')
        require(type(profile['profile']['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', profile['profile']['sha256']), 'source_profile_identity_invalid')
        if 'format' in profile:
            require(type(profile['format']) is str and re.fullmatch('[a-zA-Z0-9_./-]{1,100}', profile['format']),
                    'source_profile_identity_invalid')
    for name in ('policy', 'registry'):
        record = document[name]
        if name == 'registry' and record is None:
            require(document['projection']['config']['native'] is None, 'source_registry_identity_invalid')
            continue
        exact(record, ('path', 'sha256', 'bytes', 'semantic_sha256') if name == 'policy'
              else ('path', 'sha256', 'bytes', 'registry_id'))
        absolute(record['path'])
        require(type(record['bytes']) is int and 0 < record['bytes'] <= LIMIT
                and type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['sha256']),
                'source_reference_identity_invalid')
        require(record['path'] == document['projection']['references'][name],
                'source_reference_identity_invalid')
        if name == 'policy':
            require(type(record['semantic_sha256']) is str
                    and re.fullmatch('[0-9a-f]{64}', record['semantic_sha256']), 'source_policy_identity_invalid')
        else:
            require(document['projection']['config']['native'] is not None
                    and document['projection']['config']['native']['registry_sha256'] == record['sha256']
                    and record['registry_id'] in ('prepared-pilot-v1', 'installed-development-pilot-v1'),
                    'source_registry_identity_invalid')
    audit = document['projection']['references']['audit_directory']
    require(document['audit_directory_role'] == ('agent-home/audit' if audit is not None else None)
            and (audit is None or Path(audit) == Path(document['source_home']) / 'audit'),
            'source_audit_role_invalid')
    return document


def capture(source_home, selection, binary, expected_commit):
    source_home = absolute(source_home)
    current = runtime(selection, binary, expected_commit)
    with S.Directory(source_home) as home:
        raw, config_inode = home.read('config.yaml')
        projected = validate_projection(projection(binary, raw,
            expected_sha256=current['binding']['files']['agentfw']['sha256']))
        policy_path = projected['references']['policy']
        policy_raw, policy_inode = read(policy_path)
        require(policy_raw == current['policy_raw'], 'configuration_policy_not_selected')
        policy = {'path': policy_path, 'sha256': sha(policy_raw), 'bytes': len(policy_raw),
                  'semantic_sha256': current['policy_projection']['policy_sha256']}
        registry = None
        if projected['config']['native'] is not None:
            registry_path = projected['references']['registry']
            registry_raw, registry_inode = read(registry_path)
            parsed = strict(registry_raw)
            registry_id = parsed.get('registry_id')
            require(registry_raw == merged_registry(current, registry_id), 'configuration_registry_not_selected')
            require(projected['config']['native']['registry_sha256'] == sha(registry_raw),
                    'configuration_registry_digest_mismatch')
            registry = {'path': registry_path, 'sha256': sha(registry_raw),
                        'bytes': len(registry_raw), 'registry_id': registry_id}
        audit_path = projected['references']['audit_directory']
        require(audit_path is None or Path(audit_path) == source_home / 'audit',
                'unsupported_audit_directory_role')
        document = {'format': CONFIGURATION, 'projection': projected, 'source_home': str(source_home),
                    'source_config': {'sha256': sha(raw), 'bytes': len(raw)},
                    'runtime_binding': current['binding'], 'policy': policy, 'registry': registry,
                    'audit_directory_role': 'agent-home/audit' if audit_path else None}

        def verify():
            require(home.read('config.yaml') == (raw, config_inode), 'configuration_source_changed')
            require(read(policy_path) == (policy_raw, policy_inode), 'configuration_policy_changed')
            if registry is not None:
                require(read(registry['path']) == (registry_raw, registry_inode), 'configuration_registry_changed')
            require(runtime(selection, binary, expected_commit)['binding'] == current['binding'],
                    'configuration_runtime_changed')
        validate_document(document)
        verify()
        return document


def base_report(status, **values):
    return {'format': REPORT, 'scope': SCOPE, 'status': status,
            'configuration': 'restored' if status == 'restored' else 'not_restored',
            'enrollment': 'unverified', 'launch_readiness': 'unverified',
            'observed_protection': 'unverified', 'authority': 'not_restored',
            'readiness_blockers': ['fresh_authority_required', 'credentials_and_enrollment_not_restored',
                                   'daemon_launch_unverified', 'observed_protection_unverified'],
            'post_restore_requirements': ['supply_credentials_and_enrollment_through_existing_flows_if_needed',
                'create_fresh_authority_through_existing_flows', 'launch_explicitly_and_observe_protection'],
            'excluded': list(EXCLUDED), 'blockers': [], **values}


def inventory(source_home, selection, binary, expected_commit):
    document = capture(source_home, selection, binary, expected_commit)
    return base_report('inventoried', supported_configuration=True,
                       configuration_sha256=digest(document), archive_members=list(MEMBERS))


def archive_bytes(document):
    raw = canonical(document) + b'\n'
    require(len(raw) <= LIMIT, 'configuration_document_limit')
    manifest = {'format': FORMAT, 'scope': SCOPE,
        'source_commit': document['runtime_binding']['source_commit'],
        'configuration_schema': CONFIGURATION, 'excluded': list(EXCLUDED),
        'members': [{'name': 'configuration.json', 'bytes': len(raw), 'sha256': sha(raw)}]}
    manifest_raw = canonical(manifest) + b'\n'
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in zip(MEMBERS, (manifest_raw, raw)):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid, member.mtime = len(body), 0o600, 0, 0, 0
            archive.addfile(member, io.BytesIO(body))
    result = output.getvalue()
    require(len(result) <= MAX_ARCHIVE, 'configuration_archive_limit')
    return result


class Claim:
    def __init__(self, callback):
        self.verify = callback


def backup(source_home, selection, binary, expected_commit, archive, *, consent=False):
    require(consent is True, 'private_export_consent_required')
    archive = absolute(archive)
    require(not archive.is_relative_to(absolute(source_home)), 'backup_destination_overlaps_source')
    document = capture(source_home, selection, binary, expected_commit)
    current = runtime(selection, binary, expected_commit)
    require(current['binding'] == document['runtime_binding'], 'configuration_runtime_changed')
    for root in current['preserved_roots']:
        require(not archive.is_relative_to(absolute(root)), 'backup_overlaps_runtime_or_workspace')
    raw = archive_bytes(document)
    def verify():
        require(capture(source_home, selection, binary, expected_commit) == document,
                'configuration_source_changed')
    with S.Directory(archive.parent):
        def writer(fd):
            write_all(fd, raw)
        EXCHANGE._publish_private(archive.parent, archive.name, writer, Claim(verify))
    return base_report('backed-up', archive_sha256=sha(raw), archive_bytes=len(raw), members=2)


def load_archive(archive):
    raw, identity = private_read(archive, MAX_ARCHIVE)
    require(len(raw) % 512 == 0 and len(raw) >= 1024, 'configuration_archive_invalid')
    require(raw[:2] != b'\x1f\x8b', 'compressed_configuration_archive_refused')
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        for number, member in enumerate(tar):
            require(number < 2 and member.name == MEMBERS[number] and member.isfile()
                    and member.type == tarfile.REGTYPE and not member.pax_headers
                    and not member.linkname and member.mode == 0o600
                    and 0 < member.size <= LIMIT, 'configuration_archive_inventory_invalid')
            stream = tar.extractfile(member)
            body = stream.read(LIMIT + 1)
            require(len(body) == member.size, 'configuration_archive_member_changed')
            bodies[member.name] = body
        require(tuple(bodies) == MEMBERS, 'configuration_archive_member_missing')
        end = tar.offset
    require(not any(raw[end:]), 'configuration_archive_trailing_data')
    manifest, document = strict(bodies['manifest.json']), strict(bodies['configuration.json'])
    exact(manifest, ('format', 'scope', 'source_commit', 'configuration_schema', 'excluded', 'members'))
    require(manifest == {'format': FORMAT, 'scope': SCOPE,
        'source_commit': document.get('runtime_binding', {}).get('source_commit'),
        'configuration_schema': CONFIGURATION, 'excluded': list(EXCLUDED),
        'members': [{'name': 'configuration.json', 'bytes': len(bodies['configuration.json']),
                     'sha256': sha(bodies['configuration.json'])}]}, 'configuration_manifest_mismatch')
    validate_document(document)
    require(raw == archive_bytes(document), 'configuration_archive_noncanonical')
    return document, sha(raw), identity


def inspect(archive):
    document, archive_hash, _ = load_archive(archive)
    return base_report('inspected', archive_sha256=archive_hash,
        configuration_sha256=digest(document), source_commit=document['runtime_binding']['source_commit'],
        schema_valid=True, configuration_support='requires_current_authoritative_validation',
        current_runtime='not_selected', members=2)


def destination_state(destination):
    destination = absolute(destination)
    S.safe_component(destination.name)
    with S.Directory(destination.parent) as parent:
        parent.check()
        parent_identity = parent.object
    return destination, parent_identity


def bound_config(document, current, destination, port=None):
    cfg = copy.deepcopy(document['projection']['config'])
    if port is not None:
        require(type(port) is int and 1 <= port <= 65535, 'invalid_restore_port')
        cfg['port'] = port
    cfg['policy'] = str(destination / 'policy.yaml')
    registry_raw = None
    if cfg['native'] is not None:
        require(type(document['registry']) is dict, 'configuration_registry_missing')
        registry_raw = merged_registry(current, document['registry']['registry_id'])
        require(sha(registry_raw) == document['registry']['sha256'], 'registry_scope_changed')
        cfg['native']['registry_path'] = str(destination / 'registry.json')
        cfg['native']['registry_sha256'] = sha(registry_raw)
    if cfg['audit_retention'] is not None:
        require(document['audit_directory_role'] == 'agent-home/audit', 'audit_directory_role_invalid')
        cfg['audit_retention']['directory'] = str(destination / 'audit')
    else:
        require(document['audit_directory_role'] is None, 'audit_directory_role_invalid')
    require(sha(current['policy_raw']) == document['policy']['sha256'], 'policy_floor_changed')
    require(current['policy_projection']['policy_sha256'] == document['policy']['semantic_sha256'],
            'policy_floor_changed')
    roundtrip = validate_projection(projection(current['binary'], canonical(cfg),
        expected_sha256=current['binding']['files']['agentfw']['sha256']))
    expected = copy.deepcopy(document['projection'])
    if port is not None:
        expected['config']['port'] = port
    expected['references'] = {'policy': cfg['policy'],
        'registry': cfg['native']['registry_path'] if cfg['native'] is not None else None,
        'audit_directory': cfg['audit_retention']['directory'] if cfg['audit_retention'] is not None else None}
    require(roundtrip == expected, 'restored_configuration_projection_changed')
    bodies = {'config.yaml': canonical(cfg) + b'\n', 'policy.yaml': current['policy_raw']}
    if registry_raw is not None:
        bodies['registry.json'] = registry_raw
    return bodies


def plan(archive, selection, binary, expected_commit, destination, port=None):
    document, archive_hash, archive_identity = load_archive(archive)
    current = runtime(selection, binary, expected_commit)
    destination, parent_identity = destination_state(destination)
    require(not destination.is_relative_to(Path(document['source_home']))
            and not Path(document['source_home']).is_relative_to(destination), 'restore_overlaps_source')
    for root in current['preserved_roots']:
        root = absolute(root)
        require(not destination.is_relative_to(root) and not root.is_relative_to(destination),
                'restore_overlaps_runtime_or_workspace')
    bodies = bound_config(document, current, destination, port)
    changes = {'source_home_sha256': sha(document['source_home'].encode()),
        'destination_sha256': sha(str(destination).encode()),
        'runtime_binding_changed': document['runtime_binding'] != current['binding'],
        'old_binding_sha256': digest(document['runtime_binding']),
        'new_binding_sha256': digest(current['binding']),
        'old_port': document['projection']['config']['port'],
        'new_port': port if port is not None else document['projection']['config']['port'],
        'audit_directory_rebound': document['audit_directory_role'] is not None}
    core = {'format': JOURNAL, 'archive_sha256': archive_hash, 'candidate_binding': current['binding'],
            'destination': str(destination), 'parent_identity': parent_identity,
            'configuration_sha256': digest(document), 'changes': changes,
            'files': {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in bodies.items()},
            'audit_directory': document['audit_directory_role'] is not None}
    token = digest(core)
    receipt = {'format': JOURNAL, 'plan_sha256': token, 'configuration': 'restored',
               'authority': 'not_restored', 'enrollment': 'unverified',
               'launch_readiness': 'unverified', 'observed_protection': 'unverified'}
    bodies['configuration-restored.json'] = canonical(receipt) + b'\n'
    return {'core': core, 'plan_sha256': token, 'bodies': bodies, 'archive_identity': archive_identity,
            'current': current, 'document': document}


def restore_preview(archive, selection, binary, expected_commit, destination, port=None):
    prepared = plan(archive, selection, binary, expected_commit, destination, port)
    destination = Path(prepared['core']['destination'])
    require(not destination.exists() and not destination.is_symlink(), 'fresh_destination_required')
    return base_report('preview', plan_sha256=prepared['plan_sha256'],
                       changes=prepared['core']['changes'], write_attempts=0)


def names(prepared):
    suffix = prepared['plan_sha256'][:32]
    return '.configuration-stage-' + suffix, '.configuration-restore-' + suffix + '.json'


def verify_members(directory, prepared, *, complete):
    allowed = set(prepared['bodies']) | ({'audit'} if prepared['core']['audit_directory'] else set())
    selected = set(directory.names(8))
    require(selected <= allowed and (not complete or selected == allowed), 'restore_stage_inventory_changed')
    for name in sorted(selected):
        if name == 'audit':
            with directory.child(name) as audit:
                require(audit.names(1) == [], 'restore_audit_not_empty')
        else:
            require(directory.read(name)[0] == prepared['bodies'][name], 'restore_stage_content_changed')


def selected_journal(parent, prepared):
    stage, journal_name = names(prepared)
    raw, selected = parent.read(journal_name)
    journal = strict(raw)
    exact(journal, ('format', 'plan_sha256', 'stage', 'destination', 'stage_identity', 'files'))
    require(journal['format'] == JOURNAL and journal['plan_sha256'] == prepared['plan_sha256']
            and journal['stage'] == stage and journal['destination'] == Path(prepared['core']['destination']).name
            and journal['files'] == {k: sha(v) for k, v in prepared['bodies'].items()}
            and type(journal['stage_identity']) is list and len(journal['stage_identity']) == 4,
            'restore_journal_changed')
    return journal, raw, selected


def checked_journal(parent, prepared):
    return selected_journal(parent, prepared)[0]


def retire_journal(parent, prepared):
    """Reuse the accepted detach-and-check retirement; preserve substituted bytes."""
    _, journal_name = names(prepared)
    _, raw, selected = selected_journal(parent, prepared)
    quarantine_name = '.configuration-retire-' + prepared['plan_sha256'][:32]
    if quarantine_name not in parent.names(256):
        os.mkdir(quarantine_name, mode=0o700, dir_fd=parent.fd)
    with parent.child(quarantine_name) as quarantine:
        require(quarantine.names(1) == [], 'restore_retirement_state_changed')
        fault('before_journal_retirement')
        ARCHIVE.remove_member(parent, journal_name, quarantine,
            {'identity': selected, 'bytes': len(raw), 'sha256': sha(raw)}, parent.check)
        # Retain the empty private retirement directory. Removing a named
        # directory could itself remove a substituted directory after a check.


def fault(_point):
    """Test seam; production has no environment-selected fault behavior."""


def restore(archive, selection, binary, expected_commit, destination, *, confirm_plan,
            port=None, recovery=False):
    prepared = plan(archive, selection, binary, expected_commit, destination, port)
    require(confirm_plan == prepared['plan_sha256'], 'explicit_current_plan_required')
    destination = Path(prepared['core']['destination'])
    stage_name, journal_name = names(prepared)
    result = base_report('incomplete', plan_sha256=prepared['plan_sha256'])
    with S.Directory(destination.parent) as parent:
        require(parent.object == prepared['core']['parent_identity'], 'restore_parent_changed')
        if not recovery:
            require(destination.name not in parent.names(256) and stage_name not in parent.names(256)
                    and journal_name not in parent.names(256), 'fresh_destination_required')
        try:
            if recovery:
                journal = checked_journal(parent, prepared)
                destination_exists = destination.name in parent.names(256)
                selected_name = destination.name if destination_exists else stage_name
                with parent.child(selected_name) as stage:
                    require(stage.object == journal['stage_identity'], 'restore_destination_substituted')
                    verify_members(stage, prepared, complete=destination_exists)
                    if destination_exists:
                        parent.check()
                        retire_journal(parent, prepared)
                        return base_report('restored', plan_sha256=prepared['plan_sha256'], recovered=True)
            else:
                os.mkdir(stage_name, mode=0o700, dir_fd=parent.fd)
                with parent.child(stage_name) as stage:
                    journal = {'format': JOURNAL, 'plan_sha256': prepared['plan_sha256'],
                        'stage': stage_name, 'destination': destination.name, 'stage_identity': stage.object,
                        'files': {k: sha(v) for k, v in prepared['bodies'].items()}}
                    def write_journal(fd):
                        write_all(fd, canonical(journal) + b'\n')
                    EXCHANGE._publish_private(parent.path, journal_name, write_journal, Claim(parent.check))
            with parent.child(stage_name) as stage:
                require(stage.object == journal['stage_identity'], 'restore_stage_substituted')
                verify_members(stage, prepared, complete=False)
                for name, raw in prepared['bodies'].items():
                    if name not in stage.names(8):
                        def write_member(fd, body=raw):
                            write_all(fd, body)
                        EXCHANGE._publish_private(stage.path, name, write_member, Claim(stage.check))
                        fault('member_published')
                if prepared['core']['audit_directory'] and 'audit' not in stage.names(8):
                    os.mkdir('audit', mode=0o700, dir_fd=stage.fd)
                    os.fsync(stage.fd)
                verify_members(stage, prepared, complete=True)
                require(runtime(selection, binary, expected_commit)['binding'] == prepared['current']['binding'],
                        'restore_runtime_changed')
                require(private_read(archive, MAX_ARCHIVE)[1] == prepared['archive_identity'], 'restore_archive_changed')
                parent.check()
                require(parent.object == prepared['core']['parent_identity'], 'restore_parent_changed')
                fault('before_publication')
                stage.check()
                parent.check()
                verify_members(stage, prepared, complete=True)
                ARCHIVE.rename_exclusive(parent.fd, stage_name, parent.fd, destination.name)
                os.fsync(parent.fd)
                fault('after_publication')
                with parent.child(destination.name) as published:
                    require(published.object == journal['stage_identity'], 'restore_destination_substituted')
                    verify_members(published, prepared, complete=True)
                retire_journal(parent, prepared)
                return base_report('restored', plan_sha256=prepared['plan_sha256'], recovered=recovery)
        except (OSError, ValueError, EXCHANGE.Refusal, subprocess.SubprocessError) as exc:
            result['blockers'] = ['restore_interrupted_or_changed_retained_state']
            result['recovery'] = 'repeat_recover_with_same_explicit_inputs_and_plan'
            code = str(exc)
            if code in PUBLIC_REASONS:
                result['blockers'].append(code)
            if code in ('restore_stage_inventory_changed', 'restore_stage_content_changed',
                        'restore_destination_substituted', 'restore_stage_substituted',
                        'restore_journal_changed', 'restore_retirement_state_changed',
                        'removal_state_changed', 'staged_member_changed'):
                result['recovery'] = 'preserve_unrecognized_state_manual_inspection_required'
            try:
                parent.check()
                if journal_name not in parent.names(256):
                    result['blockers'].append('restore_journal_not_published')
                    result['recovery'] = 'unidentified_private_stage_retained_manual_inspection_required'
            except (OSError, ValueError):
                result['blockers'].append('restore_parent_identity_unconfirmed')
                result['recovery'] = 'preserve_retained_state_and_inspect_destination_parent'
            return result


def recover(archive, selection, binary, expected_commit, destination, *, confirm_plan, port=None):
    return restore(archive, selection, binary, expected_commit, destination,
                   confirm_plan=confirm_plan, port=port, recovery=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-home', type=Path, help='installed component home; never a restore source')
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('inventory', 'backup', 'inspect', 'restore-preview', 'restore', 'recover'):
        command = commands.add_parser(action)
        if action in ('inventory', 'backup'):
            command.add_argument('--source-home', required=True, type=Path)
        if action != 'inspect':
            command.add_argument('--selection', required=True, type=Path)
            command.add_argument('--agentfw', required=True, type=Path)
            command.add_argument('--expected-commit', required=True)
        if action != 'inventory':
            command.add_argument('--archive', required=True, type=Path)
        if action == 'backup':
            command.add_argument('--consent', action='store_true')
        if action in ('restore-preview', 'restore', 'recover'):
            command.add_argument('--destination', required=True, type=Path)
            command.add_argument('--port', type=int)
        if action in ('restore', 'recover'):
            command.add_argument('--confirm-plan', required=True)
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux'):
        print(json.dumps(base_report('unsupported', blockers=['linux_required']), sort_keys=True))
        return 5
    try:
        S.platform()
        if args.action in ('restore-preview', 'restore', 'recover') and args.agent_home is not None:
            component, destination = absolute(args.agent_home), absolute(args.destination)
            require(not destination.is_relative_to(component) and not component.is_relative_to(destination),
                    'restore_overlaps_installed_component')
        if args.action == 'backup' and args.agent_home is not None:
            require(not absolute(args.archive).is_relative_to(absolute(args.agent_home)),
                    'backup_overlaps_installed_component')
        if args.action == 'inspect':
            result = inspect(args.archive)
        elif args.action == 'inventory':
            result = inventory(args.source_home, args.selection, args.agentfw, args.expected_commit)
        elif args.action == 'backup':
            result = backup(args.source_home, args.selection, args.agentfw, args.expected_commit,
                            args.archive, consent=args.consent)
        elif args.action == 'restore-preview':
            result = restore_preview(args.archive, args.selection, args.agentfw, args.expected_commit,
                                     args.destination, args.port)
        else:
            result = (recover if args.action == 'recover' else restore)(args.archive, args.selection,
                args.agentfw, args.expected_commit, args.destination,
                confirm_plan=args.confirm_plan, port=args.port)
        print(json.dumps(result, sort_keys=True))
        return 4 if result['status'] == 'incomplete' else 0
    except (OSError, ValueError, EXCHANGE.Refusal, KeyError, TypeError,
            tarfile.TarError, subprocess.SubprocessError) as exc:
        code = str(exc)
        if code not in PUBLIC_REASONS:
            code = 'unsupported_or_changed_configuration_inputs'
        print(json.dumps(base_report('refused', blockers=[code]), sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
