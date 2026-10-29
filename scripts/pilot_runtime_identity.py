# SPDX-License-Identifier: Apache-2.0
"""Scoped input custody for the existing pilot producers, never a readiness gate.

The coordinator owns the predeclared plan and independent descriptor reader.
Producers submit paths, not authoritative digests. Raw input snapshots stay private.
"""
from __future__ import annotations
import base64
import copy
from functools import wraps
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading

from roadmap_support import bounded_tree, pairs_unique, require

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = 'scripts/benchmarks/pilot-readiness-scopes-v1.json'
STAGES = ('installed', 'matched', 'ask', 'prepared', 'docs-code', 'unicode-spaces', 'local-history')
BINARY_ROLES = ('agentfw', 'git_launcher', 'claude', 'node', 'git', 'bwrap')
MAX_JSON = 2 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    require(len(raw) <= MAX_JSON, 'identity_byte_limit')
    value = json.loads(raw, object_pairs_hook=pairs_unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('identity_nonfinite')))
    bounded_tree(value)
    require(type(value) is dict, 'identity_object_required')
    return value


def same_digest(actual, expected):
    require(type(actual) is str and type(expected) is str and len(actual) == len(expected) == 64
            and all(c in '0123456789abcdef' for c in actual + expected)
            and hmac.compare_digest(actual, expected), 'runtime_identity_mismatch')


def blob(raw):
    require(len(raw) <= 48000, 'identity_input_byte_limit')
    return {'sha256': sha(raw), 'base64': base64.b64encode(raw).decode('ascii')}


def unblob(value):
    require(type(value) is dict and set(value) == {'sha256', 'base64'} and
            type(value['base64']) is str and len(value['base64']) <= 64000, 'invalid_identity_input')
    raw = base64.b64decode(value['base64'], validate=True)
    same_digest(sha(raw), value['sha256'])
    return raw


def json_input(value):
    return parse(unblob(value))


def selection_input(value):
    selected = json_input(value)
    require(selected.get('format') in ('sw-installed-pilot-selection/2', 'sw-installed-pilot-selection/3'),
            'unsupported_runtime_selection')
    return selected


def file_sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def freeze(source, paths, selection, read=lambda name: (ROOT / name).read_bytes()):
    template = parse(read(TEMPLATE))
    require(template['format'] == 'sw-pilot-runtime-scopes/1' and set(template['stages']) == set(STAGES),
            'unsupported_runtime_scope_template')
    policies = {name: blob(read(ref['path'])) for name, ref in template['policies'].items()}
    for name, ref in template['policies'].items():
        same_digest(policies[name]['sha256'], ref['sha256'])
    return {'format': 'sw-pilot-runtime-plan/1', 'source': source,
            'template_sha256': sha(read(TEMPLATE)), 'template': template, 'policies': policies,
            'selection': blob(Path(selection).read_bytes()),
            'selected_sha256': {name: file_sha(path) for name, path in paths.items()},
            'classifier_sha256': {name: sha(read(path)) for name, path in template['classifier_sources'].items()},
            'producer_sha256': {stage: sha(read('scripts/' + row['producer']))
                               for stage, row in template['stages'].items()}}


def verify_plan(plan, source, read):
    require(set(plan) == {'format', 'source', 'template_sha256', 'template', 'policies', 'selection',
                         'selected_sha256', 'classifier_sha256', 'producer_sha256'}, 'runtime_plan_fields_changed')
    require(plan.get('format') == 'sw-pilot-runtime-plan/1' and plan.get('source') == source,
            'runtime_plan_source_mismatch')
    same_digest(plan['template_sha256'], sha(read(TEMPLATE)))
    require(plan['template'] == parse(read(TEMPLATE)), 'runtime_template_mismatch')
    expected = plan['template']
    require(expected['format'] == 'sw-pilot-runtime-scopes/1' and set(expected['stages']) == set(STAGES),
            'runtime_stage_inventory_changed')
    for name, ref in expected['policies'].items():
        same_digest(ref['sha256'], sha(read(ref['path'])))
        require(unblob(plan['policies'][name]) == read(ref['path']), 'runtime_policy_template_changed')
    for name, path in expected['classifier_sources'].items():
        same_digest(plan['classifier_sha256'][name], sha(read(path)))
    for profile in expected['profiles'].values():
        same_digest(profile['policy']['sha256'], sha(read(profile['policy']['path'])))
    for stage, row in expected['stages'].items():
        same_digest(plan['producer_sha256'][stage], sha(read('scripts/' + row['producer'])))
    selection = selection_input(plan['selection'])
    require(selection['source'].get('dirty') is False and canonical(selection['source']) == canonical(source),
            'runtime_selection_source_mismatch')
    require(set(selection['files']) == set(plan['selected_sha256']), 'runtime_selected_roles_changed')
    for role, item in selection['files'].items():
        same_digest(item['sha256'], plan['selected_sha256'][role])
    for role in BINARY_ROLES:
        same_digest(plan['selected_sha256'][role], plan['selected_sha256'][role])


def verify_capture(plan, stage, observation):
    """Recompute identities from the custodian's retained bytes and reviewed scopes."""
    require(stage in STAGES and observation['scope'] in plan['template']['stages'][stage]['scopes'],
            'unsupported_runtime_scope')
    scope = plan['template']['stages'][stage]['scopes'][observation['scope']]
    data = observation['inputs']
    require(set(data) == {'selection', 'policy', 'registry', 'profiles', 'configuration', 'classifiers', 'binaries', 'paths'},
            'runtime_input_roles_changed')
    paths = data['paths']
    require(set(paths) == {'selection', 'policy', 'registry', 'profiles', 'configuration', 'classifiers', 'binaries'},
            'runtime_path_roles_changed')
    selection = selection_input(data['selection'])
    require(selection['source'].get('dirty') is False and canonical(selection['source']) == canonical(plan['source'])
            and set(selection['files']) == set(plan['selected_sha256']),
            'runtime_selection_source_mismatch')
    for role, item in selection['files'].items():
        same_digest(item['sha256'], plan['selected_sha256'][role])
    require(unblob(data['policy']) == unblob(plan['policies'][scope['policy']]), 'runtime_policy_scope_mismatch')
    require(set(data['binaries']) == set(BINARY_ROLES) and set(data['classifiers']) == {'filesystem', 'git'},
            'runtime_binary_or_classifier_roles_changed')
    identities = {'policy': data['policy']['sha256'], 'selection': data['selection']['sha256'],
                  'configuration': None, 'registry': data['registry']['sha256'] if data['registry'] else None,
                  **data['binaries']}
    for role, digest in data['binaries'].items():
        same_digest(digest, plan['selected_sha256'][role])
    expected_tools = []
    require(set(data['profiles']) == {'filesystem', 'git'}, 'runtime_profile_roles_changed')
    for kind in ('filesystem', 'git'):
        item = data['profiles'][kind]
        require(set(item) == {'profile', 'registry', 'policy', 'installation', 'verified_runtime_sha256',
                             'verified_package_sha256', 'verified_libraries'}, 'runtime_profile_fields_changed')
        profile, receipt = json_input(item['profile']), json_input(item['installation'])
        expected = plan['template']['profiles'][kind]
        keys = {'format', 'workspace', 'runtimePath', 'runtimeSha256', 'packageRoot', 'packageTreeSha256',
                'bwrapPath', 'bwrapSha256', 'libraries'} | ({'git', 'gitLauncher'} if kind == 'git' else set())
        require(set(profile) in (keys, keys | {'workspaceIdentity'}), 'unsupported_runtime_profile_fields')
        require(profile['format'] == expected['format'] and receipt['profile'] == profile,
                'runtime_profile_template_mismatch')
        require(profile['packageRoot'] == str(Path(paths['profiles'][kind]) / 'package')
                and profile['bwrapPath'] == paths['binaries']['bwrap'], 'runtime_profile_path_mismatch')
        for label in ('profile', 'registry', 'policy'):
            same_digest(receipt[label + '_sha256'], item[label]['sha256'])
        same_digest(item['registry']['sha256'], expected['registry_sha256'])
        same_digest(item['policy']['sha256'], expected['policy']['sha256'])
        same_digest(profile['packageTreeSha256'], item['verified_package_sha256'])
        same_digest(profile['runtimeSha256'], item['verified_runtime_sha256'])
        require(item['verified_libraries'] == profile['libraries'], 'runtime_library_identity_mismatch')
        same_digest(profile['bwrapSha256'], data['binaries']['bwrap'])
        if kind == 'filesystem':
            same_digest(profile['runtimeSha256'], data['binaries']['node'])
            require(profile['runtimePath'] == paths['binaries']['node'], 'runtime_profile_path_mismatch')
        else:
            require(profile['runtimePath'] == str(Path(profile['packageRoot']) / 'python/bin/python3.11')
                    and profile['git']['path'] == paths['binaries']['git']
                    and profile['gitLauncher']['path'] == paths['binaries']['git_launcher'], 'runtime_profile_path_mismatch')
            same_digest(profile['git']['sha256'], data['binaries']['git'])
            same_digest(profile['gitLauncher']['sha256'], data['binaries']['git_launcher'])
        base = json_input(item['registry'])
        expected_tools.extend(base['tools'])
        same_digest(data['classifiers'][kind], plan['classifier_sha256'][scope['classifiers'][kind]])
        identities.update({kind + '_profile': item['profile']['sha256'],
                           kind + '_registry': item['registry']['sha256'],
                           kind + '_classifier': data['classifiers'][kind],
                           kind + '_policy': item['policy']['sha256'],
                           kind + '_installation': item['installation']['sha256'],
                           kind + '_runtime': item['verified_runtime_sha256'],
                           kind + '_package': item['verified_package_sha256'],
                           kind + '_libraries': sha(canonical(item['verified_libraries']))})
    registry_id = 'installed-development-pilot-v1' if scope['configuration'] == 'installed' else (
        'sou99-original-launcher' if scope['configuration'] == 'ask' else 'prepared-pilot-v1')
    if scope['configuration'] != 'selection':
        registry = json_input(data['registry'])
        require(registry == {'contract_version': 'sw-native/1', 'registry_id': registry_id, 'tools': expected_tools},
                'runtime_merged_registry_mismatch')
        config = json_input(data['configuration'])
        require(type(config.get('port')) is int and 0 < config['port'] < 65536 and config.get('enforce') is True,
                'runtime_configuration_mismatch')
        # Only paths/port supplied by the owned launcher vary; all policy,
        # liveness, approval and retention settings keep their reviewed values.
        native = config['native']
        require(config['policy'] == paths['policy'] and native['registry_path'] == paths['registry'],
                'runtime_configuration_path_mismatch')
        expected_native = {'registry_path': native['registry_path'], 'registry_sha256': data['registry']['sha256']}
        expected_config = {'port': config['port'], 'enforce': True, 'policy': config['policy'], 'native': expected_native}
        if scope['configuration'] == 'installed':
            expected_config['max_record_bytes'] = 1048576
        elif scope['configuration'] == 'ask':
            expected_native['liveness'] = {'default_lease_seconds': 4, 'max_lease_seconds': 60, 'maintenance_interval_ms': 100}
        else:
            expected_native['liveness'] = {'default_lease_seconds': 4, 'max_lease_seconds': 4, 'maintenance_interval_ms': 250}
            expected_config.update(bind='127.0.0.1', audit_retention={
                'version': 1, 'segment_size_bytes': 65536, 'segment_count': 4,
                'total_disk_bytes': 512000, 'max_record_bytes': 65536,
                'directory': config['audit_retention']['directory']})
        if scope['approval_ttl_seconds'] is not None:
            expected_native['approval'] = {'ttl_seconds': scope['approval_ttl_seconds']}
        require(canonical(config) == canonical(expected_config), 'runtime_configuration_scope_mismatch')
        identities['configuration'] = data['configuration']['sha256']
    else:
        require(data['configuration'] is None and data['registry'] is None,
                'selection_cannot_claim_daemon_configuration')
    return identities


def verify_stage(plan, stage, witness, report, original_sha, cleanup):
    require(set(witness) == {'format', 'stage', 'source', 'plan_sha256', 'report_sha256', 'cleanup', 'observations'},
            'runtime_custody_fields_changed')
    require(witness.get('format') == 'sw-pilot-runtime-custody/1' and witness.get('stage') == stage
            and witness.get('source') == plan['source'] and witness.get('plan_sha256') == sha(canonical(plan)),
            'runtime_custody_stage_or_plan_mismatch')
    same_digest(witness['report_sha256'], original_sha)
    require(witness['cleanup'] == cleanup and cleanup.get('all_stopped') is True and cleanup.get('remaining') == [],
            'runtime_custody_cleanup_unconfirmed')
    expected = set(plan['template']['stages'][stage]['scopes'])
    rows = witness['observations']
    require(len(rows) == len(expected) and {row['scope'] for row in rows} == expected,
            'runtime_scope_missing_or_duplicate')
    claims = report.get('runtime_identity')
    require(type(claims) is dict and set(claims) == {'format', 'stage', 'plan_sha256', 'claims'}
            and claims['format'] == 'sw-pilot-runtime-claims/1' and claims['stage'] == stage
            and claims['plan_sha256'] == witness['plan_sha256'], 'runtime_claims_missing_or_unsupported')
    expected_claims = []
    identities = []
    for row in rows:
        require(set(row) == {'scope', 'inputs', 'complete', 'sha256'}, 'runtime_observation_fields_changed')
        require(row['complete'] is True, 'runtime_input_lifetime_unconfirmed')
        digest = sha(canonical({'scope': row['scope'], 'inputs': row['inputs']}))
        same_digest(row['sha256'], digest)
        identities.append({'scope': row['scope'], 'identities': verify_capture(plan, stage, row)})
        expected_claims.append({'scope': row['scope'], 'sha256': digest})
    require(claims['claims'] == expected_claims, 'runtime_claims_conflict_with_custody')
    selected = report.get('selected_sha256', report.get('identity', {}).get('selected', {}))
    for role in plan['selected_sha256']:
        if role in selected:
            same_digest(selected[role], plan['selected_sha256'][role])
    profiles = report.get('profiles', report.get('identity', {}).get('profiles', {}))
    if stage == 'installed':
        profiles = next(row for row in report['cases'] if row['id'] == 'exact-installed-inputs').get('evidence', {}).get('profiles', {})
    for binding in identities:
        policy = report.get('policy_sha256', report.get('identity', {}).get('policy_sha256'))
        if policy is not None:
            same_digest(policy, binding['identities']['policy'])
        registry = report.get('registry_sha256', report.get('identity', {}).get('registry_sha256'))
        if registry is not None and stage != 'ask' and binding['identities']['configuration'] is not None:
            scope_row = next(row for row in rows if row['scope'] == binding['scope'])
            same_digest(registry, scope_row['inputs']['registry']['sha256'])
        for kind in ('filesystem', 'git'):
            old = profiles.get(kind, {}).get('profile_sha256', report.get('profile_sha256', {}).get(kind))
            if old is not None:
                same_digest(old, binding['identities'][kind + '_profile'])
            classifier = report.get('classifier_sha256', profiles.get(kind, {}).get('classifier_sha256'))
            if classifier is not None:
                same_digest(classifier, binding['identities'][kind + '_classifier'])
        if stage == 'ask':
            name = binding['scope'].split(':')
            if len(name) == 2:
                case = next(row for row in report['cases'] if row['profile'] == name[0] and row['case'] == name[1])
                same_digest(case['policy_sha256'], binding['identities']['policy'])
                same_digest(case['configuration_sha256'], binding['identities']['configuration'])
    return identities


def _message(connection):
    raw = bytearray()
    while len(raw) <= MAX_JSON:
        block = connection.recv(min(65536, MAX_JSON + 1 - len(raw)))
        if not block:
            return parse(bytes(raw))
        raw.extend(block)
    raise ValueError('identity_request_limit')


def custody_locked(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return call


class Custodian:
    """Independent coordinator-owned reader, with Linux kernel peer PID binding.

    This is private harness custody, not a signature, admission or hostile-code
    execution boundary. The explicit archive digest remains the operator's trust
    root. Target source is read-only and all measurement stays inside its enclosure.
    """
    def __init__(self, plan, address, verifier):
        self.lock = threading.RLock()
        self.plan, self.address, self.verifier = plan, Path(address), verifier
        self.plan_sha256 = sha(canonical(plan))
        self.stage = self.pid = None
        self.rows, self.opened, self.active = [], [], {}
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(address))
        os.chmod(address, 0o600)
        self.listener.listen(1)
        self.listener.settimeout(.2)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @custody_locked
    def begin(self, stage):
        require(not self.opened and not self.active and stage in STAGES, 'identity_stage_still_active')
        self.stage, self.pid, self.rows = stage, None, []

    def read(self, path, *, asset=False):
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts and len(str(path)) <= 4096,
                'identity_path_invalid')
        # Resolve aliases once; the descriptor and its original inode are used
        # for the entire capture lifetime, including normal owned cleanup/unlink.
        fd = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and (asset or before.st_size <= 48000),
                    'identity_input_not_bounded_file')
            if asset:
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    raw = hashlib.file_digest(stream, 'sha256').hexdigest()
            else:
                raw = os.read(fd, 48001)
            after = os.fstat(fd)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    and (asset or len(raw) == before.st_size), 'identity_input_changed_during_read')
            self.opened.append((fd, before, raw, path))
            return raw if asset else blob(raw)
        except BaseException:
            os.close(fd)
            raise

    @custody_locked
    def finish_capture(self, scope):
        require(scope in self.active, 'identity_capture_not_active')
        files = self.active.pop(scope)
        row = next(row for row in self.rows if row['scope'] == scope)
        try:
            for fd, before, raw, path in files:
                after = os.fstat(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                if type(raw) is str:
                    with os.fdopen(os.dup(fd), 'rb') as stream:
                        unchanged = hashlib.file_digest(stream, 'sha256').hexdigest() == raw
                else:
                    unchanged = os.read(fd, 48001) == raw
                require(unchanged and
                        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                        'identity_input_changed_during_scope')
                try:
                    current = path.stat()
                    require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                            'identity_input_changed_during_scope')
                except FileNotFoundError:
                    require(after.st_nlink == 0, 'identity_input_changed_during_scope')
                # Normal owned cleanup may unlink a config. Any other in-place
                # change, including restoring old bytes/timestamps, stays a failure.
                require(after.st_nlink == 0 or before.st_ctime_ns == after.st_ctime_ns,
                        'identity_input_changed_during_scope')
            row['complete'] = True
        finally:
            for fd, _, _, _ in files:
                os.close(fd)

    @custody_locked
    def capture(self, request):
        require(set(request) == {'operation', 'stage', 'scope', 'paths'} and not self.opened,
                'identity_request_fields_or_lifetime')
        require(request['stage'] == self.stage and not self.stopping.is_set(), 'identity_cross_stage_request')
        scope = request['scope']
        require(scope in self.plan['template']['stages'][self.stage]['scopes']
                and all(row['scope'] != scope for row in self.rows), 'identity_scope_unknown_or_duplicate')
        paths = request['paths']
        require(set(paths) == {'selection', 'policy', 'registry', 'configuration', 'profiles', 'classifiers', 'binaries'},
                'identity_request_roles_changed')
        data = {'paths': paths, 'selection': self.read(paths['selection']), 'policy': self.read(paths['policy']),
                'registry': self.read(paths['registry']) if paths['registry'] else None,
                'configuration': self.read(paths['configuration']) if paths['configuration'] else None,
                'profiles': {}, 'classifiers': {}, 'binaries': {}}
        require(set(paths['binaries']) == set(BINARY_ROLES) and
                set(paths['classifiers']) == set(paths['profiles']) == {'filesystem', 'git'},
                'identity_request_roles_changed')
        for role, path in paths['binaries'].items():
            data['binaries'][role] = self.read(path, asset=True)
        for kind in ('filesystem', 'git'):
            directory = Path(paths['profiles'][kind])
            item = {name: self.read(directory / (name + ('.yaml' if name == 'policy' else '.json')))
                    for name in ('profile', 'registry', 'policy', 'installation')}
            profile = json_input(item['profile'])
            # Reuse the current production generation verifier, including actual
            # package tree, pinned registries, native runtime and library bytes.
            verified = self.verifier(kind, directory, {k: Path(v) for k, v in paths['binaries'].items()},
                                     Path(profile['workspace']))
            item.update(verified_runtime_sha256=self.read(profile['runtimePath'], asset=True),
                        verified_package_sha256=verified['package_tree_sha256'],
                        verified_libraries=[{'path': p['path'], 'sha256': self.read(p['path'], asset=True)}
                                            for p in profile['libraries']])
            data['profiles'][kind] = item
            data['classifiers'][kind] = self.read(paths['classifiers'][kind], asset=True)
        row = {'scope': scope, 'inputs': data, 'complete': False}
        verify_capture(self.plan, self.stage, row)
        row['sha256'] = sha(canonical({'scope': scope, 'inputs': data}))
        self.rows.append(row)
        self.active[scope], self.opened = self.opened, []
        return {'scope': scope, 'sha256': row['sha256']}

    def serve(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(30)
                try:
                    require(hasattr(socket, 'SO_PEERCRED'), 'identity_custody_requires_linux_peer_credentials')
                    pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    require(pid == self.pid and uid == os.getuid(), 'identity_foreign_producer')
                    request = _message(connection)
                    with self.lock:
                        # Recheck after receiving: the producer can exit while a
                        # packet is in flight and the coordinator can advance.
                        require(pid == self.pid and not self.stopping.is_set(), 'identity_foreign_producer')
                        require(request.get('stage') == self.stage, 'identity_cross_stage_request')
                        if request.get('operation') == 'capture':
                            claim = self.capture(request)
                        else:
                            require(set(request) == {'operation', 'stage', 'scope'} and request['operation'] == 'finish',
                                    'identity_operation_unsupported')
                            self.finish_capture(request['scope'])
                            claim = None
                    response = {'status': 'captured', 'plan_sha256': self.plan_sha256, 'claim': claim}
                except (OSError, ValueError, KeyError, TypeError) as error:
                    code = str(error)
                    response = {'status': 'failed', 'reason': code if code.replace('_', '').isalnum()
                                and len(code) <= 120 else 'identity_capture_rejected'}
                try:
                    connection.sendall(canonical(response))
                except OSError:
                    pass

    @custody_locked
    def evidence(self, report_sha256, cleanup):
        # A killed/incomplete producer cannot complete its own custody lifetime.
        # Release descriptors so unrelated subsequent stages may still execute.
        self.pid = None
        self.abandon()
        return {'format': 'sw-pilot-runtime-custody/1', 'source': self.plan['source'],
                'stage': self.stage, 'plan_sha256': self.plan_sha256,
                'observations': copy.deepcopy(self.rows), 'report_sha256': report_sha256,
                'cleanup': copy.deepcopy(cleanup)}

    @custody_locked
    def abandon(self):
        for files in [self.opened, *self.active.values()]:
            for fd, _, _, _ in files:
                os.close(fd)
        self.opened, self.active = [], {}

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)
        self.abandon()
        self.address.unlink(missing_ok=True)


_ACTIVE = set()


def _request(value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect(os.environ['SOU_PILOT_IDENTITY_SOCKET'])
        connection.sendall(canonical(value))
        connection.shutdown(socket.SHUT_WR)
        response = _message(connection)
    require(response.get('status') == 'captured', response.get('reason', 'identity_custody_unavailable'))
    return response


def finish(scope=None):
    for name in list(_ACTIVE) if scope is None else [scope] if scope in _ACTIVE else []:
        _request({'operation': 'finish', 'stage': os.environ['SOU_PILOT_IDENTITY_STAGE'], 'scope': name})
        _ACTIVE.remove(name)


def capture(report, scope, paths, profiles, classifiers, policy, registry=None, configuration=None, selection=None):
    """Opt-in producer link. Only the coordinator can supply custody authority."""
    if 'SOU_PILOT_IDENTITY_SOCKET' not in os.environ:
        return
    stage = os.environ['SOU_PILOT_IDENTITY_STAGE']
    request = {'operation': 'capture', 'stage': stage, 'scope': scope, 'paths': {
        'selection': str(selection or os.environ['SOU_PILOT_IDENTITY_SELECTION']),
        'policy': str(policy), 'registry': str(registry) if registry else None,
        'configuration': str(configuration) if configuration else None,
        'binaries': {name: str(paths[name]) for name in BINARY_ROLES},
        'profiles': {name: str(path) for name, path in profiles.items()},
        'classifiers': {name: str(path) for name, path in classifiers.items()}}}
    response = _request(request)
    _ACTIVE.add(scope)
    record = report.setdefault('runtime_identity', {'format': 'sw-pilot-runtime-claims/1',
        'stage': stage, 'plan_sha256': response['plan_sha256'], 'claims': []})
    require(record['stage'] == stage and record['plan_sha256'] == response['plan_sha256'],
            'identity_producer_plan_changed')
    record['claims'].append(response['claim'])


def capture_prepared(report, scope, selection, home=None):
    if 'SOU_PILOT_IDENTITY_SOCKET' not in os.environ:
        return
    value = parse(Path(selection).read_bytes())
    paths = {name: Path(item['path']) for name, item in value['files'].items()}
    profiles = {name: Path(item['profile']['path']).parent for name, item in value['prepared_profiles'].items()}
    capture(report, scope, paths, profiles, {kind: paths['git_classifier'] for kind in profiles},
            paths['policy'], home / 'registry.json' if home else None,
            home / 'config.yaml' if home else None, selection)
