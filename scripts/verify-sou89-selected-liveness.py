#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-89 selected production filesystem and Git native liveness acceptance.

Executes required production acceptance using the accepted selected profiles:
1. Node @modelcontextprotocol/server-filesystem
2. Python mcp_server_git with pinned git and agentfw-git-sandbox

Requires Linux x86_64 or aarch64 with Bubblewrap (bwrap), systemd delegation,
and Linux /proc. Fails immediately on missing prerequisites; never skips or
falls back to generic mocks.
"""
from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
import urllib.error

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
FORMAT = 'sw-mcp/selected-liveness-acceptance/1'
LIVENESS_CONTRACT = 'sw-native-liveness/1'
NATIVE_CONTRACT = 'sw-native/1'

# Load accepted SOU-86 supervision and resource helpers
def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

try:
    SOU86 = load('sou86_crash_supervision', 'verify-sou86-crash-supervision.py')
    RESOURCE = SOU86.RESOURCE
    GIT = SOU86.GIT
    BASE = SOU86.BASE
    require = SOU86.require
    sha = SOU86.sha
    digest = SOU86.digest
    write = SOU86.write
    ProtectedClient = SOU86.ProtectedClient
    GitRig = SOU86.GitRig
    observe_crash = SOU86.observe_crash
    prepare_delegation = SOU86.prepare_delegation
    OWNER_FORMAT = SOU86.OWNER_FORMAT
    ACCEPTANCE_MILLIS = SOU86.ACCEPTANCE_MILLIS
except Exception as _err:
    SOU86 = None
    OWNER_FORMAT = 'sw-mcp/linux-crash-owner/1'
    ACCEPTANCE_MILLIS = 10000


class SelectedLivenessClient(ProtectedClient if SOU86 else object):
    """Extends ProtectedClient with opt-in native liveness support and explicit session tracking."""
    def __init__(self, rig, label: str, lease_secs: int = 4, session_id: str | None = None,
                 host_session: str | None = None, child_authority: str | None = None, **kwargs):
        self.lease_secs = lease_secs
        self.session_id = session_id or f"sel-{label}-{int(time.time() * 1000)}"
        old_env = getattr(rig, 'env', {})
        try:
            rig.env = dict(old_env)
            rig.env['AGENTFW_NATIVE_LIVENESS'] = 'true'
            rig.env['AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS'] = str(lease_secs)
            rig.env['AGENTFW_MCP_SESSION'] = self.session_id
            if host_session and child_authority:
                rig.env['AGENTFW_HOST_SESSION'] = host_session
                rig.env['AGENTFW_CHILD_AUTHORITY'] = child_authority
            super().__init__(rig, label, **kwargs)
        finally:
            rig.env = old_env

    def _build_env(self):
        return {
            'AGENTFW_NATIVE_LIVENESS': 'true',
            'AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS': str(self.lease_secs),
            'AGENTFW_MCP_SESSION': self.session_id,
        }


class SelectedLivenessRig(RESOURCE.Rig if SOU86 else object):
    """Filesystem rig with daemon native.liveness configuration."""
    def __init__(self, args, private: Path, delegation, lease_secs: int = 4, maint_interval_ms: int = 100):
        self.private, self.binary, self.node, self.delegation = (
            private, args.agentfw.resolve(), args.node.resolve(), delegation
        )
        self.clients = []
        self.home, self.workspace = private / 'home', private / 'workspace'
        self.home.mkdir(mode=0o700, exist_ok=True)
        self.workspace.mkdir(mode=0o700, exist_ok=True)
        (self.workspace / 'notes.txt').write_text(RESOURCE.TEXT)
        for number in range(9):
            fifo_path = self.workspace / f'blocked-{number}.fifo'
            if not fifo_path.exists():
                os.mkfifo(fifo_path, 0o600)
        self.env = BASE.environment(self.home)
        install = private / 'original'
        BASE.INSTALL.install(install, self.workspace, self.node, args.bwrap.resolve(), args.npm.resolve())
        self.original = json.loads((install / 'profile.json').read_text())
        self.installation = json.loads((install / 'installation.json').read_text())
        self.fixture = copy.deepcopy(self.original)
        package = private / 'owned-adversary'
        entry = package / 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'
        entry.parent.mkdir(mode=0o700, parents=True)
        entry.write_text(RESOURCE.FIXTURE)
        for source, target in [('upstream-initialize.json', 'initialize.json'), ('upstream-tools-list.json', 'manifest.json')]:
            (package / target).write_bytes((BASE.INSTALL.ASSETS / source).read_bytes())
        self.fixture.update(packageRoot=str(package), packageTreeSha256=BASE.INSTALL.tree_sha(package))
        result = subprocess.run([str(self.binary), 'install'], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        require(result.returncode == 0, 'private_agent_install_failed')
        self.port = BASE.DEMO.free_port()
        self.config = {
            'port': self.port,
            'enforce': True,
            'policy': str(install / 'policy.yaml'),
            'native': {
                'registry_path': str(install / 'registry.json'),
                'registry_sha256': sha(install / 'registry.json'),
                'liveness': {
                    'default_lease_seconds': lease_secs,
                    'max_lease_seconds': 60,
                    'maintenance_interval_ms': maint_interval_ms,
                },
            },
        }
        write(self.home / '.agentfw/config.yaml', self.config)
        self.daemon = subprocess.Popen([str(self.binary), 'serve'], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.daemon_witness = BASE.ProcessWitness(self.daemon.pid)
        self.daemon_stdout, self.daemon_stderr = RESOURCE.Capture(self.daemon.stdout), RESOURCE.Capture(self.daemon.stderr)
        if not BASE.DEMO.wait_healthy(self.port, self.daemon):
            BASE.DEMO.stop(self.daemon)
            self.daemon_witness.finish()
            self.daemon_stdout.finish()
            self.daemon_stderr.finish()
            raise ValueError('owned_daemon_unavailable')

    @property
    def native_token(self) -> str:
        token_path = self.home / '.agentfw/native-token'
        if not token_path.is_file():
            token_path = self.home / 'native-token'
        return token_path.read_text().strip()

    @property
    def liveness_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/liveness/v1'

    @property
    def instance_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/v1/instance'

    @property
    def native_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/v1'


class SelectedLivenessGitRig(GitRig if SOU86 else object):
    """Git rig with daemon native.liveness configuration."""
    def __init__(self, args, private: Path, delegation, lease_secs: int = 4, maint_interval_ms: int = 100):
        self.private, self.binary, self.git, self.delegation = (
            private, args.agentfw.resolve(), args.git.resolve(), delegation
        )
        self.clients, self.kind = [], 'git'
        self.home, self.workspace = private / 'home', private / 'workspace'
        self.home.mkdir(mode=0o700, exist_ok=True)
        self.env = BASE.environment(self.home)
        self.env.update(GIT_PYTHON_GIT_EXECUTABLE=str(self.git), GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_CONFIG_NOSYSTEM='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
        GIT.prepare_repo(self.workspace, self.git, self.env)
        install = private / 'original'
        GIT.INSTALL.install(install, self.workspace, self.git, args.git_sha256,
                            args.bwrap.resolve(), args.git_launcher.resolve())
        self.original = json.loads((install / 'profile.json').read_text())
        self.installation = json.loads((install / 'installation.json').read_text())
        self.fixture = copy.deepcopy(self.original)
        package = private / 'git-adversary'
        package.mkdir(mode=0o700, exist_ok=True)
        for source, target in [('upstream-initialize.json', 'initialize.json'), ('upstream-tools-list.json', 'manifest.json')]:
            (package / target).write_bytes((GIT.INSTALL.ASSETS / source).read_bytes())
        self.fixture.update(packageRoot=str(package), packageTreeSha256=BASE.INSTALL.tree_sha(package))
        result = subprocess.run([str(self.binary), 'install'], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        require(result.returncode == 0, 'private_git_agent_install_failed')
        self.port = BASE.DEMO.free_port()
        self.config = {
            'port': self.port,
            'enforce': True,
            'policy': str(install / 'policy.yaml'),
            'native': {
                'registry_path': str(install / 'registry.json'),
                'registry_sha256': sha(install / 'registry.json'),
                'liveness': {
                    'default_lease_seconds': lease_secs,
                    'max_lease_seconds': 60,
                    'maintenance_interval_ms': maint_interval_ms,
                },
            },
        }
        write(self.home / '.agentfw/config.yaml', self.config)
        self.daemon = subprocess.Popen([str(self.binary), 'serve'], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.daemon_witness = BASE.ProcessWitness(self.daemon.pid)
        self.daemon_stdout, self.daemon_stderr = RESOURCE.Capture(self.daemon.stdout), RESOURCE.Capture(self.daemon.stderr)
        if not BASE.DEMO.wait_healthy(self.port, self.daemon):
            BASE.DEMO.stop(self.daemon)
            self.daemon_witness.finish()
            self.daemon_stdout.finish()
            self.daemon_stderr.finish()
            raise ValueError('owned_git_daemon_unavailable')

    @property
    def native_token(self) -> str:
        token_path = self.home / '.agentfw/native-token'
        if not token_path.is_file():
            token_path = self.home / 'native-token'
        return token_path.read_text().strip()

    @property
    def liveness_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/liveness/v1'

    @property
    def instance_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/v1/instance'

    @property
    def native_url(self) -> str:
        return f'http://127.0.0.1:{self.port}/native/v1'


def read_raw_audit(rig) -> list[dict]:
    """Reads unprojected audit records from the daemon's audit.jsonl log."""
    path = rig.home / '.agentfw/audit.jsonl'
    if not path.is_file():
        path = rig.home / 'audit.jsonl'
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def http_post(url: str, token: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
    req_headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers=req_headers,
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as err:
        try:
            body = json.loads(err.read().decode('utf-8'))
        except Exception:
            body = {'error': err.reason}
        return err.code, body


def http_get(url: str, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        headers={'Authorization': f'Bearer {token}'},
        method='GET',
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as err:
        try:
            body = json.loads(err.read().decode('utf-8'))
        except Exception:
            body = {'error': err.reason}
        return err.code, body


def useful(client, expected_hash=None) -> str:
    """Performs useful work against accepted selected filesystem/Git server.

    Validates:
    1. Response ID strictly matches the requested ID (detecting protocol skew).
    2. Response payload contains genuine expected domain results.
    3. Returns stable semantic digest of the tool result content across incrementing IDs.
    """
    identifier, client.next_id = client.next_id, client.next_id + 1
    if client.kind == 'git':
        req = GIT.call(identifier, repo=client.rig.workspace if client.direct else '/workspace')
        response, raw = client.exchange(req)
        require(isinstance(response, dict) and response.get('id') == identifier, 'git_useful_response_id_mismatch')
        require('SOU-68 synthetic initial commit' in GIT.text(response), 'original_git_useful_result_changed')
    else:
        req = RESOURCE.call(identifier, str(client.rig.workspace / 'notes.txt') if client.direct else '/workspace/notes.txt')
        response, raw = client.exchange(req)
        require(isinstance(response, dict) and response.get('id') == identifier, 'filesystem_useful_response_id_mismatch')
        require(BASE.result_text(response) == RESOURCE.TEXT, 'original_filesystem_useful_result_changed')

    result_val = response.get('result', {})
    semantic_bytes = json.dumps(result_val, sort_keys=True, separators=(',', ':')).encode('utf-8')
    semantic_hash = digest(semantic_bytes)
    if expected_hash is not None:
        require(semantic_hash == expected_hash, f'{client.kind}_useful_work_diverged_across_renewal')
    return semantic_hash


# --- Production Grader Functions (tested directly by unit and observer controls) ---

def grade_crash_observation(crash_row: dict, kind: str, budget: dict | None = None) -> None:
    require(isinstance(crash_row, dict), f'{kind}_missing_crash_row')
    owner = crash_row.get('owner')
    require(isinstance(owner, dict), f'{kind}_owner_identity_missing')
    target = crash_row.get('target')
    require(isinstance(target, dict), f'{kind}_target_witness_missing')
    client_info = crash_row.get('client')
    require(isinstance(client_info, dict), f'{kind}_missing_client_in_crash_row')
    require('acceptance_fallback_used' in crash_row, f'{kind}_acceptance_fallback_used_field_missing')
    require('forced_cleanup' in client_info, f'{kind}_forced_cleanup_field_missing')

    # Reuse the accepted SOU-86 grade_crash contract for process observation, owner identity, and monotonic bounds
    if SOU86 is not None:
        try:
            SOU86.grade_crash(crash_row)
        except (ValueError, KeyError, AttributeError) as ex:
            raise ValueError(f'{kind}_{ex}') from ex

    # Additional SOU-89 validations: target PID, client close, and KernelObserver
    require(isinstance(target.get('pid'), int) and target['pid'] > 0, f'{kind}_target_witness_missing')
    require(client_info['forced_cleanup'] is False, f'{kind}_forced_cleanup_used')

    sig_num = signal.SIGKILL if crash_row.get('signal') == 'SIGKILL' else (signal.SIGSTOP if crash_row.get('signal') == 'SIGSTOP' else None)
    has_kernel = client_info.get('kernel') is not None or crash_row.get('budgeted')
    grade_client_close(client_info, f'{kind}_client', expect_failure=True, expected_signal=sig_num,
                       require_kernel=bool(has_kernel), budget=budget)


def grade_liveness_active(lstatus: dict, expected_session_id: str, kind: str, expected_instance_id: str | None = None) -> None:
    require(isinstance(lstatus, dict), f'{kind}_missing_lstatus')
    require(lstatus.get('contract_version') == LIVENESS_CONTRACT, f'{kind}_liveness_contract_mismatch')
    require(lstatus.get('status') == 'active', f'{kind}_liveness_not_active')
    require(lstatus.get('session_id') == expected_session_id, f'{kind}_session_id_mismatch')
    if expected_instance_id is not None:
        require(lstatus.get('instance_id') == expected_instance_id, f'{kind}_instance_id_mismatch')
    require(isinstance(lstatus.get('lease_seconds'), int) and lstatus['lease_seconds'] > 0, f'{kind}_invalid_lease_seconds')
    require(isinstance(lstatus.get('expires_in_ms'), int) and lstatus['expires_in_ms'] > 0, f'{kind}_expired_lease')


def grade_liveness_renewal(lstatus: dict, expected_session_id: str, min_seq: int, kind: str, expected_instance_id: str | None = None) -> None:
    grade_liveness_active(lstatus, expected_session_id, kind, expected_instance_id=expected_instance_id)
    require(isinstance(lstatus.get('lease_seq'), int) and lstatus['lease_seq'] >= min_seq, f'{kind}_lease_did_not_renew')


def grade_autonomous_reclamation(status_code: int, audit_rows: list[dict], epoch: str, kind: str) -> None:
    require(status_code == 404, f'{kind}_session_not_reclaimed_autonomously')
    require(any(r.get('event') == 'native_liveness_enrolled' and r.get('session') == epoch for r in audit_rows),
            f'{kind}_enrollment_not_audited')
    require(any(r.get('event') == 'native_session_expired' and r.get('session') == epoch for r in audit_rows),
            f'{kind}_autonomous_expiry_not_audited')


DEFAULT_BUDGET = {
    'memoryMaxBytes': 512 * 1024 * 1024,
    'pidsMax': 64,
    'cpuQuotaMicros': 100000,
    'wallMillis': 120000,
}


def grade_client_close(close_res: dict, kind: str, expect_failure: bool = False,
                       expected_signal: int | None = None, require_kernel: bool = False,
                       budget: dict | None = None) -> None:
    require(isinstance(close_res, dict), f'{kind}_missing_close_result')
    require('forced_cleanup' in close_res, f'{kind}_forced_cleanup_field_missing')
    require(close_res['forced_cleanup'] is False, f'{kind}_forced_cleanup_used')
    proc_info = close_res.get('process')
    require(isinstance(proc_info, dict), f'{kind}_missing_process_info')
    require(proc_info.get('all_stopped') is True, f'{kind}_processes_not_all_stopped')
    require(proc_info.get('remaining', []) == [], f'{kind}_processes_remaining')
    exit_code = close_res.get('exit_code')
    if expected_signal is not None:
        require(exit_code in (-expected_signal, 128 + expected_signal), f'{kind}_unexpected_signal_exit_{exit_code}')
    elif expect_failure:
        require(exit_code != 0, f'{kind}_expected_failure_but_exit_code_zero')
    else:
        require(exit_code == 0, f'{kind}_exit_code_nonzero')

    if require_kernel or close_res.get('kernel') is not None or close_res.get('budgeted'):
        k = close_res.get('kernel')
        require(isinstance(k, dict), f'{kind}_missing_kernel_evidence')
        require(k.get('thread_stopped') is True, f'{kind}_kernel_thread_not_stopped')
        require(k.get('error') is None, f'{kind}_kernel_observer_error_{k.get("error")}')
        require(k.get('leaf_removed') is True, f'{kind}_kernel_leaf_not_removed')
        require(k.get('remaining') == [], f'{kind}_kernel_processes_remaining')
        require(k.get('samples', 0) > 0, f'{kind}_kernel_samples_zero')
        require(bool(k.get('members')), f'{kind}_kernel_members_empty')

        shutdown = k.get('shutdown_read')
        if shutdown is not None:
            require(isinstance(shutdown, dict), f'{kind}_invalid_shutdown_read')
            require(shutdown.get('status') == 'resolved' and shutdown.get('resolved_within_deadline') is True,
                    f'{kind}_kernel_shutdown_uncertainty_unresolved')
            if 'errno' in shutdown:
                require(shutdown['errno'] in (errno.ENOENT, errno.ENODEV), f'{kind}_kernel_shutdown_unexpected_errno')

        if close_res.get('budgeted') or k.get('first') is not None:
            requested = budget or close_res.get('budget') or DEFAULT_BUDGET
            first = k.get('first')
            require(isinstance(first, dict), f'{kind}_effective_kernel_limits_missing')
            require(first.get('memory.max') == requested['memoryMaxBytes'], f'{kind}_effective_memory_max_mismatch')
            require(first.get('memory.swap.max') == 0, f'{kind}_effective_swap_max_mismatch')
            require(first.get('memory.oom.group') == 1, f'{kind}_effective_oom_group_mismatch')
            require(first.get('pids.max') == requested['pidsMax'], f'{kind}_effective_pids_max_mismatch')
            require(first.get('cpu.max') == [requested['cpuQuotaMicros'], 100000], f'{kind}_effective_cpu_max_mismatch')
            require(first.get('cpu.max.burst', 0) == 0, f'{kind}_unexpected_cpu_burst_allowance')

            require(0 < k.get('tasks_peak', 0) <= requested['pidsMax'], f'{kind}_kernel_task_bound_failed')
            require(0 < k.get('memory_peak_bytes', 0) <= requested['memoryMaxBytes'] + 32 * 1024 * 1024,
                    f'{kind}_owned_memory_overshoot_exceeded')


def grade_rig_cleanup_result(cleanup_res: dict, kind: str) -> None:
    require(cleanup_res is not None and isinstance(cleanup_res, dict), f'{kind}_cleanup_result_missing')
    require(cleanup_res.get('error') is None, f'{kind}_cleanup_error_{cleanup_res.get("error")}')
    daemon_proc = cleanup_res.get('daemon_process')
    require(isinstance(daemon_proc, dict), f'{kind}_daemon_process_witness_missing')
    require(daemon_proc.get('all_stopped') is True, f'{kind}_daemon_not_all_stopped')
    require(daemon_proc.get('remaining') == [], f'{kind}_daemon_process_remaining')
    clients = cleanup_res.get('clients')
    require(isinstance(clients, list), f'{kind}_clients_witness_missing')
    for i, client in enumerate(clients):
        require(isinstance(client, dict), f'{kind}_client_{i}_witness_invalid')
        require(client.get('forced_cleanup') is False, f'{kind}_client_{i}_forced_cleanup')
        proc = client.get('process')
        require(isinstance(proc, dict), f'{kind}_client_{i}_process_witness_missing')
        require(proc.get('all_stopped') is True, f'{kind}_client_{i}_process_not_all_stopped')
        require(proc.get('remaining') == [], f'{kind}_client_{i}_process_remaining')
        if client.get('kernel') is not None or client.get('budgeted'):
            k = client.get('kernel')
            require(isinstance(k, dict), f'{kind}_client_{i}_kernel_witness_invalid')
            require(k.get('thread_stopped') is True, f'{kind}_client_{i}_kernel_thread_not_stopped')
            require(k.get('error') is None, f'{kind}_client_{i}_kernel_error_{k.get("error")}')
            require(k.get('leaf_removed') is True, f'{kind}_client_{i}_kernel_leaf_not_removed')
            require(k.get('remaining') == [], f'{kind}_client_{i}_kernel_remaining')


def grade_restart_risk(checkpoint_d1: dict, checkpoint_d2: dict, d2_inst: dict,
                       post_end_inst: dict, host_session: str,
                       untrusted_host: str = 'untrusted.example.test') -> None:
    for label, cp in (('d1', checkpoint_d1), ('d2', checkpoint_d2)):
        require(isinstance(cp, dict), f'{label}_checkpoint_missing')
        require(host_session in cp.get('scoped_hosts', []), f'{label}_checkpoint_missing_scoped_host')
        prov_sessions = cp.get('provenance', {}).get('sessions', [])
        risk_sess = next((s for s in prov_sessions if s.get('session') == host_session), None)
        require(risk_sess is not None, f'{label}_checkpoint_missing_risk_session')
        require(risk_sess.get('incomplete') is True, f'{label}_checkpoint_session_incomplete_false')
        fps = risk_sess.get('fingerprints', [])
        require(isinstance(fps, list) and len(fps) > 0, f'{label}_checkpoint_fingerprints_empty')
        require(any(isinstance(fp, list) and len(fp) >= 2 and fp[1].get('source', {}).get('host') == untrusted_host for fp in fps),
                f'{label}_checkpoint_missing_expected_untrusted_host')

    prov = d2_inst.get('provenance', {})
    require(prov.get('accounting_revision') == 'sw-provenance-storage/1', 'd2_provenance_accounting_missing')
    usage = prov.get('usage', {})

    cp_sessions = checkpoint_d2.get('provenance', {}).get('sessions', [])
    exp_sessions = len(cp_sessions)
    exp_incomplete = sum(1 for s in cp_sessions if s.get('incomplete'))
    exp_fps = sum(len(s.get('fingerprints', [])) for s in cp_sessions)
    exp_literals = sum(len(s.get('literals', [])) for s in cp_sessions)

    require(usage.get('sessions') == exp_sessions, f'd2_provenance_sessions_mismatch_{usage.get("sessions")}_expected_{exp_sessions}')
    require(usage.get('incomplete_sessions') == exp_incomplete, f'd2_provenance_incomplete_sessions_mismatch_{usage.get("incomplete_sessions")}_expected_{exp_incomplete}')
    require(usage.get('fingerprints') == exp_fps, f'd2_provenance_fingerprints_mismatch_{usage.get("fingerprints")}_expected_{exp_fps}')
    require(usage.get('literals') == exp_literals, f'd2_provenance_literals_mismatch_{usage.get("literals")}_expected_{exp_literals}')
    require(isinstance(usage.get('retained_bytes'), int) and usage['retained_bytes'] > 0, 'd2_provenance_retained_bytes_not_positive')
    require(usage['retained_bytes'] >= usage.get('max_session_retained_bytes', 0), 'd2_provenance_retained_bytes_under_max_session')

    usage_end = post_end_inst.get('provenance', {}).get('usage', {})
    require(usage_end.get('sessions') == exp_sessions, 'risk_sessions_laundered_by_session_end')
    require(usage_end.get('incomplete_sessions') == exp_incomplete, 'risk_incomplete_floor_laundered_by_session_end')
    require(usage_end.get('fingerprints') == exp_fps, 'risk_fingerprints_laundered_by_session_end')
    require(usage_end.get('literals') == exp_literals, 'risk_literals_laundered_by_session_end')
    require(usage_end.get('retained_bytes') == usage.get('retained_bytes'), 'risk_retained_bytes_laundered_by_session_end')


def setup_restart_daemon(home: Path, port: int, registry_path: Path, registry_sha: str, policy_path: Path | None = None) -> dict:
    home_dir = home.resolve()
    agentfw_dir = home_dir / '.agentfw'
    agentfw_dir.mkdir(parents=True, exist_ok=True)
    cfg = {
        'port': port,
        'enforce': True,
        'native': {
            'registry_path': str(registry_path.resolve()),
            'registry_sha256': registry_sha,
            'liveness': {
                'default_lease_seconds': 2,
                'max_lease_seconds': 60,
                'maintenance_interval_ms': 100,
            },
        },
    }
    if policy_path is not None:
        cfg['policy'] = str(policy_path.resolve())
    write(agentfw_dir / 'config.yaml', cfg)
    return cfg


def verify_daemon_healthy_and_enforcing(port: int, token: str, expected_registry_sha: str, expected_lease_secs: int = 2) -> dict:
    h_status, health = http_get(f'http://127.0.0.1:{port}/health', '')
    require(h_status == 200 and health.get('status') == 'ok', 'daemon_health_check_failed')
    require(health.get('enforce') is True, 'daemon_enforce_not_active')
    i_status, inst = http_get(f'http://127.0.0.1:{port}/native/v1/instance', token)
    require(i_status == 200, 'daemon_instance_query_failed')
    require(inst.get('registry_sha256') == expected_registry_sha, 'daemon_registry_sha_mismatch')
    liveness_info = inst.get('liveness', {})
    if liveness_info.get('default_lease_seconds') is not None:
        require(liveness_info['default_lease_seconds'] == expected_lease_secs, 'daemon_default_lease_not_configured')
    return inst


def grade_selected_report(report: dict, required_cases: list[str]) -> None:
    require(isinstance(report, dict), 'report_missing')
    require(report.get('status') == 'pass', 'report_status_not_pass')
    require(report.get('selected_production_acceptance') is True, 'selected_production_acceptance_false')
    require(report.get('failed') == 0, 'report_failed_nonzero')
    before, after = report.get('source_before'), report.get('source_after')
    require(isinstance(before, dict) and isinstance(after, dict), 'candidate_source_identity_missing')
    require(before == after and before.get('dirty') is False
            and re.fullmatch(r'[0-9a-f]{40}', str(before.get('commit', '')))
            and re.fullmatch(r'[0-9a-f]{40}', str(before.get('tree', '')))
            and before['commit'] == report.get('runtime_source_commit'), 'candidate_source_changed')
    require(report.get('binary_unchanged') is True, 'candidate_binary_changed')
    for key in ('binary_sha256', 'driver_sha256', 'config_sha256', 'git_config_sha256',
                'restart_config_sha256', 'git_binary_sha256', 'git_launcher_sha256',
                'node_binary_sha256', 'bwrap_binary_sha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', str(report.get(key, ''))), f'required_identity_missing_{key}')
    completed_cases = [c['case'] for c in report.get('checks', []) if c.get('passed')]
    for req_case in required_cases:
        require(req_case in completed_cases, f'required_case_missing_{req_case}')


def write_selected_report(path: Path, report: dict) -> None:
    """Publish atomically through the accepted marker filter and private mode."""
    temporary = path.with_suffix('.checkpoint.tmp')
    try:
        write(temporary, report)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def checkpoint_selected_report(path: Path, report: dict, phase: str) -> None:
    """Retain incomplete evidence even if the disposable service is killed.

    Only the existing final grader can publish a pass. Atomic replacement keeps
    the previous complete checkpoint readable if a write is interrupted.
    """
    snapshot = dict(report)
    completed = report.get('completed_churn_clients', [])
    snapshot.update(status='incomplete', failed=max(1, report.get('failed', 0)),
                    passed=sum(c.get('passed') is True for c in report.get('checks', [])),
                    progress={'phase': phase, 'monotonic_seconds': time.monotonic(),
                              'churn_completed': {kind: sum(row.get('profile') == kind for row in completed)
                                                  for kind in ('filesystem', 'git')}})
    write_selected_report(path, snapshot)


def summary(report: dict) -> dict:
    bounded = {
        key: report.get(key)
        for key in (
            'format', 'mode', 'status', 'selected_production_acceptance',
            'error', 'passed', 'failed', 'checks_count', 'progress',
            'platform', 'machine', 'runtime_source_commit',
            'binary_sha256', 'git_binary_sha256', 'git_launcher_sha256',
            'source_before', 'source_after', 'binary_unchanged', 'driver_sha256',
            'config_sha256', 'git_config_sha256', 'restart_config_sha256',
            'node_binary_sha256', 'bwrap_binary_sha256',
        )
        if key in report
    }
    bounded['checks'] = [
        {
            'case': c.get('case'),
            'passed': c.get('passed'),
            'details': {
                k: v for k, v in (c.get('details') or {}).items()
                if k not in ('observed_processes', 'client')
            } if 'details' in c else None,
        }
        for c in report.get('checks', [])
    ]
    return bounded


REQUIRED_PRODUCTION_CASES = [
    'filesystem_sigkill_reclamation',
    'filesystem_healthy_idle_useful_renewal',
    'filesystem_active_sibling_isolation',
    'git_sigkill_reclamation',
    'git_healthy_idle_useful_renewal',
    'git_active_sibling_isolation',
    'repeated_crash_reconnect_beyond_64',
    'stale_and_forged_requests',
    'old_result_replay_rejected',
    'parent_child_grandchild_cascade',
    'restart_uncertainty_and_shared_risk',
]


def run_selected_acceptance(args) -> int:
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    report_file = output / 'report.json'

    report = {
        'format': FORMAT,
        'mode': 'selected-production-acceptance',
        'status': 'incomplete',
        'selected_production_acceptance': True,
        'passed': 0,
        'failed': 0,
        'platform': platform.system(),
        'machine': platform.machine(),
        'runtime_source_commit': getattr(args, 'runtime_source_commit', 'unknown'),
        'checks': [],
    }

    try:
        # 1. Strict Linux prerequisites
        require(platform.system() == 'Linux', 'required_linux_operating_system_missing')
        require(platform.machine() in ('x86_64', 'aarch64'), 'required_linux_architecture_missing')
        require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
        # 2. Candidate source identity
        source_info = BASE.source()
        report['source_before'] = source_info
        report['driver_sha256'] = sha(Path(__file__))
        require(not source_info['dirty'] and source_info['commit'] == args.expected_commit, 'clean_exact_candidate_source_required')
        require(args.expected_commit == args.runtime_source_commit, 'commit_contract_mismatch')

        # 3. Pinned runtime prerequisites
        require(hasattr(args, 'agentfw') and args.agentfw is not None and args.agentfw.resolve().is_file() and os.access(args.agentfw.resolve(), os.X_OK), 'agentfw_executable_missing')
        require(hasattr(args, 'node') and args.node is not None and args.node.resolve().is_file() and os.access(args.node.resolve(), os.X_OK), 'node_executable_missing')
        require(hasattr(args, 'npm') and args.npm is not None and args.npm.resolve().is_file() and os.access(args.npm.resolve(), os.X_OK), 'npm_executable_missing')
        require(hasattr(args, 'bwrap') and args.bwrap is not None and args.bwrap.resolve().is_file() and os.access(args.bwrap.resolve(), os.X_OK), 'bwrap_executable_missing')
        require(hasattr(args, 'git') and args.git is not None and args.git.resolve().is_file() and os.access(args.git.resolve(), os.X_OK), 'git_executable_missing')
        require(hasattr(args, 'git_launcher') and args.git_launcher is not None and args.git_launcher.resolve().is_file() and os.access(args.git_launcher.resolve(), os.X_OK), 'git_launcher_executable_missing')

        # Record binary and launcher identities
        report['binary_sha256'] = sha(args.agentfw.resolve())
        report['node_binary_sha256'] = sha(args.node.resolve())
        report['bwrap_binary_sha256'] = sha(args.bwrap.resolve())
        report['git_binary_sha256'] = sha(args.git.resolve())
        require(report['git_binary_sha256'] == args.git_sha256, 'git_binary_sha256_mismatch')
        report['git_launcher_sha256'] = sha(args.git_launcher.resolve())

        # 3. Systemd delegation setup
        delegation, report['delegation'] = prepare_delegation(args.disposable_systemd_unit)
        with tempfile.TemporaryDirectory(prefix='sou89-selected-') as temporary:
            private = Path(temporary).resolve()
            fs, git, d1, d2 = None, None, None, None
            try:
                fs_private, git_private = private / 'filesystem', private / 'git'
                fs_private.mkdir(mode=0o700)
                git_private.mkdir(mode=0o700)

                checkpoint_selected_report(report_file, report, 'filesystem_setup')
                # Initialize real filesystem rig with Node @modelcontextprotocol/server-filesystem and native.liveness
                fs = SelectedLivenessRig(args, fs_private, delegation, lease_secs=4, maint_interval_ms=100)
                SOU86.install_fixture(fs)

                checkpoint_selected_report(report_file, report, 'git_setup')
                # Initialize real Git rig with pinned Git and native.liveness
                git = SelectedLivenessGitRig(args, git_private, delegation, lease_secs=4, maint_interval_ms=100)

                report['config_sha256'] = sha(fs.home / '.agentfw/config.yaml')
                report['git_config_sha256'] = sha(git.home / '.agentfw/config.yaml')
                report['original_server'], report['original_git_server'] = fs.installation, git.installation

                # Execute required acceptance cases for both profiles
                for rig, kind in ((fs, 'filesystem'), (git, 'git')):
                    checkpoint_selected_report(report_file, report, f'{kind}_lifecycle_cases')
                    reg_sha = rig.config['native']['registry_sha256']
                    status, inst_info = http_get(rig.instance_url, rig.native_token)
                    require(status == 200, f'{kind}_instance_query_failed')

                    # Case 1: Actual SIGKILL without session_end reclaims capacity autonomously
                    client = SelectedLivenessClient(rig, f'{kind}-sigkill-autonomous', lease_secs=4)
                    client.initialize()
                    useful(client)

                    # Witness active leased status on daemon using physical session_id
                    status, lstatus = http_post(rig.liveness_url, rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': reg_sha,
                        'session_id': client.session_id,
                        'instance_id': inst_info['instance_id'],
                        'action': 'status',
                    })
                    grade_liveness_active(lstatus, client.session_id, kind, expected_instance_id=inst_info['instance_id'])

                    # Inject SIGKILL and witness strict process, identity, and kernel cgroup cleanup
                    t_crash_start = time.monotonic()
                    crash_row = observe_crash(client, target='collector', bwrap=args.bwrap.resolve())
                    check_sigkill = {
                        'case': f'{kind}_sigkill_reclamation',
                        'passed': False,
                        'details': {
                            'process_stop_millis': crash_row.get('process_stop_millis'),
                            'leaf_remove_millis': crash_row.get('leaf_remove_millis'),
                            'reclaimed_autonomously': False,
                        },
                        'crash_observation': crash_row,
                    }
                    report['checks'].append(check_sigkill)
                    grade_crash_observation(crash_row, kind, budget=DEFAULT_BUDGET)

                    # Quiet period: exactly zero requests during lease (4.0s) + 2 maintenance periods (2*100ms) + 500ms margin
                    quiet_seconds = 4.0 + 2 * (100 / 1000.0) + 0.5
                    time.sleep(quiet_seconds)
                    t_quiet_end = time.monotonic()

                    # Witness: session autonomously reclaimed at declared deadline without interim polling
                    deadline = t_crash_start + 4.0 + 2 * (100 / 1000.0) + 1.5
                    require(t_quiet_end <= deadline, f'{kind}_reclamation_deadline_exceeded')

                    status, lstatus = http_post(rig.liveness_url, rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': reg_sha,
                        'session_id': client.session_id,
                        'instance_id': inst_info['instance_id'],
                        'action': 'status',
                    })
                    require(status == 404 and lstatus.get('error_code') == 'native_session_unknown',
                            f'{kind}_session_not_reclaimed_autonomously')
                    grade_autonomous_reclamation(status, rig.audit()['rows'], client.epoch, kind)

                    check_sigkill['passed'] = True
                    check_sigkill['details']['reclaimed_autonomously'] = True

                    checkpoint_selected_report(report_file, report, f'{kind}_idle_renewal')
                    # Case 2: Healthy-idle renewal followed by original useful work across complete lease periods
                    renew_client = SelectedLivenessClient(rig, f'{kind}-idle-renewal', lease_secs=4)
                    renew_client.initialize()
                    useful_1 = useful(renew_client)

                    # Idle across multiple lease intervals (8.5s > 2 complete 4s leases)
                    time.sleep(8.5)

                    useful_2 = useful(renew_client, expected_hash=useful_1)
                    require(useful_1 == useful_2, f'{kind}_useful_work_diverged_across_renewal')

                    status, renew_status = http_post(rig.liveness_url, rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': reg_sha,
                        'session_id': renew_client.session_id,
                        'instance_id': inst_info['instance_id'],
                        'action': 'status',
                    })
                    grade_liveness_renewal(renew_status, renew_client.session_id, min_seq=2, kind=kind,
                                           expected_instance_id=inst_info['instance_id'])

                    close_res = renew_client.close()
                    grade_client_close(close_res, kind)

                    report['checks'].append({
                        'case': f'{kind}_healthy_idle_useful_renewal',
                        'passed': True,
                        'details': {
                            'lease_seq': renew_status.get('lease_seq'),
                            'useful_stable': True,
                        },
                    })

                    checkpoint_selected_report(report_file, report, f'{kind}_sibling_isolation')
                    # Case 3: Surviving sibling remains healthy and useful after peer SIGKILL
                    sibling_a = SelectedLivenessClient(rig, f'{kind}-sibling-a', lease_secs=4)
                    # Pin A's independently observed cgroup and native epoch before
                    # B can create another leaf under the same delegated root.
                    sibling_a.initialize()
                    sibling_b = SelectedLivenessClient(rig, f'{kind}-sibling-b', lease_secs=10)
                    sibling_b.initialize()
                    useful(sibling_a)
                    useful_b1 = useful(sibling_b)

                    crash_sib = observe_crash(sibling_a, target='collector', bwrap=args.bwrap.resolve())
                    check_sibling = {
                        'case': f'{kind}_active_sibling_isolation',
                        'passed': False,
                        'details': {
                            'sibling_reclaimed': False,
                            'surviving_sibling_useful': False,
                        },
                        'crash_observation': crash_sib,
                    }
                    report['checks'].append(check_sibling)
                    grade_crash_observation(crash_sib, f'{kind}_sibling_a', budget=DEFAULT_BUDGET)

                    # Wait for sibling_a lease to expire and be swept autonomously
                    sib_deadline = time.monotonic() + 4.0 + 2 * (100 / 1000.0) + 1.5
                    sib_reclaimed = False
                    status = 200
                    while time.monotonic() < sib_deadline:
                        status, _ = http_post(rig.liveness_url, rig.native_token, {
                            'contract_version': LIVENESS_CONTRACT,
                            'registry_sha256': reg_sha,
                            'session_id': sibling_a.session_id,
                            'instance_id': inst_info['instance_id'],
                            'action': 'status',
                        })
                        if status == 404:
                            sib_reclaimed = True
                            break
                        time.sleep(0.1)
                    require(sib_reclaimed, f'{kind}_sibling_a_reclamation_deadline_exceeded')
                    grade_autonomous_reclamation(status, rig.audit()['rows'], sibling_a.epoch, f'{kind}_sibling_a')

                    # Sibling B survives completely unaffected and executes useful work
                    useful_b2 = useful(sibling_b, expected_hash=useful_b1)
                    require(useful_b1 == useful_b2, f'{kind}_sib_b_work_diverged')

                    status, sib_b_status = http_post(rig.liveness_url, rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': reg_sha,
                        'session_id': sibling_b.session_id,
                        'instance_id': inst_info['instance_id'],
                        'action': 'status',
                    })
                    grade_liveness_active(sib_b_status, sibling_b.session_id, f'{kind}_sibling_b',
                                          expected_instance_id=inst_info['instance_id'])

                    close_b = sibling_b.close()
                    grade_client_close(close_b, f'{kind}_sibling_b')

                    check_sibling['passed'] = True
                    check_sibling['details']['sibling_reclaimed'] = True
                    check_sibling['details']['surviving_sibling_useful'] = True

                # Case 4: Repeated crash/reconnect cycles beyond 64 sessions on each daemon independently
                # Run 70 cycles on filesystem (> 64) and 70 cycles on Git (> 64)
                churn_cycles = 70
                for churn_rig, churn_kind in ((fs, 'filesystem'), (git, 'git')):
                    checkpoint_selected_report(report_file, report, f'churn_{churn_kind}')
                    for i in range(churn_cycles):
                        c = SelectedLivenessClient(churn_rig, f'churn-{churn_kind}-{i}', lease_secs=2)
                        c.initialize()
                        useful_hash = useful(c)
                        os.kill(c.process.pid, signal.SIGKILL)
                        c_res = c.close(expect_failure=True)
                        grade_client_close(c_res, f'churn_{churn_kind}_{i}', expect_failure=True,
                                           expected_signal=signal.SIGKILL, require_kernel=bool(churn_rig.delegation))
                        report.setdefault('completed_churn_clients', []).append({
                            'profile': churn_kind, 'cycle': i + 1,
                            'useful_sha256': useful_hash, 'client': c_res,
                        })
                        checkpoint_selected_report(report_file, report, f'churn_{churn_kind}')
                        if i % 14 == 13:
                            time.sleep(2.5)

                    time.sleep(2.5)
                    # Prove admission capacity restored by admitting fresh sessions beyond 64 on this daemon
                    verify_c = SelectedLivenessClient(churn_rig, f'churn-restored-{churn_kind}', lease_secs=4)
                    verify_c.initialize()
                    useful(verify_c)
                    close_vc = verify_c.close()
                    grade_client_close(close_vc, f'verify_{churn_kind}_capacity', require_kernel=bool(churn_rig.delegation))

                report['checks'].append({
                    'case': 'repeated_crash_reconnect_beyond_64',
                    'passed': True,
                    'cycles_per_profile': churn_cycles,
                })

                checkpoint_selected_report(report_file, report, 'stale_and_forged_requests')
                # Case 5: Stale and forged requests rejected on both profiles
                for s_rig, s_kind in ((fs, 'filesystem'), (git, 'git')):
                    s_inst_id = http_get(s_rig.instance_url, s_rig.native_token)[1]['instance_id']
                    s_reg_sha = s_rig.config['native']['registry_sha256']
                    sid_forged = f'sel-forged-{s_kind}-{int(time.time() * 1000)}'

                    status, start_body = http_post(s_rig.native_url, s_rig.native_token, {
                        'contract_version': NATIVE_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'liveness': LIVENESS_CONTRACT,
                        'event': 'session_start',
                    })
                    require(status == 200, f'{s_kind}_forged_session_start_failed')
                    owner_tok = start_body['owner_token']

                    # Forged: missing owner token
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'enroll',
                        'lease_seconds': 15,
                    })
                    require(status == 403 and body.get('error_code') == 'native_liveness_owner_token_required',
                            f'{s_kind}_forged_missing_token_not_rejected')

                    # Forged: wrong owner token
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'enroll',
                        'lease_seconds': 15,
                        'owner_token': 'wrong-token-value',
                    })
                    require(status == 403 and body.get('error_code') == 'native_liveness_owner_mismatch',
                            f'{s_kind}_forged_wrong_token_not_rejected')

                    # Valid enroll
                    status, enroll_body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'enroll',
                        'lease_seconds': 15,
                        'owner_token': owner_tok,
                    })
                    require(status == 200, f'{s_kind}_legitimate_enroll_failed')
                    epoch = enroll_body['epoch']

                    # Re-enrollment rejected
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'enroll',
                        'lease_seconds': 15,
                        'owner_token': owner_tok,
                    })
                    require(status == 409 and body.get('error_code') == 'native_liveness_already_enrolled',
                            f'{s_kind}_re_enroll_not_rejected')

                    # A genuine epoch still cannot authorize another owner.
                    for action in ('renew', 'retire'):
                        for forged_owner in (None, 'wrong-owner-capability'):
                            forged = {
                                'contract_version': LIVENESS_CONTRACT,
                                'registry_sha256': s_reg_sha,
                                'session_id': sid_forged,
                                'instance_id': s_inst_id,
                                'action': action,
                                'epoch': epoch,
                                'lease_seq': 2,
                            }
                            if forged_owner is not None:
                                forged['owner_token'] = forged_owner
                            status, body = http_post(s_rig.liveness_url, s_rig.native_token, forged)
                            code = ('native_liveness_owner_token_required' if forged_owner is None
                                    else 'native_liveness_owner_mismatch')
                            require(status == 403 and body.get('error_code') == code,
                                    f'{s_kind}_{action}_accepted_non_owner')

                    # Valid first renew seq 2
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'renew',
                        'epoch': epoch,
                        'lease_seq': 2,
                        'owner_token': owner_tok,
                    })
                    require(status == 200, f'{s_kind}_first_renew_failed')

                    # Stale / replayed sequence number rejected
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'renew',
                        'epoch': epoch,
                        'lease_seq': 2,
                        'owner_token': owner_tok,
                    })
                    require(status == 409 and body.get('error_code') == 'native_liveness_seq_stale',
                            f'{s_kind}_stale_seq_not_rejected')

                    # Epoch mismatch rejected
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'renew',
                        'epoch': 'wrong-epoch-token',
                        'lease_seq': 3,
                        'owner_token': owner_tok,
                    })
                    require(status == 403 and body.get('error_code') == 'native_liveness_epoch_mismatch',
                            f'{s_kind}_epoch_mismatch_not_rejected')

                    # Instance mismatch rejected
                    status, body = http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': 'wrong-instance-id-value',
                        'action': 'renew',
                        'epoch': epoch,
                        'lease_seq': 3,
                        'owner_token': owner_tok,
                    })
                    require(status == 409 and body.get('error_code') == 'native_instance_mismatch',
                            f'{s_kind}_instance_mismatch_not_rejected')

                    # Clean up
                    http_post(s_rig.liveness_url, s_rig.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': s_reg_sha,
                        'session_id': sid_forged,
                        'instance_id': s_inst_id,
                        'action': 'retire',
                        'epoch': epoch,
                        'owner_token': owner_tok,
                    })

                report['checks'].append({
                    'case': 'stale_and_forged_requests',
                    'passed': True,
                })

                checkpoint_selected_report(report_file, report, 'old_result_replay')
                # Case 6: Old result on retired session rejected on both filesystem and Git
                for rep_rig, rep_kind in ((fs, 'filesystem'), (git, 'git')):
                    rep_reg_sha = rep_rig.config['native']['registry_sha256']
                    rep_inst_id = http_get(rep_rig.instance_url, rep_rig.native_token)[1]['instance_id']
                    c_replay = SelectedLivenessClient(rep_rig, f'{rep_kind}-replay-collector', lease_secs=6)
                    c_replay.initialize()
                    req_id = c_replay.next_id
                    if rep_kind == 'git':
                        c_req = GIT.call(req_id, repo=rep_rig.workspace if c_replay.direct else '/workspace')
                    else:
                        c_req = RESOURCE.call(req_id, str(rep_rig.workspace / 'notes.txt') if c_replay.direct else '/workspace/notes.txt')
                    useful_resp, useful_wire = c_replay.exchange(c_req)
                    c_replay.next_id += 1

                    tool_name = c_req['params']['name']
                    tool_args = copy.deepcopy(c_req['params']['arguments'])

                    # Read raw audit to get exact call_id emitted for c_replay.epoch
                    raw_rows = read_raw_audit(rep_rig)
                    call_row = next(r for r in reversed(raw_rows)
                                    if r.get('event') == 'native_call' and r.get('session') == c_replay.epoch)
                    result_row = next(r for r in reversed(raw_rows)
                                      if r.get('event') == 'native_result' and r.get('session') == c_replay.epoch
                                      and r.get('call_id') == call_row['call_id'])
                    require(result_row.get('released') is True, f'{rep_kind}_original_result_not_released')

                    # Retire the session
                    status, _ = http_post(rep_rig.native_url, rep_rig.native_token, {'contract_version': NATIVE_CONTRACT, 'registry_sha256': rep_reg_sha, 'session_id': c_replay.session_id, 'event': 'session_end'})
                    require(status == 200, f'{rep_kind}_replay_collector_retire_failed')
                    close_cr = c_replay.close()
                    grade_client_close(close_cr, f'{rep_kind}_replay_client')

                    # Inject replay of exact accepted result wire payload on the retired session
                    replay_payload = {
                        'contract_version': NATIVE_CONTRACT,
                        'registry_sha256': rep_reg_sha,
                        'session_id': c_replay.session_id,
                        'event': 'result',
                        'call_id': call_row['call_id'],
                        'tool': tool_name,
                        'args': tool_args,
                        'result_kind': 'value',
                        'content': useful_wire.decode('utf-8'),
                        'delivery': 'mcp_host',
                    }
                    status, replay_resp = http_post(rep_rig.native_url, rep_rig.native_token, replay_payload)
                    require(status in (404, 409) and replay_resp.get('error_code') in ('native_session_unknown', 'native_session_terminal'),
                            f'{rep_kind}_old_result_not_rejected')
                    require(replay_resp.get('release') is not True, f'{rep_kind}_old_result_replay_must_never_release')

                report['checks'].append({
                    'case': 'old_result_replay_rejected',
                    'passed': True,
                })

                checkpoint_selected_report(report_file, report, 'parent_cascade')
                # Case 7: Parent expiration cascades to child and grandchild sessions and preserves shared risk
                useful_sample = RESOURCE.call(10, str(fs.workspace / 'notes.txt'))
                useful_tool_name = useful_sample['params']['name']
                fs_tools = json.loads(Path(fs.config['native']['registry_path']).read_text())['tools']
                useful_tool_entry = next(t for t in fs_tools if t['name'] == useful_tool_name)
                useful_tool_schema_sha = useful_tool_entry['schema_sha256']
                fs_inst_id = http_get(fs.instance_url, fs.native_token)[1]['instance_id']
                fs_reg_sha = fs.config['native']['registry_sha256']

                def mint_auth(session: str, server: str, ttl: int, tools: list[str], agent_id: str,
                              parent_id: str | None = None, parent_binding: str | None = None) -> str:
                    cmd = [
                        str(args.agentfw.resolve()), 'child-authority', 'mint',
                        '--session', session, '--server', server, '--ttl-seconds', str(ttl),
                        '--instance-id', fs_inst_id,
                    ]
                    for t in tools:
                        cmd.extend(['--tools', t])
                    if agent_id:
                        cmd.extend(['--agent-id', agent_id])
                    if parent_id:
                        cmd.extend(['--parent-id', parent_id])
                    if parent_binding:
                        cmd.extend(['--parent-binding', parent_binding])
                    c_env = BASE.environment(fs.home)
                    return subprocess.check_output(cmd, env=c_env, text=True).strip()

                # 1. Root parent collector with 2s lease
                parent_token = mint_auth('host-cascade', 'sou86-recovery', 120, [useful_tool_name], 'orch-p')
                c_p = SelectedLivenessClient(fs, 'cascade-p', lease_secs=2, host_session='host-cascade', child_authority=parent_token)
                c_p.initialize()
                useful(c_p)

                _, p_inst = http_get(fs.instance_url, fs.native_token)
                p_binding = [b for b in p_inst.get('bindings', []) if b.get('agent_id') == 'orch-p'][0]['binding_sha256']

                # 2. Child collector bound to parent with 20s lease (renewal interval 6.67s)
                child_token = mint_auth('host-cascade', 'sou86-recovery', 120, [useful_tool_name], 'orch-c',
                                        parent_id='orch-p', parent_binding=p_binding)
                c_c = SelectedLivenessClient(fs, 'cascade-c', lease_secs=20, host_session='host-cascade', child_authority=child_token)
                c_c.initialize()
                useful(c_c)

                _, c_inst = http_get(fs.instance_url, fs.native_token)
                c_binding = [b for b in c_inst.get('bindings', []) if b.get('agent_id') == 'orch-c'][0]['binding_sha256']

                # 3. Grandchild collector bound to child with 4s lease (renewal interval 1.33s)
                gc_token = mint_auth('host-cascade', 'sou86-recovery', 120, [useful_tool_name], 'orch-gc',
                                     parent_id='orch-c', parent_binding=c_binding)
                c_gc = SelectedLivenessClient(fs, 'cascade-gc', lease_secs=4, host_session='host-cascade', child_authority=gc_token)
                c_gc.initialize()
                useful(c_gc)

                # 4. Verify all scoped bindings are active in the daemon
                _, active_cascade_inst = http_get(fs.instance_url, fs.native_token)
                cascade_agents = {b.get('agent_id') for b in active_cascade_inst.get('bindings', [])}
                require({'orch-p', 'orch-c', 'orch-gc'}.issubset(cascade_agents), 'scoped_cascade_bindings_missing')

                def proc_id(proc):
                    if SOU86 is not None:
                        try:
                            res = SOU86.identity(proc.pid)
                            if res:
                                return res
                        except Exception:
                            pass
                    return {'pid': proc.pid}

                # Retain active descendant process identities before parent termination
                active_descendants = {
                    'parent': proc_id(c_p.process),
                    'child': proc_id(c_c.process),
                    'grandchild': proc_id(c_gc.process),
                }

                # Pre-record check entry before assertions to preserve observations on failure
                check_cascade = {
                    'case': 'parent_child_grandchild_cascade',
                    'passed': False,
                    'hierarchy_levels': 3,
                    'active_descendants': active_descendants,
                    'observations': {},
                }
                report['checks'].append(check_cascade)

                # 5. Monotonic timing origin: parent termination
                t_parent_kill = time.monotonic()
                os.kill(c_p.process.pid, signal.SIGKILL)
                close_p = c_p.close(expect_failure=True)
                grade_client_close(close_p, 'cascade_parent', expect_failure=True, expected_signal=signal.SIGKILL)

                # 6. Sleep 2.5s (2s parent lease + 2*100ms maint + margin) within declared finite bound (<8.0s)
                time.sleep(2.5)

                # 7. Witness: parent expiry cascades to all descendants autonomously
                for sid in (c_p.session_id, c_c.session_id, c_gc.session_id):
                    status, _ = http_post(fs.liveness_url, fs.native_token, {
                        'contract_version': LIVENESS_CONTRACT,
                        'registry_sha256': fs_reg_sha,
                        'session_id': sid,
                        'instance_id': fs_inst_id,
                        'action': 'status',
                    })
                    require(status == 404, f'cascade_session_{sid}_not_reclaimed')

                # Verify raw audit rows prove recursive parent cascade, distinguishing from child's own 20s lease
                raw_rows = read_raw_audit(fs)
                p_exp = next((r for r in raw_rows if r.get('session') == c_p.epoch and r.get('event') == 'native_session_expired' and r.get('session_id') == c_p.session_id), None)
                c_exp = next((r for r in raw_rows if r.get('session') == c_c.epoch and r.get('event') == 'native_session_expired' and r.get('session_id') == c_c.session_id and r.get('parent_id') == 'orch-p'), None)
                gc_exp = next((r for r in raw_rows if r.get('session') == c_gc.epoch and r.get('event') == 'native_session_expired' and r.get('session_id') == c_gc.session_id and r.get('parent_id') == 'orch-c'), None)
                require(p_exp is not None, 'parent_expiry_not_audited')
                require(c_exp is not None, 'child_expiry_not_audited')
                require(gc_exp is not None, 'grandchild_expiry_not_audited')
                require(isinstance(p_exp.get('at_ms'), int) and p_exp['at_ms'] > 0, 'parent_expiry_timestamp_missing')
                require(isinstance(c_exp.get('at_ms'), int) and c_exp['at_ms'] > 0, 'child_expiry_timestamp_missing')
                require(isinstance(gc_exp.get('at_ms'), int) and gc_exp['at_ms'] > 0, 'grandchild_expiry_timestamp_missing')
                p_ms = p_exp['at_ms']
                c_ms = c_exp['at_ms']
                gc_ms = gc_exp['at_ms']
                require(abs(c_ms - p_ms) <= 2000, f'child_not_expired_in_parent_cascade_sweep_p_{p_ms}_c_{c_ms}')
                require(abs(gc_ms - p_ms) <= 2000, f'grandchild_not_expired_in_parent_cascade_sweep_p_{p_ms}_gc_{gc_ms}')

                # 8. Observe autonomous fail-closed exit of grandchild on renewal rejection with stdin kept open
                # Enforce monotonic parent-kill-to-terminal deadline check (< 8.0s)
                monotonic_deadline = t_parent_kill + 8.0
                timeout_rem = max(0.1, monotonic_deadline - time.monotonic())
                try:
                    gc_exit = c_gc.process.wait(timeout=timeout_rem)
                    require(gc_exit == 1, f'grandchild_autonomous_exit_code_must_be_1_got_{gc_exit}')
                except subprocess.TimeoutExpired:
                    c_gc.process.kill()
                    c_gc.process.wait()
                    raise ValueError('grandchild_failed_to_exit_autonomously_on_renewal_failure')
                t_gc_terminal = time.monotonic()
                t_gc_total = t_gc_terminal - t_parent_kill
                require(t_gc_total < 8.0, f'grandchild_monotonic_deadline_exceeded_{t_gc_total}')

                close_gc = c_gc.close(expect_failure=True)
                grade_client_close(close_gc, 'cascade_grandchild', expect_failure=True)

                # 9. Observe actual denied useful operation on child after cascade, and its fail-closed exit
                child_denied_err = None
                if c_c.process.poll() is not None:
                    # (a) already terminal due to intended renewal uncertainty
                    c_c_exit = c_c.process.poll()
                    require(c_c_exit == 1, f'child_already_terminal_must_exit_1_got_{c_c_exit}')
                    child_denied_err = 'child_already_terminal_from_renewal_uncertainty'
                else:
                    # (b) still-running collector receiving a real refused operation
                    child_useful_succeeded = False
                    try:
                        useful(c_c)
                        child_useful_succeeded = True
                    except (BrokenPipeError, OSError) as ex:
                        child_denied_err = f'broken_pipe_during_call_{type(ex).__name__}'
                    except Exception as ex:
                        child_denied_err = str(ex)
                        require('collector_closed_before_correlated_response' in child_denied_err or
                                'denied' in child_denied_err or 'refused' in child_denied_err,
                                f'unexpected_child_denied_error_{child_denied_err}')

                    require(not child_useful_succeeded, 'descendant_useful_operation_must_be_denied_after_cascade')
                    require(child_denied_err is not None, 'child_denial_evidence_missing_after_cascade')
                    c_c_exit = c_c.process.wait(timeout=5.0)
                    require(c_c_exit == 1, f'child_fail_closed_exit_code_must_be_1_got_{c_c_exit}')

                close_c = c_c.close(expect_failure=True)
                grade_client_close(close_c, 'cascade_child', expect_failure=True)

                # 10. Witness: scoped bindings cleared
                _, retired_cascade_inst = http_get(fs.instance_url, fs.native_token)
                retired_cascade_agents = {b.get('agent_id') for b in retired_cascade_inst.get('bindings', [])}
                require(not ({'orch-p', 'orch-c', 'orch-gc'} & retired_cascade_agents), 'cascade_bindings_not_cleared')

                check_cascade['passed'] = True
                check_cascade['observations'] = {
                    'grandchild_autonomous_exit_code': gc_exit,
                    'grandchild_monotonic_wait_seconds': t_gc_total,
                    'child_denied_error': child_denied_err,
                    'child_fail_closed_exit_code': c_c_exit,
                    'parent_expire_audit_ms': p_ms,
                    'child_expire_audit_ms': c_ms,
                    'grandchild_expire_audit_ms': gc_ms,
                    'sweep_delta_ms': abs(c_ms - p_ms),
                }

                checkpoint_selected_report(report_file, report, 'restart_uncertainty_and_shared_risk')
                # Case 8: Daemon restart causes uncertainty, activates continuity barrier, and halts execution cleanly
                r_home = private / 'restart_test'
                r_home.mkdir(mode=0o700)
                r_port = BASE.DEMO.free_port()
                r_env = BASE.environment(r_home)
                r_install = subprocess.run([str(args.agentfw.resolve()), 'install'], env=r_env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
                require(r_install.returncode == 0, 'restart_daemon_install_failed')
                r_cfg = setup_restart_daemon(
                    r_home,
                    r_port,
                    fs.private / 'original/registry.json',
                    fs_reg_sha,
                    policy_path=fs.private / 'original/policy.yaml',
                )
                report['restart_config_sha256'] = sha(r_home / '.agentfw/config.yaml')

                try:
                    d1 = subprocess.Popen([str(args.agentfw.resolve()), 'serve'], env=r_env,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    require(BASE.DEMO.wait_healthy(r_port, d1), 'restart_daemon1_unavailable')
                    r_tok_path = r_home / '.agentfw/native-token'
                    if not r_tok_path.is_file():
                        r_tok_path = r_home / 'native-token'
                    r_token = r_tok_path.read_text().strip()
                    d1_inst = verify_daemon_healthy_and_enforcing(r_port, r_token, fs_reg_sha, expected_lease_secs=2)

                    r_rig = copy.copy(fs)
                    r_rig.home = r_home
                    r_rig.port = r_port
                    r_rig.env = r_env

                    c_restart = SelectedLivenessClient(r_rig, 'restart-client', lease_secs=2)
                    c_restart.initialize()
                    useful(c_restart)

                    # Read hook token from r_home
                    hook_tok_path = r_home / '.agentfw/token'
                    if not hook_tok_path.is_file():
                        hook_tok_path = r_home / 'token'
                    r_hook_token = hook_tok_path.read_text().strip()

                    # Record pre-barrier taint via authenticated hook on shared host 'host-restart-risk'
                    hook_taint = {
                        'session_id': 'host-restart-risk',
                        'hook_event_name': 'PostToolUse',
                        'tool_name': 'WebFetch',
                        'tool_input': {'url': 'https://untrusted.example.test/inventory'},
                        'tool_response': 'SOU-89 untrusted text for provenance tracking',
                    }
                    status, _ = http_post(
                        f'http://127.0.0.1:{r_port}/hook',
                        r_hook_token,
                        hook_taint,
                    )
                    require(status == 200, 'restart_pre_barrier_hook_taint_failed')

                    # Activate continuity barrier and checkpoint risk for affected host session
                    status, _ = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1/profile-barrier',
                        r_token,
                        {},
                        headers={'x-agentfw-host-session': 'host-restart-risk'},
                    )
                    require(status == 200, 'restart_profile_barrier_failed')
                    checkpoint_file = r_home / '.agentfw/mcp-profiles/risk-checkpoint.json'
                    if not checkpoint_file.is_file():
                        checkpoint_file = r_home / 'mcp-profiles/risk-checkpoint.json'
                    require(checkpoint_file.is_file(), 'risk_checkpoint_not_created')
                    checkpoint_d1 = json.loads(checkpoint_file.read_text())

                    BASE.DEMO.stop(d1)
                    d1.wait(timeout=5)
                    d1 = None

                    # Start daemon 2 on same port from same home with preserved continuity
                    d2 = subprocess.Popen([str(args.agentfw.resolve()), 'serve'], env=r_env,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    require(BASE.DEMO.wait_healthy(r_port, d2), 'restart_daemon2_unavailable')
                    d2_inst = verify_daemon_healthy_and_enforcing(r_port, r_token, fs_reg_sha, expected_lease_secs=2)
                    require(d1_inst['instance_id'] != d2_inst['instance_id'], 'restart_instance_id_not_fresh')

                    # Verify continuity checkpoint survived restart and preserves host risk
                    require(checkpoint_file.is_file(), 'risk_checkpoint_not_preserved')
                    checkpoint_d2 = json.loads(checkpoint_file.read_text())

                    # Collector observes uncertainty on renewal attempt and halts execution cleanly within 6.0s
                    try:
                        c_restart.process.wait(timeout=6.0)
                        require(c_restart.process.poll() is not None, 'collector_did_not_halt_on_uncertainty')
                    except subprocess.TimeoutExpired:
                        c_restart.process.kill()
                        c_restart.process.wait()
                        raise ValueError('collector_failed_to_halt_on_uncertainty')

                    close_cr = c_restart.close(expect_failure=True)
                    grade_client_close(close_cr, 'restart_client', expect_failure=True)

                    # Direct renewal with old instance returns 409 native_instance_mismatch while d2 is STILL RUNNING
                    status, body = http_post(
                        f'http://127.0.0.1:{r_port}/native/liveness/v1',
                        r_token,
                        {
                            'contract_version': LIVENESS_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': c_restart.session_id,
                            'instance_id': d1_inst['instance_id'],
                            'action': 'renew',
                            'epoch': c_restart.epoch,
                            'lease_seq': 2,
                        },
                    )
                    require(status == 409 and body.get('error_code') == 'native_instance_mismatch',
                            'old_instance_renewal_not_rejected')

                    check_restart = {
                        'case': 'restart_uncertainty_and_shared_risk',
                        'passed': False,
                        'observations': {
                            'd1_instance_id': d1_inst['instance_id'],
                            'd2_instance_id': d2_inst['instance_id'],
                            'retained_bytes': d2_inst['provenance']['usage']['retained_bytes'],
                            'fingerprints': d2_inst['provenance']['usage']['fingerprints'],
                        },
                    }
                    report['checks'].append(check_restart)

                    # Verify live restored risk and policy consequences on d2:
                    # 1. In hook context, unauthenticated call on restored scoped host 'host-restart-risk' is denied with native_hook_authority_required
                    hook_unauthed = {
                        'session_id': 'host-restart-risk',
                        'hook_event_name': 'PreToolUse',
                        'tool_name': 'Bash',
                        'tool_input': {'command': 'echo risk_test'},
                    }
                    status, hook_reply = http_post(
                        f'http://127.0.0.1:{r_port}/hook',
                        r_hook_token,
                        hook_unauthed,
                    )
                    require(status == 200, 'hook_query_failed')
                    out = hook_reply.get('hookSpecificOutput', {})
                    require(out.get('permissionDecision') == 'deny', 'hook_risk_host_not_denied')
                    require('native_hook_authority_required' in out.get('permissionDecisionReason', ''),
                            'hook_risk_host_missing_authority_required_reason')

                    # 2. Independent host on hook does not require scoped authority
                    status, hook_ind = http_post(
                        f'http://127.0.0.1:{r_port}/hook',
                        r_hook_token,
                        {
                            'session_id': 'host-independent',
                            'hook_event_name': 'PreToolUse',
                            'tool_name': 'Bash',
                            'tool_input': {'command': 'echo 1'},
                        },
                    )
                    require(status == 200, 'independent_host_hook_query_failed')
                    out_ind = hook_ind.get('hookSpecificOutput', {})
                    require('native_hook_authority_required' not in out_ind.get('permissionDecisionReason', ''),
                            'independent_host_should_not_require_scoped_authority')

                    # 3. Unauthenticated lifecycle claim cannot launder retained risk
                    status, _ = http_post(
                        f'http://127.0.0.1:{r_port}/hook',
                        r_hook_token,
                        {'session_id': 'host-restart-risk', 'hook_event_name': 'SessionEnd'},
                    )
                    require(status == 200, 'hook_session_end_failed')
                    _, d2_inst_post_end = http_get(f'http://127.0.0.1:{r_port}/native/v1/instance', r_token)

                    # Grade complete risk witnesses (checkpoint provenance, live restored usage, post-end protection)
                    grade_restart_risk(checkpoint_d1, checkpoint_d2, d2_inst, d2_inst_post_end, 'host-restart-risk')

                    # 4. Specific affected-host policy and effect witness via accepted bound-authority pathways:
                    # Create canary configuration on disk
                    (r_home / '.env').write_text('PORT=8000\nSECRET_KEY=sou89_test\n')
                    fs_reg_tools = json.loads((fs.private / 'original/registry.json').read_text())['tools']

                    # 4a. Mint valid child authority for affected host on d2
                    cmd_risk = [
                        str(args.agentfw.resolve()), 'child-authority', 'mint',
                        '--session', 'host-restart-risk',
                        '--server', 'sou86-recovery',
                        '--agent-id', 'agent-risk',
                        '--tools', 'read_text_file,write_file',
                        '--instance-id', d2_inst['instance_id'],
                        '--ttl-seconds', '120',
                    ]
                    proof_risk = subprocess.check_output(cmd_risk, env=r_env, text=True).strip()

                    # Start authenticated native session bound to affected host
                    st, start_bound_risk = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'sess-bound-restart-risk',
                            'liveness': LIVENESS_CONTRACT,
                            'event': 'session_start',
                            'host_session': 'host-restart-risk',
                            'server_id': 'sou86-recovery',
                            'child_authority': proof_risk,
                        },
                    )
                    require(st == 200 and start_bound_risk.get('release') is True,
                            'bound_native_session_start_failed_on_affected_host')

                    # 4b. This native-only contrast uses the selected sandbox namespace, not a host path.
                    # No original-server sensitive file execution is claimed here.
                    # The affected host is held by restored sticky taint/incomplete floor
                    st, call_risk_floor = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'sess-bound-restart-risk',
                            'event': 'call',
                            'tool': 'read_text_file',
                            'args': {'path': '/workspace/.env'},
                            'schema_sha256': next(t['schema_sha256'] for t in fs_reg_tools if t['name'] == 'read_text_file'),
                            'mcp_host_call_id': 'call-floor-1',
                        },
                    )
                    require(st == 200, 'call_risk_floor_http_failed')
                    require(call_risk_floor.get('verdict') == 'ask' and call_risk_floor.get('release') is False,
                            'affected_host_sensitive_call_must_be_held_by_taint_floor')
                    require('taint-history-incomplete' in call_risk_floor.get('reason_codes', []),
                            'affected_host_must_report_taint_history_incomplete')

                    # 4c. Side-effecting write_file on affected host is denied by policy
                    st, call_risk_write = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'sess-bound-restart-risk',
                            'event': 'call',
                            'tool': 'write_file',
                            'args': {'path': str(r_home / 'test_write.txt'), 'content': 'denied_write'},
                            'schema_sha256': next(t['schema_sha256'] for t in fs_reg_tools if t['name'] == 'write_file'),
                        },
                    )
                    require(st == 200, 'call_risk_write_http_failed')
                    require(call_risk_write.get('verdict') == 'deny' and call_risk_write.get('release') is False,
                            'affected_host_write_call_must_be_denied_by_policy')
                    require('filesystem-profile-deny-write' in call_risk_write.get('reason_codes', []),
                            'affected_host_must_report_filesystem_profile_deny_write')

                    # 4d. On hook, write_file presenting valid x-agentfw-child-authority is denied by policy
                    st, hook_write_risk = http_post(
                        f'http://127.0.0.1:{r_port}/hook',
                        r_hook_token,
                        {
                            'session_id': 'host-restart-risk',
                            'agent_id': 'agent-risk',
                            'hook_event_name': 'PreToolUse',
                            'tool_name': 'write_file',
                            'tool_input': {'path': str(r_home / 'test_write.txt'), 'content': 'denied_write'},
                        },
                        headers={'x-agentfw-child-authority': proof_risk},
                    )
                    require(st == 200, 'hook_write_risk_http_failed')
                    hook_write_out = hook_write_risk.get('hookSpecificOutput', {})
                    require(hook_write_out.get('permissionDecision') == 'deny',
                            'hook_bound_write_call_must_be_denied')
                    require('filesystem-profile-deny-write' in hook_write_out.get('permissionDecisionReason', ''),
                            'hook_bound_write_must_report_deny_write_reason')

                    # 4e. Contrast with independent authenticated host context:
                    cmd_ind = [
                        str(args.agentfw.resolve()), 'child-authority', 'mint',
                        '--session', 'host-independent-ctx',
                        '--server', 'sou86-recovery',
                        '--agent-id', 'agent-ind',
                        '--tools', 'read_text_file',
                        '--instance-id', d2_inst['instance_id'],
                        '--ttl-seconds', '120',
                    ]
                    proof_ind = subprocess.check_output(cmd_ind, env=r_env, text=True).strip()

                    st, start_bound_ind = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'sess-bound-independent',
                            'liveness': LIVENESS_CONTRACT,
                            'event': 'session_start',
                            'host_session': 'host-independent-ctx',
                            'server_id': 'sou86-recovery',
                            'child_authority': proof_ind,
                        },
                    )
                    require(st == 200 and start_bound_ind.get('release') is True,
                            'independent_host_native_session_start_failed')

                    # Calling the exact same sensitive path on independent host succeeds (no taint floor)
                    st, call_ind_sens = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'sess-bound-independent',
                            'event': 'call',
                            'tool': 'read_text_file',
                            'args': {'path': '/workspace/.env'},
                            'schema_sha256': next(t['schema_sha256'] for t in fs_reg_tools if t['name'] == 'read_text_file'),
                            'mcp_host_call_id': 'call-ind-1',
                        },
                    )
                    require(st == 200, 'independent_host_call_http_failed')
                    require(call_ind_sens.get('verdict') == 'allow' and call_ind_sens.get('release') is True,
                            'independent_host_sensitive_call_must_be_allowed')
                    require(call_ind_sens.get('reason_codes') == [],
                            'independent_host_should_not_have_reason_codes')

                    check_restart['observations'].update({
                        'affected_host_sensitive_held_by_taint_floor': True,
                        'affected_host_taint_floor_reason': 'taint-history-incomplete',
                        'affected_host_policy_denial_reason': 'filesystem-profile-deny-write',
                        'independent_host_sensitive_allowed': True,
                    })

                    # 5. Native unscoped physical session_id matching host marker is admitted on /native/v1 (distinct namespace)
                    status, start_risk = http_post(
                        f'http://127.0.0.1:{r_port}/native/v1',
                        r_token,
                        {
                            'contract_version': NATIVE_CONTRACT,
                            'registry_sha256': fs_reg_sha,
                            'session_id': 'host-restart-risk',
                            'liveness': LIVENESS_CONTRACT,
                            'event': 'session_start',
                        },
                    )
                    require(status == 200 and start_risk.get('release') is True,
                            'native_physical_session_id_must_be_admitted_distinct_namespace')

                    # Fresh sibling on an independent session executes useful work successfully on d2
                    c_fresh = SelectedLivenessClient(r_rig, 'restart-fresh-sibling', lease_secs=4)
                    c_fresh.initialize()
                    useful(c_fresh)
                    close_fresh = c_fresh.close()
                    grade_client_close(close_fresh, 'restart_fresh_sibling')

                    check_restart['passed'] = True

                finally:
                    if d1 is not None and d1.poll() is None:
                        try:
                            BASE.DEMO.stop(d1)
                            d1.wait(timeout=5)
                        except Exception:
                            if d1.poll() is None:
                                d1.kill()
                                d1.wait(timeout=5)
                    if d2 is not None and d2.poll() is None:
                        try:
                            BASE.DEMO.stop(d2)
                            d2.wait(timeout=5)
                        except Exception:
                            if d2.poll() is None:
                                d2.kill()
                                d2.wait(timeout=5)

                completed_all_cases = True

            finally:
                # TEARDOWN HAPPENS INSIDE THE TEMPORARY DIRECTORY CONTEXT BEFORE DELETION
                for d in (locals().get('d1'), locals().get('d2')):
                    if d is not None and getattr(d, 'poll', lambda: 0)() is None:
                        try:
                            BASE.DEMO.stop(d)
                            d.wait(timeout=5)
                        except Exception:
                            if d.poll() is None:
                                d.kill()
                                d.wait(timeout=5)
                if fs is not None:
                    try:
                        report['fs_cleanup'] = fs.close()
                        grade_rig_cleanup_result(report['fs_cleanup'], 'fs')
                    except Exception as ex:
                        if isinstance(report.get('fs_cleanup'), dict):
                            report['fs_cleanup']['grading_error'] = str(ex)
                        else:
                            report['fs_cleanup'] = {'error': str(ex)}
                        report['status'] = 'fail'
                        report['failed'] = report.get('failed', 0) + 1
                if git is not None:
                    try:
                        report['git_cleanup'] = git.close()
                        grade_rig_cleanup_result(report['git_cleanup'], 'git')
                    except Exception as ex:
                        if isinstance(report.get('git_cleanup'), dict):
                            report['git_cleanup']['grading_error'] = str(ex)
                        else:
                            report['git_cleanup'] = {'error': str(ex)}
                        report['status'] = 'fail'
                        report['failed'] = report.get('failed', 0) + 1

                cases_completed = locals().get('completed_all_cases', False) or (
                    len(report.get('checks', [])) >= len(REQUIRED_PRODUCTION_CASES)
                    and all(c.get('passed') is True for c in report.get('checks', []))
                    and {c.get('case') for c in report.get('checks', [])}.issuperset(set(REQUIRED_PRODUCTION_CASES))
                )
                if cases_completed and report.get('failed', 0) == 0:
                    report['source_after'] = BASE.source()
                    report['binary_unchanged'] = sha(args.agentfw.resolve()) == report['binary_sha256']
                    report['passed'] = len(report.get('checks', []))
                    report['selected_production_acceptance'] = True
                    report['status'] = 'pass'
                    try:
                        grade_selected_report(report, REQUIRED_PRODUCTION_CASES)
                    except Exception as ex:
                        report['status'] = 'fail'
                        report['failed'] = report.get('failed', 0) + 1
                        report['final_grading_error'] = str(ex)
                else:
                    if report.get('status') != 'fail':
                        report['status'] = 'incomplete' if not cases_completed else 'fail'
                    if report.get('failed', 0) == 0 and not cases_completed:
                        report['failed'] = 1

    except Exception as error:
        report['status'] = 'fail'
        report['failed'] = max(report.get('failed', 0), 1)
        report['error'] = str(error)
        report['traceback'] = traceback.format_exc()
    finally:
        if 'source_before' in report and 'source_after' not in report:
            try:
                report['source_after'] = BASE.source()
            except Exception:
                report['status'] = 'fail'
                report['failed'] = max(report.get('failed', 0), 1)
                report.setdefault('error', 'source_identity_observer_failed')
        report['checks_count'] = len(report.get('checks', []))
        write_selected_report(report_file, report)

    print(json.dumps(summary(report), indent=2))
    return 0 if report['status'] == 'pass' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='execute selected production acceptance')
    for name in ('agentfw', 'node', 'npm', 'bwrap', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--runtime-source-commit', required=True)
    parser.add_argument('--disposable-systemd-unit', required=True)
    parser.add_argument('--git', type=Path, required=True)
    parser.add_argument('--git-sha256', required=True)
    parser.add_argument('--git-launcher', type=Path, required=True)
    args = parser.parse_args()

    if not args.run:
        print(json.dumps({
            'status': 'plan',
            'executed': False,
            'mode': 'selected-production-acceptance',
            'required_linux': True,
            'required_delegation': True,
            'required_cases': len(REQUIRED_PRODUCTION_CASES),
        }))
        return 0

    return run_selected_acceptance(args)


if __name__ == '__main__':
    sys.exit(main())
