#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable Linux crash inventory and acceptance; no raw MCP output artifacts.

The baseline-inventory mode deliberately measures the accepted runtime before
any harness recovery. Its success means a complete inventory, never protection
acceptance. Missing prerequisites or an unobserved case fail the required job.
"""
from __future__ import annotations

import argparse
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = '2af2f35b326e0f70660b5c4cbde8134fe4ab9751'
FORMAT = 'sou86-linux-crash-supervision/1'
INVENTORY_MILLIS = 5000
ACCEPTANCE_MILLIS = 10000
INVENTORY_CASES = {
    'original-filesystem-collector-kill', 'original-filesystem-wrapper-kill',
    'owned-descendants-collector-kill', 'owned-descendants-wrapper-kill',
    'original-filesystem-restart',
}
CASES = {
    'original-filesystem-useful', 'original-git-useful',
    'original-filesystem-collector-kill', 'original-filesystem-unbudgeted-collector-kill',
    'original-git-collector-kill', 'original-git-unbudgeted-collector-kill',
    'owned-collector-kill', 'owned-unbudgeted-collector-kill',
    'owned-owner-kill', 'owned-unbudgeted-owner-kill', 'owned-wrapper-kill', 'owned-pid1-kill',
    'owned-owner-stop',
    'armed-startup-collector-kill', 'cancel-crash', 'cleanup-race',
    'repeat-crash-1', 'repeat-crash-2', 'repeat-crash-3',
    'restart-after-crash', 'fixture-private-boundary', 'peer-isolation',
}
OWNER_FORMAT = 'sw-mcp/linux-crash-owner/1'
OWNER_REASONS = {
    'mcp_owner_active', 'mcp_owner_cleanup_verified', 'mcp_owner_cleanup_unverified',
    'mcp_owner_lost', 'mcp_owner_control_failed', 'mcp_owner_control_invalid',
    'mcp_owner_stop_requested', 'mcp_owner_startup_failed', 'mcp_owner_parent_lost',
    'mcp_owner_control_closed', 'mcp_owner_namespace_lost',
    'mcp_owner_liveness_expired',
    'mcp_owner_sandbox_failed',
}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RESOURCE = load('sou86_resources', 'verify-sou79-resource-budgets.py')
GIT = load('sou86_git', 'verify-sou68-real-mcp.py')
BASE, require, sha, digest, write = RESOURCE.BASE, RESOURCE.require, RESOURCE.sha, RESOURCE.digest, RESOURCE.write
ORIGINAL_SAFE_EVENT = RESOURCE.safe_event


def safe_owner(value):
    if not isinstance(value, dict) or value.get('format') != OWNER_FORMAT:
        return None
    result = {'format': OWNER_FORMAT}
    if isinstance(value.get('instance'), str) and re.fullmatch(r'[a-f0-9]{32}', value['instance']):
        result['instance'] = value['instance']
    for key in ('owner_pid', 'owner_start_ticks', 'sandbox_pid', 'sandbox_start_ticks', 'pid1_pid',
                'pid1_start_ticks', 'startup_bound_ms', 'poll_ms', 'cleanup_bound_ms', 'heartbeat_ms', 'lease_ms'):
        if type(value.get(key)) is int and 0 < value[key] <= 2**63 - 1:
            result[key] = value[key]
    if type(value.get('failed')) is bool:
        result['failed'] = value['failed']
    if value.get('reason') in OWNER_REASONS:
        result['reason'] = value['reason']
    cleanup = value.get('cleanup')
    if isinstance(cleanup, dict) and cleanup.get('format') == OWNER_FORMAT:
        result['cleanup'] = {'format': OWNER_FORMAT}
        if 'instance' in result and cleanup.get('instance') == result['instance']:
            result['cleanup']['instance'] = cleanup['instance']
        for key in ('process_reaped', 'namespace_terminated', 'owned_resources_removed', 'runtime_failure'):
            if type(cleanup.get(key)) is bool:
                result['cleanup'][key] = cleanup[key]
        if cleanup.get('reason') in OWNER_REASONS:
            result['cleanup']['reason'] = cleanup['reason']
    return result


def safe_event(value):
    result = ORIGINAL_SAFE_EVENT(value)
    if isinstance(value, dict) and value.get('event') in {'mcp_real_owner_start', 'mcp_real_owner_end'}:
        result = {'event': value['event']}
        for key in ('cleanup_verified', 'observed_failure'):
            if type(value.get(key)) is bool:
                result[key] = value[key]
    if result is not None and (owner := safe_owner(value.get('owner'))) is not None:
        result['owner'] = owner
    return result


# This is a private imported module instance in this standalone process. Extend
# only its safe metadata projection; the accepted resource oracle is unchanged.
RESOURCE.safe_event = safe_event
RESOURCE.STATIC_REFUSALS |= OWNER_REASONS

FIXTURE = r'''// SOU-86 owned descendant fixture; not the upstream MCP server.
const fs=require('fs'), cp=require('child_process'), readline=require('readline');
const mode=process.argv[2];
if(mode==='--sou86-direct'||mode==='--sou86-detached') { setInterval(()=>{},1000); }
else {
 const init=JSON.parse(fs.readFileSync('/mcp-server/initialize.json'));
 const manifest=JSON.parse(fs.readFileSync('/mcp-server/manifest.json'));
 process.stderr.write(Buffer.from('534f5537395f505249564154455f5354444552525f43414e41525920736f7537392d73796e7468657469632d7365637265742d393163631b5b33316d0a','hex'));
 function result(id,text) { process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result:{content:[{type:'text',text}],structuredContent:{content:text}}})+'\n'); }
 readline.createInterface({input:process.stdin}).on('line',raw=>{
  const v=JSON.parse(raw); if(!('id' in v))return;
  if(v.method==='initialize') {const value=structuredClone(init.result);value.protocolVersion=v.params.protocolVersion;
   process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:v.id,result:value})+'\n');}
  else if(v.method==='tools/list')process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:v.id,result:manifest.result})+'\n');
  else if(v.method==='tools/call') {
   if(v.params.arguments.path==='/workspace/sou86-boundary') {
    const observed={private_lease_absent:true,host_control_fds_absent:true,pid1_private_fds_denied:false,pid1_memory_denied:false};
    for(const fd of fs.readdirSync('/proc/self/fd')) {
     try {
      const target=fs.readlinkSync('/proc/self/fd/'+fd);
      if(target.startsWith('socket:'))observed.private_lease_absent=false;
      if(target.includes('/sys/fs/cgroup')||target.includes('memfd:agentfw')||target.includes('anon_inode:[pidfd]')||target.includes('bwrap'))observed.host_control_fds_absent=false;
     }catch(_){}
    }
    try {fs.readdirSync('/proc/1/fd');}catch(e){observed.pid1_private_fds_denied=e.code==='EACCES'||e.code==='EPERM';}
    try {const fd=fs.openSync('/proc/1/mem','r');fs.closeSync(fd);}catch(e){observed.pid1_memory_denied=e.code==='EACCES'||e.code==='EPERM';}
    result(v.id,JSON.stringify(observed));
   } else if(v.params.arguments.path==='/workspace/sou86-block') {
    for(const detached of [false,true]) {
     // Inherit only owned protocol pipes. Opening /dev/null O_RDWR would be
     // correctly denied by the accepted read-only selected-profile sandbox.
     const child=cp.spawn(process.execPath,[__filename,detached?'--sou86-detached':'--sou86-direct'],{detached,stdio:[0,1,2]});
     child.on('error',()=>{});
    }
    setTimeout(()=>result(v.id,'late fixture result must remain withheld'),60000);
   } else result(v.id,fs.readFileSync(v.params.arguments.path,'utf8'));
  }
 });
}
'''


def prepare_delegation(unit):
    """The CI job authorizes exactly one fresh owned service, never host repair."""
    require(platform.system() == 'Linux' and os.geteuid() != 0, 'unprivileged_linux_required')
    require(re.fullmatch(r'sou86-[0-9]+-[0-9]+\.service', unit), 'owned_disposable_unit_required')
    expected = '/system.slice/' + unit
    require(Path('/proc/self/cgroup').read_text().strip() == '0::' + expected,
            'exact_owned_systemd_service_required')
    root = Path('/sys/fs/cgroup' + expected)
    require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.geteuid(),
            'service_delegation_ownership_required')
    require({'cpu', 'memory', 'pids'} <= set((root / 'cgroup.controllers').read_text().split()),
            'required_delegated_controllers_missing')
    require(not any(path.is_dir() for path in root.iterdir()), 'disposable_service_not_fresh')
    manager = root / 'manager'
    manager.mkdir(mode=0o700)
    (manager / 'cgroup.procs').write_text(str(os.getpid()))
    require(not (root / 'cgroup.procs').read_text().strip(), 'delegation_parent_not_empty')
    (root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    selected = root / 'budgets'
    selected.mkdir(mode=0o700)
    (selected / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    require(stat.S_IMODE(selected.stat().st_mode) == 0o700, 'private_budget_root_required')
    require(str(os.getpid()) in (manager / 'cgroup.procs').read_text().split(), 'observer_calibration_failed')
    return selected, {'unit': unit, 'unprivileged': True, 'manager_membership_verified': True,
                      'controllers': ['cpu', 'memory', 'pids'],
                      'capabilities': RESOURCE.delegation_capabilities(selected)}


def identity(pid):
    """Read bounded procfs identity and static owned-fixture roles only."""
    try:
        with Path(f'/proc/{pid}/stat').open('rb') as stream:
            raw = stream.read(8193)
        require(len(raw) <= 8192, 'process_stat_input_limit')
        fields = raw.rsplit(b')', 1)[1].split()
        with Path(f'/proc/{pid}/cmdline').open('rb') as stream:
            command = stream.read(4097)
        require(len(command) <= 4096, 'process_command_input_limit')
        argv = command.split(b'\0')
        role = next((name for name in ('direct', 'detached') if ('--sou86-' + name).encode() in argv), None)
        trusted = next((name for name, flag in (('owner', b'--agentfw-mcp-owner-v1'), ('pid1', b'--agentfw-mcp-pid1-v1'))
                        if flag in argv), None)
        return {'pid': pid, 'start_time_ticks': int(fields[19]), 'state': fields[0].decode('ascii'),
                'parent_pid': int(fields[1]), 'process_group': int(fields[2]), 'session': int(fields[3]),
                'fixture_role': role, 'trusted_role': trusted}
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return None
        raise


def same_process(row):
    current = identity(row['pid'])
    return current is not None and current['start_time_ticks'] == row['start_time_ticks']


def alive(row):
    current = identity(row['pid'])
    return (current is not None and current['start_time_ticks'] == row['start_time_ticks']
            and current['state'] not in ('Z', 'X', 'x'))


def signal_owned(pid, expected_start, executable, private_pid1=False, before_signal=None, requested_signal=None):
    """A pidfd binds the one verified target; no PID/group-wide search killing."""
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
    before = identity(pid)
    require(before is not None and before['start_time_ticks'] == expected_start, 'signal_target_identity_changed')
    expected = executable.stat()
    try:
        observed = Path(f'/proc/{pid}/exe').stat()
        require((observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino), 'signal_target_executable_changed')
    except PermissionError:
        # The trusted PID 1 deliberately disables dumpability. Its exact
        # authenticated startup identity, hidden command and nested PID 1
        # status have already been independently verified by verify_owner.
        require(private_pid1 and before.get('trusted_role') == 'pid1', 'signal_target_executable_unobservable')
    descriptor = os.pidfd_open(pid, 0)
    try:
        require(same_process(before), 'signal_target_identity_changed')
        if before_signal is not None:
            before_signal()
        try:
            signal.pidfd_send_signal(descriptor, requested_signal if requested_signal is not None else signal.SIGKILL, None, 0)
            before['signal_delivered'] = True
        except ProcessLookupError:
            require(before_signal is not None and not alive(before), 'signal_target_exited_before_injection')
            before['signal_delivered'] = False
    finally:
        os.close(descriptor)
    return before


def members(client):
    """Union independently sampled cgroup membership with current identities."""
    result = {}
    if client.kernel is not None:
        for member in client.kernel.members.copy().values():
            row = identity(member['pid'])
            if row is not None and row['start_time_ticks'] == member['start_time_ticks']:
                result[(row['pid'], row['start_time_ticks'])] = row
    for member in client.process_witness.observed.copy().values():
        row = identity(member['pid'])
        if row is not None and row['start_time_ticks'] == member['start_time_ticks']:
            result[(row['pid'], row['start_time_ticks'])] = row
    return result


def merge_members(observed, current):
    """Retain a witnessed role when the same process becomes a zombie.

    Linux clears a terminating task's cmdline. The current liveness/stat fields
    still replace the previous sample, but an already observed exact argv role
    and setsid witness belong to this PID/start identity for its whole life.
    """
    for key, member in current.items():
        value, previous = dict(member), observed.get(key, {})
        for role in ('fixture_role', 'trusted_role'):
            value[role] = value.get(role) or previous.get(role)
        value['detached_session_verified'] = previous.get('detached_session_verified', False) or (
            member.get('fixture_role') == 'detached' and member.get('session') == member['pid']
            and member.get('process_group') == member['pid'])
        observed[key] = value


def wait_descendants(client):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        observed = list(members(client).values())
        roles = {row['fixture_role']: row for row in observed if row['fixture_role'] is not None}
        if set(roles) == {'direct', 'detached'}:
            require(roles['detached']['session'] == roles['detached']['pid']
                    and roles['detached']['process_group'] == roles['detached']['pid'],
                    'detached_fixture_session_missing')
            return observed
        time.sleep(0.01)
    raise ValueError('owned_descendants_not_observed')


def leaf_removed(client):
    return client.kernel.path is not None and not client.kernel.path.exists()


def recover_leaf(client):
    """Inventory safety recovery AFTER the saved measurement; never proof."""
    path = client.kernel.path
    if path is None or not path.exists():
        return False
    require(path.parent == client.rig.delegation and RESOURCE.LEAF.fullmatch(path.name), 'unowned_recovery_target')
    require(RESOURCE.leaf_state(path, (client.kernel.device, client.kernel.inode)) == 'live', 'recovery_identity_changed')
    (path / 'cgroup.kill').write_text('1')
    until = time.monotonic() + 3
    while path.exists() and time.monotonic() < until:
        try:
            path.rmdir()
        except OSError as error:
            require(error.errno in (errno.EBUSY, errno.ENOTEMPTY), 'owned_recovery_remove_failed')
            time.sleep(0.01)
    require(not path.exists(), 'owned_recovery_incomplete')
    return True


def inventory_crash(rig, label, fixture, target, bwrap):
    client = RESOURCE.Client(rig, label, rig.fixture if fixture else rig.original)
    client.initialize()
    useful_hash = RESOURCE.useful(client)
    if fixture:
        client.send(RESOURCE.call(40, '/workspace/sou86-block'))
        RESOURCE.wait_dispatched(client, 40)
        wait_descendants(client)
    client.kernel.ready()
    observed = {}
    merge_members(observed, members(client))
    collector = identity(client.process.pid)
    require(collector is not None, 'collector_identity_missing')
    observed[(collector['pid'], collector['start_time_ticks'])] = collector
    if target == 'collector':
        selected, executable = collector, rig.binary
    else:
        starts = [event for event in client.stderr.events if event['event'] == 'mcp_real_server_start']
        require(len(starts) == 1, 'sandbox_start_identity_missing')
        selected, executable = identity(starts[0]['sandbox_pid']), bwrap
        require(selected is not None and (selected['pid'], selected['start_time_ticks']) in observed,
                'sandbox_identity_not_independently_observed')
    retained_input = client.process.stdin is not None and not client.process.stdin.closed
    injected = signal_owned(selected['pid'], selected['start_time_ticks'], executable)
    started = time.monotonic()
    deadline = started + INVENTORY_MILLIS / 1000
    stopped_at, removed_at = None, None
    while True:
        merge_members(observed, members(client))
        client.process.poll()  # Reap only our own collector if it has exited.
        now = time.monotonic()
        live = [row for row in observed.values() if alive(row)]
        if not live and stopped_at is None:
            stopped_at = now
        removed = leaf_removed(client)
        if removed and removed_at is None:
            removed_at = now
        if (not live and removed) or now >= deadline:
            break
        time.sleep(0.005)
    row = {'case': label, 'server_kind': 'owned-descendant-fixture' if fixture else 'original-filesystem',
           'in_flight': fixture, 'signal_target': target, 'signal': 'SIGKILL', 'target': injected,
           'stdin_held_open_at_injection': retained_input, 'useful_wire_sha256': useful_hash,
           'observation_bound_millis': INVENTORY_MILLIS,
           'observation_elapsed_millis': int((time.monotonic() - started) * 1000),
           'observed_processes': list(observed.values()), 'live_at_deadline': live,
           'identities_present_at_deadline': [item for item in observed.values() if same_process(item)],
           'protected_work_stopped_within_bound': stopped_at is not None,
           'process_stop_millis': int((stopped_at - started) * 1000) if stopped_at is not None else None,
           'leaf_removed_within_bound': removed,
           'leaf_remove_millis': int((removed_at - started) * 1000) if removed_at is not None else None,
           'leaf': client.kernel.path.name, 'leaf_inode': client.kernel.inode,
           'native_retirement': 'existing_300s_idle_expiry_on_next_authenticated_event',
           'immediate_native_retirement_claimed': False,
           'previous_effects_rolled_back': False, 'protection_acceptance': False}
    # Keep measurements immutable: orderly exit or the following explicit
    # recovery may remove a resource only after the deadline observation.
    row['client'] = client.close()
    row['inventory_recovery_used'] = recover_leaf(client)
    return row


def install_fixture(rig):
    package = Path(rig.fixture['packageRoot'])
    entry = package / 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'
    entry.write_text(FIXTURE)
    rig.fixture['packageTreeSha256'] = BASE.INSTALL.tree_sha(package)


class GitRig(RESOURCE.Rig):
    """A separately pinned original Git profile and private authenticating daemon."""
    def __init__(self, args, private, delegation):
        self.private, self.binary, self.delegation = private, args.agentfw.resolve(), delegation
        self.clients, self.kind = [], 'git'
        self.home, self.workspace = private / 'home', private / 'workspace'
        self.home.mkdir(mode=0o700)
        self.env = BASE.environment(self.home)
        self.env.update(GIT_PYTHON_GIT_EXECUTABLE=str(args.git.resolve()), GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_CONFIG_NOSYSTEM='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
        GIT.prepare_repo(self.workspace, args.git.resolve(), self.env)
        installed = private / 'original'
        GIT.INSTALL.install(installed, self.workspace, args.git.resolve(), args.git_sha256,
                            args.bwrap.resolve(), args.git_launcher.resolve())
        self.original = json.loads((installed / 'profile.json').read_text())
        self.installation = json.loads((installed / 'installation.json').read_text())
        result = subprocess.run([str(self.binary), 'install'], env=self.env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, timeout=30)
        require(result.returncode == 0, 'private_git_agent_install_failed')
        self.port = BASE.DEMO.free_port()
        self.config = {'port': self.port, 'enforce': True, 'policy': str(installed / 'policy.yaml'),
                       'native': {'registry_path': str(installed / 'registry.json'),
                                  'registry_sha256': sha(installed / 'registry.json')}}
        write(self.home / '.agentfw/config.yaml', self.config)
        self.daemon = subprocess.Popen([str(self.binary), 'serve'], env=self.env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.daemon_witness = BASE.ProcessWitness(self.daemon.pid)
        self.daemon_stdout, self.daemon_stderr = RESOURCE.Capture(self.daemon.stdout), RESOURCE.Capture(self.daemon.stderr)
        if not BASE.DEMO.wait_healthy(self.port, self.daemon):
            BASE.DEMO.stop(self.daemon)
            self.daemon_witness.finish()
            self.daemon_stdout.finish()
            self.daemon_stderr.finish()
            raise ValueError('owned_git_daemon_unavailable')


class ProtectedClient(RESOURCE.Client):
    def __init__(self, rig, label, fixture=False, budgeted=True, direct=False):
        self.rig, self.label, self.forced, self.closed = rig, label, False, False
        self.kind, self.direct, self.next_id = getattr(rig, 'kind', 'filesystem'), direct, 10
        selected = rig.fixture if fixture else rig.original
        self.profile_path = rig.private / (label + '-profile.json')
        write(self.profile_path, selected)
        self.limits = RESOURCE.budget(rig.delegation) if budgeted and not direct else None
        self.budget_path = rig.private / (label + '-budget.json') if self.limits else None
        env = dict(rig.env, AGENTFW_MCP_SERVER_PROFILE=str(self.profile_path), AGENTFW_CLASSIFIER='rule-baseline',
                   AGENTFW_RULE_BASELINE=str(ROOT / ('rule_baseline/git_readonly_v1/rule_baseline.py'
                       if self.kind == 'git' else 'rule_baseline/rule_baseline.py')),
                   AGENTFW_CLASSIFIER_PYTHON=sys.executable)
        env.pop('AGENTFW_MCP_LINUX_BUDGET', None)
        if self.limits:
            write(self.budget_path, self.limits)
            env['AGENTFW_MCP_LINUX_BUDGET'] = str(self.budget_path)
        if self.kind == 'git':
            server = [selected['runtimePath'], '-I', '-B', '-m', 'mcp_server_git', '--repository',
                      str(rig.workspace) if direct else '/workspace']
        else:
            server = [selected['runtimePath'], str(Path(selected['packageRoot']) /
                      'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'),
                      str(rig.workspace) if direct else '/workspace']
        # Reuse the user-facing collector ID after crashes. Native epochs and
        # private owners must still be fresh; request ID 10 is reused only on a
        # new transport. No previous receipt is imported into this process.
        command = server if direct else [str(rig.binary), 'mcp', '--native-admission', '--id', 'sou86-recovery', '--', *server]
        self.kernel = RESOURCE.KernelObserver(rig.delegation) if self.limits else None
        self.process = subprocess.Popen(command, env=rig.env if direct else env, cwd=rig.workspace,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)
        self.process_witness = BASE.ProcessWitness(self.process.pid)
        self.stdout, self.stderr = RESOURCE.Capture(self.process.stdout, True), RESOURCE.Capture(self.process.stderr)
        self.epoch, self.owner = None, None
        rig.clients.append(self)

    def initialize(self):
        protocol = '2025-11-25' if self.kind == 'git' else '2025-06-18'
        response, _ = self.exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': protocol, 'capabilities': {}, 'clientInfo': {'name': 'sou86-owned', 'version': '1'}}})
        require(response.get('result', {}).get('protocolVersion') == protocol, 'original_initialization_changed')
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        response, _ = self.exchange({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        assets = GIT.INSTALL.ASSETS if self.kind == 'git' else BASE.INSTALL.ASSETS
        expected = json.loads((assets / 'upstream-tools-list.json').read_text())['result']
        require(response.get('result') == expected, 'original_discovery_changed')
        if not self.direct:
            self.owner = verify_owner(self)
            self.epoch = next((row['session'] for row in reversed(self.rig.audit()['rows'])
                               if row.get('event') == 'native_session_start'), None)
            require(self.epoch is not None, 'authenticated_native_epoch_missing')
        if self.kernel:
            self.kernel.ready()

    def close(self, expect_failure=False):
        if self.closed:
            return self.result
        if self.process.stdin is not None and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.forced = True
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        self.result = {'case': self.label, 'server_kind': self.kind, 'budgeted': self.limits is not None,
            'direct_original_control': self.direct, 'epoch': self.epoch, 'owner': self.owner,
            'exit_code': self.process.returncode, 'forced_cleanup': self.forced,
            'profile_sha256': sha(self.profile_path),
            'budget_sha256': digest(json.dumps(self.limits, sort_keys=True, separators=(',', ':')).encode()) if self.limits else None,
            'process': self.process_witness.finish(), 'stdout': self.stdout.finish(), 'stderr': self.stderr.finish(),
            'kernel': self.kernel.finish() if self.kernel else None}
        self.closed = True
        return self.result


def useful(client, expected_hash=None):
    identifier, client.next_id = client.next_id, client.next_id + 1
    if client.kind == 'git':
        response, raw = client.exchange(GIT.call(identifier, repo=client.rig.workspace if client.direct else '/workspace'))
        require('SOU-68 synthetic initial commit' in GIT.text(response), 'original_git_useful_result_changed')
    else:
        response, raw = client.exchange(RESOURCE.call(identifier,
            str(client.rig.workspace / 'notes.txt') if client.direct else '/workspace/notes.txt'))
        require(BASE.result_text(response) == RESOURCE.TEXT, 'original_filesystem_useful_result_changed')
    if expected_hash is not None:
        require(digest(raw) == expected_hash, 'original_useful_wire_bytes_changed')
    return digest(raw)


def verify_owner(client):
    deadline = time.monotonic() + 10
    owner = None
    while owner is None and time.monotonic() < deadline:
        owner = next((event['owner'] for event in client.stderr.events if event.get('owner')
                      and event['event'] in {'mcp_real_owner_start', 'mcp_real_server_start'}), None)
        if owner is None:
            time.sleep(0.005)
    require(owner is not None, 'armed_owner_metadata_missing')
    require(owner.get('format') == OWNER_FORMAT and re.fullmatch(r'[a-f0-9]{32}', owner.get('instance', '')),
            'owner_startup_identity_missing')
    require(all(owner.get(key) == value for key, value in {'startup_bound_ms': 3000, 'poll_ms': 25,
            'cleanup_bound_ms': 3000, 'heartbeat_ms': 100, 'lease_ms': 1500}.items()), 'owner_contract_changed')
    identities = {}
    for role, pid_key, ticks_key in (('owner', 'owner_pid', 'owner_start_ticks'),
                                    ('wrapper', 'sandbox_pid', 'sandbox_start_ticks'),
                                    ('pid1', 'pid1_pid', 'pid1_start_ticks')):
        row = identity(owner[pid_key])
        require(row is not None and row['start_time_ticks'] == owner[ticks_key], 'owner_process_identity_changed')
        if role != 'wrapper':
            require(row['trusted_role'] == role, 'trusted_owner_command_identity_changed')
        identities[role] = row
    require(identities['owner']['parent_pid'] == client.process.pid
            and identities['wrapper']['parent_pid'] == identities['owner']['pid'], 'owner_process_ancestry_changed')
    with Path(f"/proc/{identities['pid1']['pid']}/status").open('rb') as status:
        raw = status.read(32769)
    require(len(raw) <= 32768, 'owner_status_input_limit')
    nested = next((line.split()[1:] for line in raw.splitlines() if line.startswith(b'NSpid:')), [])
    require(len(nested) >= 2 and int(nested[-1]) == 1 and int(nested[0]) == identities['pid1']['pid'],
            'trusted_namespace_pid1_not_observed')
    if client.kernel is not None:
        client.kernel.ready()
        expected = ('0::' + str(client.kernel.path).removeprefix('/sys/fs/cgroup')).encode()
        for role in ('owner', 'pid1'):
            with Path(f"/proc/{identities[role]['pid']}/cgroup").open('rb') as membership:
                actual = membership.read(8193)
            require(len(actual) <= 8192, 'owner_membership_input_limit')
            require((actual.strip() == expected) == (role == 'pid1'), 'owner_budget_membership_wrong')
    return copy.deepcopy(owner)


def observe_crash(client, target, bwrap, fixture=False, startup=False, cleanup_race=False, stopped_guardian=False):
    owner = client.owner or verify_owner(client)
    client.owner = owner
    initial = {}
    merge_members(initial, members(client))
    for key, ticks in (('owner_pid', 'owner_start_ticks'), ('sandbox_pid', 'sandbox_start_ticks'), ('pid1_pid', 'pid1_start_ticks')):
        row = identity(owner[key])
        require(row is not None and row['start_time_ticks'] == owner[ticks], 'owner_target_identity_changed')
        initial[(row['pid'], row['start_time_ticks'])] = row
    collector = identity(client.process.pid)
    require(collector is not None, 'collector_identity_missing')
    initial[(collector['pid'], collector['start_time_ticks'])] = collector
    if target == 'collector':
        selected, executable = collector, client.rig.binary
    else:
        pid_key = {'owner': 'owner_pid', 'wrapper': 'sandbox_pid', 'pid1': 'pid1_pid'}[target]
        selected, executable = identity(owner[pid_key]), bwrap if target == 'wrapper' else client.rig.binary
    require(selected is not None, 'crash_target_missing')
    input_open = not client.process.stdin.closed
    started = time.monotonic()
    injected = signal_owned(selected['pid'], selected['start_time_ticks'], executable,
                            private_pid1=target == 'pid1',
                            before_signal=client.process.stdin.close if cleanup_race else None,
                            requested_signal=signal.SIGSTOP if stopped_guardian else signal.SIGKILL)
    stop_observed = False
    if stopped_guardian:
        stop_deadline = time.monotonic() + 0.5
        while time.monotonic() < stop_deadline:
            state = identity(selected['pid'])
            if state is not None and state['start_time_ticks'] == selected['start_time_ticks'] and state['state'] in ('T', 't'):
                stop_observed = True
                break
            time.sleep(0.002)
        require(stop_observed, 'guardian_sigstop_not_independently_observed')
    deadline = started + ACCEPTANCE_MILLIS / 1000
    stopped_at, gone_at, removed_at = None, None, None
    while True:
        merge_members(initial, members(client))
        client.process.poll()
        now = time.monotonic()
        live = [row for row in initial.values() if alive(row)]
        present = [row for row in initial.values() if same_process(row)]
        removed = client.kernel is None or leaf_removed(client)
        if not live and stopped_at is None:
            stopped_at = now
        if not present and gone_at is None:
            gone_at = now
        if removed and removed_at is None:
            removed_at = now
        if (not present and removed) or now >= deadline:
            break
        time.sleep(0.005)
    row = {'case': client.label, 'server_kind': 'owned-descendant-fixture' if fixture else client.kind,
           'signal_target': target, 'signal': 'SIGSTOP' if stopped_guardian else 'SIGKILL',
           'guardian_stop_observed': stop_observed, 'target': injected, 'owner': owner, 'armed_before_signal': True,
           'in_flight': fixture, 'startup': startup, 'cleanup_race': cleanup_race,
           'stdin_held_open_at_injection': input_open, 'observation_bound_millis': ACCEPTANCE_MILLIS,
           'observed_processes': list(initial.values()), 'live_at_deadline': live,
           'identities_present_at_deadline': present, 'protected_work_stopped_within_bound': stopped_at is not None,
           'all_identities_gone_within_bound': gone_at is not None, 'leaf_removed_within_bound': removed,
           'process_stop_millis': int((stopped_at - started) * 1000) if stopped_at is not None else None,
           'identities_gone_millis': int((gone_at - started) * 1000) if gone_at is not None else None,
           'leaf_remove_millis': int((removed_at - started) * 1000) if removed_at is not None else None,
           'protection_acceptance': True, 'previous_effects_rolled_back': False,
           'native_retirement': 'existing_300s_idle_expiry_on_next_authenticated_event',
           'immediate_native_retirement_claimed': False, 'budgeted': client.limits is not None}
    row['client'] = client.close()
    row['acceptance_fallback_used'] = recover_leaf(client) if client.kernel else False
    return row


def cancel_pending(client):
    """Own real FIFO writers, with no release until after crash observation."""
    client.send(*(RESOURCE.call(20 + index, f'/workspace/blocked-{index}.fifo') for index in range(8)))
    descriptors = []
    try:
        deadline = time.monotonic() + 15
        for index in range(8):
            while True:
                try:
                    descriptors.append(os.open(client.rig.workspace / f'blocked-{index}.fifo', os.O_WRONLY | os.O_NONBLOCK))
                    break
                except OSError as error:
                    require(error.errno == errno.ENXIO and time.monotonic() < deadline, 'actual_parallel_fifo_read_missing')
                    time.sleep(0.005)
        client.send(RESOURCE.call(28, '/workspace/blocked-8.fifo'))
        deadline = time.monotonic() + 10
        while not any(event.get('host_call_id') == 28 and event.get('state') == 'queued' for event in client.stderr.events):
            require(time.monotonic() < deadline, 'queued_cancel_barrier_missing')
            time.sleep(0.005)
        for identifier in (28, 20):
            client.send(BASE.cancel(identifier))
            response, _ = client.receive()
            require(response.get('id') == identifier and response.get('error', {}).get('code') == -32800,
                    'original_call_cancel_failed')
        try:
            unexpected = os.open(client.rig.workspace / 'blocked-8.fifo', os.O_WRONLY | os.O_NONBLOCK)
        except OSError as error:
            require(error.errno == errno.ENXIO, 'queued_fifo_probe_failed')
        else:
            os.close(unexpected)
            raise ValueError('cancelled_queued_call_dispatched')
        return descriptors, {'independent_inflight_fifo_readers': len(descriptors), 'cancelled_ids': [28, 20],
                             'queued_reader_absent': True, 'bytes_written_before_crash': 0}
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def startup_inventory(rig):
    client = ProtectedClient(rig, 'prearm-startup-inventory')
    deadline = time.monotonic() + 10
    while client.kernel.path is None:
        require(time.monotonic() < deadline, 'startup_owned_leaf_not_observed')
        time.sleep(0.001)
    observed = {}
    merge_members(observed, members(client))
    collector = identity(client.process.pid)
    require(collector is not None, 'startup_collector_identity_missing')
    observed[(collector['pid'], collector['start_time_ticks'])] = collector
    authenticated = any(event.get('owner') for event in client.stderr.events)
    started = time.monotonic()
    signal_owned(collector['pid'], collector['start_time_ticks'], rig.binary)
    deadline = started + ACCEPTANCE_MILLIS / 1000
    while time.monotonic() < deadline:
        merge_members(observed, members(client))
        client.process.poll()
        if leaf_removed(client) and not any(same_process(row) for row in observed.values()):
            break
        time.sleep(0.005)
    live = [row for row in observed.values() if alive(row)]
    removed = leaf_removed(client)
    empty = removed or not (client.kernel.path / 'cgroup.procs').read_text().strip()
    row = {'case': 'prearm-startup-inventory', 'protection_acceptance': False,
           'ownership_authenticated_at_injection': authenticated,
           'arm_state': 'authenticated' if authenticated else 'not-authenticated-at-injection',
           'observed_processes': list(observed.values()), 'live_at_deadline': live,
           'leaf_removed_within_bound': removed, 'empty_at_deadline': empty,
           'observation_bound_millis': ACCEPTANCE_MILLIS,
           'cleanup_status': 'removed' if removed else 'unverified-empty-startup-leaf',
           'immediate_native_retirement_claimed': False}
    row['client'] = client.close()
    row['inventory_recovery_used'] = recover_leaf(client)
    require(not live and empty, 'startup_inventory_protected_work_survived')
    return row


def exercise_acceptance(args, fs, git, report):
    controls = {}
    for rig, kind in ((fs, 'filesystem'), (git, 'git')):
        control = ProtectedClient(rig, 'direct-original-' + kind, direct=True)
        control.initialize()
        controls[kind] = useful(control)
        report['original_controls'].append({'kind': kind, 'wire_sha256': controls[kind], 'client': control.close()})
    peer = ProtectedClient(fs, 'peer-isolation')
    peer.initialize()
    useful(peer, controls['filesystem'])
    peer_hashes = []
    report['peer_checks'] = []

    def peer_before():
        identifier = peer.next_id
        return {'id': identifier, 'sha256': useful(peer)}

    def peer_after(case, before):
        identifier = peer.next_id
        hashed = useful(peer)
        peer_hashes.append(hashed)
        report['peer_checks'].append({'case': case, 'before': before, 'after': {'id': identifier, 'sha256': hashed}})

    for rig, kind in ((fs, 'filesystem'), (git, 'git')):
        normal = ProtectedClient(rig, 'original-' + kind + '-useful')
        normal.initialize()
        wire = useful(normal, controls[kind])
        report['acceptance'].append({'case': normal.label, 'client': normal.close(), 'useful_wire_sha256': wire,
                                     'protection_acceptance': True})
    boundary = ProtectedClient(fs, 'fixture-private-boundary', fixture=True)
    boundary.initialize()
    useful(boundary)
    response, _ = boundary.exchange(RESOURCE.call(30, '/workspace/sou86-boundary'))
    witness = json.loads(BASE.result_text(response))
    require(set(witness) == {'private_lease_absent', 'host_control_fds_absent', 'pid1_private_fds_denied', 'pid1_memory_denied'}
            and all(value is True for value in witness.values()), 'private_owner_boundary_not_observed')
    report['acceptance'].append({'case': boundary.label, 'client': boundary.close(),
                                 'private_boundary': witness, 'protection_acceptance': True})
    for kind, rig in (('filesystem', fs), ('git', git)):
        for budgeted in (True, False):
            name = 'original-' + kind + ('-' if budgeted else '-unbudgeted-') + 'collector-kill'
            before_peer = peer_before()
            client = ProtectedClient(rig, name, budgeted=budgeted)
            client.initialize()
            wire = useful(client, controls[kind])
            row = observe_crash(client, 'collector', args.bwrap.resolve())
            row['useful_wire_sha256'] = wire
            report['acceptance'].append(row)
            peer_after(name, before_peer)
    for name, target, budgeted in (
        ('owned-collector-kill', 'collector', True),
        ('owned-unbudgeted-collector-kill', 'collector', False),
        ('owned-owner-kill', 'owner', True),
        ('owned-owner-stop', 'owner', True),
        ('owned-unbudgeted-owner-kill', 'owner', False),
        ('owned-wrapper-kill', 'wrapper', True),
        ('owned-pid1-kill', 'pid1', True),
        ('repeat-crash-1', 'collector', True),
        ('repeat-crash-2', 'collector', True),
        ('repeat-crash-3', 'collector', True),
    ):
        before_peer = peer_before()
        client = ProtectedClient(fs, name, fixture=True, budgeted=budgeted)
        client.initialize()
        useful(client)
        client.send(RESOURCE.call(40, '/workspace/sou86-block'))
        RESOURCE.wait_dispatched(client, 40)
        wait_descendants(client)
        report['acceptance'].append(observe_crash(client, target, args.bwrap.resolve(), fixture=True,
                                                stopped_guardian=name == 'owned-owner-stop'))
        peer_after(name, before_peer)
    before_peer = peer_before()
    startup = ProtectedClient(fs, 'armed-startup-collector-kill')
    startup.owner = verify_owner(startup)
    report['acceptance'].append(observe_crash(startup, 'collector', args.bwrap.resolve(), startup=True))
    peer_after(startup.label, before_peer)
    before_peer = peer_before()
    cancelled = ProtectedClient(fs, 'cancel-crash')
    cancelled.initialize()
    useful(cancelled)
    descriptors, cancellation = cancel_pending(cancelled)
    try:
        row = observe_crash(cancelled, 'collector', args.bwrap.resolve())
        row['cancellation'] = cancellation
        report['acceptance'].append(row)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    peer_after(cancelled.label, before_peer)
    before_peer = peer_before()
    race = ProtectedClient(fs, 'cleanup-race')
    race.initialize()
    useful(race)
    report['acceptance'].append(observe_crash(race, 'collector', args.bwrap.resolve(), cleanup_race=True))
    peer_after(race.label, before_peer)
    before_peer = peer_before()
    restarted = ProtectedClient(fs, 'restart-after-crash')
    restarted.initialize()
    wire = useful(restarted, controls['filesystem'])
    concurrency = RESOURCE.concurrency_cancel(restarted)
    report['acceptance'].append({'case': restarted.label, 'client': restarted.close(), 'useful_wire_sha256': wire,
                                 'concurrency': concurrency, 'protection_acceptance': True})
    peer_after(restarted.label, before_peer)
    before_peer = peer_before()
    report['startup_inventory'] = startup_inventory(fs)
    peer_after('prearm-startup-inventory', before_peer)
    report['acceptance'].append({'case': peer.label, 'client': peer.close(),
                                 'useful_followups': len(peer_hashes), 'followup_wire_hashes': peer_hashes,
                                 'protection_acceptance': True})


def grade_crash(row):
    require(row.get('protection_acceptance') is True and row.get('armed_before_signal') is True,
            'unarmed_launch_counted_as_protected')
    require(row['observation_bound_millis'] == ACCEPTANCE_MILLIS and row['observed_processes'], 'crash_observer_unbound')
    require(row['stdin_held_open_at_injection'] is True, 'collector_input_was_not_retained')
    require(row['protected_work_stopped_within_bound'] is True and row['all_identities_gone_within_bound'] is True
            and row['leaf_removed_within_bound'] is True and not row['live_at_deadline']
            and not row['identities_present_at_deadline'], 'crash_cleanup_incomplete')
    require(not row['acceptance_fallback_used'] and not row['client']['forced_cleanup'], 'harness_recovery_mislabeled_as_production')
    require(row.get('cleanup_race') is True or row['client']['exit_code'] not in (None, 0),
            'unexpected_owner_failure_reported_success')
    require(row['target'].get('signal_delivered') is True or row.get('cleanup_race') is True, 'crash_signal_not_delivered')
    if row['case'] == 'owned-owner-stop':
        require(row['signal'] == 'SIGSTOP' and row['guardian_stop_observed'] is True,
                'guardian_liveness_failure_not_exercised')
    for key in ('process_stop_millis', 'identities_gone_millis', 'leaf_remove_millis'):
        require(type(row[key]) is int and 0 <= row[key] <= ACCEPTANCE_MILLIS, 'crash_cleanup_deadline_exceeded')
    owner = row['owner']
    require(owner.get('format') == OWNER_FORMAT and re.fullmatch(r'[a-f0-9]{32}', owner.get('instance', '')),
            'crash_owner_identity_missing')
    for pid_key, ticks_key in (('owner_pid', 'owner_start_ticks'), ('sandbox_pid', 'sandbox_start_ticks'), ('pid1_pid', 'pid1_start_ticks')):
        require(any(member['pid'] == owner.get(pid_key) and member['start_time_ticks'] == owner.get(ticks_key)
                    for member in row['observed_processes']), 'trusted_process_not_independently_observed')
    require(row['immediate_native_retirement_claimed'] is False and row['previous_effects_rolled_back'] is False
            and row['native_retirement'] == 'existing_300s_idle_expiry_on_next_authenticated_event',
            'process_cleanup_misrepresented_as_authority_or_rollback')
    if row['in_flight']:
        require({member.get('fixture_role') for member in row['observed_processes'] if member.get('fixture_role')}
                == {'direct', 'detached'}, 'actual_detached_workers_missing')
        require(not any(item.get('id') == 40 and item.get('successful_result') is True
                        for item in row['client']['stdout']['records']), 'late_unadmitted_result_released')


def grade_acceptance(report):
    require(report['format'] == FORMAT and report['mode'] == 'acceptance' and report['protection_acceptance'] is True,
            'required_protection_acceptance_missing')
    require(report.get('failed') == report.get('skipped') == 0 and report.get('required_cases') == len(CASES),
            'required_protection_denominator_incomplete')
    require(report['source_before'] == report['source_after'] and report['source_before']['dirty'] is False
            and report['runtime_source_commit'] == report['source_before']['commit'] and report['binary_unchanged'],
            'candidate_source_or_binary_changed')
    require(report['original_unchanged'] and report['git_original_unchanged'] and report['workspace_unchanged']
            and report['git_workspace_unchanged'] and report['delegation_removed'], 'owned_state_changed_or_not_removed')
    for key in ('binary_sha256', 'driver_sha256', 'fixture_sha256', 'fixture_package_tree_sha256',
                'config_sha256', 'git_config_sha256', 'git_binary_sha256', 'git_launcher_sha256'):
        require(isinstance(report.get(key), str) and re.fullmatch(r'[a-f0-9]{64}', report[key]), 'candidate_identity_missing')
    for key in ('original_server', 'original_git_server'):
        installed = report.get(key, {})
        require(all(isinstance(installed.get(name), str) and re.fullmatch(r'[a-f0-9]{64}', installed[name])
                    for name in ('profile_sha256', 'registry_sha256', 'policy_sha256'))
                and re.fullmatch(r'[a-f0-9]{64}', installed.get('profile', {}).get('packageTreeSha256', '')),
                'original_installation_identity_missing')
    rows = {row['case']: row for row in report['acceptance']}
    require(set(rows) == CASES and len(report['acceptance']) == len(CASES), 'required_protected_cases_missing')
    controls = {row['kind']: row for row in report['original_controls']}
    require(set(controls) == {'filesystem', 'git'}, 'both_original_server_controls_required')
    owners, epochs = [], []
    for row in [*report['acceptance'], *report['original_controls']]:
        client = row['client']
        require(not client['forced_cleanup'] and client['process']['all_stopped'] and not client['process']['remaining'],
                'owned_process_cleanup_incomplete')
        RESOURCE.clean_stream(client['stdout'])
        RESOURCE.clean_stream(client['stderr'])
        if client.get('direct_original_control'):
            require(client['exit_code'] == 0, 'original_control_failed')
            continue
        require(client.get('owner') is not None, 'protected_owner_metadata_missing')
        owners.append(client['owner']['instance'])
        if client.get('epoch') is not None:
            epochs.append(client['epoch'])
        kernel = client.get('kernel')
        if client['budgeted']:
            require(kernel and kernel['thread_stopped'] and kernel['error'] is None and kernel['samples'] > 0
                    and kernel['leaf_removed'] and not kernel['remaining'] and kernel['members'],
                    'independent_owned_cgroup_cleanup_incomplete')
        if row.get('signal_target'):
            grade_crash(row)
        else:
            require(client['exit_code'] == 0, 'ordinary_useful_collector_failed')
            ends = [event for event in client['stderr']['events'] if event['event'] == 'mcp_real_server_end']
            require(len(ends) == 1 and ends[0].get('cleanup_verified') is True, 'ordinary_structured_cleanup_unverified')
        if 'useful_wire_sha256' in row:
            kind = client['server_kind']
            require(row['useful_wire_sha256'] == controls[kind]['wire_sha256']
                    and any(frame.get('id') == 10 and frame.get('sha256') == row['useful_wire_sha256']
                            and frame.get('successful_result') is True for frame in client['stdout']['records']),
                    'original_useful_bytes_not_preserved')
    require(len(owners) == len(set(owners)) and len(epochs) == len(set(epochs)), 'stale_owner_or_native_epoch_reused')
    cancelled = rows['cancel-crash']
    require(cancelled['cancellation'] == {'independent_inflight_fifo_readers': 8, 'cancelled_ids': [28, 20],
            'queued_reader_absent': True, 'bytes_written_before_crash': 0}, 'cancellation_crash_race_not_exercised')
    require(not any(frame.get('id') in (20, 28) and frame.get('successful_result') is True
                    for name in ('cancel-crash', 'restart-after-crash') for frame in rows[name]['client']['stdout']['records']),
            'cancelled_or_stale_result_released')
    boundary = rows['fixture-private-boundary']['private_boundary']
    require(set(boundary) == {'private_lease_absent', 'host_control_fds_absent', 'pid1_private_fds_denied', 'pid1_memory_denied'}
            and all(value is True for value in boundary.values()), 'private_owner_lease_boundary_failed')
    expected_peers = {name for name, row in rows.items() if row.get('signal_target')} | {'restart-after-crash', 'prearm-startup-inventory'}
    peer_checks = report.get('peer_checks', [])
    require(len(peer_checks) == len(expected_peers) and {item['case'] for item in peer_checks} == expected_peers
            and rows['peer-isolation']['useful_followups'] == len(expected_peers), 'unaffected_peer_followups_missing')
    peer_records = rows['peer-isolation']['client']['stdout']['records']
    for item in peer_checks:
        require(item['before']['id'] < item['after']['id'] and all(any(frame.get('id') == witness['id']
                and frame.get('sha256') == witness['sha256'] and frame.get('successful_result') is True
                for frame in peer_records) for witness in (item['before'], item['after'])), 'independent_peer_before_after_missing')
    startup = report['startup_inventory']
    require(startup['protection_acceptance'] is False and startup['empty_at_deadline'] is True
            and not startup['live_at_deadline'], 'prearm_inventory_mislabeled_or_unsafe')
    calibration = report['stream_calibration']
    require(calibration['stderr']['marker_leak'] is True and calibration['stderr']['thread_stopped']
            and calibration['stderr']['sha256'] == digest(RESOURCE.CALIBRATION_BYTES), 'stream_observer_not_calibrated')
    for cleanup in (report['cleanup'], report['git_cleanup']):
        require(cleanup['daemon_process']['all_stopped'] and not cleanup['audit']['marker_leak'], 'owned_daemon_or_audit_incomplete')
        RESOURCE.clean_stream(cleanup['daemon_stdout'])
        RESOURCE.clean_stream(cleanup['daemon_stderr'])
    report['checks'] = [{'case': name, 'passed': True, 'protection_acceptance': True} for name in sorted(CASES)]


def grade_inventory(report):
    require(report['format'] == FORMAT and report['mode'] == 'baseline-inventory'
            and report['runtime_source_commit'] == ACCEPTED, 'wrong_inventory_runtime')
    require(report.get('failed') == report.get('skipped') == 0 and report.get('required_cases') == len(INVENTORY_CASES),
            'required_inventory_denominator_incomplete')
    require(report['source_before'] == report['source_after'] and report['source_before']['dirty'] is False
            and report['binary_unchanged'], 'source_or_binary_changed')
    require(report['delegation']['unprivileged'] and report['delegation']['manager_membership_verified'],
            'ordinary_user_delegation_missing')
    require(report['original_unchanged'] and report['workspace_unchanged'] and report['delegation_removed'],
            'owned_state_changed_or_not_removed')
    rows = {row['case']: row for row in report['inventory']}
    require(set(rows) == INVENTORY_CASES and len(report['inventory']) == len(INVENTORY_CASES), 'inventory_cases_missing')
    for name, row in rows.items():
        client = row['client']
        require(client['exit_code'] is not None and not client['forced_cleanup'], 'inventory_collector_did_not_close')
        RESOURCE.clean_stream(client['stdout'])
        RESOURCE.clean_stream(client['stderr'])
        kernel = client.get('kernel') or {}
        require(kernel.get('thread_stopped') is True and kernel.get('error') is None
                and kernel.get('samples', 0) > 0 and kernel.get('members'), 'independent_inventory_observer_incomplete')
        require(isinstance(row.get('useful_wire_sha256'), str)
                and re.fullmatch(r'[a-f0-9]{64}', row['useful_wire_sha256'])
                and any(item.get('id') == 10 and item.get('successful_result') is True
                        and item.get('sha256') == row['useful_wire_sha256'] for item in client['stdout']['records']),
                'original_useful_work_not_observed')
        if name == 'original-filesystem-restart':
            require(client['exit_code'] == 0 and client['kernel']['leaf_removed'], 'original_restart_failed')
            continue
        require(row['stdin_held_open_at_injection'] and row['observed_processes'], 'signal_or_membership_not_observed')
        require(row['observation_bound_millis'] == INVENTORY_MILLIS and row['target']['start_time_ticks'] > 0,
                'crash_measurement_unbound')
        require(not any(item.get('id') == 40 and item.get('successful_result') is True
                        for item in client['stdout']['records']), 'late_fixture_result_released')
        if row['in_flight']:
            roles = {item['fixture_role'] for item in row['observed_processes'] if item['fixture_role'] is not None}
            require(roles == {'direct', 'detached'}, 'owned_descendant_inventory_missing')
    # Preserve the existing namespace/PDEATHSIG protection separately from the
    # actual new gap: the dead collector cannot remove its owned budget leaf.
    collector_rows = [row for row in rows.values() if row.get('signal_target') == 'collector']
    require(any(not row['leaf_removed_within_bound'] for row in collector_rows), 'accepted_gap_not_reproduced')
    require(report['protection_acceptance'] is False, 'inventory_mislabeled_as_protection')
    calibration = report['stream_calibration']
    require(calibration['stderr']['marker_leak'] is True and calibration['stderr']['thread_stopped']
            and calibration['stderr']['sha256'] == digest(RESOURCE.CALIBRATION_BYTES), 'stream_observer_not_calibrated')
    require(report['cleanup']['daemon_process']['all_stopped'], 'owned_daemon_survived')
    RESOURCE.clean_stream(report['cleanup']['daemon_stdout'])
    RESOURCE.clean_stream(report['cleanup']['daemon_stderr'])
    require(not report['cleanup']['audit']['marker_leak'], 'untrusted_output_reached_audit')
    report['checks'] = [{'case': name, 'inventory_complete': True, 'protection_acceptance': False}
                        for name in sorted(INVENTORY_CASES)]


def summary(report):
    result = {key: report.get(key) for key in ('format', 'mode', 'status', 'protection_acceptance', 'error',
        'passed', 'failed', 'skipped', 'incomplete', 'required_cases', 'runtime_source_commit',
        'runtime_source_tree', 'source_before', 'source_after', 'binary_sha256', 'driver_sha256',
        'fixture_sha256', 'fixture_package_tree_sha256', 'config_sha256', 'delegation',
        'delegation_removed', 'original_unchanged', 'git_original_unchanged', 'workspace_unchanged',
        'git_workspace_unchanged', 'native_expiry_seconds', 'immediate_native_retirement_implemented', 'checks')}
    result['inventory'] = [{key: value for key, value in row.items() if key != 'client'}
                           | {'exit_code': row['client']['exit_code'],
                              'kernel_observer_error': (row['client'].get('kernel') or {}).get('error'),
                              'stdout_bytes': row['client']['stdout']['bytes'],
                              'stdout_sha256': row['client']['stdout']['sha256'],
                              'stderr_bytes': row['client']['stderr']['bytes'],
                              'stderr_sha256': row['client']['stderr']['sha256']}
                           for row in report.get('inventory', [])]
    result['acceptance'] = [{key: value for key, value in row.items() if key != 'client'}
                           | {'exit_code': row['client']['exit_code'], 'epoch': row['client']['epoch'],
                              'budgeted': row['client']['budgeted'], 'owner': row['client']['owner'],
                              'kernel_observer_error': (row['client'].get('kernel') or {}).get('error'),
                              'processes_stopped': row['client']['process']['all_stopped'],
                              'stdout_bytes': row['client']['stdout']['bytes'],
                              'stdout_sha256': row['client']['stdout']['sha256'],
                              'stderr_bytes': row['client']['stderr']['bytes'],
                              'stderr_sha256': row['client']['stderr']['sha256']}
                           for row in report.get('acceptance', [])]
    startup = report.get('startup_inventory')
    result['startup_inventory'] = {key: value for key, value in startup.items() if key != 'client'} if startup else None
    result['original_identities'] = {}
    for kind, key in (('filesystem', 'original_server'), ('git', 'original_git_server')):
        installed = report.get(key, {})
        if installed:
            result['original_identities'][kind] = {name: installed.get(name)
                for name in ('profile_sha256', 'registry_sha256', 'policy_sha256')}
            result['original_identities'][kind].update(
                package_tree_sha256=installed.get('profile', {}).get('packageTreeSha256'),
                runtime_sha256=installed.get('profile', {}).get('runtimeSha256'),
                upstream_identity_sha256=digest(json.dumps(installed.get('upstream_identity'), sort_keys=True, separators=(',', ':')).encode()))
    return result


def run_baseline(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'required_linux_x86_64_missing')
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
    source = BASE.source()
    require(source['commit'] == args.expected_commit and not source['dirty'], 'clean_exact_source_required')
    require(args.runtime_source_commit == ACCEPTED, 'accepted_inventory_source_required')
    require(all(path.resolve().is_file() for path in (args.agentfw, args.node, args.npm, args.bwrap)),
            'pinned_runtime_prerequisite_missing')
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), 'fresh_output_outside_source_required')
    output.mkdir(mode=0o700, parents=True)
    tree = subprocess.check_output(['git', 'rev-parse', args.runtime_source_commit + '^{tree}'], cwd=ROOT,
                                   text=True, timeout=15).strip()
    report = {'format': FORMAT, 'mode': args.mode, 'status': 'incomplete', 'protection_acceptance': False,
              'runtime_source_commit': args.runtime_source_commit, 'runtime_source_tree': tree,
              'source_before': source, 'binary_sha256': sha(args.agentfw), 'driver_sha256': sha(__file__),
              'fixture_sha256': digest(FIXTURE.encode()), 'passed': 0, 'failed': 0, 'skipped': 0,
              'required_cases': len(INVENTORY_CASES), 'incomplete': len(INVENTORY_CASES), 'inventory': [], 'checks': []}
    rig, delegation = None, None
    try:
        delegation, report['delegation'] = prepare_delegation(args.disposable_systemd_unit)
        report['stream_calibration'] = RESOURCE.calibrate_streams(args.node.resolve())
        with tempfile.TemporaryDirectory(prefix='sou86-owned-') as temporary:
            rig = RESOURCE.Rig(args, Path(temporary).resolve(), delegation)
            install_fixture(rig)
            report['fixture_package_tree_sha256'] = rig.fixture['packageTreeSha256']
            report['original_server'] = rig.installation
            report['config_sha256'] = sha(rig.home / '.agentfw/config.yaml')
            workspace_before = BASE.snapshot(rig.workspace)
            try:
                for name, fixture, target in (
                    ('original-filesystem-collector-kill', False, 'collector'),
                    ('original-filesystem-wrapper-kill', False, 'wrapper'),
                    ('owned-descendants-collector-kill', True, 'collector'),
                    ('owned-descendants-wrapper-kill', True, 'wrapper'),
                ):
                    report['inventory'].append(inventory_crash(rig, name, fixture, target, args.bwrap.resolve()))
                restarted = RESOURCE.Client(rig, 'original-filesystem-restart')
                restarted.initialize()
                useful_hash = RESOURCE.useful(restarted)
                report['inventory'].append({'case': 'original-filesystem-restart', 'useful_wire_sha256': useful_hash,
                                            'protection_acceptance': False, 'client': restarted.close()})
            finally:
                report['cleanup'] = rig.close()
            report['workspace_unchanged'] = BASE.snapshot(rig.workspace) == workspace_before
            report['original_unchanged'] = BASE.INSTALL.tree_sha(Path(rig.original['packageRoot'])) == rig.original['packageTreeSha256']
        require(not any(path.is_dir() for path in delegation.iterdir()), 'owned_budget_leaves_survived')
        delegation.rmdir()
        report['delegation_removed'] = not delegation.exists()
        report['source_after'] = BASE.source()
        report['binary_unchanged'] = sha(args.agentfw) == report['binary_sha256']
        grade_inventory(report)
        report.update(status='inventory-complete-gap-reproduced', passed=len(report['checks']), incomplete=0)
    except Exception as error:
        message = str(error)
        report.update(status='fail', failed=1, error=message if re.fullmatch(r'[a-z0-9_]{1,100}', message) else type(error).__name__)
        report['incomplete'] = len(INVENTORY_CASES) - len(report['checks'])
    finally:
        if rig is not None and 'cleanup' not in report:
            try:
                report['cleanup'] = rig.close()
            except Exception:
                report['failure_cleanup_incomplete'] = True
        if delegation is not None and delegation.exists():
            for path in list(delegation.iterdir()):
                if path.is_dir() and RESOURCE.LEAF.fullmatch(path.name):
                    try:
                        (path / 'cgroup.kill').write_text('1')
                        report['emergency_recovery_after_failure'] = True
                    except OSError:
                        report['failure_cleanup_incomplete'] = True
        write(output / 'report.json', report)
    print(json.dumps(summary(report), indent=2))
    return 0 if report['status'] == 'inventory-complete-gap-reproduced' else 1


def run_acceptance(args):
    source = BASE.source()
    require(source['commit'] == args.expected_commit == args.runtime_source_commit and not source['dirty'],
            'clean_exact_candidate_source_required')
    require(all(path is not None and path.resolve().is_file() for path in
            (args.agentfw, args.node, args.npm, args.bwrap, args.git, args.git_launcher)), 'pinned_runtime_prerequisite_missing')
    require(isinstance(args.git_sha256, str) and re.fullmatch(r'[a-f0-9]{64}', args.git_sha256)
            and sha(args.git) == args.git_sha256, 'pinned_git_binary_identity_missing')
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), 'fresh_output_outside_source_required')
    output.mkdir(mode=0o700, parents=True)
    report = {'format': FORMAT, 'mode': 'acceptance', 'status': 'incomplete', 'protection_acceptance': True,
              'runtime_source_commit': source['commit'], 'runtime_source_tree': source['tree'], 'source_before': source,
              'binary_sha256': sha(args.agentfw), 'driver_sha256': sha(__file__), 'fixture_sha256': digest(FIXTURE.encode()),
              'git_binary_sha256': sha(args.git), 'git_launcher_sha256': sha(args.git_launcher),
              'passed': 0, 'failed': 0, 'skipped': 0, 'incomplete': len(CASES), 'required_cases': len(CASES),
              'native_expiry_seconds': 300, 'immediate_native_retirement_implemented': False,
              'acceptance': [], 'original_controls': [], 'checks': []}
    fs, git, delegation = None, None, None
    try:
        delegation, report['delegation'] = prepare_delegation(args.disposable_systemd_unit)
        report['stream_calibration'] = RESOURCE.calibrate_streams(args.node.resolve())
        with tempfile.TemporaryDirectory(prefix='sou86-protected-') as temporary:
            private = Path(temporary).resolve()
            fs_private, git_private = private / 'filesystem', private / 'git'
            fs_private.mkdir(mode=0o700)
            git_private.mkdir(mode=0o700)
            fs = RESOURCE.Rig(args, fs_private, delegation)
            install_fixture(fs)
            git = GitRig(args, git_private, delegation)
            report['original_server'], report['original_git_server'] = fs.installation, git.installation
            report['fixture_package_tree_sha256'] = fs.fixture['packageTreeSha256']
            report['config_sha256'], report['git_config_sha256'] = sha(fs.home / '.agentfw/config.yaml'), sha(git.home / '.agentfw/config.yaml')
            before, git_before = BASE.snapshot(fs.workspace), BASE.snapshot(git.workspace)
            try:
                exercise_acceptance(args, fs, git, report)
            finally:
                report['cleanup'] = fs.close()
                report['git_cleanup'] = git.close()
            report['workspace_unchanged'], report['git_workspace_unchanged'] = BASE.snapshot(fs.workspace) == before, BASE.snapshot(git.workspace) == git_before
            report['original_unchanged'] = BASE.INSTALL.tree_sha(Path(fs.original['packageRoot'])) == fs.original['packageTreeSha256']
            report['git_original_unchanged'] = GIT.INSTALL.tree_sha(Path(git.original['packageRoot'])) == git.original['packageTreeSha256']
            for row in report['acceptance']:
                audit = report['git_cleanup']['audit'] if row['client']['server_kind'] == 'git' else report['cleanup']['audit']
                row['native_session_end_observed'] = any(event.get('event') == 'native_session_end'
                    and event.get('session') == row['client']['epoch'] and event.get('released') is True for event in audit['rows'])
        require(not any(path.is_dir() for path in delegation.iterdir()), 'owned_budget_leaves_survived')
        delegation.rmdir()
        report['delegation_removed'] = not delegation.exists()
        report['source_after'] = BASE.source()
        report['binary_unchanged'] = sha(args.agentfw) == report['binary_sha256']
        grade_acceptance(report)
        report.update(status='pass', passed=len(report['checks']), incomplete=0)
    except Exception as error:
        message = str(error)
        report.update(status='fail', failed=1, error=message if re.fullmatch(r'[a-z0-9_]{1,100}', message) else type(error).__name__)
        report['incomplete'] = len(CASES) - len(report['checks'])
    finally:
        for rig, key in ((fs, 'cleanup'), (git, 'git_cleanup')):
            if rig is not None and key not in report:
                try:
                    report[key] = rig.close()
                except Exception:
                    report['failure_cleanup_incomplete'] = True
        if delegation is not None and delegation.exists():
            for path in list(delegation.iterdir()):
                if path.is_dir() and RESOURCE.LEAF.fullmatch(path.name):
                    try:
                        (path / 'cgroup.kill').write_text('1')
                        report['emergency_recovery_after_failure'] = True
                    except OSError:
                        report['failure_cleanup_incomplete'] = True
        write(output / 'report.json', report)
    print(json.dumps(summary(report), indent=2))
    return 0 if report['status'] == 'pass' else 1


def run(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'required_linux_x86_64_missing')
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
    return run_acceptance(args) if args.mode == 'acceptance' else run_baseline(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--mode', choices=('baseline-inventory', 'acceptance'), default='baseline-inventory')
    for name in ('agentfw', 'node', 'npm', 'bwrap', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--runtime-source-commit', required=True)
    parser.add_argument('--disposable-systemd-unit', required=True)
    parser.add_argument('--git', type=Path)
    parser.add_argument('--git-sha256')
    parser.add_argument('--git-launcher', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'plan', 'executed': False, 'mode': args.mode, 'protection_acceptance': False,
                          'required_linux': True, 'required_delegation': True, 'raw_output_capture': False,
                          'required_cases': len(CASES if args.mode == 'acceptance' else INVENTORY_CASES)}))
        return 0
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
