#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable Linux crash inventory and acceptance; no raw MCP output artifacts.

The baseline-inventory mode deliberately measures the accepted runtime before
any harness recovery. Its success means a complete inventory, never protection
acceptance. Missing prerequisites or an unobserved case fail the required job.
"""
from __future__ import annotations

import argparse
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
INVENTORY_CASES = {
    'original-filesystem-collector-kill', 'original-filesystem-wrapper-kill',
    'owned-descendants-collector-kill', 'owned-descendants-wrapper-kill',
    'original-filesystem-restart',
}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RESOURCE = load('sou86_resources', 'verify-sou79-resource-budgets.py')
BASE, require, sha, digest, write = RESOURCE.BASE, RESOURCE.require, RESOURCE.sha, RESOURCE.digest, RESOURCE.write

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
   if(v.params.arguments.path==='/workspace/sou86-block') {
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
        return {'pid': pid, 'start_time_ticks': int(fields[19]), 'state': fields[0].decode('ascii'),
                'parent_pid': int(fields[1]), 'process_group': int(fields[2]), 'session': int(fields[3]),
                'fixture_role': role}
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


def signal_owned(pid, expected_start, executable):
    """A pidfd binds the one verified target; no PID/group-wide search killing."""
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
    before = identity(pid)
    require(before is not None and before['start_time_ticks'] == expected_start, 'signal_target_identity_changed')
    expected = executable.stat()
    observed = Path(f'/proc/{pid}/exe').stat()
    require((observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino), 'signal_target_executable_changed')
    descriptor = os.pidfd_open(pid, 0)
    try:
        require(same_process(before), 'signal_target_identity_changed')
        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
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
    observed = members(client)
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
        observed.update(members(client))
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


def grade_inventory(report):
    require(report['format'] == FORMAT and report['mode'] == 'baseline-inventory'
            and report['runtime_source_commit'] == ACCEPTED, 'wrong_inventory_runtime')
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
        'delegation_removed', 'original_unchanged', 'workspace_unchanged', 'checks')}
    result['inventory'] = [{key: value for key, value in row.items() if key != 'client'}
                           | {'exit_code': row['client']['exit_code'],
                              'kernel_observer_error': (row['client'].get('kernel') or {}).get('error'),
                              'stdout_bytes': row['client']['stdout']['bytes'],
                              'stdout_sha256': row['client']['stdout']['sha256'],
                              'stderr_bytes': row['client']['stderr']['bytes'],
                              'stderr_sha256': row['client']['stderr']['sha256']}
                           for row in report.get('inventory', [])]
    return result


def run(args):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--mode', choices=('baseline-inventory',), default='baseline-inventory')
    for name in ('agentfw', 'node', 'npm', 'bwrap', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--runtime-source-commit', required=True)
    parser.add_argument('--disposable-systemd-unit', required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'plan', 'executed': False, 'mode': args.mode, 'protection_acceptance': False,
                          'required_linux': True, 'required_delegation': True, 'raw_output_capture': False,
                          'required_cases': len(INVENTORY_CASES)}))
        return 0
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
