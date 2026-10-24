#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Proposed offline SOU-142 actual-host and owner-first qualification slice.

Default is a plan. --run requires the ordinary-user read-only/private-network
transient unit and trusted same-source assets.json prepared by the parent.
This does not claim original pressure or budgeted emergency-stop acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
FORMAT = 'sou142-offline-budget-host-attempt/1'
NORMAL = {'memoryMaxBytes': 512 * 1024 * 1024, 'pidsMax': 64,
          'cpuQuotaMicros': 100000, 'wallMillis': 120000}
OWNER_TESTS = (
    ('preparation', 'pilot_budget::tests::native_owner_first_preparation_parent_loss',
     'prepared-before-owner', False),
    ('handback', 'pilot_budget::tests::native_owner_first_handback_parent_loss',
     'prepared-handback-before-adoption-ack', True),
)
HOST_CASES = frozenset(('useful-refusal', 'ask', 'default', 'cancel', 'daemon-loss',
                        'host-crash', 'timeout'))
GAPS = ('original-memory-pid-wall-calibration',
        'owner-loss-before-descriptor-handback')


class Refusal(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(src, name, relative):
    spec = importlib.util.spec_from_file_location(name, src / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded_json(path, limit=1024 * 1024):
    require(path.stat().st_size <= limit, 'bounded_json_input_required')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'bounded_json_input_required')
    return json.loads(raw)


def empty_root(root):
    require(not any(path.is_dir() for path in root.iterdir()), 'residual_owned_budget_leaf')
    require(not (root / 'cgroup.procs').read_text().strip(), 'residual_owned_budget_member')


def owner_observation(log, test):
    require(log.stat().st_size <= 65536, 'bounded_owner_control_output_required')
    prefix = 'test ' + test + ' ... '
    observations = []
    for line in log.read_text().splitlines():
        if line.startswith(prefix):
            line = line[len(prefix):]
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('format') == 'sou142-owner-first-parent-loss/1':
            observations.append(value)
    require(len(observations) == 1, 'one_owner_control_observation_required')
    allowed = {'format', 'status', 'stage', 'binary_sha256', 'owner_binary_sha256',
               'budget_sha256', 'leaf_created', 'original_started', 'owned_members',
               'production_cleanup_verified', 'witness_cleanup_attempted', 'inventory_restored'}
    require(set(observations[0]) <= allowed, 'finite_owner_control_projection_required')
    return observations[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--bwrap', type=Path, required=True)
    parser.add_argument('--unit', required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'status': 'plan', 'executed': False,
            'normal_limits': NORMAL, 'actual_host_cases': sorted(HOST_CASES),
            'owner_controls': [row[0] for row in OWNER_TESTS],
            'owner_profiles': ['filesystem', 'git'], 'remaining_gaps': GAPS,
            'provider': 'owned-scripted-loopback', 'paid_api_calls': 0}))
        return 0
    os.umask(0o077)
    src, out = args.source.resolve(strict=True), args.scratch.resolve(strict=True)
    record = {'format': FORMAT, 'status': 'incomplete', 'source_commit': args.expected_commit,
              'steps': [], 'owner_controls': [], 'qualifier_exit_code': None,
              'provider': 'owned-scripted-loopback', 'paid_api_calls': 0,
              'remaining_gaps': list(GAPS), 'full_sou142_qualification': False,
              'budgeted_emergency_stop_qualified': False}
    destination = out / 'budget-runtime-attempt.json'
    require(not destination.exists(), 'new_runtime_attempt_directory_required')

    def save():
        raw = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
        require(len(raw) <= 1024 * 1024, 'bounded_runtime_report_required')
        temporary = out / 'budget-runtime-attempt.next'
        temporary.write_bytes(raw)
        temporary.replace(destination)

    save()
    delegated = peer_root = None
    try:
        require(re.fullmatch(r'[0-9a-f]{40}', args.expected_commit), 'full_candidate_source_required')
        require(not out.is_relative_to(src) and stat.S_IMODE(out.stat().st_mode) == 0o700
                and out.stat().st_uid == os.geteuid(), 'isolated_private_scratch_required')
        require(os.geteuid() != 0 and {name for _, name in socket.if_nameindex()} == {'lo'},
                'ordinary_user_private_loopback_required')
        require(os.statvfs(src).f_flag & os.ST_RDONLY, 'read_only_source_mount_required')
        assets = bounded_json(out / 'assets.json')
        paths, identity = dict(assets['paths']), assets['identity']
        require(identity['source'] == args.expected_commit, 'same_source_selected_inputs_required')
        for role, digest in identity['binaries'].items():
            require(sha(paths[role]) == digest, 'selected_runtime_input_changed')
        for role in ('agentfw', 'git_launcher', 'sandbox_tests'):
            require(os.statvfs(paths[role]).f_flag & os.ST_RDONLY, 'reused_fast_binaries_must_be_read_only')
        bwrap = args.bwrap.resolve(strict=True)
        metadata = bwrap.stat()
        require(metadata.st_uid == 0 and stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & 0o022
                and sha(bwrap) == identity['binaries']['bwrap_source'], 'staged_job_bwrap_identity_unproven')
        paths['bwrap'] = str(bwrap)
        for name in ('home', 'runtime-tmp'):
            (out / name).mkdir(mode=0o700)
        env = {'PATH': str(Path(paths['node']).parent) + ':/usr/bin:/bin', 'HOME': str(out / 'home'),
               'TMPDIR': str(out / 'runtime-tmp'), 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}
        os.environ.clear()
        os.environ.update(env)

        def clean_source():
            actual = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=src, env=env, timeout=20)
            dirty = subprocess.check_output(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=all'],
                                            cwd=src, env=env, timeout=20)
            require(actual.decode().strip() == args.expected_commit and not dirty, 'clean_exact_source_required')

        clean_source()
        record.update(source_read_only=True, reused_binaries_read_only=True, network='private-loopback-only',
                      selected_sha256=identity['binaries'], driver_sha256=sha(Path(__file__)))
        save()

        def run(label, words, timeout, overrides=None):
            step = {'label': label, 'status': 'incomplete'}
            record['steps'].append(step)
            save()
            log = out / (label + '.private.log')
            try:
                with log.open('xb') as stream:
                    done = subprocess.run(list(map(str, words)), cwd=src,
                        env=dict(env, **(overrides or {})), stdin=subprocess.DEVNULL,
                        stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
                step.update(status='passed' if done.returncode == 0 else 'failed', exit_code=done.returncode)
            except subprocess.TimeoutExpired:
                step.update(status='incomplete', exit_code=124)
            finally:
                if log.exists():
                    step['log_sha256'] = sha(log)
                    if step.get('exit_code', 0):
                        tail = log.read_text(errors='replace')[-16384:]
                        print('=== ' + label + ' FAILED (' + str(step['exit_code']) + ') ===\n' + tail, file=sys.stderr)
                        step['failure_tail'] = tail[-2000:]
                        if label == "offline-preparation":
                            for ilog in (out / "preparation").glob("generations/*/*-install.log"):
                                print("=== " + ilog.name + " ===\n" + ilog.read_text(errors="replace")[-4000:], file=sys.stderr)
                save()
            require(step.get('exit_code') == 0, label.replace('-', '_') + '_failed')
            return log

        run('same-unit-namespace-probe', [bwrap, '--unshare-all', '--unshare-user', '--disable-userns',
            '--assert-userns-disabled', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--', '/usr/bin/true'], 15)
        policy_module = load(src, 'sou142_offline_policy', 'scripts/qualify-installed-pilot.py')
        policy = out / 'policy.yaml'
        policy_module.owned_bytes(policy, policy_module.PILOT_POLICY.encode())
        log = run('offline-preparation', [sys.executable, '-B', src / 'scripts/prepare-installed-pilot.py',
            '--prepare', '--output', out / 'preparation', '--expected-commit', args.expected_commit,
            '--agentfw', paths['agentfw'], '--git-launcher', paths['git_launcher'],
            '--sandbox-tests', paths['sandbox_tests'], '--node-archive', paths['node_archive'],
            '--python-archive', paths['python_archive'], '--npm-cache', out / 'npm-cache',
            '--wheelhouse', out / 'wheelhouse', '--bwrap', bwrap, '--git', paths['git'],
            '--claude', paths['claude'], '--python', paths['python'],
            '--filesystem-classifier', src / 'rule_baseline/rule_baseline.py',
            '--git-classifier', src / 'rule_baseline/git_readonly_v1/rule_baseline.py', '--policy', policy], 600)
        preparation = bounded_json(log)
        require(preparation.get('status') == 'prepared-not-active', 'prepared_selection_unavailable')
        selection = Path(preparation['selection']).resolve(strict=True)
        require(selection.is_relative_to(out / 'preparation'), 'selected_generation_escaped_scratch')
        record['selection_sha256'] = sha(selection)

        # Explicit disposable acceptance setup only. This helper checks exact
        # /system.slice/sou79-N-N.service ownership before creating manager and
        # budgets children; the normal product launch never repairs delegation.
        resource = load(src, 'sou142_resources', 'scripts/verify-sou79-resource-budgets.py')
        delegated, delegation = resource.prepare_delegation(args.unit)
        config = {'format': 'sw-mcp/linux-cgroup-budget/1', 'delegationRoot': str(delegated), **NORMAL}
        budget = out / 'linux-budget.json'
        with budget.open('x') as stream:
            stream.write(json.dumps(config, sort_keys=True) + '\n')
        # The simultaneous stop peer owns a separate explicit substrate. This
        # is disposable acceptance setup; the product never creates roots or
        # changes delegation. Both peers retain identical accepted limits.
        peer_root = delegated.with_name('peer-budgets')
        peer_root.mkdir(mode=0o700)
        (peer_root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        peer_config = dict(config, delegationRoot=str(peer_root))
        peer_budget = out / 'linux-budget-peer.json'
        with peer_budget.open('x') as stream:
            stream.write(json.dumps(peer_config, sort_keys=True) + '\n')
        budget_digest = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        record.update(budget_sha256=budget_digest,
                      peer_budget_sha256=hashlib.sha256(json.dumps(peer_config, sort_keys=True,
                          separators=(',', ':')).encode()).hexdigest(), budget_limits=NORMAL,
                      delegation={'unprivileged': delegation['unprivileged'],
                                  'controllers': delegation['controllers'],
                                  'manager_membership_verified': delegation['manager_membership_verified']})
        empty_root(delegated)
        save()

        entry = load(src, 'sou142_prepared_entry', 'scripts/pilot-run.py')
        _, _, profiles = entry.selected(argparse.Namespace(selection=selection,
            expected_commit=args.expected_commit, ask_wait_seconds=0, timeout_seconds=60, port=0))
        for server in ('filesystem', 'git'):
            for label, test, stage, leaf_created in OWNER_TESTS:
                empty_root(delegated)
                log = run('native-owner-' + label + '-' + server, [paths['sandbox_tests'], test,
                    '--exact', '--ignored', '--nocapture', '--test-threads=1'], 25,
                    {'SOU142_BUDGET_CONFIG': str(budget),
                     'SOU142_OWNER_PROFILE': profiles[server]['profile']['path'],
                     'SOU86_TEST_AGENTFW': paths['agentfw']})
                observed = owner_observation(log, test)
                expected = {'status': 'pass', 'stage': stage, 'leaf_created': leaf_created,
                    'binary_sha256': identity['binaries']['sandbox_tests'],
                    'owner_binary_sha256': identity['binaries']['agentfw'],
                    'budget_sha256': budget_digest, 'original_started': False, 'owned_members': 0,
                    'production_cleanup_verified': True, 'witness_cleanup_attempted': False}
                require(all(observed.get(key) == value for key, value in expected.items()),
                        'owner_control_observation_unverified')
                empty_root(delegated)
                record['owner_controls'].append({'server': server, **observed})
                save()

        # Existing actual pinned host and original FS/Git qualification. The
        # --linux-budget flag goes through real pilot-run -> pilot-launch ->
        # explicit collector binding/digest, not RESOURCE.Client constructors.
        run('actual-host-budget-qualification', [sys.executable, '-B', src / 'scripts/qualify-prepared-pilot-run.py',
            '--selection', selection, '--expected-commit', args.expected_commit,
            '--strace', '/usr/bin/strace', '--linux-budget', budget, '--linux-budget-peer', peer_budget,
            '--validation-timeout-seconds', '120', '--output', out / 'prepared-budget-native'], 850)
        record['qualifier_exit_code'] = 0
        result = bounded_json(out / 'prepared-budget-native/report.json', 4 * 1024 * 1024)
        require(result.get('status') == 'passed', 'actual_host_budget_report_failed')
        cases = {row['case']: row for row in result['cases'] if row.get('case') in HOST_CASES}
        require(set(cases) == HOST_CASES, 'required_actual_host_cases_missing')
        summary = []
        for name in sorted(HOST_CASES):
            row = cases[name]
            observed = row.get('resource_budget', {})
            require(row.get('status') == 'passed' and observed.get('format') == 'sw-prepared-pilot-budget/1'
                    and observed.get('budget_sha256') == budget_digest
                    and observed.get('observed_children', 0) >= 2,
                    'prepared_host_budget_binding_unverified')
            if name in ('useful-refusal', 'ask', 'default'):
                require(observed.get('status') == 'closed-enforced'
                        and observed.get('failed_children') == 0
                        and observed.get('unresolved_children') == 0, 'useful_budget_enforcement_unverified')
            summary.append({'case': name, 'status': 'passed', 'outcome': row.get('outcome'),
                            'budget_status': observed['status'],
                            'observed_children': observed['observed_children']})
        empty_root(delegated)
        empty_root(peer_root)
        record['actual_host_cases'] = summary
        section = result.get('emergency_stop', {})
        require(section.get('status') == 'passed' and len(section.get('cases', [])) == 4,
                'budgeted_stop_qualification_incomplete')
        record['budgeted_emergency_stop_qualified'] = True
        sys.path.insert(0, str(src / 'scripts'))
        pressure = load(src, 'sou142_original_pressure', 'scripts/prepared_budget_pressure.py')
        from types import SimpleNamespace
        qualifier = load(src, 'sou142_actual_host_baseline', 'scripts/qualify-prepared-pilot-run.py')
        context = SimpleNamespace(BASE=qualifier.BASE, RESOURCE=resource, ROOT=src, QUALIFIER=qualifier,
            budget=budget, peer_budget=peer_budget)
        record['original_pressure'] = pressure.qualify(context, selection, paths, profiles,
            delegated, out / 'original-pressure', args.expected_commit)
        # Failed/non-exhausting calibration remains a retained environmental
        # outcome. This partial slice never asserts final acceptance.
        if record['original_pressure']['status'] == 'passed':
            record['remaining_gaps'].remove('original-memory-pid-wall-calibration')
        save()
        clean_source()
        for role, digest in identity['binaries'].items():
            require(sha(paths[role]) == digest, 'closing_runtime_identity_changed')
        record.update(status='partial-runtime-completed-pending-parent-projection',
                      owned_budget_root_empty=True, actual_original_host_covered=True)
    except BaseException as error:
        record['status'] = 'failed'
        record['reason'] = str(error) if isinstance(error, Refusal) else 'runtime_failure'
        if isinstance(error, OSError):
            record['errno'] = error.errno
    finally:
        if delegated is not None:
            try:
                empty_root(delegated)
                record['owned_budget_root_empty'] = True
            except (Refusal, OSError):
                record.update(status='failed', owned_budget_root_empty=False)
        if peer_root is not None:
            try:
                empty_root(peer_root)
                record['owned_peer_budget_root_empty'] = True
            except (Refusal, OSError):
                record.update(status='failed', owned_peer_budget_root_empty=False)
        save()
    return 0 if record['status'] == 'partial-runtime-completed-pending-parent-projection' else 1


if __name__ == '__main__':
    raise SystemExit(main())
