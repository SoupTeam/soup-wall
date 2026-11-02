# SPDX-License-Identifier: Apache-2.0
"""Installed maintenance binding, run attribution and final spawn verification.

Only the accepted supervisor's confirmed process-group cleanup writes terminal
records. A dead PID, empty inventory or local receipt alone never proves drain.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys

_spec = importlib.util.spec_from_file_location('maintenance_store', Path(__file__).with_name('pilot_maintenance.py'))
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
require = M.require
FORMAT = 'sw-pilot-maintenance-binding/1'
RUN_FORMAT = 'sw-pilot-maintenance-run/1'


def directory(path):
    path = Path(path)
    fd = M.IO.open_directory(path)
    try:
        return {'path': str(path), 'object': M.object_id(os.fstat(fd))}
    finally:
        os.close(fd)


def file(path):
    path = Path(path)
    before = path.lstat()
    value, _ = M.IO.read_file(path, 512 * 1024 * 1024)
    require(M.stable(before) == M.stable(path.lstat()), 'maintenance_source_changed')
    return {**value, 'identity': M.stable(before)}


def revalidate(binding):
    require(type(binding) is dict and set(binding) == {'format', 'home', 'component_home', 'selection',
            'state_root', 'files', 'roots', 'launch'} and binding['format'] == FORMAT,
            'maintenance_binding_invalid')
    require(type(binding['files']) is list and 1 <= len(binding['files']) <= 24
            and type(binding['roots']) is list and 1 <= len(binding['roots']) <= 12,
            'maintenance_binding_invalid')
    for value in binding['files']:
        require(file(value['path']) == value, 'maintenance_source_changed')
    for value in binding['roots']:
        require(directory(value['path']) == value, 'maintenance_root_changed')
    require(directory(binding['home']) in binding['roots']
            and directory(binding['component_home']) in binding['roots'], 'maintenance_home_changed')


def binding(home, component_home, selection, paths, profiles, state_root, prep, coordinator=None):
    home, component_home, selection, state_root = map(Path, (home, component_home, selection, state_root))
    for path in (home, component_home):
        with M.IO.Directory(path): pass
    # Existing selected() owns profile/package validation. Pin its exact source,
    # installation pointers, selected executables, profiles, policy and roots.
    current = selection.parent.parent.parent / 'current.json'
    files = {selection, current, *map(Path, paths.values()),
             component_home / 'pilot-front-door' / 'current.json'}
    if coordinator is not None:
        files.add(Path(coordinator) / 'current.json')
    for row in profiles.values():
        profile = Path(row['profile']['path'])
        files.update((profile, profile.parent / 'registry.json'))
    roots = prep.workspace_paths(prep.PILOT.strict_json(selection.read_bytes()), selection.parent)
    launch = {'agent_bin': str(paths['agentfw']), 'claude': str(paths['claude']),
              'workspace': str(roots['filesystem']), 'git_workspace': str(roots['git']),
              'fs_profile': profiles['filesystem']['profile']['path'],
              'git_profile': profiles['git']['profile']['path'], 'policy': str(paths['policy']),
              'classifier': str(paths['git_classifier'])}
    directories = {home, component_home, state_root, selection.parent, *roots.values()}
    result = {'format': FORMAT, 'home': str(home), 'component_home': str(component_home),
              'selection': str(selection), 'state_root': str(state_root),
              'files': [file(p) for p in sorted(files) if p.is_file()],
              'roots': [directory(p) for p in sorted(directories)], 'launch': launch}
    # All mandatory pointers must exist; never silently drop a missing pin.
    require(all(p.is_file() for p in files), 'maintenance_source_missing')
    require(len(M.encoded(result)) <= M.CAP // 2, 'maintenance_binding_cap')
    revalidate(result)
    return result


def process(pid):
    require(type(pid) is int and pid > 1, 'maintenance_process_invalid')
    try:
        proc = Path('/proc') / str(pid)
        uid = proc.stat().st_uid
        raw = (proc / 'stat').read_bytes()
        require(len(raw) <= 4096, 'maintenance_process_invalid')
        fields = raw.rsplit(b') ', 1)[1].split()
        require(fields[0] not in (b'Z', b'X') and uid == os.geteuid(), 'maintenance_process_unavailable')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(len(boot) == 36 and int(fields[19]) > 0, 'maintenance_process_invalid')
        return {'pid': pid, 'uid': uid, 'boot': boot, 'start': int(fields[19])}
    except (OSError, IndexError, ValueError):
        raise M.Refusal('maintenance_process_unavailable') from None


def inventory(store, binding, ignore=None):
    rows = []
    known = set()
    with M.IO.Directory(store.home / M.DIRECTORY / 'runs') as runs:
        names = os.listdir(runs.fd)
        require(len(names) <= 2 * M.RUNS, 'maintenance_run_capacity')
        with M.IO.Directory(store.home / M.DIRECTORY / 'admissions') as admissions:
            admitted = os.listdir(admissions.fd)
            require(len(admitted) <= M.RUNS and set(admitted) == {n for n in names if not n.endswith('.finished.json')},
                    'maintenance_run_inventory_incomplete')
            for name in admitted:
                require(M.re.fullmatch(r'[0-9a-f]{32}\.json', name), 'maintenance_run_unknown')
                pin = M.strict(M.read_at(admissions.fd, name)); store.authenticated('admission', pin)
                require(pin == store.signed(store.key, 'admission', {'format': RUN_FORMAT,
                        'owner': store.anchor['owner'], 'intent_sha256': M.sha(M.read_at(runs.fd, name))}),
                        'maintenance_run_inventory_changed')

        for name in sorted(names):
            require(M.re.fullmatch(r'[0-9a-f]{32}(?:.finished)?\.json', name), 'maintenance_run_unknown')
            if name.endswith('.finished.json'): continue
            record = M.strict(M.read_at(runs.fd, name)); store.authenticated('run', record)
            require(record.get('format') == RUN_FORMAT and record.get('owner') == store.anchor['owner']
                    and record.get('run_id') + '.json' == name, 'maintenance_run_invalid')
            known.add(record['private'])
            terminal = M.read_at(runs.fd, record['run_id'] + '.finished.json', optional=True)
            state = 'uncertain'
            if terminal is not None:
                value = M.strict(terminal); store.authenticated('finished', value)
                require(value == store.signed(store.key, 'finished', {'format': RUN_FORMAT,
                    'owner': store.anchor['owner'], 'intent_sha256': M.digest(record),
                    'owned_processes_stopped': True}), 'maintenance_terminal_invalid')
                state = 'drained'
            else:
                try:
                    if process(record['supervisor']['pid']) == record['supervisor']:
                        require(directory(record['private']) == record['private_root'], 'maintenance_run_root_changed')
                        state = 'active'
                except (OSError, ValueError): pass
            rows.append({'run_id': record['run_id'], 'state': state})
        # Finished records without an intent are not evidence for an empty set.
        require(all(not n.endswith('.finished.json') or n.removesuffix('.finished.json') + '.json' in names
                    for n in names), 'maintenance_terminal_orphan')
    # Bounded complete inventory of the selected state parent, using the accepted
    # owner-editable run receipt readers. Prior untracked runs remain uncertain;
    # their disappearance never turns an enrolled interrupted intent into drain.
    root_fd = M.IO.open_directory(binding['state_root'])
    try:
        names = os.listdir(root_fd)
        require(len(names) <= 4096, 'maintenance_state_inventory_cap')
        for name in sorted(names):
            if not name.startswith('soup-wall-run-'): continue
            path = Path(binding['state_root']) / name
            if str(path) in known or path == ignore: continue
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if info.st_uid != os.geteuid(): continue
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                    'maintenance_legacy_run_uncertain')
            try:
                with M.IO.Directory(path) as run_root:
                    ref = M.strict(M.read_at(run_root.fd, 'maintenance-owner.json'))
                require(ref.get('format') == RUN_FORMAT and M.ID.fullmatch(ref.get('run_id', '')),
                        'maintenance_foreign_run_invalid')
                require(Path(ref['home']) != store.home, 'maintenance_run_inventory_incomplete')
                with M.Store(ref['home']) as foreign:
                    foreign.check()
                    with M.IO.Directory(foreign.home / M.DIRECTORY / 'runs') as foreign_runs:
                        intent = M.strict(M.read_at(foreign_runs.fd, ref['run_id'] + '.json'))
                    foreign.authenticated('run', intent)
                    require(intent['owner'] == ref['owner'] == foreign.anchor['owner']
                            and intent['private'] == str(path) and intent['private_root'] == directory(path),
                            'maintenance_foreign_run_invalid')
                    foreign.check()
                continue
            except (OSError, ValueError, KeyError, TypeError): pass
            # Do not adopt editable legacy finished files as authenticated drain.
            # An operator must retain/reconcile these before first enrollment.
            rows.append({'run_id': M.sha(str(path).encode()), 'state': 'uncertain-legacy'})
            require(len(rows) <= M.RUNS, 'maintenance_run_capacity')
    finally:
        os.close(root_fd)
    return {'uncertain': any(r['state'].startswith('uncertain') for r in rows),
            'runs': rows, 'active': sum(r['state'] == 'active' for r in rows),
            'drained': sum(r['state'] == 'drained' for r in rows),
            'scope': 'enrolled-owned-installation-and-selected-state-parent',
            'empty_process_list_proves_drain': False}


def claim(store, binding, private):
    require(store._lock_mode == 'exclusive', 'maintenance_exclusive_gate_required')
    store.admit(binding); revalidate(binding)
    require(not inventory(store, binding, private)['uncertain'], 'maintenance_runs_uncertain')
    with M.IO.Directory(store.home / M.DIRECTORY / 'runs') as runs:
        require(len(os.listdir(runs.fd)) < 2 * M.RUNS - 1, 'maintenance_run_capacity')
        run_id = M.uuid.uuid4().hex
        context = {'format': RUN_FORMAT, 'owner': store.anchor['owner'], 'run_id': run_id,
                   'binding_sha256': M.digest(binding), 'private': str(private),
                   'private_root': directory(private), 'supervisor': process(os.getpid()),
                   'binding': binding}
        context = store.signed(store.key, 'run', context)
        M.create_at(runs.fd, run_id + '.json', context)
        with M.IO.Directory(store.home / M.DIRECTORY / 'admissions') as admissions:
            M.create_at(admissions.fd, run_id + '.json', store.signed(store.key, 'admission',
                {'format': RUN_FORMAT, 'owner': store.anchor['owner'], 'intent_sha256': M.digest(context)}))
        with M.IO.Directory(private) as run_root:
            M.create_at(run_root.fd, 'maintenance-owner.json', {'format': RUN_FORMAT,
                'home': str(store.home), 'owner': store.anchor['owner'], 'run_id': run_id})

    return context


def finish(store, context):
    # Called ONLY after existing accepted GROUPS.stop_group and receipt cleanup
    # succeeds. Never called merely because supervisor/launcher PID disappeared.
    with store.locked(exclusive=True), M.IO.Directory(store.home / M.DIRECTORY / 'runs') as runs:
        require(M.strict(M.read_at(runs.fd, context['run_id'] + '.json')) == context,
                'maintenance_run_changed')
        M.create_at(runs.fd, context['run_id'] + '.finished.json',
                    store.signed(store.key, 'finished', {'format': RUN_FORMAT,
                        'owner': store.anchor['owner'], 'intent_sha256': M.digest(context),
                        'owned_processes_stopped': True}))


def check_spawn(home, run_id, expected):
    require(type(run_id) is str and M.ID.fullmatch(run_id), 'maintenance_run_invalid')
    with M.Store(home) as store, store.locked(exclusive=False):
        with M.IO.Directory(store.home / M.DIRECTORY / 'runs') as runs:
            context = M.strict(M.read_at(runs.fd, run_id + '.json'))
            require(M.read_at(runs.fd, run_id + '.finished.json', optional=True) is None,
                    'maintenance_run_finished')
        store.authenticated('run', context)
        require(context['owner'] == store.anchor['owner'] and context['run_id'] == run_id
                and context['supervisor'] == process(expected['launcher_parent_pid']),
                'maintenance_run_identity_mismatch')
        require(expected['launcher_parent_pid'] == context['supervisor']['pid']
                and expected['component_home'] == context['binding']['component_home']
                and expected['home'] == str(Path(context['private']) / '.agentfw')
                and {k: expected[k] for k in context['binding']['launch']} == context['binding']['launch'],
                'maintenance_launch_context_mismatch')
        require(directory(context['private']) == context['private_root'], 'maintenance_run_root_changed')
        store.admit(context['binding']); revalidate(context['binding'])
        require(not inventory(store, context['binding'])['uncertain'], 'maintenance_runs_uncertain')
        store.check()
    return True




def selected_binding(args, state, prep, runner):
    from types import SimpleNamespace
    selected_args = SimpleNamespace(selection=Path(state['selection']), expected_commit=state['commit'],
                                   ask_wait_seconds=0, timeout_seconds=180, port=0)
    _, paths, profiles = runner.selected(selected_args)
    home = getattr(args, 'maintenance_home', None) or args.agent_home
    require(home is not None and args.agent_home is not None, 'maintenance_installed_home_required')
    state_root = args.state_root or Path('/tmp').resolve()
    return binding(home, args.agent_home, selected_args.selection, paths, profiles, state_root,
                   prep, getattr(args, 'maintenance_coordinator_root', None))


def command(args, state, prep, runner):
    bound = selected_binding(args, state, prep, runner)
    home = Path(bound['home'])
    operation = getattr(args, 'operation', None) or args.maintenance_action
    absent = M.Store.absent(home)
    if absent:
        require(operation != 'leave', 'maintenance_not_enrolled')
        # Read-only preview/status neither creates locks nor enrolls a home.
        inventory_value = {'uncertain': True, 'runs': [], 'scope': 'not-enrolled',
                           'empty_process_list_proves_drain': False}
        value = {'format': M.FORMAT, 'operation': operation, 'mode': 'not-enrolled',
                 'binding_sha256': M.digest(bound), 'home': directory(home),
                 'inventory': inventory_value, 'executed': False}
        plan = {**value, 'confirmation_sha256': M.digest(value)}
        if args.maintenance_action == 'enter':
            require(args.confirm == plan['confirmation_sha256'], 'maintenance_confirmation_stale')
            revalidate(bound)
            with M.Store.create(home, bound, maintenance=True) as store, store.locked(exclusive=False):
                return {**store.snapshot(), 'format': M.FORMAT, 'status': 'entered',
                        'inventory': inventory(store, bound), 'authority_changed': False}
        return plan
    with M.Store(home) as store, store.locked(exclusive=args.maintenance_action in ('enter', 'leave')):
        revalidate(bound)
        observed = inventory(store, bound)
        snapshot = store.snapshot()
        if args.maintenance_action == 'status':
            _, marker, _ = store.marker(allow_uncertain=True)
            owned = marker is not None and M.digest(M.scope(marker['binding'])) == M.digest(M.scope(bound))
            # The marker governs the installation. A newer selection, preset or
            # update is reported, never silently adopted: only a freshly
            # confirmed enter/leave records it.
            return {'format': M.FORMAT, **snapshot, 'inventory': observed,
                    'drain': 'uncertain' if observed['uncertain'] else
                             'draining' if observed['active'] else 'enrolled-runs-drained',
                    'installation': 'matches' if owned else 'mismatch',
                    'selection_binding': 'unknown' if marker is None else
                                         'current' if snapshot['binding_sha256'] == M.digest(bound) else 'changed',
                    'new_launches': 'refused' if snapshot['mode'] != 'open' or observed['uncertain'] or not owned
                                    else 'eligible',
                    'executed': False, 'authority_changed': False}
        plan = store.plan(bound, operation, observed)
        if args.maintenance_action == 'preview':
            return {**plan, 'inventory': observed, 'executed': False}
        return {**store.transition(bound, operation, observed, args.confirm), 'inventory': observed}


if __name__ == '__main__':
    # Internal verified-component entry. It cannot select arbitrary executable
    # paths, start a host or return a policy decision. Rust holds the same gate
    # shared while invoking this check, through actual host spawn.
    parser = argparse.ArgumentParser()
    parser.add_argument('--spawn-check', action='store_true', required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(M.CAP + 1)
        expected = M.strict(raw)
        require(os.getppid() == expected['launcher_pid'], 'maintenance_launcher_identity_mismatch')
        check_spawn(args.home, args.run, expected)
        print('maintenance_admitted')
    except Exception:
        print('maintenance_spawn_refused')
        sys.exit(2)
