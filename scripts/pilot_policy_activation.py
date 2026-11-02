# SPDX-License-Identifier: Apache-2.0
"""Installed activation of one reviewed deny-only policy candidate for an idle owned installation.

A candidate from `agentfw policy-candidate` stays inert until this command publishes a *new verified
generation* through the existing preparation, selection lock and maintenance gate. Nothing here
overwrites a live policy, starts a daemon or host, copies a session, grant or approval, or claims
observed protection. The next launch starts fresh authority from whichever generation is selected.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
FORMAT = 'sw-pilot-policy-activation/1'
JOURNAL_FORMAT = 'sw-pilot-policy-activation-journal/1'
JOURNAL = 'policy-activation-journal.json'
POLICIES = 'operator-policies'
MARKER_FORMAT = 'sw-pilot-preparation/1'
LIMIT = 65536
HISTORY = 16
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[0-9a-f]{32}\Z')
# A Console-owned home keeps managed identity next to the installation; never layer a local policy on it.
MANAGED = re.compile(r'(?i)(managed|enroll|console|signing|policy-?key)')
PUBLIC = re.compile(r'(policy_activation|maintenance|candidate)_[a-z_]{1,80}\Z')
# Finite reasons from the accepted transition helpers, reported under this command's prefix.
INHERITED = frozenset({'selected_generation_in_use_or_transitioning', 'active_or_uncertain_pilot_run',
                       'pilot_process_observation_unavailable', 'not_prepared', 'stale_source', 'dirty_source',
                       'selection_not_current', 'invalid_current_marker', 'owned_bounded_record_required'})
_MODULES = {}


def require(ok, code):
    if not ok:
        raise ValueError('policy_activation_' + code)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def modules():
    if not _MODULES:
        _MODULES['sw'] = load('activation_switch', 'switch-prepared-pilot.py')
        _MODULES['pml'] = load('activation_maintenance_launch', 'pilot_maintenance_launch.py')
        _MODULES['runner'] = load('activation_runner', 'pilot-run.py')
    return _MODULES


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- journal (bounded, private, atomic)
def empty_journal():
    return {'format': JOURNAL_FORMAT, 'pending': None, 'history': []}


def read_journal(preparation):
    path = preparation / JOURNAL
    if not path.exists() and not path.is_symlink():
        return empty_journal()
    try:
        _, _, value = modules()['sw'].strict_record(path)
    except (OSError, ValueError):
        raise ValueError('policy_activation_journal_invalid') from None
    require(type(value) is dict and set(value) == {'format', 'pending', 'history'} and value['format'] == JOURNAL_FORMAT
            and type(value['history']) is list and len(value['history']) <= HISTORY
            and (value['pending'] is None or type(value['pending']) is dict)
            and len(canonical(value)) <= LIMIT, 'journal_invalid')
    return value


def write_journal(preparation, value):
    require(len(canonical(value)) <= LIMIT, 'journal_limit')
    modules()['sw'].publish_json(preparation, JOURNAL, value)


def record(entry, outcome):
    return {**{k: v for k, v in entry.items() if k not in ('after_state', 'after_marker')}, 'outcome': outcome}


def settle(preparation, journal, outcome):
    journal['history'] = (journal['history'] + [record(journal['pending'], outcome)])[-HISTORY:]
    journal['pending'] = None
    write_journal(preparation, journal)


# ---------------------------------------------------------------- selected policy storage
def store_candidate(preparation, facts):
    """Immutable private copy of the reviewed policy; a retry may only find identical bytes."""
    root = preparation / POLICIES
    if not root.exists():
        root.mkdir(mode=0o700)
    modules()['sw'].PREP.private_dir(root)
    target = root / facts['candidate_sha256']
    wanted = {'policy.yaml': facts['policy_raw'], 'candidate.json': facts['manifest_raw']}
    if target.exists():
        modules()['sw'].PREP.private_dir(target)
        require(sorted(os.listdir(target)) == sorted(wanted), 'staged_policy_changed')
        for name, raw in wanted.items():
            require(modules()['sw'].regular(target / name)[1] == raw, 'staged_policy_changed')
        return target / 'policy.yaml'
    stage = root / ('.stage-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    for name, raw in wanted.items():
        with (stage / name).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    os.rename(stage, target)
    return target / 'policy.yaml'


# ---------------------------------------------------------------- reconstruction via the accepted validator
def run_agent(agentfw, words):
    result = subprocess.run([str(agentfw), 'policy-candidate', *map(str, words)], cwd='/',
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=120)
    require(result.returncode == 0 and len(result.stdout) <= 512 * 1024, 'candidate_validation_refused')
    value = json.loads(result.stdout.splitlines()[-1])
    require(type(value) is dict and value.get('active') is False and value.get('executed') is False, 'candidate_validation_refused')
    return value


def candidate_facts(args, ctx):
    """Only the accepted reconstruction can authorize: a matching hash or example never does."""
    agentfw, base = ctx['paths']['agentfw'], ctx['paths']['policy']
    for name in ('profile', 'constraints', 'examples', 'candidate'):
        require(getattr(args, name).is_absolute(), 'absolute_candidate_inputs_required')
    require(HEX.fullmatch(args.expect_candidate or ''), 'candidate_digest_required')
    inspected = run_agent(agentfw, ['inspect', '--profile', args.profile, '--policy', base])
    pins = inspected.get('pins')
    require(inspected.get('status') == 'inspected' and type(pins) is dict
            and pins.get('policy_sha256') == ctx['selection']['files']['policy']['sha256'], 'base_policy_mismatch')
    validated = run_agent(agentfw, ['validate', '--profile', args.profile, '--policy', base, '--constraints', args.constraints,
                                    '--examples', args.examples, '--out', args.candidate, '--exported', args.candidate,
                                    '--expect-candidate', args.expect_candidate])
    require(validated.get('status') == 'validated_inert' and validated.get('restricting_only') is True
            and validated.get('candidate_sha256') == args.expect_candidate
            and validated.get('base_policy_sha256') == pins['policy_sha256']
            and type(validated.get('added_rules')) is int and validated['added_rules'] >= 1
            and all(HEX.fullmatch(str(validated.get(k, ''))) for k in ('policy_sha256', 'constraints_sha256')),
            'candidate_not_provably_restricting')
    sw = modules()['sw']
    policy_raw = sw.regular(args.candidate / 'policy.yaml')[1]
    manifest_raw = sw.regular(args.candidate / 'candidate.json')[1]
    # Tool-group floors and destination subsets bind to the *authoring* bundle's registry, which this
    # installation cannot prove equals its own original-server registry. Activate action-class denials only.
    try:
        constraints = json.loads(sw.regular(args.candidate / 'constraints.json')[1])
    except ValueError:
        raise ValueError('policy_activation_candidate_scope_unsupported') from None
    require(type(constraints) is dict and constraints.get('deny_tools') == [] and constraints.get('allowed_destinations') is None
            and type(constraints.get('deny_actions')) is list and constraints['deny_actions'], 'candidate_scope_unsupported')
    require(sha(policy_raw) == validated['policy_sha256'] and policy_raw != ctx['policy_raw'], 'candidate_policy_mismatch')
    return {'candidate_sha256': validated['candidate_sha256'], 'policy_sha256': validated['policy_sha256'],
            'base_policy_sha256': validated['base_policy_sha256'], 'constraints_sha256': validated['constraints_sha256'],
            'added_rules': validated['added_rules'], 'pins_sha256': digest(pins),
            'policy_raw': policy_raw, 'manifest_raw': manifest_raw}


# ---------------------------------------------------------------- installation context
def require_supported_home(home, prefix):
    for name in ('current.json', 'journal.json'):
        require(not ((prefix / name).exists() or (prefix / name).is_symlink()), 'coordinated_prefix_unsupported')
    require(not any(MANAGED.search(name) for name in os.listdir(home)), 'managed_home_unsupported')


def context(args, front):
    mods = modules()
    sw, pml = mods['sw'], mods['pml']
    require(getattr(front, 'INSTALLED_HOME', None) is not None, 'installed_home_required')
    home, prefix = Path(front.PROJECT_HOME), args.prefix
    require(prefix.is_absolute() and args.state_root.is_absolute(), 'absolute_prefix_and_state_root_required')
    require_supported_home(home, prefix)
    state = front.verified_state(prefix)
    preparation = prefix / 'preparation'
    sw.output_root(preparation)
    chosen = argparse.Namespace(selection=Path(state['selection']), expected_commit=state['commit'],
                                ask_wait_seconds=0, timeout_seconds=180, port=0)
    selection, paths, profiles = mods['runner'].selected(chosen)
    require('linked_worktree' not in selection and 'filesystem_roots' not in selection, 'selection_scope_unsupported')
    _, marker_raw, marker = sw.marker(preparation)
    require(marker['generation'] == chosen.selection.parent.name and marker['selection_sha256'] == state['selection_sha256'],
            'selection_not_current')
    bound = pml.selected_binding(argparse.Namespace(agent_home=home, maintenance_home=None, state_root=args.state_root,
                                                    maintenance_coordinator_root=None), state, front.PREP, mods['runner'])
    state_file = front.layout(prefix)['state']
    return {'home': home, 'prefix': prefix, 'preparation': preparation, 'state': state, 'state_raw': state_file.read_bytes(),
            'selection': selection, 'selection_path': chosen.selection, 'paths': paths, 'profiles': profiles,
            'marker': marker, 'marker_raw': marker_raw, 'bound': bound,
            'policy_raw': Path(paths['policy']).read_bytes()}


def gate_view(ctx, store):
    """Maintenance facts observed while the gate is held. Active or uncertain runs block."""
    pml, m = modules()['pml'], modules()['pml'].M
    pml.revalidate(ctx['bound'])
    inventory = pml.inventory(store, ctx['bound'])
    snapshot = store.snapshot()
    _, marker, _ = store.marker(allow_uncertain=True)
    owned = marker is not None and m.digest(m.scope(marker['binding'])) == m.digest(m.scope(ctx['bound']))
    return {'mode': snapshot['mode'], 'revision': snapshot['revision'], 'marker_sha256': snapshot['marker_sha256'],
            'installation': 'matches' if owned else 'mismatch', 'inventory_sha256': m.digest(inventory),
            'active': inventory['active'], 'uncertain': inventory['uncertain']}


def blockers(view, journal):
    found = []
    if view['mode'] == 'not-enrolled':
        found.append('maintenance_entry_required')
    elif view['mode'] != 'entered':
        found.append('maintenance_entry_required' if view['mode'] == 'open' else 'maintenance_state_uncertain')
    if view['mode'] != 'not-enrolled' and view['installation'] != 'matches':
        found.append('installation_mismatch')
    if view.get('uncertain'):
        found.append('runs_uncertain')
    if view.get('active'):
        found.append('runs_active')
    if journal['pending'] is not None:
        found.append('recover_pending_activation_first')
    return found


def current_summary(ctx):
    files = ctx['selection']['files']
    return {'generation': ctx['marker']['generation'], 'marker_sha256': sha(ctx['marker_raw']),
            'selection_sha256': ctx['marker']['selection_sha256'], 'policy_sha256': files['policy']['sha256'],
            'front_door_state_sha256': sha(ctx['state_raw']), 'source_commit': ctx['state']['commit']}


def build_plan(ctx, view, journal, operation, subject):
    plan = {'format': FORMAT, 'operation': operation,
            'installation_binding_sha256': modules()['pml'].M.digest(ctx['bound']),
            'current': current_summary(ctx), 'journal_sha256': digest(journal), 'maintenance': view, 'subject': subject,
            'effects': {'publishes_new_selection_only': True, 'overwrites_live_policy': False,
                        'copies_session_or_authority': False, 'starts_process': False},
            'blockers': blockers(view, journal)}
    return {**plan, 'confirmation_sha256': digest(plan)}


def observe(ctx, exclusive):
    """The maintenance gate stays held for the whole operation; absence is reported, never created."""
    m = modules()['pml'].M
    stack = ExitStack()
    if m.Store.absent(ctx['home']):
        require(not exclusive, 'maintenance_entry_required')
        return stack, None, {'mode': 'not-enrolled', 'installation': 'mismatch', 'active': 0, 'uncertain': True,
                             'revision': None, 'marker_sha256': None, 'inventory_sha256': None}
    store = stack.enter_context(m.Store(ctx['home']))
    stack.enter_context(store.locked(exclusive=exclusive))
    return stack, store, gate_view(ctx, store)


# ---------------------------------------------------------------- generation staging and comparison
def stage_words(ctx, front, policy_path):
    state, selection = ctx['state'], ctx['selection']
    files, inputs = selection['files'], state.get('inputs', {})
    words = [str(front.SCRIPTS / 'prepare-installed-pilot.py'), '--prepare', '--rebuild', '--stage-only',
             '--output', str(ctx['preparation']), '--expected-commit', state['commit'],
             '--git-profile', front.PREP.GIT_PROFILES.from_selection(selection),
             '--refusal-verdict', selection['expected_refusal']['verdict'],
             '--refusal-rule', selection['expected_refusal']['rule']]
    for role in front.PREP.PILOT.ROLES:
        if role in ('node', 'npm', 'policy'):
            continue
        words += ['--' + role.replace('_', '-'), files[role]['path']]
    if inputs.get('node_archive'):
        words += ['--node-archive', inputs['node_archive']]
    else:
        words += ['--node', files['node']['path'], '--npm', files['npm']['path']]
    words += ['--policy', str(policy_path)]
    if 'prepared_workspaces' in selection:
        roots = selection['prepared_workspaces']['roots']
        words += ['--filesystem-workspace', roots['filesystem']['path'], '--git-workspace', roots['git']['path']]
    for name in ('python_archive', 'npm_cache', 'wheelhouse'):
        if inputs.get(name):
            words += ['--' + name.replace('_', '-'), inputs[name]]
    if state.get('allow_download'):
        words.append('--allow-download')
    return words


def stage_generation(ctx, front, policy_path):
    code, value = front.child(stage_words(ctx, front, policy_path), timeout=3600, cwd=front.ROOT)
    require(code == 0 and value.get('status') == 'staged-not-selected' and ID.fullmatch(str(value.get('generation', '')))
            and HEX.fullmatch(str(value.get('selection_sha256', ''))), 'staging_refused')
    return value


def same_scope(old, new, policy_item):
    """Only the selected policy may differ: nothing else is silently relaxed, swapped or widened."""
    for key in set(old) | set(new):
        if key not in ('files', 'prepared_profiles'):
            require(old.get(key) == new.get(key), 'generation_scope_changed')
    require(set(old['files']) == set(new['files']), 'generation_scope_changed')
    for role, item in old['files'].items():
        if role == 'policy':
            require(new['files']['policy'] == policy_item, 'generation_policy_not_selected')
        elif role in ('node', 'npm'):
            require(new['files'][role]['sha256'] == item['sha256'], 'generation_scope_changed')
        else:
            require(new['files'][role] == item, 'generation_scope_changed')
    for kind in ('filesystem', 'git'):
        before, after = old['prepared_profiles'][kind], new['prepared_profiles'][kind]
        for key in ('format', 'registry_sha256', 'package_tree_sha256', 'policy_sha256'):
            require(before[key] == after[key], 'generation_profile_changed')


def verified_generation(ctx, front, generation):
    sw = modules()['sw']
    directory = ctx['preparation'] / 'generations' / generation
    sw.PREP.private_dir(directory)
    selection_path, profiles = front.PREP.verify_generation(directory, ctx['state']['commit'])
    raw = selection_path.read_bytes()
    selection = front.PREP.PILOT.strict_json(raw)
    require(selection.get('prepared_profiles') == profiles, 'generation_profile_changed')
    return selection_path, sha(raw), selection


# ---------------------------------------------------------------- transition
def state_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def publish(ctx, front, journal, plan, operation, target):
    """Journal intent first; marker, then front-door state; every crash point is recoverable."""
    sw = modules()['sw']
    preparation, prefix = ctx['preparation'], ctx['prefix']
    after_marker = {'format': MARKER_FORMAT, 'generation': target['generation'],
                    'selection_sha256': target['selection_sha256'], 'status': 'prepared-not-active'}
    after_state = {**ctx['state'], 'selection': str(target['selection_path']),
                   'selection_sha256': target['selection_sha256'], 'status': 'prepared-not-active'}
    pending = {'operation': operation, 'plan_sha256': plan['confirmation_sha256'],
               'previous_generation': ctx['marker']['generation'], 'target_generation': target['generation'],
               'previous_selection_sha256': ctx['marker']['selection_sha256'],
               'target_selection_sha256': target['selection_sha256'],
               'previous_selection_path': ctx['state']['selection'], 'target_selection_path': str(target['selection_path']),
               'previous_policy_sha256': ctx['selection']['files']['policy']['sha256'],
               'target_policy_sha256': target['policy_sha256'], 'candidate_sha256': target.get('candidate_sha256'),
               'before_marker_sha256': sha(ctx['marker_raw']), 'after_marker_sha256': sha(canonical(after_marker) + b'\n'),
               'before_state_sha256': sha(ctx['state_raw']), 'after_state_sha256': sha(state_bytes(after_state)),
               'after_state': after_state}
    with sw.LOCK.hold(preparation, exclusive=True):
        # Another writer or a launch that slipped past the gate changes one of these exactly-bound inputs.
        _, latest_raw, _ = sw.marker(preparation)
        require(sha(latest_raw) == pending['before_marker_sha256']
                and sha(front.layout(prefix)['state'].read_bytes()) == pending['before_state_sha256'], 'concurrent_selection_change')
        sw.require_inactive({'agent_path': str(ctx['paths']['agentfw']), 'claude_path': str(ctx['paths']['claude'])})
        journal['pending'] = pending
        write_journal(preparation, journal)
        inject('after_intent')
        sw.publish_json(preparation, 'current.json', after_marker)
        inject('after_marker')
        front.write_state(prefix, after_state)
        inject('after_state')
        settle(preparation, journal, 'published')
    return pending


def inject(point):
    """Test seam for crash points; never set outside tests."""


def recover_pending(ctx, front, journal):
    sw = modules()['sw']
    preparation, prefix = ctx['preparation'], ctx['prefix']
    with sw.LOCK.hold(preparation, exclusive=True):
        pending = journal['pending']
        if pending is None:
            return {'status': 'settled', 'actual_generation': ctx['marker']['generation']}
        try:
            _, marker_raw, _ = sw.marker(preparation)
        except (OSError, ValueError, KeyError, TypeError):
            return {'status': 'conflicting_operator_edit', 'actual_generation': None}
        marker_sha, state_sha = sha(marker_raw), sha(front.layout(prefix)['state'].read_bytes())
        outcome = None
        if marker_sha == pending['before_marker_sha256'] and state_sha == pending['before_state_sha256']:
            outcome = 'interrupted_before_publication'
        elif marker_sha == pending['after_marker_sha256'] and state_sha == pending['after_state_sha256']:
            outcome = 'published_before_journal_completion'
        elif marker_sha == pending['after_marker_sha256'] and state_sha == pending['before_state_sha256']:
            # The selection was published; completing the exactly journaled state is the only roll-forward.
            front.write_state(prefix, pending['after_state'])
            outcome = 'completed_by_recovery'
        if outcome is None:
            return {'status': 'conflicting_operator_edit', 'actual_generation': json.loads(marker_raw).get('generation')}
        settle(preparation, journal, outcome)
        return {'status': outcome, 'actual_generation': json.loads(modules()['sw'].marker(preparation)[1])['generation']}


# ---------------------------------------------------------------- commands
def revert_target(ctx, front, journal, generation):
    require(type(generation) is str and ID.fullmatch(generation) and generation != ctx['marker']['generation'], 'target_generation_invalid')
    confirmed = [h for h in journal['history'] if h['target_generation'] == ctx['marker']['generation']
                 and h['previous_generation'] == generation and h['outcome'] in ('published', 'completed_by_recovery',
                                                                                'published_before_journal_completion')]
    require(confirmed, 'revert_target_not_previously_confirmed')
    selection_path, selection_sha, selection = verified_generation(ctx, front, generation)
    require(selection_sha == confirmed[-1]['previous_selection_sha256'] and str(selection_path) == confirmed[-1]['previous_selection_path'],
            'revert_target_changed')
    return {'generation': generation, 'selection_sha256': selection_sha, 'selection_path': selection_path,
            'policy_sha256': selection['files']['policy']['sha256'], 'candidate_sha256': None}


def operation(args, front):
    ctx = context(args, front)
    sw = modules()['sw']
    journal = read_journal(ctx['preparation'])
    applying = args.action in ('confirm',) or (args.action == 'revert' and args.confirm is not None)
    stack, store, view = observe(ctx, exclusive=applying)
    with stack:
        if args.action == 'inspect':
            return inspect_report(ctx, view, journal)
        if args.action == 'recover':
            return recover_pending(ctx, front, journal)
        if args.action == 'revert':
            target = revert_target(ctx, front, journal, args.generation)
            plan = build_plan(ctx, view, journal, 'revert', {k: str(v) for k, v in target.items() if k != 'candidate_sha256'})
        else:
            facts = candidate_facts(args, ctx)
            subject = {k: v for k, v in facts.items() if k not in ('policy_raw', 'manifest_raw')}
            plan = build_plan(ctx, view, journal, 'activate', subject)
        if not applying:
            return {**plan, 'status': 'preview', 'mutates': False, 'executed': False}
        require(args.confirm == plan['confirmation_sha256'], 'confirmation_stale')
        require(not plan['blockers'], plan['blockers'][0] if plan['blockers'] else 'blocked')
        sw.require_inactive({'agent_path': str(ctx['paths']['agentfw']), 'claude_path': str(ctx['paths']['claude'])})
        if args.action == 'revert':
            pending = publish(ctx, front, journal, plan, 'revert', target)
            result = {'status': 'reverted'}
        else:
            policy_path = store_candidate(ctx['preparation'], facts)
            staged = stage_generation(ctx, front, policy_path)
            selection_path, selection_sha, selection = verified_generation(ctx, front, staged['generation'])
            require(selection_sha == staged['selection_sha256'] and str(selection_path) == staged['selection'], 'staging_changed')
            same_scope(ctx['selection'], selection, {'path': str(policy_path), 'sha256': facts['policy_sha256']})
            target = {'generation': staged['generation'], 'selection_sha256': selection_sha, 'selection_path': selection_path,
                      'policy_sha256': facts['policy_sha256'], 'candidate_sha256': facts['candidate_sha256']}
            pending = publish(ctx, front, journal, plan, 'activate', target)
            result = {'status': 'activated'}
        return {**result, 'plan_sha256': plan['confirmation_sha256'], 'previous_generation': pending['previous_generation'],
                'generation': pending['target_generation'], 'policy_sha256': pending['target_policy_sha256'],
                'active_protection': 'not-observed', 'session_authority_copied': False,
                'next': 'Leave maintenance with a fresh preview; the next launch starts fresh authority from this generation.'}


def inspect_report(ctx, view, journal):
    files = ctx['selection']['files']
    stored = ctx['preparation'] / POLICIES
    origin = 'operator-candidate' if Path(files['policy']['path']).parent.parent == stored else 'baseline'
    return {'format': FORMAT, 'status': 'inspected', 'executed': False, 'active_protection': 'not-observed',
            'current': current_summary(ctx), 'selected_policy_origin': origin,
            'pending': None if journal['pending'] is None else record(journal['pending'], 'pending'),
            'history': [{k: h[k] for k in ('operation', 'previous_generation', 'target_generation', 'candidate_sha256',
                                           'target_policy_sha256', 'outcome')} for h in journal['history']],
            'maintenance': view, 'blockers': blockers(view, journal)}


def main(argv, front):
    parser = argparse.ArgumentParser(prog=front.PROG + ' policy-activation', description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'preview', 'confirm', 'revert', 'recover'):
        sub = commands.add_parser(action)
        sub.add_argument('--prefix', type=Path, required=True)
        sub.add_argument('--state-root', type=Path, required=True)
        if action in ('preview', 'confirm'):
            sub.add_argument('--candidate', type=Path, required=True, help='exported inert candidate directory')
            sub.add_argument('--expect-candidate', required=True, help='candidate_sha256 from the reviewed export')
            sub.add_argument('--profile', type=Path, required=True)
            sub.add_argument('--constraints', type=Path, required=True)
            sub.add_argument('--examples', type=Path, required=True)
        if action == 'confirm':
            sub.add_argument('--confirm', required=True, help='confirmation_sha256 from a fresh preview')
        if action == 'revert':
            sub.add_argument('--generation', required=True)
            sub.add_argument('--confirm', help='confirmation_sha256 from a fresh revert preview')
    args = parser.parse_args(argv)
    report = {'format': FORMAT, 'status': 'refused', 'executed': False, 'active_protection': 'not-observed'}
    try:
        require(sys.platform.startswith('linux') and front.platform_reason() is None, 'native_linux_required')
        require(getattr(args, 'confirm', None) is None or HEX.fullmatch(args.confirm), 'confirmation_required')
        report = operation(args, front)
        print(json.dumps(report, sort_keys=True))
        return 2 if report.get('status') == 'conflicting_operator_edit' else 0
    except Exception as error:
        reason = str(error)
        report['reason'] = (reason if PUBLIC.fullmatch(reason) else
                            'policy_activation_' + reason if reason in INHERITED else 'policy_activation_input_unavailable')
        report['action'] = 'Inspect the exact inputs and retained journal; repeat the preview. Nothing is retried or repaired automatically.'
        print(json.dumps(report, sort_keys=True))
        return 2
