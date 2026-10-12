"""Controlled execution of synthetic fixtures with instrumented effect traces.

Evidence model (see docs/EVIDENCE_MODEL.md):
  1. Instrumented world: in-memory stores, ACL table, remote (HTTP GET) table, outbox.
     Fixtures act on it only through `Effects`; every call appends a trace event.
  2. Runtime guard: during a call, file/OS/process/socket entry points and imports are
     replaced by functions that raise SandboxViolation.
  3. State diff: every state change between the before/after snapshots must be explained
     by a trace event.
  4. Raw-access audit: every read-type access to a world table must be explained by a
     trace event on the same table/key (catches reads that bypass `Effects`).
  5. Canaries: one probe per event type proves the instrumentation detects that channel;
     two rogue probes prove the diff and access audits detect bypasses.

This is NOT a security boundary. Fixtures are trusted, author-written synthetic code; the
guard exists to detect some accidental side-effect paths, not to contain hostile code. Known
gaps (docs/EVIDENCE_MODEL.md): e.g. os.open/os.write/os.truncate/os.link and os.environ are not
guarded, and base-class dict reads bypass the raw-access audit.
"""
import builtins
import io
import json
import os
import socket
import subprocess
from contextlib import contextmanager

from .hashing import sha
from .labels import ACTIONS

# Event type -> (action, contract basis). Single source of truth for trace-derived labels.
EVENT_TO_ACTION = {
    'store_read': ('read', 'SOU-10 §2 read: retrieving/inspecting existing data or metadata'),
    'http_get': ('read', 'SOU-10 §2 rule 2 / D03: plain HTTP GET without body is read; URL alone is not send_data'),
    'store_write': ('write', 'SOU-10 §2 write: creating/updating/modifying data content or storage state'),
    'store_delete': ('delete', 'SOU-10 §2 delete: removing/truncating/unlinking; D03: does not imply write'),
    'send': ('send_data', 'SOU-10 §2 send_data: egressing payload over a network/communication channel; D03: does not imply read'),
    'acl_change': ('change_permissions', 'SOU-10 §2 change_permissions: ACLs/modes/ownership; D03: does not imply write'),
}
NON_EFFECT_EVENTS = ('opaque_invoked',)
IMPORT_ALLOW = frozenset({'json'})


class SandboxViolation(Exception):
    pass


class OpaqueEffect(Exception):
    """Raised when execution reaches a component whose semantics are not modelled."""


class ChannelUnavailable(Exception):
    pass


class TrackingStore(dict):
    """dict that logs read-type accesses; mutations are caught by the state diff."""

    def __init__(self, name, log, data=None):
        super().__init__(data or {})
        self._name, self._log = name, log

    def _touch(self, key):
        self._log.append((self._name, key))

    def __getitem__(self, key):
        self._touch(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self._touch(key)
        return super().get(key, default)

    def __contains__(self, key):
        self._touch(key)
        return super().__contains__(key)

    def __iter__(self):
        self._touch('*')
        return super().__iter__()

    def keys(self):
        self._touch('*')
        return super().keys()

    def values(self):
        self._touch('*')
        return super().values()

    def items(self):
        self._touch('*')
        return super().items()


def _plain(store):
    # Base-class method: bypasses TrackingStore overrides, so snapshots are not logged.
    return json.loads(json.dumps({k: v for k, v in dict.items(store)}, sort_keys=True))


class World:
    def __init__(self, spec):
        self.spec = json.loads(json.dumps(spec))
        self.raw_access = []
        self.tables = {name: TrackingStore(name, self.raw_access, data)
                       for name, data in spec.get('stores', {}).items()}
        self.tables['acl'] = TrackingStore('acl', self.raw_access, spec.get('acl', {}))
        self.tables['remote'] = TrackingStore('remote', self.raw_access, spec.get('remote', {}))
        self.outbox = []
        self.disabled = frozenset(spec.get('disabled_actions', []))

    def snapshot(self):
        return {'tables': {n: _plain(t) for n, t in dict.items(self.tables)},
                'outbox': json.loads(json.dumps(self.outbox))}


class Effects:
    """The only interface a fixture uses to affect the world."""

    def __init__(self, world):
        self._world = world
        self.trace = []

    def _event(self, kind, **detail):
        ev = {'seq': len(self.trace) + 1, 'event': kind, **detail}
        self.trace.append(ev)
        return ev

    def _table(self, name):
        return dict.__getitem__(self._world.tables, name)

    def get(self, store, key):
        self._event('store_read', table=store, key=key)
        return self._table(store)[key]

    def put(self, store, key, value):
        self._event('store_write', table=store, key=key, mode='set')
        self._table(store)[key] = value

    def create(self, store, key, value):
        """Create a NEW entry; refuses to overwrite (keeps truncation semantics out of scope)."""
        self._event('store_write', table=store, key=key, mode='create')
        table = self._table(store)
        if dict.__contains__(table, key):
            raise ValueError(f'create target already exists: {store}/{key}')
        dict.__setitem__(table, key, value)

    def append(self, store, key, data):
        """Append to an EXISTING entry without reading it back (POSIX `>>` semantics)."""
        self._event('store_write', table=store, key=key, mode='append')
        table = self._table(store)
        if not dict.__contains__(table, key):
            raise ValueError(f'append target must already exist: {store}/{key}')
        dict.__setitem__(table, key, dict.__getitem__(table, key) + data)

    def inspect(self, store, path):
        """Inspect metadata/listing of a file or directory prefix (e.g. `ls`)."""
        self._event('store_read', table=store, key=path, view='metadata')
        table = self._table(store)
        prefix = path.rstrip('/') + '/'
        names = sorted(k for k in dict.keys(table) if k == path or k.startswith(prefix))
        if not names:
            raise ValueError(f'no such path in world: {store}/{path}')
        return '\n'.join(names)

    def remove(self, store, key):
        self._event('store_delete', table=store, key=key)
        del self._table(store)[key]

    def http_get(self, url):
        self._event('http_get', table='remote', key=url, method='GET', body=None)
        return self._table('remote')[url]

    def send(self, channel, recipient, payload):
        if 'send_data' in self._world.disabled:
            raise ChannelUnavailable('send_data channel is not available in this environment')
        text = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
        self._event('send', channel=channel, recipient=recipient, payload_sha256=sha(text), payload_len=len(text))
        self._world.outbox.append({'channel': channel, 'recipient': recipient, 'payload': text})

    def set_acl(self, resource, principal, role):
        self._event('acl_change', table='acl', key=resource, principal=principal, role=role)
        acl = self._table('acl')
        current = dict(acl[resource]) if resource in acl else {}
        current[principal] = role
        acl[resource] = current

    def opaque(self, component):
        self._event('opaque_invoked', component=component)
        raise OpaqueEffect(component)


@contextmanager
def guard(violations):
    def deny(name):
        def blocked(*_a, **_k):
            violations.append(name)
            raise SandboxViolation(name)
        return blocked

    targets = [(builtins, 'open'), (io, 'open'), (socket, 'socket'), (socket, 'create_connection'),
               (subprocess, 'Popen'), (subprocess, 'run')]
    targets += [(os, n) for n in ('system', 'popen', 'remove', 'unlink', 'rename', 'replace', 'mkdir',
                                   'makedirs', 'rmdir', 'chmod', 'chown', 'listdir', 'scandir')
                if hasattr(os, n)]
    saved = [(mod, name, getattr(mod, name)) for mod, name in targets]
    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name.split('.')[0] not in IMPORT_ALLOW:
            violations.append('import:' + name)
            raise SandboxViolation('import:' + name)
        return real_import(name, globals, locals, fromlist, level)

    try:
        for mod, name, _ in saved:
            setattr(mod, name, deny(f'{mod.__name__}.{name}'))
        builtins.__import__ = guarded_import
        yield
    finally:
        builtins.__import__ = real_import
        for mod, name, original in saved:
            setattr(mod, name, original)


def _unexplained_changes(before, after, trace):
    problems = []
    keyed = {(e['event'], e.get('table'), e.get('key')) for e in trace}
    for table in sorted(set(before['tables']) | set(after['tables'])):
        b, a = before['tables'].get(table, {}), after['tables'].get(table, {})
        for key in sorted(set(b) | set(a)):
            if b.get(key) == a.get(key) and (key in b) == (key in a):
                continue
            if key not in a:
                ok = ('store_delete', table, key) in keyed
            elif table == 'acl':
                ok = ('acl_change', 'acl', key) in keyed
            elif table == 'remote':
                ok = False
            else:
                ok = ('store_write', table, key) in keyed
            if not ok:
                problems.append(f'unexplained state change: {table}/{key}')
    sends = [e for e in trace if e['event'] == 'send']
    new = after['outbox'][len(before['outbox']):]
    if after['outbox'][:len(before['outbox'])] != before['outbox'] or len(new) != len(sends) or \
            any(m['recipient'] != e['recipient'] or sha(m['payload']) != e['payload_sha256'] for m, e in zip(new, sends)):
        problems.append('outbox change not explained by send events')
    return problems


def _unexplained_access(raw_access, trace):
    explained = {(e.get('table'), e.get('key')) for e in trace}
    return sorted({f'unexplained read access: {t}/{k}' for t, k in raw_access if (t, k) not in explained})


def execute(fixture, args, world_spec):
    """Run one fixture call under guard; return a JSON-serialisable execution record."""
    world = World(world_spec)
    fx = Effects(world)
    violations = []
    outcome, opaque_component = 'completed', None
    before = world.snapshot()
    world.raw_access.clear()
    try:
        with guard(violations):
            fixture(fx, json.loads(json.dumps(args)))
    except OpaqueEffect as exc:
        outcome, opaque_component = 'stopped_at_opaque_component', str(exc)
    except SandboxViolation:
        outcome = 'sandbox_violation'
    after = world.snapshot()
    problems = _unexplained_changes(before, after, fx.trace) + _unexplained_access(world.raw_access, fx.trace)
    if violations:
        outcome = 'sandbox_violation'
    return {
        'outcome': outcome,
        'opaque_component': opaque_component,
        'guard_violations': violations,
        'unexplained': problems,
        'trace': fx.trace,
        'trace_sha256': sha(fx.trace),
        'world_initial_sha256': sha(world_spec),
        'disabled_actions': sorted(world.disabled),
        'state_diff_explained': not problems,
    }


class EvidenceError(ValueError):
    pass


def labels_from_execution(rec, coverage, strength='execution'):
    """Derive tri-state labels + per-label evidence from an execution record.

    true  <- a trace event mapped by EVENT_TO_ACTION
    false <- run completed, diff/access fully explained, channel covered by a canary, no event
    false <- (SOU13-CONV-FORBIDDEN-ACTIONS, pending) action disabled by the environment while an opaque component remains
    null  <- run stopped at an opaque component and absence is not established
    """
    if rec['outcome'] == 'sandbox_violation' or rec['unexplained']:
        raise EvidenceError(f"unreliable execution: {rec['outcome']} {rec['guard_violations']} {rec['unexplained']}")
    observed = {}
    for e in rec['trace']:
        if e['event'] in EVENT_TO_ACTION:
            observed.setdefault(EVENT_TO_ACTION[e['event']][0], []).append(e['seq'])
        elif e['event'] not in NON_EFFECT_EVENTS:
            raise EvidenceError('unmapped event ' + e['event'])
    targets, evidence = {}, {}
    for a in ACTIONS:
        if a in observed:
            rules = sorted({EVENT_TO_ACTION[e['event']][1] for e in rec['trace'] if e['seq'] in observed[a]})
            targets[a] = True
            evidence[a] = {'value': True, 'basis': 'controlled_execution_trace', 'strength': strength,
                           'refs': [f'trace#{s}' for s in observed[a]] + rules}
        elif rec['outcome'] == 'completed':
            if not coverage.get(a):
                raise EvidenceError(f'no canary coverage for {a}')
            targets[a] = False
            evidence[a] = {'value': False, 'basis': 'controlled_execution_absence', 'strength': strength,
                           'refs': ['state_diff_explained', 'raw_access_explained', f'canary:{a}']}
        elif a in rec['disabled_actions']:
            targets[a] = False
            evidence[a] = {'value': False, 'basis': 'environment_channel_disabled', 'strength': 'environment_declaration',
                           'refs': ['world.disabled_actions', 'SOU13-CONV-FORBIDDEN-ACTIONS']}
        else:
            targets[a] = None
            evidence[a] = {'value': None, 'basis': 'opaque_component', 'strength': 'not_established',
                           'refs': [f"opaque:{rec['opaque_component']}"]}
    return targets, rec['outcome'] != 'completed', evidence


# --- canaries --------------------------------------------------------------------------------

CANARY_WORLD = {'stores': {'docs': {'k': 'v'}}, 'acl': {'r': {}}, 'remote': {'https://c.example.test/x': 'body'}}
CANARIES = {
    'store_read': lambda fx, a: fx.get('docs', 'k'),
    'http_get': lambda fx, a: fx.http_get('https://c.example.test/x'),
    'store_write': lambda fx, a: fx.put('docs', 'k2', 'new'),
    'store_delete': lambda fx, a: fx.remove('docs', 'k'),
    'send': lambda fx, a: fx.send('http', 'https://c.example.test/in', 'p'),
    'acl_change': lambda fx, a: fx.set_acl('r', 'u', 'viewer'),
}


def _rogue_write(fx, _a):
    dict.__getitem__(fx._world.tables, 'docs')['k'] = 'tampered'


def _rogue_read(fx, _a):
    return dict.__getitem__(fx._world.tables, 'docs')['k']


def _rogue_open(_fx, _a):
    # Read mode on a non-existent path: harmless even if the guard were broken.
    open('sou13-canary-nonexistent-dir/never.txt', 'r')


def run_canaries():
    """Prove each channel is observed and that bypasses are detected. Returns coverage record."""
    per_event = {}
    for event, fn in sorted(CANARIES.items()):
        rec = execute(fn, {}, CANARY_WORLD)
        per_event[event] = (rec['outcome'] == 'completed' and not rec['unexplained']
                            and [e['event'] for e in rec['trace']] == [event])
    detectors = {
        'unexplained_write_detected': bool(execute(_rogue_write, {}, CANARY_WORLD)['unexplained']),
        'unexplained_read_detected': bool(execute(_rogue_read, {}, CANARY_WORLD)['unexplained']),
        'guard_blocks_open': execute(_rogue_open, {}, CANARY_WORLD)['outcome'] == 'sandbox_violation',
    }
    by_action = {a: all(ok for ev, ok in per_event.items() if EVENT_TO_ACTION[ev][0] == a)
                 and any(EVENT_TO_ACTION[ev][0] == a for ev in per_event) for a in ACTIONS}
    by_action = {a: ok and all(detectors.values()) for a, ok in by_action.items()}
    report = {'per_event': per_event, 'detectors': detectors, 'by_action': by_action}
    report['sha256'] = sha(report)
    return report
