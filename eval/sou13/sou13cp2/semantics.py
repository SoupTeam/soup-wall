"""CP2 closed declarative semantics interpreter (replaces Python fixtures for NEW cases).

Why: the CP1 sandbox runs author-written Python fixtures under an in-process guard whose coverage is
incomplete (audit H1: os.open/os.write/... bypass) and whose raw-access audit misses reads and ignores the
event type (H2). New CP2 cases therefore never execute fixture code. A tool's semantics is DATA: a program
over a fixed, closed set of operations. Only this interpreter touches the in-memory world, and every
storage access it performs is logged with its TYPE and the sequence number of the operation that caused
it. The audit then requires every access to be of a kind permitted for that operation's event (a read
during a delete, a write that is later restored, or any access outside an operation is unexplained), and
every state change to be explained by an event. Unsupported behaviour is expressed only as `opaque`,
which yields null labels.

This is NOT a security boundary and says nothing about real tools: it is trusted, narrowly scoped
synthetic semantics. `false` means "absent in the declared synthetic semantics, program fully executed,
typed audit clean"."""
import copy
import json

try:  # repository layout
    from sou13.hashing import sha

    from .compute import COMPUTE
except ImportError:  # flat layout of a handoff package (tools/semantics.py, tools/compute.py, tools/hashing.py)
    from compute import COMPUTE
    from hashing import sha

# op -> allowed keys (besides 'op'); nested step lists are validated recursively
OPS = {
    'read': {'store', 'key', 'into'},
    'inspect': {'store', 'key'},
    'scan': {'store', 'prefix', 'into'},
    'http_get': {'url', 'into'},
    'create': {'store', 'key', 'value'},
    'set': {'store', 'key', 'value'},
    'append': {'store', 'key', 'value'},
    'delete': {'store', 'key'},
    'delete_prefix': {'store', 'prefix'},
    'send': {'channel', 'to', 'payload'},
    'acl_set': {'resource', 'principal', 'role'},
    'acl_revoke': {'resource', 'principal'},
    'compute': {'fn', 'inputs', 'into'},
    'opaque': {'component'},
    'when': {'arg', 'equals', 'then', 'else'},
    'foreach': {'arg', 'as', 'do'},
    'switch': {'on', 'cases'},
}
REQUIRED = {op: keys - {'into', 'else'} for op, keys in OPS.items()}
CHANNELS = ('http', 'email', 'chat', 'sms')


def _json_dump(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


# effect event (access class) -> storage access kinds that event may cause
PERMITTED_ACCESS = {
    'read': {'exists', 'value_read'},
    'inspect': {'exists', 'keys'},
    'scan': {'keys', 'value_read'},
    'create': {'exists', 'write'},
    'set': {'exists', 'write'},
    'append': {'exists', 'append'},
    'delete': {'exists', 'delete'},
    'delete_prefix': {'keys', 'delete'},
    'http_get': {'remote_read'},
    'send': {'outbox_write'},
    'acl_set': {'acl_read', 'acl_write'},
    'acl_revoke': {'acl_read', 'acl_write'},
}
MUTATING_ACCESS = {'write', 'append', 'delete', 'outbox_write', 'acl_write'}


class SemanticsError(ValueError):
    pass


class _Opaque(Exception):
    pass


# ---- program validation ------------------------------------------------------------------------------------
def _ref_ok(ref):
    if isinstance(ref, list):
        return all(_ref_ok(x) for x in ref)
    return isinstance(ref, (str, bool, int, float)) or ref is None


def program_errors(program, path='program'):
    if not isinstance(program, list):
        return [f'{path}: must be a list of operations']
    errors = []
    for i, step in enumerate(program):
        p = f'{path}[{i}]'
        if not isinstance(step, dict) or step.get('op') not in OPS:
            errors.append(f'{p}: unknown operation {step.get("op") if isinstance(step, dict) else step!r}')
            continue
        op, keys = step['op'], set(step) - {'op'}
        if keys - OPS[op]:
            errors.append(f'{p}: {op} does not accept {sorted(keys - OPS[op])}')
        if REQUIRED[op] - keys:
            errors.append(f'{p}: {op} requires {sorted(REQUIRED[op] - keys)}')
        if op == 'send' and step.get('channel') not in CHANNELS:
            errors.append(f'{p}: channel must be one of {CHANNELS}')
        if op == 'compute' and step.get('fn') not in COMPUTE:
            errors.append(f'{p}: compute fn must be one of {sorted(COMPUTE)}')
        for k in ('key', 'prefix', 'url', 'to', 'payload', 'value', 'resource', 'principal', 'role', 'component', 'on'):
            if k in step and not _ref_ok(step[k]):
                errors.append(f'{p}: bad reference in {k}')
        if op == 'when':
            errors += program_errors(step['then'], p + '.then') + program_errors(step.get('else', []), p + '.else')
        elif op == 'foreach':
            errors += program_errors(step['do'], p + '.do')
        elif op == 'switch':
            for val, sub in sorted(step['cases'].items()):
                errors += program_errors(sub, f'{p}.cases[{val}]')
    return errors


# ---- audited world -------------------------------------------------------------------------------------------
class World:
    """In-memory world reachable only through the interpreter. In seed mode, absent preconditions are
    recorded (and treated as present) so that the minimal initial world can be derived from the program."""

    def __init__(self, spec, seed_mode=False):
        spec = copy.deepcopy(spec)
        self._stores = {k: dict(v) for k, v in spec.get('stores', {}).items()}
        self._acl = {k: dict(v) for k, v in spec.get('acl', {}).items()}
        self._remote = dict(spec.get('remote', {}))
        self._outbox = []
        self.seed_mode = seed_mode
        self.seed = {'stores': {}, 'acl': {}, 'remote': {}}
        self.access_log = []
        self.current_seq = None

    def _log(self, kind, table, key):
        self.access_log.append({'seq': self.current_seq, 'kind': kind, 'table': table, 'key': key})

    def _store(self, table):
        return self._stores.setdefault(table, {})

    def _require(self, table, key):
        store = self._store(table)
        if key not in store:
            if not self.seed_mode:
                raise SemanticsError(f'precondition violated: {table}/{key} must exist')
            store[key] = f'synthetic content of {table}/{key}'
            self.seed['stores'].setdefault(table, {})[key] = store[key]

    def exists(self, table, key):
        self._log('exists', table, key)
        return key in self._store(table)

    def read(self, table, key):
        self._log('exists', table, key)
        self._require(table, key)
        self._log('value_read', table, key)
        return self._store(table)[key]

    def keys(self, table, prefix):
        self._log('keys', table, prefix)
        store = self._store(table)
        found = sorted(k for k in store if k == prefix or k.startswith(prefix))
        if not found:
            if not self.seed_mode:
                raise SemanticsError(f'precondition violated: no entry under {table}/{prefix}')
            for i in (1, 2):
                k = f'{prefix}item-{i}'
                store[k] = f'synthetic content of {table}/{k}'
                self.seed['stores'].setdefault(table, {})[k] = store[k]
            found = sorted(k for k in store if k.startswith(prefix))
        return found

    def inspect(self, table, key):
        """Metadata of an entry, or listing of a directory-like prefix `key/` (no value is read)."""
        if self.exists(table, key):
            return [key]
        if self.seed_mode:
            self._require(table, key)
            return [key]
        return self.keys(table, key.rstrip('/') + '/')

    def value_at(self, table, key):
        self._log('value_read', table, key)
        return self._store(table)[key]

    def write(self, table, key, value, must_exist):
        self._log('exists', table, key)
        if must_exist:
            self._require(table, key)
        elif key in self._store(table):
            raise SemanticsError(f'create target already exists: {table}/{key}')
        self._log('write', table, key)
        self._store(table)[key] = value

    def append(self, table, key, value):
        self._log('exists', table, key)
        self._require(table, key)
        self._log('append', table, key)
        self._store(table)[key] = self._store(table)[key] + value  # O_APPEND: not a tool-level read

    def delete(self, table, key, checked=False):
        if not checked:
            self._log('exists', table, key)
            self._require(table, key)
        self._log('delete', table, key)
        del self._store(table)[key]

    def remote_get(self, url):
        self._log('remote_read', 'remote', url)
        if url not in self._remote:
            if not self.seed_mode:
                raise SemanticsError(f'precondition violated: remote {url} must exist')
            self._remote[url] = self.seed['remote'][url] = 'synthetic remote body'
        return self._remote[url]

    def outbox_add(self, msg):
        self._log('outbox_write', 'outbox', msg['recipient'])
        self._outbox.append(msg)

    def acl_update(self, resource, principal, role):
        self._log('acl_read', 'acl', resource)
        if resource not in self._acl:
            if not self.seed_mode:
                raise SemanticsError(f'precondition violated: acl resource {resource} must exist')
            self._acl[resource] = {'owner@example.test': 'owner'}
            if role is None:
                self._acl[resource][principal] = 'member'
            self.seed['acl'][resource] = dict(self._acl[resource])
        entry = dict(self._acl[resource])
        if role is None:
            if principal not in entry:
                if not self.seed_mode:
                    raise SemanticsError(f'precondition violated: {principal} has no role on {resource}')
                entry[principal] = 'member'
                self.seed['acl'].setdefault(resource, dict(self._acl[resource]))[principal] = 'member'
            entry.pop(principal)
        else:
            entry[principal] = role
        self._log('acl_write', 'acl', resource)
        self._acl[resource] = entry

    def snapshot(self):
        return copy.deepcopy({'stores': self._stores, 'acl': self._acl, 'remote': self._remote,
                              'outbox': self._outbox})


# ---- interpreter ----------------------------------------------------------------------------------------------
class _Run:
    def __init__(self, world, args):
        self.world, self.args, self.vars, self.trace = world, args, {}, []

    def ref(self, r):
        if isinstance(r, list):
            return ''.join(str(self.ref(x)) for x in r)
        if isinstance(r, str) and r.startswith('$'):
            if r[1:] not in self.args:
                raise SemanticsError(f'argument {r[1:]} missing')
            return self.args[r[1:]]
        if isinstance(r, str) and r.startswith('@'):
            name, _, field = r[1:].partition('.')
            value = self.vars[name]
            return value[field] if field else value
        return r

    def event(self, access_class, event, **detail):
        ev = {'seq': len(self.trace) + 1, 'event': event, **detail}
        self.trace.append(ev)
        self.world.current_seq = ev['seq']
        ev['_access_class'] = access_class
        return ev

    def run(self, program):
        for step in program:
            getattr(self, 'op_' + step['op'])(step)
            self.world.current_seq = None

    def op_read(self, s):
        key = str(self.ref(s['key']))
        self.event('read', 'store_read', table=s['store'], key=key)
        value = self.world.read(s['store'], key)
        if 'into' in s:
            self.vars[s['into']] = value

    def op_inspect(self, s):
        key = str(self.ref(s['key']))
        self.event('inspect', 'store_read', table=s['store'], key=key, view='metadata')
        self.world.inspect(s['store'], key)

    def op_scan(self, s):
        prefix = str(self.ref(s['prefix']))
        self.event('scan', 'store_read', table=s['store'], key=prefix, view='scan')
        rows = {k: self.world.value_at(s['store'], k) for k in self.world.keys(s['store'], prefix)}
        if 'into' in s:
            self.vars[s['into']] = rows

    def op_http_get(self, s):
        url = str(self.ref(s['url']))
        self.event('http_get', 'http_get', table='remote', key=url, method='GET', body=None)
        value = self.world.remote_get(url)
        if 'into' in s:
            self.vars[s['into']] = value

    def _write(self, s, mode):
        key, value = str(self.ref(s['key'])), self.ref(s['value'])
        value = value if isinstance(value, str) else _json_dump(value)
        self.event(mode, 'store_write', table=s['store'], key=key, mode=mode)
        if mode == 'append':
            self.world.append(s['store'], key, value)
        else:
            self.world.write(s['store'], key, value, must_exist=(mode == 'set'))

    def op_create(self, s):
        self._write(s, 'create')

    def op_set(self, s):
        self._write(s, 'set')

    def op_append(self, s):
        self._write(s, 'append')

    def op_delete(self, s):
        key = str(self.ref(s['key']))
        self.event('delete', 'store_delete', table=s['store'], key=key)
        self.world.delete(s['store'], key)

    def op_delete_prefix(self, s):
        prefix = str(self.ref(s['prefix']))
        self.event('delete_prefix', 'store_delete', table=s['store'], key=prefix, scope='prefix')
        for k in self.world.keys(s['store'], prefix):
            self.world.delete(s['store'], k, checked=True)

    def op_send(self, s):
        to, payload = str(self.ref(s['to'])), self.ref(s['payload'])
        text = payload if isinstance(payload, str) else _json_dump(payload)
        self.event('send', 'send', channel=s['channel'], recipient=to, payload_sha256=sha(text),
                   payload_len=len(text))
        self.world.outbox_add({'channel': s['channel'], 'recipient': to, 'payload': text})

    def op_acl_set(self, s):
        res, pr, role = str(self.ref(s['resource'])), str(self.ref(s['principal'])), str(self.ref(s['role']))
        self.event('acl_set', 'acl_change', table='acl', key=res, principal=pr, role=role)
        self.world.acl_update(res, pr, role)

    def op_acl_revoke(self, s):
        res, pr = str(self.ref(s['resource'])), str(self.ref(s['principal']))
        self.event('acl_revoke', 'acl_change', table='acl', key=res, principal=pr, role=None)
        self.world.acl_update(res, pr, None)

    def op_compute(self, s):
        out = COMPUTE[s['fn']](*[copy.deepcopy(self.ref(x)) for x in s['inputs']])
        if 'into' in s:
            self.vars[s['into']] = out

    def op_opaque(self, s):
        comp = str(self.ref(s['component']))
        self.event(None, 'opaque_invoked', component=comp)
        raise _Opaque(comp)

    def op_when(self, s):
        self.run(s['then'] if self.args.get(s['arg']) == s['equals'] else s.get('else', []))

    def op_foreach(self, s):
        for item in self.ref('$' + s['arg']):
            self.vars[s['as']] = item
            self.run(s['do'])

    def op_switch(self, s):
        val = str(self.ref(s['on']))
        if val not in s['cases']:
            self.op_opaque({'component': 'unmodelled_case:' + val})
        self.run(s['cases'][val])


def _execute(program, args, world_spec, seed_mode):
    world = World(world_spec, seed_mode)
    run = _Run(world, copy.deepcopy(args))
    before = world.snapshot()
    outcome, opaque = 'completed', None
    try:
        run.run(program)
    except _Opaque as exc:
        outcome, opaque = 'stopped_at_opaque_component', str(exc)
    return world, run, before, outcome, opaque


def seed_world(program, args):
    """Minimal initial world satisfying the program's preconditions for these arguments."""
    world, *_ = _execute(program, args, {}, seed_mode=True)
    return {k: v for k, v in world.seed.items() if v}


def audit(trace, access_log, before, after):
    """Typed access audit + state-diff explanation. Returns a list of problems (empty = clean)."""
    problems = []
    events = {e['seq']: e for e in trace}
    for a in access_log:
        ev = events.get(a['seq'])
        if ev is None:
            problems.append(f"access outside any operation: {a['kind']} {a['table']}/{a['key']}")
            continue
        cls = ev.get('_access_class')
        if a['kind'] not in PERMITTED_ACCESS.get(cls, set()):
            problems.append(f"{a['kind']} on {a['table']}/{a['key']} not permitted for event #{ev['seq']} ({cls})")
            continue
        if a['table'] not in ('outbox', ev.get('table')):
            problems.append(f"access to {a['table']} not explained by event #{ev['seq']} on {ev.get('table')}")
        elif a['table'] != 'outbox' and not (a['key'] == ev.get('key') or
                                             (ev.get('view') == 'metadata' and str(a['key']).startswith(str(ev['key']))) or
                                             (cls in ('scan', 'delete_prefix') and str(a['key']).startswith(str(ev['key'])))):
            problems.append(f"access to key {a['key']} not explained by event #{ev['seq']} ({ev.get('key')})")
    mutated = {(a['table'], a['key']) for a in access_log if a['kind'] in MUTATING_ACCESS}
    for table in sorted(set(before['stores']) | set(after['stores'])):
        b, c = before['stores'].get(table, {}), after['stores'].get(table, {})
        for key in sorted(set(b) | set(c)):
            if (key in b) != (key in c) or b.get(key) != c.get(key):
                if (table, key) not in mutated:
                    problems.append(f'unexplained state change: {table}/{key}')
    for res in sorted(set(before['acl']) | set(after['acl'])):
        if before['acl'].get(res) != after['acl'].get(res) and ('acl', res) not in mutated:
            problems.append(f'unexplained acl change: {res}')
    if before['remote'] != after['remote']:
        problems.append('remote state changed')
    sends = [e for e in trace if e['event'] == 'send']
    if len(after['outbox']) != len(sends) or any(m['recipient'] != e['recipient'] or sha(m['payload']) != e['payload_sha256']
                                                 for m, e in zip(after['outbox'], sends)):
        problems.append('outbox not explained by send events')
    return problems


def execute(program, args, world_spec=None):
    """Run a validated program. Returns a JSON-serialisable execution record; raises SemanticsError on
    invalid programs, violated preconditions or an unclean audit (evidence would be unreliable)."""
    errors = program_errors(program)
    if errors:
        raise SemanticsError(f'invalid program: {errors}')
    world_spec = seed_world(program, args) if world_spec is None else world_spec
    world, run, before, outcome, opaque = _execute(program, args, world_spec, seed_mode=False)
    after = world.snapshot()
    problems = audit(run.trace, world.access_log, before, after)
    if problems:
        raise SemanticsError(f'unreliable execution: {problems}')
    trace = [{k: v for k, v in e.items() if k != '_access_class'} for e in run.trace]
    return {'outcome': outcome, 'opaque_component': opaque, 'trace': trace, 'trace_sha256': sha(trace),
            'access_log': world.access_log, 'access_log_sha256': sha(world.access_log),
            'world_initial': world_spec, 'world_initial_sha256': sha(world_spec),
            'audit': {'typed_access_unexplained': [], 'state_changes_unexplained': [], 'clean': True}}
