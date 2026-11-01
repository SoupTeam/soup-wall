# SPDX-License-Identifier: Apache-2.0
"""Local installed-pilot launch exclusion. Never grants authority or stops work.

The stable gate serializes only admission and state transitions, not host lifetime.
The marker inode is permanent: a missing/replaced marker is never recreated by a
reader. A synced intent precedes every in-place state change; uncertainty closes
admission. Only explicit, newly confirmed enter can conservatively recover it.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import uuid

_spec = importlib.util.spec_from_file_location('maintenance_owned_io', Path(__file__).with_name('pilot_update.py'))
IO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(IO)

FORMAT = 'sw-pilot-maintenance/1'
ANCHOR = 'pilot-maintenance.anchor.json'
DIRECTORY = 'pilot-maintenance'
CAP = 32768
EVENTS = 128
RUNS = 64
SHA = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[0-9a-f]{32}\Z')


class Refusal(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(encoded(value))


def strict(raw):
    require(len(raw) <= CAP, 'maintenance_record_cap')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'maintenance_duplicate_field')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False, 'maintenance_invalid_number'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('maintenance_invalid_record') from None
    require(type(value) is dict, 'maintenance_invalid_record')
    return value


def object_id(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def stable(info):
    return [*object_id(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read_at(directory, name, *, optional=False, expected=None):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        if optional:
            return None
        raise Refusal('maintenance_record_missing') from None
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= CAP, 'maintenance_owned_private_record_required')
        require(expected is None or object_id(before) == expected, 'maintenance_record_replaced')
        raw = bytearray()
        while len(raw) <= CAP:
            block = os.read(fd, min(8192, CAP + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(len(raw) <= CAP and stable(before) == stable(os.fstat(fd)) == stable(after),
                'maintenance_record_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def create_at(directory, name, value):
    raw = encoded(value)
    require(len(raw) <= CAP and '/' not in name, 'maintenance_record_cap')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            require(count > 0, 'maintenance_partial_write')
            at += count
        os.fsync(fd)
        result = object_id(os.fstat(fd))
    finally:
        os.close(fd)
    os.fsync(directory)
    return result


class Store:
    def __init__(self, home):
        self.home = Path(home)
        self.parent = IO.Directory(self.home)
        self.root = None
        self.gate = None
        self.key = None
        self._lock_mode = None
        try:
            self.anchor_raw = read_at(self.parent.fd, ANCHOR)
            self.anchor = strict(self.anchor_raw)
            require(set(self.anchor) == {'format', 'home', 'root', 'gate', 'marker', 'pin', 'owner', 'initial_marker_sha256', 'key', 'key_sha256', 'events', 'runs', 'admissions'}
                    and self.anchor['format'] == FORMAT and ID.fullmatch(self.anchor['owner'])
                    and self.anchor['home'] == object_id(os.fstat(self.parent.fd)), 'maintenance_foreign_anchor')
            self.root = IO.Directory(self.home / DIRECTORY)
            require(object_id(os.fstat(self.root.fd)) == self.anchor['root'], 'maintenance_store_replaced')
            pin = strict(read_at(self.root.fd, 'anchor-pin.json', expected=self.anchor['pin']))
            require(pin == {'format': FORMAT, 'anchor_sha256': sha(self.anchor_raw)}, 'maintenance_anchor_changed')
            key_raw = read_at(self.root.fd, 'key.json', expected=self.anchor['key'])
            key = strict(key_raw)
            require(set(key) == {'format', 'key'} and key['format'] == FORMAT
                    and type(key['key']) is str and SHA.fullmatch(key['key'])
                    and hmac.compare_digest(sha(key_raw), self.anchor['key_sha256']), 'maintenance_key_changed')
            self.key = bytes.fromhex(key['key'])
            self.gate = os.open('gate', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.root.fd)
            meta = os.fstat(self.gate)
            require(object_id(meta) == self.anchor['gate'] and meta.st_nlink == 1
                    and stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o600,
                    'maintenance_gate_replaced')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.gate is not None:
            os.close(self.gate); self.gate = None
        if self.root is not None:
            self.root.__exit__(); self.root = None
        if self.parent is not None:
            self.parent.__exit__(); self.parent = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @classmethod
    def absent(cls, home):
        # Both names are checked, including dangling symlinks. Missing just one
        # side is damage, never implicit opt-out or permission to reinitialize.
        with IO.Directory(home) as parent:
            found = []
            for name in [ANCHOR, DIRECTORY]:
                try:
                    os.stat(name, dir_fd=parent.fd, follow_symlinks=False); found.append(True)
                except FileNotFoundError:
                    found.append(False)
            require(found[0] == found[1], 'maintenance_enrollment_incomplete')
            return not found[0]

    @classmethod
    def create(cls, home, binding, *, maintenance):
        require(cls.absent(home), 'maintenance_already_enrolled')
        with IO.Directory(home) as parent:
            os.mkdir(DIRECTORY, mode=0o700, dir_fd=parent.fd)
            with IO.Directory(Path(home) / DIRECTORY) as root:
                os.mkdir('events', mode=0o700, dir_fd=root.fd)
                os.mkdir('runs', mode=0o700, dir_fd=root.fd)
                os.mkdir('admissions', mode=0o700, dir_fd=root.fd)
                owner = uuid.uuid4().hex
                key = os.urandom(32)
                key_record = {'format': FORMAT, 'key': key.hex()}
                key_id = create_at(root.fd, 'key.json', key_record)
                marker = {'format': FORMAT, 'owner': owner, 'revision': 0, 'maintenance': maintenance,
                          'binding': binding, 'binding_sha256': digest(binding), 'last_event': None}
                marker = cls.signed(key, 'state', marker)
                marker_id = create_at(root.fd, 'marker.json', marker)
                gate_id = create_at(root.fd, 'gate', {})
                pin_id = create_at(root.fd, 'anchor-pin.json', {})
                anchor = {'format': FORMAT, 'home': object_id(os.fstat(parent.fd)),
                          'root': object_id(os.fstat(root.fd)), 'marker': marker_id,
                          'gate': gate_id, 'pin': pin_id, 'owner': owner,
                          'key': key_id, 'key_sha256': digest(key_record),
                          'initial_marker_sha256': digest(marker),
                          **{name: object_id(os.stat(name, dir_fd=root.fd, follow_symlinks=False))
                             for name in ('events', 'runs', 'admissions')}}
                raw = encoded({'format': FORMAT, 'anchor_sha256': digest(anchor)})
                fd = os.open('anchor-pin.json', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root.fd)
                try:
                    require(os.write(fd, raw) == len(raw), 'maintenance_partial_write')
                    os.ftruncate(fd, len(raw)); os.fsync(fd)
                finally:
                    os.close(fd)
                create_at(parent.fd, ANCHOR, anchor)
                os.fsync(root.fd); os.fsync(parent.fd)
        return cls(home)

    def check(self):
        self.parent.check(); self.root.check()
        require(object_id(os.fstat(self.parent.fd)) == self.anchor['home']
                and object_id(os.fstat(self.root.fd)) == self.anchor['root'], 'maintenance_directory_changed')
        require(read_at(self.parent.fd, ANCHOR) == self.anchor_raw, 'maintenance_anchor_changed')
        for name in ('events', 'runs', 'admissions'):
            with IO.Directory(self.home / DIRECTORY / name) as child:
                require(object_id(os.fstat(child.fd)) == self.anchor[name], 'maintenance_inventory_replaced')
        require(object_id(os.stat('gate', dir_fd=self.root.fd, follow_symlinks=False)) == self.anchor['gate']
                and object_id(os.fstat(self.gate)) == self.anchor['gate']
                and os.fstat(self.gate).st_nlink == 1, 'maintenance_gate_replaced')
        require(hmac.compare_digest(sha(read_at(self.root.fd, 'key.json', expected=self.anchor['key'])),
                                    self.anchor['key_sha256']), 'maintenance_key_changed')

    @staticmethod
    def signed(key, purpose, value):
        body = {k: v for k, v in value.items() if k != 'mac'}
        return {**body, 'mac': hmac.new(key, b'agentfw/pilot-maintenance/' + purpose.encode() + b'/v1\0'
                                      + encoded(body), hashlib.sha256).hexdigest()}

    def authenticated(self, purpose, value):
        require(type(value) is dict and type(value.get('mac')) is str and SHA.fullmatch(value['mac'])
                and hmac.compare_digest(value['mac'], self.signed(self.key, purpose, value)['mac']),
                'maintenance_record_unauthenticated')

    @contextmanager
    def locked(self, *, exclusive):
        self.check()
        require(self._lock_mode is None, 'maintenance_nested_gate_refused')
        try:
            fcntl.flock(self.gate, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('maintenance_transition_busy') from None
        try:
            self.check()
            self._lock_mode = 'exclusive' if exclusive else 'shared'
            yield
            self.check()
        finally:
            # Explicitly end ownership even if another fork briefly inherited
            # the open-file description; exec also closes it through CLOEXEC.
            fcntl.flock(self.gate, fcntl.LOCK_UN)
            self._lock_mode = None

    def valid_state(self, value):
        require(type(value) is dict and set(value) == {'format', 'owner', 'revision', 'maintenance', 'binding', 'binding_sha256', 'last_event', 'mac'}
                and value['format'] == FORMAT and value['owner'] == self.anchor['owner']
                and type(value['revision']) is int and 0 <= value['revision'] <= EVENTS
                and type(value['maintenance']) is bool and type(value['binding']) is dict
                and type(value['binding_sha256']) is str
                and hmac.compare_digest(value['binding_sha256'], digest(value['binding'])), 'maintenance_marker_invalid')
        self.authenticated('state', value)

    def history(self):
        maximum = 0
        with IO.Directory(self.home / DIRECTORY / 'events') as events:
            names = os.listdir(events.fd)
            require(len(names) <= EVENTS, 'maintenance_history_capacity')
            for name in names:
                require(re.fullmatch(r'(?:unresolved-)?[0-9a-f]{32}\.json', name), 'maintenance_history_unknown')
                value = strict(read_at(events.fd, name))
                if name.startswith('unresolved-'):
                    self.authenticated('evidence', value)
                else:
                    self.authenticated('transition', value)
                    self.valid_state(value['before'])
                    require(value.get('format') == FORMAT and value.get('owner') == self.anchor['owner']
                            and value.get('before_sha256') == digest(value['before']), 'maintenance_history_invalid')
                    after_revision = value.get('after_revision')
                    require(type(after_revision) is int and value['before']['revision'] < after_revision <= EVENTS
                            and (after_revision == value['before']['revision'] + 1
                                 or value.get('recovery_enter') is True and value.get('operation') == 'enter'),
                            'maintenance_history_invalid')
                    maximum = max(maximum, after_revision)
        return maximum

    def marker(self, *, allow_uncertain=False):
        raw = read_at(self.root.fd, 'marker.json', expected=self.anchor['marker'])
        pending = read_at(self.root.fd, 'pending.json', optional=True)
        try:
            value = strict(raw)
            self.valid_state(value)
            require(value['revision'] == self.history(), 'maintenance_state_replayed')
            if value['revision'] == 0:
                require(value['last_event'] is None and hmac.compare_digest(sha(raw), self.anchor['initial_marker_sha256']),
                        'maintenance_initial_marker_changed')
            else:
                require(value['last_event'] is not None, 'maintenance_event_missing')
            if value['last_event'] is not None:
                require(type(value['last_event']) is str and ID.fullmatch(value['last_event']), 'maintenance_event_invalid')
                with IO.Directory(self.home / DIRECTORY / 'events') as events:
                    event = strict(read_at(events.fd, value['last_event'] + '.json'))
                    self.authenticated('transition', event)
                    require(event.get('format') == FORMAT and event.get('owner') == value['owner']
                            and event.get('after_sha256') == sha(raw), 'maintenance_event_invalid')
        except (ValueError, TypeError, KeyError):
            if not allow_uncertain:
                raise Refusal('maintenance_state_uncertain') from None
            value = None
        require(allow_uncertain or pending is None, 'maintenance_transition_incomplete')
        return raw, value, pending

    def snapshot(self):
        require(self._lock_mode is not None, 'maintenance_gate_required')
        raw, value, pending = self.marker(allow_uncertain=True)
        return {'anchor_sha256': sha(self.anchor_raw), 'marker_sha256': sha(raw),
                'pending_sha256': sha(pending) if pending is not None else None,
                'mode': 'uncertain' if value is None or pending is not None else
                        'entered' if value['maintenance'] else 'open',
                'revision': value['revision'] if value else None}

    def plan(self, binding, operation, inventory):
        require(operation in ('enter', 'leave'), 'maintenance_operation_invalid')
        result = {'format': FORMAT, 'operation': operation, 'snapshot': self.snapshot(),
                  'binding_sha256': digest(binding), 'inventory_sha256': digest(inventory)}
        return {**result, 'confirmation_sha256': digest(result)}

    def transition(self, binding, operation, inventory, confirmation):
        # Caller holds exclusive gate throughout source/inventory revalidation,
        # confirmation and publication. No process or authority state changes.
        require(self._lock_mode == 'exclusive', 'maintenance_exclusive_gate_required')
        plan = self.plan(binding, operation, inventory)
        require(type(confirmation) is str and SHA.fullmatch(confirmation)
                and hmac.compare_digest(confirmation, plan['confirmation_sha256']), 'maintenance_confirmation_stale')
        raw, current, pending = self.marker(allow_uncertain=True)
        if operation == 'leave':
            require(current is not None and pending is None, 'maintenance_state_uncertain')
            require(not inventory.get('uncertain', True), 'maintenance_runs_uncertain')
        recovery_revision = None
        if current is None or pending is not None:
            require(operation == 'enter' and pending is not None, 'maintenance_explicit_recovery_enter_required')
            evidence = strict(pending)
            self.authenticated('transition', evidence)
            require(evidence.get('format') == FORMAT and evidence.get('owner') == self.anchor['owner']
                    and type(evidence.get('before')) is dict
                    and evidence['before'].get('binding_sha256') == digest(binding), 'maintenance_recovery_identity_unproven')
            current = evidence['before']
            self.valid_state(current)
            require(evidence.get('before_sha256') == digest(current), 'maintenance_recovery_identity_unproven')
            high = self.history()
            proposed = evidence.get('after_revision')
            require(type(proposed) is int and current['revision'] < proposed <= EVENTS,
                    'maintenance_recovery_identity_unproven')
            with IO.Directory(self.home / DIRECTORY / 'events') as events:
                archived = any(not n.startswith('unresolved-') and
                               digest(strict(read_at(events.fd, n))) == digest(evidence)
                               for n in os.listdir(events.fd))
            require((archived and high == proposed)
                    or (not archived and high == current['revision']
                        and hmac.compare_digest(sha(raw), evidence['before_sha256'])),
                    'maintenance_recovery_replayed')
            recovery_revision = max(high, proposed) + 1
            with IO.Directory(self.home / DIRECTORY / 'events') as events:
                create_at(events.fd, 'unresolved-' + uuid.uuid4().hex + '.json',
                          self.signed(self.key, 'evidence', {'format': FORMAT,
                              'original_pending': evidence, 'observed_marker_sha256': sha(raw)}))
            # Keep the authenticated old intent until the complete newly signed
            # conservative-enter plan is ready. Leave never takes this path.
        require(current['binding_sha256'] == digest(binding), 'maintenance_selection_stale')
        require(current['revision'] < EVENTS, 'maintenance_history_capacity')
        event_id = uuid.uuid4().hex
        after_revision = recovery_revision or current['revision'] + 1
        require(after_revision <= EVENTS, 'maintenance_history_capacity')
        after = {**current, 'maintenance': operation == 'enter', 'revision': after_revision,
                 'last_event': event_id}
        after = self.signed(self.key, 'state', after)
        event = {'format': FORMAT, 'owner': self.anchor['owner'], 'operation': operation,
                 'before': current, 'before_sha256': digest(current), 'observed_marker_sha256': sha(raw),
                 'after_sha256': digest(after),
                 'after_revision': after_revision, 'recovery_enter': recovery_revision is not None,
                 'confirmation_sha256': confirmation}
        event = self.signed(self.key, 'transition', event)
        with IO.Directory(self.home / DIRECTORY / 'events') as events:
            require(len(os.listdir(events.fd)) < EVENTS, 'maintenance_history_capacity')
        if pending is None:
            pending_id = create_at(self.root.fd, 'pending.json', event)
        else:
            self.root.write('pending.json', event)
            pending_id = object_id(os.stat('pending.json', dir_fd=self.root.fd, follow_symlinks=False))
        with IO.Directory(self.home / DIRECTORY / 'events') as events:
            create_at(events.fd, event_id + '.json', event)
        fd = os.open('marker.json', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root.fd)
        try:
            require(object_id(os.fstat(fd)) == self.anchor['marker'], 'maintenance_record_replaced')
            value = encoded(after)
            at = 0
            while at < len(value):
                count = os.write(fd, value[at:]); require(count > 0, 'maintenance_partial_write'); at += count
            os.ftruncate(fd, len(value)); os.fsync(fd)
        finally:
            os.close(fd)
        self.check()
        require(read_at(self.root.fd, 'marker.json', expected=self.anchor['marker']) == encoded(after), 'maintenance_publish_unverified')
        require(strict(read_at(self.root.fd, 'pending.json', expected=pending_id)) == event, 'maintenance_pending_replaced')
        os.unlink('pending.json', dir_fd=self.root.fd)
        os.fsync(self.root.fd)
        return {'format': FORMAT, 'status': 'entered' if after['maintenance'] else 'left',
                'revision': after['revision'], 'binding_sha256': after['binding_sha256'],
                'existing_runs_unchanged': True, 'authority_changed': False}

    def admit(self, binding):
        require(self._lock_mode is not None, 'maintenance_gate_required')
        _, value, _ = self.marker()
        require(value['binding_sha256'] == digest(binding), 'maintenance_selection_stale')
        require(not value['maintenance'], 'maintenance_entered')
        return value
