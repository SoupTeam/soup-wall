#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Observe actual Linux owner SIGKILL before descriptor handback (diagnostic).

An independently stopped sendmsg ENTRY establishes that no descriptor packet
reached the collector. This does not change the production owner or its limits.
An orphan is reported as BLOCKED, never as verified production cleanup. Only
the independently pinned, empty inode may receive explicitly labelled observer
cleanup. Raw process identities and IPC packets remain private.
"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import subprocess
import sys
import time

FORMAT = 'sou142-owner-self-loss/1'
TEST = 'pilot_budget::tests::native_owner_first_collector_child'
MAX_PACKET = 65536
MAX_TRACEES = 64
PTRACE_TRACEME, PTRACE_PEEKDATA, PTRACE_CONT = 0, 2, 7
PTRACE_DETACH, PTRACE_SYSCALL, PTRACE_SETOPTIONS = 17, 24, 0x4200
PTRACE_GETEVENTMSG, PTRACE_GET_SYSCALL_INFO = 0x4201, 0x420E
TRACE_OPTIONS = 1 | 2 | 4 | 8 | 16  # TRACESYSGOOD, FORK, VFORK, CLONE, EXEC
WALL = 0x40000000
PACKET_FIELDS = {'format', 'instance', 'budget'}
BUDGET_FIELDS = {'budget_sha256', 'leaf', 'device', 'inode', 'started_monotonic_nanos'}


class Incomplete(Exception):
    pass


def need(value, reason):
    if not value:
        raise Incomplete(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_packet_key')
        result[key] = value
    return result


def descriptor_packet(read, address, budget_sha):
    """Read one Linux x86-64 msghdr through the stopped owner's memory reader."""
    need(type(address) is int and address > 0, 'message_address_invalid')
    def exact(address, size):
        need(type(address) is int and address > 0 and 0 < size <= MAX_PACKET,
             'bounded_packet_read_required')
        value = read(address, size)
        need(type(value) is bytes and len(value) == size, 'message_memory_incomplete')
        return value
    header = exact(address, 56)
    name, name_len, iov, iov_count, control, control_bytes, flags = struct.unpack('<QI4xQQQQI4x', header)
    need(name == name_len == flags == 0 and iov_count == 1 and iov > 0
         and control > 0 and control_bytes == 48, 'descriptor_message_shape_invalid')
    data, length = struct.unpack('<QQ', exact(iov, 16))
    need(data > 0 and 0 < length <= MAX_PACKET, 'descriptor_payload_size_invalid')
    ancillary = exact(control, control_bytes)
    size, level, kind = struct.unpack_from('<Qii', ancillary)
    need(size == 48 and level == 1 and kind == 1, 'one_rights_message_required')
    fds = struct.unpack_from('<8i', ancillary, 16)
    need(len(set(fds)) == 8 and min(fds) >= 3, 'eight_distinct_descriptors_required')
    try:
        packet = json.loads(exact(data, length), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        raise Incomplete('descriptor_payload_invalid') from error
    need(type(packet) is dict and set(packet) == PACKET_FIELDS
         and packet['format'] == 'sw-mcp/linux-crash-owner/1'
         and type(packet['instance']) is str
         and re.fullmatch('[0-9a-f]{32}', packet['instance']), 'owner_packet_identity_invalid')
    budget = packet['budget']
    need(type(budget) is dict and set(budget) == BUDGET_FIELDS
         and budget['budget_sha256'] == budget_sha
         and type(budget['leaf']) is str
         and re.fullmatch('agentfw-mcp-[0-9a-f]{32}', budget['leaf'])
         and all(type(budget[k]) is int and budget[k] > 0 for k in
                 ('device', 'inode', 'started_monotonic_nanos')), 'prepared_budget_identity_invalid')
    return budget


class Trace:
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]

    def call(self, request, pid, address=0, data=0):
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, pid, address, data)
        code = ctypes.get_errno()
        if result == -1 and code:
            raise OSError(code, 'ptrace')
        return result

    def memory(self, pid, address, length):
        need(address > 0 and 0 < length <= MAX_PACKET, 'bounded_memory_read_required')
        aligned = address & ~7
        offset = address - aligned
        result = bytearray()
        for step in range(0, offset + length, 8):
            word = self.call(PTRACE_PEEKDATA, pid, aligned + step)
            result.extend((word & ((1 << 64) - 1)).to_bytes(8, 'little'))
        return bytes(result[offset:offset + length])

    def entry(self, pid):
        data = ctypes.create_string_buffer(128)
        count = self.call(PTRACE_GET_SYSCALL_INFO, pid, len(data), ctypes.addressof(data))
        need(count >= 24, 'syscall_info_unavailable')
        if data.raw[0] != 1:  # entry, never a post-transfer exit observation
            return None
        need(count >= 80 and struct.unpack_from('<I', data.raw, 4)[0] == 0xC000003E,
             'native_x86_64_syscall_info_required')
        return struct.unpack_from('<7Q', data.raw, 24)


def identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    need(len(fields) >= 20, 'process_generation_unavailable')
    return int(fields[19])


def leaf_empty(leaf):
    def read(name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=leaf)
        try:
            raw = os.read(fd, MAX_PACKET + 1)
            need(len(raw) <= MAX_PACKET, 'leaf_control_overflow')
            return raw
        finally:
            os.close(fd)
    need(not read('cgroup.procs').strip() and b'populated 0' in read('cgroup.events').splitlines(),
         'owned_leaf_not_empty')
    need(not any(e.is_dir(follow_symlinks=False) for e in os.scandir(f'/proc/self/fd/{leaf}')),
         'owned_leaf_has_children')


def same_leaf(root, prepared, pinned):
    current = os.stat(prepared['leaf'], dir_fd=root, follow_symlinks=False)
    original = os.fstat(pinned)
    need(stat.S_ISDIR(current.st_mode)
         and (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
         == (prepared['device'], prepared['inode']), 'owned_leaf_replaced')


def observe(args):
    need(sys.platform == 'linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
         'ordinary_user_native_linux_x86_64_required')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_api_required')
    source = args.source.resolve(strict=True)
    need(os.statvfs(source).f_flag & os.ST_RDONLY, 'read_only_source_required')
    need(re.fullmatch('[0-9a-f]{40}', args.expected_commit)
         and all(re.fullmatch('[0-9a-f]{64}', digest) for digest in
                 (args.agentfw_sha256, args.test_sha256)), 'exact_source_and_binary_digests_required')
    git_env = {'PATH': '/usr/bin:/bin', 'HOME': str(args.output.parent),
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_OPTIONAL_LOCKS': '0'}
    def clean_source():
        need(subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=source,
             env=git_env, timeout=10).decode().strip() == args.expected_commit
             and not subprocess.check_output(['/usr/bin/git', 'status', '--porcelain',
                 '--untracked-files=all'], cwd=source, env=git_env, timeout=10),
             'clean_exact_source_required')
    clean_source()
    need(sha(args.agentfw) == args.agentfw_sha256 and sha(args.test_binary) == args.test_sha256,
         'exact_candidate_binary_required')
    need(all(os.statvfs(path).f_flag & os.ST_RDONLY for path in (args.agentfw, args.test_binary)),
         'read_only_candidate_binaries_required')
    with args.budget.open('rb') as stream:
        raw = stream.read(MAX_PACKET + 1)
    need(len(raw) <= MAX_PACKET, 'bounded_budget_config_required')
    config = json.loads(raw, object_pairs_hook=unique_object)
    budget_sha = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    root = os.open(config['delegationRoot'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(root)
    need(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
         'private_owned_budget_root_required')
    fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
    need(not any(e.is_dir() for e in os.scandir(f'/proc/self/fd/{root}')), 'empty_owned_budget_root_required')
    trace = Trace()
    report = {'format': FORMAT, 'status': 'incomplete', 'acceptance_pass': False,
              'source_commit': args.expected_commit, 'agentfw_sha256': args.agentfw_sha256,
              'test_binary_sha256': args.test_sha256, 'profile_sha256': sha(args.profile),
              'budget_sha256': budget_sha, 'production_cleanup_verified': False,
              'observer_cleanup_attempted': False, 'observer_cleanup_verified': False,
              'original_started': None, 'runtime_or_policy_modified': False}
    live, stopped, pidfds = set(), set(), {}
    owner, prepared, pinned = None, None, None
    helper, owner_generation, helper_exit, owner_exit = None, None, None, None
    killed, owner_execs, unexpected_execs = False, 0, 0
    private_log = args.output.with_suffix('.private.log')
    previous_alarm = None
    try:
        log = os.open(private_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        helper = os.fork()
        if helper == 0:
            try:
                os.dup2(log, 1); os.dup2(log, 2)
                trace.call(PTRACE_TRACEME, 0)
                os.execve(args.test_binary, [str(args.test_binary), TEST, '--exact', '--ignored',
                          '--nocapture', '--test-threads=1'], {
                    'PATH': '/usr/bin:/bin', 'HOME': str(args.output.parent),
                    'TMPDIR': str(args.output.parent), 'LANG': 'C.UTF-8',
                    'SOU142_BUDGET_CONFIG': str(args.budget), 'SOU142_OWNER_PROFILE': str(args.profile),
                    'SOU86_TEST_AGENTFW': str(args.agentfw),
                    'SOU142_PREOWNER_CHILD_READY': str(args.output.with_suffix('.ready')),
                    'SOU142_TEST_COLLECTOR_STAGE': 'owner-self-loss'})
            except BaseException:
                os._exit(125)
        os.close(log)
        live.add(helper); pidfds[helper] = os.pidfd_open(helper)
        deadline = time.monotonic() + 20
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'standalone_observer_required')
        def timed_out(_signal, _frame):
            raise Incomplete('native_trace_deadline_exceeded')
        previous_alarm = signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, 20)
        while live:
            need(time.monotonic() < deadline, 'native_trace_deadline_exceeded')
            # Blocking wait avoids adding a polling delay to every traced
            # syscall. SIGALRM bounds this observer without changing the actual
            # owner's unchanged three-second startup/adoption deadline.
            pid, status = os.waitpid(-1, WALL)
            if pid not in live:
                # A child's initial ptrace stop can be reported before its
                # parent's FORK event. Kernel tracer custody and an existing
                # owned parent/thread group are both required before touching it.
                status_fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                                     if ':' in line)
                need(os.WIFSTOPPED(status) and len(live) < MAX_TRACEES
                     and int(status_fields['TracerPid']) == os.getpid()
                     and (int(status_fields['PPid']) in live or int(status_fields['Tgid']) in live),
                     'unexpected_wait_identity')
                live.add(pid)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                live.remove(pid); stopped.discard(pid)
                value = ('exit', os.WEXITSTATUS(status)) if os.WIFEXITED(status) else ('signal', os.WTERMSIG(status))
                if pid == helper: helper_exit = value
                if pid == owner: owner_exit = value
                continue
            need(os.WIFSTOPPED(status), 'unexpected_wait_state')
            stopped.add(pid)
            sig, event = os.WSTOPSIG(status), status >> 16
            if event in (1, 2, 3):
                message = ctypes.c_ulong()
                trace.call(PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(message))
                need(message.value > 0 and message.value != pid and len(live) < MAX_TRACEES,
                     'bounded_owned_trace_tree_required')
                live.add(message.value)
            if pid == helper and not owner_execs and sig == signal.SIGTRAP and event == 0:
                trace.call(PTRACE_SETOPTIONS, pid, 0, TRACE_OPTIONS)
            if event == 4 and pid != helper:
                command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                if b'--agentfw-mcp-owner-v1' in command:
                    need(owner is None and sha(f'/proc/{pid}/exe') == args.agentfw_sha256,
                         'one_actual_owner_generation_required')
                    owner = pid; owner_generation = identity(pid)
                    pidfds[pid] = os.pidfd_open(pid); owner_execs += 1
                else:
                    unexpected_execs += 1
            if pid == owner and sig == (signal.SIGTRAP | 0x80) and not killed:
                entry = trace.entry(pid)
                if entry and entry[0] == 46:  # Linux x86-64 sendmsg
                    need(entry[3] == 0x4000, 'expected_descriptor_send_flags_required')
                    prepared = descriptor_packet(lambda address, count: trace.memory(pid, address, count),
                                                 entry[2], budget_sha)
                    pinned = os.open(prepared['leaf'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, dir_fd=root)
                    same_leaf(root, prepared, pinned); leaf_empty(pinned)
                    need(identity(pid) == owner_generation and unexpected_execs == 0,
                         'owner_generation_or_pre_adoption_execution_invalid')
                    signal.pidfd_send_signal(pidfds[pid], signal.SIGKILL)
                    killed = True
                    report.update(owner_signal='SIGKILL', observed_stage='descriptor_sendmsg_entry',
                                  descriptors_delivered=False, descriptor_count=8,
                                  owner_generation_verified=True)
            try:
                # Trace only the actual owner's syscall boundary. The collector
                # verifies its complete runtime tree first; tracing every read
                # there would perturb the existing startup deadline needlessly.
                request = PTRACE_SYSCALL if pid == owner and not killed else PTRACE_CONT
                trace.call(request, pid, 0,
                           0 if sig in (signal.SIGTRAP, signal.SIGTRAP | 0x80, signal.SIGSTOP) else sig)
            except OSError as error:
                if not (killed and pid == owner and error.errno == errno.ESRCH): raise
            stopped.discard(pid)
        need(killed and owner_execs == 1 and owner_exit == ('signal', signal.SIGKILL)
             and helper_exit == ('exit', 0) and unexpected_execs == 0,
             'owner_kill_and_collector_refusal_unverified')
        raw = private_log.read_bytes()
        need(len(raw) < MAX_PACKET and b'1 passed; 0 failed' in raw
             and b'"spawn_refused":true' in raw and b'"original_started":false' in raw,
             'actual_collector_refusal_marker_missing')
        # Keep the existing 3000ms production cleanup observation window. This
        # is observation, not a deadline extension for the terminated launch.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            same_leaf(root, prepared, pinned); leaf_empty(pinned)
            time.sleep(0.01)
        clean_source()
        need(sha(args.agentfw) == args.agentfw_sha256 and sha(args.test_binary) == args.test_sha256,
             'closing_candidate_identity_changed')
        report.update(status='blocked', reason='owner_self_loss_orphan_reproduced', original_started=False,
                      collector_refused=True, residual_owned_leaf=True,
                      owned_members=0, all_traced_processes_stopped=True,
                      private_log_sha256=hashlib.sha256(raw).hexdigest())
    except BaseException as error:
        report['reason'] = str(error) if isinstance(error, Incomplete) else 'native_observation_incomplete'
        if isinstance(error, OSError): report['errno'] = error.errno
    finally:
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)
        # Let the real owner observe collector death on a failed observation.
        # Never count this diagnostic hygiene as production cleanup evidence.
        if helper in live and helper in pidfds:
            try: signal.pidfd_send_signal(pidfds[helper], signal.SIGKILL)
            except ProcessLookupError: pass
        deadline = time.monotonic() + 7
        while live and time.monotonic() < deadline:
            for pid in list(stopped):
                try: trace.call(PTRACE_DETACH, pid)
                except OSError: pass
                stopped.discard(pid)
            try: pid, status = os.waitpid(-1, WALL | os.WNOHANG)
            except ChildProcessError: break
            if not pid:
                time.sleep(0.01); continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status): live.discard(pid)
            elif os.WIFSTOPPED(status): stopped.add(pid)
        if live:
            report.update(status='incomplete', reason='trace_cleanup_unverified')
        if pinned is not None:
            try:
                same_leaf(root, prepared, pinned); leaf_empty(pinned)
                report['observer_cleanup_attempted'] = True
                os.rmdir(prepared['leaf'], dir_fd=root)
                report['observer_cleanup_verified'] = True
            except (OSError, Incomplete):
                report.update(status='incomplete', reason='observer_owned_cleanup_unverified')
            os.close(pinned)
        for fd in pidfds.values(): os.close(fd)
        os.close(root)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    for name in ('source', 'agentfw', 'test-binary', 'profile', 'budget', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-commit', 'agentfw-sha256', 'test-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'status': 'plan', 'executed': False,
                          'acceptance_pass': False, 'target': 'outside-owner-before-descriptor-handback'}))
        return 0
    os.umask(0o077)
    need(not args.output.exists(), 'new_output_required')
    try:
        result = observe(args)
    except BaseException as error:
        result = {'format': FORMAT, 'status': 'incomplete', 'acceptance_pass': False,
                  'reason': str(error) if isinstance(error, Incomplete) else 'native_setup_incomplete',
                  'production_cleanup_verified': False}
        if isinstance(error, OSError): result['errno'] = error.errno
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    # Successful DIAGNOSTIC reproduction is deliberately still status=blocked,
    # acceptance_pass=false, production_cleanup_verified=false.
    return 0 if result['status'] == 'blocked' and result.get('observer_cleanup_verified') else 1


if __name__ == '__main__':
    raise SystemExit(main())
