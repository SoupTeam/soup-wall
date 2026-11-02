#!/usr/bin/env python3
"""Discover offline help from an explicitly selected installed Python pilot."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import os
import types
from unittest.mock import patch

ALLOWED_READER = None


def effects(parts):
    if parts in (['preview'], ['status'], ['help'], ['provider', 'preview'],
                 ['lifecycle', 'status'], ['update', 'preview'], ['update', 'inspect']):
        return 'read_only'
    if parts == ['doctor']:
        return 'read_only_unless_support_bundle_export_is_selected'
    if parts == ['update', 'inventory']:
        return 'inventory_export_requires_explicit_output'
    if parts in (['update', 'rollback'], ['update', 'recover'], ['update', 'cleanup']):
        return 'preview_unless_confirm_then_lifecycle_mutation'
    if parts == ['provider', 'check']:
        return 'read_only_unless_transport_is_selected'
    if parts == ['run']:
        return 'launch_and_provider'
    if parts == ['prepare']:
        return 'preview_unless_apply_then_prepare_and_possible_download'
    if parts[:1] == ['provider'] and len(parts) > 1:
        return 'preview_unless_apply_then_private_profile_mutation'
    if parts[:1] == ['update'] and len(parts) > 1:
        return 'lifecycle_mutation_requires_command_specific_confirmation'
    return 'may_mutate_launch_or_contact_provider_review_parser_help'


def guard(event, args):
    if event in ('os.mkdir', 'os.remove', 'os.rename', 'os.rmdir'):
        raise ValueError('help lookup attempted a filesystem change')
    if event == 'open':
        mode, flags = args[1:3]
        if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)):
            raise ValueError('help lookup attempted a file write')
    if event == 'subprocess.Popen' and ALLOWED_READER is not None:
        executable, command = args[:2]
        if executable == ALLOWED_READER and isinstance(command, list) and command[-1] == '--help' and all(re.fullmatch('[a-z][a-z0-9-]*', word) for word in command[1:-1]):
            return
    if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'socket.connect', 'socket.bind', 'socket.getaddrinfo'):
        raise ValueError('help lookup attempted a process or network operation')


def discover(path, expected, update_sha256=None):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents):
        raise ValueError('linked component path')
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('selected component digest mismatch')
    sys.dont_write_bytecode = True
    sys.addaudithook(guard)
    module = types.ModuleType('selected_pilot')
    module.__file__ = str(path.absolute())
    exec(compile(raw, str(path.absolute()), 'exec'), module.__dict__)
    parser = module.parser()
    rows = []
    def walk(node, parts):
        flags = []
        positionals = []
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    if not re.fullmatch('[a-z][a-z0-9-]{0,63}', name):
                        raise ValueError('unsafe command name')
                    walk(child, parts + [name])
            elif action.help != argparse.SUPPRESS:
                if not action.option_strings:
                    choices = list(action.choices or [])
                    if any(not isinstance(word, str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', word) for word in choices):
                        raise ValueError('unsafe positional choice')
                    positionals.append({'name': action.dest, 'required': action.required, 'choices': choices})
                for flag in action.option_strings:
                    if not re.fullmatch('-{1,2}[a-zA-Z0-9][a-zA-Z0-9-]*', flag):
                        raise ValueError('unsafe flag')
                    flags.append({'name': flag, 'required': action.required,
                                  'takes_value': action.nargs != 0,
                                  'type': getattr(action.type, '__name__', 'string') if action.nargs != 0 else 'boolean'})
        rows.append({'command': parts, 'flags': flags, 'positionals': positionals,
                     'effects': effects(parts),
                     'confirmation_flags': [f['name'] for f in flags if f['name'] in ('--apply', '--transport', '--confirm', '--expected-version', '--inventory-sha256')]})
    walk(parser, [])
    delegated = None
    if update_sha256 is not None:
        delegate_path = path.with_name('pilot_update.py')
        if delegate_path.is_symlink():
            raise ValueError('linked delegated component')
        delegate_raw = delegate_path.read_bytes()
        if len(delegate_raw) > 1024 * 1024 or hashlib.sha256(delegate_raw).hexdigest() != update_sha256:
            raise ValueError('delegated component digest mismatch')
        delegate = types.ModuleType('selected_update')
        delegate.__file__ = str(delegate_path.absolute())
        exec(compile(delegate_raw, str(delegate_path.absolute()), 'exec'), delegate.__dict__)
        captured = []
        class ParserCaptured(Exception):
            pass
        def capture(node, *args, **kwargs):
            captured.append(node)
            raise ParserCaptured()
        with patch.object(argparse.ArgumentParser, 'parse_args', capture):
            try:
                delegate.main([])
            except ParserCaptured:
                pass
        if len(captured) != 1:
            raise ValueError('unsupported delegated parser')
        rows[:] = [row for row in rows if row['command'] != ['update']]
        walk(captured[0], ['update'])
        for action in captured[0]._actions:
            if not action.option_strings and action.choices:
                for operation in action.choices:
                    walk(captured[0], ['update', operation])
        delegated = update_sha256
    if len(rows) > 256:
        raise ValueError('catalog exceeds command limit')
    return {'schema': 'sw-agent-command-catalog/2', 'component_sha256': expected,
            'platform': 'native Ubuntu 24.04 pilot; lookup uses Python 3.11+',
            'delegated_component_sha256': delegated,
            'outcome_references': sorted(key for key in getattr(module, 'HINTS', {}) if re.fullmatch('[a-z][a-z0-9_]{0,79}', key))[:256], 'commands': rows}


def completion(data, shell, context=None):
    context = list(context or [])
    if shell not in ('bash', 'zsh', 'fish') or len(data['commands']) > 256:
        raise ValueError('unsupported completion input')
    if any(not isinstance(word, str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', word) for word in context):
        raise ValueError('unsafe completion context')
    selected = []
    for row in data['commands']:
        command = row['command']
        if not isinstance(command, list) or len(command) > 8 or any(
                not isinstance(word, str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', word) for word in command):
            raise ValueError('unsafe completion command')
        if len(row['flags']) > 256 or any(not isinstance(flag.get('name'), str) or not re.fullmatch(
                '-{1,2}[a-zA-Z0-9][a-zA-Z0-9-]{0,79}', flag['name']) for flag in row['flags']):
            raise ValueError('unsafe completion flag')
        if command[:len(context)] == context:
            selected.append(row)
    if not selected:
        raise ValueError('unknown completion context')
    words = sorted({row['command'][len(context)] for row in selected if len(row['command']) > len(context)} |
                   {flag['name'] for row in selected if row['command'] == context for flag in row['flags']})
    joined = ' '.join(words)
    if not context:
        cases = []
        for row in data['commands']:
            path = row['command']
            candidates = {other['command'][len(path)] for other in data['commands']
                          if other['command'][:len(path)] == path and len(other['command']) > len(path)}
            candidates.update(flag['name'] for flag in row['flags'])
            cases.append((' '.join(path), ' '.join(sorted(candidates))))
        if shell == 'bash':
            lines = ['_pilot_help_complete() {', ' local context="" word choices="" i',
                     ' COMPREPLY=()', ' for ((i=1; i<COMP_CWORD; i++)); do',
                     '  word=${COMP_WORDS[i]}', '  case "$word" in -* ) return ;; esac',
                     '  context="${context:+$context }$word"', ' done', ' case "$context" in']
            lines += ["  '" + key + "') choices='" + value + "' ;;" for key, value in cases]
            lines += ['  *) return ;;', ' esac',
                      ' while IFS= read -r word; do COMPREPLY+=("$word"); done < <(compgen -W "$choices" -- "${COMP_WORDS[COMP_CWORD]}")',
                      '}', 'complete -F _pilot_help_complete pilot']
            return '\n'.join(lines) + '\n'
        if shell == 'zsh':
            lines = ['#compdef pilot', '_pilot_help_complete() {', ' local context="" word choices="" i',
                     ' for ((i=2; i<CURRENT; i++)); do', '  word=${words[i]}',
                     '  case "$word" in -*) return ;; esac',
                     '  context="${context:+$context }$word"', ' done', ' case "$context" in']
            lines += ["  '" + key + "') choices='" + value + "' ;;" for key, value in cases]
            lines += ['  *) return ;;', ' esac', ' compadd -- ${=choices}', '}', 'compdef _pilot_help_complete pilot']
            return '\n'.join(lines) + '\n'
        lines = ['function __pilot_help_context', ' set -l words (commandline -opc)',
                 ' test (count $words) -ge 1; or return 1', ' set -e words[1]',
                 ' test (string join " " -- $words) = "$argv[1]"', 'end']
        for key, value in cases:
            for word in value.split():
                option = "-l '" + word[2:] + "'" if word.startswith('--') else "-s '" + word[1:] + "'" if word.startswith('-') else "-a '" + word + "'"
                lines.append("complete -c pilot -f -n '__pilot_help_context \"" + key + "\"' " + option)
        return '\n'.join(lines) + '\n'
    if shell == 'bash':
        return "_pilot_help_complete() { COMPREPLY=( $(compgen -W '" + joined + "' -- \"${COMP_WORDS[COMP_CWORD]}\") ); }\ncomplete -F _pilot_help_complete pilot\n"
    if shell == 'zsh':
        return "#compdef pilot\n_pilot_help_complete() { compadd -- " + joined + "; }\ncompdef _pilot_help_complete pilot\n"
    return '\n'.join("complete -c pilot -f " + ("-l '" + word[2:] + "'" if word.startswith('--') else "-s '" + word[1:] + "'" if word.startswith('-') else "-a '" + word + "'") for word in words) + '\n'


def rust_catalog(path, expected):
    if sys.platform != 'linux' or not hasattr(os, 'memfd_create'):
        raise ValueError('verified binary help requires Linux sealed executable support')
    import fcntl
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    source_fd = os.open(path, flags)
    snapshot = os.memfd_create('agentfw-help', os.MFD_ALLOW_SEALING)
    try:
        import stat
        meta = os.fstat(source_fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 256 * 1024 * 1024:
            raise ValueError('unsafe binary')
        hashed = hashlib.sha256()
        size = 0
        while True:
            block = os.read(source_fd, 65536)
            if not block:
                break
            size += len(block)
            if size > 256 * 1024 * 1024:
                raise ValueError('binary exceeds cap')
            hashed.update(block)
            offset = 0
            while offset < len(block):
                offset += os.write(snapshot, block[offset:])
        if hashed.hexdigest() != expected:
            raise ValueError('binary digest mismatch')
        fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return rust_catalog_snapshot(Path('/proc/self/fd') / str(snapshot), expected, snapshot)
    finally:
        os.close(source_fd)
        os.close(snapshot)


def rust_catalog_snapshot(path, expected, snapshot):
    global ALLOWED_READER
    ALLOWED_READER = str(path.absolute())
    rows, pending = [], [[]]
    while pending:
        parts = pending.pop(0)
        if len(rows) >= 256 or len(parts) > 8:
            raise ValueError('command tree exceeds cap')
        with tempfile.TemporaryFile() as output:
            child = subprocess.Popen([ALLOWED_READER, *parts, '--help'], stdout=output, stderr=subprocess.DEVNULL, pass_fds=(snapshot,))
            try:
                status = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise ValueError('help reader timed out')
            output.seek(0)
            raw = output.read(65537)
        if status or len(raw) > 65536:
            raise ValueError('help reader failed or exceeded cap')
        flags, section = [], ''
        for line in raw.decode('utf-8').splitlines():
            if line and not line[0].isspace():
                section = line
            elif section == 'Commands:':
                match = re.match(r'  ([a-z][a-z0-9-]*)\s', line)
                if match and match[1] != 'help':
                    pending.append(parts + [match[1]])
            elif section == 'Options:':
                for flag in re.findall(r'(?<!\w)--?[a-zA-Z][a-zA-Z0-9-]*', re.split(r'\s{2,}', line.strip(), maxsplit=1)[0]):
                    flags.append({'name': flag, 'required': False, 'takes_value': '<' in line, 'type': 'parser_help'})
        rows.append({'command': parts, 'flags': flags, 'effects': effects(parts),
                     'confirmation_flags': [flag['name'] for flag in flags if flag['name'] in
                                            ('--apply', '--confirm', '--yes', '--approve', '--sha256')]})
    return {'schema': 'sw-agent-command-catalog/2', 'component_sha256': expected, 'commands': rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', type=Path)
    parser.add_argument('--agentfw', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--update-sha256')
    parser.add_argument('action', choices=('list', 'topic', 'completion'))
    parser.add_argument('topic', nargs='*')
    parser.add_argument('--shell', choices=('bash', 'zsh', 'fish'))
    parser.add_argument('--context', nargs='*', default=[])
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch('[0-9a-f]{64}', args.sha256):
            raise ValueError('invalid component digest')
        if (args.pilot is None) == (args.agentfw is None):
            raise ValueError('select one component')
        data = discover(args.pilot, args.sha256, args.update_sha256) if args.pilot else rust_catalog(args.agentfw, args.sha256)
        if args.action == 'completion':
            if not args.shell:
                raise ValueError('shell is required')
            print(completion(data, args.shell, args.context), end='')
        elif args.action == 'topic':
            rows = [row for row in data['commands'] if row['command'] == args.topic]
            if len(rows) != 1:
                raise ValueError('unknown topic')
            print(json.dumps(rows[0], indent=2))
        else:
            print(json.dumps(data, indent=2))
        return 0
    except (OSError, ValueError, AttributeError, ImportError) as error:
        reasons = {'unsafe binary', 'binary exceeds cap', 'binary digest mismatch',
                   'command tree exceeds cap', 'help reader failed or exceeded cap', 'help reader timed out'}
        reason = str(error) if type(error) is ValueError and str(error) in reasons else 'unsupported or changed installed component'
        print('error: ' + reason, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
