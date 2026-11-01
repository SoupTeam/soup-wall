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

ALLOWED_READER = None


def effects(parts):
    if parts in (['preview'], ['status'], ['help'], ['provider', 'preview']):
        return 'read_only'
    if parts == ['provider', 'check']:
        return 'read_only_unless_transport_is_selected'
    if parts == ['run']:
        return 'launch_and_provider'
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


def discover(path, expected):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents):
        raise ValueError('linked component path')
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('selected component digest mismatch')
    sys.dont_write_bytecode = True
    sys.addaudithook(guard)
    spec = importlib.util.spec_from_file_location('selected_pilot', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parser = module.parser()
    rows = []
    def walk(node, parts):
        flags = []
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    if not re.fullmatch('[a-z][a-z0-9-]{0,63}', name):
                        raise ValueError('unsafe command name')
                    walk(child, parts + [name])
            elif action.help != argparse.SUPPRESS:
                for flag in action.option_strings:
                    if not re.fullmatch('-{1,2}[a-zA-Z0-9][a-zA-Z0-9-]*', flag):
                        raise ValueError('unsafe flag')
                    flags.append({'name': flag, 'required': action.required,
                                  'takes_value': action.nargs != 0,
                                  'type': getattr(action.type, '__name__', 'string') if action.nargs != 0 else 'boolean'})
        rows.append({'command': parts, 'flags': flags,
                     'effects': effects(parts),
                     'confirmation_flags': [f['name'] for f in flags if f['name'] in ('--apply', '--transport')]})
    walk(parser, [])
    if len(rows) > 256:
        raise ValueError('catalog exceeds command limit')
    return {'schema': 'sw-agent-command-catalog/2', 'component_sha256': expected,
            'platform': 'native Ubuntu 24.04 pilot; lookup uses Python 3.11+',
            'outcome_references': sorted(key for key in getattr(module, 'HINTS', {}) if re.fullmatch('[a-z][a-z0-9_]{0,79}', key))[:256], 'commands': rows}


def completion(data, shell):
    words = sorted({word for row in data['commands'] for word in row['command']} |
                   {flag['name'] for row in data['commands'] for flag in row['flags']})
    joined = ' '.join(words)
    if shell == 'bash':
        return "_pilot_help_complete() { COMPREPLY=( $(compgen -W '" + joined + "' -- \"${COMP_WORDS[COMP_CWORD]}\") ); }\ncomplete -F _pilot_help_complete pilot\n"
    if shell == 'zsh':
        return "#compdef pilot\n_pilot_help_complete() { compadd -- " + joined + "; }\ncompdef _pilot_help_complete pilot\n"
    return '\n'.join("complete -c pilot -f " + ("-l '" + word[2:] + "'" if word.startswith('--') else "-s '" + word[1:] + "'" if word.startswith('-') else "-a '" + word + "'") for word in words) + '\n'


def rust_catalog(path, expected):
    global ALLOWED_READER
    if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents) or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('unsafe binary')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != expected:
        raise ValueError('binary digest mismatch')
    ALLOWED_READER = str(path.absolute())
    rows, pending = [], [[]]
    while pending:
        parts = pending.pop(0)
        if len(rows) >= 256 or len(parts) > 8:
            raise ValueError('command tree exceeds cap')
        with tempfile.TemporaryFile() as output:
            child = subprocess.Popen([ALLOWED_READER, *parts, '--help'], stdout=output, stderr=subprocess.DEVNULL)
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
        rows.append({'command': parts, 'flags': flags, 'effects': 'review_command_help_before_execution'})
    return {'schema': 'sw-agent-command-catalog/2', 'component_sha256': expected, 'commands': rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', type=Path)
    parser.add_argument('--agentfw', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('action', choices=('list', 'topic', 'completion'))
    parser.add_argument('topic', nargs='*')
    parser.add_argument('--shell', choices=('bash', 'zsh', 'fish'))
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch('[0-9a-f]{64}', args.sha256):
            raise ValueError('invalid component digest')
        if (args.pilot is None) == (args.agentfw is None):
            raise ValueError('select one component')
        data = discover(args.pilot, args.sha256) if args.pilot else rust_catalog(args.agentfw, args.sha256)
        if args.action == 'completion':
            if not args.shell:
                raise ValueError('shell is required')
            print(completion(data, args.shell), end='')
        elif args.action == 'topic':
            rows = [row for row in data['commands'] if row['command'] == args.topic]
            if len(rows) != 1:
                raise ValueError('unknown topic')
            print(json.dumps(rows[0], indent=2))
        else:
            print(json.dumps(data, indent=2))
        return 0
    except (OSError, ValueError, AttributeError, ImportError):
        print('error: unsupported or changed installed component', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
