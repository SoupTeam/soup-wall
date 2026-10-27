#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit disposable Linux qualification of installed exact edit sessions.

The default is inert. Genuine pinned Claude uses only the owned loopback
scripted provider. Runtime bytes and state live outside the read-only checkout.
Raw contents, private native pending records and authority never enter report.json.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'sw-installed-edit-qualification/1'
CASES = ('installed-closure', 'inert-preview', 'useful-create', 'useful-replace',
         'ask-reject', 'no-approval', 'unlisted-tool', 'outside-target', 'linked-target',
         'stale-plan', 'changed-plan', 'no-exclusion', 'pending-old-change',
         'pending-new-change', 'approval-replay', 'cancel-pending', 'daemon-loss',
         'restart-authority', 'postcommit-result-loss')
CLAUDE = 'fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7'
OLD = 'Original ledger: seven blue containers.\n'
NEW = 'Revised report: twelve red samples.\n'


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HOST = load('edit_original_host', 'mcp-admission-demo.py')
BASE = load('edit_process_witness', 'verify-sou62-real-mcp.py')


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(path):
    try:
        m = path.lstat()
    except FileNotFoundError:
        return {'exists': False}
    row = {'exists': True, 'device': m.st_dev, 'inode': m.st_ino, 'mode': m.st_mode,
           'links': m.st_nlink, 'size': m.st_size}
    if stat.S_ISREG(m.st_mode):
        require(m.st_size <= 4096, 'snapshot_cap')
        row['sha256'] = sha(path.read_bytes())
    return row


def passed_report(report):
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and [r.get('id') for r in report.get('cases', [])] == list(CASES)
            and all(r.get('status') == 'passed' for r in report['cases'])
            and report.get('claude_sha256') == CLAUDE
            and report.get('paid_inference') is False)


class Suite:
    def __init__(self, args):
        self.args = args
        self.binary = args.output / 'installed/bin/agentfw'
        self.binary.parent.mkdir(parents=True, mode=0o700)
        shutil.copyfile(args.agentfw, self.binary)
        self.binary.chmod(0o500)
        self.claude = args.output / 'installed/bin/claude'
        shutil.copyfile(args.claude, self.claude)
        self.claude.chmod(0o500)
        self.home = args.output / 'installed/agent'
        self.home.mkdir(mode=0o700)
        self.work = args.output / 'work'
        self.work.mkdir(mode=0o700)
        self.state = args.output / 'runs'
        self.state.mkdir(mode=0o700)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(args.output), 'LANG': 'C.UTF-8',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        self.sentinel = args.output / 'unrelated.txt'
        self.sentinel.write_text('Owned unrelated witness.\n')
        self.sentinel.chmod(0o600)
        self.before_sentinel = snapshot(self.sentinel)
        self.last_run = None
        self.last_record = None

    def cli(self, *words, env=None, timeout=30):
        result = subprocess.run([str(self.binary), 'edit-session', *map(str, words)],
                                cwd=self.work, env=env or self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
        require(len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 128 * 1024, 'cli_output_cap')
        lines = result.stdout.splitlines()
        try:
            value = json.loads(lines[-1]) if lines else None
        except ValueError:
            value = None
        return result.returncode, value

    def prepare(self, label, replacing=False, apply=True, exclusion=True):
        root = self.work / label
        root.mkdir(mode=0o700)
        target = root / 'result.txt'
        if replacing:
            target.write_text(OLD)
            target.chmod(0o600)
        else:
            (root / 'source.txt').write_text(OLD)
            (root / 'source.txt').chmod(0o600)
        plan = self.work / (label + '-plan')
        words = ['prepare', '--home', self.home, '--root', root, '--claude', self.claude,
                 '--read', 'result.txt', '--replace' if replacing else '--create', 'result.txt', '--out', plan]
        if not replacing:
            words += ['--read', 'source.txt']
        if exclusion:
            words += ['--private-sole-writer']
        if apply:
            words += ['--apply']
        code, value = self.cli(*words)
        return root, target, plan, code, value

    def ask(self, run, *words):
        return self.cli('ask', '--run', run, *words)

    def host(self, label, root, target, plan, prepared, proposals, mode='approve', timeout=40):
        model = HOST.ScriptedModel([])
        offered = set()
        observed = {}
        changed = False
        retired = self.last_run if mode == 'restart-authority' else None
        restart_refused = False
        def next_step(body):
            names = {t.get('name') for t in body.get('tools', [])}
            if not any(n and n.startswith('mcp__private-output__') for n in names):
                return [{'type': 'text', 'text': 'Owned auxiliary request.'}]
            for message in body.get('messages', []):
                for block in message.get('content', []) if isinstance(message.get('content'), list) else []:
                    if isinstance(block, dict) and block.get('type') == 'tool_result' and block.get('tool_use_id') in offered:
                        observed[block['tool_use_id']] = {'is_error': bool(block.get('is_error')), 'content': block.get('content')}
            for index, (tool, arguments) in enumerate(proposals):
                identity = f'toolu_edit_{index}'
                if identity not in observed:
                    require(identity not in offered, 'host_reissued_request')
                    offered.add(identity)
                    return [{'type': 'tool_use', 'id': identity, 'name': 'mcp__private-output__' + tool, 'input': arguments}]
            if mode == 'postcommit-result-loss':
                time.sleep(60)
            return [{'type': 'text', 'text': 'Owned edit sequence finished.'}]
        model.next = next_step
        env = dict(self.env, ANTHROPIC_API_KEY=secrets.token_hex(32), ANTHROPIC_BASE_URL=model.url,
                   HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', NO_PROXY='localhost,127.0.0.1,::1')
        prompt = self.work / (label + '-prompt.txt')
        prompt.write_text('Use only the selected private output tools. Produce the requested bounded report.')
        prompt.chmod(0o600)
        before = snapshot(target)
        words = [str(self.binary), 'edit-session', 'run', '--plan', str(plan), '--sha256', prepared['profile_sha256'],
                 '--state', str(self.state), '--prompt-file', str(prompt), '--timeout-seconds', str(timeout)]
        output = self.work / (label + '-stdout.private')
        errors = self.work / (label + '-stderr.private')
        decisions = []; run = None; stopped = False; live_config = None; seen = set(); pending_seen = set()
        with output.open('wb') as out, errors.open('wb') as err:
            process = subprocess.Popen(words, cwd=self.work, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            witness = BASE.ProcessWitness(process.pid)
            deadline = time.monotonic() + timeout + 15
            try:
                while process.poll() is None and time.monotonic() < deadline:
                    if run is None:
                        lines = output.read_bytes().splitlines()
                        if lines:
                            row = json.loads(lines[0]); run = Path(row['run'])
                            self.last_run = run
                            live_config = json.loads((run / 'mcp.json').read_text())
                            if retired is not None:
                                import re, urllib.request, urllib.error
                                port = int(re.search(r'^port: ([0-9]+)$', (run / 'agent/config.yaml').read_text(), re.M)[1])
                                stale = (retired / 'agent/native-token').read_text()
                                request = urllib.request.Request(f'http://127.0.0.1:{port}/native/edit-session/v1',
                                    data=b'old authority must not reach the new epoch',
                                    headers={'Authorization': 'Bearer ' + stale}, method='POST')
                                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                                try:
                                    opener.open(request, timeout=3)
                                except urllib.error.HTTPError as error:
                                    require(error.code == 401, 'old_epoch_was_not_unauthorized')
                                    restart_refused = True
                                require(restart_refused, 'old_epoch_accepted')
                    if run is not None:
                        code, rows = self.ask(run, 'list')
                        if code != 0:
                            time.sleep(.025)
                            continue
                        require(isinstance(rows, list), 'ask_list_failed')
                        for row in rows:
                            pending_seen.add(row['pending_id'])
                            if row['pending_id'] in seen:
                                continue
                            code, inspected = self.ask(run, 'inspect', row['pending_id'])
                            require(code == 0 and inspected.get('arguments_redacted') is True and 'args' not in inspected
                                    and NEW not in json.dumps(inspected), 'inspect_exposed_arguments')
                            if mode in ('no-approval', 'cancel-pending', 'daemon-loss'):
                                if mode != 'no-approval' and not stopped:
                                    process.send_signal(signal.SIGINT if mode == 'cancel-pending' else signal.SIGKILL)
                                    stopped = True
                                continue
                            if mode == 'pending-old-change':
                                target.write_text('Operator superseding version.\n');changed = True
                            seen.add(row['pending_id'])
                            if mode == 'pending-new-change':
                                # Ask authority includes the exact argument digest. A different
                                # inspected binding cannot approve this already pending call.
                                code, _ = self.ask(run, 'approve', row['pending_id'], '--binding', sha(b'changed content'))
                                require(code != 0, 'changed_content_binding_accepted')
                                code, _ = self.ask(run, 'reject', row['pending_id'])
                                require(code == 0, 'changed_content_cleanup_failed')
                                changed = True
                                continue
                            action = 'reject' if mode == 'ask-reject' else 'approve'
                            code, _ = self.ask(run, action, row['pending_id'], *(['--binding', row['binding_sha256']] if action == 'approve' else []))
                            require(code == 0, 'decision_failed')
                            decisions.append({'id': row['pending_id'], 'binding_sha256': row['binding_sha256'], 'action': action})
                            self.last_record = decisions[-1]
                        if mode == 'postcommit-result-loss' and target.exists() and target.read_text() == NEW and not stopped:
                            process.send_signal(signal.SIGINT);stopped = True
                    time.sleep(.025)
                require(process.poll() is not None, 'host_timeout_outside_bound')
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL);process.wait(timeout=5)
                model.close()
                cleanup = witness.finish()
        require(cleanup['all_stopped'] and cleanup['descendant_count'] >= 2, 'owned_process_cleanup_failed')
        require(snapshot(self.sentinel) == self.before_sentinel, 'unrelated_sentinel_changed')
        require(len(model.requests) <= 32, 'provider_request_bound')
        terminal = json.loads((run / 'terminal.json').read_text()) if run and (run / 'terminal.json').exists() else None
        if run and mode != 'daemon-loss':
            code, rows = self.ask(run, 'list');require(code == 0 and rows == [], 'stale_pending_remains')
        diagnostics = errors.read_bytes()
        require(b'"mutation_dispatches":1' not in diagnostics and b'edit_adapter_mutation_dispatch' not in diagnostics,
                'adapter_received_mutation')
        native = (run / 'agent/audit.jsonl').read_bytes() if run else b''
        return {'id': label, 'status': 'passed', 'exit': process.returncode, 'before': before, 'after': snapshot(target),
                'approved': len([d for d in decisions if d['action'] == 'approve']), 'decisions': decisions,
                'pending_seen': len(pending_seen), 'provider_requests': len(model.requests), 'observed_results': len(observed),
                'process_cleanup': cleanup, 'terminal': terminal, 'audit_sha256': sha(native),
                'adapter_mutation_dispatches': 0, 'changed_control': changed, 'retired_epoch_refused': restart_refused}, observed, live_config


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == CLAUDE, 'genuine_pinned_claude_required')
    require(not args.output.is_relative_to(ROOT), 'outside_checkout_required')
    suite = Suite(args)
    report.update(agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()))
    archive = args.output / 'component.tar'
    build = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                           env=suite.env, cwd=ROOT, capture_output=True, timeout=60)
    require(build.returncode == 0, 'component_build_failed')
    built = json.loads(build.stdout.splitlines()[-1])
    install = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                              '--sha256', built['archive_sha256'], '--python', str(args.python)], env=suite.env,
                             cwd=suite.work, capture_output=True, timeout=60)
    require(install.returncode == 0, 'component_install_failed')
    report['source_commit'] = built['commit']
    report['cases'][0].update(status='passed', component=built['component'], source=built['commit'])
    def setrow(name, row):
        report['cases'][CASES.index(name)] = dict(row, id=name)
    root, target, plan, code, prepared = suite.prepare('preview', apply=False)
    require(code == 0 and not plan.exists() and not target.exists() and prepared['authority'] is False,
            'preview_has_effect')
    setrow('inert-preview', {'status': 'passed', 'authority': False, 'plan_created': False})
    for label in CASES[2:]:
        replacing = label not in ('useful-create', 'unlisted-tool', 'outside-target', 'no-exclusion')
        root, target, plan, code, prepared = suite.prepare(label, replacing, exclusion=label != 'no-exclusion')
        if label == 'no-exclusion':
            require(code != 0 and not plan.exists() and not target.exists(), 'missing_exclusion_accepted')
            setrow(label, {'status': 'passed', 'authority': False});continue
        require(code == 0 and prepared['status'] == 'prepared-not-active' and prepared['authority'] is False, 'prepare_failed_' + label)
        before = snapshot(target)
        if label in ('linked-target', 'stale-plan', 'changed-plan'):
            if label == 'linked-target':
                target.unlink();target.symlink_to(suite.sentinel)
            elif label == 'stale-plan':
                target.write_text('A newer operator-owned object.\n')
            else:
                file = plan / 'profile.json';file.chmod(0o600);file.write_bytes(file.read_bytes() + b' ');file.chmod(0o400)
            expected = snapshot(target)
            prompt = suite.work / (label + '-prompt');prompt.write_text('Bounded edit.');prompt.chmod(0o600)
            code, _ = suite.cli('run', '--plan', plan, '--sha256', prepared['profile_sha256'], '--state', suite.state, '--prompt-file', prompt)
            require(code != 0 and snapshot(target) == expected, 'invalid_plan_started_' + label)
            setrow(label, {'status': 'passed', 'target_preserved': True});continue
        profile = prepared['profile'];index = next(i for i, t in enumerate(profile['targets']) if t['name'] == 'result.txt')
        tool = ('replace' if replacing else 'create') + f'_output_{index}'
        arguments = {'path': 'result.txt', 'content': NEW}
        if replacing:
            old = profile['targets'][index]['replacement'];arguments.update(old_identity=old['identity'], old_sha256=old['sha256'])
        proposals = [(tool, arguments)]
        if label in ('useful-create', 'useful-replace'):
            source = 'result.txt' if replacing else 'source.txt'
            source_index = next(i for i, t in enumerate(profile['targets']) if t['name'] == source)
            proposals = [(f'read_output_{source_index}', {'path': source}), *proposals, (f'read_output_{index}', {'path': 'result.txt'})]
        elif label == 'unlisted-tool':
            proposals = [('write_file', arguments)]
        elif label == 'outside-target':
            proposals[0][1]['path'] = '../unrelated.txt'
        elif label == 'approval-replay':
            proposals = [*proposals, (tool, dict(arguments))]
        mode = label if label in ('ask-reject', 'no-approval', 'pending-old-change', 'pending-new-change', 'cancel-pending', 'daemon-loss', 'postcommit-result-loss', 'restart-authority') else 'approve'
        row, observed, config = suite.host(label, root, target, plan, prepared, proposals, mode, 12 if label == 'no-approval' else 40)
        if mode not in ('approve',) or label in ('useful-create', 'useful-replace', 'approval-replay'):
            require(row['pending_seen'] > 0, 'actual_pending_approval_missing_' + label)
        if label in ('useful-create', 'useful-replace', 'approval-replay', 'postcommit-result-loss', 'restart-authority'):
            require(target.read_text() == NEW and row['approved'] == 1, 'exact_effect_missing_' + label)
            if label.startswith('useful-'):
                require(len(observed) == 3 and all(not r['is_error'] for r in observed.values()), 'useful_read_edit_read_incomplete_' + label)
                require(NEW.strip() in json.dumps(observed['toolu_edit_2']['content']), 'verified_final_read_missing')
                require(row['exit'] == 0, 'useful_host_failed_' + label)
            if label == 'restart-authority':
                require(row['retired_epoch_refused'] and row['exit'] == 0, 'fresh_epoch_control_failed')
            if label == 'approval-replay':
                require(observed['toolu_edit_1']['is_error'], 'replayed_replacement_succeeded')
            if label == 'postcommit-result-loss':
                require(row['exit'] != 0 and row['terminal']['state'] == 'failed', 'postcommit_interruption_reported_success')
        elif label == 'pending-old-change':
            require(target.read_text() == 'Operator superseding version.\n', 'superseding_inventory_overwritten')
        else:
            require(snapshot(target) == before, 'unauthorized_effect_' + label)
            if label in ('ask-reject', 'pending-new-change', 'unlisted-tool', 'outside-target'):
                require(observed and all(r['is_error'] for r in observed.values()), 'refusal_not_observed_' + label)
        setrow(label, row)
    require(snapshot(suite.sentinel) == suite.before_sentinel, 'final_unrelated_witness_changed')
    report['status'] = 'passed'
    require(passed_report(report), 'incomplete_qualification')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--agentfw', type=Path)
    p.add_argument('--claude', type=Path)
    p.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'executed': False, 'cases': list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format': FORMAT, 'status': 'incomplete', 'paid_inference': False,
              'scope': 'native-installed-genuine-host-owned-scripted-provider',
              'cases': [{'id': name, 'status': 'incomplete'} for name in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__, failure=str(error)[:160])
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format': FORMAT, 'status': report['status'], 'passed': sum(r['status'] == 'passed' for r in report['cases']), 'required': len(CASES)}))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
