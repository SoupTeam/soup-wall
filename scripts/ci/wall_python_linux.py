# SPDX-License-Identifier: Apache-2.0
"""Run Wall's existing POSIX driver suites in a disposable Linux checkout.

Invoked only inside the already owned WSL distro; never called native Windows QA.
"""
import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from vps_counts import test_counts, validate_target


def run(source: Path, output: Path, sha: str) -> None:
    validate_target('soup-wall', sha)
    if platform.system() != 'Linux' or os.geteuid() == 0:
        raise ValueError('Require the non-root owned Linux user, not native Windows or root')
    source, output = source.resolve(strict=True), output.resolve()
    output.mkdir()
    report = {'source_sha': sha, 'os': platform.platform(), 'python': sys.version,
              'status': 'running', 'steps': [], 'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'limitations': ['WSL Linux driver/unit checks; not Windows ACL, standard-user or installed acceptance']}
    # Fixture directories intentionally exercise POSIX mode checks. This affects
    # this disposable helper process/children only, not the host's security policy.
    os.umask(0o022)
    env = os.environ.copy()
    env.update({'HF_HUB_OFFLINE': '1', 'HF_DATASETS_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1',
                'PYTHONUTF8': '1', 'PYTHONNOUSERSITE': '1'})
    env.pop('PYTHONPATH', None)

    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def step(name, argv, cwd, reader=None):
        result = {'name': name, 'argv': argv, 'status': 'running'}
        report['steps'].append(result)
        save()
        print('Linux step: ' + name, flush=True)
        logfile = output / (name + '.log')
        with logfile.open('w', encoding='utf-8') as log:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            for line in process.stdout:
                print(line, end='', flush=True)
                log.write(line)
            process.stdout.close()
            result['exit_code'] = process.wait()
        if result['exit_code']:
            result['status'] = 'failed'
            raise RuntimeError(f"{name} failed with exit {result['exit_code']}")
        if reader:
            result['tests'] = test_counts(reader, logfile.read_text(encoding='utf-8'), output)
        result['status'] = 'passed'
        save()

    try:
        with tempfile.TemporaryDirectory(prefix='soup-wall-ci-') as temporary:
            root = Path(temporary)
            checkout = root / 'source'
            # Local clone uses the verified public checkout's object store, but
            # creates LF/executable/POSIX worktree files on the Linux filesystem.
            step('clone', ['git', '-c', f'safe.directory={source}', 'clone', '--no-hardlinks',
                           '--no-checkout', str(source), str(checkout)], root)
            step('checkout', ['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', sha], checkout)
            actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip()
            if actual != sha:
                raise ValueError('Linux checkout does not match the selected public source')
            report['tree_sha'] = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=checkout, text=True).strip()
            venv = root / 'venv'
            step('venv', [sys.executable, '-m', 'venv', str(venv)], root)
            python = str(venv / 'bin/python')
            env['PATH'] = str(venv / 'bin') + os.pathsep + env.get('PATH', '')
            step('dependencies', [python, '-m', 'pip', 'install', '--disable-pip-version-check',
                                  'requests==2.34.2', 'cryptography==50.0.2', 'psutil==7.2.2'], checkout)
            step('python-tests', [python, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-p', 'test_*.py', '-v'], checkout, 'unittest')
            step('benchmark-tests', [python, '-m', 'unittest', 'discover', '-s', 'scripts/benchmarks', '-p', 'test_*.py', '-v'], checkout, 'unittest')
            step('documentation', [python, 'scripts/check_docs.py'], checkout)
        report['status'] = 'passed'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        for result in report['steps']:
            if result['status'] == 'running':
                result['status'] = 'failed'
        raise
    finally:
        report['ended_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    run(args.source, args.output, args.source_sha)
