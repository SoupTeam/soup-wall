#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Trusted online SOU143 input setup; no candidate binaries/builds/tests execute.

Reuses a completed same-source native fast slice, verifies every
network input against accepted main, and leaves candidate preparation offline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

ACCEPTED = '04efdf1d959599238a0a9a3eb42cbe26b3531b74'
HOST_SHA = 'fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7'
DOWNLOADS = {
    'node': ('https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz',
             '9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37', 'xz'),
    'git': ('https://www.kernel.org/pub/software/scm/git/git-2.51.2.tar.xz',
            '233d7143a2d58e60755eee9b76f559ec73ea2b3c297f5b503162ace95966b4e3', 'xz'),
    'bwrap': ('https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz',
              '0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d', 'xz'),
    'python': ('https://github.com/astral-sh/python-build-standalone/releases/download/20251014/cpython-3.11.14%2B20251014-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
               '91ab434738647ab45d630aaa02e3808bb516239beeb52f7799c12a12d1557a38', 'gz'),
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--scratch', type=Path, required=True)
    p.add_argument('--fast-scratch', type=Path, required=True)
    p.add_argument('--expected-commit', required=True)
    p.add_argument('--rustup-home', type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    src, out, fast = [path.resolve(strict=True) for path in (a.source, a.scratch, a.fast_scratch)]
    require(re.fullmatch(r'[0-9a-f]{40}', a.expected_commit), 'full_source_sha_required')
    require(not out.is_relative_to(src) and out != fast and not fast.is_relative_to(out), 'isolated_host_scratch_required')
    for path in (out, fast):
        info = path.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private_owned_scratch_required')
    record = {'format': 'sou143-trusted-host-inputs/1', 'status': 'incomplete',
              'source': a.expected_commit, 'accepted_setup_source': ACCEPTED,
              'candidate_code_executed': False, 'steps': []}
    def save():
        temporary = out / 'setup-attempt.next'
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        temporary.replace(out / 'setup-attempt.json')
    save()
    for name in ('setup-home', 'tmp', 'assets', 'npm-cache', 'wheelhouse'):
        (out / name).mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(out / 'setup-home'), 'TMPDIR': str(out / 'tmp'),
           'LANG': 'C.UTF-8', 'RUSTUP_HOME': str(a.rustup_home.resolve(strict=True)),
           'RUSTUP_AUTO_INSTALL': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    def git(*words):
        return subprocess.check_output(['/usr/bin/git', *words], cwd=src, env=env, timeout=20)
    def run(label, words, *, cwd=out, selected_env=None, timeout=900):
        step = {'label': label, 'status': 'incomplete'}
        record['steps'].append(step)
        save()
        log = out / (label + '.private.log')
        try:
            with log.open('wb') as stream:
                done = subprocess.run(list(map(str, words)), cwd=cwd, env=selected_env or env,
                                      stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
            step.update(exit_code=done.returncode, status='passed' if done.returncode == 0 else 'failed')
        finally:
            if log.exists():
                step['log_sha256'] = sha(log)
            save()
        require(step['status'] == 'passed', label + '_failed')
    try:
        require(git('rev-parse', 'HEAD').decode().strip() == a.expected_commit, 'same_candidate_source_required')
        require(not git('status', '--porcelain', '--untracked-files=all'), 'clean_candidate_source_required')
        git('merge-base', '--is-ancestor', ACCEPTED, a.expected_commit)
        first = json.loads((fast / 'native-first-slice.json').read_text())
        require(first.get('format') == 'sou142143-native-first-slice/1' and first.get('status') == 'passed'
                and first.get('issue') == '143' and first.get('source') == a.expected_commit,
                'passed_same_source_143_fast_slice_required')
        step = [row for row in first['steps'] if row['label'] == 'native-test-build']
        require(len(step) == 1 and step[0]['status'] == 'passed'
                and step[0]['log_sha256'] == sha(fast / 'native-test-build.log'), 'native_test_build_identity_changed')
        rows = [json.loads(line) for line in (fast / 'native-test-build.log').read_text().splitlines() if line.startswith('{')]
        tests = [Path(row['executable']).resolve(strict=True) for row in rows
                 if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'agentfw'
                 and row.get('profile', {}).get('test') and row.get('executable')]
        require(len(tests) == 1 and tests[0].is_relative_to((fast / 'target/debug/deps').resolve(strict=True)),
                'one_exact_native_test_binary_required')
        selected = {'agentfw': str(fast / 'target/debug/agentfw'),
                    'git_launcher': str(fast / 'target/debug/agentfw-git-sandbox'),
                    'sandbox_tests': str(tests[0]), 'python': str(Path(sys.executable).resolve(strict=True))}
        for role, name in [('agentfw', 'agentfw'), ('git_launcher', 'agentfw-git-sandbox')]:
            require(sha(selected[role]) == first['binary_sha256'][name], 'native_binary_identity_changed')
        # Guard only the exact data consumed by networked setup, not candidate code.
        guarded = [
            'profiles/mcp/filesystem-readonly-v1/package.json',
            'profiles/mcp/filesystem-readonly-v1/package-lock.json',
            'profiles/mcp/filesystem-readonly-v1/upstream-identity.json',
            'profiles/mcp/filesystem-readonly-v1/claude-host/package.json',
            'profiles/mcp/filesystem-readonly-v1/claude-host/package-lock.json',
            'profiles/mcp/git-readonly-v1/requirements.lock',
            'profiles/mcp/git-readonly-v1/upstream-identity.json',
            'scripts/ci_bwrap_userns.py',
        ]
        for name in guarded:
            require((src / name).read_bytes() == git('show', ACCEPTED + ':' + name), 'accepted_setup_input_changed')
        (out / 'accepted-ci-bwrap.py').write_bytes(git('show', ACCEPTED + ':scripts/ci_bwrap_userns.py'))
        assets = out / 'assets'
        for name, (url, digest, compression) in DOWNLOADS.items():
            archive = assets / (name + '.tar.' + compression)
            run('download-' + name, ['curl', '--fail', '--location', '--retry', '3', url, '--output', archive])
            require(sha(archive) == digest, 'trusted_archive_digest_mismatch')
            directory = assets / name
            directory.mkdir(mode=0o700)
            run('extract-' + name, ['tar', '-xf', archive, '-C', directory, '--strip-components=1',
                                   '--no-same-owner', '--no-same-permissions'])
        # Accepted native-24.04 setup uses an extracted private libcap development
        # package and the runner's already installed libcap.so.2, not global repair.
        caproot = assets / 'libcap'
        caproot.mkdir(mode=0o700)
        run('download-libcap-dev', ['apt-get', 'download', 'libcap-dev'], cwd=assets)
        debs = list(assets.glob('libcap-dev_*.deb'))
        require(len(debs) == 1, 'one_libcap_development_package_required')
        run('extract-libcap-dev', ['dpkg-deb', '-x', debs[0], caproot])
        caplib = caproot / 'usr/lib/x86_64-linux-gnu'
        shutil.copyfile('/lib/x86_64-linux-gnu/libcap.so.2', caplib / 'libcap.so.2')
        if (caplib / 'libcap.so').exists() or (caplib / 'libcap.so').is_symlink():
            (caplib / 'libcap.so').unlink()
        (caplib / 'libcap.so').symlink_to('libcap.so.2')
        (caproot / 'usr/lib64').symlink_to(caplib)
        run('install-meson', [sys.executable, '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
                              '--target', assets / 'build-tools', 'meson==1.9.1'])
        build_env = dict(env, PYTHONPATH=str(assets / 'build-tools'),
                         PKG_CONFIG_LIBDIR=str(caplib / 'pkgconfig'), PKG_CONFIG_SYSROOT_DIR=str(caproot))
        run('configure-bwrap', [sys.executable, '-m', 'mesonbuild.mesonmain', 'setup', assets / 'bwrap-build',
                               assets / 'bwrap', '-Dtests=false', '-Dman=disabled', '-Dselinux=disabled',
                               '-Dbash_completion=disabled', '-Dzsh_completion=disabled'], selected_env=build_env)
        run('build-bwrap', [sys.executable, '-m', 'mesonbuild.mesonmain', 'compile', '-C', assets / 'bwrap-build'], selected_env=build_env)
        run('build-git', ['make', '-C', assets / 'git', '-j2', 'NO_CURL=YesPlease', 'NO_EXPAT=YesPlease',
                          'NO_TCLTK=YesPlease', 'NO_GETTEXT=YesPlease', 'NO_OPENSSL=YesPlease', 'git'])
        node_env = dict(env, PATH=str(assets / 'node/bin') + ':/usr/bin:/bin')
        for name, relative in [('fs-seed', 'profiles/mcp/filesystem-readonly-v1'),
                               ('claude', 'profiles/mcp/filesystem-readonly-v1/claude-host')]:
            directory = assets / name
            directory.mkdir(mode=0o700)
            for filename in ('package.json', 'package-lock.json'):
                shutil.copyfile(src / relative / filename, directory / filename)
            run('cache-' + name, [assets / 'node/bin/npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund',
                '--userconfig=/dev/null', '--globalconfig=/dev/null', '--cache', out / 'npm-cache',
                '--prefix', directory], selected_env=node_env)
        python = assets / 'python/bin/python3.11'
        run('cache-git-wheels', [python, '-I', '-m', 'pip', '--isolated', 'download', '--require-hashes',
             '--only-binary=:all:', '--disable-pip-version-check', '--dest', out / 'wheelhouse',
             '-r', src / 'profiles/mcp/git-readonly-v1/requirements.lock'])
        requirements = (src / 'profiles/mcp/git-readonly-v1/requirements.lock').read_text().splitlines()
        allowed = set(re.findall(r'--hash=sha256:([0-9a-f]{64})', '\n'.join(requirements)))
        wheels = list((out / 'wheelhouse').glob('*.whl'))
        require(len(wheels) == len([row for row in requirements if row.strip()]) == 33,
                'complete_pinned_wheelhouse_required')
        require(all(sha(path) in allowed for path in wheels), 'wheelhouse_digest_unreviewed')
        selected.update(node_archive=str(assets / 'node.tar.xz'), python_archive=str(assets / 'python.tar.gz'),
                        node=str(assets / 'node/bin/node'), npm=str(assets / 'node/bin/npm'),
                        bwrap_source=str(assets / 'bwrap-build/bwrap'), git=str(assets / 'git/git'),
                        claude=str(assets / 'claude/node_modules/@anthropic-ai/claude-code-linux-x64/claude'))
        require(sha(selected['claude']) == HOST_SHA, 'pinned_actual_claude_digest_mismatch')
        identity = {'source': a.expected_commit, 'binaries': {role: sha(selected[role]) for role in
                    ('agentfw', 'git_launcher', 'sandbox_tests', 'python', 'node', 'bwrap_source', 'git', 'claude')},
                    'archives': {name: digest for name, (_, digest, _) in DOWNLOADS.items()},
                    'input_files': {name: sha(src / name) for name in guarded},
                    'wheel_count': len(wheels),
                    'wheelhouse_sha256': hashlib.sha256(json.dumps({path.name: sha(path) for path in sorted(wheels)},
                                        sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        (out / 'assets.json').write_text(json.dumps({'paths': selected, 'identity': identity}, indent=2) + '\n')
        (out / 'inputs-public.json').write_text(json.dumps(identity, indent=2) + '\n')
        record['status'] = 'prepared-not-qualified'
    except BaseException as error:
        record['status'] = 'failed'
        record['reason'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if isinstance(error, OSError):
            record['errno'] = error.errno
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
