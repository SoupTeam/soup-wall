#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build four exact variants offline in caller-enforced read-only isolation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
for key in ('baseline', 'candidate', 'scratch'):
    p.add_argument('--' + key, type=Path, required=True)
a = p.parse_args()
builds = {}
for variant, source in (('instrumented-baseline', a.baseline), ('measured-candidate', a.candidate)):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source), 'immutable clean source required'
    builds[variant] = {}
    for profile in ('dev', 'release'):
        started = time.monotonic()
        with (a.scratch / f'build-{variant}-{profile}.log').open('wb') as log:
            subprocess.run(['cargo', 'build', '--locked', '--offline', '-p', 'agentfw', '--bin', 'agentfw',
                            '--profile', profile], cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
        binary = a.scratch / 'binaries' / f'{variant}-{profile}'
        target = a.scratch / 'target' / ('debug' if profile == 'dev' else 'release') / 'agentfw'
        shutil.copyfile(target, binary)
        binary.chmod(0o700)
        builds[variant][profile] = {'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   'source': commit, 'profile': profile,
                                   'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip()}
        (a.scratch / f'build-{variant}-{profile}-timing.json').write_text(json.dumps({'elapsed_seconds': time.monotonic() - started}))
        (a.scratch / 'builds.json').write_text(json.dumps(builds, indent=2) + '\n')
