#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build four exact variants offline in caller-enforced read-only isolation."""
import argparse
import hashlib
import json
import os
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
    # Separate output roots avoid Cargo mtime freshness aliasing between two
    # simultaneously checked-out workspaces with the same package versions.
    target_root = a.scratch / 'target' / variant
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target_root))
    for profile in ('dev', 'release'):
        started = time.monotonic()
        with (a.scratch / f'build-{variant}-{profile}.log').open('wb') as log:
            subprocess.run(['cargo', 'build', '--locked', '--offline', '-p', 'agentfw', '--bin', 'agentfw',
                            '--profile', profile, '--manifest-path', str(source / 'Cargo.toml')],
                           cwd=source, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        binary = a.scratch / 'binaries' / f'{variant}-{profile}'
        target = target_root / ('debug' if profile == 'dev' else 'release') / 'agentfw'
        shutil.copyfile(target, binary)
        binary.chmod(0o700)
        builds[variant][profile] = {'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   'source': commit, 'profile': profile,
                                   'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip()}
        (a.scratch / f'build-{variant}-{profile}-timing.json').write_text(json.dumps({'elapsed_seconds': time.monotonic() - started}))
        (a.scratch / 'builds.json').write_text(json.dumps(builds, indent=2) + '\n')

assert builds['instrumented-baseline']['dev']['binary_sha256'] != builds['measured-candidate']['dev']['binary_sha256'], 'independent dev variants unexpectedly identical'
