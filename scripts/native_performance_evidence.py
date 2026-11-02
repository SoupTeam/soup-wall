#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate, or check byte for byte, the SOU-203 evidence bundle from retained SOU-141 reports.

Every case reads the committed SOU-141 files unchanged. The broken-copy control mutates one
trial of a private copy (outside the repository) to show the validation gate rejecting it.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_performance', ROOT / 'scripts/native_performance.py')
NP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NP)
SOU141 = 'docs/operations/evidence/sou-141/'
SOU124 = 'docs/operations/evidence/sou-124/'
SOU106 = 'docs/operations/evidence/sou106/'
BUNDLE = ROOT / 'docs/operations/evidence/sou-203'
FINAL = ['--baseline', SOU141 + 'native-final-ask-series-summary.json',
         '--baseline-manifest', SOU141 + 'native-final-ask-series-manifest.json']
CASES = {
    'identity-control': (FINAL + ['--candidate', SOU141 + 'native-final-ask-series-summary.json',
                                  '--candidate-manifest', SOU141 + 'native-final-ask-series-manifest.json',
                                  '--paired'], 1),
    'historical-cross-revision': (['--baseline', SOU141 + 'native-ask-series-summary.json',
                                   '--baseline-manifest', SOU141 + 'native-ask-series-manifest.json',
                                   '--candidate', SOU141 + 'native-final-ask-series-summary.json',
                                   '--candidate-manifest', SOU141 + 'native-final-ask-series-manifest.json'], 1),
    'native-vs-wsl2': (FINAL + ['--candidate', SOU141 + 'wsl2-ask-series.json'], 1),
    'ask-qualification-identity-control': (['--baseline', SOU124 + 'native-attempt2-baseline.json',
                                            '--candidate', SOU124 + 'native-attempt2-baseline.json', '--paired'], 1),
    'ask-qualification-vs-series': (['--baseline', SOU124 + 'native-attempt2-baseline.json',
                                     '--candidate', SOU141 + 'native-final-ask-series-summary.json',
                                     '--candidate-manifest', SOU141 + 'native-final-ask-series-manifest.json'], 1),
    'installed-host-identity-control': (['--baseline', SOU106 + 'measured-report.json',
                                         '--candidate', SOU106 + 'measured-report.json', '--paired'], 1),
    'installed-host-historical': (['--baseline', SOU106 + 'attempt-2.json',
                                   '--candidate', SOU106 + 'measured-report.json'], 1),
    'installed-host-vs-ask-series': (['--baseline', SOU106 + 'measured-report.json',
                                      '--candidate', SOU141 + 'native-final-ask-series-summary.json',
                                      '--candidate-manifest', SOU141 + 'native-final-ask-series-manifest.json'], 1),
}


def broken_copy(directory, input_root=ROOT):
    """Deliberately broken input: one genuine trial lowered by 100 ms, published aggregates left as they were.
    Written as explicit LF bytes so the private copy is identical on every platform."""
    value = json.loads((Path(input_root) / SOU141 / 'native-final-ask-series-summary.json').read_bytes())
    value['runs'][2]['summary']['trials']['git']['continuation_ms_by_trial'][5]['decision_to_result_ms'] -= 100
    path = Path(directory) / 'broken-final-ask-series-summary.json'
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    return str(path)


def generate(out_dir, observation_dir, input_root=ROOT):
    """Canonical (checkout-independent) bundle into out_dir; this checkout's read observations into
    observation_dir, one checkout-observation.json per case. Inputs are read from input_root, named
    relative to it, and verified against the repository's git objects."""
    out_dir, observation_dir, input_root = Path(out_dir), Path(observation_dir), Path(input_root)
    codes = {}
    with tempfile.TemporaryDirectory(prefix='sou203-broken-') as private:
        cases = dict(CASES)
        broken = broken_copy(private, input_root)
        cases['broken-copy-control'] = (['--baseline', broken, '--candidate', broken], 2)
        for name, (words, expected) in sorted(cases.items()):
            code = NP.main([*(str(input_root / w) if w.startswith((SOU141, SOU124, SOU106)) else w for w in words),
                            '--repository', str(ROOT), '--name-root', str(input_root),
                            '--checkout-observation-out', str(observation_dir / name),
                            '--out-dir', str(out_dir / name)])
            codes[name] = code
            if code != expected:
                raise SystemExit(f'{name}: exit {code}, expected {expected}')
    return codes


def check(input_root=ROOT):
    """Regenerate privately from input_root and compare the canonical files with the committed bundle."""
    with tempfile.TemporaryDirectory(prefix='sou203-check-') as tmp:
        generate(Path(tmp) / 'bundle', Path(tmp) / 'observation', input_root)
        fresh = {p.relative_to(Path(tmp) / 'bundle').as_posix(): p.read_bytes()
                 for p in sorted((Path(tmp) / 'bundle').rglob('*')) if p.is_file()}
    committed = {p.relative_to(BUNDLE).as_posix(): p.read_bytes() for p in sorted(BUNDLE.rglob('*'))
                 if p.is_file() and p.name != 'README.md'}
    differing = sorted(k for k in set(fresh) | set(committed) if fresh.get(k) != committed.get(k))
    print(json.dumps({'status': 'reproduced' if not differing else 'differs', 'files': len(fresh),
                      'differing': differing}))
    return 0 if not differing else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--out-dir', type=Path, help='new or empty directory for the regenerated canonical bundle')
    group.add_argument('--check', action='store_true', help='regenerate privately and compare to the bundle')
    parser.add_argument('--observation-dir', type=Path,
                        help='with --out-dir: new or empty directory for the read observations of this checkout '
                             '(never part of the committed bundle)')
    args = parser.parse_args(argv)
    if args.check:
        return check()
    if args.observation_dir is None:
        parser.error('--out-dir needs --observation-dir (checkout observations are kept out of the bundle)')
    print(json.dumps({'cases': generate(args.out_dir, args.observation_dir)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
