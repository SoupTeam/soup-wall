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
}


def broken_copy(directory):
    """Deliberately broken input: one genuine trial lowered by 100 ms, published aggregates left as they were."""
    value = json.loads((ROOT / SOU141 / 'native-final-ask-series-summary.json').read_text())
    value['runs'][2]['summary']['trials']['git']['continuation_ms_by_trial'][5]['decision_to_result_ms'] -= 100
    path = Path(directory) / 'broken-final-ask-series-summary.json'
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    return str(path)


def generate(out_dir):
    out_dir = Path(out_dir)
    codes = {}
    with tempfile.TemporaryDirectory(prefix='sou203-broken-') as private:
        cases = dict(CASES)
        cases['broken-copy-control'] = (['--baseline', broken_copy(private), '--candidate', broken_copy(private)], 2)
        for name, (words, expected) in sorted(cases.items()):
            code = NP.main([*(str(ROOT / w) if w.startswith((SOU141, SOU124)) else w for w in words),
                            '--repository', str(ROOT), '--out-dir', str(out_dir / name)])
            codes[name] = code
            if code != expected:
                raise SystemExit(f'{name}: exit {code}, expected {expected}')
    return codes


def check():
    with tempfile.TemporaryDirectory(prefix='sou203-check-') as tmp:
        generate(tmp)
        fresh = {p.relative_to(tmp).as_posix(): p.read_bytes() for p in sorted(Path(tmp).rglob('*')) if p.is_file()}
    committed = {p.relative_to(BUNDLE).as_posix(): p.read_bytes() for p in sorted(BUNDLE.rglob('*'))
                 if p.is_file() and p.name != 'README.md'}
    differing = sorted(k for k in set(fresh) | set(committed) if fresh.get(k) != committed.get(k))
    print(json.dumps({'status': 'reproduced' if not differing else 'differs', 'files': len(fresh),
                      'differing': differing}))
    return 0 if not differing else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--out-dir', type=Path, help='new or empty directory for the regenerated bundle')
    group.add_argument('--check', action='store_true', help='regenerate privately and compare to the bundle')
    args = parser.parse_args(argv)
    if args.check:
        return check()
    print(json.dumps({'cases': generate(args.out_dir)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
