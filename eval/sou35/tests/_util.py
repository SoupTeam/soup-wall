"""Shared helpers. Toy families only: they are artificial fixtures, never SOU-35 dataset families."""
import copy
import functools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TOY_DIR = ROOT / 'tests' / 'toy'


@functools.lru_cache(maxsize=None)
def _toys():
    from sou35 import families, generate
    decls = families.load_dir(TOY_DIR)
    records = generate.generate(decls, {})
    return decls, records


def toys():
    decls, records = _toys()
    return copy.deepcopy(decls), copy.deepcopy(records)


def find(records, family_suffix, variant):
    return next(r for r in records if r['family_id'].endswith(family_suffix) and r['template_id'].endswith('.' + variant))
