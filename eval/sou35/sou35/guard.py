"""Custody guard: SOU-35 must never load the consumed SOU-13/SOU-16 sealed material.

`sou13cp2.taxonomy` and `sou13cp2.catalog` read `cp2_sealed/restricted/test_families.json` at import time when
it exists. This guard checks only that the sealed directory is ABSENT (existence test, nothing is opened or
listed) and must run before any `sou13cp2` import."""
from pathlib import Path

SEALED_DIRS = ('cp2_sealed',)


class CustodyError(RuntimeError):
    pass


def sealed_paths_present(sou13_root):
    return [name for name in SEALED_DIRS if (Path(sou13_root) / name).exists()]


def check(sou13_root):
    present = sealed_paths_present(sou13_root)
    if present:
        raise CustodyError(f'refusing to run: consumed SOU-13 sealed material is present under {sou13_root} '
                           f'({present}); SOU-35 must run from a checkout without it')
