"""Shared helpers for CP2 tests. Records built here are in-memory TEST MUTANTS, never dataset cases."""
import copy
import functools

from sou13.build import definition_hash
from sou13.hashing import sha
from sou13cp2 import ROOT
from sou13cp2.records import cp1_view_records
from sou13cp2.splits import build_manifest
from sou13cp2.taxonomy import families


@functools.lru_cache(maxsize=None)
def _base():
    fams = families()
    manifest = build_manifest(fams)
    return fams, manifest, cp1_view_records(ROOT, fams, manifest)


def base():
    fams, manifest, records = _base()
    return copy.deepcopy(fams), copy.deepcopy(manifest), copy.deepcopy(records)


def by_id(records, rid):
    return next(r for r in records if r['id'] == rid)


def mutant(record, new_id, *, split=None, family=None, manifest=None, input_changes=None, template_id=None):
    """Copy a record under a new id; optionally move it to another family/split and edit its input.
    Hashes are recomputed so that only the intended defect remains."""
    r = copy.deepcopy(record)
    r['id'] = new_id
    if input_changes:
        r['input'].update(input_changes)
        r['hashes'] = {'input_sha256': sha(r['input']), 'arguments_sha256': sha(r['input']['raw_arguments']),
                       'definition_sha256': definition_hash(r['input'])}
    if family is not None:
        r['family_id'] = family
        r['alias_group_id'] = 'ag.' + family[len('fam.'):]
        r['leakage_group_id'] = manifest['family_group'][family]
        r['split'] = manifest['family_split'][family]
    if template_id is not None:
        r['template_id'] = template_id
    if split is not None:
        r['split'] = split
    return r


def family_in(manifest, split, behavior_prefix=''):
    return next(f for f, s in sorted(manifest['family_split'].items())
                if s == split and f.startswith('fam.' + behavior_prefix))
