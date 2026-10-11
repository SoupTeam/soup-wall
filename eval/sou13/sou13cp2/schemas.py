"""Draft 2020-12 JSON Schema validation (jsonschema.Draft202012Validator; see requirements-cp2.txt).

  schema/cp2_case.schema.json        every CP2 record (CP1 lifted, CP1 revised, new candidates)
  schema/case.schema.cp1-fix1.json   the unchanged CP1 records, against a copy of the CP1 schema with only the
                                     Draft 2020-12 fix from the 2026-10-10 technical review ($defs/actions5
                                     declares its five properties). schema/case.schema.json (CP1) is not modified."""
import functools
import json

from . import ROOT

CP2_SCHEMA = 'schema/cp2_case.schema.json'
CP1_FIXED_SCHEMA = 'schema/case.schema.cp1-fix1.json'
CP1_ORIGINAL_SCHEMA = 'schema/case.schema.json'


@functools.lru_cache(maxsize=None)
def validator(rel):
    from jsonschema import Draft202012Validator  # required dependency for CP2 validation
    schema = json.loads((ROOT / rel).read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def errors(record, rel=CP2_SCHEMA):
    return [f"{record.get('id', '?')}: /{'/'.join(map(str, e.absolute_path))}: {e.message[:160]}"
            for e in sorted(validator(rel).iter_errors(record), key=lambda e: list(map(str, e.absolute_path)))]


def validate_records(cp2_records, raw_cp1_records):
    """Errors for CP2 records against the CP2 schema and raw CP1 records against the fixed CP1 schema."""
    out = []
    for r in cp2_records:
        out += errors(r, CP2_SCHEMA)
    for r in raw_cp1_records:
        out += errors(r, CP1_FIXED_SCHEMA)
    return out
