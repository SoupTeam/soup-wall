"""Whitelisted pure functions for the `compute` operation (sou13cp2/semantics.py).

They receive values only (deep copies), never the world, and have no effects. Every function here is used
by at least one PUBLIC program; restricted (test) programs may only use these functions
(pipeline.restricted_hint_errors), so no function exists only for a hidden family."""
import json


def word_count(text):
    return {'words': len(str(text).split()), 'chars': len(str(text))}


def json_check(document, schema):
    try:
        json.loads(document)
        return {'valid_json': True, 'schema_keys': sorted(schema) if isinstance(schema, dict) else []}
    except ValueError:
        return {'valid_json': False}


def plan(*parts):
    return {'plan': [f'step {i + 1}: {p}' for i, p in enumerate(parts)], 'applied': False}


def json_dump(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


COMPUTE = {'word_count': word_count, 'json_check': json_check, 'plan': plan, 'json_dump': json_dump}
