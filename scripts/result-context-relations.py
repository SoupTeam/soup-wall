#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate source-bound contextual relations, without granting release authority.

This verifies the integrity of proposed discourse annotations, not their semantic
truth. No producer, model, quotation label or annotation can authorize Allow.
"""
from collections import deque
import hashlib

ROLES = {'other', 'mention', 'description', 'adoption', 'action_request', 'unresolved'}


def source_hash(channels):
    if len(channels) > 1024:
        raise ValueError('channel_limit')
    digest = hashlib.sha256(b'sw-context-relations/1\0')
    total = 0
    for channel in channels:
        raw = channel.encode('utf-8', errors='strict')
        total += len(raw)
        if total > 8*1024*1024:
            raise ValueError('source_limit')
        digest.update(len(raw).to_bytes(8, 'little')); digest.update(raw)
    return digest.hexdigest()


def check(channels, proposal):
    if set(proposal) != {'source_sha256', 'scopes', 'relations'}:
        raise ValueError('unsupported_proposal_fields')
    if proposal['source_sha256'] != source_hash(channels):
        raise ValueError('source_binding')
    scopes, relations = proposal['scopes'], proposal['relations']
    if not isinstance(scopes,list) or not isinstance(relations,list):
        raise ValueError('unsupported_relation_arrays')
    if len(scopes) > 65536 or len(relations) > 65536:
        raise ValueError('relation_limit')
    raw_channels = [c.encode('utf-8') for c in channels]
    inventory = [[] for _ in channels]
    for i, scope in enumerate(scopes):
        if set(scope) != {'channel', 'start', 'end', 'role'} or scope['role'] not in ROLES:
            raise ValueError('unsupported_scope')
        c, a, b = scope['channel'], scope['start'], scope['end']
        if any(type(v) is not int for v in (c, a, b)) or not 0 <= c < len(channels):
            raise ValueError('invalid_source_index')
        raw = raw_channels[c]
        if not 0 <= a < b <= len(raw):
            raise ValueError('invalid_source_range')
        if (a < len(raw) and raw[a] & 0xc0 == 0x80) or (b < len(raw) and raw[b] & 0xc0 == 0x80):
            raise ValueError('invalid_utf8_boundary')
        inventory[c].append((a, b, i))
    # Every byte, including remote scope/padding, must be represented. Empty
    # channels are retained by the source hash and require no synthetic ranges.
    for c, spans in enumerate(inventory):
        cursor = 0
        for a, b, _ in sorted(spans):
            if a != cursor:
                raise ValueError('coverage_gap_or_overlap')
            cursor = b
        if cursor != len(raw_channels[c]):
            raise ValueError('coverage_incomplete')
    adjacency = [[] for _ in scopes]
    indegree = [0]*len(scopes)
    seen = set()
    for edge in relations:
        if set(edge) != {'kind', 'from', 'to'}:
            raise ValueError('unsupported_relation')
        kind, a, b = edge['kind'], edge['from'], edge['to']
        if kind not in ('describes','adopts'):
            raise ValueError('unsupported_relation_kind')
        if type(a) is not int or type(b) is not int or not 0 <= a < len(scopes) or not 0 <= b < len(scopes) or a == b:
            raise ValueError('invalid_relation_index')
        if (kind, a, b) in seen:
            raise ValueError('duplicate_relation')
        seen.add((kind, a, b))
        roles = scopes[a]['role'], scopes[b]['role']
        if kind == 'describes':
            valid = roles == ('description', 'mention')
        elif kind == 'adopts':
            valid = roles[0] in ('adoption', 'action_request') and roles[1] in ('mention', 'action_request')
        else:
            valid = False
        if not valid:
            raise ValueError('unsupported_relation_roles')
        adjacency[a].append(b); indegree[b] += 1
    pending = deque(i for i, count in enumerate(indegree) if count == 0)
    visited = 0
    while pending:
        i = pending.popleft(); visited += 1
        for target in adjacency[i]:
            indegree[target] -= 1
            if indegree[target] == 0: pending.append(target)
    if visited != len(scopes):
        raise ValueError('relation_cycle')
    observation = 'unresolved'
    if any(s['role'] in ('adoption', 'action_request') for s in scopes):
        observation = 'instruction_candidate'
    elif any(e['kind'] == 'describes' for e in relations) and not any(s['role'] == 'unresolved' for s in scopes):
        observation = 'mention_candidate'
    return {'source_bound': True, 'coverage_complete': True,
            'relation_observation': observation, 'origin': 'untrusted_mcp',
            'semantic_validation': 'not_performed', 'enforcement': 'unresolved',
            'production_authority': False}
