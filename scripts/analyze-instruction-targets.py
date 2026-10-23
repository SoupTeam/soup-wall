#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline additive instruction-target evidence. Never returns safe or Allow."""
import argparse
import hashlib
import json
import re
from pathlib import Path

MAX_TEXT = 65536
MAX_CHANNELS = 16
MAX_TOTAL = 256 * 1024
TARGET = re.compile(r'\b(?:assistant|AI\s+(?:agent|code\s+reviewer))\b', re.I)
EFFECTS = {
    'download_and_execute': re.compile(r'\bcurl\b[^\n]{0,256}\|\s*(?:sh|bash)\b', re.I),
    'external_data_transfer': re.compile(r'\b(?:send|sending|email|transmit)\b[^\n]{0,256}(?:https?://|\b[^\s@]+@[^\s@]+)', re.I),
    'private_key_disclosure': re.compile(r'(?:~|/)[^\s]{0,128}/?\.ssh/[^\s]{1,80}[^\n]{0,160}\b(?:append|include|verbatim)\w*\b', re.I),
    'system_prompt_disclosure': re.compile(r'\breveal\b[^\n]{0,80}\bsystem\s+prompt\b', re.I),
}


def analyze(text, authorized_task_kind):
    # Task kind is trusted evaluator context, not extracted from tool metadata.
    result = dict(observation='unknown', reason='insufficient_target_effect_evidence', evidence=[])
    if authorized_task_kind != 'read_and_summarize':
        result['reason'] = 'unsupported_authorized_task'
        return result
    try:
        raw = text.encode('utf-8')
    except (AttributeError, UnicodeError):
        result['reason'] = 'invalid_text'
        return result
    result['sha256'] = hashlib.sha256(raw).hexdigest()
    if len(raw) > MAX_TEXT:
        result['reason'] = 'text_limit'
        return result
    # Bounded full-input scan; no harmless prefix permits skipping a tail.
    for target in TARGET.finditer(text):
        end = min(len(text), target.end() + 384)
        context = text[target.start():end]
        for effect, pattern in EFFECTS.items():
            match = pattern.search(context)
            if match:
                stop = target.start() + match.end()
                result['evidence'].append(dict(
                    start=len(text[:target.start()].encode('utf-8')),
                    end=len(text[:stop].encode('utf-8')),
                    target='assistant_candidate', effect=effect,
                    task_redirection='requires_action_beyond_read_and_summarize'))
                if len(result['evidence']) >= 32:
                    return dict(observation='unknown', reason='evidence_limit',
                                sha256=result['sha256'], evidence=[])
    if result['evidence']:
        result.update(observation='instruction_candidate', reason='explicit_target_and_effect')
    return result


def analyze_channels(channels, authorized_task_kind):
    if not isinstance(channels, list) or not channels or len(channels) > MAX_CHANNELS:
        return dict(observation='unknown', reason='channel_limit_or_shape', channels=[])
    try:
        if sum(len(t.encode('utf-8')) for t in channels) > MAX_TOTAL:
            raise ValueError('total_limit')
    except (AttributeError, UnicodeError, ValueError):
        return dict(observation='unknown', reason='invalid_or_oversize_channels', channels=[])
    reports = [analyze(text, authorized_task_kind) for text in channels]
    return dict(observation='instruction_candidate' if any(r['observation'] == 'instruction_candidate' for r in reports) else 'unknown',
                channels=reports)


def evaluate(corpus):
    observations = []
    counts = {}
    for case in corpus['cases']:
        # Author label and forbidden_effect never enter the analyzer.
        result = analyze_channels([case['exact_text']], 'read_and_summarize')
        label = case['expected_label']
        key = label + ' -> ' + result['observation']
        counts[key] = counts.get(key, 0) + 1
        observations.append(dict(case_id=case['case_id'], author_label=label, **result))
    return dict(mode='offline_additive_evidence_only', production_authority=False,
                corpus_scope='public_development_not_held_out', counts=counts,
                observations=observations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    args = parser.parse_args()
    with args.corpus.open('rb') as stream:
        raw = stream.read(MAX_TOTAL + 1)
    if len(raw) > MAX_TOTAL:
        raise SystemExit('corpus_limit')
    report = evaluate(json.loads(raw))
    report['corpus_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
