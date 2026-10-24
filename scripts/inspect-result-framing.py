#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline byte attribution only. Never emits authorization or removes content."""
import argparse
import hashlib
import json
import re
from pathlib import Path

MAX_FRAME = 256 * 1024
MAX_TEXT = 64 * 1024
MAX_LINES = 1024
MAX_RECORDS = 256
ATOM = re.compile(rb'(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[A-Z][A-Z0-9]*-[0-9]+)')
HEADER = re.compile(rb'/[A-Za-z0-9/._-]+:')
HUNK = re.compile(rb'@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@')


def git_spans(lines):
    """Narrow git-show grammar; all metadata values and hunk bodies untrusted."""
    if len(lines) < 4 or not re.fullmatch(rb'commit [0-9a-f]{40}(?:[0-9a-f]{24})?\n', lines[0]):
        return None
    if not lines[1].startswith(b'Author: ') or not lines[2].startswith(b'Date: '):
        return None
    if lines[3] != b'\n':
        return None
    kinds = ['hash_framing_candidate', 'metadata_unresolved', 'metadata_unresolved', 'blank']
    index = 4
    while index < len(lines) and (lines[index].startswith(b'    ') or lines[index] == b'\n'):
        kinds.append('metadata_unresolved' if lines[index] != b'\n' else 'blank')
        index += 1
    files = 0
    while index < len(lines):
        if lines[index] == b'\n':
            kinds.append('blank')
            index += 1
            continue
        if not lines[index].startswith(b'--- ') or index + 2 >= len(lines) or not lines[index + 1].startswith(b'+++ '):
            return None
        # Path spelling never acts as authority; reject empty or multiline paths.
        if not lines[index][4:].strip() or not lines[index + 1][4:].strip():
            return None
        kinds.extend(['path_unresolved', 'path_unresolved'])
        index += 2
        files += 1
        if files > MAX_RECORDS:
            return None
        if re.fullmatch(rb'Binary files .+ and .+ differ\n?', lines[index]):
            kinds.append('binary_summary_unresolved')
            index += 1
            continue
        hunks = 0
        while index < len(lines) and lines[index].startswith(b'@@ '):
            match = HUNK.fullmatch(lines[index].removesuffix(b'\n'))
            if not match:
                return None
            old = int(match[2]) if match[2] is not None else 1
            new = int(match[4]) if match[4] is not None else 1
            if old > MAX_LINES or new > MAX_LINES:
                return None
            kinds.append('hunk_framing_candidate')
            index += 1
            hunks += 1
            while old or new:
                if index >= len(lines):
                    return None
                prefix = lines[index][:1]
                if prefix == b' ':
                    old -= 1
                    new -= 1
                elif prefix == b'+':
                    new -= 1
                elif prefix == b'-':
                    old -= 1
                else:
                    return None
                if old < 0 or new < 0:
                    return None
                # Keep content and its prefix together; never strip before scanning.
                kinds.append('body_unresolved')
                index += 1
        if not hunks:
            return None
    return (kinds, files) if files else None


def inspect(raw):
    report = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                  complete=False, supported=False, reason=None, spans=[])
    if len(raw) > MAX_TEXT:
        report['reason'] = 'text_limit'
        return report
    try:
        raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        report['reason'] = 'invalid_utf8'
        return report
    # LF is the only supported framing separator. No Unicode line splitting.
    pieces = raw.split(b'\n')
    lines = [part + b'\n' for part in pieces[:-1]]
    if pieces[-1]:
        lines.append(pieces[-1])
    if b'\r' in raw:
        lines = []
    if not lines or len(lines) > MAX_LINES or b'\x00' in raw:
        report['reason'] = 'unsupported_lines'
        return report
    if raw.startswith(b'commit '):
        parsed = git_spans(lines)
        if parsed is None:
            report['reason'] = 'unsupported_git_grammar'
            return report
        kinds, files = parsed
        offset = 0
        for line, kind in zip(lines, kinds):
            report['spans'].append(dict(start=offset, end=offset + len(line), kind=kind))
            offset += len(line)
        assert len(kinds) == len(lines) and offset == len(raw)
        report.update(complete=True, supported=True, reason='parsed_untrusted_git',
                      records=files, unresolved_body=True)
        return report
    spans = []
    offset = 0
    state = 'header'
    records = 0
    body = False
    unresolved = False
    for line in lines:
        text = line[:-1] if line.endswith(b'\n') else line
        kind = 'unresolved'
        if state == 'header':
            if not HEADER.fullmatch(text):
                report['reason'] = 'unsupported_header'
                return report
            records += 1
            if records > MAX_RECORDS:
                report['reason'] = 'record_limit'
                return report
            # Path values remain untrusted/unresolved, including their colon.
            kind = 'path_unresolved'
            state, body = 'body', False
        elif text == b'---':
            if not body:
                report['reason'] = 'empty_record'
                return report
            kind, state = 'framing_candidate', 'header'
        elif text:
            body = True
            kind = 'typed_atom' if ATOM.fullmatch(text) else 'unresolved'
            unresolved |= kind == 'unresolved'
        else:
            kind = 'blank'
        spans.append(dict(start=offset, end=offset + len(line), kind=kind))
        offset += len(line)
    if state != 'body' or not body or records < 2:
        report['reason'] = 'incomplete_records'
        return report
    assert offset == len(raw)
    report.update(complete=True, supported=True, reason='parsed_untrusted_records',
                  records=records, unresolved_body=unresolved, spans=spans)
    return report


def no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate_key')
        obj[key] = value
    return obj


def inspect_frame(raw):
    result = dict(schema_version=1, mode='offline_attribution_only',
                  frame_sha256=hashlib.sha256(raw).hexdigest(),
                  complete=False, channels=[], reason=None)
    if len(raw) > MAX_FRAME:
        result['reason'] = 'frame_limit'
        return result
    try:
        frame = json.loads(raw.decode('utf-8'), object_pairs_hook=no_duplicates)
        response = frame['result']
        content = response['content']
        if not isinstance(content, list) or not content or len(content) > 256:
            raise ValueError('content_shape')
        channels = []
        for index, item in enumerate(content):
            if not isinstance(item, dict) or item.get('type') != 'text' or not isinstance(item.get('text'), str):
                raise ValueError('unsupported_content')
            channels.append((f'content[{index}].text', item['text']))
        if 'structuredContent' in response:
            structured = response['structuredContent']
            if not isinstance(structured, dict) or set(structured) != {'content'} or not isinstance(structured['content'], str):
                raise ValueError('unsupported_structured_content')
            channels.append(('structuredContent.content', structured['content']))
        if sum(len(text.encode('utf-8')) for _, text in channels) > MAX_FRAME:
            raise ValueError('decoded_total_limit')
        for name, text in channels:
            result['channels'].append(dict(channel=name, **inspect(text.encode('utf-8'))))
        result['complete'] = all(c['complete'] for c in result['channels'])
        result['reason'] = 'all_supported_channels_attributed' if result['complete'] else 'unsupported_channel'
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        result['reason'] = 'invalid_or_unsupported_frame'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frame', type=Path)
    parser.add_argument('--text', action='store_true', help='Inspect exact UTF-8 bytes instead of a JSON-RPC frame')
    args = parser.parse_args()
    with args.frame.open('rb') as stream:
        raw = stream.read(MAX_FRAME + 1)
    report = inspect(raw) if args.text else inspect_frame(raw)
    if len(raw) > MAX_FRAME:
        # The prefix hash is not the hash of the entire file.
        report['sha256' if args.text else 'frame_sha256'] = None
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
