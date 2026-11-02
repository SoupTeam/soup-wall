#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline candidate custody and publication admission. Never publishes anything."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile

from roadmap_support import Invalid, load_json, require, safe_file

MAX_JSON = 256 * 1024
MAX_ARTIFACT = 2 * 1024 ** 3
MAX_CANDIDATE = 4 * 1024 ** 3
SHA = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
NUMBER = re.compile(r'[1-9][0-9]{0,19}\Z')
TAG = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z')


def text_match(value, pattern, code):
    require(type(value) is str and len(value) <= 160 and pattern.fullmatch(value), code)
    return value


def names(tag):
    return [f'soup-wall-{tag}-{target}.{extension}' for target, extension in (
        ('x86_64-unknown-linux-gnu', 'tar.gz'), ('aarch64-apple-darwin', 'tar.gz'),
        ('x86_64-apple-darwin', 'tar.gz'), ('x86_64-pc-windows-msvc', 'zip'))] + [
        name + '.cdx.json' for name in ('soup-wall-core', 'soup-wall-agent', 'agentfw',
                                      'soup-wall-adapter', 'soup-wall-bench', 'llm-firewall')
        ] + ['soup-wall-image.tar']


def checksums(rows, tag):
    require(type(rows) is list and len(rows) == 11, 'exact_eleven_artifacts_required')
    found = {}
    for row in rows:
        require(type(row) is str and len(row) <= 300, 'invalid_checksum_record')
        match = re.fullmatch(r'([a-f0-9]{64})  ([a-zA-Z0-9_.-]+)', row)
        require(match is not None, 'invalid_checksum_grammar')
        digest, name = match.groups()
        require('..' not in name and name not in found, 'unsafe_or_duplicate_artifact')
        found[name] = digest
    require(set(found) == set(names(tag)), 'canonical_artifact_inventory_mismatch')
    return found


def record(path, *, attachment=False):
    value, _ = load_json(Path(path), MAX_JSON)
    required = {'decision', 'run_id', 'run_attempt', 'artifact_id', 'artifact_digest',
                'source_sha', 'checksums', 'evidence_ref', 'gates'}
    require(set(value) in (required, required | {'readiness'}), 'acceptance_record_fields')
    require(value['decision'] == 'approved', 'candidate_not_approved')
    require(type(value['gates']) is dict and set(value['gates']) == {'product', 'operator', 'license'}
            and all(v == 'passed' for v in value['gates'].values()), 'required_gate_not_passed')
    require(type(value['evidence_ref']) is str and 0 < len(value['evidence_ref']) <= 2048
            and all(32 <= ord(c) != 127 for c in value['evidence_ref']), 'reviewed_evidence_required')
    for key in ('run_id', 'run_attempt', 'artifact_id'):
        text_match(value[key], NUMBER, 'invalid_' + key)
    text_match(value['source_sha'], SHA, 'invalid_source_sha')
    text_match(value['artifact_digest'], DIGEST, 'invalid_artifact_digest')
    require(type(value['checksums']) is list and len(value['checksums']) == 11,
            'exact_eleven_artifacts_required')
    if attachment or 'readiness' in value:
        selected = value.get('readiness')
        require(type(selected) is dict and set(selected) == {
            'artifact_id', 'archive_sha256', 'index_sha256'}, 'readiness_attachment_required')
        text_match(selected['artifact_id'], NUMBER, 'invalid_readiness_artifact_id')
        for key in ('archive_sha256', 'index_sha256'):
            text_match(selected[key], DIGEST, 'invalid_readiness_' + key)
    return value


def api_identity(rec, path, tag, source):
    api, _ = load_json(Path(path), MAX_JSON)
    expected = {'workflow_path': '.github/workflows/release.yml', 'repository': 'SoupTeam/soup-wall',
                'prepare_job_status': 'success', 'status': 'completed', 'conclusion': 'success',
                'head_sha': source, 'head_branch': tag,
                **{k: rec[k] for k in ('run_id', 'run_attempt', 'artifact_id')}}
    require(set(api) == set(expected) | {'event'}, 'api_context_fields')
    require(api['event'] in ('push', 'workflow_dispatch'), 'untrusted_preparation_event')
    for key, value in expected.items():
        require(api[key] == value, 'api_' + key + '_mismatch')


def hash_artifact(path, limit=MAX_ARTIFACT):
    """Stream large release bytes with descriptor identity and size/change checks."""
    path = Path(path).absolute()
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not parent.is_symlink()
                and not getattr(info, 'st_file_attributes', 0) & 0x400, 'unsafe_artifact_parent')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not path.is_symlink()
            and not getattr(before, 'st_file_attributes', 0) & 0x400, 'unsafe_artifact_file')
    require(before.st_size <= limit, 'artifact_byte_limit')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
                 | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        # Windows path stat exposes creation time where fstat may expose last
        # metadata change. Compare the shared file identity/size/write time;
        # Unix additionally binds metadata change time. Expected SHA binds bytes.
        def identity(value):
            shared = (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            return shared if os.name == 'nt' else shared + (value.st_ctime_ns,)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and identity(opened) == identity(before), 'artifact_changed_during_open')
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            size += len(block)
            require(size <= limit, 'artifact_byte_limit')
            digest.update(block)
        require(size == before.st_size and identity(os.fstat(fd)) == identity(before)
                and identity(path.lstat()) == identity(before), 'artifact_changed_during_read')
        return digest.hexdigest(), size
    finally:
        os.close(fd)


def validate(record_path, manifest_path, tag, source, api_path, mode='full',
             index=None, bundle=None, approval=None, repo=None):
    text_match(tag, TAG, 'invalid_release_tag')
    text_match(source, SHA, 'invalid_expected_source')
    require(mode in ('full', 'api-only'), 'unsupported_validation_mode')
    rec = record(record_path, attachment=mode == 'full')
    require(rec['source_sha'] == source, 'record_source_mismatch')
    checksums(rec['checksums'], tag)
    api_identity(rec, api_path, tag, source)
    if mode == 'api-only':
        return {'format': 'sw-candidate-validation/1', 'status': 'identity-verified',
                'meaning': 'pre-download identity only; publication not admitted', 'blockers': []}
    require(all(v is not None for v in (index, bundle, approval, repo)), 'readiness_inputs_required')
    manifest_path = Path(manifest_path).absolute()
    man, manifest_digest = load_json(manifest_path, MAX_JSON)
    require(set(man) == {'tag', 'source_sha', 'run_attempt', 'checksums'}, 'manifest_fields')
    require(man['tag'] == tag and man['source_sha'] == source, 'manifest_source_or_tag_mismatch')
    require(man['run_attempt'] == rec['run_attempt'], 'manifest_attempt_mismatch')
    inventory = checksums(man['checksums'], tag)
    require(inventory == checksums(rec['checksums'], tag), 'approved_checksums_mismatch')
    total = 0
    for name, expected in inventory.items():
        actual, size = hash_artifact(manifest_path.parent / name)
        total += size
        require(total <= MAX_CANDIDATE, 'candidate_byte_limit')
        require(actual == expected, 'artifact_checksum_mismatch')
    index_raw = safe_file(Path(index), MAX_JSON)
    require(hashlib.sha256(index_raw).hexdigest() == rec['readiness']['index_sha256'],
            'approved_readiness_index_mismatch')
    import publication_readiness
    result = publication_readiness.verify(Path(index), Path(bundle), Path(repo), source,
        manifest_digest, Path(approval), artifacts=manifest_path.parent, manifest_path=manifest_path)
    require(result['status'] == 'admitted', 'readiness_refused:' + ','.join(result['blockers'][:16]))
    return {'format': 'sw-candidate-validation/1', 'status': 'admitted', 'blockers': [],
            'source': source, 'candidate_manifest_sha256': manifest_digest,
            'index_sha256': rec['readiness']['index_sha256'], 'artifact_count': 11}


def preflight_zip(stream, max_entries, archive_size):
    """Bound the central directory before zipfile allocates its ZipInfo list.

    Only ordinary single-disk ZIP is needed for these bounded attachments.
    ZIP64/split/self-extracting archives are deliberately unsupported.
    """
    stream.seek(max(0, archive_size - 65557))
    tail = stream.read(65557)
    base = archive_size - len(tail)
    offset = tail.rfind(b'PK\x05\x06')
    require(offset >= 0 and len(tail) - offset >= 22, 'zip_directory_missing')
    _, disk, directory_disk, disk_count, count, size, start, comment = struct.unpack(
        '<4s4H2IH', tail[offset:offset + 22])
    require(offset + 22 + comment == len(tail), 'zip_trailing_data_or_comment')
    require(disk == directory_disk == 0 and disk_count == count and 0 < count <= max_entries,
            'archive_member_limit')
    require(start != 0xffffffff and size != 0xffffffff and size <= max_entries * 4096
            and start + size == base + offset, 'zip_directory_byte_limit')
    stream.seek(start)
    directory = stream.read(size)
    require(len(directory) == size, 'zip_directory_truncated')
    position = 0
    for _ in range(count):
        header = directory[position:position + 46]
        require(len(header) == 46 and header[:4] == b'PK\x01\x02', 'invalid_zip_directory')
        name_size, extra_size, comment_size, member_disk = struct.unpack_from('<4H', header, 28)
        require(0 < name_size <= 240 and extra_size <= 2048 and comment_size <= 1024
                and member_disk == 0, 'zip_directory_member_bound')
        compressed, expanded = struct.unpack_from('<2I', header, 20)
        local_offset = struct.unpack_from('<I', header, 42)[0]
        require(compressed != 0xffffffff and expanded != 0xffffffff and local_offset < start,
                'unsupported_zip64_or_local_offset')
        position += 46 + name_size + extra_size + comment_size
        require(position <= size, 'zip_directory_truncated')
    require(position == size, 'zip_directory_count_mismatch')
    stream.seek(0)


def extract(archive_path, destination, expected, readiness=False):
    """Inspect every member before bounded extraction into a new owned directory."""
    text_match(expected, DIGEST, 'invalid_archive_digest')
    archive_path, destination = Path(archive_path), Path(destination).absolute()
    limit = 64 * 1024 ** 2 if readiness else MAX_CANDIDATE
    digest, _ = hash_artifact(archive_path, limit)
    require(digest == expected, 'archive_digest_mismatch')
    require(not destination.exists() and not destination.is_symlink(), 'fresh_extraction_directory_required')
    for parent in destination.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not parent.is_symlink()
                and not getattr(info, 'st_file_attributes', 0) & 0x400, 'unsafe_extraction_parent')
    # Never block on a substituted FIFO or follow a substituted symlink between
    # the first hash and parsing. Preflight and ZipFile share this held handle.
    before = archive_path.lstat()
    descriptor = os.open(archive_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as held:
        opened = os.fstat(held.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                'archive_changed_during_open')
        preflight_zip(held, 256 if readiness else 32, os.fstat(held.fileno()).st_size)
        _extract_members(held, destination, readiness)
    require(hash_artifact(archive_path, limit)[0] == expected, 'archive_changed_during_extraction')


def _extract_members(stream, destination, readiness):
    with zipfile.ZipFile(stream) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= (256 if readiness else 32), 'archive_member_limit')
        seen, total = set(), 0
        for member in infos:
            require(member.orig_filename == member.filename
                    and '\\' not in member.orig_filename, 'unsafe_archive_path')
            path = member.filename.rstrip('/') if member.is_dir() else member.filename
            require(re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,7}', path)
                    and len(path) <= 240 and all(p not in ('.', '..') for p in path.split('/')),
                    'unsafe_archive_path')
            require(path not in seen, 'duplicate_archive_path')
            seen.add(path)
            require(not member.flag_bits & 1 and stat.S_IFMT(member.external_attr >> 16)
                    in (0, stat.S_IFREG, stat.S_IFDIR), 'archive_link_or_encryption')
            require(member.file_size <= (64 * 1024 ** 2 if readiness else MAX_ARTIFACT),
                    'archive_member_byte_limit')
            total += member.file_size
            require(total <= (128 * 1024 ** 2 if readiness else MAX_CANDIDATE), 'archive_expansion_limit')
        files = {m.filename for m in infos if not m.is_dir()}
        require(all(not any(name.startswith(f + '/') for name in seen) for f in files),
                'archive_file_directory_conflict')
        destination.mkdir(mode=0o700)
        for member in infos:
            output = destination / member.filename
            if member.is_dir():
                output.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(member) as stream, output.open('xb') as target:
                os.chmod(output, 0o600)
                size = 0
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    size += len(block)
                    require(size <= member.file_size, 'archive_member_size_mismatch')
                    target.write(block)
                require(size == member.file_size, 'archive_member_size_mismatch')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv and argv[0] == 'record-metadata':
            require(len(argv) == 2, 'record_metadata_arguments')
            print(json.dumps(record(argv[1], attachment=True), sort_keys=True))
            return 0
        if argv and argv[0] == 'extract':
            parser = argparse.ArgumentParser(description=__doc__)
            parser.add_argument('command')
            parser.add_argument('archive')
            parser.add_argument('destination')
            parser.add_argument('--sha256', required=True)
            parser.add_argument('--readiness', action='store_true')
            args = parser.parse_args(argv)
            extract(args.archive, args.destination, args.sha256, args.readiness)
            print('Validated archive extracted into new private directory.')
            return 0
        require(5 <= len(argv) <= 10, 'candidate_validation_arguments')
        result = validate(*argv)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Invalid, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile,
            RuntimeError, RecursionError) as exc:
        code = str(exc) if isinstance(exc, Invalid) else 'invalid_or_unavailable_input'
        if not re.fullmatch(r'[a-zA-Z0-9_:,.-]{1,2048}', code):
            code = 'invalid_or_unavailable_input'
        print(json.dumps({'format': 'sw-candidate-validation/1', 'status': 'blocked', 'blockers': [code]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
