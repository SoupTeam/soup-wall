# SPDX-License-Identifier: Apache-2.0
"""Stage and check the explicit offline documentation in public binary archives.

This is an offline structure/integrity check, not release admission or native
binary qualification. It never downloads, executes packaged programs or publishes.
"""

import argparse
import gzip
import hashlib
import html
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote, unquote, urlsplit
import zipfile

import check_docs


FORMAT = "sw-release-documentation/1"
MANIFEST = "release-docs.json"
CONTRACT = "deploy/release-docs-manifest.json"
INDEX = "docs/RELEASE_ARCHIVE.md"
TARGETS = (
    "x86_64-unknown-linux-gnu", "aarch64-apple-darwin",
    "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
)
MAX_FILES = 256
MAX_DOC = 2 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
REPOSITORY = "https://github.com/SoupTeam/soup-wall"
BASE = ("firewall.yaml", "policies/default.yaml", "LICENSE", "NOTICE",
        "third-party/kryptering/LICENSE")
PRIVATE = (".git", ".codex", ".checkpoint", "local-notes", "evidence", "__pycache__")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def contract_digest(contract):
    """Bind contract content independently of clean-checkout text EOL style."""
    return digest(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def load_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def safe_name(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("invalid path length/type")
    if "\\" in value or value.startswith("/") or any(ord(c) < 32 for c in value):
        raise ValueError("absolute, backslash or control-character path")
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", "..") or any(c in part for c in ':<>|?*') or part[-1:] in (".", " "):
            raise ValueError("unsafe path component")
        if part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}:
            raise ValueError("reserved Windows pathname")
    return value


def read_file(root, name, maximum=MAX_DOC):
    safe_name(name)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or getattr(root_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ValueError("linked or unsupported root directory")
    path = root
    for part in name.split("/"):
        if not path.is_dir() or part not in os.listdir(path):
            raise ValueError(f"missing or incorrectly cased path: {name}")
        path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError(f"linked path: {name}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_nlink != 1:
        raise ValueError(f"unsupported file/size/link count: {name}")
    return path.read_bytes()


def source_bytes(root, name):
    data = read_file(root, name)
    # Text input identities use canonical LF, independent of Git autocrlf.
    return data.replace(b"\r\n", b"\n") if name.endswith((".md", ".svg")) else data


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.PIPE).decode("utf-8").strip()


def source_names(root):
    return set(git(root, "ls-files", "-z").split("\0")) - {""}


def source_target(root, source, original, tracked):
    parts = urlsplit(html.unescape(original))
    if "\\" in unquote(parts.path) or parts.query:
        raise ValueError(f"unsupported local link: {source}: {original}")
    path = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(parts.path))) if parts.path else source
    if path == ".":
        return path, parts.fragment, True
    safe_name(path)
    directory = path not in tracked and any(p.startswith(path + "/") for p in tracked)
    if path not in tracked and not directory:
        raise ValueError(f"untracked or incorrectly cased source link: {source}: {original}")
    if parts.fragment:
        if directory or not path.endswith(".md"):
            raise ValueError("fragments require Markdown files")
        anchors = check_docs.heading_anchors(list(check_docs.markdown_lines(source_bytes(root, path).decode("utf-8"))))
        if unquote(parts.fragment) not in anchors:
            raise ValueError(f"broken source anchor: {source}: {original}")
    return path, parts.fragment, directory


def link_spans(line):
    """Destinations in the same inline Markdown/HTML image subset as check_docs."""
    masked = check_docs.INLINE_CODE.sub(lambda match: " " * len(match[0]), line)
    position, brackets = 0, []
    while position < len(masked):
        if masked[position] == "\\":
            position += 2
            continue
        if masked[position] == "[":
            brackets.append(position)
        elif masked[position] == "]" and brackets:
            opening = brackets.pop()
            if masked[position + 1:position + 2] == "(":
                start = position + 2
                while start < len(masked) and masked[start].isspace():
                    start += 1
                if start < len(masked) and masked[start] == "<":
                    start += 1
                    end = masked.find(">", start)
                else:
                    end, depth = start, 0
                    while end < len(masked):
                        c = masked[end]
                        if c == "\\":
                            end += 2
                            continue
                        if c == ")" and depth == 0 or c.isspace():
                            break
                        depth += (c == "(") - (c == ")")
                        end += 1
                parsed = check_docs.destination(masked, position + 2)
                if parsed and end >= start:
                    yield start, end, parsed[0], opening > 0 and masked[opening - 1] == "!"
                    position = parsed[1]
                    continue
        position += 1
    for match in re.finditer(r"<img\b[^>]*\bsrc\s*=\s*([\"'])(.*?)\1", masked, re.I):
        yield match.start(2), match.end(2), html.unescape(match[2]), True


def classify_url(original):
    parts = urlsplit(original)
    if parts.scheme:
        if parts.scheme.lower() not in {"http", "https", "mailto"}:
            raise ValueError("unsupported link scheme")
        return "external"
    if parts.netloc or original.startswith("//"):
        raise ValueError("protocol-relative links are unsupported")
    return "local"


def render(root, name, data, bundled, online, tracked, commit):
    text = data.decode("utf-8")
    lines = text.splitlines(keepends=True)
    usable = {n for n, _ in check_docs.markdown_lines(text)}
    for number, line in enumerate(lines, 1):
        if number not in usable:
            continue
        visible = check_docs.INLINE_CODE.sub(lambda match: " " * len(match[0]), line)
        if re.search(r"\[[^\]]+\]\s*\[[^\]]*\]|^\s*\[[^\]]+\]:|<\s*(?:a|iframe|script|link)\b", visible, re.I):
            raise ValueError(f"unsupported documentation link syntax: {name}:{number}")
        replacements = []
        for start, end, original, image in link_spans(line):
            if classify_url(original) == "external":
                continue
            target, fragment, directory = source_target(root, name, original, tracked)
            if target == "vendor/kryptering/LICENSE":
                target = "third-party/kryptering/LICENSE"
            if target in bundled:
                replacement = posixpath.relpath(target, posixpath.dirname(name) or ".")
                if target == name and fragment:
                    replacement = ""
                replacement += "#" + fragment if fragment else ""
            else:
                if image or target not in online:
                    raise ValueError(f"undeclared offline omission: {name}: {original}")
                kind = "tree" if directory else "blob"
                replacement = f"{REPOSITORY}/{kind}/{commit}/" + quote(target if target != "." else "", safe="/")
                replacement += "#" + quote(unquote(fragment), safe="-_") if fragment else ""
            replacements.append((start, end, replacement))
        for start, end, replacement in sorted(replacements, reverse=True):
            line = line[:start] + replacement + line[end:]
        lines[number - 1] = line
    prefix = ("> **Binary archive copy.** Start with the offline [archive guide](" +
              posixpath.relpath(INDEX, posixpath.dirname(name) or ".") + "). "
              "Canonical source-build examples remain unchanged: commands using Cargo, "
              "`target/release`, `scripts/`, `deploy/`, or other checkout assets require "
              "the source checkout. Exact-commit GitHub links are online source-only "
              "references, not files supplied by this archive. HTTPS badges and external "
              "references require a network.\n\n")
    return (prefix + "".join(lines)).encode("utf-8")


def read_contract(root):
    contract = load_json(read_file(root, CONTRACT))
    if set(contract) != {"format", "documents", "source_only"} or contract["format"] != FORMAT:
        raise ValueError("unsupported release documentation contract")
    documents = contract["documents"]
    if not isinstance(documents, dict) or not 2 <= len(documents) <= 192 or not {"README.md", INDEX} <= documents.keys():
        raise ValueError("incomplete or oversized documentation list")
    online = contract["source_only"]
    if not isinstance(online, list) or len(online) > 512 or len(set(online)) != len(online):
        raise ValueError("invalid source-only list")
    names = set()
    for name, expected in documents.items():
        safe_name(name)
        if any(part.lower() in PRIVATE for part in name.split("/")) or name == "AGENTS.md":
            raise ValueError("private or historical artifact in documentation contract")
        if name.casefold() in names:
            raise ValueError("case-colliding documentation names")
        names.add(name.casefold())
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("invalid documentation hash")
    return contract


def rendered_documents(root, commit):
    contract = read_contract(root)
    tracked = source_names(root)
    docs = contract["documents"]
    result = {}
    for name, expected in docs.items():
        if name not in tracked:
            raise ValueError(f"untracked documentation input: {name}")
        data = source_bytes(root, name)
        if digest(data) != expected:
            raise ValueError(f"stale documentation source hash: {name}")
        result[name] = render(root, name, data, set(docs) | set(BASE), contract["source_only"], tracked, commit) if name.endswith(".md") else data
    if sum(map(len, result.values())) > 16 * 1024 * 1024:
        raise ValueError("documentation bundle exceeds byte budget")
    return result, contract


def refresh_contract(root):
    """Update identities, never discover additional bundled documents implicitly."""
    contract = read_contract(root)
    tracked = source_names(root)
    online = set()
    for name in contract["documents"]:
        data = source_bytes(root, name)
        contract["documents"][name] = digest(data)
        if not name.endswith(".md"):
            continue
        for _, line in check_docs.markdown_lines(data.decode("utf-8")):
            for _, _, original, image in link_spans(line):
                if classify_url(original) == "external":
                    continue
                target, _, _ = source_target(root, name, original, tracked)
                if target == "vendor/kryptering/LICENSE":
                    target = "third-party/kryptering/LICENSE"
                if target not in set(contract["documents"]) | set(BASE):
                    if image:
                        raise ValueError(f"image must be explicitly bundled: {name}: {original}")
                    online.add(target)
    contract["source_only"] = sorted(online)
    (root / CONTRACT).write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return {"status": "refreshed", "documents": len(contract["documents"]), "source_only": len(online)}


def required_files(target):
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    suffix = ".exe" if target.endswith("windows-msvc") else ""
    return set(BASE) | {name + suffix for name in ("agentfw", "soup-wall-bench", "llm-firewall", "soup-wall-gateway")}


def inventory(root):
    rows, names, total = {}, set(), 0
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ValueError("linked or unsupported staging directory")
    for directory, directories, files in os.walk(root, followlinks=False):
        for item in directories + files:
            relative = (Path(directory) / item).relative_to(root).as_posix()
            safe_name(relative)
            folded = relative.casefold()
            if folded in names:
                raise ValueError("case-colliding archive paths")
            names.add(folded)
            path = root / relative
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise ValueError("linked archive entry")
            if item in files:
                data = read_file(root, relative, MAX_FILE)
                total += len(data)
                rows[relative] = {"sha256": digest(data), "size": len(data)}
                if len(rows) > MAX_FILES or total > MAX_TOTAL:
                    raise ValueError("archive inventory budget exceeded")
    return rows


def validate_links(root, names):
    sources = {name for name in names if name.endswith(".md")}
    for name in sources:
        text = read_file(root, name).decode("utf-8")
        for _, line in check_docs.markdown_lines(text):
            for original in check_docs.link_destinations(line):
                if classify_url(original) == "external":
                    continue
                parts = urlsplit(original)
                if parts.query or "\\" in unquote(parts.path):
                    raise ValueError("unsupported extracted local link")
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(parts.path))) if parts.path else name
                safe_name(target)
                if target not in names:
                    raise ValueError(f"missing extracted local target: {name}: {original}")
                read_file(root, target, MAX_FILE)
                if parts.fragment:
                    if target not in sources or unquote(parts.fragment) not in check_docs.heading_anchors(list(check_docs.markdown_lines(read_file(root, target).decode("utf-8")))):
                        raise ValueError(f"missing extracted anchor: {name}: {original}")


def stage(root, directory, commit, target):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("expected full source commit")
    documents, contract = rendered_documents(root, commit)
    before = inventory(directory)
    expected_before = required_files(target) | {"README.md"}
    if set(before) != expected_before:
        raise ValueError("existing release stage is missing required assets or contains undeclared files")
    suffix = ".exe" if target.endswith("windows-msvc") else ""
    if before["llm-firewall" + suffix] != before["soup-wall-gateway" + suffix]:
        raise ValueError("Gateway alias differs from the supplied binary")
    for name in BASE:
        source = "vendor/kryptering/LICENSE" if name == "third-party/kryptering/LICENSE" else name
        if read_file(directory, name) != read_file(root, source):
            raise ValueError(f"release payload differs from source: {name}")
    for name, data in documents.items():
        if name in before and name not in {"README.md", "LICENSE", "NOTICE"}:
            raise ValueError("documentation overwrites release payload")
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    rows = inventory(directory)
    record = {"format": FORMAT, "source_commit": commit, "target": target,
              "contract_sha256": contract_digest(contract),
              "source_documents": contract["documents"], "files": rows,
              "qualification": "archive structure and offline documentation only; packaged binaries are not executed"}
    (directory / MANIFEST).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    validate_tree(root, directory, commit, target)
    return record


def validate_tree(source, directory, commit, target):
    record = load_json(read_file(directory, MANIFEST))
    docs, contract = rendered_documents(source, commit)
    if (record.get("format") != FORMAT or record.get("source_commit") != commit or
            record.get("target") != target or record.get("contract_sha256") != contract_digest(contract) or
            record.get("source_documents") != contract["documents"]):
        raise ValueError("stale or mismatched source documentation identity")
    actual = inventory(directory)
    del actual[MANIFEST]
    if actual != record.get("files") or set(actual) != required_files(target) | set(docs):
        raise ValueError("archive membership/hash mismatch")
    for name, data in docs.items():
        if read_file(directory, name) != data:
            raise ValueError("archive documentation differs from canonical rendering")
    validate_links(directory, actual)
    return {"status": "passed", "target": target, "source_commit": commit,
            "files": len(actual), "documents": len(docs), "native_execution": "not performed"}


def bound_archive_headers(archive, windows):
    """Bound parser metadata allocation before the standard archive readers run."""
    if windows:
        with archive.open("rb") as stream:
            stream.seek(max(0, archive.stat().st_size - 65557))
            tail = stream.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or offset + 22 > len(tail):
            raise ValueError("missing ZIP end record")
        _, disk, central_disk, disk_entries, entries, central_size, central_offset, comment = struct.unpack("<4s4H2IH", tail[offset:offset + 22])
        if (disk or central_disk or disk_entries != entries or entries > MAX_FILES * 4 or
                central_size > 1024 * 1024 or offset + 22 + comment != len(tail) or
                central_offset + central_size > archive.stat().st_size - len(tail) + offset):
            raise ValueError("unsupported or oversized ZIP directory")
        return
    with gzip.open(archive, "rb") as stream:
        count, total = 0, 0
        while True:
            header = stream.read(512)
            if not header:
                raise ValueError("tar has no end marker")
            if len(header) != 512:
                raise ValueError("truncated tar header")
            total += 512
            if not any(header):
                while True:
                    block = stream.read(65536)
                    if not block:
                        return
                    total += len(block)
                    if any(block) or total > MAX_TOTAL + 1024 * 1024:
                        raise ValueError("nonzero or oversized tar trailer")
            count += 1
            try:
                size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
            except ValueError as error:
                raise ValueError("unsupported tar size encoding") from error
            limit = 65536 if header[156:157] in (b"x", b"g", b"L", b"K") else MAX_FILE
            if size < 0 or size > limit or count > MAX_FILES * 4:
                raise ValueError("tar header/metadata budget exceeded")
            remaining = ((size + 511) // 512) * 512
            total += remaining
            if total > MAX_TOTAL + 1024 * 1024:
                raise ValueError("tar expanded byte budget exceeded")
            while remaining:
                block = stream.read(min(remaining, 65536))
                if not block:
                    raise ValueError("truncated tar body")
                remaining -= len(block)


def check_archive(source, archive, commit, target, expected_root):
    safe_name(expected_root)
    if "/" in expected_root:
        raise ValueError("archive root must be one directory")
    if archive.stat().st_size > MAX_TOTAL:
        raise ValueError("archive exceeds compressed byte budget")
    windows = target.endswith("windows-msvc")
    bound_archive_headers(archive, windows)
    # Bind every component, including implicit directories, before extraction
    # can collapse differently cased names on a case-insensitive filesystem.
    casing = {}

    def register_casing(name):
        parts = name.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            folded = prefix.casefold()
            if folded in casing and casing[folded] != prefix:
                raise ValueError("inconsistent archive path casing")
            casing[folded] = prefix

    expected_files = required_files(target) | set(read_contract(source)["documents"]) | {MANIFEST}
    for name in expected_files:
        register_casing(expected_root + "/" + name)
    opener = zipfile.ZipFile if windows else lambda path: tarfile.open(path, "r:gz")
    with opener(archive) as package, tempfile.TemporaryDirectory(prefix="soup-wall-release-docs-") as temporary:
        members = package.infolist() if windows else package.getmembers()
        if len(members) > MAX_FILES * 4:
            raise ValueError("too many archive entries")
        paths, files, directories, total = set(), [], [], 0
        for member in members:
            name = member.filename if windows else member.name
            name = name.rstrip("/")
            safe_name(name)
            if name != expected_root and not name.startswith(expected_root + "/"):
                raise ValueError("unexpected archive root")
            register_casing(name)
            if name.casefold() in paths:
                raise ValueError("duplicate/colliding archive entry")
            paths.add(name.casefold())
            is_directory = member.is_dir() if windows else member.isdir()
            if windows:
                mode = member.external_attr >> 16
                if member.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("encrypted or linked ZIP entry")
                size = member.file_size
            else:
                if not member.isfile() and not is_directory:
                    raise ValueError("linked or special tar entry")
                size = member.size
                if is_directory and member.mode & 0o500 != 0o500:
                    raise ValueError("Unix directory lost owner read/traverse mode")
                if not is_directory and not member.mode & stat.S_IRUSR:
                    raise ValueError("Unix file lost owner readable mode")
                if name.rsplit("/", 1)[-1] in {"agentfw", "soup-wall-bench", "llm-firewall", "soup-wall-gateway"} and not member.mode & stat.S_IXUSR:
                    raise ValueError("Unix binary lost owner executable mode")
            if size > MAX_FILE or size < 0:
                raise ValueError("archive entry size budget exceeded")
            total += size
            if total > MAX_TOTAL:
                raise ValueError("archive expanded byte budget exceeded")
            if not is_directory:
                files.append((member, name, size))
            else:
                directories.append(name)
        if len(files) > MAX_FILES:
            raise ValueError("too many archive files")
        if any(not any(name.startswith(directory + "/") for _, name, _ in files) for directory in directories):
            raise ValueError("undeclared empty archive directory")
        for _, name, _ in files:
            if any(name[:i].casefold() in {n.casefold() for _, n, _ in files} for i, c in enumerate(name) if c == "/"):
                raise ValueError("archive file/directory collision")
        for member, name, size in files:
            path = Path(temporary) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with (package.open(member) if windows else package.extractfile(member)) as stream:
                data = stream.read(size + 1)
                if len(data) != size:
                    raise ValueError("archive size mismatch")
                path.write_bytes(data)
        result = validate_tree(source, Path(temporary) / expected_root, commit, target)
        result["archive_sha256"] = digest(archive.read_bytes())
        result["archive_format"] = "zip" if windows else "tar.gz"
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    refresh = sub.add_parser("refresh-manifest", help="refresh hashes and classified links of the existing explicit document list")
    refresh.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    for name in ("stage", "check-archive"):
        command = sub.add_parser(name)
        command.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        command.add_argument("--expected-commit", required=True)
        command.add_argument("--target", choices=TARGETS, required=True)
        if name == "stage":
            command.add_argument("--directory", type=Path, required=True)
        else:
            command.add_argument("--archive", type=Path, required=True)
            command.add_argument("--archive-root", required=True)
    args = parser.parse_args()
    try:
        if args.command == "refresh-manifest":
            print(json.dumps(refresh_contract(args.root), sort_keys=True))
            return 0
        if git(args.root, "rev-parse", "HEAD") != args.expected_commit:
            raise ValueError("source HEAD differs from expected commit")
        if git(args.root, "diff", "--name-only", "HEAD", "--"):
            raise ValueError("source checkout has uncommitted tracked changes")
        if args.command == "stage":
            record = stage(args.root, args.directory, args.expected_commit, args.target)
            result = {"status": "staged", "files": len(record["files"]), "source_commit": args.expected_commit, "target": args.target}
        else:
            result = check_archive(args.root, args.archive, args.expected_commit, args.target, args.archive_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Release documentation check refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
