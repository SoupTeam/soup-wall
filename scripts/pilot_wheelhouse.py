#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare exact reviewed wheels with bounded stdlib HTTPS; pip stays offline.

The manifest is reviewed data, never an index or a source of new requirements.
No wheel contents are imported or executed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.parse
import urllib.request

FORMAT = "sw-pilot-wheelhouse/1"
TARGET = "cpython-3.11-linux-x86_64"
MAX_METADATA = 1024 * 1024
MAX_WHEELS = 64
MAX_WHEEL = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
TIMEOUT = 60
TOTAL_TIMEOUT = 300
BLOCK = 64 * 1024


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def no_links(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("wheelhouse_symlink_refused")
    return path


def regular(path):
    """Open a bounded regular file without accepting symlinks or path aliases."""
    path = no_links(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    stream = os.fdopen(descriptor, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        stream.close()
        raise ValueError("wheelhouse_regular_file_required")
    return stream


def metadata(path):
    with regular(path) as stream:
        value = stream.read(MAX_METADATA + 1)
    if len(value) > MAX_METADATA:
        raise ValueError("wheelhouse_metadata_exceeds_bound")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("wheelhouse_duplicate_json_key")
        result[key] = value
    return result


def checked_url(url, filename=None):
    if not isinstance(url, str) or len(url) > 2048 or not url.isascii():
        raise ValueError("wheelhouse_url_refused")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "files.pythonhosted.org"
            or parsed.query or parsed.fragment or "%" in parsed.path
            or not re.fullmatch(r"/packages/[A-Za-z0-9_./-]+", parsed.path)
            or any(part in ("", ".", "..") for part in parsed.path.split("/")[1:])
            or (filename is not None and parsed.path.rsplit("/", 1)[-1] != filename)):
        raise ValueError("wheelhouse_url_refused")
    return url


def load_manifest(manifest, requirements):
    raw = metadata(requirements)
    locked = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9.!+_-]*)"
                            r"((?: --hash=sha256:[0-9a-f]{64})+)", line)
        if match is None:
            raise ValueError("wheelhouse_exact_requirements_required")
        name, version, hashes = match.groups()
        name = normalized(name)
        if name in locked:
            raise ValueError("wheelhouse_duplicate_requirement")
        locked[name] = (version, set(re.findall(r"sha256:([0-9a-f]{64})", hashes)))
    document = json.loads(metadata(manifest), object_pairs_hook=unique_object)
    if (not isinstance(document, dict)
            or set(document) != {"format", "target", "requirements_sha256", "wheels"}
            or document["format"] != FORMAT or document["target"] != TARGET
            or document["requirements_sha256"] != hashlib.sha256(raw).hexdigest()):
        raise ValueError("wheelhouse_manifest_identity_mismatch")
    wheels = document["wheels"]
    if not isinstance(wheels, list) or not 1 <= len(wheels) == len(locked) <= MAX_WHEELS:
        raise ValueError("wheelhouse_graph_mismatch")
    names, filenames, digests = set(), set(), set()
    total = 0
    for wheel in wheels:
        if not isinstance(wheel, dict) or set(wheel) != {"name", "version", "filename", "url", "size", "sha256"}:
            raise ValueError("wheelhouse_invalid_entry")
        name, version, filename, digest, size = [wheel[key] for key in ("name", "version", "filename", "sha256", "size")]
        if (not all(isinstance(item, str) for item in (name, version, filename, digest))
                or name != normalized(name) or name not in locked or name in names
                or locked[name][0] != version or digest not in locked[name][1]):
            raise ValueError("wheelhouse_graph_mismatch")
        if (len(filename) > 240 or not re.fullmatch(r"[A-Za-z0-9_]+-[A-Za-z0-9_.!+]+-(?:[A-Za-z0-9_.]+-){2}[A-Za-z0-9_.]+\.whl", filename)
                or normalized(filename.split("-")[0]) != name or filename.split("-")[1] != version
                or filename.casefold() in filenames or digest in digests
                or type(size) is not int or not 1 <= size <= MAX_WHEEL):
            raise ValueError("wheelhouse_invalid_filename_or_size")
        checked_url(wheel["url"], filename)
        names.add(name)
        filenames.add(filename.casefold())
        digests.add(digest)
        total += size
    if names != set(locked) or total > MAX_TOTAL:
        raise ValueError("wheelhouse_graph_or_total_mismatch")
    return wheels


def verify_file(path, wheel):
    with regular(path) as stream:
        if os.fstat(stream.fileno()).st_size != wheel["size"]:
            raise ValueError("wheelhouse_size_mismatch")
        digest = hashlib.sha256()
        remaining = wheel["size"]
        while remaining:
            chunk = stream.read(min(BLOCK, remaining))
            if not chunk:
                raise ValueError("wheelhouse_truncated_file")
            remaining -= len(chunk)
            digest.update(chunk)
        if stream.read(1) or digest.hexdigest() != wheel["sha256"]:
            raise ValueError("wheelhouse_digest_mismatch")


def directory(path, *, private=False):
    path = no_links(path)
    if not path.is_dir():
        raise ValueError("wheelhouse_directory_required")
    info = path.stat()
    if private and os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("wheelhouse_private_owned_cache_required")
    return path


def verify_directory(path, wheels, *, complete=True):
    path = directory(path)
    expected = {wheel["filename"] for wheel in wheels}
    present = {entry.name for entry in path.iterdir()}
    if not present <= expected or (complete and present != expected):
        raise ValueError("wheelhouse_missing_or_unreviewed_files")
    for wheel in wheels:
        if wheel["filename"] in present:
            verify_file(path / wheel["filename"], wheel)
    return path


class ReviewedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        # The stdlib handler drains redirect bodies before following them.
        # Reviewed artifact URLs are direct: close without reading any body.
        if response is not None:
            response.close()
        raise ValueError("wheelhouse_redirect_refused")


def download(wheel, output, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("wheelhouse_download_deadline")
    # Ignore environment proxy configuration and never ask for compressed data.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReviewedRedirects())
    request = urllib.request.Request(checked_url(wheel["url"], wheel["filename"]),
        headers={"Accept-Encoding": "identity", "User-Agent": "Soup-Wall-reviewed-wheelhouse/1"})
    with opener.open(request, timeout=min(TIMEOUT, remaining)) as response:
        checked_url(response.geturl())
        headers = response.headers
        if (response.status != 200 or headers.get("Content-Encoding", "identity").lower() != "identity"
                or headers.get("Transfer-Encoding") is not None
                or len(headers.get_all("Content-Length", [])) != 1
                or len(headers.get_all("Content-Encoding", [])) > 1
                or headers.get("Content-Length") != str(wheel["size"])):
            raise ValueError("wheelhouse_response_framing_refused")
        remaining = wheel["size"]
        digest = hashlib.sha256()
        while remaining:
            if time.monotonic() >= deadline:
                raise ValueError("wheelhouse_download_deadline")
            chunk = response.read1(min(BLOCK, remaining))
            if not chunk or len(chunk) > remaining:
                raise ValueError("wheelhouse_download_truncated_or_oversize")
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if time.monotonic() >= deadline or response.read1(1) or digest.hexdigest() != wheel["sha256"]:
            raise ValueError("wheelhouse_download_digest_or_size_mismatch")


def prepare_wheelhouse(manifest, requirements, destination, *, source=None, allow_download=False):
    """Populate/reuse a private cache, refusing bad existing files before network.

    An explicit source is verified completely and copied without any fallback.
    This also isolates pip from a supplied wheelhouse's permissions and contents.
    """
    wheels = load_manifest(manifest, requirements)
    destination = no_links(destination)
    if source is not None:
        source = verify_directory(source, wheels)
    if not destination.exists() and not destination.is_symlink():
        destination.mkdir(mode=0o700)
    destination = directory(destination, private=True)
    verify_directory(destination, wheels, complete=False)
    missing = [wheel for wheel in wheels if not (destination / wheel["filename"]).exists()]
    if missing and source is None and not allow_download:
        raise ValueError("wheelhouse_missing_without_explicit_downloads")
    deadline = time.monotonic() + TOTAL_TIMEOUT
    for wheel in missing:
        descriptor, name = tempfile.mkstemp(prefix=".wheel-", dir=destination)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                if source is None:
                    download(wheel, output, deadline)
                else:
                    with regular(source / wheel["filename"]) as stream:
                        remaining = wheel["size"]
                        while remaining:
                            chunk = stream.read(min(BLOCK, remaining))
                            if not chunk:
                                raise ValueError("wheelhouse_truncated_file")
                            output.write(chunk)
                            remaining -= len(chunk)
                        if stream.read(1):
                            raise ValueError("wheelhouse_size_mismatch")
            verify_file(temporary, wheel)
            # Atomic create, never replace an existing (possibly hostile) entry.
            os.link(temporary, destination / wheel["filename"])
        finally:
            temporary.unlink()
    return verify_directory(destination, wheels)


def install_arguments(wheelhouse, requirements):
    """The only pip install route: no HTTP index or remote find-links."""
    return ["-I", "-m", "pip", "--isolated", "install", "--require-hashes", "--only-binary=:all:",
            "--no-compile", "--no-cache-dir", "--disable-pip-version-check", "--no-index", "--find-links",
            str(Path(wheelhouse).absolute()), "-r", str(Path(requirements).absolute())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--allow-download", action="store_true")
    args = parser.parse_args()
    path = prepare_wheelhouse(args.manifest, args.requirements, args.destination, allow_download=args.allow_download)
    print(json.dumps({"status": "verified", "wheels": len(load_manifest(args.manifest, args.requirements)), "directory": str(path)}))


if __name__ == "__main__":
    main()
