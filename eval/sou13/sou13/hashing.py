"""Canonical JSON hashing. Logic adapted from the earlier v0.2 pilot build script (v0.2 is not
included in this archive; nothing here depends on it)."""
import hashlib
import json
from pathlib import Path


def canonical(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
