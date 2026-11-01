#!/usr/bin/env python3
"""Compare two private support bundles without network or process activity."""
from __future__ import annotations
import argparse, hashlib, json, math, os, re, sys
from pathlib import Path

MAX_FILES, MAX_BYTES, MAX_RECORDS = 64, 2_000_000, 256
SECRET = re.compile(r"(?i)(api[_-]?key|token|password|secret|bearer)\s*['\"]?\s*[:=]")
REQUIRED = {"schema", "source", "scope"}

def fail(message: str) -> None:
    raise ValueError(message)

def safe_json(path: Path) -> object:
    if not path.is_file() or path.is_symlink(): fail("bundle contains a non-regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES: fail("bundle file is too large")
    if SECRET.search(raw.decode("utf-8", "replace")): fail("secret-like content is not accepted")
    try: value = json.loads(raw)
    except json.JSONDecodeError as exc: fail(f"invalid JSON: {path.name}")
    def finite(v: object) -> object:
        if isinstance(v, float) and not math.isfinite(v): fail("non-finite number")
        if isinstance(v, dict): return {str(k): finite(x) for k, x in v.items()}
        if isinstance(v, list): return [finite(x) for x in v]
        return v
    return finite(value)

def read_bundle(root: Path) -> dict:
    root = root.resolve()
    if not root.is_dir(): fail("bundle is not a directory")
    files = sorted(root.rglob("*.json"))
    if len(files) > MAX_FILES: fail("bundle has too many files")
    if any(p.is_symlink() for p in root.rglob("*")): fail("symlinks are not accepted")
    total = sum(p.stat().st_size for p in files)
    if total > MAX_BYTES: fail("bundle is too large")
    data = {}
    for path in files:
        rel = path.relative_to(root)
        if ".." in rel.parts: fail("unsafe bundle path")
        data[str(rel)] = safe_json(path)
    manifest = data.get("manifest.json")
    if not isinstance(manifest, dict) or not REQUIRED.issubset(manifest):
        fail("manifest.json is missing required scope")
    if manifest.get("schema") != "sw-agent-diagnostic-bundle/1": fail("unsupported bundle schema")
    return {"manifest": manifest, "files": data}

def pick(bundle: dict, key: str) -> object:
    manifest = bundle["manifest"]
    value = manifest.get(key)
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)

def compare(a: dict, b: dict) -> dict:
    keys = ("source", "scope", "component", "runtime", "classifier", "profile", "policy", "selection", "transport", "daemon", "storage", "cleanup", "failures")
    changes, missing, same = [], [], []
    for key in keys:
        av, bv = pick(a, key), pick(b, key)
        if av is None or bv is None:
            missing.append(key)
        elif av == bv:
            same.append(key)
        else:
            changes.append({"field": key, "before": av, "after": bv})
    return {"changed": changes, "missing": missing, "unchanged": same,
            "notes": ["Differences describe evidence only; they do not prove cause or readiness."]}

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("--json-out", type=Path, required=True)
    p.add_argument("--markdown-out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.before.resolve() == args.after.resolve(): fail("the two selected bundles must be different")
        left, right = read_bundle(args.before), read_bundle(args.after)
        result = {"schema": "sw-agent-diagnostic-diff/1", "mode": "offline-private",
                  "before": left["manifest"].get("source"), "after": right["manifest"].get("source"),
                  "comparison": compare(left, right)}
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode()) > MAX_BYTES: fail("diff is too large")
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        c = result["comparison"]
        lines = ["# Diagnostic Diff", "", "Mode: offline private", "", "## Changes", ""]
        lines += [f"- `{x['field']}` changed from `{x['before']}` to `{x['after']}`" for x in c["changed"]] or ["- None"]
        lines += ["", "## Missing or unchanged", "", "- Missing: " + (", ".join(c["missing"]) or "none"), "- Unchanged: " + (", ".join(c["unchanged"]) or "none"), "", c["notes"][0], ""]
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text("\n".join(lines), encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
if __name__ == "__main__": sys.exit(main())
