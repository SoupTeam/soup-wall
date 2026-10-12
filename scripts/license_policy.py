#!/usr/bin/env python3
"""Fail-closed license/provenance inventory for the complete locked Cargo workspace.

Python >=3.11, standard library only.  Does not fetch third-party assets or
claim legal approval; see docs/PROVENANCE.md.  No license expression is silently
coerced into an approved one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from datetime import datetime, timezone

SPDX_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:-]*|[()]", re.ASCII)

# Minimum known external/source asset inventory for the repository snapshot.
# These records must not silently disappear from the manifest even when the
# corresponding optional binary/data is absent from the checkout.
REQUIRED_ASSET_PATHS = frozenset({
    "vendor/kryptering/LICENSE",
    "scripts/benchmarks/agentdojo-live.requirements.txt",
    "eval/sou13/requirements-cp2.txt",
    "models/injection/model.safetensors",
    "models/moderation/model.safetensors",
    "datasets/deepset_injection.jsonl",
    "datasets/jailbreak_classification.jsonl",
    "datasets/safe_guard.jsonl",
    "datasets/jailbreakbench.jsonl",
})


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha1(path: pathlib.Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def within(root: pathlib.Path, value: str) -> pathlib.Path:
    """A checked-in manifest must never resolve outside the source root."""
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"path outside source root: {value}")
    return candidate


class SPDXSyntaxError(ValueError):
    pass


class SPDXParser:
    """Parse SPDX AND/OR/WITH with correct precedence (WITH > AND > OR).

    Returns a tree; identifiers not in a *reviewed* allowlist are rejected by
    the evaluator.  No attempt is made to infer an unrecorded license grant.
    """

    def __init__(self, expression: str):
        if not isinstance(expression, str) or not expression.strip():
            raise SPDXSyntaxError("missing license expression")
        self.tokens: list[str] = []
        end = 0
        for m in SPDX_TOKEN.finditer(expression):
            if expression[end:m.start()].strip():
                raise SPDXSyntaxError(f"invalid SPDX token at {end}")
            self.tokens.append(m.group())
            end = m.end()
        if expression[end:].strip():
            raise SPDXSyntaxError("trailing invalid SPDX text")
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        if self.peek() is None:
            raise SPDXSyntaxError("unexpected end of SPDX expression")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise SPDXSyntaxError(f"unexpected token: {self.peek()}")
        def has_special(n):
            if n[0] == "LICENSE":
                return n[1].upper() in {"NONE", "NOASSERTION"}
            if n[0] == "WITH":
                return n[1].upper() in {"NONE", "NOASSERTION"}
            return has_special(n[1]) or has_special(n[2])
        def invalid_special_or(n):
            if n[0] == "OR":
                return has_special(n[1]) or has_special(n[2]) or invalid_special_or(n[1]) or invalid_special_or(n[2])
            if n[0] in {"AND"}:
                return invalid_special_or(n[1]) or invalid_special_or(n[2])
            return n[0] == "WITH" and n[1].upper() in {"NONE", "NOASSERTION"}
        if invalid_special_or(node):
            raise SPDXSyntaxError("NONE/NOASSERTION cannot be OR alternatives or use WITH")
        return node

    def parse_or(self):
        node = self.parse_and()
        while (self.peek() or "").upper() == "OR":
            self.take()
            node = ("OR", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_atom()
        while (self.peek() or "").upper() == "AND":
            self.take()
            node = ("AND", node, self.parse_atom())
        return node

    def parse_atom(self):
        if self.peek() == "(":
            self.take()
            inner = self.parse_or()
            if self.take() != ")":
                raise SPDXSyntaxError("missing closing parenthesis")
            if (self.peek() or "").upper() == "WITH":
                raise SPDXSyntaxError("WITH must follow a simple license identifier")
            return inner
        license_id = self.take()
        if license_id in {"(", ")"} or license_id.upper() in {"AND", "OR", "WITH"}:
            raise SPDXSyntaxError(f"expected license identifier, got {license_id}")
        if (self.peek() or "").upper() == "WITH":
            self.take()
            exception = self.take()
            if exception in {"(", ")"} or exception.upper() in {"AND", "OR", "WITH"}:
                raise SPDXSyntaxError("invalid license exception")
            return ("WITH", license_id, exception)
        return ("LICENSE", license_id)


def evaluate_spdx(node, allowed: set[str], allowed_with: set[str]) -> tuple[bool, list[str]]:
    kind = node[0]
    if kind == "LICENSE":
        name = node[1]
        return (name in allowed, [name] if name in allowed else [])
    if kind == "WITH":
        candidate = f"{node[1]} WITH {node[2]}"
        return (candidate in allowed_with, [candidate] if candidate in allowed_with else [])
    lhs_ok, lhs = evaluate_spdx(node[1], allowed, allowed_with)
    rhs_ok, rhs = evaluate_spdx(node[2], allowed, allowed_with)
    if kind == "OR":
        # An offered alternative is allowed only if at least one COMPLETE
        # branch meets the policy.  Prefer the left branch consistently.
        return (True, lhs) if lhs_ok else ((True, rhs) if rhs_ok else (False, []))
    if kind == "AND":
        return lhs_ok and rhs_ok, (lhs + rhs) if lhs_ok and rhs_ok else []
    raise SPDXSyntaxError("invalid SPDX AST")


def judge_spdx(expression: str | None, policy: dict) -> tuple[str, list[str], str]:
    if not expression:
        return "unknown", [], "missing license metadata"
    try:
        tree = SPDXParser(expression).parse()
    except SPDXSyntaxError as exc:
        return "unknown", [], f"invalid or unsupported SPDX expression: {exc}"
    approved, selected = evaluate_spdx(tree, set(policy.get("allowed_licenses", [])), set(policy.get("allowed_with_exceptions", [])))
    return ("approved", selected, "reviewed policy branch") if approved else ("disallowed", [], "no fully approved SPDX alternative")


def inventory_rust(metadata: dict, lock: dict, policy: dict, root: pathlib.Path) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    meta_pkgs = metadata.get("packages")
    members = metadata.get("workspace_members")
    if not isinstance(meta_pkgs, list) or not isinstance(members, list):
        raise ValueError("cargo metadata must include packages and workspace_members; do not use --no-deps")
    lock_pkgs = lock.get("package")
    if not isinstance(lock_pkgs, list) or not lock_pkgs:
        raise ValueError("Cargo.lock has no [[package]] entries")
    # Comparison by (name, version, source) also detects missing optional/target
    # dependencies.  The root patch is represented by source=null in metadata.
    def key(p):
        return (p.get("name"), p.get("version"), p.get("source") or "path")
    lm = {key(p) for p in lock_pkgs}
    mm = {key(p) for p in meta_pkgs}
    if len(lm) != len(lock_pkgs) or len(mm) != len(meta_pkgs):
        errors.append("duplicate metadata/lock identity; cannot prove complete inventory")
    if lm != mm:
        missing = sorted(lm - mm)
        additional = sorted(mm - lm)
        errors.append(f"Cargo.lock/metadata coverage mismatch; missing={missing[:12]} ({len(missing)}), extra={additional[:12]} ({len(additional)})")
    if len(members) != policy["workspace"]["expected_member_count"]:
        errors.append(f"workspace member count mismatch: {len(members)}")
    expected_names = set(policy["workspace"].get("expected_member_names", []))
    if expected_names:
        found = {p.get("name") for p in meta_pkgs if p.get("id") in set(members)}
        if expected_names != found:
            errors.append(f"workspace members changed: expected={sorted(expected_names)}, actual={sorted(found)}")
    member_set = set(members)
    meta_by_id = {p.get("id"): p for p in meta_pkgs}
    for mid in member_set:
        if mid not in meta_by_id:
            errors.append(f"workspace member not in resolved metadata: {mid}")
    seen_vendor = 0
    exceptions = policy.get("package_exceptions", [])
    if not isinstance(exceptions, list) or any(not isinstance(e, dict) for e in exceptions):
        errors.append("package_exceptions must be a list of TOML tables")
        exceptions = []
    # Exceptions must refer to an immutable crate archive pinned by Cargo.lock.
    # A package/version alone is not enough when reviewing non-standard licenses.
    lock_by_identity = {key(p): p for p in lock_pkgs}
    rows: list[dict] = []
    for p in sorted(meta_pkgs, key=lambda p: (p.get("name", ""), p.get("version", ""), str(p.get("source")))):
        name, version, source = key(p)
        if not name or not version or not p.get("manifest_path"):
            errors.append(f"incomplete package metadata: {name} {version}")
        license_expr = p.get("license")
        result, selected, note = judge_spdx(license_expr, policy)
        kind = "workspace" if p.get("id") in member_set else ("registry" if p.get("source") else "path")
        if kind == "path" and name != policy["workspace"]["vendored_package"]:
            errors.append(f"unreviewed path dependency (not workspace/vendor): {name}@{version}")
        if kind == "registry" and source != "registry+https://github.com/rust-lang/crates.io-index":
            errors.append(f"unreviewed non-default dependency source: {name}@{version}: {source}")
        if kind == "workspace":
            if result != "approved":
                errors.append(f"workspace crate {name}@{version}: {note}")
        if name == policy["workspace"]["vendored_package"] and version == policy["workspace"]["vendored_version"]:
            seen_vendor += 1
            if source != "path" or kind != "path":
                errors.append("vendored kryptering must resolve to local path, not registry")
            manifest = pathlib.Path(p["manifest_path"]).resolve()
            if manifest != within(root, policy["workspace"]["vendored_manifest"]):
                errors.append("vendored kryptering resolved outside reviewed vendor path")
            if license_expr != policy["workspace"]["vendored_license"]:
                errors.append("vendored license differs from reviewed source manifest")
        used_exception = None
        if result != "approved":
            matches = [e for e in exceptions if e.get("name") == name and e.get("version") == version and e.get("source") == source]
            if len(matches) == 1:
                e = matches[0]
                notice = e.get("notice_path", "")
                reason = e.get("reason", "")
                pinned = lock_by_identity.get((name, version, source), {})
                checksum = pinned.get("checksum")
                # Include supplementary copyright/derived-code notices verbatim.
                supplementary = e.get("supplemental_notices", [])
                extras_valid = (isinstance(supplementary, list)
                                and all(isinstance(extra, dict)
                                        and isinstance(extra.get("path"), str)
                                        and isinstance(extra.get("sha256"), str)
                                        and within(root, extra["path"]).is_file()
                                        and sha256(within(root, extra["path"])) == extra["sha256"]
                                        for extra in supplementary))
                choice = e.get("selected_license")
                # MIT is explicitly evidenced by the exact license notice;
                # CDLA must stay limited to this specific package/version.
                choice_valid = (choice in policy.get("allowed_licenses", [])
                                or (choice == "CDLA-Permissive-2.0"
                                    and license_expr == choice
                                    and name == "webpki-roots"
                                    and version == "1.0.9"))
                if (isinstance(e.get("license"), str) and e["license"].strip()
                        and e["license"] == license_expr
                        and isinstance(reason, str) and len(reason) >= 30
                        and notice and within(root, notice).is_file()
                        and isinstance(e.get("notice_sha256"), str)
                        and sha256(within(root, notice)) == e["notice_sha256"]
                        and isinstance(checksum, str)
                        and re.fullmatch(r"[0-9a-f]{64}", checksum)
                        and e.get("cargo_lock_checksum") == checksum
                        and choice_valid and extras_valid):
                    result, selected, note = "exception", [choice], "exact locked crate and reviewed notice exception"
                    used_exception = {"reason": reason, "notice_path": notice,
                                      "notice_sha256": e["notice_sha256"],
                                      "cargo_lock_checksum": checksum,
                                      "supplemental_notices": supplementary}
                else:
                    note += "; exception needs exact lock checksum, selected license and verified notice(s)"
            elif len(matches) > 1:
                errors.append(f"duplicate policy exceptions: {name}@{version}")
        rows.append({"name": name, "version": version, "source": source, "kind": kind,
                     "license": license_expr, "decision": result, "selected": selected,
                     "reason": note, "exception": used_exception})
    if seen_vendor != 1:
        errors.append(f"expected exactly one reviewed vendored package, got {seen_vendor}")
    for e in exceptions:
        if not any(p["name"] == e.get("name") and p["version"] == e.get("version") and p["source"] == e.get("source") for p in rows):
            errors.append(f"stale policy exception: {e.get('name')}@{e.get('version')}")
    return rows, errors


def inventory_assets(root: pathlib.Path, asset_manifest: dict) -> tuple[list[dict], list[str]]:
    rows = []
    errors = []
    entries = asset_manifest.get("asset", [])
    if not isinstance(entries, list):
        return [], ["asset manifest entries must be a list"]
    for a in entries:
        if not isinstance(a, dict):
            errors.append("malformed asset entry (expected TOML table)")
            continue
        name = a.get("name")
        kind = a.get("kind")
        path = a.get("path")
        decision = a.get("decision", "unresolved")
        mandatory = a.get("mandatory", False)
        if not name or not kind or decision not in {"reviewed", "unresolved", "rejected"} or not isinstance(mandatory, bool):
            errors.append(f"malformed asset record: {name}")
            continue
        filehash = None
        blob = None
        if path:
            try:
                p = within(root, path)
                if p.is_file():
                    filehash = sha256(p)
                    blob = git_blob_sha1(p)
                elif mandatory:
                    errors.append(f"missing mandatory provenance asset: {name} ({path})")
            except ValueError as exc:
                errors.append(str(exc))
        elif mandatory:
            errors.append(f"mandatory asset without pinned path: {name}")
        if decision == "reviewed":
            notice = a.get("notice_path", "")
            if not a.get("license") or not a.get("origin") or not a.get("version") or not notice or not within(root, notice).is_file():
                errors.append(f"asset falsely marked reviewed or missing required notice: {name}")
            if not filehash:
                errors.append(f"reviewed asset absent; cannot claim approval: {name}")
            pinned_blob = a.get("reviewed_git_blob_sha1")
            if not isinstance(pinned_blob, str) or not re.fullmatch(r"[0-9a-f]{40}", pinned_blob) or pinned_blob != blob:
                errors.append(f"reviewed asset bytes do not match pinned Git blob: {name}")
        if mandatory and decision != "reviewed":
            errors.append(f"mandatory asset unapproved: {name}")
        row = {"name": name, "kind": kind, "path": path, "present": filehash is not None,
               "sha256": filehash, "git_blob_sha1": blob, "mandatory": mandatory, "decision": decision,
               "origin": a.get("origin"), "version": a.get("version"), "license": a.get("license"),
               "reason": a.get("reason", "")}
        if kind == "optional_support_requirements" and filehash:
            pins = []
            for line in within(root, path).read_text(encoding="utf8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^;\s]+)", line)
                if not m:
                    errors.append(f"unrecorded/unpinned Python support requirement: {line[:100]}")
                else:
                    pins.append({"name": m.group(1), "version": m.group(2), "license": None,
                                 "decision": "unresolved", "source": "Python support requirements; wheel not bundled"})
            row["pinned_packages"] = pins
        rows.append(row)
    return rows, errors


def build_report(root: pathlib.Path, policy_path: pathlib.Path, asset_path: pathlib.Path, metadata: dict | None, metadata_error: str | None) -> dict:
    lock_path = root / "Cargo.lock"
    report = {"schema": "soup-wall-license-policy-v1", "generated_utc": datetime.now(timezone.utc).isoformat(),
              "inputs": {}, "rust_packages": [], "assets": [], "errors": [], "summary": {}}
    try:
        policy = tomllib.loads(policy_path.read_text(encoding="utf8"))
        assets = tomllib.loads(asset_path.read_text(encoding="utf8"))
        if not isinstance(policy.get("workspace"), dict):
            raise ValueError("license policy missing [workspace] table")
    except (OSError, UnicodeError, ValueError) as exc:
        report["errors"].append(f"cannot load license/asset policy: {exc}")
        for label, path in [("cargo_lock_sha256", lock_path), ("cargo_toml_sha256", root / "Cargo.toml"),
                            ("policy_sha256", policy_path), ("assets_manifest_sha256", asset_path)]:
            try:
                report["inputs"][label] = sha256(path)
            except (OSError, ValueError):
                report["inputs"][label] = None
        report["summary"] = {"rust": {x: 0 for x in ("approved", "exception", "unknown", "disallowed")},
                             "rust_count": 0, "unreviewed_optional_assets": [],
                             "approved_for_release": False, "license_gate_pass": False}
        return report
    for label, path in [("cargo_lock_sha256", lock_path), ("cargo_toml_sha256", root / "Cargo.toml"),
                        ("policy_sha256", policy_path), ("assets_manifest_sha256", asset_path),
                        ("vendor_manifest_sha256", root / policy["workspace"]["vendored_manifest"]),
                        ("vendor_patch_record_sha256", root / "vendor/kryptering/PATCH.md")]:
        try:
            report["inputs"][label] = sha256(path)
        except (OSError, ValueError) as exc:
            report["inputs"][label] = None
            report["errors"].append(f"cannot hash {label}: {exc}")
    report["inputs"]["metadata_command"] = "cargo metadata --locked --all-features --format-version 1 (no platform filter)"
    report["inputs"]["checker_sha256"] = sha256(pathlib.Path(__file__))
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                text=True, check=False, timeout=8)
        report["inputs"]["git_head"] = commit.stdout.strip() if commit.returncode == 0 else None
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root,
                               capture_output=True, text=True, check=False, timeout=8)
        report["inputs"]["git_tracked_changes"] = bool(dirty.stdout.strip()) if dirty.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        report["inputs"]["git_head"] = None
        report["inputs"]["git_tracked_changes"] = None
    try:
        report["assets"], asset_errors = inventory_assets(root, assets)
        report["errors"].extend(asset_errors)
        paths = [a["path"] for a in report["assets"] if a.get("path")]
        for path in sorted(REQUIRED_ASSET_PATHS):
            if paths.count(path) != 1:
                report["errors"].append(
                    f"required provenance record missing or duplicated: {path}"
                )
        vendor_records = [a for a in report["assets"] if a["kind"] == "bundled_vendor"
                          and a["path"] == "vendor/kryptering/LICENSE"]
        if len(vendor_records) != 1 or vendor_records[0]["decision"] != "reviewed":
            report["errors"].append("required vendored license/provenance inventory missing")
        support_records = [a for a in report["assets"] if a["kind"] == "optional_support_requirements"
                           and a["path"] == "scripts/benchmarks/agentdojo-live.requirements.txt"]
        # A missing support manifest is a release-inventory finding; a pending
        # license for an optionally downloaded Python wheel is NOT an approval.
        if root.joinpath("scripts/benchmarks/agentdojo-live.requirements.txt").is_file() and len(support_records) != 1:
            report["errors"].append("unrecorded pinned Python support requirements")
        if metadata_error:
            raise RuntimeError(metadata_error)
        if metadata is None:
            raise RuntimeError("missing metadata")
        lock = tomllib.loads(lock_path.read_text(encoding="utf8"))
        report["rust_packages"], rust_errors = inventory_rust(metadata, lock, policy, root)
        report["errors"].extend(rust_errors)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        report["errors"].append(f"license inventory incomplete: {exc}")
    counts = {x: sum(p["decision"] == x for p in report["rust_packages"]) for x in ("approved", "exception", "unknown", "disallowed")}
    pending = [a["name"] for a in report["assets"] if a["decision"] != "reviewed"]
    report["summary"] = {"rust": counts, "rust_count": len(report["rust_packages"]),
                         "unreviewed_optional_assets": pending,
                         "approved_for_release": False,
                         "license_gate_pass": not report["errors"] and not (counts["unknown"] or counts["disallowed"]) and bool(report["rust_packages"])}
    # This gate says only that reviewed Rust license policy passes; it is never
    # a legal endorsement of separate optional Python/model/dataset assets.
    # License inventory is diagnostic input to a separately authorized release
    # gate. Never turn an empty/modified asset manifest into release approval.
    report["summary"]["approved_for_release"] = False
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", default=".")
    p.add_argument("--policy", default="policy/license-policy.toml")
    p.add_argument("--assets", default="policy/asset-provenance.toml")
    p.add_argument("--metadata-json", help="pre-recorded cargo metadata for offline unit tests")
    p.add_argument("--report", default="target/license-policy/report.json")
    args = p.parse_args(argv)
    root = pathlib.Path(args.root).resolve()
    def under(v):
        return within(root, v)
    report_path = under(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    meta = None
    error = None
    try:
        if args.metadata_json:
            meta = json.loads(pathlib.Path(args.metadata_json).read_text(encoding="utf8"))
        else:
            cmd = ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"]
            cp = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=240, check=False)
            if cp.returncode:
                error = f"cargo metadata exit {cp.returncode}: {cp.stderr[-2500:]}"
            else:
                meta = json.loads(cp.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        error = f"cannot obtain Cargo metadata: {exc}"
    report = build_report(root, under(args.policy), under(args.assets), meta, error)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf8")
    status = "PASS" if report["summary"]["license_gate_pass"] else "FAIL"
    print(f"Rust license gate: {status}; packages={report['summary']['rust_count']}; "
          f"unknown={report['summary']['rust']['unknown']}, disallowed={report['summary']['rust']['disallowed']}, "
          f"errors={len(report['errors'])}; report={report_path}")
    if not report["summary"]["license_gate_pass"]:
        for msg in report["errors"][:25]:
            print(f"ERROR: {msg}", file=sys.stderr)
        for pkg in [x for x in report["rust_packages"] if x["decision"] in {"unknown", "disallowed"}][:30]:
            print(f"{pkg['decision'].upper()}: {pkg['name']}@{pkg['version']}: {pkg['license']} ({pkg['reason']})", file=sys.stderr)
    return 0 if report["summary"]["license_gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
