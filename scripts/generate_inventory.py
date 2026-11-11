#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the selected installed pilot, exact scanner graphs and runtime notices.

An upstream-identity.json is source metadata, never an installed selection. All
incomplete checks and findings remain blocking; this command cannot publish.
"""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import email
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import runtime_reviews

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT = 120


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def read_json(path):
    path = Path(path)
    require(path.stat().st_size <= MAX_OUTPUT_BYTES, "json_size_limit")
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def run_cmd(command, *, cwd=ROOT, timeout=DEFAULT_TIMEOUT, allowed=(0,)):
    # File-backed capture bounds memory while the process runs, instead of
    # truncating an arbitrarily large capture after it has already completed.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = None
        try:
            process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=os.name == "posix")
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                require(time.monotonic() < deadline, "scanner_timeout")
                require(os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size <= MAX_OUTPUT_BYTES,
                        "scanner_output_limit")
                time.sleep(0.05)
            require(os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size <= MAX_OUTPUT_BYTES,
                    "scanner_output_limit")
            out.seek(0); err.seek(0)
            return {"status": "passed" if process.returncode in allowed else "failed",
                    "command": command, "exit_code": process.returncode,
                    "stdout": out.read().decode("utf-8"), "stderr": err.read().decode("utf-8")}
        except (OSError, ValueError, UnicodeError) as error:
            out.seek(0); err.seek(0)
            return {"status": "incomplete", "command": command, "reason": str(error),
                    "stdout": out.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace"),
                    "stderr": err.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")}
        finally:
            if process is not None and process.poll() is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)


def python_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def scanner_identity(ecosystem, name, version):
    if ecosystem == "PyPI":
        name = python_name(name)
        # PEP 440 release components permit zero padding. OSV 2.7 reports,
        # for example, installed pip 25.2 as 25.2.0. Preserve raw versions in
        # the inventory; normalize only plain numeric releases for comparison.
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
            parts = [int(part) for part in version.split(".")]
            while len(parts) > 1 and parts[-1] == 0:
                parts.pop()
            version = ".".join(map(str, parts))
    return ecosystem, name, version


def lock_graphs(root=ROOT):
    root = Path(root)
    cargo = root / "Cargo.lock"
    py = root / "profiles/mcp/git-readonly-v1/requirements.lock"
    node = root / "profiles/mcp/filesystem-readonly-v1/package-lock.json"
    rust = tomllib.loads(cargo.read_text())["package"]
    # OSV labels local and patched Cargo.lock entries with the crates.io
    # ecosystem too. This is an expected scanner representation, not evidence
    # that a local/vendored component came from that registry. Keep the actual
    # lock sources separately in the report.
    cargo_graph = {("crates.io", p["name"], p["version"]) for p in rust}
    requirements = []
    for line in py.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)((?: --hash=sha256:[0-9a-f]{64})+)", line)
        require(match is not None, "unhashed_or_unpinned_python_requirement")
        requirements.append(("PyPI", python_name(match[1]), match[2]))
    require(len(requirements) == len(set(requirements)), "duplicate_python_requirement")
    npm_lock = read_json(node)
    require(npm_lock.get("lockfileVersion") == 3, "npm_lock_schema")
    npm_graph = set()
    for path, package in npm_lock["packages"].items():
        if not path:
            continue
        require(path.startswith("node_modules/") and package.get("integrity"), "npm_package_identity_missing")
        name = package.get("name") or path.rsplit("node_modules/", 1)[1]
        npm_graph.add(("npm", name, package["version"]))
    graphs = {str(cargo.resolve()): cargo_graph, str(py.resolve()): set(requirements), str(node.resolve()): npm_graph}
    require(all(graphs.values()), "empty_package_graph")
    return graphs


def osv_observation(data, graphs):
    require(isinstance(data, dict) and isinstance(data.get("results"), list), "osv_schema")
    observed = {path: set() for path in graphs}
    findings = []
    for result in data["results"]:
        source = result.get("source", {})
        require(source.get("type") == "lockfile", "osv_source_type")
        path = str(Path(source.get("path", "")).resolve())
        require(path in graphs, "osv_unexpected_source")
        require(isinstance(result.get("packages"), list), "osv_packages_missing")
        for row in result["packages"]:
            package = row.get("package", {})
            eco, name, version = (package.get(k) for k in ("ecosystem", "name", "version"))
            require(all(isinstance(v, str) and v for v in (eco, name, version)), "osv_package_identity_missing")
            if eco == "PyPI":
                name = python_name(name)
            observed[path].add(scanner_identity(eco, name, version))
            require(isinstance(row.get("vulnerabilities", []), list), "osv_findings_schema")
            for finding in row.get("vulnerabilities", []):
                findings.append({"source": path, "package": {"ecosystem": eco, "name": name, "version": version},
                                 "advisory": finding, "reachability": "not_established"})
    for path, expected in graphs.items():
        normalized = {scanner_identity(*item) for item in expected}
        require(len(normalized) == len(expected), "ambiguous_expected_graph")
        require(observed[path] == normalized, "osv_exact_graph_mismatch:" + Path(path).name)
    return {"coverage": {path: len(packages) for path, packages in observed.items()}, "findings": findings}


def verify_osv(data, graphs):
    observation = osv_observation(data, graphs)
    require(not observation["findings"], "unresolved_osv_findings")
    return observation["coverage"]


def rust_license_command(report_path):
    require(Path(report_path).resolve().is_relative_to(ROOT.resolve()), "rust_license_report_outside_source")
    return [sys.executable, str(ROOT / "scripts/license_policy.py"), "--root", str(ROOT),
            "--report", str(report_path)]


def rustsec_identity(path, expected):
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{40}", expected), "expected_rustsec_commit_required")
    path = Path(path).resolve(strict=True)
    values = []
    for arguments in (("rev-parse", "HEAD"), ("config", "--get", "remote.origin.url"),
                      ("status", "--porcelain", "--untracked-files=all")):
        result = run_cmd(["git", "-C", str(path), *arguments], timeout=15)
        require(result["status"] == "passed", "rustsec_identity_unavailable")
        values.append(result["stdout"].strip())
    commit, origin, changed = values
    require(commit == expected and not changed, "rustsec_database_changed")
    require(origin.lower().rstrip("/").removesuffix(".git") == "https://github.com/rustsec/advisory-db",
            "rustsec_database_origin_mismatch")
    return {"commit": commit, "source": "https://github.com/RustSec/advisory-db", "dirty": False}


def verify_cargo_audit(data):
    require(isinstance(data.get("database"), dict)
            and isinstance(data["database"].get("advisory-count"), int)
            and data["database"]["advisory-count"] > 0
            and isinstance(data.get("vulnerabilities"), dict)
            and data["vulnerabilities"].get("found") is False
            and data["vulnerabilities"].get("list") == []
            and data.get("lockfile", {}).get("dependency-count", 0) > 0
            and isinstance(data.get("warnings"), dict)
            and not any(data["warnings"].values()), "cargo_audit_incomplete_or_findings")


def original_server_notices(generation, metadata):
    """Use the already-shipped original notice when npm omits its own file."""
    identity = read_json(ROOT / "profiles/mcp/filesystem-readonly-v1/upstream-identity.json")
    selected = identity["package"]
    if (metadata.get("name"), metadata.get("version")) != (selected["name"], selected["version"]):
        return []
    profile = generation / "filesystem-profile"
    notices = [row for row in identity["upstreamNotices"] if row.get("component") == "server"]
    require(len(notices) == 1, "original_server_notice_identity_missing")
    result = []
    for row in notices:
        parts = PurePosixPath(row["path"]).parts
        require(len(parts) == 2 and parts[0] == "upstream-notices" and parts[1] not in {".", ".."},
                "original_server_notice_path")
        path = profile / row["path"]
        require(not path.is_symlink() and path.resolve().is_relative_to(profile.resolve())
                and sha(path) == row["sha256"], "original_server_notice_changed")
        result.append(path)
    return result


def python_tree(site):
    """One finite, non-symlink walk inside the already-verified selected tree."""
    require(site.is_dir() and not site.is_symlink(), "python_site_missing_or_symlink")
    directories, files = [], []
    for current, children, names in os.walk(site, followlinks=False):
        current = Path(current)
        require(len(current.relative_to(site).parts) <= 32, "python_tree_depth_limit")
        for name in sorted(children + names):
            path = current / name
            require(not path.is_symlink() and path.resolve().is_relative_to(site.resolve()),
                    "python_tree_unsafe_path")
            (directories if name in children else files).append(path)
            require(len(directories) + len(files) <= 100000, "python_tree_entry_limit")
    return directories, files


def python_identity(name, version):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name)
            and isinstance(version, str)
            and re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]{0,199}", version),
            "python_distribution_identity_missing_or_invalid")
    return "PyPI", python_name(name), version


def python_metadata(path):
    require(path.is_file() and path.stat().st_size <= MAX_OUTPUT_BYTES, "python_metadata_missing_or_size_limit")
    metadata = email.message_from_bytes(path.read_bytes())
    require(all(len(metadata.get_all(key, [])) == 1 for key in ("Name", "Version"))
            and len(metadata.get_all("License-Expression", [])) <= 1
            and len(metadata.get_all("License", [])) <= 1, "python_metadata_ambiguous")
    python_identity(metadata.get("Name"), metadata.get("Version"))
    return metadata


def python_notice_files(files, root, declared=()):
    result = {}
    declared_paths = set()
    for name in declared:
        relative = safe_relative(name)
        declared_paths.update((root.joinpath(*relative.parts), root / "licenses" / relative))
    for path in files:
        if path.is_relative_to(root) and (path in declared_paths or path.name.lower().startswith(
                ("license", "licence", "copying", "notice", "copyright", "authors"))):
            require(path.stat().st_size <= MAX_OUTPUT_BYTES, "python_notice_size_limit")
            result[str(path)] = sha(path)
    return result


def installed_python(site, expected):
    directories, files = python_tree(site)
    distributions = [path for path in directories if path.name.endswith(".dist-info")]
    require(len(distributions) <= 1000, "python_distribution_count_limit")
    top, vendored, notices, owners = set(), set(), [], {}
    recorded_code = set()
    for directory in sorted(distributions):
        metadata_path = directory / "METADATA"
        metadata = python_metadata(metadata_path)
        identity = python_identity(metadata["Name"], metadata["Version"])
        nested = directory.parent != site
        owner = None
        if nested:
            relative = directory.relative_to(site).parts
            require(len(relative) >= 3 and relative[:2] in {("pip", "_vendor"), ("setuptools", "_vendor")},
                    "unexpected_python_vendor_origin")
            owner = relative[0]
            directory_name, separator, directory_version = directory.name.removesuffix(".dist-info").rpartition("-")
            require(separator and python_name(directory_name) == identity[1] and directory_version == identity[2],
                    "python_vendor_metadata_identity_mismatch")
            record = directory / "RECORD"
            require(record in files and record.stat().st_size <= MAX_OUTPUT_BYTES,
                    "python_vendor_record_missing_or_size_limit")
            material = []
            for count, row in enumerate(csv.reader(record.read_text(encoding="utf-8").splitlines()), 1):
                require(count <= 100000, "python_vendor_record_count_limit")
                require(len(row) == 3 and row[0] and "\\" not in row[0], "python_vendor_record_invalid")
                path = PurePosixPath(row[0])
                require(not path.is_absolute() and not any(part in {".", ".."} for part in path.parts)
                        and ":" not in row[0], "python_vendor_record_unsafe_path")
                target = directory.parent.joinpath(*path.parts)
                if not target.is_relative_to(directory) and target.suffix in {".py", ".so", ".pyd"}:
                    require(target in files, "python_vendor_material_missing:" + identity[1])
                    material.append(target)
            require(material, "python_vendor_material_missing:" + identity[1])
            recorded_code.update(material)
            vendored.add(identity)
        else:
            require(not any(item[1] == identity[1] for item in top), "duplicate_installed_python_distribution")
            top.add(identity)
            owners[identity[1]] = directory
        notices.append({"ecosystem": "PyPI", "name": metadata["Name"], "version": metadata["Version"],
                        "license": metadata.get("License-Expression") or metadata.get("License"),
                        "license_declarations": {key: metadata.get_all(key, []) for key in
                                                 ("License-Expression", "License", "License-File", "Classifier")},
                        "origin": {"kind": "vendored_distribution" if nested else "installed_distribution",
                                   "owner": owner, "path": str(directory)},
                        "identity_files": {str(metadata_path): sha(metadata_path)},
                        "files": python_notice_files(files, directory, metadata.get_all("License-File", []))})
        if nested:
            notices[-1]["identity_files"][str(record)] = sha(record)
    # Only the top-level installed graph may satisfy the hashed wheel lock.
    require(expected <= top, "installed_python_graph_mismatch")
    require(all(name in {"pip", "setuptools"} for _, name, _ in top - expected),
            "unexpected_python_distribution")
    require(all(row["origin"]["owner"] in owners for row in notices
                if row["origin"]["kind"] == "vendored_distribution"), "python_vendor_owner_missing")
    setuptools_vendor = site / "setuptools/_vendor"
    setuptools_code = {path for path in files if path.is_relative_to(setuptools_vendor)
                       and path.suffix in {".py", ".so", ".pyd"} and path != setuptools_vendor / "__init__.py"}
    require(setuptools_code <= recorded_code, "python_vendor_unattributed_material")

    pip_vendor = site / "pip/_vendor"
    if site / "pip" in directories or pip_vendor in directories:
        require("pip" in owners, "python_vendor_owner_missing")
        require(pip_vendor in directories, "python_vendor_material_missing:pip")
        manifest = pip_vendor / "vendor.txt"
        require(manifest in files and manifest.stat().st_size <= MAX_OUTPUT_BYTES,
                "python_vendor_manifest_missing_or_size_limit")
        pins = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.partition("#")[0].strip()
            if not line:
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)", line)
            require(match is not None, "python_vendor_unpinned_requirement")
            identity = python_identity(match[1], match[2])
            require(identity[1] not in pins and len(pins) < 1000, "python_vendor_duplicate_or_count_limit")
            pins[identity[1]] = identity
        require(pins, "python_vendor_empty_manifest")
        require(all(python_name(row["name"]) in pins for row in notices if row["origin"]["owner"] == "pip"),
                "python_vendor_unpinned_metadata")
        material = set()
        for name, identity in sorted(pins.items()):
            # pip vendors only pkg_resources from this setuptools pin.
            module = "pkg_resources" if name == "setuptools" else name.replace("-", "_")
            package = pip_vendor / module
            if package not in directories:
                package = pip_vendor / (module + ".py")
            require(package in directories or package in files, "python_vendor_material_missing:" + name)
            require(package in files or any(path.is_relative_to(package) and path.suffix == ".py" for path in files),
                    "python_vendor_material_missing:" + name)
            material.add(package)
            matches = [row for row in notices if row["origin"]["owner"] == "pip"
                       and python_name(row["name"]) == name]
            require(all(row["version"] == identity[2] for row in matches), "python_vendor_version_mismatch")
            component_files = python_notice_files(files, package) if package in directories else {}
            # Modern wheels also retain pip's per-vendor notices under its dist-info.
            component_files.update(python_notice_files(files, owners["pip"] / "licenses/src/pip/_vendor" / module))
            if package in files:
                for path in files:
                    if path.parent == pip_vendor and path.name.lower().startswith(module.lower() + ".license"):
                        require(path.stat().st_size <= MAX_OUTPUT_BYTES, "python_notice_size_limit")
                        component_files[str(path)] = sha(path)
            vendored.add(identity)
            if not matches:
                notices.append({"ecosystem": "PyPI", "name": identity[1], "version": identity[2],
                                "license": None,
                                "origin": {"kind": "vendored_manifest", "owner": "pip", "path": str(package)},
                                "identity_files": {str(manifest): sha(manifest)}, "files": component_files})
        # Code without a manifest pin cannot silently disappear from coverage.
        immediate = {path for path in directories if path.parent == pip_vendor and path.name != "__pycache__"}
        immediate.update(path for path in files if path.parent == pip_vendor
                         and path.suffix == ".py" and path.name != "__init__.py")
        immediate = {path for path in immediate if not path.name.endswith(".dist-info")}
        require(immediate <= material, "python_vendor_unpinned_material")
    return notices, top | vendored


def safe_relative(value):
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value,
            "runtime_license_unsafe_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in {"", ".", ".."} for part in value.split("/")),
            "runtime_license_unsafe_path")
    return path


def bound_file(root, relative, digest):
    relative = safe_relative(relative)
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "runtime_license_digest_invalid")
    path = Path(root)
    require(path.is_dir() and not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents),
            "runtime_license_unsafe_path")
    for part in relative.parts:
        path = path / part
        require(not path.is_symlink(), "runtime_license_unsafe_path")
    require(path.resolve().is_relative_to(Path(root).resolve()) and path.is_file()
            and path.stat().st_size <= MAX_OUTPUT_BYTES and sha(path) == digest,
            "runtime_license_bound_file_changed:" + str(relative))
    return path


def runtime_license_provenance(generation):
    """Source evidence is usable only with the identical installed asset bundle."""
    source = ROOT / "profiles/mcp/git-readonly-v1"
    identity = read_json(source / "upstream-identity.json")
    binding = identity.get("runtime_license_provenance")
    installed = generation / "git-profile"
    receipt_path = installed / "installation.json"
    receipt_binding = None
    if receipt_path.exists():
        require(not receipt_path.is_symlink(), "runtime_license_unsafe_path")
        receipt_binding = read_json(receipt_path).get("upstream_identity", {}).get("runtime_license_provenance")
    if binding is None:
        require(receipt_binding is None, "runtime_license_source_binding_missing")
        return None
    require(isinstance(binding, dict) and set(binding) == {"path", "sha256"}
            and binding["path"] == "upstream-notices/runtime-licenses/provenance.json",
            "runtime_license_provenance_binding_invalid")
    source_path = bound_file(source, binding["path"], binding["sha256"])
    # Small unit fixtures predate prepared generation receipts. They must not
    # acquire source-only attribution. Real prepared generations have a receipt.
    if not receipt_path.exists() and not (installed / binding["path"]).exists():
        return None
    require(receipt_binding == binding, "runtime_license_installed_binding_mismatch")
    installed_path = bound_file(installed, binding["path"], binding["sha256"])
    data = read_json(source_path)
    require(data.get("format") == "sw-python-runtime-license-provenance/1"
            and isinstance(data.get("components"), list) and 0 < len(data["components"]) <= 1000,
            "runtime_license_provenance_schema")
    require(read_json(installed_path) == data, "runtime_license_installed_provenance_mismatch")
    keys = set()
    for row in data["components"]:
        key = provenance_key(row)
        require(key not in keys and row.get("observed_identity_files") and row.get("installed_notices")
                and "original_declared_license" in row and "original_license_declarations" in row,
                "runtime_license_component_schema")
        keys.add(key)
        evidence = row.get("source", {})
        require(evidence.get("archive_url", "").startswith("https://files.pythonhosted.org/")
                and all(re.fullmatch(r"[0-9a-f]{64}", evidence.get(key, ""))
                        for key in ("archive_sha256", "metadata_sha256"))
                and evidence.get("notices") and row.get("obligations")
                and isinstance(row.get("evidenced_spdx_expression"), str),
                "runtime_license_source_evidence_invalid")
        for notice in row.get("supplemental_notices", []):
            require(notice["path"] != "upstream-notices/runtime-licenses/provenance.json"
                    and safe_relative(notice["path"]).parts[:2] == ("upstream-notices", "runtime-licenses"),
                    "runtime_license_unsafe_path")
            bound_file(source, notice["path"], notice["sha256"])
            bound_file(installed, notice["path"], notice["sha256"])
    return {"binding": binding, "components": data["components"]}


def provenance_key(row):
    origin = row.get("origin", {})
    return (*python_identity(row["name"], row["version"]), row.get("ecosystem"),
            origin.get("kind"), origin.get("owner"))


def apply_runtime_license_provenance(notices, site, generation, provenance):
    """Resolve exact factual attribution; never bypass judge_spdx policy."""
    errors = []
    for notice in notices:
        notice["original_declared_license"] = notice.get("license")
        notice["effective_license"] = notice.get("license")
        if notice.get("ecosystem") != "PyPI" or provenance is None:
            continue
        matches = [row for row in provenance["components"] if provenance_key(row) == provenance_key(notice)]
        if not matches:
            continue
        require(len(matches) == 1, "runtime_license_ambiguous_mapping")
        row = matches[0]
        try:
            require(notice["license"] == row["original_declared_license"]
                    and notice.get("license_declarations") == row["original_license_declarations"]
                    and Path(notice["origin"]["path"]).relative_to(site).as_posix() == row["origin"]["path"],
                    "runtime_license_observed_identity_mismatch")
            actual_identity = {Path(path).relative_to(site).as_posix(): digest
                               for path, digest in notice["identity_files"].items()}
            require(actual_identity == row["observed_identity_files"], "runtime_license_observed_identity_mismatch")
            for path, digest in row["observed_identity_files"].items():
                bound_file(site, path, digest)
            parent = row.get("parent_distribution")
            if notice["origin"]["owner"] is not None:
                require(parent is not None and parent["name"] == notice["origin"]["owner"],
                        "runtime_license_parent_identity_mismatch")
                parents = [item for item in notices if item.get("ecosystem") == "PyPI"
                           and python_name(item["name"]) == parent["name"]
                           and item["version"] == parent["version"]
                           and item["origin"]["kind"] == "installed_distribution"]
                require(len(parents) == 1 and
                        {Path(path).relative_to(site).as_posix(): digest
                         for path, digest in parents[0]["identity_files"].items()} == parent["identity_files"],
                        "runtime_license_parent_identity_mismatch")
                for path, digest in parent["identity_files"].items():
                    bound_file(site, path, digest)
            source_digests = {item["sha256"] for item in row["source"]["notices"]}
            for path, digest in row["installed_notices"].items():
                actual = bound_file(site, path, digest)
                require(notice["files"].get(str(actual)) == digest and digest in source_digests,
                        "runtime_license_notice_mismatch")
            require(all(digest in source_digests for digest in notice["files"].values()),
                    "runtime_license_notice_mismatch")
            supplemental = {}
            for item in row.get("supplemental_notices", []):
                require(item["sha256"] in source_digests, "runtime_license_notice_mismatch")
                path = bound_file(generation / "git-profile", item["path"], item["sha256"])
                supplemental[str(path)] = item["sha256"]
            require(source_digests <= set(notice["files"].values()) | set(supplemental.values()),
                    "runtime_license_notice_incomplete")
            notice["files"].update(supplemental)
            notice["effective_license"] = row["evidenced_spdx_expression"]
            notice["attribution"] = {"status": "notice_verified", "provenance": provenance["binding"],
                                     "source": row["source"], "obligations": row["obligations"]}
        except (ValueError, OSError, KeyError, TypeError) as error:
            notice["effective_license"] = None
            notice["attribution"] = {"status": "rejected", "reason": str(error)}
            errors.append("runtime_license_provenance_mismatch:" + notice["name"] + ":" + str(error))
    return errors


def installed_graphs(generation, graphs):
    fs = read_json(generation / "filesystem-profile/profile.json")
    git = read_json(generation / "git-profile/profile.json")
    npm_graph = set()
    notices = []
    package_root = Path(fs["packageRoot"])
    lock = read_json(package_root / "package-lock.json")
    for relative, locked in lock["packages"].items():
        if not relative:
            continue
        directory = package_root / relative
        metadata = read_json(directory / "package.json")
        require(metadata["version"] == locked["version"], "installed_npm_version_mismatch")
        npm_graph.add(("npm", metadata["name"], metadata["version"]))
        files = [p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(
            ("license", "licence", "copying", "notice", "copyright"))]
        if not files:
            files = original_server_notices(generation, metadata)
        notices.append({"ecosystem": "npm", "name": metadata["name"], "version": metadata["version"],
                        "license": metadata.get("license"), "files": {str(p): sha(p) for p in files},
                        "origin": {"kind": "installed_package", "owner": None, "path": relative},
                        "identity_files": {str(directory / "package.json"): sha(directory / "package.json")}})
    site = Path(git["packageRoot"]) / "python/lib/python3.11/site-packages"
    expected = {next(iter(values))[0]: values for values in graphs.values()}
    require(npm_graph == expected["npm"], "installed_npm_graph_mismatch")
    python_notices, py_graph = installed_python(site, expected["PyPI"])
    notices.extend(python_notices)
    # The accepted interpreter archive also redistributes its bootstrap tools.
    # Scan these real installed versions rather than omitting them or adding
    # invented wheel hashes to the strict runtime installer lock.
    import license_policy
    policy = tomllib.loads((ROOT / "policy/license-policy.toml").read_text())
    errors = []
    provenance = None
    provenance_failure = None
    try:
        provenance = runtime_license_provenance(generation)
    except (ValueError, OSError, KeyError, TypeError) as error:
        provenance_failure = str(error)
        errors.append("runtime_license_provenance:" + str(error))
    errors.extend(apply_runtime_license_provenance(notices, site, generation, provenance))
    if provenance_failure is not None:
        for notice in python_notices:
            notice["effective_license"] = None
            notice["attribution"] = {"status": "rejected", "reason": provenance_failure}
    for notice in notices:
        expression = notice.get("effective_license")
        if not isinstance(expression, str) or not notice["files"]:
            notice["policy_disposition_required"] = True
            errors.append("runtime_license_notice_incomplete:" + notice["name"])
            continue
        status, selected, reason = license_policy.judge_spdx(expression, policy)
        notice["policy"] = {"status": status, "selected": selected, "reason": reason}
        notice["policy_disposition_required"] = status != "approved"
        if status != "approved":
            errors.append("runtime_license_review_required:" + notice["name"])
    return notices, py_graph, errors




def native_libraries(selection, generation, preparation):
    """Union profile libraries with every selected native executable closure."""
    libraries = {}
    for kind in ("filesystem", "git"):
        profile = read_json(generation / (kind + "-profile/profile.json"))
        for item in profile["libraries"]:
            require(item["path"] not in libraries or libraries[item["path"]] == item["sha256"],
                    "native_library_identity_conflict")
            libraries[item["path"]] = item["sha256"]
    git_profile = read_json(generation / "git-profile/profile.json")
    selected = {role: selection["files"][role] for role in preparation.PILOT.EXECUTABLE_ROLES}
    selected["git_python"] = {"path": git_profile["runtimePath"], "sha256": git_profile["runtimeSha256"]}
    executables = []
    for role, item in selected.items():
        require(sha(item["path"]) == item["sha256"], "native_selected_binary_changed")
        with Path(item["path"]).open("rb") as stream:
            magic = stream.read(4)
            if role == "npm" and magic != b"\x7fELF":
                # The pinned npm CLI is JavaScript, run by the separately
                # selected Node interpreter. Other script interpreters fail.
                stream.seek(0)
                require(stream.readline(128).strip() == b"#!/usr/bin/env node",
                        "native_selected_script_interpreter")
                continue
            require(magic == b"\x7fELF", "native_selected_elf_required")
        executables.append(Path(item["path"]))
    # Reuse the installer's finite missing-library/path/count checks. Packaged
    # Python libraries remain covered by its verified package tree/native review.
    for item in preparation.GIT.dependencies(executables, Path(git_profile["packageRoot"])):
        require(item["path"] not in libraries or libraries[item["path"]] == item["sha256"],
                "native_library_identity_conflict")
        libraries[item["path"]] = item["sha256"]
    for item in selected.values():
        require(sha(item["path"]) == item["sha256"], "native_selected_binary_changed")
    return libraries


def verify_native_libraries(data, selection, generation, preparation):
    libraries = native_libraries(selection, generation, preparation)
    supplied = data.get("system_libraries", {})
    require(set(supplied) == set(libraries), "system_library_review_coverage")
    for path, digest in libraries.items():
        item = supplied[path]
        require(item.get("sha256") == digest and sha(path) == digest and item.get("license")
                and item.get("sources") and item.get("notices")
                and all(sha(p) == value for p, value in item["notices"].items()),
                "system_library_review_incomplete")
    return libraries


def verify_native_reviews(path, selection, generation, *, preparation):
    """Explicit reviewer evidence for components outside package-manager scans."""
    require(path is not None, "native_reviews_required")
    data = read_json(path)
    require(data.get("format") == "sw-pilot-native-reviews/1", "native_review_schema")
    require(set(data.get("components", {})) == {"git", "bwrap", "node", "python", "git_python"}, "native_review_coverage")
    git_profile = read_json(generation / "git-profile/profile.json")
    expected_binaries = {role: item for role, item in selection["files"].items() if role in {"git", "bwrap", "node", "python"}}
    expected_binaries["git_python"] = {"path": git_profile["runtimePath"], "sha256": git_profile["runtimeSha256"]}
    upstream = read_json(ROOT / "profiles/mcp/git-readonly-v1/upstream-identity.json")
    pins = {"git": (upstream["git_version"], upstream["git_source_sha256"]),
            "git_python": (upstream["python"]["version"], upstream["python"]["sha256"]),
            "node": ("22.23.4", "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce"),
            "bwrap": ("0.13.1", "0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d")}
    for role, review in data["components"].items():
        require(review.get("binary_sha256") == expected_binaries[role]["sha256"], "native_review_binary_mismatch")
        if role in pins:
            require((review.get("version"), review.get("source_sha256")) == pins[role], "native_review_source_mismatch")
        else:
            version = subprocess.check_output([expected_binaries[role]["path"], "--version"], text=True, timeout=10).strip()
            require(version == "Python " + review.get("version", ""), "host_python_version_mismatch")
        require(review.get("status") == "reviewed" and review.get("findings") == []
                and review.get("version") and re.fullmatch(r"[0-9a-f]{64}", review.get("source_sha256", ""))
                and isinstance(review.get("sources"), list) and review["sources"]
                and all(url.startswith("https://") for url in review["sources"]), "native_advisory_review_incomplete")
        checked = datetime.fromisoformat(review["checked_at"].replace("Z", "+00:00"))
        require(checked.tzinfo is not None and checked <= datetime.now(timezone.utc), "native_review_timestamp")
        require(review.get("notices") and all(sha(p) == digest for p, digest in review["notices"].items()),
                "native_notice_mismatch")
    verify_native_libraries(data, selection, generation, preparation)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", "--receipt", dest="selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--native-reviews", type=Path)
    parser.add_argument("--runtime-reviews", type=Path,
                        help="explicit exact-material maintainer dispositions and compliance bundle; default blocks")
    parser.add_argument("--rustsec-db", type=Path,
                        help="explicit pre-fetched RustSec database; audit uses --no-fetch")
    parser.add_argument("--rustsec-commit", help="full expected commit of the explicit official RustSec checkout")
    parser.add_argument("--output", type=Path, default=ROOT / "target/runtime_inventory.json")
    args = parser.parse_args(argv)
    report = {"format": "sw-installed-runtime-inventory/1", "status": "incomplete",
              "checked_at": datetime.now(timezone.utc).isoformat(), "checks": {}, "errors": []}
    try:
        selection = read_json(args.selection)
        require(args.selection.name == "selection.json" and "prepared_profiles" in selection,
                "verified_installed_selection_required")
        spec = importlib.util.spec_from_file_location("inventory_preparation", ROOT / "scripts/prepare-installed-pilot.py")
        prep = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prep)
        prep.verify_generation(args.selection.parent, args.expected_commit, probe_native=False)
        report["source"] = selection["source"]
        report["selection_sha256"] = sha(args.selection)
        report["binaries"] = selection["files"]
        graphs = lock_graphs()
        before = {path: sha(path) for path in graphs}
        report["lock_sha256"] = before
        report["packages"] = {path: sorted(values) for path, values in graphs.items()}
        report["cargo_lock_components"] = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        report["notices"], python_graph, license_errors = installed_graphs(args.selection.parent, graphs)
        report["license_errors"] = license_errors
        report["errors"].extend(license_errors)
        report["python_graphs"] = {
            kind: sorted({python_identity(row["name"], row["version"]) for row in report["notices"]
                          if row["ecosystem"] == "PyPI"
                          and (row["origin"]["kind"] == "installed_distribution") == (kind == "top_level")})
            for kind in ("top_level", "vendored")}
        python_lock = next(path for path in graphs if path.endswith("requirements.lock"))
        scan_requirements = args.output.parent / (args.output.stem + "-installed-requirements.txt")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with scan_requirements.open("x", encoding="utf-8") as stream:
            os.chmod(scan_requirements, 0o600)
            stream.write("".join(name + "==" + version + "\n" for _, name, version in sorted(python_graph)))
        graphs.pop(python_lock)
        graphs[str(scan_requirements.resolve())] = python_graph
        report["scan_input_sha256"] = {path: sha(path) for path in graphs}
        report["packages"] = {path: sorted(values) for path, values in graphs.items()}
        report["scan_input_labels"] = {
            path: ("installed-python" if path == str(scan_requirements.resolve())
                   else (Path(path).relative_to(ROOT).as_posix() if Path(path).is_relative_to(ROOT)
                         else Path(path).name)) for path in graphs}
        # Test fixtures may use external artificial locks; real prepared inputs
        # are rooted in this exact clean source.
        try:
            if args.native_reviews is not None:
                report["native_reviews_input"] = {"sha256": runtime_reviews.file_sha(args.native_reviews), "data": read_json(args.native_reviews)}
            report["native_reviews"] = verify_native_reviews(args.native_reviews, selection, args.selection.parent, preparation=prep)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
            report["errors"].append("native_reviews:" + str(error))
        # Keep scanner invocation and its complete bounded raw result, including
        # failed reports. Exit 1 and informational findings are never waived.
        audit_command = ["cargo", "audit", "--json", "--file", str(ROOT / "Cargo.lock")]
        if args.rustsec_db is not None:
            report["rustsec_database"] = rustsec_identity(args.rustsec_db, args.rustsec_commit)
            audit_command.extend(["--no-fetch", "--db", str(args.rustsec_db.resolve(strict=True))])
        else:
            require(args.rustsec_commit is None, "rustsec_commit_requires_database")
        target = ROOT / "target"
        target.mkdir(exist_ok=True)
        license_temp = tempfile.TemporaryDirectory(prefix="runtime-inventory-license-", dir=target)
        license_path = Path(license_temp.name) / "report.json"
        commands = {
            "cargo_audit": audit_command,
            "rust_licenses": rust_license_command(license_path),
            "osv": ["osv-scanner", "scan", "source", "--format=json", "--all-packages", "--all-vulns", "--no-resolve",
                    *["--lockfile=" + ("requirements.txt:" if path.endswith("requirements.txt") else "") + path
                      for path in graphs]],
        }
        review_findings = []
        for name, command in commands.items():
            result = run_cmd(command)
            report["checks"][name] = result
            if name == "rust_licenses" and license_path.exists():
                report["rust_license_report"] = read_json(license_path)
            if result["status"] != "passed":
                if not (args.runtime_reviews is not None and name in {"osv", "cargo_audit"}
                        and result["status"] == "failed" and result.get("exit_code") == 1):
                    report["errors"].append(name + "_failed_or_incomplete")
                if name not in {"osv", "cargo_audit"} or result.get("exit_code") not in {0, 1}:
                    continue
            try:
                if name == "osv":
                    observation = osv_observation(json.loads(result["stdout"], object_pairs_hook=pairs), graphs)
                    report["osv_coverage"] = observation["coverage"]
                    report["findings"] = observation["findings"]
                    review_findings.extend(runtime_reviews.osv_findings(
                        observation["findings"], ROOT, scan_requirements))
                    if args.runtime_reviews is None:
                        require(not observation["findings"], "unresolved_osv_findings")
                elif name == "cargo_audit":
                    data = json.loads(result["stdout"], object_pairs_hook=pairs)
                    report["cargo_audit_report"] = data
                    if args.runtime_reviews is None:
                        verify_cargo_audit(data)
                    else:
                        maintenance = runtime_reviews.cargo_findings(data)
                        report["cargo_maintenance_findings"] = maintenance
                        review_findings.extend(maintenance)
            except (ValueError, TypeError, KeyError) as error:
                report["errors"].append(name + ":" + str(error))
        license_temp.cleanup()
        # Preserve policy results and scanner findings. A supplied review can
        # discharge only these exact license-review errors, never missing
        # notices, provenance failures, unknown warnings or scan failures.
        report["runtime_reviews_expected_binding"] = runtime_reviews.context(report)
        if args.runtime_reviews is not None:
            try:
                require(not args.runtime_reviews.is_symlink(), "runtime_reviews_symlink")
                review_input_sha = runtime_reviews.file_sha(args.runtime_reviews)
                data = read_json(args.runtime_reviews)
                review = runtime_reviews.Review(data, args.runtime_reviews, report,
                                               args.expected_commit, args.selection.parent)
                review.licenses(report["notices"])
                review.advisories(review_findings)
                require(all(name in report["checks"] and
                    report["checks"][name].get("exit_code") in {0, 1}
                    for name in ("osv", "cargo_audit")) and
                    "osv_coverage" in report and "cargo_maintenance_findings" in report,
                    "runtime_review_scanner_coverage_incomplete")
                report["runtime_reviews"] = review.finish()
                report["runtime_reviews_input_sha256"] = review_input_sha
                report["errors"] = [error for error in report["errors"]
                    if not error.startswith("runtime_license_review_required:")]
                require(runtime_reviews.file_sha(args.runtime_reviews) == review_input_sha, "runtime_reviews_changed")
            except (OSError, ValueError, KeyError, TypeError) as error:
                report["errors"].append("runtime_reviews:" + str(error))
        require(before == {path: sha(path) for path in before}, "lockfiles_changed_during_scan")
        require(report["scan_input_sha256"] == {path: sha(path) for path in graphs}, "scan_inputs_changed")
        if args.rustsec_db is not None:
            require(report["rustsec_database"] == rustsec_identity(args.rustsec_db, args.rustsec_commit),
                    "rustsec_database_changed_during_scan")
        prep.verify_generation(args.selection.parent, args.expected_commit, probe_native=False)
        if args.native_reviews is not None and "native_reviews" in report:
            require(runtime_reviews.file_sha(args.native_reviews) == report["native_reviews_input"]["sha256"],
                    "native_reviews_changed")
            verify_native_reviews(args.native_reviews, selection, args.selection.parent, preparation=prep)
        if "runtime_reviews" in report:
            require(runtime_reviews.file_sha(args.runtime_reviews) == report["runtime_reviews_input_sha256"], "runtime_reviews_changed")
            checked = runtime_reviews.Review(read_json(args.runtime_reviews), args.runtime_reviews, report,
                                            args.expected_commit, args.selection.parent)
            checked.licenses(report["notices"])
            checked.advisories(review_findings)
            checked.finish()
        if not report["errors"]:
            report["status"] = "checks_passed"
    except Exception as error:
        report["errors"].append(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        os.chmod(args.output, 0o600)
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "errors": report["errors"]}))
    return 0 if report["status"] == "checks_passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
