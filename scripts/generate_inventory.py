#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the selected installed pilot, exact scanner graphs and runtime notices.

An upstream-identity.json is source metadata, never an installed selection. All
incomplete checks and findings remain blocking; this command cannot publish.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import email
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib

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
            process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
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
            return {"status": "incomplete", "command": command, "reason": str(error)}
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def python_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_graphs(root=ROOT):
    root = Path(root)
    cargo = root / "Cargo.lock"
    py = root / "profiles/mcp/git-readonly-v1/requirements.lock"
    node = root / "profiles/mcp/filesystem-readonly-v1/package-lock.json"
    rust = tomllib.loads(cargo.read_text())["package"]
    cargo_graph = {("crates.io", p["name"], p["version"]) for p in rust if p.get("source")}
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


def verify_osv(data, graphs):
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
            observed[path].add((eco, name, version))
            require(isinstance(row.get("vulnerabilities", []), list), "osv_findings_schema")
            findings.extend(row.get("vulnerabilities", []))
    for path, expected in graphs.items():
        require(observed[path] == expected, "osv_exact_graph_mismatch:" + Path(path).name)
    require(not findings, "unresolved_osv_findings")
    return {path: len(packages) for path, packages in observed.items()}


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
        notices.append({"ecosystem": "npm", "name": metadata["name"], "version": metadata["version"],
                        "license": metadata.get("license"), "files": {str(p): sha(p) for p in files}})
    py_graph = set()
    site = Path(git["packageRoot"]) / "python/lib/python3.11/site-packages"
    for directory in sorted(site.glob("*.dist-info")):
        metadata = email.message_from_bytes((directory / "METADATA").read_bytes())
        name, version = metadata.get("Name"), metadata.get("Version")
        require(bool(name) and bool(version), "python_distribution_identity_missing")
        # Bootstrap packages from the pinned interpreter archive are inventoried
        # and scanned even when absent from the server's wheel lock.
        py_graph.add(("PyPI", python_name(name), version))
        files = [p for p in directory.rglob("*") if p.is_file() and (
            "license" in p.name.lower() or p.name.lower().startswith(("copying", "notice")))]
        notices.append({"ecosystem": "PyPI", "name": name, "version": version,
                        "license": metadata.get("License-Expression") or metadata.get("License"),
                        "files": {str(p): sha(p) for p in files}})
    expected = {next(iter(values))[0]: values for values in graphs.values()}
    require(npm_graph == expected["npm"], "installed_npm_graph_mismatch")
    require(expected["PyPI"] <= py_graph, "installed_python_graph_mismatch")
    extra = py_graph - expected["PyPI"]
    require(all(name in {"pip", "setuptools"} for _, name, _ in extra), "unexpected_python_distribution")
    # The accepted interpreter archive also redistributes its bootstrap tools.
    # Scan these real installed versions rather than omitting them or adding
    # invented wheel hashes to the strict runtime installer lock.
    import license_policy
    policy = tomllib.loads((ROOT / "policy/license-policy.toml").read_text())
    errors = []
    for notice in notices:
        expression = notice.get("license")
        if not isinstance(expression, str) or not notice["files"]:
            errors.append("runtime_license_notice_incomplete:" + notice["name"])
            continue
        status, selected, reason = license_policy.judge_spdx(expression, policy)
        notice["policy"] = {"status": status, "selected": selected, "reason": reason}
        if status != "approved":
            errors.append("runtime_license_review_required:" + notice["name"])
    return notices, py_graph, errors



def verify_native_reviews(path, selection, generation):
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
            "node": ("22.22.0", "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37"),
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
    libraries = {}
    for kind in ("filesystem", "git"):
        profile = read_json(generation / (kind + "-profile/profile.json"))
        libraries.update({item["path"]: item["sha256"] for item in profile["libraries"]})
    supplied = data.get("system_libraries", {})
    require(set(supplied) == set(libraries), "system_library_review_coverage")
    for path, digest in libraries.items():
        item = supplied[path]
        require(item.get("sha256") == digest and sha(path) == digest and item.get("license")
                and item.get("sources") and item.get("notices")
                and all(sha(p) == value for p, value in item["notices"].items()), "system_library_review_incomplete")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", "--receipt", dest="selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--native-reviews", type=Path)
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
        report["notices"], python_graph, license_errors = installed_graphs(args.selection.parent, graphs)
        report["errors"].extend(license_errors)
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
        try:
            report["native_reviews"] = verify_native_reviews(args.native_reviews, selection, args.selection.parent)
        except (OSError, ValueError, KeyError, TypeError) as error:
            report["errors"].append("native_reviews:" + str(error))
        # Keep scanner invocation and its complete bounded raw result, including
        # failed reports. Exit 1 and informational findings are never waived.
        commands = {
            "cargo_audit": ["cargo", "audit", "--json", "--file", str(ROOT / "Cargo.lock")],
            "rust_licenses": [sys.executable, str(ROOT / "scripts/license_policy.py"), "--root", str(ROOT),
                              "--report", str(args.output.parent / "rust-license-policy.json")],
            "osv": ["osv-scanner", "scan", "source", "--format=json", "--all-packages",
                    *["--lockfile=" + ("requirements.txt:" if path.endswith("requirements.txt") else "") + path
                      for path in graphs]],
        }
        for name, command in commands.items():
            result = run_cmd(command)
            report["checks"][name] = result
            if result["status"] != "passed":
                report["errors"].append(name + "_failed_or_incomplete")
                continue
            try:
                if name == "osv":
                    report["osv_coverage"] = verify_osv(json.loads(result["stdout"], object_pairs_hook=pairs), graphs)
                elif name == "cargo_audit":
                    data = json.loads(result["stdout"], object_pairs_hook=pairs)
                    require(isinstance(data.get("vulnerabilities"), dict)
                            and data["vulnerabilities"].get("found") is False
                            and data["vulnerabilities"].get("list") == []
                            and data.get("lockfile", {}).get("dependency-count", 0) > 0
                            and isinstance(data.get("database"), dict)
                            and not any(data.get("warnings", {}).values()), "cargo_audit_incomplete_or_findings")
            except (ValueError, TypeError, KeyError) as error:
                report["errors"].append(name + ":" + str(error))
        require(before == {path: sha(path) for path in before}, "lockfiles_changed_during_scan")
        require(report["scan_input_sha256"] == {path: sha(path) for path in graphs}, "scan_inputs_changed")
        prep.verify_generation(args.selection.parent, args.expected_commit, probe_native=False)
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
