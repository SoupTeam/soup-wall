#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Attest the compiler and interpreter inputs of the Linux pilot candidate (SOU-122).

The command compares what the checked-in pins (`profiles/toolchain/linux-pilot-toolchain.json`)
declare with what this checkout and this machine actually resolve: the source commit and
tree, `rust-toolchain.toml`, every workflow compiler reference, `rustc`/`cargo`, the host
target, `Cargo.lock`, the explicitly selected Python interpreter, the pinned package inputs
and the build scripts. Any mismatch or unavailable input is a refusal with a named check;
nothing is downloaded, installed or substituted. Every external command has a deadline.

Passing means the inputs are the reviewed ones. It does not claim that two builds produce
byte-identical binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "profiles/toolchain/linux-pilot-toolchain.json"
FORMAT = "sw-pilot-toolchain-attestation/1"
PINS_FORMAT = "sw-pilot-toolchain-pins/1"
MAX_BYTES = 8 * 1024 * 1024
EXECUTABLE_MAX_BYTES = 512 * 1024 * 1024  # real compiler/interpreter binaries are tens of MiB
COMMAND_TIMEOUT = 20
OUTPUT_LIMIT = 16384
EXACT = re.compile(r"^\d+\.\d+\.\d+$")
FLOATING = {"stable", "beta", "nightly"}
ACTION_REF = re.compile(r"uses:\s*([\w.-]+/[\w.-]+)@([^\s#]+)")


class Refusal(Exception):
    pass


def sha256_file(path: Path, limit: int = MAX_BYTES) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        remaining = limit + 1
        while remaining > 0:
            chunk = handle.read(min(65536, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining <= 0:
            raise Refusal("input_too_large:" + path.name)
    return digest.hexdigest()


def read_text(path: Path) -> str:
    if path.stat().st_size > MAX_BYTES:
        raise Refusal("input_too_large:" + path.name)
    return path.read_text(encoding="utf-8")


def run(command, cwd=ROOT, env=None, timeout=COMMAND_TIMEOUT):
    """Run one command with a deadline; never raise on a nonzero exit."""
    base = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "LC_ALL": "C",
            "RUSTUP_AUTO_INSTALL": "0", "RUSTUP_TOOLCHAIN_AUTO_INSTALL": "0"}
    for name in ("CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"):
        if name in os.environ:
            base[name] = os.environ[name]
    base.update(env or {})
    try:
        done = subprocess.run(command, cwd=str(cwd), env=base, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return None, "command not found: " + str(command[0])
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s: {command[0]}"
    out = (done.stdout + done.stderr).decode("utf-8", "replace")[:OUTPUT_LIMIT]
    return done.returncode, out


class Report:
    def __init__(self):
        self.checks = []
        self.resolved = {}
        self.declared = {}

    def check(self, name, ok, declared=None, resolved=None, detail=None):
        entry = {"check": name, "status": "pass" if ok else "fail"}
        if declared is not None:
            entry["declared"] = declared
        if resolved is not None:
            entry["resolved"] = resolved
        if detail:
            entry["detail"] = detail
        self.checks.append(entry)
        return ok

    @property
    def verified(self):
        return bool(self.checks) and all(c["status"] == "pass" for c in self.checks)


def load_pins(path: Path):
    try:
        pins = json.loads(read_text(path))
    except (OSError, ValueError) as error:
        raise Refusal("pins_unreadable:" + str(error)[:120])
    if not isinstance(pins, dict) or pins.get("format") != PINS_FORMAT:
        raise Refusal("pins_format_unsupported")
    rust = pins.get("rust") or {}
    if not EXACT.match(str(rust.get("version", ""))):
        raise Refusal("pinned_rust_version_not_exact")
    if not re.match(r"^[0-9a-f]{9,40}$", str(rust.get("commit_prefix", ""))):
        raise Refusal("pinned_rust_commit_missing")
    return pins


def lane_pin(pins, lane):
    """Compiler identity the selected lane must resolve to (main pin, or the documented native lane)."""
    rust = pins["rust"]
    if lane == "main":
        return {"version": rust["version"], "commit_prefix": rust["commit_prefix"], "host": rust["host"]}
    legacy = pins["legacy_lane"]
    return {"version": legacy["version"], "commit_prefix": legacy.get("commit_prefix"), "host": rust["host"]}


def check_source(report, root, expected_commit, allow_dirty):
    code, head = run(["git", "-C", str(root), "rev-parse", "HEAD"])
    if code != 0:
        report.check("source", False, detail="not a git checkout: " + head.strip()[:120])
        return
    commit = head.strip()
    _, tree = run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"])
    _, status = run(["git", "-C", str(root), "status", "--porcelain"])
    dirty = bool(status.strip())
    report.resolved["source"] = {"commit": commit, "tree": tree.strip(), "dirty": dirty}
    ok = (allow_dirty or not dirty)
    detail = None if ok else "working tree has uncommitted changes"
    if expected_commit is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
            ok, detail = False, "expected commit must be 40 hex characters"
        elif commit != expected_commit:
            ok, detail = False, "checkout is not the expected commit"
    report.check("source", ok, declared=expected_commit, resolved=commit, detail=detail)


def toolchain_channel(text):
    match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else None


def check_toolchain_file(report, root, pins, lane="main"):
    expected = pins["rust"]["version"]
    path = root / "rust-toolchain.toml"
    if lane == "native":
        wanted = pins["legacy_lane"]["version"]
        override = os.environ.get("RUSTUP_TOOLCHAIN")
        try:
            channel = toolchain_channel(read_text(path))
        except OSError as error:
            report.check("toolchain-file", False, declared=wanted, detail=str(error)[:120])
            return
        ok = override == wanted and channel == expected
        report.resolved["toolchain_file"] = {"channel": channel, "sha256": sha256_file(path), "env_RUSTUP_TOOLCHAIN": override}
        report.check("toolchain-file", ok, declared={"env_RUSTUP_TOOLCHAIN": wanted, "file_channel": expected},
                     resolved={"env_RUSTUP_TOOLCHAIN": override, "file_channel": channel},
                     detail=None if ok else "native lane needs RUSTUP_TOOLCHAIN=%s (the explicit override) and the checked-in file at %s" % (wanted, expected))
        return
    try:
        channel = toolchain_channel(read_text(path))
    except OSError as error:
        report.check("toolchain-file", False, declared=expected, detail=str(error)[:120])
        return
    ok = channel == expected and EXACT.match(channel or "") is not None
    detail = None
    if channel in FLOATING:
        detail = f"rust-toolchain.toml uses the floating channel {channel!r}"
    elif not ok:
        detail = "rust-toolchain.toml does not name the pinned exact release"
    report.resolved["toolchain_file"] = {"channel": channel, "sha256": sha256_file(path)}
    report.check("toolchain-file", ok, declared=expected, resolved=channel, detail=detail)


def workflow_refs(root):
    refs = {}
    directory = root / ".github/workflows"
    for path in sorted(directory.glob("*.y*ml")) if directory.is_dir() else []:
        for number, line in enumerate(read_text(path).splitlines(), 1):
            match = ACTION_REF.search(line)
            if match and match.group(1) == "dtolnay/rust-toolchain":
                refs.setdefault(str(path.relative_to(root)), []).append((number, match.group(2)))
    return refs


def check_workflow_refs(report, root, pins):
    pinned = pins["rust"]["version"]
    legacy = pins["legacy_lane"]
    allowed_legacy = set(legacy["workflows"])
    problems, counts = [], {}
    for file, items in workflow_refs(root).items():
        for number, ref in items:
            counts[ref] = counts.get(ref, 0) + 1
            if ref == pinned:
                continue
            if ref == legacy["version"] and file in allowed_legacy:
                continue
            reason = "floating" if ref in FLOATING else "unrecorded"
            problems.append(f"{file}:{number} @{ref} ({reason})")
    report.resolved["workflow_toolchain_refs"] = dict(sorted(counts.items()))
    report.check("workflow-toolchain-refs", not problems, declared={"pinned": pinned, "legacy": legacy["version"]},
                 resolved=dict(sorted(counts.items())), detail="; ".join(problems[:10]) or None)


def docker_declarations(root):
    found = {}
    for path in sorted((root / "deploy").glob("Dockerfile*")) if (root / "deploy").is_dir() else []:
        images = re.findall(r"^FROM\s+(rust:[^\s]+)", read_text(path), re.MULTILINE)
        if images:
            found[str(path.relative_to(root))] = images
    return found


def effective_executable(name, root):
    """Resolve the concrete file that running `name` would execute, or explain why it is ambiguous.

    A rustup shim (a proxy that is the `rustup` binary under another name) is resolved explicitly with
    `rustup which`, which honours RUSTUP_TOOLCHAIN and the toolchain file. Anything else on PATH must be
    the executable itself. Returns (path, how, problem).
    """
    found = shutil.which(name, path=os.environ.get("PATH", ""))
    if not found:
        return None, None, f"{name} was not found on PATH"
    try:
        real = Path(found).resolve(strict=True)
        sibling = Path(found).parent / "rustup"
        shim = real.name == "rustup" or (sibling.is_file() and os.path.samefile(sibling, found))
    except OSError as error:
        return None, None, f"{name} on PATH could not be resolved: {str(error)[:80]}"
    if not shim:
        return real, "path", None
    code, out = run([str(real if real.name == "rustup" else sibling), "which", name], cwd=root)
    lines = out.strip().splitlines() if code == 0 else []
    target = Path(lines[0]) if len(lines) == 1 else None
    if target is None or not target.is_absolute():
        return None, None, f"{name} is a rustup shim and `rustup which {name}` did not give one absolute path"
    try:
        return target.resolve(strict=True), "rustup-shim", None
    except OSError as error:
        return None, None, f"{name} resolved by rustup does not exist: {str(error)[:80]}"


def check_compiler(report, root, pins, lane="main"):
    rust = lane_pin(pins, lane)
    chosen, problems = {}, []
    for name in ("rustc", "cargo"):
        path, how, problem = effective_executable(name, root)
        if problem:
            problems.append(problem)
        else:
            chosen[name] = (path, how)
    if "rustc" not in chosen:
        report.check("compiler", False, declared=rust["version"],
                     detail="rustc unavailable or ambiguous (no toolchain is installed by this command): " + "; ".join(problems)[:200])
        return
    code, out = run([str(chosen["rustc"][0]), "-Vv"], cwd=root)
    if code != 0:
        report.check("compiler", False, declared=rust["version"],
                     detail="rustc unavailable or failed (no toolchain is installed by this command): " + out.strip()[:160])
        return
    release = re.search(r"^release:\s*(\S+)", out, re.MULTILINE)
    commit = re.search(r"^commit-hash:\s*([0-9a-f]+)", out, re.MULTILINE)
    host = re.search(r"^host:\s*(\S+)", out, re.MULTILINE)
    cargo_code, cargo_out = run([str(chosen["cargo"][0]), "-V"], cwd=root) if "cargo" in chosen else (None, "")
    cargo = re.search(r"^cargo\s+(\S+)", cargo_out)
    resolved = {"rustc_release": release and release.group(1), "rustc_commit": commit and commit.group(1),
                "host": host and host.group(1), "cargo_release": cargo and cargo.group(1)}
    report.resolved["compiler"] = resolved
    # Hash the executables that were actually invoked, and refuse if they are not the ones in the
    # sysroot that rustc reports: a same-version binary elsewhere on PATH must not pass unrecorded.
    sysroot_code, sysroot_out = run([str(chosen["rustc"][0]), "--print", "sysroot"], cwd=root)
    executables = {}
    if sysroot_code != 0 or not sysroot_out.strip():
        problems.append("could not resolve the rustc sysroot to check the selected executables")
    for name, (real, how) in chosen.items():
        try:
            if sysroot_code == 0 and sysroot_out.strip():
                expected = (Path(sysroot_out.strip().splitlines()[0]) / "bin" / name).resolve(strict=True)
                if expected != real:
                    problems.append("invoked %s (%s) is not the sysroot executable (%s); ambiguous resolution refused"
                                    % (name, real, expected))
                    continue
            executables[name] = {"path": str(real), "resolved_via": how,
                                 "sha256": sha256_file(real, EXECUTABLE_MAX_BYTES)}
        except (OSError, Refusal) as error:
            problems.append("%s executable could not be hashed: %s" % (name, str(error)[:80]))
    resolved["executables"] = executables
    if resolved["rustc_release"] != rust["version"]:
        problems.append(f"rustc {resolved['rustc_release']} is not the pinned {rust['version']}")
    if rust["commit_prefix"] is None:
        resolved["commit_pinned"] = False  # recorded in the report, not yet enforced for this lane
    elif not (resolved["rustc_commit"] or "").startswith(rust["commit_prefix"]):
        problems.append("rustc commit hash does not match the pin")
    if resolved["host"] != rust["host"]:
        problems.append(f"host target {resolved['host']} is not the pinned {rust['host']}")
    if "cargo" in chosen and (cargo_code != 0 or resolved["cargo_release"] != rust["version"]):
        problems.append(f"cargo {resolved['cargo_release']} is not the pinned {rust['version']}")
    report.check("compiler", not problems, declared=dict(rust, lane=lane),
                 resolved=resolved, detail="; ".join(problems) or None)


def check_lockfile(report, root):
    path = root / "Cargo.lock"
    try:
        text = read_text(path)
    except OSError as error:
        report.check("lockfile", False, detail=str(error)[:120])
        return
    version = re.search(r"^version\s*=\s*(\d+)", text, re.MULTILINE)
    packages = len(re.findall(r"^\[\[package\]\]", text, re.MULTILINE))
    code, tracked = run(["git", "-C", str(root), "ls-files", "--error-unmatch", "Cargo.lock"])
    ok = bool(version) and packages > 0 and code == 0
    report.resolved["lockfile"] = {"sha256": sha256_file(path), "format_version": version and int(version.group(1)),
                                   "packages": packages, "tracked": code == 0}
    report.check("lockfile", ok, resolved=report.resolved["lockfile"],
                 detail=None if ok else "Cargo.lock is missing, empty or not tracked")


def check_interpreter(report, python, role, pins):
    if python is None:
        report.check("interpreter", False, detail="--python is required: the interpreter is never chosen silently")
        return
    path = Path(python)
    if not path.is_absolute() or not path.is_file():
        report.check("interpreter", False, resolved=str(python), detail="provide an existing absolute interpreter path")
        return
    real = path.resolve()
    code, out = run([str(real), "-I", "-c",
                     "import sys,platform;print(platform.python_implementation());print('.'.join(map(str,sys.version_info[:3])))"])
    lines = out.split() if code == 0 else []
    if len(lines) < 2:
        report.check("interpreter", False, resolved=str(real), detail="interpreter did not report its version: " + out.strip()[:120])
        return
    implementation, version = lines[0], lines[1]
    resolved = {"executable": str(real), "sha256": sha256_file(real, EXECUTABLE_MAX_BYTES), "implementation": implementation, "version": version}
    report.resolved["interpreter"] = resolved
    wanted = pins["python"][role]
    problems = []
    if implementation != wanted["implementation"]:
        problems.append(f"{implementation} is not {wanted['implementation']}")
    if "version" in wanted and version != wanted["version"]:
        problems.append(f"Python {version} is not the pinned {wanted['version']}")
    if "minimum_version" in wanted:
        have = tuple(int(part) for part in version.split("."))
        need = tuple(int(part) for part in wanted["minimum_version"].split("."))
        if have < need:
            problems.append(f"Python {version} is older than {wanted['minimum_version']}")
    report.check("interpreter", not problems, declared={"role": role, **wanted}, resolved=resolved,
                 detail="; ".join(problems) or None)


def check_inputs(report, root, pins, git_archive, python_archive):
    inputs = pins["inputs"]
    problems, resolved = [], {}
    try:
        git_identity = json.loads(read_text(root / inputs["git_profile_identity"]))
        fs_identity = json.loads(read_text(root / inputs["filesystem_profile_identity"]))
        requirements = sha256_file(root / inputs["git_requirements_lock"])
        package_lock = sha256_file(root / inputs["filesystem_package_lock"])
    except (OSError, ValueError, KeyError) as error:
        report.check("pinned-inputs", False, detail="unreadable pinned input: " + str(error)[:120])
        return
    resolved["git_requirements_lock"] = requirements
    resolved["filesystem_package_lock"] = package_lock
    if requirements != git_identity.get("files", {}).get("requirements.lock"):
        problems.append("requirements.lock digest differs from the Git profile identity")
    if package_lock != fs_identity.get("packageLockSha256"):
        problems.append("package-lock.json digest differs from the filesystem profile identity")
    python = git_identity.get("python") or {}
    if python.get("version") != pins["python"]["git_runtime"]["version"]:
        problems.append("Git profile Python version differs from the pin")
    if not re.fullmatch(r"[0-9a-f]{64}", python.get("sha256", "")) or not str(python.get("url", "")).startswith("https://"):
        problems.append("Git profile Python archive is not pinned by URL and digest")
    if not re.fullmatch(r"[0-9a-f]{64}", git_identity.get("git_source_sha256", "")):
        problems.append("Git source archive is not pinned by digest")
    resolved["git_source_sha256"] = git_identity.get("git_source_sha256")
    resolved["python_archive_sha256"] = python.get("sha256")
    for label, supplied, expected in (("git_archive", git_archive, git_identity.get("git_source_sha256")),
                                      ("python_archive", python_archive, python.get("sha256"))):
        if supplied is None:
            continue
        path = Path(supplied)
        if not path.is_absolute() or not path.is_file():
            problems.append(f"provide an existing absolute --{label.replace('_', '-')} path")
            continue
        digest = sha256_file(path)
        resolved[label + "_supplied_sha256"] = digest
        if digest != expected:
            problems.append(f"supplied {label} does not match its pinned digest")
    report.resolved["pinned_inputs"] = resolved
    report.check("pinned-inputs", not problems, resolved=resolved, detail="; ".join(problems) or None)


def check_build_scripts(report, root, pins):
    digests, missing = {}, []
    for relative in pins["build_scripts"]:
        path = root / relative
        if path.is_file():
            digests[relative] = sha256_file(path)
        else:
            missing.append(relative)
    report.resolved["build_scripts"] = digests
    report.check("build-scripts", not missing, resolved={"files": len(digests)},
                 detail=("missing: " + ", ".join(missing)) if missing else None)


def attest(args):
    report = Report()
    started = time.monotonic()
    try:
        pins = load_pins(args.pins)
    except Refusal as error:
        report.check("pins", False, detail=str(error))
        return finish(report, started, args)
    report.declared = {"rust": pins["rust"], "legacy_lane": {"version": pins["legacy_lane"]["version"],
                                                              "workflows": pins["legacy_lane"]["workflows"]},
                       "python": pins["python"]}
    root = args.root
    for step in (lambda: check_source(report, root, args.expected_commit, args.allow_dirty),
                 lambda: check_toolchain_file(report, root, pins, getattr(args, "lane", "main")),
                 lambda: check_workflow_refs(report, root, pins),
                 lambda: check_compiler(report, root, pins, getattr(args, "lane", "main")),
                 lambda: check_lockfile(report, root),
                 lambda: check_interpreter(report, args.python, args.python_role, pins),
                 lambda: check_inputs(report, root, pins, args.git_archive, args.python_archive),
                 lambda: check_build_scripts(report, root, pins)):
        try:
            step()
        except Refusal as error:
            report.check("input", False, detail=str(error))
        except OSError as error:
            report.check("input", False, detail="unreadable input: " + str(error)[:120])
    report.resolved["docker_rust_images_declared"] = docker_declarations(root)
    return finish(report, started, args)


def finish(report, started, args):
    verified = report.verified
    document = {
        "format": FORMAT,
        "status": "verified" if verified else "refused",
        "checks": report.checks,
        "declared": report.declared,
        "resolved": report.resolved,
        "reproducibility": {
            "by_source_identity": verified,
            "byte_for_byte": "not claimed; deterministic binary equality is not demonstrated by this command",
        },
        "docker_lane_note": "Docker builder images are separate digest-pinned lanes and are listed, not verified here.",
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output = Path(args.output)
        if not output.is_absolute() or output.exists():
            print(json.dumps({"status": "refused", "reason": "output must be a new absolute path"}))
            return 2
        output.write_text(text, encoding="utf-8")
    sys.stdout.write(text if args.output is None else json.dumps({"status": document["status"], "report": str(args.output)}) + "\n")
    return 0 if verified else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pins", type=Path, default=PINS)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--lane", choices=("main", "native"), default="main",
                        help="main: the pinned compiler; native: the documented native Ubuntu lane (explicit RUSTUP_TOOLCHAIN)")
    parser.add_argument("--expected-commit", help="full 40-hex commit the checkout must be at")
    parser.add_argument("--python", help="absolute path of the interpreter to attest (never chosen silently)")
    parser.add_argument("--python-role", choices=("classifier", "git_runtime"), default="classifier")
    parser.add_argument("--git-archive", help="absolute path of a locally supplied git-2.51.2.tar.xz to digest-check")
    parser.add_argument("--python-archive", help="absolute path of the supplied pinned CPython archive to digest-check")
    parser.add_argument("--allow-dirty", action="store_true", help="development only: accept uncommitted changes")
    parser.add_argument("--output", type=Path, help="write the full report to a new absolute path")
    return attest(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
