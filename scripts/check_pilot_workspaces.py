#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux-only synthetic CLI witnesses; never inspects an operator repository."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


MAX_TRACE = 8 * 1024 * 1024
MUTATIONS = {
    "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir",
    "mkdirat", "rmdir", "chmod", "fchmod", "fchmodat", "chown", "fchown",
    "lchown", "fchownat", "truncate", "ftruncate", "link", "linkat", "symlink",
    "symlinkat", "mknod", "mknodat", "utime", "utimes", "utimensat", "mount",
}
NETWORK = {"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
           "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
           "getsockname", "getpeername", "getsockopt", "setsockopt", "shutdown"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def analyze_trace(raw):
    require(len(raw) <= MAX_TRACE, "trace_bound")
    rows = raw.decode("utf-8", errors="strict").splitlines()
    counts = {"exec": 0, "children": 0, "network": 0, "mutation_intents": 0}
    for line in rows:
        match = re.match(r"(?:\d+\s+)?([a-z][a-z0-9_]*)\((.*)", line)
        if not match:
            # strace signal/exit annotations are not syscalls. Unfinished calls
            # cannot be silently omitted from the effect witness.
            require("<unfinished ...>" not in line and "resumed>" not in line,
                    "incomplete_trace")
            require(not line.strip() or "--- SIG" in line or "+++ exited" in line,
                    "unknown_trace_line")
            continue
        name, args = match.groups()
        require("<unfinished ...>" not in args, "incomplete_trace")
        counts["exec"] += name in {"execve", "execveat"}
        counts["children"] += name in {"fork", "vfork", "clone", "clone3"}
        counts["network"] += name in NETWORK
        mutation = name in MUTATIONS
        if name in {"open", "openat", "openat2"}:
            mutation |= bool(re.search(r"\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)\b", args))
        if name in {"write", "writev", "pwrite64", "pwritev", "pwritev2"}:
            # Only stdout/stderr are allowed write targets; fixture writes are
            # performed by this parent before tracing, never by the inspector.
            mutation |= not bool(re.match(r"[12],", args))
        mutation |= name == "mmap" and "PROT_WRITE" in args and "MAP_SHARED" in args
        mutation |= name in {"io_uring_setup", "io_uring_enter"}
        counts["mutation_intents"] += bool(mutation)
    require(counts["exec"] == 1, "helper_execution")
    require(counts["children"] == 0, "child_execution")
    require(counts["network"] == 0, "network_effect")
    require(counts["mutation_intents"] == 0, "write_or_repair_effect")
    return counts


def snapshot(root):
    # Independent test witness: reads synthetic fixture content, not the CLI's
    # metadata implementation. Access times are not an asserted invariant.
    records = {}
    for path in [root, *sorted(root.rglob("*"))]:
        meta = path.lstat()
        relative = str(path.relative_to(root))
        content = (os.readlink(path) if path.is_symlink() else
                   digest(path.read_bytes()) if stat.S_ISREG(meta.st_mode) else None)
        records[relative] = [meta.st_mode, meta.st_uid, meta.st_gid, meta.st_ino,
                             meta.st_mtime_ns, meta.st_ctime_ns, content]
    return records


def source(repo):
    require(subprocess.run(["git", "-C", str(repo), "diff", "--quiet", "HEAD", "--"],
                           capture_output=True).returncode == 0, "dirty_source")
    return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()


def run_case(binary, tracer, root, kind):
    files, git, helpers = root / "files", root / "repository", root / "helpers"
    for path in (files, git, helpers):
        path.mkdir(mode=0o700)
    (git / ".git").mkdir()
    config = "[core]\nbare = false\nrepositoryformatversion = 0\n"
    (git / ".git/config").write_text(config, encoding="utf-8")
    (git / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (files / "note").write_text("synthetic untrusted text", encoding="utf-8")
    marker = root / "forbidden-helper-effect"
    for name in ("git", "sh", "curl", "wget", "ssh"):
        helper = helpers / name
        helper.write_text('#!/bin/sh\nprintf forbidden > "' + str(marker) + '"\n', encoding="utf-8")
        helper.chmod(0o700)
    expected, reason = "supported", None
    profile = "v1"
    if kind == "helper-config":
        (git / ".git/config").write_text(config + "fsmonitor = " + str(helpers / "git") + "\n", encoding="utf-8")
        expected, reason = "unsupported", "git_config_unsupported"
    elif kind == "attributes":
        (git / ".gitattributes").write_text("* filter=untrusted\n", encoding="utf-8")
        expected, reason = "unsupported", "git_attributes_unsupported"
    elif kind == "alternates":
        (git / ".git/objects/info").mkdir(parents=True)
        (git / ".git/objects/info/alternates").write_text("/synthetic/outside\n", encoding="utf-8")
        expected, reason = "unsupported", "git_object_indirection_unsupported"
    elif kind == "symlink":
        (files / "link").symlink_to(root)
        expected, reason = "unsupported", "unsafe_link_or_special_file"
    elif kind == "local-clone":
        profile = "local-clone"
        (git / ".git/config").write_text(config + '[remote "origin"]\nurl = https://synthetic-user:synthetic-token@example.invalid/repo\n', encoding="utf-8")
        expected, reason = "conditional", "selected_profile_requires_runtime_proof"
    trace = root.parent / (kind + ".trace")
    before = snapshot(root)
    environment = {**os.environ, "PATH": str(helpers), "HOME": str(root),
                   "AGENTFW_HOME": str(root / "absent-daemon-home")}
    result = subprocess.run([str(tracer), "-f", "-qq", "-o", str(trace),
        "-e", "trace=%process,%network,%file,write,pwrite64,writev,pwritev,pwritev2,ftruncate,fchmod,fchown,mmap,msync,io_uring_setup,io_uring_enter",
        str(binary), "pilot-workspaces", "--workspace", str(files),
        "--git-workspace", str(git), "--git-profile-kind", profile],
        capture_output=True, timeout=30, env=environment)
    require(snapshot(root) == before, "workspace_changed")
    require(not marker.exists(), "helper_marker_present")
    require(trace.stat().st_size <= MAX_TRACE, "trace_bound")
    raw = trace.read_bytes()
    counts = analyze_trace(raw)
    require(len(result.stdout) <= 16384 and len(result.stderr) <= 4096, "output_bound")
    report = json.loads(result.stdout)
    require(report["format"] == "sw-pilot-workspace-inspection/1", "report_schema")
    require(report["state"] == expected, "unexpected_state")
    require(result.returncode == (0 if expected == "supported" else 1), "unexpected_exit")
    require(not report["executed"] and not report["launch_authorized"]
            and not report["runtime_protection_verified"], "authority_claim")
    require(reason is None or any(c["reason"] == reason for c in report["checks"]), "missing_reason")
    for forbidden in (str(root), "synthetic-user", "synthetic-token", "example.invalid"):
        require(forbidden.encode() not in result.stdout + result.stderr, "private_output")
    return {"id": kind, "status": "pass", "state": expected, "exit_code": result.returncode,
            "syscalls": counts, "trace_sha256": digest(raw), "workspace_unchanged": True,
            "helper_marker_absent": True, "report": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = {"format": "sw-pilot-workspace-witness/1", "status": "incomplete", "cases": [],
              "scope": "synthetic-linux-inspection-only", "runtime_protection_verified": False}
    # Keep incomplete attempts too. The private output directory must be new.
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        require(sys.platform == "linux", "native_linux_required")
        binary = args.agentfw.resolve(strict=True)
        tracer = shutil.which("strace")
        require(tracer is not None, "strace_required_no_hidden_skip")
        repo = Path(__file__).resolve().parents[1]
        report["source_before"] = source(repo)
        require(report["source_before"] == args.expected_commit, "source_mismatch")
        report["source_tree"] = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True).strip()
        report["environment"] = {"system": os.uname().sysname,
                                 "kernel_release": os.uname().release,
                                 "architecture": os.uname().machine}
        report["binary_sha256"] = digest(binary.read_bytes())
        report["driver_sha256"] = digest(Path(__file__).read_bytes())
        with tempfile.TemporaryDirectory(prefix="sou144-synthetic-") as temporary:
            root = Path(temporary)
            for kind in ("supported", "helper-config", "attributes", "alternates", "symlink", "local-clone"):
                case = root / kind
                case.mkdir(mode=0o700)
                report["cases"].append(run_case(binary, Path(tracer), case, kind))
        report["source_after"] = source(repo)
        require(report["source_after"] == report["source_before"], "source_changed")
        report["status"] = "pass"
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        report["reason"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
