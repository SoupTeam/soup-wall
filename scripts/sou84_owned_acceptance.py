#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned Linux acceptance for bounded Agent audit retention (synthetic only).

Runs the real native MCP self-test in bounded mode, restarts its installed
daemon twice, causes multiple genuine hook rotations, then verifies and views
the retained history. All raw inputs, logs and reports stay owner-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parent.parent
MAX_RSS_KIB = 256 * 1024
SENTINEL = "SOU84_PRIVATE_SENTINEL_DO_NOT_PUBLISH"
SOURCE_PATHS = (
    "crates/agentfw/src/audit.rs", "crates/agentfw/src/audit_retention.rs",
    "crates/agentfw/src/config.rs", "crates/agentfw/src/handlers.rs",
    "crates/agentfw/src/main.rs", "crates/agentfw/src/self_test/mod.rs",
    "crates/agentfw/src/self_test/unix.rs", "scripts/agent-audit-report.py",
    "scripts/sou84_owned_acceptance.py", "scripts/tests/test_agent_audit_explorer_browser.js",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_sha() -> str:
    digest = hashlib.sha256()
    for name in SOURCE_PATHS:
        digest.update(name.encode() + b"\0")
        digest.update(bytes.fromhex(sha(REPO / name)))
    return digest.hexdigest()


def private_write(path: Path, body: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)


def request(port: int, route: str, body: dict | None = None, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    encoded = json.dumps(body).encode() if body is not None else None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(f"http://127.0.0.1:{port}{route}",
                                            data=encoded, headers=headers), timeout=3) as response:
        return json.load(response)


def owned_bytes(directory: Path) -> int:
    return sum(entry.stat().st_size for entry in directory.iterdir() if entry.is_file())


def peak_rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def start(agent: Path, profile_home: Path, port: int, dest: Path, ordinal: int):
    out = (dest / f"daemon-{ordinal}.stdout").open("xb")
    err = (dest / f"daemon-{ordinal}.stderr").open("xb")
    try:
        proc = subprocess.Popen([str(agent), "serve"], stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err, start_new_session=True,
                                env={"HOME": str(profile_home), "PATH": "/usr/bin:/bin",
                                     "LANG": "C.UTF-8"})
    finally:
        out.close()
        err.close()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("owned daemon exited before health check")
        try:
            health = request(port, "/health")
            if (health.get("status") == "ok" and health.get("audit", {}).get("mode") == "retained" and
                    health["audit"].get("state") == "healthy" and
                    str(profile_home) not in json.dumps(health)):
                return proc
        except (urllib.error.URLError, TimeoutError, ValueError):
            time.sleep(0.1)
    stop(proc)
    raise RuntimeError("owned daemon did not become healthy")


def stop(proc) -> None:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("Linux is required")
    agent = args.agent.resolve(strict=True)
    if not agent.is_file() or not os.access(agent, os.X_OK):
        parser.error("--agent must name an executable regular file")
    dest = args.output_dir.absolute()
    if dest.exists() or dest.is_symlink():
        parser.error("--output-dir must be new")
    os.umask(0o077)
    dest.mkdir(mode=0o700)
    if stat.S_IMODE(dest.stat().st_mode) != 0o700:
        raise RuntimeError("output filesystem did not honor owner-only directory mode")
    work = dest / "work"
    work.mkdir(mode=0o700)
    classifier = REPO / "rule_baseline" / "rule_baseline.py"
    command = [str(agent), "self-test", "--agent", str(agent), "--classifier", "rule-baseline",
               "--classifier-script", str(classifier), "--classifier-sha256", sha(classifier),
               "--classifier-python", sys.executable, "--report", str(dest / "self-test.json"),
               "--work-parent", str(work), "--keep-workspace", "--bounded-audit-retention",
               "--timeout-seconds", "180"]
    result = subprocess.run(command, capture_output=True, timeout=210)
    private_write(dest / "self-test.stdout", result.stdout)
    private_write(dest / "self-test.stderr", result.stderr)
    if result.returncode != 0:
        raise RuntimeError("bounded native self-test failed; inspect private evidence")
    native_report = json.loads((dest / "self-test.json").read_text())
    scenarios = native_report.get("scenarios", [])
    if not scenarios or any(item.get("status") != "passed" for item in scenarios):
        raise RuntimeError("native positive/negative controls did not all pass")
    roots = list(work.glob("agentfw-self-test-*"))
    if len(roots) != 1:
        raise RuntimeError("expected one owned self-test workspace")
    profile_home = roots[0] / "home"
    profile = profile_home / ".agentfw"
    retained = profile / "audit-retention"
    if not retained.is_dir():
        raise RuntimeError("native self-test did not create bounded audit storage")
    config_path = profile / "config.yaml"
    config = json.loads(config_path.read_text())
    config["capture_unknown_raw"] = True
    private_write(dest / "accepted-config.json", json.dumps(config, indent=2).encode())
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    port = config["port"]
    token = (profile / "token").read_text().strip()
    peak_rss = 0
    peak_disk = owned_bytes(retained)
    hook_count = 0
    for ordinal in (1, 2):
        proc = start(agent, profile_home, port, dest, ordinal)
        try:
            for index in range(220):
                response = request(port, "/hook", {
                    "session_id": "sou84-owned-session", "hook_event_name": "SOU84FutureEvent",
                    "synthetic": SENTINEL + "x" * 1300, "ordinal": ordinal,
                    "index": index,
                }, token)
                if not isinstance(response, dict):
                    raise RuntimeError("hook response unavailable")
                hook_count += 1
                if index % 10 == 0:
                    peak_rss = max(peak_rss, peak_rss_kib(proc.pid))
                    peak_disk = max(peak_disk, owned_bytes(retained))
                    if peak_rss > MAX_RSS_KIB or peak_disk > config["audit_retention"]["total_disk_bytes"]:
                        raise RuntimeError("declared acceptance resource limit exceeded")
        finally:
            peak_rss = max(peak_rss, peak_rss_kib(proc.pid))
            peak_disk = max(peak_disk, owned_bytes(retained))
            stop(proc)
    manifest = json.loads((retained / "manifest.json").read_text())
    if manifest["pruned_through"] == 0 or manifest["next_id"] < 4:
        raise RuntimeError("real Agent records did not rotate and prune")
    report_cli = REPO / "scripts" / "agent-audit-report.py"
    export = dest / "retained-export.jsonl"
    html = dest / "retained-report.html"
    subprocess.run([sys.executable, str(report_cli), "--retained-dir", str(retained),
                    "--output", str(export)], check=True, timeout=30)
    subprocess.run([sys.executable, str(report_cli), "--input", str(export),
                    "--output", str(html)], check=True, timeout=30)
    text = html.read_text()
    if SENTINEL in text or "Older segments were intentionally pruned" not in text:
        raise RuntimeError("report leaked sentinel or omitted the retention gap")
    if stat.S_IMODE(export.stat().st_mode) != 0o600 or stat.S_IMODE(html.stat().st_mode) != 0o600:
        raise RuntimeError("private outputs lost owner-only mode")
    summary = {"schema": "sou84-owned-acceptance/1", "source_commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "agent_sha256": sha(agent), "config_sha256": sha(config_path),
        "source_files_sha256": source_sha(),
        "native_scenarios_passed": len(scenarios), "hook_requests": hook_count,
        "segments_created": manifest["next_id"] - 1,
        "segments_retained": len(manifest["segments"]),
        "pruned_through": manifest["pruned_through"],
        "peak_owned_bytes": peak_disk, "owned_cap_bytes": config["audit_retention"]["total_disk_bytes"],
        "peak_daemon_rss_kib": peak_rss, "tested_rss_limit_kib": MAX_RSS_KIB,
        "export_sha256": sha(export), "html_sha256": sha(html),
        "result": "passed"}
    private_write(dest / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
