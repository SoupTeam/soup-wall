#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-command native standard-user acceptance for Windows audit retention.

Raw evidence stays in a new private local NTFS directory. The printed summary
contains counts and hashes only. A supported positive skipped by the Agent
self-test is a failure.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

import agent_audit_windows_io as secure


REPO = Path(__file__).resolve().parent.parent
SOURCE = (
    "Cargo.lock", "crates/agentfw/Cargo.toml",
    "crates/agentfw/src/audit.rs", "crates/agentfw/src/audit_retention_windows.rs",
    "crates/agentfw/src/private_file_windows.rs", "crates/agentfw/src/windows_read.rs",
    "crates/agentfw/src/self_test/windows.rs", "crates/agentfw/src/self_test/mod.rs",
    "crates/agentfw/src/config.rs", "crates/agentfw/src/main.rs", "crates/agentfw/src/native.rs",
    "scripts/agent-audit-report.py", "scripts/agent-audit-explorer.html",
    "scripts/agent_audit_windows_io.py",
    "scripts/sou95_windows_owned_acceptance.py",
)
SENTINEL = "SOU95_PRIVATE_SENTINEL_DO_NOT_PUBLISH"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest():
    h = hashlib.sha256()
    for name in SOURCE:
        h.update(name.encode() + b"\0" + bytes.fromhex(digest(REPO / name)))
    return h.hexdigest()


def private_file(path, body):
    secure.private_output(path, body)


def request(port, route, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(f"http://127.0.0.1:{port}{route}",
                                    data=data, headers=headers), timeout=4) as response:
        return json.load(response)


def owned_bytes(directory):
    return sum(entry.stat().st_size for entry in directory.iterdir()
               if entry.is_file() and (entry.name in {"writer.lock", "manifest.json", "manifest.pending"}
                                       or entry.name.startswith("segment-")))


def copy_store(source, target, manifest, *, missing=None, corrupt=None, partial=False):
    reader = secure.Reader(source)
    try:
        raw_manifest = reader.read("manifest.json", 65536)
        require(raw_manifest is not None, "source manifest vanished during copied controls")
        private_file(target / "manifest.json", raw_manifest)
        for segment in manifest["segments"]:
            name = f"segment-{segment['id']:020}.jsonl"
            if segment["id"] == missing:
                continue
            body = reader.read(name, manifest["limits"]["segment_size_bytes"])
            require(body is not None, "source segment vanished during copied controls")
            if segment["id"] == corrupt:
                require(body, "closed corruption control needs nonempty evidence")
                body = bytes([body[0] ^ 1]) + body[1:]
            if partial and not segment["closed"]:
                body += b'{"incomplete":'
            private_file(target / name, body)
    finally:
        reader.close()


def export_control(report_cli, directory, output, expected_notice, *selection):
    subprocess.run([sys.executable, str(report_cli), "--retained-dir", str(directory),
                    "--output", str(output), *selection], capture_output=True,
                   check=True, timeout=30)
    header = json.loads(output.read_bytes().split(b"\n", 1)[0])
    require(expected_notice in header["notices"],
            f"export omitted {expected_notice} notice")
    return header


def daemon_start(agent, home, port, stage, ordinal):
    out = stage / f"daemon-{ordinal}.stdout"
    err = stage / f"daemon-{ordinal}.stderr"
    private_file(out, b"")
    private_file(err, b"")
    env = dict(os.environ, USERPROFILE=str(home), HOME=str(home),
               PYTHONDONTWRITEBYTECODE="1")
    with out.open("ab") as stdout, err.open("ab") as stderr:
        process = subprocess.Popen([str(agent), "serve"], stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, env=env)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        require(process.poll() is None, "owned daemon exited before health")
        try:
            health = request(port, "/health")
            if (health.get("status") == "ok" and
                    health.get("audit", {}).get("mode") == "retained" and
                    health["audit"].get("state") == "healthy"):
                require(str(home) not in json.dumps(health), "health leaked a private path")
                return process
        except (urllib.error.URLError, TimeoutError, ValueError):
            time.sleep(0.1)
    daemon_stop(process)
    raise RuntimeError("owned daemon did not become healthy")


def daemon_stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=8)


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--native-test-binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    require(os.name == "nt", "native Windows is required")
    require(not ctypes.windll.shell32.IsUserAnAdmin(), "non-elevated standard user required")
    agent = args.agent.resolve(strict=True)
    native_tests = args.native_test_binary.resolve(strict=True)
    stage = args.output_dir.absolute()
    require(not stage.exists(), "output directory must be new")
    private_file(stage / "owner-marker", b"sou95-owned\n")
    focused = (("audit::retention::tests", 8),
               ("retained_sink_failure_withholds_native", 2))
    for label, expected in focused:
        test_run = subprocess.run([str(native_tests), label, "--test-threads=2"],
                                  capture_output=True, timeout=120)
        private_file(stage / f"focused-{expected}.stdout", test_run.stdout)
        private_file(stage / f"focused-{expected}.stderr", test_run.stderr)
        match = re.search(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored", test_run.stdout)
        require(test_run.returncode == 0 and match and int(match.group(1)) == expected,
                f"focused native {label} tests did not all execute and pass")
    work = stage / "work"
    private_file(work / "owner-marker", b"sou95-work\n")
    unsafe = stage / "unsafe-default-acl"
    unsafe.mkdir()
    try:
        reader = secure.Reader(unsafe)
    except secure.WinStoreError:
        unsafe_refused = True
    else:
        reader.close()
        unsafe_refused = False
    require(unsafe_refused, "unsafe existing directory was adopted")
    test_file = stage / "hardlink-control.txt"
    hardlink = stage / "hardlink-alias.txt"
    private_file(test_file, b"control\n")
    os.link(test_file, hardlink)
    reader = secure.Reader(stage)
    try:
        try:
            reader.read(test_file.name, 64)
        except secure.WinStoreError:
            hardlink_refused = True
        else:
            hardlink_refused = False
    finally:
        reader.close()
    require(hardlink_refused, "hard-linked owned file was accepted")
    hardlink.unlink()
    junction = stage / "junction-control"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(work)],
                             capture_output=True, timeout=10)
    require(created.returncode == 0, "standard-user junction control could not be created")
    try:
        try:
            reader = secure.Reader(junction)
        except secure.WinStoreError:
            junction_refused = True
        else:
            reader.close()
            junction_refused = False
        require(junction_refused, "junction store path was accepted")
    finally:
        junction.rmdir()
    pin = stage / "path-pin-control"
    private_file(pin / "marker", b"control\n")
    reader = secure.Reader(pin)
    try:
        try:
            pin.rename(stage / "path-pin-moved")
        except OSError:
            replacement_refused = True
        else:
            replacement_refused = False
            (stage / "path-pin-moved").rename(pin)
    finally:
        reader.close()
    require(replacement_refused, "held directory path was replaceable")
    baseline = REPO / "rule_baseline" / "rule_baseline.py"
    report = stage / "self-test.json"
    command = [str(agent), "self-test", "--agent", str(agent), "--classifier", "rule-baseline",
               "--classifier-script", str(baseline), "--classifier-sha256", digest(baseline),
               "--classifier-python", sys.executable, "--report", str(report),
               "--work-parent", str(work), "--keep-workspace", "--bounded-audit-retention",
               "--timeout-seconds", "240"]
    run = subprocess.run(command, capture_output=True, timeout=270)
    private_file(stage / "self-test.stdout", run.stdout)
    private_file(stage / "self-test.stderr", run.stderr)
    require(run.returncode == 0, "bounded native self-test failed; inspect private evidence")
    data = json.loads(report.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios", [])
    require(scenarios and all(item.get("status") == "passed" for item in scenarios),
            "native self-test has failed or skipped supported scenarios")
    by_id = {item.get("id"): item.get("observed", {}) for item in scenarios}
    require(len(by_id) == len(scenarios), "native scenario identity is ambiguous")
    for scenario in ("allowed_read", "useful_read_after_refusal"):
        observed = by_id.get(scenario, {})
        require(observed.get("outcome") == "released" and
                observed.get("mcp_child_executions") == 1,
                f"{scenario} did not execute and release exactly once")
    for scenario in ("protected_send_refused", "daemon_loss"):
        observed = by_id.get(scenario, {})
        require(observed.get("mcp_child_executions") == 0 and
                observed.get("receiver_deliveries") == 0 and
                observed.get("receiver_connections") == 0,
                f"{scenario} had an unapproved side effect")
    require(by_id.get("adversarial_result", {}).get("outcome") == "result_withheld" and
            by_id["adversarial_result"].get("marker_reached_client") is False,
            "injected native result was not withheld")
    cleanup = data.get("cleanup", {})
    require(cleanup.get("collector", {}).get("job_empty") is True and
            cleanup.get("collector", {}).get("reaped") is True and
            cleanup.get("daemon", {}).get("job_empty") is True and
            cleanup.get("daemon", {}).get("reaped") is True and
            cleanup.get("receiver", {}).get("socket_closed") is True,
            "native self-test left an owned process or receiver running")
    roots = list(work.glob("agentfw-self-test-*"))
    require(len(roots) == 1, "expected one owned self-test workspace")
    home = roots[0] / "home"
    profile = home / ".agentfw"
    retained = profile / "audit-retention"
    require(retained.is_dir(), "self-test did not create retained store")
    config_path = profile / "config.yaml"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["capture_unknown_raw"] = True
    config_path.write_text(json.dumps(config), encoding="utf-8")
    port = config["port"]
    token = (profile / "token").read_text(encoding="utf-8").strip()
    peak = owned_bytes(retained)
    hooks = 0
    duplicate_refused = False
    foreign = retained / "operator-note.txt"
    foreign.write_text("preserve", encoding="ascii")
    for ordinal in (1, 2):
        process = daemon_start(agent, home, port, stage, ordinal)
        try:
            if ordinal == 1:
                before = digest(retained / "manifest.json")
                duplicate = subprocess.run([str(agent), "audit-retention-recover", "--home", str(profile)],
                                           capture_output=True, timeout=10)
                duplicate_refused = duplicate.returncode != 0
                require(duplicate_refused and digest(retained / "manifest.json") == before,
                        "duplicate writer changed the store")
            for index in range(220):
                response = request(port, "/hook", {
                    "session_id": "sou95-owned-session", "hook_event_name": "SOU95FutureEvent",
                    "synthetic": SENTINEL + "x" * 1300, "ordinal": ordinal, "index": index,
                }, token)
                require(isinstance(response, dict), "hook response unavailable")
                hooks += 1
                peak = max(peak, owned_bytes(retained))
                require(peak <= config["audit_retention"]["total_disk_bytes"],
                        "owned store exceeded configured disk cap")
        finally:
            daemon_stop(process)
    manifest = json.loads((retained / "manifest.json").read_text(encoding="utf-8"))
    require(manifest["pruned_through"] > 0 and manifest["next_id"] >= 4,
            "real Agent records did not rotate and prune")
    require(foreign.read_text(encoding="ascii") == "preserve", "foreign file was changed")

    # Stage the exact manifest that a crash between sealing the active segment
    # and publishing its rotation would have left on disk.
    staged = json.loads(json.dumps(manifest))
    active = staged["segments"][-1]
    require(active["closed"] is False, "expected an active segment before rotation")
    active_bytes = (retained / f"segment-{active['id']:020}.jsonl").read_bytes()
    require(not active_bytes or active_bytes.endswith(b"\n"),
            "active segment already has an incomplete tail")
    active["closed"] = True
    active["bytes"] = len(active_bytes)
    active["sha256"] = hashlib.sha256(active_bytes).hexdigest()
    active["partial_tail"] = False
    staged["generation"] += 1
    private_file(retained / "manifest.pending", json.dumps(staged, separators=(",", ":")).encode())
    recovery = subprocess.run([str(agent), "audit-retention-recover", "--home", str(profile)],
                              capture_output=True, timeout=20)
    require(recovery.returncode == 0, "interrupted manifest publication did not recover")
    after = json.loads((retained / "manifest.json").read_text(encoding="utf-8"))
    require(after["generation"] > staged["generation"] and
            after["next_id"] == staged["next_id"] + 1 and
            not (retained / "manifest.pending").exists(),
            "recovery did not complete the interrupted rotation")
    peak = max(peak, owned_bytes(retained))
    require(peak <= config["audit_retention"]["total_disk_bytes"],
            "recovery exceeded the owned disk cap")
    export = stage / "retained-export.jsonl"
    html = stage / "retained-report.html"
    report_cli = REPO / "scripts" / "agent-audit-report.py"
    subprocess.run([sys.executable, str(report_cli), "--retained-dir", str(retained),
                    "--output", str(export)], check=True, timeout=30)
    subprocess.run([sys.executable, str(report_cli), "--input", str(export),
                    "--output", str(html)], check=True, timeout=30)
    viewer = html.read_text(encoding="utf-8")
    require(SENTINEL not in viewer and "Older segments were intentionally pruned" in viewer and
            "connect-src 'none'" in viewer,
            "viewer leaked sentinel, omitted the retention gap, or lost its no-network policy")
    reader = secure.Reader(stage)
    try:
        require(reader.read(export.name, 16 * 1024 * 1024) is not None,
                "private export verification failed")
    finally:
        reader.close()
    closed = next((segment["id"] for segment in after["segments"] if segment["closed"]), None)
    require(closed is not None, "range and corruption controls need a closed segment")
    selected = export_control(report_cli, retained, stage / "selected-export.jsonl",
                              "selected_range", "--from-segment", str(after["segments"][-1]["id"]))
    copy_store(retained, stage / "partial-copy", after, partial=True)
    partial = export_control(report_cli, stage / "partial-copy", stage / "partial-export.jsonl",
                             "partial_tail")
    copy_store(retained, stage / "missing-copy", after, missing=closed)
    missing = export_control(report_cli, stage / "missing-copy", stage / "missing-export.jsonl",
                             "missing_segment")
    require(missing["gaps"]["unexplained"] > 0, "missing segment gap count is absent")
    copy_store(retained, stage / "corrupt-copy", after, corrupt=closed)
    corrupt = export_control(report_cli, stage / "corrupt-copy", stage / "corrupt-export.jsonl",
                             "corrupt_segment")
    require(corrupt["gaps"]["corrupt"] > 0, "corrupt segment gap count is absent")
    summary = {
        "schema": "sou95-owned-windows-acceptance/1", "result": "passed",
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_clean": not subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True).strip(),
        "source_files_sha256": source_digest(), "agent_sha256": digest(agent),
        "native_test_sha256": digest(native_tests),
        "classifier_source_sha256": digest(baseline),
        "focused_retention_tests_executed": 8, "focused_native_audit_failure_tests_executed": 2,
        "platform": f"{platform.system()} {platform.release()} {platform.version()} {platform.machine()}",
        "duration_ms": round((time.monotonic() - started) * 1000),
        "config_sha256": digest(config_path), "native_scenarios_executed": len(scenarios),
        "native_scenarios_failed": 0, "native_scenarios_unsupported": 0,
        "native_allowed_executions": 2, "native_denied_child_effects": 0,
        "native_denied_receiver_effects": 0,
        "native_process_cleanup_verified": True,
        "hook_requests": hooks, "segments_created": after["next_id"] - 1,
        "pruned_through": after["pruned_through"], "peak_owned_bytes": peak,
        "owned_cap_bytes": config["audit_retention"]["total_disk_bytes"],
        "duplicate_writer_refused": duplicate_refused,
        "recovery_verified": True, "foreign_file_preserved": True,
        "unsafe_acl_refused": unsafe_refused, "hardlink_refused": hardlink_refused,
        "junction_refused": junction_refused, "path_replacement_refused": replacement_refused,
        "selected_range_reported": "selected_range" in selected["notices"],
        "partial_tail_reported": "partial_tail" in partial["notices"],
        "missing_segment_reported": missing["gaps"]["unexplained"],
        "corrupt_segment_reported": corrupt["gaps"]["corrupt"],
        "export_sha256": digest(export), "html_sha256": digest(html),
    }
    private_file(stage / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
