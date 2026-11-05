# SPDX-License-Identifier: Apache-2.0
"""Verify the installed demo and offline report from an external directory."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import subprocess


def qualify(args, door, home, env, report, *, load, require):
    work = args.output / "installed-tools"
    work.mkdir(mode=0o700)
    evidence = dict(source=report["source_before"], status="incomplete", cases=[], reports=[])
    report["installed_tools"] = evidence
    engine = load("installed_report_source_control", "roadmap_support.py")

    def call(command, *words, timeout=180):
        result = subprocess.run(
            [str(args.agentfw), "pilot", "--home", str(home), command, *map(str, words)],
            cwd=door.cwd, env=env, capture_output=True, timeout=timeout,
        )
        require(len(result.stdout) <= 2 * 1024 * 1024
                and len(result.stderr) <= 2 * 1024 * 1024, "installed_tools_output_bound")
        return result

    plan = call("demo")
    require(plan.returncode == 0 and json.loads(plan.stdout)["executed"] is False,
            "installed_demo_plan_failed")
    evidence["cases"].append(dict(id="demo-plan", status="passed"))
    demo = call("demo", "--run", "--selection", report["pilot_scope"]["demo_selection"],
                "--expected-commit", args.expected_commit, "--strace", args.strace,
                "--output", work / "demo", timeout=900)
    evidence["demo_exit"] = demo.returncode
    evidence["demo_stderr_sha256"] = hashlib.sha256(demo.stderr).hexdigest()
    demo_path = work / "demo/report.json"
    demo_raw = engine.safe_file(demo_path, engine.MAX_REPORT) if demo_path.exists() else None
    if demo_raw is not None:
        evidence["reports"].append(dict(path=demo_path.relative_to(args.output).as_posix(),
                                        bytes=len(demo_raw), sha256=hashlib.sha256(demo_raw).hexdigest()))
    require(demo.returncode == 0 and demo_raw is not None, "installed_demo_failed")
    demo_report = json.loads(demo.stdout)
    require(json.loads(demo_raw) == demo_report, "installed_demo_saved_report_mismatch")
    require(demo_report["status"] == "passed" and demo_report["fixture_cleanup"]["complete"],
            "installed_demo_incomplete")
    evidence["cases"].append(dict(id="installed-demo", status="passed",
                                  report_sha256=hashlib.sha256(demo.stdout).hexdigest()))
    inputs = work / "evidence"
    inputs.mkdir(mode=0o700)
    output = work / "support"
    support = call("roadmap-support", "--source", args.expected_commit,
                   "--evidence-dir", inputs, "--output", output)
    require(support.returncode == 0, "installed_support_failed")
    root = Path(__file__).resolve().parents[1]
    control = work / "source-control"
    with contextlib.redirect_stdout(io.StringIO()):
        code = engine.main([
            "--source", args.expected_commit, "--evidence-dir", str(inputs),
            "--index", str(root / "docs/operations/roadmap-support-index.json"),
            "--roadmap", str(root / "docs/ROADMAP.md"), "--output", str(control),
        ])
    require(code == 0, "support_source_control_failed")
    hashes = {}
    for name in ("report.json", "index.html"):
        path = output / name
        raw = engine.safe_file(path, engine.MAX_OUTPUT)
        hashes[name] = hashlib.sha256(raw).hexdigest()
        evidence["reports"].append(dict(path=path.relative_to(args.output).as_posix(),
                                        bytes=len(raw), sha256=hashes[name]))
        require(raw == (control / name).read_bytes(), "installed_support_parity_failed")
    require(call("roadmap-support", "--source", args.expected_commit,
                 "--evidence-dir", inputs, "--output", output).returncode != 0,
            "installed_support_replaced_output")
    evidence["cases"].append(dict(id="installed-support-parity", status="passed", hashes=hashes))
    evidence["status"] = "passed"
