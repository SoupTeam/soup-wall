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
    evidence = dict(source=report["source_before"], status="incomplete", cases=[])
    report["installed_tools"] = evidence

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
    require(demo.returncode == 0, "installed_demo_failed")
    demo_report = json.loads(demo.stdout)
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
    engine = load("installed_report_source_control", "roadmap_support.py")
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
        raw = (output / name).read_bytes()
        require(raw == (control / name).read_bytes(), "installed_support_parity_failed")
        hashes[name] = hashlib.sha256(raw).hexdigest()
    require(call("roadmap-support", "--source", args.expected_commit,
                 "--evidence-dir", inputs, "--output", output).returncode != 0,
            "installed_support_replaced_output")
    evidence["cases"].append(dict(id="installed-support-parity", status="passed", hashes=hashes))
    evidence["status"] = "passed"
