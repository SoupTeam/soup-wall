#!/usr/bin/env python3
"""Regenerate the sanitized SOU-228 test fixtures from the original GitHub artifact reports.

Usage (after the digest-verified preparation in docs/operations/ROADMAP_SUPPORT_REPORT.md):

    python3 -I scripts/tests/fixtures/sou228/sanitize.py "$evidence" NEW_OUTPUT_DIR

`$evidence` must contain the extracted originals under `sou-228/<run>/`. The output is
byte-identical to the committed fixtures. Rules, applied to every report the same way:

* drop host, account, process, timing and sealed-provenance fields (`DROP`), and keep
  only the precondition flags of `environment` (`KEEP_ENV`);
* replace any string that looks like a host path with `<redacted>`;
* keep every other value exactly as in the original;
* rebind the clean-user report's companion hashes and embedded user-session
  observation to the sanitized companions, so the fixture set stays self-consistent.

Deliberately retained: epoch-millisecond Ask timing values (the run times are public
GitHub metadata) and random 32-hex pilot generation IDs from disposable runner state.
Neither identifies a host, account or credential.

`provenance.json` records, per fixture, its own SHA-256, the immutable original report
member SHA-256 and the GitHub artifact ZIP digest. These are three different hashes.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

DROP = {"uid", "gid", "user_namespace", "boot_identity_sha256", "kernel", "run_id", "run_attempt", "job",
        "runner_image", "pid", "start_time_ticks", "observed", "recipient_certificate_sha256",
        "private_provenance", "private_provenance_sha256", "encrypted_provenance_sha256", "context_before",
        "before", "after", "quiescence", "empty_vendor_user_units", "host_runs", "bindings", "steps", "results",
        "stderr_hint", "compiler_inputs", "evidence", "programs", "last_cli", "native_source_build_seconds",
        "observed_at", "elapsed_seconds", "elapsed_ms", "run_ids", "started_at_ms", "setup_seconds",
        "decision_to_result_ms", "trace_sha256", "strace_sha256", "removal_preview", "preview_attempts", "batches",
        "raw_archives", "profiles", "python", "environment_note", "descendants", "descendant_count", "remaining",
        "native_codes", "claude_version", "limits", "benign_workflows"}
# Binary identity maps keep every role, including `python`.
IDENTITY_MAPS = ("selected_sha256", "inputs_sha256")
KEEP_ENV = {"ordinary_user", "effective_capabilities", "unassisted_stock_host_acceptance", "fresh_private_home",
            "sandbox_precondition", "os", "machine"}
PATHLIKE = re.compile(r"(^/|/home/|/tmp/|/proc/|/usr/|/opt/|runner|_temp|\\\\)")
ARTIFACTS = {
    "41818201020": (13316278678, "sou215-pilot-scope-41818201020-1",
                    "864669ba33cb5df823e44d1c52c408948bcd342754bef38a3feab3d60ba44f1b"),
    "41818211366": (13316597197, "sou216-clean-user-41818211366-1",
                    "ffa3b7a3f30f6707acdd1f5a2ac62128eab4557b1d4dca12ab8a032379faa1b1"),
    "41818225908": (13317206981, "sou216-clean-user-41818225908-1",
                    "8daccd83d0f88d49bbc5152bcedd2fdbaa32e51c49c03bace5fc15db5c95d6a3"),
}
DESCRIPTION = ("Sanitized SOU-228 fixtures. fixture_sha256 is the committed test file; original_sha256 is the "
               "immutable report member inside the GitHub artifact ZIP; artifact_zip_sha256 is GitHub's digest "
               "of the whole ZIP.")


def clean(value, key=None):
    if isinstance(value, dict):
        out = {}
        for name, child in value.items():
            if name in DROP and key not in IDENTITY_MAPS:
                continue
            if key == "environment" and name not in KEEP_ENV:
                continue
            out[name] = clean(child, name)
        return out
    if isinstance(value, list):
        return [clean(child, key) for child in value]
    if isinstance(value, str) and PATHLIKE.search(value):
        return "<redacted>"
    return value


def main(source: Path, output: Path) -> None:
    output.mkdir(parents=False, exist_ok=False)
    manifest = []

    def write(relative, obj):
        raw = (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        artifact, name, zip_sha256 = ARTIFACTS[relative.split("/")[1]]
        manifest.append({"path": relative, "fixture_sha256": hashlib.sha256(raw).hexdigest(),
                         "original_sha256": hashlib.sha256((source / relative).read_bytes()).hexdigest(),
                         "artifact_id": artifact, "artifact_name": name, "artifact_zip_sha256": zip_sha256})
        return manifest[-1]["fixture_sha256"], obj

    def load(relative):
        return clean(json.loads((source / relative).read_bytes()))

    base = "sou-228/41818201020/"
    for relative in ("sou215-installed-pilot/report.json", "sou215-pilot-demo/report.json",
                     "sou215-pilot-scope/report.json"):
        write(base + relative, load(base + relative))
    for run in ("41818211366", "41818225908"):
        base = "sou-228/" + run + "/"
        companions = {role: write(base + relative, load(base + relative)) for role, relative in (
            ("walkthrough", "sou216-clean-user/walkthrough/report.json"),
            ("ask", "sou216-clean-user/ask/qualification.json"),
            ("user-session", "sou216-user-session/report.json"),
            ("after-cleanup", "sou216-user-session-after-cleanup/report.json"))}
        report = load(base + "sou216-clean-user/report.json")
        rows = {row["id"]: row for row in report["clean_user"]["cases"]}
        rows["documented-walkthrough"]["original_report_sha256"] = companions["walkthrough"][0]
        rows["ask-once-replay"]["original_report_sha256"] = companions["ask"][0]
        report["ci_user_session"]["report_sha256"] = companions["user-session"][0]
        report["ci_user_session"]["observation"] = companions["user-session"][1]
        write(base + "sou216-clean-user/report.json", report)
    (output / "provenance.json").write_bytes(
        (json.dumps({"description": DESCRIPTION, "files": manifest}, indent=1) + "\n").encode())


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
