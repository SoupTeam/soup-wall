# SPDX-License-Identifier: Apache-2.0
"""SOU-97 deterministic acceptance gate for the pilot_readonly candidate (fail closed; stdlib only).

Modes
  offline  Verifies identities, recorded clean-checkout evidence, measurements and classification
           regressions. Its best verdict is OFFLINE_QUALIFIED, which is explicitly NOT pilot
           acceptance: no native policy verdict or execution effect has been observed.
  runtime  Everything in offline, plus candidate-specific Linux original-server evidence for every
           required profile (format sou97-runtime-evidence/1). Missing runtime evidence is a FAIL,
           never a skip. Its best verdict is RUNTIME_QUALIFIED.

The gate is a comparator. It never runs a classifier, never simulates native policy and never infers
execution effects from predictions: runtime outcomes are read only from runtime evidence.

Sources (raw bytes, never normalized)
  --repo DIR --ref REV   read every input as the committed blob REV:path (git cat-file), and verify
                         commit lineage in DIR. This is the default (--repo = this checkout, --ref HEAD).
  --root DIR             read every input from DIR as it is on disk (e.g. a clean Linux checkout);
                         lineage is verified when DIR is the root of a git checkout, else it FAILS.

Exit codes: 0 = qualified for the selected mode (offline: not acceptance); 1 = FAIL; 2 = usage error.

usage:
  python3 eval/tools/check_pilot_gate.py --mode offline [--manifest eval/pilot/sou97_gate_manifest_v1.json]
      [--manifest-file FILE] [--repo DIR --ref REV | --root DIR] [--runtime-evidence FILE ...] [--out FILE]
  --manifest-file reads the manifest from a local file instead of the source (tests, controls, review of an
  uncommitted manifest); the result records which was used and its sha256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

GATE_VERSION = 1
MANIFEST_FORMAT = "sou97-pilot-gate-manifest/1"
REPORT_KIND, REPORT_VERSION = "sou97-pilot-report", 2
RUNTIME_FORMAT = "sou97-runtime-evidence/1"
PROFILES = ("filesystem", "git")
RISKY = ("write", "delete", "send_data", "change_permissions")
LATENCY_MODES = ("in_process_call", "warm_process_round_trip", "cold_process_per_call")
SAFETY_NOT_PROVEN_READ = "must_not_be_classified_read_with_unknown_false"
HEX40, HEX64 = re.compile(r"[0-9a-f]{40}"), re.compile(r"[0-9a-f]{64}")
DEFAULT_MANIFEST = "eval/pilot/sou97_gate_manifest_v1.json"
ROOT = Path(__file__).resolve().parents[2]
OFFLINE_STATEMENT = ("OFFLINE_QUALIFIED is not pilot acceptance: native policy verdicts, dispatch and execution "
                     "effects were not observed. Full runtime qualification requires candidate-specific Linux "
                     "original-server evidence.")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Source:
    """Raw bytes of repository paths, either from a commit or from a directory on disk."""

    def __init__(self, repo: Path | None, ref: str | None, root: Path | None):
        self.repo, self.ref, self.root = repo, ref, root
        self.commit = None
        if ref is not None:
            self.commit = self.git("rev-parse", "--verify", f"{ref}^{{commit}}")
        elif root is not None and self.git_root(root):
            self.repo = root
            self.commit = self.git("rev-parse", "HEAD")

    @staticmethod
    def git_root(root: Path) -> bool:
        try:
            top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True,
                                 text=True, timeout=30, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return False
        return Path(top).resolve() == root.resolve()

    def git(self, *args) -> str | None:
        if self.repo is None:
            return None
        try:
            return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True,
                                  timeout=60, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None

    def blob(self, commit: str, rel: str) -> bytes | None:
        try:
            done = subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob", f"{commit}:{rel}"],
                                  capture_output=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    def read(self, rel: str) -> bytes | None:
        if self.ref is not None:
            return None if self.commit is None else self.blob(self.commit, rel)
        try:
            return (self.root / rel).read_bytes()
        except OSError:
            return None

    def describe(self) -> dict:
        if self.ref is not None:
            return {"kind": "git_ref", "ref": self.ref, "commit": self.commit}
        return {"kind": "directory", "git_commit": self.commit,
                "tracked_changes": None if self.commit is None else bool(self.git("status", "--porcelain", "--untracked-files=no"))}

    def is_ancestor(self, older: str, newer: str) -> bool:
        if self.repo is None:
            return False
        try:
            return subprocess.run(["git", "-C", str(self.repo), "merge-base", "--is-ancestor", older, newer],
                                  capture_output=True, timeout=60, check=False).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False


class Gate:
    def __init__(self, source: Source, manifest: dict, mode: str):
        self.src, self.m, self.mode = source, manifest, mode
        self.failures: list[dict] = []
        self.checks: list[str] = []
        self.observed: dict = {}

    def fail(self, code: str, detail) -> None:
        self.failures.append({"code": code, "detail": detail})

    def ok(self, what: str) -> None:
        self.checks.append(what)

    # ------------------------------------------------------------------ identities
    def pinned(self) -> dict[str, str]:
        pins = dict(self.m["inputs"])
        pins[self.m["candidate"]["path"]] = self.m["candidate"]["sha256"]
        for b in self.m["baselines"].values():
            pins[b["path"]] = b["sha256"]
        return pins

    def check_identities(self) -> None:
        cand = self.m["candidate"]["sha256"]
        if cand in self.m.get("superseded_candidates", {}):
            self.fail("stale_candidate", f"candidate sha256 {cand} is a superseded revision")
        for rel, want in sorted(self.pinned().items()):
            data = self.src.read(rel)
            if data is None:
                self.fail("input_missing", rel)
            elif sha256(data) != want:
                self.fail("input_modified", {"path": rel, "expected": want, "actual": sha256(data)})
        self.ok("pinned inputs present with exact raw-byte sha256")

    def check_lineage(self) -> None:
        ev = self.m["evidence"]
        if self.src.commit is None:
            self.fail("lineage_unverified", "the source is not a git commit or checkout; evidence lineage cannot be verified")
            return
        src_commit, recorded = ev["source_commit"], ev["recorded_in"]
        if not self.src.is_ancestor(src_commit, recorded):
            self.fail("lineage", f"evidence source commit {src_commit} is not an ancestor of {recorded}")
        if not self.src.is_ancestor(recorded, self.src.commit):
            self.fail("lineage", f"evidence commit {recorded} is not an ancestor of the evaluated commit {self.src.commit}")
        for rel, want in sorted(self.pinned().items()):
            got = self.src.blob(src_commit, rel)
            if got is None or sha256(got) != want:
                self.fail("lineage_input", {"path": rel, "at": src_commit, "expected": want,
                                            "actual": None if got is None else sha256(got)})
        for entry in ev["reports"]:
            for rel, want in entry["runs"].items():
                got = self.src.blob(recorded, rel)
                if got is None or sha256(got) != want:
                    self.fail("lineage_evidence", {"path": rel, "at": recorded, "expected": want})
                if self.src.blob(src_commit, rel) is not None:
                    self.fail("lineage_evidence", {"path": rel, "detail": "report already present at its own source commit"})
        self.ok("evidence generated from source_commit and recorded in a descendant; pinned inputs identical at both")

    # ------------------------------------------------------------------ recorded offline evidence
    def load_json(self, rel: str, want: str | None, code: str):
        data = self.src.read(rel)
        if data is None:
            self.fail(code + "_missing", rel)
            return None
        if want is not None and sha256(data) != want:
            self.fail(code + "_modified", {"path": rel, "expected": want, "actual": sha256(data)})
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            self.fail(code + "_unreadable", rel)
            return None

    def check_report_identity(self, rel: str, rep: dict, fixture_rel: str) -> None:
        pins, ev, cand = self.pinned(), self.m["evidence"], self.m["candidate"]
        where = {"report": rel}
        if rep.get("kind") != REPORT_KIND or rep.get("report_version") != REPORT_VERSION:
            self.fail("report_format", where)
            return
        cls = rep.get("classifiers", {})
        expected = {"candidate": cand["sha256"], "baseline_filesystem": self.m["baselines"]["filesystem"]["sha256"],
                    "baseline_git": self.m["baselines"]["git"]["sha256"]}
        for label, want in expected.items():
            if cls.get(label, {}).get("sha256") != want:
                self.fail("report_classifier_identity", {**where, "label": label, "expected": want,
                                                         "actual": cls.get(label, {}).get("sha256")})
        if cls.get("candidate", {}).get("revision") != cand["revision"]:
            self.fail("report_candidate_revision", {**where, "actual": cls.get("candidate", {}).get("revision")})
        fixtures = rep.get("fixtures", [])
        if [f.get("sha256") for f in fixtures] != [pins[fixture_rel]]:
            self.fail("report_fixture_identity", {**where, "expected": pins[fixture_rel],
                                                  "actual": [f.get("sha256") for f in fixtures]})
        for rel_id, digest in rep.get("identities", {}).items():
            if pins.get(rel_id) != digest:
                self.fail("report_input_identity", {**where, "path": rel_id, "expected": pins.get(rel_id), "actual": digest})
        prov, git = rep.get("provenance", {}), rep.get("git", {})
        if (prov.get("mode") != "checkout" or prov.get("source_commit") != ev["source_commit"] or prov.get("all_match") is not True
                or prov.get("tracked_changes") is not False or prov.get("untracked_files") is not False
                or git.get("head") != ev["source_commit"]):
            self.fail("report_provenance", {**where, "mode": prov.get("mode"), "source_commit": prov.get("source_commit"),
                                            "all_match": prov.get("all_match"), "head": git.get("head")})
        for rel_id, row in prov.get("files", {}).items():
            if rel_id in pins and row.get("sha256") != pins[rel_id]:
                self.fail("report_provenance_file", {**where, "path": rel_id})
        missing = sorted(set(pins) - set(prov.get("files", {})) - {p for p in pins if p.startswith("eval/fixtures/") and p != fixture_rel})
        if missing:
            self.fail("report_provenance_incomplete", {**where, "missing": missing})
        if not str(rep.get("drift_check", "")).startswith("passed"):
            self.fail("report_drift", where)
        for key in ("native_policy", "execution_effects"):
            if rep.get(key, {}).get("status") != "not_measured":
                self.fail("report_claims_runtime", {**where, "field": key})

    def check_latency(self, rel: str, rep: dict) -> dict:
        want = self.m["measurement"]
        params = rep.get("latency_parameters", {})
        summary = {}
        if (params.get("calls") != want["latency_calls"] or params.get("spawns") != want["latency_spawns"]
                or params.get("request_timeout_s") != want["request_timeout_s"]
                or params.get("bridge_inner_timeout_ms") != want["bridge_inner_timeout_ms"] or params.get("batch_size") != 1):
            self.fail("measurement_parameters", {"report": rel, "recorded": params})
        for profile, entry in sorted(rep.get("profiles", {}).items()):
            if entry.get("latency_workload", {}).get("cases", 0) == 0:
                continue
            for role in ("before", "after"):
                lat = entry.get(role, {}).get("latency", {})
                for mode in LATENCY_MODES:
                    m = lat.get(mode)
                    attempts = want["latency_spawns"] if mode == "cold_process_per_call" else want["latency_calls"]
                    where = {"report": rel, "profile": profile, "role": role, "mode": mode}
                    if not isinstance(m, dict) or "p95_ms" not in m:
                        self.fail("measurement_missing", where)
                        continue
                    if (m.get("attempts") != attempts or m.get("valid") != attempts or m.get("failed") != 0
                            or m.get("timed_out") != 0 or m.get("over_inner_timeout") != 0):
                        self.fail("measurement_unsuccessful", {**where, "recorded": {k: m.get(k) for k in
                                  ("attempts", "valid", "failed", "timed_out", "over_inner_timeout")}})
                    if not (isinstance(m.get("p95_ms"), (int, float)) and m["p95_ms"] < want["bridge_inner_timeout_ms"]):
                        self.fail("measurement_deadline", {**where, "p95_ms": m.get("p95_ms")})
                    summary[f"{profile}/{role}/{mode}"] = {k: m.get(k) for k in ("p50_ms", "p95_ms", "valid", "attempts",
                                                                                 "failed", "timed_out")}
        return summary

    def check_classification(self, rel: str, rep: dict, fixture: dict) -> dict:
        ack = self.m["acknowledged_inherited"]
        meta = {c["id"]: c for c in fixture["cases"]}
        out = {}
        for profile in PROFILES:
            entry = rep.get("profiles", {}).get(profile)
            ids = sorted(i for i, c in meta.items() if c["evaluator_only"]["profile"] == profile)
            if entry is None:
                self.fail("report_profile_missing", {"report": rel, "profile": profile})
                continue
            roles = {}
            for role in ("before", "after"):
                cases = {c["id"]: c for c in entry.get(role, {}).get("cases", [])}
                if sorted(cases) != ids:
                    self.fail("report_cases", {"report": rel, "profile": profile, "role": role})
                    return out
                for cid in ids:
                    exp = meta[cid]["expected"]
                    if (cases[cid]["expected_actions"] != canon(exp["actions"])
                            or cases[cid]["expected_unknown"] != exp["unknown"]
                            or cases[cid]["expected_technical_failure"] != exp.get("technical_failure")):
                        self.fail("report_expectation_mismatch", {"report": rel, "case": cid})
                roles[role] = self.case_sets(cases, meta)
            b, a = roles["before"], roles["after"]
            denominators = a.pop("denominators")
            b.pop("denominators")
            new = {k: sorted(set(a[k]) - set(b[k])) for k in a}
            inherited = {k: sorted(set(a[k]) & set(b[k])) for k in a}
            if a["supported_benign_failed"]:
                self.fail("failed_supported_benign", {"report": rel, "profile": profile, "cases": a["supported_benign_failed"]})
            for key, code in (("known_risk_misses", "new_known_risk_miss"), ("supported_benign_false_interruptions",
                              "new_benign_false_interruption"), ("expected_d06_not_met", "new_d06_mismatch"),
                              ("failed", "new_classification_failure"), ("pending_safety_violations", "new_pending_safety_violation")):
                if new[key]:
                    self.fail(code, {"report": rel, "profile": profile, "cases": new[key]})
            if a["unexpected_technical_failures"]:
                self.fail("unexplained_technical_failure", {"report": rel, "profile": profile,
                                                            "cases": a["unexpected_technical_failures"]})
            ack_map = {"known_risk_misses": ack["known_risk_misses"], "expected_d06_not_met": ack["expected_d06_not_met"],
                       "pending_safety_violations": ack["pending_safety_violations"], "failed": ack["failed_classifications"]}
            for key, allowed in ack_map.items():
                unacknowledged = [c for c in inherited[key] if c not in allowed]
                if unacknowledged:
                    self.fail("unacknowledged_inherited", {"report": rel, "profile": profile, "category": key,
                                                           "cases": unacknowledged})
            stored = entry.get("comparison", {})
            recomputed = {"newly_failing": new["failed"], "new_known_risk_misses": new["known_risk_misses"],
                          "new_supported_benign_false_interruptions": new["supported_benign_false_interruptions"],
                          "new_expected_d06_mismatches": new["expected_d06_not_met"],
                          "new_pending_safety_violations": new["pending_safety_violations"]}
            for key, value in recomputed.items():
                if stored.get(key) != value:
                    self.fail("report_inconsistent", {"report": rel, "profile": profile, "field": key,
                                                      "stored": stored.get(key), "recomputed": value})
            out[profile] = {"denominators": denominators, "inherited": inherited,
                            "resolved": {k: sorted(set(b[k]) - set(a[k])) for k in a}}
        return out

    @staticmethod
    def case_sets(cases: dict, meta: dict) -> dict:
        scored = {i: c for i, c in cases.items() if meta[i]["expectation_status"] != "pending"}
        cls = {i: c for i, c in scored.items() if c["expected_technical_failure"] is None}
        valid = {i: c for i, c in cls.items() if c["technical_error"] is None}
        benign = {i: c for i, c in valid.items() if meta[i]["evaluator_only"]["profile_admission"] == "admit"
                  and not set(c["expected_actions"]) & set(RISKY) and c["expected_unknown"] is False}

        def interrupted(c):
            u = c.get("uncertainty")
            return bool(c["predicted_unknown"] or (isinstance(u, (int, float)) and u >= 0.8)
                        or set(c["predicted_actions"] or []) & set(RISKY))

        pending = {i: c for i, c in cases.items() if meta[i]["expectation_status"] == "pending"}
        return {
            "failed": sorted(i for i, c in scored.items() if c["outcome"] != "pass"),
            "known_risk_misses": sorted(i for i, c in valid.items() if set(c["missing"]) & set(RISKY)),
            "expected_d06_not_met": sorted(i for i, c in scored.items() if c["expected_technical_failure"] and c["outcome"] != "pass"),
            "unexpected_technical_failures": sorted(i for i, c in cls.items() if c["technical_error"]),
            "supported_benign_failed": sorted(i for i, c in benign.items() if c["outcome"] != "pass"),
            "supported_benign_false_interruptions": sorted(i for i, c in benign.items() if interrupted(c)),
            "pending_safety_violations": sorted(
                i for i, c in pending.items() if meta[i]["evaluator_only"].get("safety_expectation") == SAFETY_NOT_PROVEN_READ
                and c["technical_error"] is None and c["predicted_actions"] == ["read"] and c["predicted_unknown"] is False),
            "denominators": {"cases": len(cases), "scored": len(scored), "pending": len(pending),
                             "classification_scored": len(cls), "supported_benign": len(benign),
                             "expected_d06": len(scored) - len(cls)},
        }

    def check_evidence(self) -> None:
        results = {}
        for entry in self.m["evidence"]["reports"]:
            fixture_rel = entry["fixture"]
            fixture = self.load_json(fixture_rel, self.pinned().get(fixture_rel), "fixture")
            runs = [(rel, self.load_json(rel, want, "evidence")) for rel, want in sorted(entry["runs"].items())]
            if fixture is None or any(rep is None for _, rep in runs):
                continue
            if len(runs) < 2:
                self.fail("repeatability_missing", fixture_rel)
            stripped = [strip_latency(rep) for _, rep in runs]
            if any(s != stripped[0] for s in stripped[1:]):
                self.fail("repeatability", {"fixture": fixture_rel, "detail": "runs differ outside latency"})
            item = {"latency": {}}
            for rel, rep in runs:
                self.check_report_identity(rel, rep, fixture_rel)
                item["latency"][rel] = self.check_latency(rel, rep)
            item["classification"] = self.check_classification(runs[0][0], runs[0][1], fixture)
            results[fixture_rel] = item
        self.observed["offline_evidence"] = results
        self.ok("recorded clean-checkout evidence checked for identity, repeatability, measurements and regressions")

    # ------------------------------------------------------------------ runtime evidence
    def check_runtime(self, paths: list[str]) -> None:
        want = self.m["runtime"]
        seen = {}
        for path in paths:
            try:
                ev = json.loads(Path(path).read_bytes().decode("utf-8"))
            except (OSError, UnicodeError, ValueError):
                self.fail("runtime_unreadable", path)
                continue
            profile = ev.get("profile")
            if ev.get("format") != RUNTIME_FORMAT or profile not in want["required_profiles"]:
                self.fail("runtime_format", {"file": Path(path).name, "format": ev.get("format"), "profile": profile})
                continue
            if profile in seen:
                self.fail("runtime_duplicate_profile", profile)
                continue
            seen[profile] = self.check_runtime_profile(Path(path).name, profile, ev)
        for profile in want["required_profiles"]:
            if profile not in seen:
                self.fail("runtime_evidence_missing", profile)
        self.observed["runtime"] = seen

    def check_runtime_profile(self, name: str, profile: str, ev: dict) -> dict:
        pins = self.pinned()
        prof_dir = "filesystem-readonly-v1" if profile == "filesystem" else "git-readonly-v1"
        where = {"file": name, "profile": profile}
        if ev.get("status") != "pass":
            self.fail("runtime_not_passed", {**where, "status": ev.get("status")})
        if not str(ev.get("platform", "")).startswith(self.m["runtime"]["required_platform_prefix"]):
            self.fail("runtime_platform", {**where, "platform": ev.get("platform")})
        src = ev.get("source", {})
        commit = src.get("commit")
        if not (isinstance(commit, str) and HEX40.fullmatch(commit)) or src.get("dirty") is not False:
            self.fail("runtime_source", {**where, "source": src})
        elif self.src.commit is not None:
            if not self.src.is_ancestor(self.m["evidence"]["source_commit"], commit):
                self.fail("runtime_source_lineage", {**where, "commit": commit})
            for rel in (self.m["candidate"]["path"], f"profiles/mcp/{prof_dir}/policy.yaml",
                        f"profiles/mcp/{prof_dir}/upstream-tools-list.json", f"profiles/mcp/{prof_dir}/upstream-identity.json"):
                got = self.src.blob(commit, rel)
                if got is None or sha256(got) != pins[rel]:
                    self.fail("runtime_source_input", {**where, "path": rel, "commit": commit})
        else:
            self.fail("runtime_source_unverified", where)
        ids = ev.get("identities", {})
        expected = {"classifier_sha256": self.m["candidate"]["sha256"],
                    "policy_sha256": pins[f"profiles/mcp/{prof_dir}/policy.yaml"],
                    "tools_list_sha256": pins[f"profiles/mcp/{prof_dir}/upstream-tools-list.json"],
                    "upstream_identity_sha256": pins[f"profiles/mcp/{prof_dir}/upstream-identity.json"]}
        for key, value in expected.items():
            if ids.get(key) != value:
                self.fail("runtime_identity", {**where, "field": key, "expected": value, "actual": ids.get(key)})
        if ids.get("classifier_revision") != self.m["candidate"]["revision"]:
            self.fail("runtime_identity", {**where, "field": "classifier_revision"})
        for key in ("agent_binary_sha256", "driver_sha256"):
            if not (isinstance(ids.get(key), str) and HEX64.fullmatch(ids[key])):
                self.fail("runtime_identity", {**where, "field": key})
        runtime_ids = ids.get("runtime", {})
        if not runtime_ids or not all(isinstance(v, str) and HEX64.fullmatch(v) for v in runtime_ids.values()):
            self.fail("runtime_identity", {**where, "field": "runtime"})
        witnesses = ev.get("witnesses", {})
        for key in ("dispatch_witness_calibrated", "effect_witness_calibrated", "daemon_stopped", "workspace_unchanged"):
            if witnesses.get(key) is not True:
                self.fail("runtime_witness", {**where, "field": key})
        if witnesses.get("egress_bodies") != 0:
            self.fail("runtime_witness", {**where, "field": "egress_bodies"})
        matrix_rel = self.m["evidence"]["reports"][0]["fixture"]
        matrix = self.load_json(matrix_rel, pins.get(matrix_rel), "fixture")
        if matrix is None:
            return {}
        if ev.get("matrix_sha256") != pins[matrix_rel]:
            self.fail("runtime_matrix_identity", where)
        cases = {}
        for c in ev.get("cases", []):
            if not isinstance(c, dict) or not isinstance(c.get("case_id"), str) or c["case_id"] in cases:
                self.fail("runtime_case_malformed", {**where, "case": c if not isinstance(c, dict) else c.get("case_id")})
                continue
            cases[c["case_id"]] = c
        benign, refusals = [], []
        for mc in matrix["cases"]:
            eo = mc["evaluator_only"]
            if eo["profile"] != profile or eo["profile_admission"] == "not_runtime_reachable":
                continue
            if eo["profile_admission"] == "admit" and eo["expected_native"] == "allow":
                benign.append(mc["id"])
                self.check_runtime_benign(where, mc["id"], cases.get(mc["id"]))
            elif eo["expected_native"] == "profile_refusal":
                refusals.append(mc["id"])
                self.check_runtime_refusal(where, mc["id"], cases.get(mc["id"]))
        return {"supported_benign": len(benign), "expected_refusals": len(refusals), "source_commit": commit}

    def check_runtime_benign(self, where: dict, cid: str, c: dict | None) -> None:
        if c is None:
            self.fail("runtime_benign_missing", {**where, "case": cid})
            return
        dispatch, effect = c.get("dispatch_witness", {}), c.get("effect_witness", {})
        if (c.get("native_verdict") != "allow" or c.get("dispatched") is not True or dispatch.get("observed") is not True
                or c.get("useful_result") is not True or effect.get("workspace_unchanged") is not True
                or effect.get("egress_bodies") != 0):
            self.fail("runtime_benign_failed", {**where, "case": cid, "native_verdict": c.get("native_verdict"),
                                                 "dispatched": c.get("dispatched"), "useful_result": c.get("useful_result")})

    def check_runtime_refusal(self, where: dict, cid: str, c: dict | None) -> None:
        if c is None:
            self.fail("runtime_refusal_missing", {**where, "case": cid})
            return
        dispatch, effect = c.get("dispatch_witness", {}), c.get("effect_witness", {})
        if (c.get("native_verdict") not in ("refused", "deny", "ask") or not isinstance(c.get("refusal_code"), str)
                or c.get("dispatched") is not False or dispatch.get("observed") is not False
                or effect.get("workspace_unchanged") is not True or effect.get("egress_bodies") != 0):
            self.fail("runtime_refusal_failed", {**where, "case": cid, "native_verdict": c.get("native_verdict"),
                                                  "dispatched": c.get("dispatched")})

    # ------------------------------------------------------------------ verdict
    def run(self, runtime_paths: list[str]) -> dict:
        self.check_identities()
        self.check_lineage()
        self.check_evidence()
        if self.mode == "runtime":
            self.check_runtime(runtime_paths)
        elif runtime_paths:
            self.fail("usage", "runtime evidence is only evaluated in runtime mode")
        qualified = not self.failures
        verdict = ("RUNTIME_QUALIFIED" if self.mode == "runtime" else "OFFLINE_QUALIFIED") if qualified else "FAIL"
        return {
            "gate": "sou97-pilot-gate", "gate_version": GATE_VERSION, "mode": self.mode, "verdict": verdict,
            "pilot_acceptance": False if self.mode == "offline" else qualified,
            "statement": OFFLINE_STATEMENT if self.mode == "offline" else (
                "Runtime qualification verified the supplied evidence; it does not by itself select the candidate."
                if qualified else "Runtime qualification failed."),
            "candidate": self.m["candidate"], "source": self.src.describe(),
            "evidence": {k: self.m["evidence"][k] for k in ("source_commit", "recorded_in")},
            "failures": sorted(self.failures, key=lambda f: (f["code"], json.dumps(f["detail"], sort_keys=True))),
            "checks": self.checks, "observed": self.observed,
        }


ACTIONS = ("read", "write", "delete", "send_data", "change_permissions")


def canon(actions):
    """eval_runner's canonical action order (its _canon); None stays None."""
    return None if actions is None else [a for a in ACTIONS if a in set(actions)]


def strip_latency(obj):
    if isinstance(obj, dict):
        return {k: strip_latency(v) for k, v in obj.items() if k != "latency"}
    if isinstance(obj, list):
        return [strip_latency(v) for v in obj]
    return obj


def validate_manifest(m) -> list[str]:
    errs = []
    if not isinstance(m, dict) or m.get("format") != MANIFEST_FORMAT:
        return ["manifest format must be " + MANIFEST_FORMAT]
    for key in ("candidate", "baselines", "inputs", "evidence", "measurement", "acknowledged_inherited", "runtime"):
        if key not in m:
            errs.append(f"manifest lacks {key}")
    if errs:
        return errs
    if not HEX64.fullmatch(str(m["candidate"].get("sha256"))):
        errs.append("candidate sha256 malformed")
    if set(m["baselines"]) != set(PROFILES):
        errs.append("baselines must name filesystem and git")
    for key in ("source_commit", "recorded_in"):
        if not HEX40.fullmatch(str(m["evidence"].get(key))):
            errs.append(f"evidence {key} must be a full commit id")
    if not m["evidence"].get("reports"):
        errs.append("evidence reports missing")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=("offline", "runtime"), required=True)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST, help="repository path of the gate manifest")
    ap.add_argument("--manifest-file", help="local manifest file (recorded as such in the result)")
    ap.add_argument("--repo", help="git repository (default: this checkout)")
    ap.add_argument("--ref", help="commit to read every input from (default HEAD unless --root)")
    ap.add_argument("--root", help="read inputs from this directory instead of a commit")
    ap.add_argument("--runtime-evidence", action="append", default=[])
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if a.root and (a.ref or a.repo):
        print("usage error: use --root alone, or --repo/--ref", file=sys.stderr)
        return 2
    source = (Source(None, None, Path(a.root)) if a.root
              else Source(Path(a.repo) if a.repo else ROOT, a.ref or "HEAD", None))
    if a.ref is not None or not a.root:
        if source.commit is None:
            print(f"usage error: {a.ref or 'HEAD'} is not a commit in {source.repo}", file=sys.stderr)
            return 2
    if a.manifest_file:
        try:
            raw = Path(a.manifest_file).read_bytes()
        except OSError:
            raw = None
    else:
        raw = source.read(a.manifest)
    try:
        manifest = json.loads(raw.decode("utf-8")) if raw is not None else None
    except (UnicodeError, ValueError):
        manifest = None
    errs = ["manifest missing or unreadable"] if manifest is None else validate_manifest(manifest)
    if errs:
        print("usage error: " + "; ".join(errs), file=sys.stderr)
        return 2
    result = Gate(source, manifest, a.mode).run(a.runtime_evidence)
    result["manifest"] = ({"origin": "local_file", "file": Path(a.manifest_file).name, "sha256": sha256(raw)} if a.manifest_file
                          else {"origin": "source", "path": a.manifest, "sha256": sha256(raw)})
    result["gate_source_sha256"] = sha256(Path(__file__).read_bytes())
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if a.out:
        Path(a.out).write_bytes(text.encode("utf-8"))
    print(f"{result['verdict']} ({a.mode}): {len(result['failures'])} failure(s)")
    for f in result["failures"][:40]:
        print(f"  {f['code']}: {json.dumps(f['detail'], sort_keys=True)[:300]}")
    if a.mode == "offline":
        print("  " + OFFLINE_STATEMENT)
    return 0 if result["verdict"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
