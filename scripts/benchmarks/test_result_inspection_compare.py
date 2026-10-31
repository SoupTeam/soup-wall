# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the SOU-191 result-inspection comparison and recorder.

Every run directory built here is a SYNTHETIC TEST FIXTURE: adapter outputs are invented, bound to
the real predeclared commits and the real frozen corpus so that Git-object and corpus checks are
exercised. None of them is evidence about either revision.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import result_inspection_compare as ric  # noqa: E402
import result_inspection_record as rec  # noqa: E402

PRE = ROOT / "docs/benchmarks/evidence/sou191/predeclaration.json"
FAKE_ARTIFACT = {"baseline": "a" * 64, "candidate": "b" * 64}


def _have_commits():
    try:
        git = ric.Git(ROOT)
        pre = json.loads(PRE.read_bytes())
        for role in ric.ROLES:
            git.text("cat-file", "-t", pre["revisions"][role]["commit"])
        return True
    except Exception:  # noqa: BLE001 - any missing prerequisite skips the Git-bound tests
        return False


def entry(run_dir, name, raw, **extra):
    (run_dir / name).write_bytes(raw)
    digest = ric._sha(raw)
    return dict({"file": name, "raw_sha256": digest, "raw_bytes": len(raw), "retained_sha256": digest,
                 "retained_bytes": len(raw), "truncated": False, "sanitized": False}, **extra)


def result_for(case, verdict="Deny", status="inspected", rule="synthetic_rule", latency=100):
    if status in ("inspected", "evidence_budget_not_inspected"):
        return {"case_id": case["case_id"], "status": status, "verdict": verdict, "rule": rule, "findings": [],
                "latency_micros": latency}
    if status == "over_budget_not_inspected":
        return {"case_id": case["case_id"], "status": status, "bytes": case["size_bytes"]}
    return {"case_id": case["case_id"], "status": status, "reason": "payload_not_utf8"}


def default_results(manifest, verdicts=None):
    verdicts = verdicts or {}
    out = []
    for case in manifest["cases"]:
        if case["class"] == "technical":
            out.append(result_for(case, status="over_budget_not_inspected") if case["category"] == "over_budget"
                       else result_for(case, verdict="Allow"))
        else:
            out.append(result_for(case, verdict=verdicts.get(case["case_id"], "Deny")))
    return out


@unittest.skipUnless(_have_commits(), "predeclared commits are not in this Git repository")
class ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.git = ric.Git(ROOT)
        cls.pre = json.loads(PRE.read_bytes())
        cls.pre_sha = ric._sha(PRE.read_bytes())
        cls.corpus = ric.load_corpus(ROOT)
        cls.manifest = cls.corpus["manifest"]
        cls.runners = {role: ric.load_runner(cls.git, cls.pre["revisions"][role]["commit"]) for role in ric.ROLES}
        # Committed recorder and contract sources at HEAD, hashed as stored in Git.
        cls.recorder = {key: ric._sha(cls.git.show("HEAD", path)) for key, path in ric.RECORDER_SOURCES.items()}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sou191-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # -------------------------------------------------------------- fixture builder

    def side(self, role, results=None, attempt=1, status="executed", exit_code=0, timed_out=False, stdout=None,
             report_edit=None, run_edit=None, pre_sha=None, commit=None, root=None):
        commit = commit or self.pre["revisions"][role]["commit"]
        run_dir = (root or self.tmp) / role / f"attempt-{attempt:03d}"
        run_dir.mkdir(parents=True)
        results = default_results(self.manifest) if results is None else results
        raw_stdout = stdout if stdout is not None else json.dumps({"results": results}).encode()
        artifact = FAKE_ARTIFACT[role]
        inputs = {path: {"blob": self.git.blob_id(commit, path), "sha256": "0" * 64} for path in ric.BUILD_INPUTS}
        inputs["eval/sou123/payloads"] = {"tree": self.git.text("rev-parse", f"{commit}:eval/sou123/payloads")}
        run = {"schema": ric.RUN_SCHEMA, "role": role, "attempt": attempt, "status": status,
               "predeclaration_sha256": pre_sha or self.pre_sha,
               "recorder": {"synthetic_fixture": "SYNTHETIC TEST FIXTURE - not evidence", **self.recorder},
               "revision": {"commit": commit, "tree": self.git.text("rev-parse", f"{commit}^{{tree}}")},
               "checkout": {"clean_before": True, "clean_after": True, "inputs_match_blobs_before": True,
                            "inputs_match_blobs_after": True, "inputs": inputs, "cargo_config_files": []},
               "toolchain": {"rustc_release": "1.99.1", "rustc_commit_hash": "synthetic",
                             "host": "x86_64-pc-windows-msvc"},
               "environment": {"refused_variables_present": []},
               "build": {"argv": list(self.pre["build"]["argv"]), "target_dir_fresh": True, "exit_code": 0,
                         "messages": entry(run_dir, "build-messages.jsonl", b"{}\n"),
                         "artifact": {"relative_path": "debug/examples/result_inspection_corpus.exe",
                                      "sha256": artifact, "bytes": 1}},
               "execution": {"exit_code": exit_code, "timed_out": timed_out, "artifact_sha256_before": artifact,
                             "artifact_sha256_after": artifact,
                             "stdout": entry(run_dir, "adapter-stdout.json", raw_stdout),
                             "stderr": entry(run_dir, "adapter-stderr.txt", b"")},
               "report": None, "problems": []}
        if status == "executed" and exit_code == 0 and not timed_out and stdout is None:
            identities = {"source": commit, "rustc": "1.99.1 dev", "policy_path": "profiles/pilot/linux-readonly-v1/policy.yaml",
                          "manifest_sha256": self.corpus["manifest_sha256"], "policy_sha256": self.corpus["policy_sha256"],
                          "adapter_sha256": artifact}
            report = self.runners[role].build_report(self.manifest, results, identities)
            if report_edit:
                report_edit(report)
            raw = (json.dumps(report, indent=1, ensure_ascii=False) + "\n").encode()
            (run_dir / "report.json").write_bytes(raw)
            run["report"] = {"file": "report.json", "sha256": ric._sha(raw)}
        if run_edit:
            run_edit(run, run_dir)
        (run_dir / "run.json").write_bytes(json.dumps(run, indent=1).encode())
        return run_dir.parent

    def compare(self, base=None, cand=None, pre=PRE, corpus_root=None, amendments=()):
        base = base or self.side("baseline")
        cand = cand or self.side("candidate")
        return ric.compare(pre, base, cand, ROOT, corpus_root, amendments)

    def amendment(self, name="amend.json", argv=None, amends=None, **extra):
        argv = argv or self.pre["build"]["argv"][:3] + ["--jobs", "2"] + self.pre["build"]["argv"][3:]
        data = {"schema": ric.AMENDMENT_SCHEMA, "issue": "SOU-191", "sequence": 1,
                "amends_sha256": amends or self.pre_sha, "declared_at_utc": "2026-10-31T00:00:00Z",
                "reason": "SYNTHETIC TEST FIXTURE", "changes": {"build.argv": argv},
                "applies_to": list(ric.ROLES), "not_claimed": "synthetic", **extra}
        path = self.tmp / name
        path.write_bytes(json.dumps(data).encode())
        return path, ric._sha(path.read_bytes()), argv

    def assertInvalid(self, outcome, code):
        result, exit_code = outcome
        self.assertEqual(exit_code, ric.EXIT_INVALID, result["errors"])
        self.assertEqual(result["errors"][0]["code"], code, result["errors"])
        return result

    # -------------------------------------------------------------- comparable path

    def test_transitions_denominators_and_outputs(self):
        cases = {c["case_id"]: c for c in self.manifest["cases"]}
        attack = sorted(i for i, c in cases.items() if c["label"] == "attack")
        benign = sorted(i for i, c in cases.items() if c["label"] == "benign")
        base = self.side("baseline", default_results(self.manifest, {attack[0]: "Allow", attack[1]: "Allow"}))
        cand = self.side("candidate", default_results(self.manifest, {attack[1]: "Allow", attack[2]: "Allow",
                                                                     **{i: "Allow" for i in benign[:3]}}))
        result, code = self.compare(base, cand)
        self.assertEqual(code, ric.EXIT_COMPARABLE, result["errors"] + result["non_comparable"])
        a, b = result["outcomes"]["attack"], result["outcomes"]["benign"]
        self.assertEqual((a["transitions"]["improved"], a["transitions"]["regressed"]), (1, 1))
        self.assertEqual(a["transitions"]["missed_instruction->missed_instruction"], 1)
        self.assertEqual((b["transitions"]["improved"], b["transitions"]["regressed"]), (3, 0))
        self.assertEqual(result["denominators"]["baseline"]["attack"],
                         {"planned": 24, "attempted": 24, "inspected": 24, "incomplete": 0, "error": 0, "unknown": 0,
                          "unobserved": 0, "not_run": 0, "timeout": 0})
        # Predeclared grouping: far below the minimum, so no interval and no established change.
        self.assertEqual(a["family_uncertainty"]["status"], "insufficient_clusters")
        self.assertIsNone(a["family_uncertainty"]["interval95"])
        self.assertTrue(a["overall_change"].startswith("not_established"))
        self.assertEqual(result["latency"]["method"]["unit"], "microseconds")
        out = self.tmp / "out"
        ric.write_result(out, result)
        self.assertTrue((out / "units.csv").read_text(encoding="utf-8").startswith("case_id,pair_id"))
        self.assertIn("missed_instruction_rate", (out / "report.md").read_text(encoding="utf-8"))
        json.loads((out / "comparison.json").read_bytes())

    def test_identical_runs_report_equality(self):
        result, code = self.compare()
        self.assertEqual(code, ric.EXIT_COMPARABLE)
        for label in ("attack", "benign"):
            self.assertEqual(result["outcomes"][label]["transitions"]["improved"], 0)
            self.assertEqual(result["outcomes"][label]["transitions"]["regressed"], 0)

    # -------------------------------------------------------------- negative controls

    def _results(self, edit):
        results = default_results(self.manifest)
        edit(results)
        return results

    def test_missing_case(self):
        self.assertInvalid(self.compare(cand=self.side("candidate", self._results(lambda r: r.pop(3)))), "missing_case")

    def test_fabricated_case(self):
        fake = lambda r: r.append(dict(r[0], case_id="z99-a"))  # noqa: E731
        self.assertInvalid(self.compare(cand=self.side("candidate", self._results(fake))), "fabricated_case")

    def test_duplicate_case(self):
        self.assertInvalid(self.compare(cand=self.side("candidate", self._results(lambda r: r.append(dict(r[0]))))),
                           "duplicate_case")

    def _corpus_copy(self):
        root = self.tmp / "corpus"
        for rel in ("eval/sou123/manifest.json", "eval/sou123/payloads", "profiles/pilot/linux-readonly-v1/policy.yaml"):
            src, dst = ROOT / rel, root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            (shutil.copytree if src.is_dir() else shutil.copyfile)(src, dst)
        return root

    def test_altered_payload(self):
        root = self._corpus_copy()
        path = root / "eval/sou123/payloads/g01-a.txt"
        path.write_bytes(path.read_bytes() + b" ")
        self.assertInvalid(self.compare(corpus_root=root), "payload_altered")

    def test_altered_policy(self):
        root = self._corpus_copy()
        path = root / "profiles/pilot/linux-readonly-v1/policy.yaml"
        path.write_bytes(path.read_bytes() + b"\n# drift\n")
        self.assertInvalid(self.compare(corpus_root=root), "policy_or_corpus_drift")

    def test_fake_aggregate_success_with_consistent_digest(self):
        def fake(report):
            report["acceptance"] = "pass"
            report["totals"]["missed_instructions"] = 0
        # The record carries the edited report's own digest, so only derivation from raw output catches it.
        self.assertInvalid(self.compare(cand=self.side("candidate", report_edit=fake)), "report_not_derivable")

    def test_relabelled_report_row(self):
        def relabel(report):
            report["cases"][0]["label"] = "attack" if report["cases"][0]["label"] == "benign" else "benign"
        self.assertInvalid(self.compare(cand=self.side("candidate", report_edit=relabel)), "report_not_derivable")

    def test_raw_output_edited_after_recording(self):
        def edit(run, run_dir):
            path = run_dir / "adapter-stdout.json"
            path.write_bytes(path.read_bytes().replace(b'"Deny"', b'"Allow"', 1))
        self.assertInvalid(self.compare(cand=self.side("candidate", run_edit=edit)), "custody_mismatch")

    def test_truncated_and_nonfinite_output(self):
        truncated = json.dumps({"results": default_results(self.manifest)}).encode()[:-20]
        self.assertInvalid(self.compare(cand=self.side("candidate", stdout=truncated)), "malformed_adapter_output")
        nan = json.dumps({"results": default_results(self.manifest)}).replace('"latency_micros": 100', '"latency_micros": NaN', 1)
        root = self.tmp / "nan"
        self.assertInvalid(self.compare(self.side("baseline", root=root),
                                        self.side("candidate", stdout=nan.encode(), root=root)),
                           "malformed_adapter_output")

    def test_unsupported_outcome_contract(self):
        def extra(results):
            results[0]["confidence_override"] = 1
        self.assertInvalid(self.compare(cand=self.side("candidate", self._results(extra))), "unsupported_outcome_contract")

    def test_unknown_technical_and_incomplete_outcomes(self):
        semantic = [c for c in self.manifest["cases"] if c["class"] == "semantic"]
        by = {c["case_id"]: c for c in semantic}
        ids = sorted(i for i, c in by.items() if c["label"] == "attack")

        def edit(results):
            index = {r["case_id"]: n for n, r in enumerate(results)}
            results[index[ids[0]]]["verdict"] = "Maybe"  # unknown
            results[index[ids[1]]] = result_for(by[ids[1]], status="technical_error")  # error
            results[index[ids[2]]]["status"] = "evidence_budget_not_inspected"  # incomplete (candidate adapter)
            # CI-1: the same refusal reported as inspected must not count as a caught attack.
            results[index[ids[3]]]["rule"] = "mcp_result_evidence_incomplete_block"
        result, code = self.compare(cand=self.side("candidate", self._results(edit)))
        self.assertEqual(code, ric.EXIT_COMPARABLE, result["errors"])
        d = result["denominators"]["candidate"]["attack"]
        self.assertEqual((d["inspected"], d["unknown"], d["error"], d["incomplete"], d["attempted"]), (20, 1, 1, 2, 24))
        rows = {r["case_id"]: r for r in result["units"]}
        self.assertEqual(rows[ids[3]]["candidate_status"], "incomplete")
        self.assertEqual(rows[ids[3]]["candidate_original_report_outcome"], "caught_instruction")
        self.assertEqual(rows[ids[3]]["transition"], "not_paired")
        self.assertEqual(result["outcomes"]["attack"]["denominators"]["paired_inspected"], 20)
        # Latency: only inspected cases are measured; durations of the two budget refusals and the invalid
        # verdict are kept apart.
        lat = result["latency"]["attack"]["candidate"]
        self.assertEqual((lat["measured"], lat["planned"], lat["micros"]["n"]), (20, 24, 20))
        self.assertEqual(lat["unmeasured_by_status"], {"error": 1, "incomplete": 2, "unknown": 1})
        self.assertEqual((lat["not_inspected_with_duration"]["n"], lat["not_inspected_with_duration"]["statuses"]),
                         (3, {"incomplete": 2, "unknown": 1}))
        self.assertEqual(result["latency"]["attack"]["paired_measured"], 20)
        technical = result["latency"]["technical"]["candidate"]
        over = sum(c["category"] == "over_budget" for c in self.manifest["cases"] if c["class"] == "technical")
        self.assertEqual(technical["unmeasured_by_status"], {"incomplete": over})
        self.assertEqual(result["latency"]["all_cases"]["candidate"]["planned"], len(self.manifest["cases"]))

    def test_incomplete_run_keeps_progress_unknown(self):
        partial = json.dumps({"results": default_results(self.manifest)[:10]}).encode()[:500]
        cand = self.side("candidate", exit_code=None, timed_out=True, stdout=partial)
        result, code = self.compare(cand=cand)
        self.assertEqual(code, ric.EXIT_COMPARABLE, result["errors"])
        d = result["denominators"]["candidate"]["benign"]
        self.assertEqual((d["planned"], d["attempted"], d["not_run"], d["unobserved"], d["timeout"]), (24, None, None, 24, 1))
        attack = result["outcomes"]["attack"]
        self.assertEqual(attack["paired_conditional"]["n"], 0)
        self.assertEqual(attack["candidate"]["missing_outcome_bounds"], [0.0, 1.0])
        self.assertEqual(result["latency"]["attack"]["candidate"]["censored_by_run_timeout"], 24)
        self.assertTrue(attack["overall_change"].startswith("not_established"))

    def test_adapter_failure_is_not_replaced_by_a_rerun(self):
        root = self.tmp / "r"
        self.side("candidate", root=root, attempt=1, exit_code=2, stdout=b"")
        cand = self.side("candidate", root=root, attempt=2)
        result, code = self.compare(cand=cand)
        self.assertEqual(result["sides"]["candidate"]["attempt"], "attempt-001")
        self.assertFalse(result["sides"]["candidate"]["observable"])
        self.assertEqual(result["attempts"]["candidate"][1]["use"], "retained, not used: after the measurement")

    def test_build_failure_before_measurement_is_listed(self):
        root = self.tmp / "r"
        self.side("candidate", root=root, attempt=1, status="build_failed")
        cand = self.side("candidate", root=root, attempt=2)
        result, code = self.compare(cand=cand)
        self.assertEqual(code, ric.EXIT_COMPARABLE)
        self.assertEqual(result["sides"]["candidate"]["attempt"], "attempt-002")
        self.assertTrue(result["attempts"]["candidate"][0]["use"].startswith("not measured"))

    def test_source_claim_checked_against_git_objects(self):
        # The run claims the candidate commit but carries the baseline adapter blob: the Git object
        # store, not another editable field, refuses it.
        base_blob = self.git.blob_id(self.pre["revisions"]["baseline"]["commit"],
                                     "crates/agentfw/examples/result_inspection_corpus.rs")

        def swap(run, _):
            run["checkout"]["inputs"]["crates/agentfw/examples/result_inspection_corpus.rs"]["blob"] = base_blob
        self.assertInvalid(self.compare(cand=self.side("candidate", run_edit=swap)), "source_mismatch")

    def test_executed_artifact_differs_from_built_artifact(self):
        def swap(run, _):
            run["execution"]["artifact_sha256_after"] = "c" * 64
        self.assertInvalid(self.compare(cand=self.side("candidate", run_edit=swap)), "artifact_integrity")

    def test_report_identity_must_match_built_artifact(self):
        def other(report):
            report["identities"]["adapter_sha256"] = "d" * 64
        self.assertInvalid(self.compare(cand=self.side("candidate", report_edit=other)), "identity_mismatch")

    def test_unclean_checkout(self):
        def dirty(run, _):
            run["checkout"]["clean_after"] = False
        self.assertInvalid(self.compare(cand=self.side("candidate", run_edit=dirty)), "source_unclean")

    def test_revision_not_on_accepted_main(self):
        pre = json.loads(PRE.read_bytes())
        # SOU-123's own topic commit: an ancestor of main, but never a first-parent main commit.
        pre["revisions"]["candidate"]["commit"] = "b0f9b217a71de3018b67381051ba7f34c2c6a00e"
        path = self.tmp / "pre.json"
        path.write_bytes(json.dumps(pre).encode())
        sha = ric._sha(path.read_bytes())
        base = self.side("baseline", pre_sha=sha)
        cand = self.side("candidate", pre_sha=sha, commit=pre["revisions"]["candidate"]["commit"])
        self.assertInvalid(self.compare(base, cand, pre=path), "not_accepted_main")

    def test_short_or_wrong_predeclaration(self):
        pre = json.loads(PRE.read_bytes())
        pre["revisions"]["baseline"]["commit"] = "68d8a597"
        path = self.tmp / "pre.json"
        path.write_bytes(json.dumps(pre).encode())
        self.assertInvalid(self.compare(pre=path), "invalid_predeclaration")
        root = self.tmp / "x"
        base = self.side("baseline", pre_sha="e" * 64, root=root)
        self.assertInvalid(self.compare(base, self.side("candidate", root=root)), "predeclaration_mismatch")

    def test_grouping_edit_after_declaration(self):
        pre = json.loads(PRE.read_bytes())
        first = sorted(pre["grouping"]["resampling_units"])[0]
        pre["grouping"]["resampling_units"][first] = "g999"
        path = self.tmp / "pre.json"
        path.write_bytes(json.dumps(pre).encode())
        sha = ric._sha(path.read_bytes())
        self.assertInvalid(self.compare(self.side("baseline", pre_sha=sha), self.side("candidate", pre_sha=sha), pre=path),
                           "grouping_drift")

    def test_amendment_governs_attempts_after_it(self):
        path, sha, argv = self.amendment()

        def jobs(run, _):
            run["build"]["argv"] = list(argv)
        root = self.tmp / "ok"
        self.side("baseline", attempt=1, status="build_failed", root=root)
        base = self.side("baseline", attempt=2, pre_sha=sha, run_edit=jobs, root=root)
        cand = self.side("candidate", pre_sha=sha, run_edit=jobs, root=root)
        result, code = self.compare(base, cand, amendments=[path])
        self.assertEqual(code, ric.EXIT_COMPARABLE, result["errors"] or result["non_comparable"])
        self.assertEqual(result["predeclaration"]["governing_sha256"], sha)
        self.assertEqual([a["use"].split(":")[0] for a in result["attempts"]["baseline"]], ["not measured", "measurement"])
        # The same runs without the amendment: the build command no longer matches a declaration.
        self.assertInvalid(self.compare(base, cand), "predeclaration_mismatch")
        # An old-argv run recorded under the amendment is non-comparable.
        other = self.tmp / "old"
        _, code = self.compare(self.side("baseline", pre_sha=sha, root=other), self.side("candidate", pre_sha=sha,
                               run_edit=jobs, root=other), amendments=[path])
        self.assertEqual(code, ric.EXIT_NON_COMPARABLE)

    def test_amendment_after_measurement_is_refused(self):
        path, sha, argv = self.amendment()

        def jobs(run, _):
            run["build"]["argv"] = list(argv)
        root = self.tmp / "late"
        self.side("baseline", attempt=1, root=root)  # executed under the original declaration
        base = self.side("baseline", attempt=2, pre_sha=sha, run_edit=jobs, root=root)
        cand = self.side("candidate", pre_sha=sha, run_edit=jobs, root=root)
        self.assertInvalid(self.compare(base, cand, amendments=[path]), "predeclaration_mismatch")

    def test_amendment_may_only_add_jobs(self):
        argv = self.pre["build"]["argv"]
        sides = (self.side("baseline"), self.side("candidate"))
        for name, bad in (("release", argv[:3] + ["--jobs", "2"] + argv[3:] + ["--release"]),
                          ("profile", argv[:3] + ["--profile", "release"] + argv[3:]),
                          ("zero", argv[:3] + ["--jobs", "0"] + argv[3:]),
                          ("moved", argv + ["--jobs", "2"])):
            path, _, _ = self.amendment(f"{name}.json", argv=bad)
            with self.subTest(name):
                self.assertInvalid(self.compare(*sides, amendments=[path]), "invalid_predeclaration")
        path, _, _ = self.amendment("chain.json", amends="f" * 64)
        self.assertInvalid(self.compare(*sides, amendments=[path]), "predeclaration_mismatch")
        path, _, _ = self.amendment("extra.json", toolchain="1.97.0")
        self.assertInvalid(self.compare(*sides, amendments=[path]), "invalid_predeclaration")

    def test_malformed_run_record_is_invalid_not_a_crash(self):
        edits = {
            "checkout_list": lambda run, _: run.__setitem__("checkout", []),
            "build_null": lambda run, _: run.__setitem__("build", None),
            "artifact_text": lambda run, _: run["build"].__setitem__("artifact", "x"),
            "stdout_entry_missing": lambda run, _: run["execution"].pop("stdout"),
            "exit_code_text": lambda run, _: run["execution"].__setitem__("exit_code", "0"),
            "problems_text": lambda run, _: run.__setitem__("problems", "x"),
        }
        base = self.side("baseline")
        for n, (name, edit) in enumerate(edits.items()):
            with self.subTest(name):
                result, code = self.compare(base, self.side("candidate", run_edit=edit, root=self.tmp / f"m{n}"))
                self.assertEqual(code, ric.EXIT_INVALID, result["errors"])
                self.assertIn(result["errors"][0]["code"], ("invalid_record", "build_identity_missing"))

    def test_findings_and_rule_types(self):
        def bad(results):
            next(r for r in results if "findings" in r)["findings"] = "not a list"
        self.assertInvalid(self.compare(cand=self.side("candidate", self._results(bad))), "malformed_adapter_output")

    def test_recorder_identity_accepts_only_declared_checkout_forms(self):
        raw = self.git.show("HEAD", ric.RECORDER_SOURCES["recorder_sha256"])
        forms = {"crlf": (ric._sha(raw.replace(b"\n", b"\r\n")), None),
                 "trailing_space": (ric._sha(raw + b" "), "recorder_unidentified"),
                 "unknown": ("0" * 64, "recorder_unidentified")}
        base = self.side("baseline")
        for n, (name, (digest, error)) in enumerate(forms.items()):
            def edit(run, _, digest=digest):
                run["recorder"]["recorder_sha256"] = digest
            with self.subTest(name):
                result, code = self.compare(base, self.side("candidate", run_edit=edit, root=self.tmp / f"r{n}"))
                if error:
                    self.assertInvalid((result, code), error)
                else:
                    self.assertEqual(code, ric.EXIT_COMPARABLE, result["errors"])
                    source = result["attempts"]["candidate"][0]["recorder_source"]
                    self.assertEqual(source["result_inspection_record.py"]["checkout_form"], "lf_to_crlf")

    def test_toolchain_mismatch_is_non_comparable(self):
        def old(run, _):
            run["toolchain"]["rustc_release"] = "1.97.0"
        result, code = self.compare(base=self.side("baseline", run_edit=old))
        self.assertEqual(code, ric.EXIT_NON_COMPARABLE)
        self.assertIsNone(result["outcomes"])

    def test_negative_controls_script_on_synthetic_evidence(self):
        import result_inspection_controls as controls
        evidence = self.tmp / "evidence"
        (evidence / "runs").mkdir(parents=True)
        shutil.copyfile(PRE, evidence / "predeclaration.json")
        cases = sorted(c["case_id"] for c in self.manifest["cases"] if c["label"] == "attack")
        # As in the real evidence: a failed baseline attempt precedes the measured one.
        self.side("baseline", attempt=1, status="build_failed", root=evidence / "runs")
        self.side("baseline", attempt=2, root=evidence / "runs")
        self.side("candidate", default_results(self.manifest, {cases[0]: "Allow"}), root=evidence / "runs")
        result = controls.run_controls(evidence, ROOT)
        self.assertTrue(result["all_passed"], [r for r in result["controls"] if not r["passed"]])
        self.assertEqual(len(result["controls"]), len(controls.CONTROLS))

    def test_oversized_input_refused_before_parsing(self):
        def big(run, run_dir):
            raw = b" " * (ric.LIMITS["max_stdout_bytes"] + 1)
            run["execution"]["stdout"] = entry(run_dir, "adapter-stdout.json", raw)
        self.assertInvalid(self.compare(cand=self.side("candidate", run_edit=big)), "custody_incomplete")


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sou191-rec-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def messages(self, *paths):
        return "\n".join(json.dumps({"reason": "compiler-artifact", "executable": str(p),
                                     "target": {"name": "result_inspection_corpus", "kind": ["example"]}})
                         for p in paths).encode()

    def test_artifact_only_from_cargo_inside_fresh_target(self):
        target = self.tmp / "target"
        (target / "debug/examples").mkdir(parents=True)
        exe = target / "debug/examples/result_inspection_corpus.exe"
        exe.write_bytes(b"x")
        self.assertEqual(rec.select_artifact(self.messages(exe) + b"\nnot json\n", target), exe.resolve())
        outside = self.tmp / "elsewhere.exe"
        outside.write_bytes(b"x")
        with self.assertRaises(rec.Refused):
            rec.select_artifact(self.messages(outside), target)
        with self.assertRaises(rec.Refused):
            rec.select_artifact(self.messages(exe, exe), target)
        with self.assertRaises(rec.Refused):
            rec.select_artifact(b"", target)

    def test_artifact_replaced_before_or_during_execution(self):
        # A real executable boundary: the hashed file is the program the interpreter runs.
        script = self.tmp / "adapter.py"
        script.write_text("print('{\"results\": []}')\n", encoding="utf-8")
        built = rec.file_sha(script)
        script.write_text("print('{\"results\": [1]}')\n", encoding="utf-8")
        with self.assertRaises(rec.Refused):
            rec.execute_verified([sys.executable, str(script)], script, built, 30)
        script.write_text("import pathlib, sys\npathlib.Path(sys.argv[0]).write_text('# replaced\\n')\n", encoding="utf-8")
        built = rec.file_sha(script)
        execution, out, _ = rec.execute_verified([sys.executable, str(script)], script, built, 30)
        self.assertEqual(execution["artifact_sha256_before"], built)
        self.assertNotEqual(execution["artifact_sha256_after"], built)

    def test_timeout_keeps_partial_output(self):
        script = self.tmp / "slow.py"
        script.write_text("import sys, time\nsys.stdout.write('{\"results\": [');sys.stdout.flush()\ntime.sleep(30)\n",
                          encoding="utf-8")
        execution, out, _ = rec.execute_verified([sys.executable, str(script)], script, rec.file_sha(script), 2)
        self.assertTrue(execution["timed_out"])
        self.assertIsNone(execution["exit_code"])

    def test_environment_and_cargo_config_refusals(self):
        self.assertEqual(rec.refused_environment({"RUSTFLAGS": "-C opt-level=3", "CARGO_TARGET_DIR": "x",
                                                  "CARGO_PROFILE_DEV_DEBUG": "0", "PATH": "p"}),
                         ["CARGO_PROFILE_DEV_DEBUG", "CARGO_TARGET_DIR", "RUSTFLAGS"])
        start = self.tmp / "a" / "b"
        start.mkdir(parents=True)
        (self.tmp / "a" / ".cargo").mkdir()
        (self.tmp / "a" / ".cargo" / "config.toml").write_text("[build]\n", encoding="utf-8")
        found = rec.cargo_configs(start, {"CARGO_HOME": str(self.tmp / "home")})
        self.assertEqual([Path(p).name for p in found], ["config.toml"])

    def test_sanitizer_removes_local_paths(self):
        clean = rec.sanitizer((self.tmp, "<work>"), (Path.home(), "<home>"))
        text = json.dumps({"p": str(self.tmp / "src" / "x.rs"), "q": str(Path.home())}).encode()
        out = clean(text).decode()
        self.assertNotIn(str(self.tmp).replace("\\", "\\\\"), out)
        self.assertIn("<work>", out)
        self.assertIn("<home>", out)
        twice = json.dumps({"m": json.dumps({"p": str(self.tmp / "out.o")})}).encode()
        self.assertNotIn(str(self.tmp.resolve().drive), clean(twice).decode())
        dump = clean(b"  PATH = Some(C:\\Windows;D:\\Tools (x86)\\bin;)\n  CC = None\n").decode()
        self.assertEqual(dump, "  PATH = Some(<redacted: 3 entries>)\n  CC = None\n")

    def test_attempts_are_never_overwritten(self):
        out = self.tmp / "role"
        self.assertEqual(rec.next_attempt(out).name, "attempt-001")
        self.assertEqual(rec.next_attempt(out).name, "attempt-002")

    def test_checkout_verification_detects_changed_build_input(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        run = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false", *a],  # noqa: E731
                                        check=True, capture_output=True)
        run("init", "-q")
        for path in ric.BUILD_INPUTS + ("eval/sou123/payloads/x01-a.txt",):
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(f"{path}\r\n".encode())
        run("add", "-A")
        run("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "fixture")
        commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        git = ric.Git(repo)
        ok = rec.verify_checkout(git, repo, commit, ["x01-a"])
        self.assertTrue(ok["clean"] and ok["inputs_match_blobs"], ok)
        (repo / "Cargo.lock").write_bytes(b"changed\r\n")
        bad = rec.verify_checkout(git, repo, commit, ["x01-a"])
        self.assertFalse(bad["clean"])
        self.assertIn("Cargo.lock", bad["mismatched"])


if __name__ == "__main__":
    unittest.main()
