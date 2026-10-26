# SPDX-License-Identifier: Apache-2.0
"""Focused regressions for the SOU-153 paired development-regression comparator.

Standard library only; no model, provider or upstream checkout. Synthetic inputs come from
``paired_regression_controls`` and pass the unchanged matched-protocol validators.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import agentdojo_live as adapter
import agentdojo_protocol as protocol
import paired_regression as pr
import paired_regression_controls as controls


def write(directory: Path, name: str, value) -> Path:
    path = directory / name
    path.write_bytes(value if isinstance(value, bytes) else controls.encode(value))
    return path


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = Path(tempfile.mkdtemp())
        cls.report = controls.write_controls(cls.temp / "out")
        cls.controls = cls.temp / "out" / "controls"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def result(self, name):
        return json.loads((self.temp / "out" / "results" / name / "comparison.json").read_text(encoding="utf-8"))

    def compare(self, plan, run, inputs=True, families=True, limits=None, baseline=None):
        directory = Path(tempfile.mkdtemp(dir=self.temp))
        plan_path = write(directory, "candidate-plan.json", plan)
        run_path = write(directory, "candidate-run.json", run)
        base_plan, base_run = baseline or (self.controls / "baseline-plan.json", self.controls / "baseline-run.json")
        return pr.compare(base_plan, base_run, plan_path, run_path,
                          (self.controls / "inputs.json") if inputs is True else inputs,
                          (self.controls / "families.json") if families is True else families, limits)

    def codes(self, result):
        return {r["code"] for r in result["comparability"]["reasons"]} | \
            {e["code"] for e in result["input_validity"]["errors"]}


class Controls(Fixture):
    def test_every_control_has_its_expected_status_and_exit_code(self):
        failed = [(name, code, codes) for name, ok, code, codes, _ in self.report if not ok]
        self.assertEqual(failed, [])

    def test_improved_and_regressed_transitions_are_exact(self):
        improved = self.result("improved")["outcomes"]
        self.assertEqual(improved["security"]["transitions"],
                         {"improved": 10, "regressed": 0, "unchanged_true": 2, "unchanged_false": 12})
        self.assertEqual(improved["utility"]["transitions"]["regressed"], 0)
        regressed = self.result("regressed")["outcomes"]
        self.assertEqual(regressed["security"]["transitions"]["regressed"], 6)
        self.assertEqual(regressed["utility"]["transitions"]["regressed"], 4)
        self.assertEqual(regressed["benign_interruption"]["transitions"]["regressed"], 4)
        self.assertEqual(regressed["security"]["paired_conditional"]["difference"], 0.25)

    def test_a_valid_regression_is_a_comparable_report_without_a_verdict(self):
        result = self.result("regressed")
        self.assertEqual(result["comparability"]["status"], "conditionally_comparable")
        self.assertEqual(result["input_validity"]["status"], "valid")
        self.assertEqual(result["completeness"]["status"], "complete")
        self.assertIsNone(result["readiness_verdict"])
        self.assertIsNone(result["outcomes"]["overall_direction"])
        self.assertNotIn("limits_verdict", json.dumps(result))

    def test_missing_work_cannot_improve_the_planned_denominator_result(self):
        result = self.result("incomplete_hard_cases_dropped")
        security = result["outcomes"]["security"]
        self.assertEqual(result["completeness"]["status"], "partial")
        self.assertEqual(result["completeness"]["paired"]["paired_evaluable"], 18)
        self.assertEqual(result["completeness"]["candidate"]["all"],
                         {"planned": 48, "attempted": 19, "evaluable": 18, "incomplete": 1, "not_run": 29})
        # Conditional on the evaluated subset the candidate looks perfect ...
        self.assertEqual(security["paired_conditional"]["difference"], -1.0)
        # ... but on the fixed planned set missing outcomes may all be missed attacks.
        self.assertTrue(security["missing_outcome_difference_bounds"]["includes_zero"])
        self.assertEqual(security["overall_change"], "not_established: missing-outcome bounds include zero")

    def test_missing_outcome_bound_formulas_on_the_planned_set(self):
        # Hand-derived from the generator: 12 user tasks x 2 repetitions, so 24 attacked and 24 benign
        # planned units. Baseline is complete: 12/24 missed attacks, 22/24 benign successes, 2/24 benign
        # Asks, 12/24 attacked utility. The candidate stops at task 05's attack: 8 attacked units
        # (none missed, all denied) and 10 benign units (all succeed, none interrupted) are evaluable.
        # Per side the bounds are [k/P, (k + P - evaluable)/P]; the difference bounds are
        # [cand_low - base_high, cand_high - base_low].
        outcomes = self.result("incomplete_hard_cases_dropped")["outcomes"]
        expected = {
            "security": ((24, 24, 8, 8), [0.5, 0.5], [0.0, 16 / 24], (0 - 0.5, 16 / 24 - 0.5), (1.0, 0.0)),
            "utility": ((24, 24, 10, 10), [22 / 24, 22 / 24], [10 / 24, 1.0], (10 / 24 - 22 / 24, 1.0 - 22 / 24),
                        (1.0, 1.0)),
            "benign_interruption": ((24, 24, 10, 10), [2 / 24, 2 / 24], [0.0, 14 / 24],
                                    (0 - 2 / 24, 14 / 24 - 2 / 24), (0.0, 0.0)),
            "utility_under_attack": ((24, 24, 8, 8), [0.5, 0.5], [0.0, 16 / 24], (0 - 0.5, 16 / 24 - 0.5),
                                     (1.0, 0.0)),
        }
        for name, (denominators, base, cand, diff, conditional) in expected.items():
            with self.subTest(metric=name):
                metric = outcomes[name]
                self.assertEqual(tuple(metric["denominators"].values()), denominators)
                self.assertEqual(metric["baseline"]["missing_outcome_bounds"], [round(v, 6) for v in base])
                self.assertEqual(metric["candidate"]["missing_outcome_bounds"], [round(v, 6) for v in cand])
                bounds = metric["missing_outcome_difference_bounds"]
                self.assertAlmostEqual(bounds["lower"], diff[0], places=5)
                self.assertAlmostEqual(bounds["upper"], diff[1], places=5)
                self.assertIn("not a confidence interval", bounds["kind"])
                self.assertTrue(bounds["includes_zero"])
                self.assertTrue(metric["overall_change"].startswith("not_established"))
                paired = metric["paired_conditional"]
                self.assertEqual((paired["baseline"]["rate"], paired["candidate"]["rate"]), conditional)
                self.assertIn("different subset", paired["subset"])

    def test_difference_bounds_pair_opposite_extremes_when_both_sides_are_incomplete(self):
        # Baseline stops at task 08's attack: 14 attacked units evaluable (12 missed), 16 benign units
        # evaluable (all succeed). Its bounds are [12/24, 22/24] and [16/24, 24/24]. The candidate is
        # the incomplete control: [0, 16/24] and [10/24, 24/24]. The difference must pair opposite
        # extremes; pairing like extremes would wrongly give [-0.5, -0.25] for security.
        directory = Path(tempfile.mkdtemp(dir=self.temp))
        base_plan = controls.plan("baseline")
        base_run = controls.run("baseline", base_plan, controls.baseline_outcome,
                                stop=(controls._case(7, True), 1, True, "provider_failure"))
        candidate = self.controls / "incomplete_hard_cases_dropped"
        result, code = self.compare((candidate / "candidate-plan.json").read_bytes(),
                                    (candidate / "candidate-run.json").read_bytes(),
                                    baseline=(write(directory, "bp.json", base_plan), write(directory, "br.json", base_run)))
        self.assertEqual(code, pr.EXIT_COMPARABLE)
        security, utility = result["outcomes"]["security"], result["outcomes"]["utility"]
        self.assertEqual(security["baseline"]["missing_outcome_bounds"], [0.5, round(22 / 24, 6)])
        bounds = security["missing_outcome_difference_bounds"]
        self.assertAlmostEqual(bounds["lower"], 0 - 22 / 24, places=5)
        self.assertAlmostEqual(bounds["upper"], 16 / 24 - 12 / 24, places=5)
        self.assertTrue(bounds["includes_zero"])
        bounds = utility["missing_outcome_difference_bounds"]
        self.assertAlmostEqual(bounds["lower"], 10 / 24 - 1.0, places=5)
        self.assertAlmostEqual(bounds["upper"], 1.0 - 16 / 24, places=5)
        # Baseline evaluates 14 + 16 = 30 units; the candidate's 18 are a subset of them.
        self.assertEqual(result["completeness"]["paired"],
                         {"planned": 48, "paired_evaluable": 18, "evaluable_baseline_only": 12,
                          "evaluable_candidate_only": 0, "evaluable_neither": 18})

    def test_zero_denominator_has_no_rates(self):
        result = self.result("all_unevaluable")
        paired = result["outcomes"]["security"]["paired_conditional"]
        self.assertEqual((paired["n"], paired["status"], paired["difference"]), (0, "zero_denominator", None))
        self.assertIsNone(paired["candidate"]["rate"])
        self.assertEqual(result["outcomes"]["security"]["transitions"],
                         {"improved": 0, "regressed": 0, "unchanged_true": 0, "unchanged_false": 0})

    def test_failures_keep_producer_reasons_and_timeouts_stay_undistinguished(self):
        failures = self.result("all_unevaluable")["completeness"]["failures"]["candidate"]
        self.assertEqual(failures["stopped_units"][0]["reason"], "provider_failure")
        self.assertEqual(failures["stopped_units"][0]["error_type"], "AdapterError")
        self.assertEqual(failures["not_run_units"], 47)
        self.assertIsNone(failures["timeouts"]["count"])
        self.assertEqual(failures["timeouts"]["availability"], "undistinguished")

    def test_unknown_is_unavailable_and_ask_is_not_unknown(self):
        result = self.result("improved")
        self.assertEqual(result["unknown"]["availability"], "unavailable")
        decisions = result["outcomes"]["policy_decisions"]["baseline"]["benign"]
        self.assertEqual((decisions["ask_observed"], decisions["deny_observed"]), (2, 0))

    def test_policy_refusals_keep_recorded_evaluator_outcomes(self):
        outcomes = self.result("no_change")["outcomes"]
        # Denied attacks keep utility=false and injection_success=false as the evaluators recorded them.
        self.assertEqual(outcomes["utility_under_attack"]["baseline"]["own_evaluable"]["k"], 12)
        self.assertEqual(outcomes["security"]["baseline"]["own_evaluable"]["k"], 12)
        self.assertEqual(outcomes["policy_decisions"]["baseline"]["attacked"]["deny_observed"], 12)

    def test_pins_and_input_hashes_are_shown_for_both_sides(self):
        result = self.result("improved")
        pins = result["comparability"]["pins"]
        self.assertEqual(pins["baseline"]["plan_policy_sha256"], "2" * 64)
        self.assertEqual(pins["candidate"]["run"]["agent_binary_sha256"], "3" * 64)
        self.assertIn("plan_policy_sha256", pins["differs"])
        self.assertEqual({i["role"] for i in result["inputs"]},
                         {"baseline_plan", "baseline_run", "candidate_plan", "candidate_run", "inputs", "families"})
        self.assertTrue(all(len(i["sha256"]) == 64 for i in result["inputs"]))

    def test_units_carry_label_identity_cluster_and_family(self):
        unit = self.result("improved")["units"][2]
        self.assertEqual(unit["expected_label"], "attack")
        self.assertEqual(unit["input_identity"], "partially_verified")
        self.assertEqual((unit["semantic_family"], unit["dependency_cluster"]), ("calendar", "g001"))
        self.assertEqual(self.result("improved")["grouping"]["resampling_units"]["count"], 6)

    def test_public_examples_are_explicitly_non_comparable(self):
        identity = self.result("public_identity_no_change")
        self.assertEqual(identity["input_validity"]["status"], "valid")
        self.assertEqual(identity["comparability"]["input_binding"]["status"], "declared_unverified")
        self.assertIsNone(identity["outcomes"])
        fresh = self.result("public_dev_vs_fresh")
        self.assertEqual(fresh["completeness"]["failures"]["candidate"]["by_reason"], {"budget_exhausted": 1})


class InputBinding(Fixture):
    def test_inventory_hash_matches_the_producer_verify_checkout(self):
        if shutil.which("git") is None:
            self.skipTest("git is unavailable")
        checkout = Path(tempfile.mkdtemp(dir=self.temp))
        files = dict(controls.source_files(), **{"src/x/crlf.txt": "a\r\nb\n", "src/x/Upper.py": "Z = 1\n"})
        for name, content in files.items():
            (checkout / name).parent.mkdir(parents=True, exist_ok=True)
            (checkout / name).write_bytes(content.encode("utf-8"))
        (checkout / "LICENSE").write_text("synthetic\n", encoding="utf-8")

        def git(*arguments):
            return subprocess.run(["git", "-C", str(checkout), "-c", "core.autocrlf=false", *arguments],
                                  capture_output=True, check=True, text=True).stdout.strip()
        git("init", "-q")
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "fixture")
        with patch.object(adapter, "REVISION", git("rev-parse", "HEAD")):
            producer = adapter.verify_checkout(checkout)["source_inventory_sha256"]
        self.assertEqual(pr.source_inventory_sha256(files), producer)

    def test_changed_source_bytes_fail_binding(self):
        bundle = controls.bundle()
        name = sorted(bundle["files"])[0]
        bundle["files"][name] += "# edited\n"
        directory = Path(tempfile.mkdtemp(dir=self.temp))
        improved = self.controls / "improved"
        result, code = self.compare((improved / "candidate-plan.json").read_bytes(),
                                    (improved / "candidate-run.json").read_bytes(),
                                    inputs=write(directory, "inputs.json", bundle))
        self.assertEqual(code, pr.EXIT_NON_COMPARABLE)
        self.assertIn("input_binding_failed", self.codes(result))

    def test_links_are_reported_separately_and_case_semantic_input_stays_unverified(self):
        result = self.result("improved")
        comparability = result["comparability"]
        binding = comparability["input_binding"]
        self.assertEqual(binding["status"], "partially_verified")
        self.assertEqual({link: value["status"] for link, value in binding["links"].items()},
                         {"run_to_plan": "verified", "source_to_inventory": "verified",
                          "injections_to_plan": "verified", "case_semantic_input": "unverified"})
        self.assertEqual(comparability["status"], "conditionally_comparable")
        self.assertEqual({gap["code"] for gap in comparability["gaps"]},
                         {"case_semantic_input_unverified", "synthetic_inputs"})
        self.assertIn("not evidence of any execution", binding["provenance"]["description"])

    def test_a_broken_link_is_attributed_to_its_own_link(self):
        bundle = controls.bundle()
        first = sorted(bundle["injections"])[0]
        bundle["injections"][first] = {controls.VECTOR: "different string"}
        directory = Path(tempfile.mkdtemp(dir=self.temp))
        improved = self.controls / "improved"
        result, code = self.compare((improved / "candidate-plan.json").read_bytes(),
                                    (improved / "candidate-run.json").read_bytes(),
                                    inputs=write(directory, "inputs.json", bundle))
        links = result["comparability"]["input_binding"]["links"]
        self.assertEqual(code, pr.EXIT_NON_COMPARABLE)
        self.assertEqual((links["source_to_inventory"]["status"], links["injections_to_plan"]["status"]),
                         ("verified", "mismatch"))

    def test_matching_declarations_without_a_bundle_are_not_a_verified_comparison(self):
        improved = self.controls / "improved"
        result, code = self.compare((improved / "candidate-plan.json").read_bytes(),
                                    (improved / "candidate-run.json").read_bytes(), inputs=None, families=None)
        self.assertEqual((code, result["comparability"]["status"]), (pr.EXIT_NON_COMPARABLE, "non_comparable"))
        self.assertIsNone(result["outcomes"])


class Families(Fixture):
    def improved(self, families):
        directory = Path(tempfile.mkdtemp(dir=self.temp))
        improved = self.controls / "improved"
        return self.compare((improved / "candidate-plan.json").read_bytes(),
                            (improved / "candidate-run.json").read_bytes(),
                            families=write(directory, "families.json", families))

    def test_uncovered_or_repeated_cases_are_non_comparable(self):
        families = controls.families()
        moved = families["families"]["calendar"].pop()
        result, code = self.improved(families)
        self.assertEqual(code, pr.EXIT_NON_COMPARABLE)
        self.assertIn("semantic_families_mismatch", self.codes(result))
        families["families"]["calendar"].append(moved)
        families["families"]["email"].append(moved)
        result, code = self.improved(families)
        self.assertIn("in more than one family", json.dumps(result["comparability"]["reasons"]))

    def test_missing_families_are_a_listed_gap_never_a_verified_comparison(self):
        improved = self.controls / "improved"
        result, code = self.compare((improved / "candidate-plan.json").read_bytes(),
                                    (improved / "candidate-run.json").read_bytes(), families=None)
        self.assertEqual(code, pr.EXIT_COMPARABLE)
        self.assertEqual(result["comparability"]["status"], "conditionally_comparable")
        self.assertIn("semantic_families_unavailable", {gap["code"] for gap in result["comparability"]["gaps"]})
        self.assertEqual(result["grouping"]["semantic_families"]["status"], "unavailable")
        self.assertIsNone(result["grouping"]["resampling_units"])

    def test_families_cannot_carry_labels(self):
        families = dict(controls.families(), expected_labels={"x": "benign"})
        result, code = self.improved(families)
        self.assertEqual(code, pr.EXIT_INVALID)
        self.assertIn("invalid_families", self.codes(result))

    def test_shared_injection_identity_merges_dependency_clusters(self):
        cases = controls.cases(controls.USER_TASKS[:4])
        cases[3]["injection_task_id"] = cases[1]["injection_task_id"]
        grouping, dependency, _, _ = pr.grouping(cases, None)
        self.assertEqual(grouping["dependency_clusters"]["count"], 3)
        self.assertEqual(dependency[cases[1]["case_id"]], dependency[cases[2]["case_id"]])
        self.assertEqual(grouping["semantic_families"]["status"], "unavailable")


class Bounds(Fixture):
    def improved(self, limits, plan=None, run=None):
        improved = self.controls / "improved"
        return self.compare(plan if plan is not None else (improved / "candidate-plan.json").read_bytes(),
                            run if run is not None else (improved / "candidate-run.json").read_bytes(), limits=limits)

    def test_oversized_files_are_rejected_before_reading(self):
        with patch("builtins.open", side_effect=AssertionError("read attempted")):
            result, code = self.improved({"max_file_bytes": 100})
        self.assertEqual(code, pr.EXIT_INVALID)
        self.assertEqual({e["code"] for e in result["input_validity"]["errors"]}, {"file_too_large"})
        self.assertEqual(result["comparability"]["status"], "non_comparable")

    def test_record_counts_are_bounded_before_validation(self):
        with patch.object(protocol, "validate_run", side_effect=AssertionError("validated")):
            result, code = self.improved({"max_run_rows": 10})
        self.assertEqual(code, pr.EXIT_INVALID)
        self.assertIn("too_many_records", self.codes(result))
        result, code = self.improved({"max_plan_cases": 5})
        self.assertIn("too_many_records", self.codes(result))

    def test_huge_declared_repetitions_are_rejected(self):
        plan = controls.plan("candidate")
        plan["sets"]["development"]["repetitions"] = 10 ** 12
        result, code = self.improved(None, plan=plan)
        self.assertEqual(code, pr.EXIT_INVALID)
        self.assertIn("too_many_records", self.codes(result))

    def test_duplicate_json_fields_are_rejected(self):
        raw = (self.controls / "improved" / "candidate-run.json").read_bytes()
        result, code = self.improved(None, run=raw.replace(b'"status":', b'"status": "completed", "status":', 1))
        self.assertEqual(code, pr.EXIT_INVALID)
        self.assertIn("malformed_json", self.codes(result))

    def test_undefended_drift_is_reported(self):
        plan = controls.plan("candidate")

        def drifted(task, attacked, repetition, defended):
            if not defended and task == 0 and not attacked:
                return (False, None, 0, 0, 100)
            return controls.improved_outcome(task, attacked, repetition, defended)
        result, code = self.compare(plan, controls.run("candidate", plan, drifted))
        self.assertEqual(code, pr.EXIT_COMPARABLE)
        self.assertEqual(len(result["outcomes"]["undefended_arm_drift"]["differing_units"]), 2)


class Command(Fixture):
    def test_cli_writes_comparison_and_refuses_a_non_empty_out_dir(self):
        improved = self.controls / "improved"
        args = ["--baseline-plan", str(self.controls / "baseline-plan.json"),
                "--baseline-run", str(self.controls / "baseline-run.json"),
                "--candidate-plan", str(improved / "candidate-plan.json"),
                "--candidate-run", str(improved / "candidate-run.json"),
                "--inputs", str(self.controls / "inputs.json"), "--families", str(self.controls / "families.json")]
        out = self.temp / "cli"
        with patch("sys.stdout"):
            self.assertEqual(pr.main(args + ["--out-dir", str(out)]), pr.EXIT_COMPARABLE)
            self.assertEqual(json.loads((out / "comparison.json").read_text(encoding="utf-8"))["comparability"]["status"],
                             "conditionally_comparable")
            with patch("sys.stderr"):
                self.assertEqual(pr.main(args + ["--out-dir", str(out)]), pr.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
