# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("sou159",ROOT/"scripts/verify-sou159-replace-file.py")
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


def seed():
    rows=[]
    for case in probe.CASES:
        row={"case":case,"status":"pass","committed":case in probe.COMMITTED,
             "child_dispatches":0,"outside_unchanged":True,"cleanup_verified":True,"target_unchanged":True,
             "old":{"inode":1},"after":{"inode":2,"sha256":probe.sha(probe.NEW.encode())}}
        row.update(publication_gates=1 if case in probe.COMMITTED else 0,publication_binding_matches=True)
        row.update(approved_bindings=["a"*64],publication_bindings=["a"*64] if case in probe.COMMITTED else [])
        if case in probe.FAULT_ERRORS:
            row.update(executor_error=probe.FAULT_ERRORS[case],result_success=False,fault_library_sha256="f"*64,staged_bytes=5)
        if case=="result-withheld":row.update(result_withheld=True,refusal_codes=["resource_replacement_committed","native_provenance_unrecordable","native_provenance_source"])
        if case in {"target-substitution","root-substitution"}:
            row.update(displaced_unchanged=True,displaced_before={"inode":1,"sha256":"d"*64},displaced_after={"inode":1,"sha256":"d"*64})
        rows.append(row)
    return {"platform":"Linux","source_commit":"a"*40,"binary_sha256":"b"*64,"cases":rows}


class ReplacementEvidence(unittest.TestCase):
    def test_public_classifier_keeps_the_complete_normal_replacement_a_known_write(self):
        arguments={"path":"result.txt","content":probe.NEW,"old_sha256":"a"*64,
                   "old_identity":{key:1 for key in probe.fixture.IDENTITY_FIELDS}}
        event={"tool_name":"replace_result","raw_arguments":arguments,
               "tool_description":probe.fixture.TOOLS[0]["description"],"tool_schema":probe.fixture.SCHEMA,"server_id":"sou159"}
        result=subprocess.run([sys.executable,"-I",str(ROOT/"rule_baseline/rule_baseline.py")],
                              input=probe.canonical(event)+b"\n",capture_output=True,timeout=5,check=True)
        prediction=probe.base.strict_json(result.stdout)
        self.assertEqual(prediction["actions"],["write"])
        self.assertFalse(prediction["unknown"])

    def test_complete_finite_projection(self):
        self.assertEqual(probe.validate(seed())["cases"],22)

    def test_no_actual_replacement_cannot_pass(self):
        report=seed()
        for row in report["cases"]:row["committed"]=False
        with self.assertRaises(ValueError):probe.validate(report)

    def test_missing_duplicate_or_reordered_cases_refuse(self):
        for rows in [seed()["cases"][:-1],seed()["cases"]+[seed()["cases"][0]],list(reversed(seed()["cases"]))]:
            report=seed();report["cases"]=rows
            with self.assertRaises(ValueError):probe.validate(report)

    def test_each_independent_guard_is_required(self):
        for field,value in [("status","incomplete"),("child_dispatches",1),("outside_unchanged",False),("cleanup_verified",False)]:
            report=seed();report["cases"][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):probe.validate(report)

    def test_wrong_bytes_or_unchanged_inode_are_not_commit_evidence(self):
        for field,value in [("sha256","c"*64),("inode",1)]:
            report=seed();report["cases"][0]["after"][field]=value
            with self.assertRaises(ValueError):probe.validate(report)

    def test_competing_publication_must_match_one_of_the_exact_approved_calls(self):
        report=seed();row=next(r for r in report["cases"] if r["case"]=="competing-same-version")
        row["approved_bindings"].append("b"*64);row["publication_bindings"]=["b"*64]
        probe.validate(report)
        row["publication_bindings"]=["c"*64]
        with self.assertRaises(ValueError):probe.validate(report)

    def test_substitution_must_also_preserve_the_displaced_original(self):
        for case in ["target-substitution","root-substitution"]:
            report=seed();row=next(r for r in report["cases"] if r["case"]==case)
            row["displaced_after"]["sha256"]="e"*64
            with self.subTest(case=case),self.assertRaises(ValueError):probe.validate(report)

    def test_committed_error_and_partial_progress_cannot_be_relabelled(self):
        for name,field,value in [("committed-error","committed",False),("committed-error","result_success",True),
                                 ("stage-fault","staged_bytes",26),("publication-fault","executor_error","success")]:
            report=seed();row=next(r for r in report["cases"] if r["case"]==name);row[field]=value
            with self.subTest(name=name,field=field),self.assertRaises(ValueError):probe.validate(report)


if __name__=="__main__":unittest.main()
