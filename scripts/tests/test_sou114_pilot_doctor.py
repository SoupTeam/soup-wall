# SPDX-License-Identifier: Apache-2.0
"""Adversarial evidence controls, never a substitute for installed Linux."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sou114", ROOT / "scripts/verify-sou114-pilot-doctor.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class EvidenceControls(unittest.TestCase):
    def fixture(self):
        source = {"commit":"a"*40,"tree":"b"*40,"dirty":False}
        return {"source_before":source,"source_after":source.copy(),"source_files_before":{"owned":"c"*64},"source_files_after":{"owned":"c"*64},
            "cases":[{"case":case,"passed":True,"executed_programs":1} for case in M.CASES],
            "original_profiles_verified":True,"real_managed_daemon":True,
            "real_refusal":{"verdict":"deny","released":False,"useful_prior_read":True,"collector_cleanup":True,"record_sha256":"a"*64,
                            "forced_cleanup":False,"collector_exit_code":0,"process_witness_sha256":"b"*64},
            "workspace_unchanged":True,"operator_config_unchanged":True,"daemon_stopped":True,"skipped":0,"privacy_scan_passed":True,
            "support_exports":[{"name":name,"schema":"sw-agent-doctor-support/1","pilot_schema":"sw-agent-doctor-pilot/1",
                "report_sha256":"a"*64,"report_bytes":100,"manifest_sha256":"b"*64,"manifest_bytes":100,"private_modes_verified":True} for name in M.SUPPORT_NAMES]}

    def test_valid_denominator(self): M.grade(self.fixture())

    def test_rejects_missing_case_or_failed_program_observation(self):
        for mutation in (lambda r:r["cases"].pop(),lambda r:r["cases"][0].update(passed=False),lambda r:r["cases"][0].update(executed_programs=2)):
            value=self.fixture();mutation(value)
            with self.assertRaises(ValueError):M.grade(value)

    def test_rejects_source_changes_skips_and_missing_real_evidence(self):
        for key in ("original_profiles_verified","real_managed_daemon","real_refusal","workspace_unchanged","operator_config_unchanged","daemon_stopped","privacy_scan_passed"):
            value=self.fixture();value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):M.grade(value)
        for mutation in (lambda r:r.update(skipped=1),lambda r:r["source_after"].update(dirty=True),lambda r:r["source_files_after"].update(owned="different")):
            value=self.fixture();mutation(value)
            with self.assertRaises(ValueError):M.grade(value)

    def test_rejects_invented_refusal_and_incomplete_cleanup(self):
        for key,value in (("verdict","allow"),("released",True),("useful_prior_read",False),("collector_cleanup",False),("record_sha256","invalid"),
                          ("collector_exit_code",1),("forced_cleanup",True),("process_witness_sha256","invalid")):
            report=self.fixture();report["real_refusal"][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):M.grade(report)

    def test_rejects_missing_oversized_or_unverified_support(self):
        for mutation in (lambda r:r["support_exports"].pop(),lambda r:r["support_exports"][0].update(report_bytes=128*1024+1),
                         lambda r:r["support_exports"][0].update(private_modes_verified=False),lambda r:r["support_exports"][0].update(manifest_sha256="wrong")):
            report=self.fixture();mutation(report)
            with self.assertRaises(ValueError):M.grade(report)

    def test_scan_refuses_every_canary_and_actual_credentials(self):
        secrets=[*M.CANARIES,b"actual-owned-random-token"]
        M.scan(b"fixed safe codes",secrets)
        for secret in secrets:
            with self.subTest(secret=secret),self.assertRaises(ValueError):M.scan(b"prefix"+secret+b"suffix",secrets)

    def test_process_observer_rejects_execveat_failed_exec_and_nonthread_children(self):
        good='10 execve("/owned/agentfw", ["agentfw", "doctor"], 0x0) = 0\n11 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 12\n'
        self.assertEqual(M.process_witness(good,Path('/owned/agentfw'))['executed_programs'],1)
        for extra in ('12 execve("/bin/true", [], 0x0) = -1 ENOENT\n','12 execveat(3, "", [], 0x0, AT_EMPTY_PATH) = 0\n',
                      '12 fork() = 13\n','12 clone(child_stack=NULL, flags=SIGCHLD) = 13\n'):
            with self.subTest(extra=extra),self.assertRaises(ValueError):M.process_witness(good+extra,Path('/owned/agentfw'))

    @unittest.skipUnless(os.name=='posix','owned process-group timeout requires POSIX')
    def test_late_execution_is_failed_with_bounded_private_streams_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);evidence=root/'private';evidence.mkdir(mode=0o700)
            trace=root/'trace'
            script="import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('owned trace');print('PRIVATE-RAW-OUTPUT',flush=True);time.sleep(5)"
            with patch.object(M,'DIAGNOSTIC_SECONDS',0.15),self.assertRaisesRegex(ValueError,'diagnostic_deadline_exceeded'):
                M.run_observed([sys.executable,'-c',script,str(trace)],root,dict(os.environ),trace,evidence,'late')
            self.assertIn(b'PRIVATE-RAW-OUTPUT',(evidence/'late.stdout.private').read_bytes())
            self.assertLessEqual((evidence/'late.stdout.private').stat().st_size,M.STREAM_CAP)
            self.assertTrue((evidence/'late.syscalls.private').is_file())

    def test_export_manifest_regraded_from_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'bundle';root.mkdir(mode=0o700)
            value={"schema":"sw-agent-doctor/1","active_host_call_protection":"unknown","pilot":{"schema":"sw-agent-doctor-pilot/1","active_host_call_protection":"unknown"}}
            raw=json.dumps(value).encode();(root/'report.json').write_bytes(raw);(root/'report.json').chmod(0o600)
            manifest={"schema":"sw-agent-doctor-support/1","report_schema":value['schema'],"pilot_schema":value['pilot']['schema'],
                "privacy":"fixed_allowlist_no_raw_inputs_no_network","active_host_call_protection":"unknown",
                "files":[{"name":"report.json","sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}]}
            (root/'manifest.json').write_text(json.dumps(manifest));(root/'manifest.json').chmod(0o600)
            self.assertTrue(M.inspect_support(root)['private_modes_verified'])
            (root/'report.json').write_bytes(raw+b' ')
            with self.assertRaises(ValueError):M.inspect_support(root)
