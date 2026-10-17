# SPDX-License-Identifier: Apache-2.0
"""Controls for the owned production-path provenance budget evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou72_acceptance", ROOT / "scripts/verify-sou72-provenance-budget.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def sample(limits=None, sessions=1, retained=60000, incomplete=1):
    return {"accounting_revision":"sw-provenance-storage/1","limits":dict(limits or VERIFY.LIMITS),"usage":{"retained_bytes":retained,"max_session_retained_bytes":min(retained,60000),
        "sessions":sessions,"incomplete_sessions":incomplete,"fingerprints":32,"literals":4,"legacy_unknown_history":False}}


def complete_report():
    def rig(limits):
        return {"limits":limits,"samples":[sample(limits) for _ in range(8)],
            "cleanup":{"all_stopped":True,"daemon_stopped":True,"private_profile_removed":True},
            "rss":{"daemon":{"kind":"sampled_process_rss_not_tracker_budget","sample_count":1}}}
    def reply(refused=False):
        return {"refused":refused}
    def ask(approved=False):
        return {"no_effect_before_decision":True,"reply":reply(not approved),"after":{"exists":approved,"sha256":VERIFY.sha_bytes(VERIFY.EARLY.encode())},
            "rule":"taint-history-incomplete","incomplete":True,"taint_present":False,"binding_sha256":"b"*64,"pending_id":"owned-pending","backend_calls_before":1,"backend_calls_after":2 if approved else 1}
    limits = dict(VERIFY.LIMITS)
    report = {"format":VERIFY.FORMAT,"skipped":0,"failed":0,"source_before":{"commit":"1"*40,"dirty":False},"source_after":{"commit":"1"*40,"dirty":False},
        **{name:"a"*64 for name in ("binary_sha256","driver_sha256","fixture_sha256")},"binary_unchanged":True,
        "calibration":{"reply":reply(),"native_allow":True,"early_taint_present":True,"file":{"exists":True,"sha256":"c"*64},"expected_sha256":"c"*64},
        "duplicate":{"before":4096,"after":4096,"repetitions":8},"pressure":{"admitted":40},"early_refusal":ask(),
        "unrecordable":{"reply":reply(True),"reason_present":True,"original_marker_absent":True},"approved":ask(True),
        "approval_replay_refused":True,"after_approval_refusal":ask(),"continuation":{"useful":True},
        "peer":{"reply":reply(),"file":{"exists":True}},"hard_deny":{"reply":reply(True),"rule_present":True,"effect_absent":True,"pending_empty":True},
        "global_pressure":{"admitted":48},"capacity":{"refused_exit_code":1,"refused_no_execution":True,"capacity_reason":True,"replacement_useful":True,
            "before":sample(sessions=2),"after_end":sample(sessions=1)},
        "shared":{name:{"reply":reply(True),"ask_reason":True,"effect_absent":True} for name in ("after_child_exit","after_reconnect")},
        "rpc_failure":{"original_error_delivered":True},"cancelled":{"call_was_dispatched":True,"collector_exit_code":1,"original_marker_absent":True},
        "rigs":{"primary":rig(limits),"global":rig(dict(limits,total_bytes=98304)),"capacity":rig(dict(limits,max_sessions=2)),"shared":rig(limits)}}

    process = {"all_stopped":True,"remaining":[],"observed":[{"pid":4242,"start_time_ticks":12,"parent_process":True}],"descendant_count":0}
    primary_sent,primary_received,audit = [],[],[]
    cases = ("calibration","early_refusal","unrecordable","approved","after_approval_refusal","continuation","hard_deny","rpc_failure")
    for index,name in enumerate(cases,10):
        refused = name in ("early_refusal","unrecordable","after_approval_refusal","hard_deny")
        text = "native_provenance_unrecordable" if name == "unrecordable" else "owned-hard-deny" if name == "hard_deny" else "taint-history-incomplete" if refused else VERIFY.USEFUL
        reply = {"jsonrpc":"2.0","id":index,"result":{"content":[{"type":"text","text":text}]}}
        if refused: reply['result']['isError']=True
        if name == 'rpc_failure': reply={"jsonrpc":"2.0","id":index,"error":{"code":-32603,"message":VERIFY.payload('failed')}}
        raw=json.dumps(reply,separators=(',',':'))+'\n'
        report[name]['reply']=VERIFY.evidence_reply(reply,raw.encode())
        primary_received.append(raw)
        primary_sent.append(json.dumps({"jsonrpc":"2.0","id":index,"method":"tools/call","params":{"name":"publish_note" if name in ("calibration","early_refusal","approved","after_approval_refusal") else "read_metadata","arguments":{}}})+'\n')
    audit=[{"event":"native_call","binding_sha256":"b"*64,"pending_id":"owned-pending","rule":"taint-history-incomplete","provenance_incomplete":True,"released":False},
        {"event":"native_result","released":False,"reason_codes":["native_provenance_unrecordable"]}]
    audit=[]
    for name in ('early_refusal','after_approval_refusal'):
        section=report[name]
        section['binding_sha256']=VERIFY.sha_bytes(name.encode())
        section['pending_id']='owned-'+name
        original=next(json.loads(raw) for raw in primary_sent if json.loads(raw)['id']==section['reply']['id'])
        audit += [{'event':'native_call','session':'owned-epoch','tool':'publish_note','rule':'taint-history-incomplete','provenance_incomplete':True,'released':False},
            {'event':'native_approval_requested','session':'owned-epoch','tool':'publish_note','binding_sha256':section['binding_sha256'],
                'approval_id':section['pending_id'],'args_sha256':VERIFY.digest(original['params']['arguments'])}]
    audit.append({'event':'native_result','released':False,'reason_codes':['native_provenance_unrecordable']})
    for name,rig in report['rigs'].items():
        rig.update(config_sha256='c'*64,registry_sha256='d'*64,policy_sha256=VERIFY.sha_bytes(VERIFY.POLICY.encode()))
        transcript={"label":"primary" if name == 'primary' else name,"sent":primary_sent if name == 'primary' else [],
            "received":primary_received if name == 'primary' else [],"process_cleanup":copy.deepcopy(process)}
        for direction in ('sent','received'):
            transcript[direction+'_sha256']=VERIFY.sha_bytes(''.join(transcript[direction]).encode())
        rig['client_transcripts']=[transcript]
        rig['client_transcripts_sha256']=VERIFY.digest(rig['client_transcripts'])
        rig['owned_native_audit']=copy.deepcopy(audit)
        rig['owned_native_audit_sha256']=VERIFY.digest(rig['owned_native_audit'])
        rig['cleanup'].update(daemon=copy.deepcopy(process),clients=[{'process_cleanup':copy.deepcopy(process)}])
    return report


class EvidenceControls(unittest.TestCase):
    def fails(self, change):
        report = complete_report()
        change(report)
        with self.assertRaises((ValueError,KeyError,TypeError)):
            VERIFY.grade(report)

    def test_complete_evidence_has_exact_nonempty_cases(self):
        report = complete_report()
        VERIFY.grade(report)
        self.assertEqual({row['case'] for row in report['checks']},VERIFY.CHECKS)
        self.assertTrue(all(row['passed'] for row in report['checks']))

    def test_skips_dirty_changed_source_and_binary_are_not_passes(self):
        for change in (lambda r:r.update(skipped=1),lambda r:r.update(failed=1),lambda r:r['source_before'].update(dirty=True),
                lambda r:r['source_after'].update(commit='2'*40),lambda r:r.update(binary_unchanged=False),lambda r:r.pop('fixture_sha256')):
            with self.subTest(change=change): self.fails(change)

    def test_self_reported_allow_without_independent_calibration_is_rejected(self):
        for change in (lambda r:r['calibration']['file'].update(exists=False),lambda r:r['calibration']['file'].update(sha256='d'*64),
                lambda r:r['calibration'].update(early_taint_present=False),lambda r:r['calibration'].update(native_allow=False)):
            with self.subTest(change=change): self.fails(change)

    def test_memory_bounds_use_bytes_per_context_and_globally(self):
        for name,field,value in (('primary','max_session_retained_bytes',65537),('global','retained_bytes',98305),('primary','sessions',9)):
            with self.subTest(field=field):
                self.fails(lambda r:r['rigs'][name]['samples'][0]['usage'].update({field:value}))

    def test_missing_effective_limits_or_byte_counters_never_fall_back_to_rss(self):
        for change in (lambda r:r['rigs']['primary']['samples'][0].pop('limits'),lambda r:r['rigs']['primary']['samples'][0].update(accounting_revision='unknown'),
                lambda r:r['rigs']['primary']['samples'][0]['usage'].pop('retained_bytes'),
                lambda r:r['rigs']['primary']['samples'][0]['limits'].update(per_session_bytes=99999)):
            with self.subTest(change=change): self.fails(change)

    def test_early_marker_must_have_been_evicted_and_action_asked(self):
        for change in (lambda r:r['early_refusal'].update(taint_present=True),lambda r:r['early_refusal'].update(rule='owned-hard-deny'),
                lambda r:r['early_refusal']['after'].update(exists=True),lambda r:r['early_refusal'].update(backend_calls_after=2),
                lambda r:r['early_refusal'].update(no_effect_before_decision=False)):
            with self.subTest(change=change): self.fails(change)

    def test_unrecordable_original_result_and_wrong_refusal_reason_are_rejected(self):
        for key in ('original_marker_absent','reason_present'):
            with self.subTest(key=key): self.fails(lambda r:r['unrecordable'].update({key:False}))
        self.fails(lambda r:r['unrecordable']['reply'].update(refused=False))

    def test_approval_must_be_single_use_and_keep_history_incomplete(self):
        for change in (lambda r:r.update(approval_replay_refused=False),lambda r:r['approved'].update(backend_calls_after=1),
                lambda r:r['approved'].update(no_effect_before_decision=False),lambda r:r['after_approval_refusal']['reply'].update(refused=False)):
            with self.subTest(change=change): self.fails(change)

    def test_capacity_recovery_requires_retirement_and_actual_replacement_work(self):
        for change in (lambda r:r['capacity'].update(replacement_useful=False),lambda r:r['capacity'].update(refused_exit_code=0),
                lambda r:r['capacity'].update(refused_no_execution=False),lambda r:r['capacity']['after_end']['usage'].update(sessions=2)):
            with self.subTest(change=change): self.fails(change)

    def test_reconnect_and_child_exit_cannot_clear_shared_history(self):
        for event in ('after_child_exit','after_reconnect'):
            for field in ('ask_reason','effect_absent'):
                with self.subTest(event=event,field=field): self.fails(lambda r:r['shared'][event].update({field:False}))

    def test_useful_peer_read_and_hard_deny_are_required(self):
        for change in (lambda r:r['continuation'].update(useful=False),lambda r:r['peer']['file'].update(exists=False),
                lambda r:r['hard_deny'].update(effect_absent=False),lambda r:r['hard_deny']['reply'].update(refused=False)):
            with self.subTest(change=change): self.fails(change)

    def test_failed_cancelled_and_cleanup_outcomes_are_not_omitted(self):
        for change in (lambda r:r['rpc_failure'].update(original_error_delivered=False),lambda r:r['cancelled'].update(original_marker_absent=False),
                lambda r:r['cancelled'].update(collector_exit_code=0),lambda r:r['rigs']['shared']['cleanup'].update(all_stopped=False)):
            with self.subTest(change=change): self.fails(change)

    def test_small_empty_load_is_not_a_budget_plateau(self):
        self.fails(lambda r:r['pressure'].update(admitted=1))
        self.fails(lambda r:r['duplicate'].update(after=9000))
        self.fails(lambda r:r['rigs']['primary'].update(samples=[sample(retained=100,incomplete=0)]))

    def test_required_rigs_configuration_identities_and_raw_cleanup_are_verified(self):
        for change in (lambda r:r['rigs'].pop('shared'),lambda r:r['rigs']['global'].pop('config_sha256'),
                lambda r:r['rigs']['primary'].update(policy_sha256='a'*64),
                lambda r:r['rigs']['shared']['limits'].update(max_sessions=9),
                lambda r:r['rigs']['primary']['cleanup']['daemon'].update(remaining=[{'pid':4242}])):
            with self.subTest(change=change): self.fails(change)

    def test_original_critical_output_and_native_ask_cannot_be_omitted_or_forged(self):
        def no_audit(r):
            rig=r['rigs']['primary']
            rig['owned_native_audit']=[{'event':'native_result','released':False,'reason_codes':['native_provenance_unrecordable']}]
            rig['owned_native_audit_sha256']=VERIFY.digest(rig['owned_native_audit'])
        def no_reply(r):
            rig=r['rigs']['primary']; transcript=rig['client_transcripts'][0]
            transcript['received'].pop(1)
            transcript['received_sha256']=VERIFY.sha_bytes(''.join(transcript['received']).encode())
            rig['client_transcripts_sha256']=VERIFY.digest(rig['client_transcripts'])
        for change in (no_audit,no_reply,lambda r:r['early_refusal']['reply'].update(sha256='0'*64)):
            with self.subTest(change=change): self.fails(change)

    def test_after_approval_requires_exact_ask_and_zero_backend_publications(self):
        for change in (lambda r:r['after_approval_refusal'].update(rule='different-deny'),
                lambda r:r['after_approval_refusal'].update(incomplete=False),
                lambda r:r['after_approval_refusal'].update(backend_calls_after=3)):
            with self.subTest(change=change): self.fails(change)

    def test_owned_fixture_publishes_exact_bytes_and_parent_detects_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'published').mkdir()
            server=root/'server.py'; server.write_text(VERIFY.SERVER)
            request={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'publish_note','arguments':{'name':'owned-control','note':VERIFY.USEFUL}}}
            before=VERIFY.publication(root,'owned-control')
            result=subprocess.run([sys.executable,'-I','-u',str(server),str(root),json.dumps(VERIFY.SCHEMAS)],
                input=json.dumps(request)+'\n',capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(before['exists'])
            self.assertEqual(VERIFY.publication(root,'owned-control')['sha256'],VERIFY.sha_bytes(VERIFY.USEFUL.encode()))
            self.assertEqual(json.loads(result.stdout)['id'],3)

    def test_oversized_fixture_is_utf8_and_exceeds_literal_limit_without_real_secrets(self):
        value=VERIFY.payload('oversized')
        self.assertGreater(len(value.encode()),VERIFY.LIMITS['max_literal_bytes'])
        self.assertLess(len(value.encode()),VERIFY.LIMITS['max_input_bytes'])
        self.assertIn('UNTRACKABLE-OWNED-RESULT',value)

    def test_secrets_are_redacted_and_missing_linux_is_failure(self):
        with patch.object(VERIFY,'SECRETS',['owned-token']):
            self.assertNotIn('owned-token',VERIFY.redact('failure owned-token'))
        with patch.object(VERIFY.platform,'system',return_value='Windows'):
            with self.assertRaisesRegex(ValueError,'Linux'):
                VERIFY.run(None)

    def test_plan_starts_no_processes(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/verify-sou72-provenance-budget.py'),
            '--agentfw','/missing-owned-agent','--expected-commit','1'*40,'--output','/missing-owned-output'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIs(json.loads(result.stdout)['executed'],False)


if __name__ == '__main__':
    unittest.main()
