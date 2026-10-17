# SPDX-License-Identifier: Apache-2.0
"""Controls for independent owned stderr capture and sanitized runtime evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('sou76',ROOT/'scripts/verify-sou76-native-stderr.py')
V=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(V)


def process():
    return {'all_stopped':True,'remaining':[],'observed':[{'pid':100,'start_time_ticks':1,'parent_process':True},
        {'pid':101,'start_time_ticks':2,'parent_process':False}]}


def stream(events=None):
    return {'thread_stopped':True,'read_failure':None,'markers':{key:False for key in V.MARKERS},
        'buffer_peak':1024,'bytes':100,'sha256':'a'*64,'safe_events':events or [],'protocol_records':[]}


def complete_report():
    clients=[]; audit=[]
    for index,name in enumerate(sorted(V.CASES)):
        outcome='byte_limit' if 'flood' in name else 'eof'
        events=[{'event':'mcp_native_server_start','diagnostics':'sw-mcp/native-stderr/1','server_pid':101,**V.START_LIMITS},
            {'event':'mcp_native_stderr','outcome':outcome,'received_bytes':V.LIMITS['max_observed_bytes'] if 'flood' in name else len(V.EMISSION),'read_chunks':4,'released':False},
            {'event':'mcp_native_server_end','process_cleanup_verified':True,'stderr_cleanup_verified':True,'transport_complete':name in ('useful','denied','peer')}]
        replies=[{'id':1,'refused':False},{'id':2,'refused':False}]
        if name=='denied': replies += [{'id':3,'refused':True},{'id':4,'refused':False}]
        row={'case':name,'server_pid':101,'server_start_ticks':2,'native_epoch':str(index),'forced_cleanup':False,'process_cleanup':process(),'stdout':stream(),'stderr':stream(events),
            'exit_code':0 if name in ('useful','denied','peer') else 1,'responses':replies,
            'effect':{'exists':name in ('useful','call-flood'),'sha256':V.sha(V.NOTE.encode())}}
        if name in ('useful','denied','peer','held-pipe'):
            identifier=4 if name=='denied' else 3
            raw=json.dumps({'jsonrpc':'2.0','id':identifier,'result':{'content':[{'type':'text','text':V.TEXT}]}},ensure_ascii=False,separators=(',',':')).encode()+b'\n'
            row['stdout']['protocol_records']=[{'id':identifier,'sha256':V.sha(raw),'bytes':len(raw),'refused':False}]
        if name=='denied':
            audit += [{'event':event,'session':str(index),'released':released,'rule':'owned-result-refusal' if event=='native_result' and not released else None}
                for event,released in [('native_call',True),('native_result',False),('native_call',True),('native_result',True)]]
        clients.append(row); audit.append({'event':'native_session_end','session':str(index),'released':True})
    calibration={'exit_code':0,'stderr':stream(),'effect':{'sha256':V.sha(V.NOTE.encode())}}
    calibration['stderr'].update(bytes=len(V.EMISSION),sha256=V.sha(V.EMISSION))
    for name in ('public','synthetic_secret','terminal_control','invalid_binary'): calibration['stderr']['markers'][name]=True
    report = {'format':V.FORMAT,'failed':0,'skipped':0,'source_before':{'commit':'1'*40,'dirty':False},'source_after':{'commit':'1'*40,'dirty':False},'binary_unchanged':True,
        'limits':copy.deepcopy(V.LIMITS),**{key:'a'*64 for key in ('binary_sha256','driver_sha256','fixture_sha256','config_sha256','registry_sha256')},
        'policy_sha256':V.sha(V.POLICY.encode()),'calibration':calibration,
        **{name:{'followup_useful':True,'useful_original_sha256':'b'*64,'expected_sha256':'b'*64} for name in ('useful','denied','peer')},
        'cleanup':{'clients':clients,'daemon_process':process(),'daemon_stdout':stream(),'daemon_stderr':stream(),'private_profile_removed':True,'audit':{'rows':audit,'raw_marker_seen':False}},
        'held_pipe':{'descendant_pid':101,'descendant_start_ticks':2,'useful_result_sha256':next(row for row in clients if row['case']=='held-pipe')['stdout']['protocol_records'][0]['sha256']}}
    for name in ('useful','denied','peer'):
        client=next(row for row in clients if row['case']==name)
        value=client['stdout']['protocol_records'][0]['sha256']
        report[name].update(useful_original_sha256=value,expected_sha256=value)
    return report


class EvidenceControls(unittest.TestCase):
    def fails(self,change):
        report=complete_report(); change(report)
        with self.assertRaises((ValueError,KeyError,TypeError)): V.grade(report)

    def test_complete_owned_evidence_has_required_nonempty_cases(self):
        report=complete_report(); V.grade(report)
        self.assertEqual(len(report['checks']),len(V.CASES)+3)

    def test_missing_or_skipped_runtime_and_changed_source_do_not_pass(self):
        for change in (lambda r:r.update(failed=1),lambda r:r.update(skipped=1),lambda r:r['source_before'].update(dirty=True),
            lambda r:r.update(binary_unchanged=False),lambda r:r['cleanup']['clients'].pop()):
            with self.subTest(change=change): self.fails(change)

    def test_observer_must_detect_all_unprotected_marker_forms(self):
        for key in ('public','synthetic_secret','terminal_control','invalid_binary'):
            with self.subTest(key=key): self.fails(lambda r:r['calibration']['stderr']['markers'].update({key:False}))
        self.fails(lambda r:r['calibration']['stderr'].update(sha256='c'*64))

    def test_any_actual_stdout_stderr_or_daemon_marker_leak_fails(self):
        for side in ('stdout','stderr'):
            self.fails(lambda r:r['cleanup']['clients'][0][side]['markers'].update(public=True))
        self.fails(lambda r:r['cleanup']['daemon_stderr']['markers'].update(synthetic_secret=True))
        self.fails(lambda r:r['cleanup']['audit'].update(raw_marker_seen=True))

    def test_native_byte_chunk_limits_and_read_failure_are_verified(self):
        for change in (lambda r:r['cleanup']['clients'][0]['stderr']['safe_events'][1].update(received_bytes=1048578),
            lambda r:r['cleanup']['clients'][0]['stderr']['safe_events'][1].update(read_chunks=4097),
            lambda r:r['cleanup']['clients'][0]['stderr'].update(read_failure='observer_read_failure'),
            lambda r:r['limits'].update(byte_limit=9999999)):
            with self.subTest(change=change): self.fails(change)

    def test_declared_start_limits_missing_counters_and_fake_useful_hashes_fail(self):
        for change in (lambda r:r['cleanup']['clients'][0]['stderr']['safe_events'][0].pop('stderr_chunk_bytes'),
            lambda r:r['cleanup']['clients'][0]['stderr']['safe_events'][1].pop('received_bytes'),
            lambda r:r['useful'].update(expected_sha256='e'*64,useful_original_sha256='e'*64),
            lambda r:r['cleanup']['clients'][0].update(server_start_ticks=999)):
            with self.subTest(change=change): self.fails(change)

    def test_parent_kill_is_not_production_cleanup_and_raw_pid_witness_is_required(self):
        for change in (lambda r:r['cleanup']['clients'][0].update(forced_cleanup=True),
            lambda r:r['cleanup']['clients'][0]['process_cleanup'].update(remaining=[{'pid':101}]),
            lambda r:r['cleanup']['clients'][0]['process_cleanup'].update(observed=[])):
            with self.subTest(change=change): self.fails(change)

    def test_already_committed_flood_effect_is_reported_not_erased(self):
        def change(r):
            next(row for row in r['cleanup']['clients'] if row['case']=='call-flood')['effect']['sha256']='d'*64
        self.fails(change)

    def test_unconsumed_late_result_is_still_an_actual_output_leak(self):
        def change(r):
            next(row for row in r['cleanup']['clients'] if row['case']=='cancel')['stdout']['protocol_records']=[{'id':3,'sha256':'d'*64}]
        self.fails(change)

    def test_authenticated_pending_retirement_and_descendant_identity_are_required(self):
        self.fails(lambda r:r['cleanup']['audit'].update(rows=[]))
        self.fails(lambda r:r['held_pipe'].update(descendant_start_ticks=9))

    def test_stream_scanner_detects_markers_across_arbitrary_chunk_boundaries(self):
        read,write=os.pipe()
        with os.fdopen(read,'rb',buffering=0) as source:
            capture=V.Capture(source)
            for raw in (V.EMISSION[:9],V.EMISSION[9:31],V.EMISSION[31:]): os.write(write,raw)
            os.close(write)
            result=capture.finish()
        self.assertEqual(result['sha256'],V.sha(V.EMISSION))
        self.assertTrue(all(result['markers'][key] for key in ('public','synthetic_secret','terminal_control','invalid_binary')))
        self.assertTrue(result['thread_stopped'])

    def test_nonobject_protocol_values_cannot_fail_observer_silently(self):
        for value in ([1],'owned string',{'id':3,'result':[]}):
            with self.subTest(value_type=type(value).__name__):
                read,write=os.pipe()
                with os.fdopen(read,'rb',buffering=0) as source:
                    capture=V.Capture(source,True)
                    os.write(write,json.dumps(value).encode()+b'\n');os.close(write)
                    result=capture.finish()
                self.assertEqual(result['read_failure'],'observer_invalid_protocol')
                self.assertTrue(result['thread_stopped'])

    def test_held_pipe_result_uses_exact_json_wire_hash(self):
        self.fails(lambda r:r['held_pipe'].update(useful_result_sha256='e'*64))

    def test_protocol_partial_eof_and_oversized_line_are_explicit_failures(self):
        for data,code in ((b'{"jsonrpc":','observer_protocol_partial_eof'),(b'x'*262145,'observer_protocol_line_limit')):
            with self.subTest(code=code):
                read,write=os.pipe()
                def emit():
                    try:
                        offset=0
                        while offset<len(data): offset+=os.write(write,data[offset:])
                    finally: os.close(write)
                with os.fdopen(read,'rb',buffering=0) as source:
                    capture=V.Capture(source,True)
                    worker=threading.Thread(target=emit); worker.start(); worker.join(timeout=10)
                    result=capture.finish()
                self.assertEqual(result['read_failure'],code)
                self.assertLessEqual(result['buffer_peak'],262144)
                self.assertTrue(result['thread_stopped'])

    def test_large_no_newline_observation_keeps_fixed_private_buffer(self):
        read,write=os.pipe()
        chunk=V.EMISSION+b'x'*(4096-len(V.EMISSION))
        def emit():
            try:
                for _ in range(512): os.write(write,chunk)
            finally: os.close(write)
        with os.fdopen(read,'rb',buffering=0) as source:
            capture=V.Capture(source)
            worker=threading.Thread(target=emit); worker.start()
            worker.join(timeout=10)
            result=capture.finish()
        self.assertFalse(worker.is_alive())
        self.assertEqual(result['bytes'],4096*512)
        self.assertLessEqual(result['buffer_peak'],4096)
        self.assertTrue(result['thread_stopped'])

    def test_binary_no_newline_calibration_uses_real_owned_child_and_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); server=root/'server.py'; server.write_text(V.SERVER)
            result=V.calibration(root,server,V.BASE.environment(root))
            self.assertEqual(result['stderr']['sha256'],V.sha(V.EMISSION))
            self.assertEqual(result['effect']['sha256'],V.sha(V.NOTE.encode()))

    def test_safe_metadata_never_copies_arbitrary_source_strings(self):
        event=V.safe_event({'event':'mcp_native_stderr','outcome':V.SECRET.decode(),'source':V.PUBLIC.decode(),'received_bytes':1,'released':False})
        self.assertNotIn('source',event); self.assertNotIn('outcome',event)
        self.assertNotIn(V.SECRET.decode(),json.dumps(event))
        self.assertIsNone(V.safe_event({'event':V.PUBLIC.decode()}))

    def test_evidence_writer_rejects_accidental_raw_canaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError,'unsafe_evidence_payload'):
                V.write(Path(temporary)/'out.json',{'accident':V.SECRET.decode()})

    def test_missing_linux_is_a_failure_and_plan_starts_no_processes(self):
        with patch.object(V.platform,'system',return_value='Windows'):
            with self.assertRaisesRegex(ValueError,'required_linux'): V.run(None)
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/verify-sou76-native-stderr.py'),'--agentfw','/missing',
            '--expected-commit','1'*40,'--output','/missing-output'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0)
        self.assertFalse(json.loads(result.stdout)['executed'])


if __name__=='__main__': unittest.main()
