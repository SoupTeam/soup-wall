// SPDX-License-Identifier: Apache-2.0
//! Actual production collector and daemon: unsupported pipelining must not
//! silently serialize broker reads or release their protected contents.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;

const PROBE: &str = r#"
import importlib.util, json, pathlib, queue, sys, tempfile
repo, binary, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
probe = load(repo / 'scripts/verify-sou18-resources.py', 'concurrency_resource_probe')
original_load = probe.load
class Capture:
    submitted = []
def patched_load(path, name):
    module = original_load(path, name)
    if name == 'resource_demo' and mode != 'sequential':
        original = module.Harness
        class Pipelined(original):
            def send(self, frame, reply=True):
                request = json.loads(frame)
                if request.get('method') != 'tools/call':
                    return super().send(frame, reply)
                extra = dict(request, id='overlapping-resource')
                suffix = '\n' if mode == 'complete' else ''
                wire = frame + '\n' + json.dumps(extra, separators=(',', ':')) + suffix
                Capture.submitted.append(wire)
                # One actual pipe write: both complete and partial overlap are
                # present before the first classification/native reservation.
                self.process.stdin.write(wire.encode())
                self.process.stdin.flush()
                self.process.stdin.close()
                replies = []
                while True:
                    line = self.lines.get(timeout=15)
                    if line is None:
                        break
                    replies.append(line)
                    self.received.append(line)
                return replies[0] if replies else None
        module.Harness = Pipelined
    return module
probe.load = patched_load
modules = [load(repo / 'scripts' / filename, 'concurrency_' + name) for name, filename in (
    ('setup', 'clean-setup-acceptance.py'), ('status', 'verify-sou18-status.py'),
    ('evidence', 'measure-sou17-latency.py'), ('pending', 'verify-sou17-pending-admission.py'),
    ('generic', 'verify-sou17-generic-boundary.py'))]
with tempfile.TemporaryDirectory(prefix='sou17-concurrency-evidence-') as directory:
    case = 'read-error-recovery' if mode == 'sequential' else 'absolute-read'
    row = probe.run_case(repo, binary, pathlib.Path(directory) / 'case', case, modules)
    errors = row.get('read_errors', [])
    replies = row.get('client_output_raw', '').splitlines()
    try:
        last_reply_id = json.loads(replies[-1]).get('id') if replies else None
    except (ValueError, AttributeError):
        last_reply_id = 'malformed_final_response'
    first_missing = next((index for index, item in enumerate(errors) if not item.get('released_raw')), None)
    audit = []
    for line in row.get('native_audit_raw', '').splitlines():
        try:
            audit.append(json.loads(line))
        except ValueError:
            pass
    diagnostic = {
        'boundary': 'production_mcp_resource_continuation', 'mode': mode,
        'collector_exit': row.get('collector_exit'), 'stdout_complete': row.get('stdout_complete'),
        'classification_count': len(row.get('classifications', [])),
        'native_call_count': sum(item.get('event') == 'native_call' for item in row.get('native_decisions', [])),
        'native_result_count': sum(item.get('event') == 'native_result' for item in row.get('native_decisions', [])),
        'read_error_observation_count': len(errors), 'first_missing_read_reply_index': first_missing,
        'last_reply_id': last_reply_id,
        'native_session_end_observed': any(item.get('event') == 'native_session_end' for item in audit),
        'overlap_refusal_diagnostic': 'concurrent MCP requests are not supported' in row.get('collector_raw', ''),
        'stdio_write_timeout_diagnostic': 'MCP stdio write timed out' in row.get('collector_raw', ''),
        'admission_unavailable_diagnostic': 'MCP admission unavailable' in row.get('collector_raw', ''),
        'classifier_timeout_observed': any(item.get('failure') == 'classifier_timeout' for item in row.get('classifications', [])),
        'child_ledger_empty': row.get('child_ledger_raw') == '',
        'receiver_count': row.get('receiver_count'), 'file_bytes_unchanged': row.get('files_unchanged'),
        'owned_profile_removed': row.get('owned_profile_removed'),
        'error_type': (row.get('error') or '').split(':', 1)[0] or None,
    }
    print('SOU17_OBSERVATION ' + json.dumps(diagnostic), file=sys.stderr, flush=True)
    assert row['error'] is None if 'error' in row else True, row.get('error')
    assert row['child_ledger_raw'] == '' and row['ledger_present'] is True, row
    assert row['files_unchanged'] is True and row['receiver_count'] == 0, row
    assert row['stdout_complete'] is True and row['owned_profile_removed'] is True, row
    if mode == 'sequential':
        assert row['grade']['status'] == 'pass', row['grade']
        assert row['collector_exit'] == 0, row
        assert len(row['classifications']) == 71 and len(row['native_decisions']) == 142, row
    else:
        assert len(Capture.submitted) == 1, Capture.submitted
        assert row['collector_exit'] != 0, row
        assert 'concurrent MCP requests are not supported' in row['collector_raw'], row
        assert row['native_decisions'] == [] and row['classifications'] == [], row
        client = [json.loads(line) for line in row['client_output_raw'].splitlines()]
        assert [item['id'] for item in client] == ['init', 'list'], row
        assert row['file_content'] not in row['client_output_raw'], row
    print(json.dumps({'status':'pass', 'mode':mode, 'native_gates':len(row['native_decisions']),
        'child_tool_calls':0, 'receiver_deliveries':0, 'files_unchanged':True, 'owned_profile_removed':True,
        'client_tool_result_bytes':sum(len(raw.encode()) for raw in row['client_output_raw'].splitlines(keepends=True)[2:]),
        'protected_contents_released':row['file_content'] in row['client_output_raw'],
        'broker_output_produced':mode == 'sequential', 'native_session_cleanup_observed':'native_session_end' in row['native_audit_raw']}))
"#;

fn run(mode: &str) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = Command::new("python3")
        .args(["-I", "-u", "-c", PROBE])
        .arg(repo)
        .arg(env!("CARGO_BIN_EXE_agentfw"))
        .arg(mode)
        .output()
        .expect("local Python fixture must start");
    assert!(
        output.status.success(),
        "resource concurrency regression ({mode}): stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "pass");
    assert_eq!(result["mode"], mode);
    eprintln!("SOU17_EVIDENCE {result}");
}

#[test]
fn queued_resource_calls_are_refused_before_native_execution() {
    run("complete");
}

#[test]
fn partial_queued_resource_call_is_refused_before_native_execution() {
    run("partial");
}

#[test]
fn sequential_resource_failures_keep_useful_same_session_continuation() {
    run("sequential");
}

fn run_backpressure(mode: &str) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = Command::new("python3")
        .arg("-I")
        .arg("-u")
        .arg(repo.join("scripts/fixtures/mcp_resource_backpressure.py"))
        .arg("--repo")
        .arg(repo)
        .arg("--agentfw")
        .arg(env!("CARGO_BIN_EXE_agentfw"))
        .arg("--mode")
        .arg(mode)
        .output()
        .expect("owned backpressure fixture must start");
    if let Ok(observation) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        eprintln!("SOU17_EVIDENCE {observation}");
    }
    assert!(
        output.status.success(),
        "resource reply backpressure ({mode}): stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn resource_reply_backpressure_refuses_queued_call() {
    run_backpressure("complete");
}

#[test]
fn resource_reply_backpressure_refuses_partial_call() {
    run_backpressure("partial");
}

#[test]
fn resource_reply_backpressure_refuses_cancellation() {
    run_backpressure("cancel");
}

#[test]
fn large_resource_replies_keep_sequential_calls_useful() {
    run_backpressure("sequential");
}

#[test]
fn large_resource_reply_finishes_once_after_client_eof() {
    run_backpressure("eof");
}

#[test]
fn immediate_next_resource_frame_after_lf_and_final_eof_remain_useful() {
    run_backpressure("immediate-success");
}

#[test]
fn immediate_resource_read_errors_recover_and_close_cleanly_after_final_lf() {
    run_backpressure("immediate-errors");
}

#[test]
fn immediate_resource_refusals_preserve_same_session_recovery_and_eof() {
    run_backpressure("immediate-refusals");
}
