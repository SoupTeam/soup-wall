# SPDX-License-Identifier: Apache-2.0
import sys, json, subprocess, os, queue, threading, time
from candidate_evidence import AuditWindow, policy_evidence

action = sys.argv[1]
path = sys.argv[2] if len(sys.argv) > 2 else ""
content = sys.argv[3] if len(sys.argv) > 3 else ""
agent_cmd = sys.argv[4:]

audit = None
if action == "verify_policy":
    try:
        audit = AuditWindow(os.environ["CANDIDATE_AUDIT_PATH"])
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"CRITICAL: Daemon audit unavailable: {error}")

proc = subprocess.Popen(agent_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
responses = queue.Queue(maxsize=128)
stderr_chunks = []
stream_errors = []
deadline = time.monotonic() + 45

def drain_stderr():
    size = 0
    for chunk in iter(lambda: proc.stderr.read(4096), ""):
        size += len(chunk)
        if size > 1024 * 1024:
            stream_errors.append("collector_stderr_limit")
            proc.kill()
            break
        stderr_chunks.append(chunk)

def drain_stdout():
    size = 0
    try:
        for line in proc.stdout:
            size += len(line)
            if size > 1024 * 1024 or responses.full():
                stream_errors.append("collector_stdout_limit")
                proc.kill()
                break
            responses.put(line)
    finally:
        try:
            responses.put_nowait(None)
        except queue.Full:
            pass

threads = [threading.Thread(target=target, daemon=True) for target in (drain_stderr, drain_stdout)]
for thread in threads:
    thread.start()

def send(msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()

def read_response(expected_id):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("collector_response_timeout")
        try:
            line = responses.get(timeout=remaining)
        except queue.Empty:
            raise ValueError("collector_response_timeout") from None
        if line is None:
            raise ValueError("collector_eof: " + "".join(stderr_chunks))
        msg = json.loads(line)
        if msg.get("id") == expected_id:
            if msg.get("jsonrpc") != "2.0":
                raise ValueError("invalid_jsonrpc")
            return msg

try:
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"validator","version":"1.0"}}})
    if "error" in read_response(1):
        raise ValueError("initialize_failed")
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
    if "error" in read_response(2):
        raise ValueError("discovery_failed")

    if action in ("verify_unsupported", "calibrate_write"):
        send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":path,"content":content}}})
    elif action == "verify_generic_error":
        send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}})
    else:
        send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":path}}})

    resp = read_response(3)
    
    # Graceful shutdown to capture ALL daemon logs
    proc.stdin.close()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        
    for thread in threads:
        thread.join(timeout=2)
    if stream_errors or any(thread.is_alive() for thread in threads):
        raise ValueError("collector_stream_incomplete")
    daemon_stderr = "".join(stderr_chunks)
except Exception as e:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    if audit is not None:
        audit.close()
    sys.exit(f"CRITICAL: Failed to communicate with collector: {e}")

if action == "calibrate_write":
    if "error" in resp or resp.get("result", {}).get("isError"):
        sys.exit(f"CRITICAL: Direct original-server calibration failed: {resp}")

elif action == "read" or action == "broken_path":
    if action == "read":
        if "error" in resp or resp.get("result", {}).get("isError"):
            sys.exit(f"CRITICAL: Unexpected error on read: {resp}")
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
        if "CANDIDATE-EXACT-WITNESS-DATA" not in text:
            sys.exit("CRITICAL: Useful read failed to return expected content.")

elif action == "verify_unsupported":
    error_obj = resp.get("error", {})
    err_msg = error_obj.get("message", "")
    if error_obj.get("code") != -32601 or "explicitly unsupported in the read-only profile" not in err_msg:
        sys.exit(f"CRITICAL: Expected strict read-only unsupported tool error, got {resp}")
    sys.exit(0)

elif action == "verify_generic_error":
    error_obj = resp.get("error", {})
    if not error_obj:
        sys.exit(f"CRITICAL: Expected error for malformed request, got {resp}")
    err_msg = error_obj.get("message", "")
    err_str = json.dumps(resp)
    if "explicitly unsupported" in err_msg or "withheld" in err_str:
        sys.exit(f"CRITICAL: Generic setup failure falsely triggered a boundary condition! {resp}")
    sys.exit(0)

elif action == "verify_policy":
    if "error" in resp:
        sys.exit(f"CRITICAL: Expected structured policy denial result, but got raw JSON-RPC error: {resp}")
    
    if resp.get("jsonrpc") != "2.0":
        sys.exit(f"CRITICAL: Invalid JSON-RPC version (expected 2.0): {resp}")
    if resp.get("id") != 3:
        sys.exit(f"CRITICAL: Invalid response ID (expected 3): {resp}")
    
    result = resp.get("result", {})
    if not isinstance(result, dict) or result.get("isError") is not True:
        sys.exit(f"CRITICAL: Expected strict policy denial (isError=True), got {resp}")
        
    content_list = result.get("content", [])
    if not isinstance(content_list, list) or len(content_list) == 0:
        sys.exit(f"CRITICAL: Invalid or missing content array in policy denial: {resp}")
        
    content_item = content_list[0]
    if not isinstance(content_item, dict) or content_item.get("type") != "text":
        sys.exit(f"CRITICAL: Expected content type 'text' in policy denial, got {resp}")
        
    text_content = content_item.get("text", "").strip()
    expected_framing = "Soup Wall withheld MCP result (filesystem-profile-refuse-result-injection)"
    
    if text_content != expected_framing:
        sys.exit(f"CRITICAL: Expected EXACT policy denial framing, but got incidental substring match or wrong text: '{text_content}'")
        
    try:
        evidence = policy_evidence(resp, audit.records(), os.environ["CANDIDATE_REGISTRY_SHA256"])
        print(json.dumps(evidence, sort_keys=True))
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"CRITICAL: Fresh daemon policy evidence missing: {error}")
    finally:
        audit.close()
    sys.exit(0)
