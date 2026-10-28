// SPDX-License-Identifier: Apache-2.0
//! Bounded stage profile. Owned public text only, no network or external child.
use super::*;

#[test]
fn concurrent_eight_original_sized_results_have_complete_timing() {
    let dir = tempfile::tempdir().unwrap();
    let st = fixture(dir.path());
    let n = st.native.as_ref().unwrap();
    start(&st, "profile");
    let line = "owned synthetic source line 0123456789 abcdefghijklmnopqrstuvwxyz SOU_LARGE_OWNED_PAYLOAD\n";
    let text = line.repeat(122_880 / line.len() + 1)[..122_880].to_string();
    let calls: Vec<_> = (0..8)
        .map(|_| {
            inspect(
                &st,
                n,
                request(
                    n,
                    "profile",
                    "call",
                    json!({
                        "tool":"lookup_note","schema_sha256":"a".repeat(64),"args":{}
                    }),
                ),
            )
            .unwrap()
        })
        .collect();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    std::thread::scope(|scope| {
        let threads: Vec<_> = calls.into_iter().enumerate().map(|(i, call)| {
            let st = &st; let barrier=barrier.clone(); let text=&text;
            scope.spawn(move || {
                let n=st.native.as_ref().unwrap();
                let content=json!({"jsonrpc":"2.0","id":i,"result":{"content":[{"type":"text","text":text}]}}).to_string();
                let req=request(n,"profile","result",json!({"tool":"lookup_note","args":{},"call_id":call.call_id,"content":content,"result_kind":"value","delivery":"mcp_host"}));
                barrier.wait();
                let r=inspect(st,n,req).unwrap();
                assert!(r.release,"{:?}",r.reason_codes);
            })
        }).collect();
        for thread in threads {
            thread.join().unwrap();
        }
    });
}

#[test]
fn result_timing_contains_only_fixed_fields_and_hashes_on_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let st = fixture(dir.path());
    let n = st.native.as_ref().unwrap();
    let secret = "private-credential-and-/private/owned/path";
    let req = request(
        n,
        secret,
        "result",
        json!({
            "tool":"lookup_note", "args":{"credential":secret}, "call_id":secret,
            "content":secret, "result_kind":"value","delivery":"mcp_host"
        }),
    );
    let timing = timing::Timing::new(&req);
    let row = timing.record(&Err("native_call_unknown_or_spent"));
    assert_eq!(row["outcome"], "native_call_unknown_or_spent");
    assert_eq!(row["release_decision"], false);
    for key in ["session_sha256", "call_sha256", "content_sha256"] {
        assert_eq!(row[key], hash(secret.as_bytes()));
    }
    assert!(row.to_string().len() < 2048);
    assert!(!row.to_string().contains(secret));
    assert_eq!(row.as_object().unwrap().len(), 16);
}

#[test]
fn result_waiting_on_session_lock_cannot_redeem_an_expired_call() {
    let dir = tempfile::tempdir().unwrap();
    let st = fixture(dir.path());
    let n = st.native.as_ref().unwrap();
    start(&st, "queue-expiry");
    let call = inspect(
        &st,
        n,
        request(
            n,
            "queue-expiry",
            "call",
            json!({
                "tool":"lookup_note","schema_sha256":"a".repeat(64),"args":{}
            }),
        ),
    )
    .unwrap();
    let req = request(
        n,
        "queue-expiry",
        "result",
        json!({"tool":"lookup_note","args":{},
        "call_id":call.call_id,"content":"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"owned\"}]}}",
        "delivery":"mcp_host","result_kind":"value"}),
    );
    let locked = n.sessions.lock().unwrap();
    std::thread::scope(|scope| {
        let (entered, waiting) = std::sync::mpsc::channel();
        let state = &st;
        let worker = scope.spawn(move || {
            entered.send(()).unwrap();
            inspect(state, n, req)
        });
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        n.advance_test_time_ms(301_000);
        drop(locked);
        assert!(worker.join().unwrap().is_err());
    });
    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(!audit.lines().any(|line| {
        let row: Value = serde_json::from_str(line).unwrap();
        row["event"] == "native_result" && row["released"] == true
    }));
}
