// SPDX-License-Identifier: Apache-2.0
// Included inside the private Linux worker. Scripted duplex peers test protocol
// only; they cannot manufacture production Completion through a public API.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncBufReadExt;

fn profile() -> ProfileConfig {
    ProfileConfig {
        format: git::FORMAT.into(),
        workspace: "/workspace".into(),
        workspace_identity: None,
        linked_worktree: None,
        runtime_path: "/owned/python".into(),
        runtime_sha256: "1".repeat(64),
        package_root: "/owned/package".into(),
        package_tree_sha256: "2".repeat(64),
        bwrap_path: "/owned/bwrap".into(),
        bwrap_sha256: "3".repeat(64),
        libraries: vec![],
        git: Some(server_profile::Library {
            path: "/owned/git".into(),
            sha256: "4".repeat(64),
        }),
        git_launcher: Some(server_profile::Library {
            path: "/owned/launcher".into(),
            sha256: "5".repeat(64),
        }),
    }
}
fn wire(id: Value, tool: &str, args: Value) -> Vec<u8> {
    let mut raw=json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}}).to_string().into_bytes();
    raw.push(b'\n');
    raw
}
fn show() -> Vec<u8> {
    wire(
        json!("host-77"),
        "git_show",
        json!({"repo_path":"/workspace","revision":"HEAD"}),
    )
}

#[tokio::test]
#[ignore = "requires explicit owned Linux FILE profile and pinned original runtime"]
async fn file_worker_withholds_after_original_tools_call_write_and_source_restore() {
    let path =
        std::env::var("SOU68_SANDBOX_TEST_PROFILE").expect("explicit owned profile required");
    let p = ProfileConfig::read(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(p.format, git::FILE_READS_FORMAT);
    let reference = p.workspace.join(".git/refs/heads/main");
    let original = std::fs::read(&reference).unwrap();
    let moved = reference.with_extension("sou146-owned-withdrawal");
    assert!(!moved.exists());
    let (written_tx, written_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let key = crate::token::generate();
    let raw = wire(
        json!(&key),
        "git_show",
        json!({"repo_path":"/workspace","revision":"HEAD:notes.txt"}),
    );
    let expected = run(&p, &raw).await.unwrap().raw().to_vec();
    struct ResetBarrier {
        key: String,
        resume: Option<oneshot::Sender<()>>,
    }
    impl Drop for ResetBarrier {
        fn drop(&mut self) {
            let mut slot = AFTER_TOOLS_WRITE.lock().unwrap();
            if slot.as_ref().is_some_and(|barrier| barrier.key == self.key) {
                slot.take();
            }
            if let Some(resume) = self.resume.take() {
                let _ = resume.send(());
            }
        }
    }
    let mut reset = ResetBarrier {
        key: key.clone(),
        resume: Some(resume_tx),
    };
    assert!(AFTER_TOOLS_WRITE
        .lock()
        .unwrap()
        .replace(DispatchBarrier {
            key,
            original: raw.clone(),
            workspace: p.workspace.clone(),
            format: p.format.clone(),
            written: written_tx,
            resume: resume_rx,
        })
        .is_none());
    let runner = p.clone();
    let original_request = raw.clone();
    let task = tokio::spawn(async move { run(&runner, &original_request).await });
    tokio::time::timeout(Duration::from_secs(4), written_rx)
        .await
        .unwrap()
        .unwrap();
    std::fs::rename(&reference, &moved).unwrap();
    std::fs::rename(&moved, &reference).unwrap();
    reset.resume.take().unwrap().send(()).unwrap();
    let result = task.await.unwrap();
    let failure = result
        .err()
        .expect("withdrawn source must never create a Completion");
    assert_eq!(
        failure.to_string(),
        "Git file-revision source changed; a new protected session is required"
    );
    assert_eq!(std::fs::read(&reference).unwrap(), original);
    assert!(AFTER_TOOLS_WRITE.lock().unwrap().is_none());
    let fresh = run(&p, &raw).await.unwrap();
    assert_eq!(fresh.raw(), expected);
    println!("SOU146_REAL_WORKER_AFTER_WRITE_WITHHELD restored=true completion=false fresh_original_bytes=true");
}
#[test]
fn execution_profiles_are_finite_and_file_grammar_stays_separate() {
    for format in [git::FORMAT, git::FILE_READS_FORMAT] {
        let mut p = profile();
        p.format = format.into();
        assert!(supports_profile(format));
        assert!(request(&p, &show()).is_ok());
        let file = wire(
            json!(7),
            "git_show",
            json!({"repo_path":"/workspace","revision":"HEAD:docs/機能 notes.txt"}),
        );
        assert_eq!(request(&p, &file).is_ok(), format == git::FILE_READS_FORMAT);
        for tool in ["git_show", "git_diff"] {
            let key = if tool == "git_show" {
                "revision"
            } else {
                "target"
            };
            for revision in [
                "refs/heads/main",
                "HEAD:../outside",
                "HEAD~1",
                "HEAD:.git/config",
            ] {
                let mut args = json!({"repo_path":"/workspace"});
                args[key] = json!(revision);
                assert!(request(&p, &wire(json!(7), tool, args)).is_err());
            }
        }
    }
    for format in [
        git::LOCAL_REFS_FORMAT,
        git::SHALLOW_FORMAT,
        server_profile::git_local_clone::FORMAT,
        server_profile::FORMAT,
        "unknown",
    ] {
        let mut p = profile();
        p.format = format.into();
        assert!(!supports_profile(format));
        assert!(request(&p, &show()).is_err());
    }
}
#[test]
fn tracked_execution_allowlist_preserves_the_original_argument_contract() {
    for format in [git::FORMAT, server_profile::git_tracked_symlinks::FORMAT] {
        let mut p = profile();
        p.format = format.into();
        assert!(supports_profile(format));
        assert!(request(&p, &show()).is_ok());
        for revision in [
            "HEAD:notes.txt",
            "refs/heads/main",
            "refs/remotes/origin/main",
            "refs/remotes/origin/HEAD",
            "HEAD~1",
            "../outside",
        ] {
            assert!(request(
                &p,
                &wire(
                    json!(1),
                    "git_show",
                    json!({"repo_path":"/workspace","revision":revision})
                )
            )
            .is_err());
        }
    }
    for format in [
        git::LOCAL_REFS_FORMAT,
        git::SHALLOW_FORMAT,
        server_profile::git_local_clone::FORMAT,
        server_profile::FORMAT,
    ] {
        let mut p = profile();
        p.format = format.into();
        assert!(!supports_profile(format));
        assert!(request(&p, &show()).is_err());
    }
}
#[test]
fn request_rejects_duplicate_keys_malformed_frames_and_unapproved_tools() {
    let p = profile();
    let valid = show();
    assert!(request(&p, &valid).is_ok());
    let duplicate = String::from_utf8(valid.clone()).unwrap().replace(
        "\"jsonrpc\":\"2.0\"",
        "\"jsonrpc\":\"1.0\",\"jsonrpc\":\"2.0\"",
    );
    for bad in [
        duplicate.into_bytes(),
        valid[..valid.len() - 1].to_vec(),
        vec![b'x'; REQUEST_LIMIT + 1],
        wire(
            json!(null),
            "git_show",
            json!({"repo_path":"/workspace","revision":"HEAD"}),
        ),
        wire(json!(1), "git_commit", json!({"repo_path":"/workspace"})),
        wire(
            json!(1),
            "git_show",
            json!({"repo_path":"/outside","revision":"HEAD"}),
        ),
    ] {
        assert!(request(&p, &bad).is_err());
    }
}
#[test]
fn oid_range_is_fixed_header_only_and_commit_kind_is_required() {
    use git::object_witness::{ObjectIdentity, ShowTarget};
    let id = "a".repeat(40);
    let text = format!("commit {id}\nbody {id}\n");
    for kind in [
        ObjectKind::Blob,
        ObjectKind::Tree,
        ObjectKind::Tag,
        ObjectKind::Commit,
    ] {
        let target = ShowTarget {
            requested: ObjectIdentity {
                oid: id.clone(),
                kind,
            },
            effective: ObjectIdentity {
                oid: id.clone(),
                kind,
            },
            tag_chain: vec![],
        };
        let span = header_span("git_show", &json!({}), Some(&target), &text);
        assert_eq!(
            span,
            if kind == ObjectKind::Commit {
                Some(7..47)
            } else {
                None
            }
        );
        assert!(header_span(
            "git_show",
            &json!({"revision":"HEAD:notes.txt"}),
            Some(&target),
            &text
        )
        .is_none());
        assert!(header_span(
            "git_show",
            &json!({}),
            Some(&target),
            &format!("body\n{text}")
        )
        .is_none());
    }
    let diff = format!("Diff with {id}:\nbody {id}\n");
    assert_eq!(
        header_span("git_diff", &json!({"target":id}), None, &diff),
        Some(10..50)
    );
    assert!(header_span("git_diff", &json!({"target":"HEAD"}), None, &diff).is_none());
    assert!(header_span("git_show", &json!({}), None, &text).is_none());
}
#[tokio::test]
async fn strict_bounded_response_correlation_rejects_uninspected_wire() {
    let valid = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    for raw in [
        valid.to_vec(),
        b"{\"jsonrpc\":\"2.0\",\"id\":9,\"id\":1,\"result\":{}}\n".to_vec(),
        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n".to_vec(),
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"extra\":true}\n".to_vec(),
        vec![b'x'; 1025],
    ] {
        let mut reader = BufReader::new(raw.as_slice());
        let result = receive(&mut reader, &json!(1), 1024).await;
        assert_eq!(result.is_ok(), raw == valid);
    }
}
#[tokio::test]
async fn original_request_bytes_are_written_once_after_pinned_handshake_and_discovery() {
    for bad_manifest in [false, true] {
        let p = profile();
        let original = String::from_utf8(show())
            .unwrap()
            .replace("\"jsonrpc\":", "\"jsonrpc\" : ")
            .into_bytes();
        let call = request(&p, &original).unwrap();
        let (client, server) = tokio::io::duplex(32768);
        let (r, mut w) = tokio::io::split(client);
        let mut r = BufReader::new(r);
        let seen = Arc::new(AtomicUsize::new(0));
        let count = seen.clone();
        let expected = original.clone();
        let peer = tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(server);
            let mut r = BufReader::new(r);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            let init: Value = serde_json::from_str(&line).unwrap();
            let initialization: Value = serde_json::from_str(include_str!(
                "../../../../profiles/mcp/git-readonly-v1/upstream-initialize.json"
            ))
            .unwrap();
            send(
                &mut w,
                &json!({"jsonrpc":"2.0","id":init["id"],"result":initialization["result"]}),
            )
            .await
            .unwrap();
            line.clear();
            r.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["method"],
                "notifications/initialized"
            );
            line.clear();
            r.read_line(&mut line).await.unwrap();
            let list: Value = serde_json::from_str(&line).unwrap();
            send(&mut w,&json!({"jsonrpc":"2.0","id":list["id"],"result":if bad_manifest{json!({"tools":[]})}else{git::original_manifest()}})).await.unwrap();
            if bad_manifest {
                return;
            }
            line.clear();
            r.read_line(&mut line).await.unwrap();
            assert_eq!(line.as_bytes(), expected);
            count.fetch_add(1, Ordering::SeqCst);
            let call: Value = serde_json::from_str(&line).unwrap();
            send(&mut w,&json!({"jsonrpc":"2.0","id":call["id"],"result":{"content":[{"type":"text","text":"original error"}],"isError":true}})).await.unwrap();
            line.clear();
            assert_eq!(r.read_line(&mut line).await.unwrap(), 0);
        });
        let snapshot = Snapshot::transport_test_snapshot();
        let result = exchange(&p, &original, &call, &snapshot, &mut r, &mut w).await;
        assert_eq!(result.is_err(), bad_manifest);
        if let Ok((reply, raw)) = result {
            assert_eq!(reply["id"], "host-77");
            assert_eq!(reply["result"]["isError"], true);
            assert!(raw.ends_with(b"\n"));
        }
        drop(w);
        peer.await.unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), usize::from(!bad_manifest));
    }
}
fn fixture(format: &str) -> (tempfile::TempDir, Value, Arc<Snapshot>) {
    use base64::Engine;
    let data: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/sou156-original-object-confusion.json"
    ))
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    for path in [".git/objects/info", ".git/objects/pack", ".git/refs/tags"] {
        std::fs::create_dir_all(root.path().join(path)).unwrap();
    }
    for (path, value) in data["images_base64"].as_object().unwrap() {
        let file = root.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            file,
            base64::engine::general_purpose::STANDARD
                .decode(value.as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    }
    let snapshot = Snapshot::capture(&std::fs::File::open(root.path()).unwrap(), format).unwrap();
    (root, data, snapshot)
}
#[test]
fn completion_binds_entire_original_text_and_retains_sticky_snapshot() {
    use base64::Engine;
    for format in [
        git::FORMAT,
        git::FILE_READS_FORMAT,
        server_profile::git_tracked_symlinks::FORMAT,
    ] {
        let (root, data, snapshot) = fixture(format);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(data["original_response_base64"].as_str().unwrap())
            .unwrap();
        let reply: Value = serde_json::from_slice(&raw).unwrap();
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut p = profile();
        p.format = format.into();
        for (key, eligible) in [("commit_oid", true), ("blob_oid", false)] {
            let original = wire(
                json!(10),
                "git_show",
                json!({"repo_path":"/workspace","revision":data[key]}),
            );
            let call = request(&p, &original).unwrap();
            // Local completion parser test, NOT a runtime-origin acceptance claim.
            let completion =
                completed_owned_output(&p, &call, reply.clone(), raw.clone(), snapshot.clone())
                    .unwrap();
            assert_eq!(completion.raw(), raw);
            assert_eq!(completion.formatter_span(&text).is_some(), eligible);
            assert!(completion
                .formatter_span(&format!("{text}changed"))
                .is_none());
            completion.validate().unwrap();
        }
        let original = wire(
            json!(10),
            "git_show",
            json!({"repo_path":"/workspace","revision":"HEAD"}),
        );
        let call = request(&p, &original).unwrap();
        let completion = completed_owned_output(&p, &call, reply, raw, snapshot).unwrap();
        let selected = root.path().join(".git/refs/heads/main");
        let moved = selected.with_extension("moved");
        std::fs::rename(&selected, &moved).unwrap();
        std::fs::rename(&moved, &selected).unwrap();
        assert!(completion.validate().is_err());
        assert!(completion.formatter_span(&text).is_none());
    }
}
#[tokio::test]
#[ignore = "requires native Linux pinned Git/Python/bwrap profile and SOU86_TEST_AGENTFW; not a scripted qualification"]
async fn actual_owned_original_git_commit_and_blob_keep_exact_kind_boundary() {
    let profile_path = std::env::var_os("SOU156_VERIFIED_GIT_TEST_PROFILE")
        .expect("explicit pinned profile required");
    let mut p = ProfileConfig::read(&std::fs::read(profile_path).unwrap()).unwrap();
    let (root, data, _) = fixture(&p.format);
    p.workspace = root.path().to_owned();
    p.workspace_identity = Some(server_profile::WorkspaceIdentity::from_metadata(
        &std::fs::metadata(root.path()).unwrap(),
    ));
    for (revision, eligible) in [
        ("HEAD".to_owned(), true),
        (data["blob_oid"].as_str().unwrap().to_owned(), false),
    ] {
        let completion = run(
            &p,
            &wire(
                json!("original-host"),
                "git_show",
                json!({"repo_path":"/workspace","revision":revision}),
            ),
        )
        .await
        .unwrap();
        completion.validate().unwrap();
        let value: Value = serde_json::from_slice(completion.raw()).unwrap();
        assert_eq!(value["id"], "original-host");
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(completion.formatter_span(text).is_some(), eligible);
    }
    match p.format.as_str() {
        git::FILE_READS_FORMAT => println!("SOU146_REAL_WORKER_KIND_BOUNDARY format={}", p.format),
        server_profile::git_tracked_symlinks::FORMAT => {
            println!("SOU150_REAL_WORKER_KIND_BOUNDARY format={}", p.format)
        }
        _ => println!("SOU156_REAL_WORKER_KIND_BOUNDARY format={}", p.format),
    }
}

#[test]
fn explicit_sandbox_entry_rejects_non_git_and_incomplete_runtime_configs() {
    let mut p = profile();
    p.format = server_profile::FORMAT.into();
    assert!(server_sandbox::prepare_verified_git(&p).is_err());
    let mut p = profile();
    p.git_launcher = None;
    assert!(server_sandbox::prepare_verified_git(&p).is_err());
}
