// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn incomplete_inspection_output_never_creates_a_receipt() {
    struct Partial {
        remaining: usize,
    }
    impl Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let size = self.remaining.min(bytes.len());
            self.remaining -= size;
            Ok(size)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let receipt = root.path().join("inspected-call.json");
    for remaining in [0, 7, 1000] {
        let error = record_inspection(
            root.path(),
            &receipt,
            &json!({}),
            "complete arguments",
            &mut Partial { remaining },
        )
        .unwrap_err();
        assert!(matches!(result::reason(&error), Reason::OutputUnavailable));
        assert!(!receipt.exists());
    }
}

fn run() -> Run {
    Run {
        contract: "sw-pilot-run/1".into(),
        run_id: "a".repeat(32),
        home: PathBuf::from("/owned"),
        instance_id: "daemon-one".into(),
        registry_sha256: "b".repeat(64),
        host_session: "host-one".into(),
        launcher_pid: 1,
        launcher_start: 1,
        manifest_fd: 3,
        expires_at_ms: u64::MAX,
        authority_expires_at_ms: u64::MAX,
        authorities: BTreeMap::from([("filesystem".into(), "c".repeat(64))]),
        files: vec![],
    }
}

#[test]
#[cfg(unix)]
fn stop_receipts_bind_exact_run_bytes_and_authentication_and_never_regress() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    create_dir(&home).unwrap();
    write_new(&home.join("native-token"), &"owned-test-key").unwrap();
    let dir = root.path().join("run");
    create_dir(&dir).unwrap();
    let mut run = run();
    run.home = home;
    let bytes = serde_json::to_vec(&run).unwrap();
    for status in ["requested", "revoked", "stopped"] {
        write_stop(&dir, &run, &bytes, status).unwrap();
        assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, status);
    }
    write_stop(&dir, &run, &bytes, "requested").unwrap();
    assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, "stopped");
    assert!(read_stop(&dir, &run, b"foreign run bytes").is_err());
    let mut altered: Value =
        serde_json::from_slice(&fs::read(dir.join("stop.json")).unwrap()).unwrap();
    altered["status"] = json!("revoked");
    fs::write(dir.join("stop.json"), serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(read_stop(&dir, &run, &bytes).is_err());
}

#[test]
#[cfg(unix)]
fn linked_stop_receipt_is_never_accepted() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    create_dir(&home).unwrap();
    write_new(&home.join("native-token"), &"owned-test-key").unwrap();
    let dir = root.path().join("run");
    create_dir(&dir).unwrap();
    let mut run = run();
    run.home = home;
    let bytes = serde_json::to_vec(&run).unwrap();
    write_stop(&dir, &run, &bytes, "requested").unwrap();
    fs::rename(dir.join("stop.json"), dir.join("linked.json")).unwrap();
    symlink(dir.join("linked.json"), dir.join("stop.json")).unwrap();
    assert!(read_stop(&dir, &run, &bytes).is_err());
}

#[test]
#[cfg(unix)]
fn stop_completion_waits_for_an_inflight_metadata_update() {
    use std::sync::mpsc;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    create_dir(&home).unwrap();
    write_new(&home.join("native-token"), &"owned-test-key").unwrap();
    let dir = root.path().join("run");
    create_dir(&dir).unwrap();
    let mut run = run();
    run.home = home;
    let bytes = serde_json::to_vec(&run).unwrap();
    write_stop(&dir, &run, &bytes, "revoked").unwrap();
    let reservation = lock_dir(&dir).unwrap();
    // A permanently held lock still fails within a declared budget.
    assert!(lock_dir_for(&dir, Duration::from_millis(20)).is_err());
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker_dir = dir.clone();
    let worker_run = run.clone();
    let worker_bytes = bytes.clone();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        done_tx
            .send(write_stop(
                &worker_dir,
                &worker_run,
                &worker_bytes,
                "stopped",
            ))
            .unwrap();
    });
    started_rx.recv().unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(reservation);
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, "stopped");
}

#[test]
#[cfg(unix)]
fn inspection_output_cannot_lock_out_stop_or_record_after_stop() {
    struct Terminal<'a> {
        dir: &'a Path,
        receipt: &'a Path,
        run: &'a Run,
        bytes: &'a [u8],
        stop_on_flush: bool,
    }
    impl Write for Terminal<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            // Includes an arbitrarily blocked stdout: metadata stays available.
            assert!(lock_dir(self.dir).is_ok());
            assert!(!self.receipt.exists());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            assert!(lock_dir(self.dir).is_ok());
            assert!(!self.receipt.exists());
            if self.stop_on_flush {
                write_stop(self.dir, self.run, self.bytes, "requested").unwrap();
            }
            Ok(())
        }
    }
    for stop_on_flush in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        create_dir(&home).unwrap();
        write_new(&home.join("native-token"), &"owned-test-key").unwrap();
        let dir = root.path().join("run");
        create_dir(&dir).unwrap();
        let mut run = run();
        run.home = home;
        let bytes = serde_json::to_vec(&run).unwrap();
        let receipt = dir.join("inspected-call.json");
        let mut terminal = Terminal {
            dir: &dir,
            receipt: &receipt,
            run: &run,
            bytes: &bytes,
            stop_on_flush,
        };
        let value = json!({"binding_sha256":"owned", "expires_at_ms":u64::MAX});
        let result = record_inspection(&dir, &receipt, &value, "exact call", &mut terminal);
        assert_eq!(result.is_err(), stop_on_flush);
        assert_eq!(receipt.is_file(), !stop_on_flush);
        if !stop_on_flush {
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(&receipt).unwrap()).unwrap(),
                value
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn ordinary_exit_cannot_skip_unavailable_owner_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().canonicalize().unwrap();
    // A real closed loopback endpoint models loss of the authenticated
    // cleanup observer. Ordinary completion must not call it confirmed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let config = home.join("config.yaml");
    write_new(&config, &json!({"bind":"127.0.0.1","port":port})).unwrap();
    write_new(&home.join("native-token"), &"owned-witness-key").unwrap();
    let dir = home.join("run");
    create_dir(&dir).unwrap();
    let mut run = run();
    run.home = home;
    run.files = vec![FileIdentity {
        path: config.clone(),
        sha256: sha256_hex(&fs::read(config).unwrap()),
    }];
    let guard = RunGuard {
        _manifest: fs::File::create(dir.join("fixture-manifest")).unwrap(),
        dir,
        run,
    };
    assert!(!has_stop(&guard.dir).unwrap());
    assert!(
        guard.cleanup_waiter()().is_err(),
        "ordinary completion skipped the authenticated owner confirmation"
    );
}

#[cfg(not(unix))]
#[tokio::test]
async fn ordinary_exit_refuses_unsupported_owner_contract_before_network() {
    let server = wiremock::MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().canonicalize().unwrap();
    let config = home.join("config.yaml");
    write_new(
        &config,
        &json!({"bind":"127.0.0.1", "port":server.address().port()}),
    )
    .unwrap();
    write_new(&home.join("native-token"), &"owned-witness-key").unwrap();
    let dir = home.join("run");
    create_dir(&dir).unwrap();
    let mut run = run();
    run.home = home;
    run.files = vec![FileIdentity {
        path: config.clone(),
        sha256: sha256_hex(&fs::read(config).unwrap()),
    }];
    let guard = RunGuard {
        _manifest: fs::File::create(dir.join("fixture-manifest")).unwrap(),
        dir,
        run,
    };
    let result = tokio::task::spawn_blocking(guard.cleanup_waiter())
        .await
        .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("run-scoped approval requires qualified Linux"));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(!has_stop(&guard.dir).unwrap());
}

// RunGuard's private-file/owned-process contract is Unix-only. Windows
// refuses it before opening a native endpoint and cannot exercise this path.
#[cfg(unix)]
#[tokio::test]
async fn ordinary_exit_revokes_before_waiting_for_exact_owner_acknowledgement() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    for foreign_owner in [false, true] {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let config = home.join("config.yaml");
        write_new(
            &config,
            &json!({"bind":"127.0.0.1", "port":server.address().port()}),
        )
        .unwrap();
        write_new(&home.join("native-token"), &"owned-witness-key").unwrap();
        let dir = home.join("run");
        create_dir(&dir).unwrap();
        let mut run = run();
        run.home = home;
        run.authorities.insert("git".into(), "d".repeat(64));
        run.files = vec![FileIdentity {
            path: config.clone(),
            sha256: sha256_hex(&fs::read(config).unwrap()),
        }];
        let revoked = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(tokio::sync::Notify::new());
        let revoked_reply = revoked.clone();
        Mock::given(method("POST"))
            .and(path(crate::native::pilot_stop::ENDPOINT))
            .and(body_json(
                json!({"contract_version":crate::native::pilot_stop::CONTRACT,
                "instance_id":run.instance_id,"registry_sha256":run.registry_sha256,
                "host_session":run.host_session,"authorities":run.authorities,
                "expires_at_ms":run.authority_expires_at_ms}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                revoked_reply.store(true, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "contract_version":crate::native::pilot_stop::CONTRACT,
                    "instance_id":"daemon-one","host_session":"host-one","status":"revoked"}))
            })
            .expect(1)
            .mount(&server)
            .await;
        let ready_reply = ready.clone();
        let observed_reply = observed.clone();
        Mock::given(method("GET"))
            .and(path("/native/v1/instance"))
            .respond_with(move |_: &wiremock::Request| {
                assert!(
                    revoked.load(Ordering::SeqCst),
                    "owner observation preceded exact revocation"
                );
                let verified = ready_reply.load(Ordering::SeqCst);
                if !verified {
                    observed_reply.notify_one();
                }
                ResponseTemplate::new(200).set_body_json(json!({
                    "instance_id":"daemon-one","pilot_collectors":[],"pilot_pending":[],
                    "pilot_cleanup":[{"authority_sha256":"c".repeat(64),
                        "host_session":if foreign_owner {"foreign"} else {"host-one"},
                        "server_id":"filesystem","verified":verified}]}))
            })
            .mount(&server)
            .await;
        let guard = RunGuard {
            _manifest: fs::File::create(dir.join("fixture-manifest")).unwrap(),
            dir,
            run,
        };
        assert!(!has_stop(&guard.dir).unwrap());
        let task = tokio::task::spawn_blocking(guard.cleanup_waiter());
        if foreign_owner {
            let result = tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("foreign namespace cleanup identity"));
        } else {
            tokio::time::timeout(Duration::from_secs(3), observed.notified())
                .await
                .unwrap();
            assert!(
                !task.is_finished(),
                "unconfirmed namespace was accepted as clean"
            );
            ready.store(true, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        // Ordinary completion never forges an authenticated operator Stop.
        assert!(!has_stop(&guard.dir).unwrap());
    }
}

#[test]
fn stop_never_sends_credentials_to_a_changed_daemon_destination() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().canonicalize().unwrap();
    let path = home.join("config.yaml");
    write_new(&path, &json!({"bind":"127.0.0.1","port":12345})).unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut run = run();
    run.home = home;
    run.files = vec![FileIdentity {
        path: path.clone(),
        sha256: sha256_hex(&bytes),
    }];
    assert!(stop_config(&run).is_ok());
    fs::write(&path, b"bind: 127.0.0.1\nport: 54321\n").unwrap();
    assert!(stop_config(&run).is_err());
}

fn live() -> Value {
    json!({"instance_id":"daemon-one","registry_sha256":"b".repeat(64),
        "pilot_collectors":[{"active":true,"host_session":"host-one","server_id":"filesystem","agent_id":"claude-filesystem",
            "authority_sha256":"c".repeat(64),"session_id":"native-one","session_epoch":"epoch-one"}],
        "pilot_pending":[{"pending_id":"pending-one","tool":"read_text_file","binding_sha256":"d".repeat(64),
            "session_id":"native-one","session_epoch":"epoch-one"}]})
}

#[test]
fn retirement_without_namespace_confirmation_cannot_complete_stop() {
    let run = run();
    let retired = json!({"pilot_collectors":[], "pilot_pending":[]});
    assert!(selected_cleanup_complete(&run, &retired).is_err());
    let mut pending = json!({"pilot_cleanup":[{"authority_sha256":"c".repeat(64),
        "host_session":"host-one","server_id":"filesystem","verified":false}]});
    assert!(!selected_cleanup_complete(&run, &pending).unwrap());
    pending["pilot_cleanup"][0]["verified"] = json!(true);
    assert!(selected_cleanup_complete(&run, &pending).unwrap());
    pending["pilot_cleanup"][0]["host_session"] = json!("foreign");
    assert!(selected_cleanup_complete(&run, &pending).is_err());
    // No owner ever registered for this (now spent) authority. Other runs'
    // obligations may not block or satisfy this run's confirmation.
    pending["pilot_cleanup"][0]["authority_sha256"] = json!("e".repeat(64));
    pending["pilot_cleanup"][0]["verified"] = json!(false);
    assert!(selected_cleanup_complete(&run, &pending).unwrap());
}

#[test]
fn base64url_pending_ids_with_leading_hyphens_are_positional_values() {
    use clap::Parser;
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: OperatorArgs,
    }
    for action in ["inspect", "approve", "reject"] {
        for id in ["-owned", "--owned", "_owned"] {
            let mut words = vec![
                "operator".to_string(),
                "--run".into(),
                "a".repeat(32),
                action.into(),
                id.into(),
            ];
            if action != "inspect" {
                words.extend(["--binding".into(), "b".repeat(64)]);
            }
            let parsed = TestCli::try_parse_from(words).expect("valid broker id must parse");
            let parsed_id = match parsed.args.action {
                OperatorAction::Inspect { id }
                | OperatorAction::Approve { id, .. }
                | OperatorAction::Reject { id, .. } => id,
                OperatorAction::List | OperatorAction::Stop | OperatorAction::Watch { .. } => {
                    unreachable!()
                }
            };
            assert_eq!(parsed_id, id);
        }
    }
}

#[test]
fn run_selection_requires_all_authenticated_identities() {
    assert_eq!(pending(&run(), &live()).unwrap().len(), 1);
    for (key, value) in [
        ("host_session", "other-host"),
        ("server_id", "git"),
        ("agent_id", "claude-git"),
        ("authority_sha256", "different-grant"),
        ("session_id", "foreign-collector"),
        ("session_epoch", "old-epoch"),
    ] {
        let mut value_live = live();
        value_live["pilot_collectors"][0][key] = json!(value);
        assert!(
            pending(&run(), &value_live).unwrap().is_empty(),
            "{key} must be authoritative"
        );
    }
    for key in ["instance_id", "registry_sha256"] {
        let mut other = live();
        other[key] = json!("changed");
        assert!(pending(&run(), &other).is_err());
    }
    let mut expired = live();
    expired["pilot_collectors"][0]["active"] = json!(false);
    assert!(pending(&run(), &expired).unwrap().is_empty());
}

#[test]
fn same_label_cannot_select_another_runs_grant() {
    let mut value = live();
    let mut foreign = value["pilot_collectors"][0].clone();
    foreign["authority_sha256"] = json!("e".repeat(64));
    value["pilot_collectors"] = json!([foreign]);
    assert!(pending(&run(), &value).unwrap().is_empty());
}

#[test]
fn pending_record_removed_after_snapshot_has_a_producer_reason() {
    let home = tempfile::tempdir().unwrap();
    create_dir(&approval::pending_dir(home.path())).unwrap();
    let observed = live()["pilot_pending"][0].clone();
    let path = approval::pending_dir(home.path()).join("pending-one.json");
    write_new(&path, &observed).unwrap();
    fs::remove_file(path).unwrap();
    let error = checked_record(home.path(), &observed).unwrap_err();
    assert!(matches!(result::reason(&error), Reason::PendingUnavailable));
}

#[test]
#[cfg(unix)]
fn raw_arguments_cannot_change_behind_a_trusted_binding() {
    let dir = tempfile::tempdir().unwrap();
    create_dir(&approval::pending_dir(dir.path())).unwrap();
    let args = json!({"path":"/workspace/approved.txt"});
    let observed = json!({"pending_id":"pending-one","session_id":"native-one","session_epoch":"epoch-one",
        "tool":"read_text_file","binding_sha256":"d".repeat(64), "args_sha256":crate::native::canonical_digest(&args)});
    let mut observed = observed;
    observed["expires_at_ms"] = json!(approval::now_ms() + 10_000);
    let mut file = observed.clone();
    file["args"] = args;
    file["scope"] = json!("native-mcp/approval/v1");
    file["expires_at_ms"] = observed["expires_at_ms"].clone();
    let path = approval::pending_dir(dir.path()).join("pending-one.json");
    write_new(&path, &file).unwrap();
    assert!(checked_record(dir.path(), &observed).is_ok());
    for key in ["scope", "expires_at_ms"] {
        let mut changed = file.clone();
        changed[key] = json!("foreign");
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let error = checked_record(dir.path(), &observed).unwrap_err();
        assert!(
            matches!(result::reason(&error), Reason::BindingChanged),
            "{key}"
        );
    }
    for key in [
        "session_id",
        "session_epoch",
        "binding_sha256",
        "args_sha256",
    ] {
        let mut tampered = file.clone();
        tampered[key] = json!("foreign");
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(checked_record(dir.path(), &observed).is_err(), "{key}");
    }
    file["args"] = json!({"path":"/workspace/other.txt"});
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(checked_record(dir.path(), &observed).is_err());
}

#[test]
fn terminal_control_and_bidi_are_escaped_even_in_explicit_inspection() {
    let text =
        escaped(&json!({"args":{"text":"\u{1b}[31m\u{9b}31m\u{202e}spoof\u{2066}end"}})).unwrap();
    for c in ['\u{1b}', '\u{9b}', '\u{202e}', '\u{2066}'] {
        assert!(!text.contains(c));
    }
    assert!(text.contains("\\u001b") && text.contains("\\u009b") && text.contains("\\u202e"));
}

#[test]
fn inspection_escapes_invisible_unicode_and_preserves_exact_arguments() {
    let value = json!({"args":{"path":"/workspace/данные\u{ad}\u{180e}😀.txt"}});
    let display = escaped(&value).unwrap();
    assert!(display.is_ascii());
    assert!(display.contains("\\u00ad") && display.contains("\\u180e"));
    assert!(display.contains("\\ud83d\\ude00"));
    assert_eq!(serde_json::from_str::<Value>(&display).unwrap(), value);
}

#[test]
#[cfg(unix)]
fn private_metadata_rejects_symlinks_and_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    write_new(&path, &json!({"owned":true})).unwrap();
    assert!(read_file(&path, true).is_ok());
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_file(&link, true).is_err());
    }
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_BYTES as u64 + 1)
        .unwrap();
    assert!(read_file(&path, true).is_err());
}

#[test]
#[cfg(unix)]
fn inspection_pruning_is_bounded_to_own_expired_receipts() {
    let dir = tempfile::tempdir().unwrap();
    write_new(&dir.path().join("run.json"), &json!({"expires_at_ms":0})).unwrap();
    write_new(
        &dir.path().join("inspected-old.json"),
        &json!({"expires_at_ms":0}),
    )
    .unwrap();
    write_new(
        &dir.path().join("inspected-live.json"),
        &json!({"expires_at_ms":u64::MAX}),
    )
    .unwrap();
    write_new(&dir.path().join("other.json"), &json!({"expires_at_ms":0})).unwrap();
    let reservation = lock_dir(dir.path()).unwrap();
    assert!(lock_dir(dir.path()).is_err());
    prune_inspections(dir.path()).unwrap();
    assert!(!dir.path().join("inspected-old.json").exists());
    for name in ["run.json", "inspected-live.json", "other.json"] {
        assert!(dir.path().join(name).is_file());
    }
    drop(reservation);
    assert!(lock_dir(dir.path()).is_ok());
}

#[test]
#[cfg(target_os = "linux")]
fn sealed_selection_rejects_disk_tampering_and_lost_launcher_identity() {
    let mut file = manifest().unwrap();
    let mut run = run();
    run.launcher_pid = std::process::id();
    run.launcher_start = process_start(run.launcher_pid).unwrap();
    run.manifest_fd = descriptor(&file);
    seal(&mut file, &run).unwrap();
    let bytes = serde_json::to_vec(&run).unwrap();
    verify_sealed(&run, &bytes).unwrap();
    assert!(
        verify_manifest(&run, &bytes).is_err(),
        "a library test process is not a pilot launcher"
    );
    assert!(file.write_all(b"replacement").is_err());
    let mut changed = run.clone();
    changed.host_session = "other-run".into();
    assert!(verify_sealed(&changed, &serde_json::to_vec(&changed).unwrap()).is_err());
    changed = run.clone();
    changed.launcher_start += 1;
    assert!(verify_sealed(&changed, &serde_json::to_vec(&changed).unwrap()).is_err());
    drop(file);
    assert!(verify_sealed(&run, &bytes).is_err());
}
