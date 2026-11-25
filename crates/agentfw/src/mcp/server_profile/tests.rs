// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an explicitly selected operator-owned installed native profile"]
fn native_installed_profile_ask_capture_resume() {
    let profile = ProfileConfig::load_from_env()
        .expect("read selected profile")
        .expect("explicit selected profile required");
    profile
        .verify_assets()
        .expect("initial selected asset verification");
    let captured = profile
        .capture_verified_assets()
        .expect("selected input capture");
    profile
        .revalidate_assets(&captured)
        .expect("selected input resume");
    let (immutable, leased, _) = captured.inputs.counts();
    assert!(
        immutable + leased > 0,
        "actual installed input kernel reuse required"
    );
}

#[test]
fn capture_failure_codes_never_export_arbitrary_error_payloads() {
    assert_eq!(
        verified_capture_failure(&anyhow::anyhow!("private payload and token")),
        "capture_failure"
    );
    assert_eq!(
        verified_capture_failure(&anyhow::anyhow!(
            "selected asset changed during identity lookup"
        )),
        "identity_lookup_changed"
    );
}

#[test]
fn frozen_false_refusal_paths_do_not_gain_selected_runtime_custody() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../../../eval/sou123/manifest.json")).unwrap();
    let tools = classify_manifest(&original_manifest()).unwrap();
    for id in ["f05-a", "f12-a"] {
        let case = manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["case_id"] == id)
            .unwrap();
        let error = tools["read_multiple_files"]
            .validate_arguments(&case["arguments"])
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PathRefusal>(),
            Some(PathRefusal::Outside)
        ));
    }
}

#[test]
fn original_upstream_discovery_preserves_every_tool_and_classifies_support() {
    let original = original_manifest();
    let tools = classify_manifest(&original).unwrap();
    assert_eq!(tools.len(), 14);
    assert_eq!(
        tools
            .values()
            .filter(|p| p.unsupported_reason.is_none())
            .count(),
        9
    );
    assert!(tools["read_text_file"]
        .validate_arguments(&json!({"path":"/workspace/note.txt"}))
        .is_ok());
    assert!(tools["write_file"]
        .validate_arguments(&json!({"path":"/workspace/note.txt","content":"new"}))
        .is_err());
    assert!(tools["read_media_file"].unsupported_reason.is_some());
    assert!(tools["list_directory_with_sizes"]
        .validate_arguments(&json!({"path":"/workspace","sortBy":"size"}))
        .is_ok());
    assert!(tools["list_directory_with_sizes"]
        .validate_arguments(&json!({"path":"/workspace","sortBy":"arbitrary"}))
        .is_err());
    assert!(tools["read_multiple_files"]
        .validate_arguments(&json!({"paths":[]}))
        .is_err());
    assert!(tools["read_text_file"]
        .validate_arguments(&json!({"path":"/workspace/note.txt","head":1.5}))
        .is_err());
    assert!(tools["read_text_file"]
        .validate_arguments(&json!({"path":"/workspace/note.txt","head":-1}))
        .is_err());
    assert!(tools["read_text_file"]
        .validate_arguments(&json!({"path":"/workspace/note.txt","unknown":"ignored upstream"}))
        .is_err());
    for path in ["/etc/passwd", "../note.txt", "/workspace/../etc/passwd", ""] {
        assert!(tools["read_text_file"]
            .validate_arguments(&json!({"path":path}))
            .is_err());
    }
    assert!(
        tools["read_text_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt"}))
            .is_ok(),
        "unsupported calls do not consume unrelated schemas"
    );
}

#[test]
fn selected_upstream_pins_cover_metadata_execution_and_output_schema() {
    for field in [
        "description",
        "title",
        "inputSchema",
        "outputSchema",
        "annotations",
        "execution",
    ] {
        let mut changed = original_manifest();
        changed["tools"][0][field] = Value::Null;
        assert!(classify_manifest(&changed).is_err(), "{field}");
    }
    let mut changed = original_manifest();
    changed["nextCursor"] = json!("hidden-page");
    assert!(classify_manifest(&changed).is_err());
}

#[test]
fn selected_protocol_versions_are_the_frozen_original_sdk_allowlist() {
    let original: Value = serde_json::from_str(ORIGINAL_INITIALIZATION).unwrap();
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        let mut response = original["result"].clone();
        response["protocolVersion"] = json!(version);
        assert!(validate_initialization(&response).is_ok());
    }
    for version in ["future", "", "2026-07-28"] {
        let mut response = original["result"].clone();
        response["protocolVersion"] = json!(version);
        assert!(validate_initialization(&response).is_err());
    }
    let mut response = original["result"].clone();
    response["capabilities"]["logging"] = json!({});
    assert!(validate_initialization(&response).is_err());
}

#[test]
fn selected_original_result_requires_inspectable_structured_text() {
    let tools = classify_manifest(&original_manifest()).unwrap();
    let read = &tools["read_text_file"];
    let value = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ordinary"}],"structuredContent":{"content":"independent text"}}});
    assert_eq!(read.validate_result(&value).unwrap(), "value");
    for result in [
        json!({"content":[],"structuredContent":{"content":"text","hidden":"payload"}}),
        json!({"content":[],"structuredContent":{"content":42}}),
        json!({"content":[],"structuredContent":{"instructions":"payload"}}),
        json!({"content":[],"structuredContent":null}),
        json!({"content":[]}),
        json!({"content":[{"type":"image","data":"payload"}],"structuredContent":{"content":"text"}}),
        json!({"content":[],"structuredContent":{"content":"text"},"_meta":{"payload":"uninspected"}}),
    ] {
        assert!(read
            .validate_result(&json!({"jsonrpc":"2.0","id":1,"result":result}))
            .is_err());
    }
    assert_eq!(
        read.validate_result(
            &json!({"result":{"content":[{"type":"text","text":"ordinary error"}],"isError":true}})
        )
        .unwrap(),
        "error"
    );
}

#[test]
fn result_budget_is_separate_from_argument_budget_on_both_channels() {
    use super::super::input::ResultBudgetExceeded;
    let tools = classify_manifest(&original_manifest()).unwrap();
    let read = &tools["read_text_file"];
    let frame = |text: &str, structured: &str| {
        json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":text}],
            "structuredContent":{"content":structured}}})
    };
    let budget_error = |value: &Value| {
        read.validate_result(value)
            .unwrap_err()
            .downcast_ref::<ResultBudgetExceeded>()
            .copied()
    };
    // The old argument default was the result limit; it no longer is.
    for size in [16_383, 16_384, 16_385, 20 * 1024, 60 * 1024, 120 * 1024] {
        let text = "a".repeat(size);
        assert_eq!(read.validate_result(&frame(&text, &text)).unwrap(), "value");
    }
    let below = "b".repeat(RESULT_TEXT_BYTES - 1);
    let at = "b".repeat(RESULT_TEXT_BYTES);
    let above = "b".repeat(RESULT_TEXT_BYTES + 1);
    assert_eq!(
        read.validate_result(&frame(&below, &below)).unwrap(),
        "value"
    );
    assert_eq!(read.validate_result(&frame(&at, &at)).unwrap(), "value");
    let limit = Some(ResultBudgetExceeded {
        limit: RESULT_TEXT_BYTES,
    });
    assert_eq!(budget_error(&frame(&above, "small")), limit);
    assert_eq!(budget_error(&frame("small", &above)), limit);
    // Bytes, not characters: 65_536 four-byte scalars fill the budget exactly.
    let wide = "\u{1F963}".repeat(RESULT_TEXT_BYTES / 4);
    assert_eq!(read.validate_result(&frame(&wide, &wide)).unwrap(), "value");
    let wider = format!("{wide}x");
    assert_eq!(budget_error(&frame(&wider, &wider)), limit);
    // Type and shape validation are unchanged by the result role.
    let typed = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"x"}],
        "structuredContent":{"content":7}}});
    assert!(budget_error(&typed).is_none() && read.validate_result(&typed).is_err());
    // Arguments keep the reviewed 16 KiB default string budget.
    let input = read.input.as_ref().unwrap();
    assert!(input.validate(&json!({"path":"p".repeat(16_384)})).is_ok());
    assert!(input.validate(&json!({"path":"p".repeat(16_385)})).is_err());
}

#[test]
fn tree_hash_records_empty_directories_file_bytes_and_every_entry() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("file"), "first").unwrap();
    let first = package_tree_sha256(root.path()).unwrap();
    fs::create_dir(root.path().join("empty")).unwrap();
    let second = package_tree_sha256(root.path()).unwrap();
    assert_ne!(first, second);
    fs::write(root.path().join("file"), "other").unwrap();
    assert_ne!(second, package_tree_sha256(root.path()).unwrap());
    fs::write(root.path().join(".hidden"), "covered").unwrap();
    assert_ne!(first, package_tree_sha256(root.path()).unwrap());
}

#[cfg(unix)]
#[test]
fn tree_hash_covers_internal_links_and_refuses_escape_links() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("bin")).unwrap();
    fs::write(root.path().join("entry.js"), "original").unwrap();
    std::os::unix::fs::symlink("../entry.js", root.path().join("bin/tool")).unwrap();
    assert!(package_tree_sha256(root.path()).is_ok());
    fs::remove_file(root.path().join("bin/tool")).unwrap();
    std::os::unix::fs::symlink("../../outside", root.path().join("bin/tool")).unwrap();
    assert!(package_tree_sha256(root.path()).is_err());
}
#[cfg(unix)]
#[test]
fn tree_hash_refuses_escape_hidden_by_a_chained_link_before_parent_traversal() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("package");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(parent.path().join("outside"), "must not mount").unwrap();
    std::os::unix::fs::symlink("..", root.join("dir/a")).unwrap();
    std::os::unix::fs::symlink("a/../outside", root.join("dir/tool")).unwrap();
    assert!(package_tree_sha256(&root).is_err());
}

#[test]
fn explicit_profile_is_strict_and_binds_the_actual_command() {
    // Physical operator paths use the host filesystem's absolute syntax;
    // the child argument remains the fixed virtual POSIX `/workspace`.
    let owned = tempfile::tempdir().unwrap();
    let root = owned.path().canonicalize().unwrap();
    let workspace = root.join("approved");
    let runtime = root.join("runtime").join("node");
    let package = root.join("installed").join("server");
    let bwrap = root.join("runtime").join("bwrap");
    let other = root.join("other");
    let value = json!({"format":FORMAT,"workspace":workspace,"runtimePath":runtime,"runtimeSha256":"a".repeat(64),"packageRoot":package,"packageTreeSha256":"b".repeat(64),"bwrapPath":bwrap,"bwrapSha256":"c".repeat(64),"libraries":[]});
    let profile = ProfileConfig::read(value.to_string().as_bytes()).unwrap();
    let args = vec![
        package.join(SERVER_ENTRYPOINT).to_str().unwrap().to_owned(),
        "/workspace".to_owned(),
    ];
    assert!(profile
        .validate_command(runtime.to_str().unwrap(), &args, &workspace)
        .is_ok());
    assert!(profile
        .validate_command(other.to_str().unwrap(), &args, &workspace)
        .is_err());
    assert!(profile
        .validate_command(runtime.to_str().unwrap(), &args, &other)
        .is_err());
    let mut changed = value.clone();
    changed["allowNetwork"] = json!(true);
    assert!(ProfileConfig::read(changed.to_string().as_bytes()).is_err());
    let mut changed = value;
    changed["format"] = json!("unknown");
    assert!(ProfileConfig::read(changed.to_string().as_bytes()).is_err());
    #[cfg(not(target_os = "linux"))]
    assert!(
        super::super::server_sandbox::prepare(&profile)
            .unwrap_err()
            .to_string()
            .contains("requires Linux bubblewrap"),
        "a valid physical configuration must not enable an unsupported host"
    );
}

#[test]
fn virtual_workspace_paths_have_posix_semantics_on_every_host() {
    for path in [
        "/workspace",
        "/workspace/file.txt",
        "/workspace/sub/file.txt",
        "file.txt",
        "sub/file.txt",
        "café.txt",
    ] {
        assert!(validate_workspace_path(&json!(path)).is_ok(), "{path}");
    }
    for path in [
        "",
        "/",
        "/etc/passwd",
        "/workspaces/file.txt",
        "../file",
        "sub/../file",
        "./file",
        "sub/./file",
        "sub//file",
        "/workspace/",
        "//workspace/file",
        "C:/workspace/file",
        "C:\\workspace\\file",
        "\\workspace\\file",
        "file:stream",
        "~/file",
        "/workspace/back\\slash",
        "/workspace/tab\tname",
        "/workspace:extra",
        "/workspace/a/../../etc/passwd",
    ] {
        assert!(validate_workspace_path(&json!(path)).is_err(), "{path}");
    }
}

#[test]
fn path_refusals_name_their_boundary_and_accept_linux_names() {
    let refusal = |path: &str| {
        validate_workspace_path(&json!(path))
            .unwrap_err()
            .downcast_ref::<PathRefusal>()
            .copied()
    };
    for path in ["/etc/passwd", "/workspaces/file.txt", "/", "/tmp/x:y"] {
        assert_eq!(refusal(path), Some(PathRefusal::Outside), "{path}");
    }
    for path in [
        "",
        "../file",
        "/workspace/../etc/passwd",
        "sub//file",
        "/workspace/",
        "C:/workspace/file",
        "file:stream",
        "~/file",
        "/workspace/a\\b",
        "/workspace/a\nb",
    ] {
        assert_eq!(refusal(path), Some(PathRefusal::Spelling), "{path:?}");
    }
    assert_eq!(
        refusal(&format!("/workspace/{}", "a".repeat(4096))),
        Some(PathRefusal::Spelling)
    );
    // Ordinary Linux names stay exact: nothing is normalized or decoded.
    for path in [
        "/workspace/a:b.txt",
        "/workspace/dir with spaces/file name.txt",
        "/workspace/кириллица/файл.txt",
        "/workspace/-leading-dash.txt",
        "-leading-dash.txt",
        "/workspace/.hidden",
        "/workspace/$(touch pwned).txt",
        "/workspace/; ls.txt",
        "/workspace/quote\"name.txt",
        "/workspace/caf\u{e9}.txt",
        "/workspace/cafe\u{301}.txt",
        "/workspace/percent%2F.txt",
    ] {
        assert!(validate_workspace_path(&json!(path)).is_ok(), "{path}");
    }
    // A type error is not a path refusal.
    assert!(validate_workspace_path(&json!(7))
        .unwrap_err()
        .downcast_ref::<PathRefusal>()
        .is_none());
}
