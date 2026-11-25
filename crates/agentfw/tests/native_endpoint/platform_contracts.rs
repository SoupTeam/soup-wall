// SPDX-License-Identifier: Apache-2.0

use super::*;

/// In-process native-contract regression, separate from installed executor evidence.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[tokio::test]
async fn macos_v7_v8_managed_transition_spends_old_receipts_and_recovers() {
    use agentfw::native::resource as r;
    for create in [false, true] {
        for verdict in ["deny", "ask"] {
            let mut f = Fixture::new(ALLOW);
            let root = f.dir.path().canonicalize().unwrap();
            let input = root.join("approved.txt");
            std::fs::write(&input, "unchanged approved document").unwrap();
            let target = if create {
                root.join("new.txt")
            } else {
                input.clone()
            };
            let name = if create {
                "create_file"
            } else {
                "read_document"
            };
            let schema = agentfw::native::canonical_digest(&if create {
                r::macos_create_schema()
            } else {
                r::macos_read_schema()
            });
            let mut policy = json!({
                "profile":{"server_id":"macos-policy-fixture","tool_name":name,
                    "schema_sha256":schema,"selectors":[{"pointer":"/path","kind":"path",
                        "allow_missing_leaf":create}]},
                "workspace":root,"cwd":root,"classifier_sha256":"c".repeat(64),
                "executor_sha256": if create {r::macos_create_executor_sha256()} else {r::macos_read_executor_sha256()},
                "allowed_resources":[{"kind":"path","canonical":target}]
            });
            if create {
                policy["execution"] = json!({"operation":"create_file","action":"write",
                    "max_content_bytes":r::MACOS_CREATE_MAX_CONTENT,"executor_profile":r::MACOS_CREATE_EXECUTOR_PROFILE});
            } else {
                policy["macos_read"] = json!({"executor_profile":r::MACOS_READ_EXECUTOR_PROFILE,
                    "max_content_bytes":r::MACOS_READ_MAX_CONTENT});
            }
            let configured = json!({"contract_version":CONTRACT,"registry_id":"macos-transition",
                "tools":[{"name":name,"schema_sha256":schema,
                    "action_class":if create {"side_effecting"} else {"read_only"},
                    "result_provenance":"untrusted","egress":[],"resource_policy":policy}]});
            let bytes = serde_json::to_vec(&configured).unwrap();
            f.registry_sha256 = sha256_hex(&bytes);
            f.state = make_state(
                f.dir.path(),
                Config {
                    enforce: true,
                    ..Config::default()
                },
                ALLOW,
                &bytes,
                &f.registry_sha256,
            );
            let policy: r::Policy = serde_json::from_value(policy).unwrap();
            let args = if create {
                json!({"path":"new.txt","content":"policy bytes"})
            } else {
                json!({"path":"approved.txt"})
            };
            let mut admission = resource_context(
                &serde_json::to_value(&policy.profile).unwrap(),
                json!([{"pointer":"/path","source":"argument","resource":policy.allowed_resources[0]}]),
            );
            admission["server_id"] = json!(policy.profile.server_id);
            admission["executor_sha256"] = json!(policy.executor_sha256);
            if create {
                admission["execution"] =
                    serde_json::to_value(r::macos_create_binding(&policy, &args).unwrap()).unwrap();
            } else {
                admission["macos_read"] =
                    serde_json::to_value(r::macos_read_binding(&policy, &args).unwrap()).unwrap();
            }
            let activate = |sequence, text: &str| {
                f.state.firewall.lock().unwrap().activate_managed_policy(
                    AgentPolicySet::from_yaml(text).unwrap(),
                    format!("revision-{sequence}"),
                    sequence,
                    sha256_hex(text.as_bytes()),
                );
            };
            activate(1, ALLOW);
            let mut start = f.event("macos-transition", "session_start");
            start["policy_transition"] = json!(agentfw::policy_transition::CONTRACT);
            let (status, started) = f.post(&start).await;
            assert_allow(status, &started);
            let mut call = resource_call(&f, "macos-transition", name, args.clone(), admission);
            call["contract_version"] = json!(policy.contract());
            call["schema_sha256"] = json!(schema);
            let (status, old) = f.post(&call).await;
            assert_eq!(status, StatusCode::OK, "{old}");
            assert_eq!(old["contract_version"], policy.contract());
            assert_eq!(old["release"], true, "{old}");
            let changed = format!("default: allow\nagent_policies:\n  - name: changed-action\n    when: {{min_action_class: read_only}}\n    action: {verdict}\n");
            activate(2, &changed);
            let mut result = f.result(
                "macos-transition",
                &old,
                name,
                &args,
                "value",
                "ordinary useful result",
            );
            result["contract_version"] = json!(policy.contract());
            let (status, refused) = f.post(&result).await;
            assert_eq!(status, StatusCode::OK, "{refused}");
            assert_eq!(refused["release"], false, "{refused}");
            assert_eq!(refused["verdict"], verdict);
            assert!(refused["reason_codes"]
                .as_array()
                .unwrap()
                .contains(&json!("native_policy_transition_result_refused")));
            let (_, spent) = f.post(&result).await;
            assert_eq!(spent["error_code"], "native_call_unknown_or_spent");
            let (_, new_denied) = f.post(&call).await;
            assert_eq!(new_denied["release"], false);
            activate(3, ALLOW);
            let (status, fresh) = f.post(&call).await;
            assert_eq!(status, StatusCode::OK, "{fresh}");
            assert_eq!(fresh["contract_version"], policy.contract());
            assert_eq!(fresh["release"], true, "{fresh}");
            result["call_id"] = fresh["call_id"].clone();
            let (status, released) = f.post(&result).await;
            assert_eq!(status, StatusCode::OK, "{released}");
            assert_eq!(released["contract_version"], policy.contract());
            assert_eq!(released["release"], true, "{released}");
            assert_eq!(
                std::fs::read(&input).unwrap(),
                b"unchanged approved document"
            );
            assert!(
                !root.join("new.txt").exists(),
                "Admission alone must not publish a file"
            );
        }
    }
}

#[cfg(not(windows))]
#[tokio::test]
async fn windows_read_v4_requests_are_unavailable_on_other_platforms() {
    let fixture = Fixture::new(ALLOW);
    fixture.start("windows-read-platform").await;
    let mut request = fixture.call(
        "windows-read-platform",
        "read_document",
        &json!({"path":"file.txt"}),
    );
    request["contract_version"] = json!(agentfw::native::resource::WINDOWS_READ_CONTRACT);
    request["resource_admission"] = resource_context(
        &json!({
            "server_id":"resource-fixture","tool_name":"read_document",
            "schema_sha256":schema(),"selectors":[]
        }),
        json!([]),
    );
    let (status, refused) = fixture.post(&request).await;
    assert_failure(status, &refused, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused["error_code"],
        "native_windows_read_platform_unsupported"
    );
}

#[cfg(windows)]
fn windows_read_fixture() -> (Fixture, agentfw::native::resource::Policy) {
    use agentfw::native::resource::{
        windows_read_executor_sha256, windows_read_schema, WINDOWS_READ_EXECUTOR_PROFILE,
        WINDOWS_READ_MAX_CONTENT,
    };
    let mut fixture = Fixture::new(ALLOW);
    let workspace = fixture.dir.path().join("windows-read-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let target = workspace.join("approved.txt");
    std::fs::write(&target, "approved bytes").unwrap();
    let schema_sha256 = agentfw::native::canonical_digest(&windows_read_schema());
    let resource_policy = json!({
        "profile":{"server_id":"windows-native-fixture","tool_name":"read_document",
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/path","kind":"path"}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":windows_read_executor_sha256(),"classifier_sha256":"c".repeat(64),
        "allowed_resources":[{"kind":"path","canonical":target}],
        "windows_read":{"executor_profile":WINDOWS_READ_EXECUTOR_PROFILE,
            "max_content_bytes":WINDOWS_READ_MAX_CONTENT}
    });
    let policy = serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    let tool = configured["tools"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|tool| tool["name"] == "read_document")
        .unwrap();
    tool["schema_sha256"] = json!(schema_sha256);
    tool["resource_policy"] = resource_policy;
    let bytes = serde_json::to_vec(&configured).unwrap();
    fixture.registry_sha256 = sha256_hex(&bytes);
    fixture.state = make_state(
        fixture.dir.path(),
        Config {
            enforce: true,
            ..Config::default()
        },
        ALLOW,
        &bytes,
        &fixture.registry_sha256,
    );
    (fixture, policy)
}

#[cfg(windows)]
fn windows_read_call(
    fixture: &Fixture,
    policy: &agentfw::native::resource::Policy,
    session: &str,
    args: &Value,
) -> Value {
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("original-windows-read-id"),
        profile_sha256: agentfw::native::canonical_digest(
            &serde_json::to_value(&policy.profile).unwrap(),
        ),
        executor_sha256: policy.executor_sha256.clone(),
        classifier_sha256: policy.classifier_sha256.clone(),
        snapshot_sha256: "d".repeat(64),
        definition_sha256: "f".repeat(64),
        input_sha256: "a".repeat(64),
        resources: vec![agentfw::mcp::resources::ResourceEvidence {
            pointer: "/path".into(),
            source: agentfw::mcp::resources::EvidenceSource::Argument,
            resource: policy.allowed_resources[0].clone(),
        }],
        execution: None,
        network: None,
        post: None,
        windows_read: Some(agentfw::native::resource::windows_read_binding(policy, args).unwrap()),
        macos_read: None,
    };
    let mut request = fixture.call(session, "read_document", args);
    request["contract_version"] = json!(agentfw::native::resource::WINDOWS_READ_CONTRACT);
    request["schema_sha256"] = json!(policy.profile.schema_sha256);
    request["resource_admission"] = serde_json::to_value(admission).unwrap();
    request
}

#[cfg(windows)]
#[tokio::test]
async fn windows_read_v4_native_binds_identity_arguments_and_single_use_result() {
    let (fixture, policy) = windows_read_fixture();
    fixture.start("windows-bound").await;
    let args = json!({"path":"approved.txt"});
    let request = windows_read_call(&fixture, &policy, "windows-bound", &args);
    for field in [
        "policy_sha256",
        "args_sha256",
        "workspace_sha256",
        "target_sha256",
    ] {
        let mut changed = request.clone();
        changed["resource_admission"]["windows_read"][field] = json!("0".repeat(64));
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{refused}");
        assert_eq!(refused["release"], false);
        assert_eq!(
            refused["reason_codes"],
            json!(["native_windows_read_binding_mismatch"])
        );
        assert!(refused["call_id"].is_null());
    }
    let mut changed = request.clone();
    changed["args"]["path"] = json!(policy.workspace.join("approved.txt"));
    let (_, refused) = fixture.post(&changed).await;
    assert_eq!(refused["release"], false, "{refused}");
    let (_, allowed) = fixture.post(&request).await;
    assert_eq!(allowed["release"], true, "{allowed}");
    assert_eq!(
        allowed["contract_version"],
        agentfw::native::resource::WINDOWS_READ_CONTRACT
    );
    let mut result = fixture.result(
        "windows-bound",
        &allowed,
        "read_document",
        &args,
        "value",
        "approved bytes",
    );
    result["contract_version"] = json!(agentfw::native::resource::WINDOWS_READ_CONTRACT);
    let (_, released) = fixture.post(&result).await;
    assert_eq!(released["release"], true, "{released}");
    let (_, replayed) = fixture.post(&result).await;
    assert_eq!(replayed["release"], false, "{replayed}");
}

#[cfg(windows)]
#[tokio::test]
async fn windows_read_v4_native_refuses_downgrade_and_replaced_leaf() {
    let (fixture, policy) = windows_read_fixture();
    fixture.start("windows-replaced").await;
    let args = json!({"path":"approved.txt"});
    let request = windows_read_call(&fixture, &policy, "windows-replaced", &args);
    for contract in [
        agentfw::native::resource::CONTRACT,
        agentfw::native::resource::CREATE_CONTRACT,
        agentfw::native::resource::NETWORK_CONTRACT,
        agentfw::native::resource::WINDOWS_CREATE_CONTRACT,
    ] {
        let mut changed = request.clone();
        changed["contract_version"] = json!(contract);
        let (status, refused) = fixture.post(&changed).await;
        assert_failure(status, &refused, StatusCode::BAD_REQUEST);
        assert_eq!(refused["error_code"], "native_resource_contract_mismatch");
    }
    let original = policy.workspace.join("approved.txt");
    std::fs::rename(&original, policy.workspace.join("original.txt")).unwrap();
    std::fs::write(&original, "substituted bytes").unwrap();
    let (_, refused) = fixture.post(&request).await;
    assert_eq!(refused["release"], false, "{refused}");
    assert_eq!(
        refused["reason_codes"],
        json!(["native_windows_read_binding_mismatch"])
    );
    assert!(refused["call_id"].is_null());
}

#[cfg(not(windows))]
#[tokio::test]
async fn windows_create_v5_requests_are_unavailable_on_other_platforms() {
    let fixture = Fixture::new(ALLOW);
    fixture.start("windows-create-platform").await;
    let mut request = fixture.call(
        "windows-create-platform",
        "create_file",
        &json!({"path":"new.txt","content":"owned bytes"}),
    );
    request["contract_version"] = json!(agentfw::native::resource::WINDOWS_CREATE_CONTRACT);
    request["resource_admission"] = resource_context(
        &json!({
            "server_id":"resource-fixture","tool_name":"create_file",
            "schema_sha256":schema(),"selectors":[]
        }),
        json!([]),
    );
    let (status, refused) = fixture.post(&request).await;
    assert_failure(status, &refused, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused["error_code"],
        "native_windows_create_platform_unsupported"
    );
}

#[cfg(windows)]
fn windows_create_fixture() -> (Fixture, agentfw::native::resource::Policy) {
    use agentfw::native::resource::{
        create_file_schema, windows_create_executor_sha256, CREATE_FILE_MAX_CONTENT,
        WINDOWS_CREATE_EXECUTOR_PROFILE,
    };
    let mut fixture = Fixture::new(ALLOW);
    let workspace = fixture.dir.path().join("windows-create-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let schema_sha256 = agentfw::native::canonical_digest(&create_file_schema());
    let resource_policy = json!({
        "profile":{"server_id":"windows-create-native-fixture","tool_name":"create_file",
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/path","kind":"path",
            "allow_missing_leaf":true}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":windows_create_executor_sha256(),"classifier_sha256":"c".repeat(64),
        "allowed_resources":[{"kind":"path","canonical":workspace.join("new.txt")}],
        "execution":{"operation":"create_file","action":"write",
            "max_content_bytes":CREATE_FILE_MAX_CONTENT,
            "executor_profile":WINDOWS_CREATE_EXECUTOR_PROFILE}
    });
    let policy = serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name":"create_file","schema_sha256":schema_sha256,"action_class":"side_effecting",
        "result_provenance":"untrusted","egress":[],"resource_policy":resource_policy
    }));
    let bytes = serde_json::to_vec(&configured).unwrap();
    fixture.registry_sha256 = sha256_hex(&bytes);
    fixture.state = make_state(
        fixture.dir.path(),
        Config {
            enforce: true,
            ..Config::default()
        },
        ALLOW,
        &bytes,
        &fixture.registry_sha256,
    );
    (fixture, policy)
}

#[cfg(windows)]
fn windows_create_call(
    fixture: &Fixture,
    policy: &agentfw::native::resource::Policy,
    session: &str,
    args: &Value,
) -> Value {
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("original-windows-create-id"),
        profile_sha256: agentfw::native::canonical_digest(
            &serde_json::to_value(&policy.profile).unwrap(),
        ),
        executor_sha256: policy.executor_sha256.clone(),
        classifier_sha256: policy.classifier_sha256.clone(),
        snapshot_sha256: "d".repeat(64),
        definition_sha256: "f".repeat(64),
        input_sha256: "a".repeat(64),
        resources: vec![agentfw::mcp::resources::ResourceEvidence {
            pointer: "/path".into(),
            source: agentfw::mcp::resources::EvidenceSource::Argument,
            resource: policy.allowed_resources[0].clone(),
        }],
        execution: Some(agentfw::native::resource::windows_create_binding(policy, args).unwrap()),
        network: None,
        post: None,
        windows_read: None,
        macos_read: None,
    };
    let mut request = fixture.call(session, "create_file", args);
    request["contract_version"] = json!(agentfw::native::resource::WINDOWS_CREATE_CONTRACT);
    request["schema_sha256"] = json!(policy.profile.schema_sha256);
    request["resource_admission"] = serde_json::to_value(admission).unwrap();
    request
}

#[cfg(windows)]
#[tokio::test]
async fn windows_create_v5_binds_exact_arguments_content_policy_and_workspace() {
    let (fixture, policy) = windows_create_fixture();
    fixture.start("windows-create-bound").await;
    let args = json!({"path":"new.txt","content":"exact UTF-8 ☃\n"});
    let request = windows_create_call(&fixture, &policy, "windows-create-bound", &args);
    for field in [
        "policy_sha256",
        "args_sha256",
        "content_sha256",
        "workspace_sha256",
    ] {
        let mut changed = request.clone();
        changed["resource_admission"]["execution"][field] = json!("0".repeat(64));
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{field}: {refused}");
        assert_eq!(refused["release"], false, "{field}: {refused}");
        assert_eq!(
            refused["reason_codes"],
            json!(["native_create_binding_mismatch"])
        );
        assert!(refused["call_id"].is_null());
    }
    let mut changed = request.clone();
    changed["args"]["content"] = json!("substituted UTF-8 bytes");
    let (_, refused) = fixture.post(&changed).await;
    assert_eq!(
        refused["reason_codes"],
        json!(["native_create_binding_mismatch"])
    );
    assert_eq!(refused["release"], false);
    let (status, allowed) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["release"], true, "{allowed}");
    assert_eq!(
        allowed["contract_version"],
        agentfw::native::resource::WINDOWS_CREATE_CONTRACT
    );
    let mut result = fixture.result(
        "windows-create-bound",
        &allowed,
        "create_file",
        &args,
        "value",
        "Created.",
    );
    result["contract_version"] = json!(agentfw::native::resource::WINDOWS_CREATE_CONTRACT);
    result["delivery"] = json!("mcp_host");
    result["content"] = json!(json!({"jsonrpc":"2.0","id":"original-windows-create-id",
        "result":{"content":[{"type":"text","text":"Created."}]}})
    .to_string());
    let (_, released) = fixture.post(&result).await;
    assert_eq!(released["release"], true, "{released}");
    let (status, replayed) = fixture.post(&result).await;
    assert_failure(status, &replayed, StatusCode::CONFLICT);
    assert_eq!(replayed["error_code"], "native_call_unknown_or_spent");
    // Native admission alone never creates a file. Windows execution is proved
    // separately through the actual stdio broker and independent filesystem.
    assert_eq!(std::fs::read_dir(&policy.workspace).unwrap().count(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_create_v5_results_are_bound_to_session_and_original_host_call() {
    let (fixture, policy) = windows_create_fixture();
    fixture.start("windows-create-one").await;
    fixture.start("windows-create-two").await;
    let args = json!({"path":"new.txt","content":"complete document"});
    let request = windows_create_call(&fixture, &policy, "windows-create-one", &args);
    let (_, first) = fixture.post(&request).await;
    assert_eq!(first["release"], true, "{first}");
    let mut second_request = request.clone();
    second_request["session_id"] = json!("windows-create-two");
    let (_, second) = fixture.post(&second_request).await;
    assert_eq!(second["release"], true, "{second}");
    assert_ne!(first["binding_sha256"], second["binding_sha256"]);
    let mut result = fixture.result(
        "windows-create-two",
        &first,
        "create_file",
        &args,
        "value",
        "Created.",
    );
    result["contract_version"] = json!(agentfw::native::resource::WINDOWS_CREATE_CONTRACT);
    let (status, wrong_session) = fixture.post(&result).await;
    assert_failure(status, &wrong_session, StatusCode::CONFLICT);
    assert_eq!(wrong_session["error_code"], "native_call_unknown_or_spent");
    result["session_id"] = json!("windows-create-one");
    result["delivery"] = json!("mcp_host");
    result["content"] = json!(json!({"jsonrpc":"2.0","id":"another-host-call",
        "result":{"content":[{"type":"text","text":"Created."}]}})
    .to_string());
    let (status, wrong_host) = fixture.post(&result).await;
    assert_failure(status, &wrong_host, StatusCode::CONFLICT);
    assert_eq!(wrong_host["error_code"], "native_host_call_mismatch");
    let (status, spent) = fixture.post(&result).await;
    assert_failure(status, &spent, StatusCode::CONFLICT);
    assert_eq!(spent["error_code"], "native_call_unknown_or_spent");
    let (_, continued) = fixture.post(&request).await;
    assert_eq!(continued["release"], true, "{continued}");
    assert!(!policy.workspace.join("new.txt").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_create_v5_refuses_older_and_unknown_execution_contracts() {
    let (fixture, policy) = windows_create_fixture();
    fixture.start("windows-create-contract").await;
    let args = json!({"path":"new.txt","content":"original document"});
    let request = windows_create_call(&fixture, &policy, "windows-create-contract", &args);
    for contract in [
        agentfw::native::resource::CONTRACT,
        agentfw::native::resource::CREATE_CONTRACT,
        agentfw::native::resource::NETWORK_CONTRACT,
        agentfw::native::resource::WINDOWS_READ_CONTRACT,
    ] {
        let mut changed = request.clone();
        changed["contract_version"] = json!(contract);
        let (status, refused) = fixture.post(&changed).await;
        assert_failure(status, &refused, StatusCode::BAD_REQUEST);
        assert_eq!(refused["error_code"], "native_resource_contract_mismatch");
    }
    let mut changed = request.clone();
    changed["contract_version"] = json!(agentfw::native::resource::CREATE_CONTRACT);
    changed["resource_admission"]["execution"]["executor_profile"] =
        json!(agentfw::native::resource::CREATE_FILE_EXECUTOR_PROFILE);
    let (status, downgraded) = fixture.post(&changed).await;
    assert_failure(status, &downgraded, StatusCode::CONFLICT);
    assert_eq!(
        downgraded["error_code"],
        "native_resource_contract_required"
    );
    changed = request.clone();
    changed["resource_admission"]["execution"]["executor_profile"] =
        json!("sw-native/create-file/windows-handles/unknown");
    let (status, unsupported) = fixture.post(&changed).await;
    assert_failure(status, &unsupported, StatusCode::BAD_REQUEST);
    assert!(!policy.workspace.join("new.txt").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_create_v5_refuses_parent_replacement_before_authorization() {
    let (fixture, policy) = windows_create_fixture();
    fixture.start("windows-create-root").await;
    let args = json!({"path":"new.txt","content":"bound to the original parent"});
    let request = windows_create_call(&fixture, &policy, "windows-create-root", &args);
    let original = policy.workspace.with_extension("original");
    std::fs::rename(&policy.workspace, &original).unwrap();
    std::fs::create_dir(&policy.workspace).unwrap();
    let (status, refused) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["release"], false, "{refused}");
    assert_eq!(
        refused["reason_codes"],
        json!(["native_create_binding_mismatch"])
    );
    assert!(refused["call_id"].is_null());
    assert_eq!(std::fs::read_dir(&policy.workspace).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_create_v5_refuses_a_target_created_after_configuration() {
    let (fixture, policy) = windows_create_fixture();
    fixture.start("windows-create-existing").await;
    let args = json!({"path":"new.txt","content":"must never overwrite"});
    let request = windows_create_call(&fixture, &policy, "windows-create-existing", &args);
    let target = policy.workspace.join("new.txt");
    std::fs::write(&target, b"independent competing creator").unwrap();
    let (status, refused) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["release"], false, "{refused}");
    assert_eq!(
        refused["reason_codes"],
        json!(["native_windows_create_target_invalid"])
    );
    assert!(refused["call_id"].is_null());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"independent competing creator"
    );
    assert_eq!(std::fs::read_dir(&policy.workspace).unwrap().count(), 1);
}
