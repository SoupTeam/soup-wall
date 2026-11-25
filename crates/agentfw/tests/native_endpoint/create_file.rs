// SPDX-License-Identifier: Apache-2.0

use super::*;

#[cfg(unix)]
fn create_file_fixture() -> (Fixture, agentfw::native::resource::Policy) {
    use agentfw::native::resource::{
        create_file_executor_sha256, create_file_schema, CREATE_FILE_EXECUTOR_PROFILE,
        CREATE_FILE_MAX_CONTENT,
    };
    let mut fixture = Fixture::new(ALLOW);
    let workspace = fixture.dir.path().join("create-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let schema_sha256 = agentfw::native::canonical_digest(&create_file_schema());
    let resource_policy = json!({
        "profile":{"server_id":"create-native-fixture","tool_name":"create_file",
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/path","kind":"path",
            "allow_missing_leaf":true}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":create_file_executor_sha256(),"classifier_sha256":"c".repeat(64),
        "allowed_resources":[{"kind":"path","canonical":workspace.join("new.txt")}],
        "execution":{"operation":"create_file","action":"write",
            "max_content_bytes":CREATE_FILE_MAX_CONTENT,"executor_profile":CREATE_FILE_EXECUTOR_PROFILE}
    });
    let policy = serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name":"create_file","schema_sha256":schema_sha256,"action_class":"side_effecting",
        "result_provenance":"local_project","egress":[],"resource_policy":resource_policy
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

#[cfg(unix)]
fn create_file_call(
    fixture: &Fixture,
    policy: &agentfw::native::resource::Policy,
    session: &str,
    args: &Value,
) -> Value {
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("original-create-id"),
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
        execution: Some(agentfw::native::resource::create_file_binding(policy, args).unwrap()),
        network: None,
        post: None,
        windows_read: None,
        macos_read: None,
    };
    let mut body = fixture.event(session, "call");
    body["contract_version"] = json!(agentfw::native::resource::CREATE_CONTRACT);
    body["tool"] = json!("create_file");
    body["args"] = args.clone();
    body["schema_sha256"] = json!(policy.profile.schema_sha256);
    body["resource_admission"] = serde_json::to_value(admission).unwrap();
    body
}

#[cfg(unix)]
#[tokio::test]
async fn create_file_v2_native_admission_binds_args_operation_host_and_session() {
    let (fixture, policy) = create_file_fixture();
    fixture.start("write-one").await;
    fixture.start("write-two").await;
    let args = json!({"path":"new.txt","content":"exact UTF-8 ☃\n"});
    let body = create_file_call(&fixture, &policy, "write-one", &args);
    let (status, first) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        first["contract_version"],
        agentfw::native::resource::CREATE_CONTRACT
    );
    assert_eq!(first["verdict"], "allow", "{first}");
    assert_eq!(first["release"], true);
    assert!(first["binding_sha256"]
        .as_str()
        .is_some_and(agentfw::native::is_digest));
    let mut second_body = body.clone();
    second_body["session_id"] = json!("write-two");
    let (_, second) = fixture.post(&second_body).await;
    assert_eq!(second["release"], true, "{second}");
    assert_ne!(first["binding_sha256"], second["binding_sha256"]);
    let mut result = fixture.result(
        "write-two",
        &first,
        "create_file",
        &args,
        "value",
        "Created.",
    );
    result["contract_version"] = json!(agentfw::native::resource::CREATE_CONTRACT);
    let (status, wrong_session) = fixture.post(&result).await;
    assert_failure(status, &wrong_session, StatusCode::CONFLICT);
    assert_eq!(wrong_session["error_code"], "native_call_unknown_or_spent");
    result["session_id"] = json!("write-one");
    result["delivery"] = json!("mcp_host");
    result["content"] = json!(json!({"jsonrpc":"2.0","id":"different-host-id",
        "result":{"content":[{"type":"text","text":"Created."}]}})
    .to_string());
    let (status, wrong_host) = fixture.post(&result).await;
    assert_failure(status, &wrong_host, StatusCode::CONFLICT);
    assert_eq!(wrong_host["error_code"], "native_host_call_mismatch");
    let (status, replay) = fixture.post(&result).await;
    assert_failure(status, &replay, StatusCode::CONFLICT);
    assert_eq!(replay["error_code"], "native_call_unknown_or_spent");
    // Admission alone performs no filesystem mutation; the separate constrained
    // broker must obtain a release before its actual execution boundary.
    assert!(!policy.workspace.join("new.txt").exists());
    let (status, continued) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{continued}");
    assert_eq!(continued["release"], true);
}

#[cfg(unix)]
#[tokio::test]
async fn create_file_v2_native_refuses_downgrade_and_content_substitution() {
    let (fixture, policy) = create_file_fixture();
    fixture.start("write-refusals").await;
    let args = json!({"path":"new.txt","content":"original bytes"});
    let body = create_file_call(&fixture, &policy, "write-refusals", &args);
    let mut changed = body.clone();
    changed["args"]["content"] = json!("replacement bytes");
    let (status, refused) = fixture.post(&changed).await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["verdict"], "deny");
    assert_eq!(refused["release"], false);
    assert_eq!(
        refused["reason_codes"],
        json!(["native_create_binding_mismatch"])
    );
    assert!(refused["call_id"].is_null());
    changed = body.clone();
    changed["contract_version"] = json!(agentfw::native::resource::CONTRACT);
    let (status, shape_downgrade) = fixture.post(&changed).await;
    assert_failure(status, &shape_downgrade, StatusCode::BAD_REQUEST);
    assert_eq!(
        shape_downgrade["error_code"],
        "native_resource_contract_mismatch"
    );
    changed["resource_admission"]
        .as_object_mut()
        .unwrap()
        .remove("execution");
    let (status, policy_downgrade) = fixture.post(&changed).await;
    assert_failure(status, &policy_downgrade, StatusCode::CONFLICT);
    assert_eq!(
        policy_downgrade["error_code"],
        "native_resource_contract_required"
    );
    changed = body.clone();
    changed["resource_admission"]["execution"]["action"] = json!("read");
    let (status, wrong_action) = fixture.post(&changed).await;
    assert_failure(status, &wrong_action, StatusCode::BAD_REQUEST);
    changed = body.clone();
    changed["resource_admission"]["executor_sha256"] = json!("e".repeat(64));
    let (_, wrong_executor) = fixture.post(&changed).await;
    assert_eq!(wrong_executor["release"], false);
    assert_eq!(
        wrong_executor["reason_codes"],
        json!(["native_resource_revision_mismatch"])
    );
    assert!(!policy.workspace.join("new.txt").exists());
    let (status, allowed) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["release"], true);
}

#[cfg(unix)]
#[tokio::test]
async fn sou67_create_file_v2_native_operator_bound_tool_name_admits_and_binds() {
    use agentfw::native::resource::{
        create_file_executor_sha256, create_file_schema, CREATE_FILE_EXECUTOR_PROFILE,
        CREATE_FILE_MAX_CONTENT,
    };
    let mut fixture = Fixture::new(ALLOW);
    let workspace = fixture.dir.path().join("create-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let schema_sha256 = agentfw::native::canonical_digest(&create_file_schema());
    let tool_name = "save_artifact";
    let resource_policy = json!({
        "profile":{"server_id":"create-native-fixture","tool_name":tool_name,
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/path","kind":"path",
            "allow_missing_leaf":true}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":create_file_executor_sha256(),"classifier_sha256":"c".repeat(64),
        "allowed_resources":[{"kind":"path","canonical":workspace.join("new.txt")}],
        "execution":{"operation":"create_file","action":"write",
            "max_content_bytes":CREATE_FILE_MAX_CONTENT,"executor_profile":CREATE_FILE_EXECUTOR_PROFILE}
    });
    let policy: agentfw::native::resource::Policy =
        serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name":tool_name,"schema_sha256":schema_sha256,"action_class":"side_effecting",
        "result_provenance":"local_project","egress":[],"resource_policy":resource_policy
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

    fixture.start("write-bound").await;
    let args = json!({"path":"new.txt","content":"exact bound UTF-8 ☃\n"});
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("original-create-id"),
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
        execution: Some(agentfw::native::resource::create_file_binding(&policy, &args).unwrap()),
        network: None,
        post: None,
        windows_read: None,
        macos_read: None,
    };
    let mut body = fixture.event("write-bound", "call");
    body["contract_version"] = json!(agentfw::native::resource::CREATE_CONTRACT);
    body["tool"] = json!(tool_name);
    body["args"] = args.clone();
    body["schema_sha256"] = json!(policy.profile.schema_sha256);
    body["resource_admission"] = serde_json::to_value(admission).unwrap();

    let (status, reply) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["verdict"], "allow", "{reply}");
    assert_eq!(reply["release"], true);
    assert!(reply["binding_sha256"]
        .as_str()
        .is_some_and(agentfw::native::is_digest));
}

#[cfg(unix)]
#[tokio::test]
async fn sou67_create_file_v2_native_operator_bound_nested_schema_admits_and_binds() {
    use agentfw::native::resource::{
        create_file_executor_sha256, CREATE_FILE_EXECUTOR_PROFILE, CREATE_FILE_MAX_CONTENT,
    };
    let mut fixture = Fixture::new(ALLOW);
    let workspace = fixture.dir.path().join("nested-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let tool_name = "publish_blob";
    let schema = json!({
        "type": "object",
        "properties": {
            "spec": {
                "type": "object",
                "properties": {
                    "destination": { "type": "string" },
                    "payload": { "type": "string" }
                },
                "required": ["destination", "payload"],
                "additionalProperties": false
            }
        },
        "required": ["spec"],
        "additionalProperties": false
    });
    let schema_sha256 = agentfw::native::canonical_digest(&schema);
    let resource_policy = json!({
        "profile": {
            "server_id": "nested-native-fixture",
            "tool_name": tool_name,
            "schema_sha256": schema_sha256,
            "selectors": [{
                "pointer": "/spec/destination",
                "kind": "path",
                "allow_missing_leaf": true
            }]
        },
        "workspace": workspace,
        "cwd": workspace,
        "executor_sha256": create_file_executor_sha256(),
        "classifier_sha256": "c".repeat(64),
        "allowed_resources": [{
            "kind": "path",
            "canonical": workspace.join("nested_out.txt")
        }],
        "binding": {
            "contract_version": "sw-native/binding/1",
            "operation": "create_file",
            "action": "write",
            "path_selector": "/spec/destination",
            "content_selector": "/spec/payload",
            "response_contract": "sw-native/response/text/1",
            "executor_profile": CREATE_FILE_EXECUTOR_PROFILE,
            "max_content_bytes": CREATE_FILE_MAX_CONTENT
        }
    });

    let policy: agentfw::native::resource::Policy =
        serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name": tool_name,
        "schema_sha256": schema_sha256,
        "action_class": "side_effecting",
        "result_provenance": "local_project",
        "egress": [],
        "resource_policy": resource_policy
    }));
    let bytes = serde_json::to_vec(&configured).unwrap();
    fixture.registry_sha256 = sha256_hex(&bytes);
    // Explicitly proves that NativeState::from_bytes accepts nested create schema under SOU-67 operator binding.
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

    fixture.start("nested-write").await;
    let args = json!({
        "spec": {
            "destination": "nested_out.txt",
            "payload": "nested create bound content\n"
        }
    });
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("nested-call-1"),
        profile_sha256: agentfw::native::canonical_digest(
            &serde_json::to_value(&policy.profile).unwrap(),
        ),
        executor_sha256: policy.executor_sha256.clone(),
        classifier_sha256: policy.classifier_sha256.clone(),
        snapshot_sha256: "d".repeat(64),
        definition_sha256: "f".repeat(64),
        input_sha256: "a".repeat(64),
        resources: vec![agentfw::mcp::resources::ResourceEvidence {
            pointer: "/spec/destination".into(),
            source: agentfw::mcp::resources::EvidenceSource::Argument,
            resource: policy.allowed_resources[0].clone(),
        }],
        execution: Some(agentfw::native::resource::create_file_binding(&policy, &args).unwrap()),
        network: None,
        post: None,
        windows_read: None,
        macos_read: None,
    };
    let mut body = fixture.event("nested-write", "call");
    body["contract_version"] = json!(agentfw::native::resource::CREATE_CONTRACT);
    body["tool"] = json!(tool_name);
    body["args"] = args.clone();
    body["schema_sha256"] = json!(policy.profile.schema_sha256);
    body["resource_admission"] = serde_json::to_value(admission).unwrap();

    let (status, reply) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["verdict"], "allow", "{reply}");
    assert_eq!(reply["release"], true);
    assert!(reply["binding_sha256"]
        .as_str()
        .is_some_and(agentfw::native::is_digest));

    // Content substitution is denied
    let mut mutated = body.clone();
    mutated["args"]["spec"]["payload"] = json!("substituted payload\n");
    let (mut_status, mut_reply) = fixture.post(&mutated).await;
    assert_eq!(mut_status, StatusCode::OK, "{mut_reply}");
    assert_eq!(mut_reply["verdict"], "deny");
    assert_eq!(mut_reply["release"], false);
    assert_eq!(
        mut_reply["reason_codes"],
        json!(["native_create_binding_mismatch"])
    );
}

#[cfg(unix)]
#[test]
fn sou67_native_parser_rejects_dual_binding_and_execution() {
    use agentfw::native::resource::{Policy, BINDING_CONTRACT, READ_DOCUMENT_EXECUTOR_PROFILE};

    let (_fixture, policy) = create_file_fixture();
    let legacy = serde_json::to_value(&policy).unwrap();

    let mut binding_only = legacy.clone();
    let mut binding = binding_only
        .as_object_mut()
        .unwrap()
        .remove("execution")
        .unwrap();
    binding["contract_version"] = json!(BINDING_CONTRACT);
    binding["path_selector"] = json!("/path");
    binding["content_selector"] = json!("/content");
    binding["response_contract"] = json!("sw-native/response/text/1");
    binding_only["binding"] = binding;

    let load = |resource_policy: &Value| {
        let configured = json!({
            "contract_version": CONTRACT,
            "registry_id": "sou67-authority-parser",
            "tools": [{
                "name": "create_file",
                "schema_sha256": policy.profile.schema_sha256,
                "action_class": "side_effecting",
                "result_provenance": "local_project",
                "egress": [],
                "resource_policy": resource_policy
            }]
        });
        let bytes = serde_json::to_vec(&configured).unwrap();
        NativeState::from_bytes(&bytes, &sha256_hex(&bytes), NATIVE_TOKEN.into())
    };

    // Positive production-parser controls prevent blanket rejection.
    for (label, configured) in [("execution-only", &legacy), ("binding-only", &binding_only)] {
        if let Err(error) = load(configured) {
            panic!("{label} rejected: {error:#}");
        }
        let parsed: Policy = serde_json::from_value(configured.clone()).unwrap();
        assert!(
            parsed.effective_execution().is_some(),
            "{label} lost its execution authority"
        );
    }

    let equivalent = legacy["execution"].clone();

    let mut read_document = equivalent.clone();
    read_document["operation"] = json!("read_document");
    read_document["action"] = json!("read");
    read_document["executor_profile"] = json!(READ_DOCUMENT_EXECUTOR_PROFILE);
    read_document["max_content_bytes"] = json!(MAX_CONTENT);

    let mut unsupported_profile = equivalent.clone();
    unsupported_profile["executor_profile"] = json!("unsupported-executor");

    let mut incompatible_path = equivalent.clone();
    incompatible_path["path_selector"] = json!("/other_path");

    let mut undersized_content = equivalent.clone();
    undersized_content["max_content_bytes"] = json!(1);

    let mut reviewer_witness = read_document.clone();
    reviewer_witness["executor_profile"] = json!("unsupported-executor");
    reviewer_witness["path_selector"] = json!("/other_path");
    reviewer_witness["max_content_bytes"] = json!(1);

    for (label, execution) in [
        ("equivalent", equivalent),
        ("read-document", read_document),
        ("unsupported-profile", unsupported_profile),
        ("incompatible-path", incompatible_path),
        ("undersized-content", undersized_content),
        ("reviewer-witness", reviewer_witness),
    ] {
        let mut dual = binding_only.clone();
        dual["execution"] = execution;

        let parsed: Policy = serde_json::from_value(dual.clone()).unwrap();
        assert!(
            parsed.effective_execution().is_none(),
            "{label}: silently selected a dual authority"
        );

        let error = match load(&dual) {
            Ok(_) => panic!("{label}: production parser accepted dual authority"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "conflicting operator execution policies",
            "{label}: rejected for an unrelated reason"
        );
    }

    // Registry parsing must never execute the configured operation.
    assert!(!policy.workspace.join("new.txt").exists());
}
