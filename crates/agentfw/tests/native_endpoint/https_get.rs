// SPDX-License-Identifier: Apache-2.0

use super::*;

// This fixture only exercises daemon authorization. No resolver, socket or HTTP
// client runs, and the synthetic approved address is never contacted.
fn https_get_fixture(firewall_policy: &str) -> (Fixture, agentfw::native::resource::Policy) {
    let mut fixture = Fixture::new(firewall_policy);
    let workspace = fixture.dir.path().canonicalize().unwrap();
    let schema_sha256 =
        agentfw::native::canonical_digest(&agentfw::native::resource::https_get_schema());
    let resource_policy = json!({
        "profile":{"server_id":"https-native-fixture","tool_name":"https_get",
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/url","kind":"url"}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":agentfw::mcp::https_get::executor_profile_sha256(),
        "classifier_sha256":"c".repeat(64),
        "allowed_resources":[url_resource(HTTPS_NATIVE_URL)["resource"]],
        "network":{"exact_url":HTTPS_NATIVE_URL,"approved_addresses":["93.184.216.34"],
            "private_endpoint":null,"root_certificate_pem":null}
    });
    let policy = serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name":"https_get","schema_sha256":schema_sha256,"action_class":"network",
        "result_provenance":"untrusted",
        "egress":[{"pointer":"/url","kind":"url_host","optional":false}],
        "resource_policy":resource_policy
    }));
    let bytes = serde_json::to_vec(&configured).unwrap();
    fixture.registry_sha256 = sha256_hex(&bytes);
    fixture.state = make_state(
        fixture.dir.path(),
        Config {
            enforce: true,
            ..Config::default()
        },
        firewall_policy,
        &bytes,
        &fixture.registry_sha256,
    );
    (fixture, policy)
}

fn https_get_call(
    fixture: &Fixture,
    policy: &agentfw::native::resource::Policy,
    session: &str,
) -> Value {
    let args = json!({"url":policy.network.as_ref().unwrap().exact_url});
    let admission = agentfw::native::resource::Admission {
        server_id: policy.profile.server_id.clone(),
        host_call_id: json!("original-https-id"),
        profile_sha256: agentfw::native::canonical_digest(
            &serde_json::to_value(&policy.profile).unwrap(),
        ),
        executor_sha256: policy.executor_sha256.clone(),
        classifier_sha256: policy.classifier_sha256.clone(),
        snapshot_sha256: "d".repeat(64),
        definition_sha256: "f".repeat(64),
        input_sha256: "a".repeat(64),
        resources: vec![agentfw::mcp::resources::ResourceEvidence {
            pointer: "/url".into(),
            source: agentfw::mcp::resources::EvidenceSource::Argument,
            resource: policy.allowed_resources[0].clone(),
        }],
        execution: None,
        network: Some(agentfw::native::resource::https_get_binding(policy, &args).unwrap()),
        post: None,
        windows_read: None,
        macos_read: None,
    };
    let mut body = fixture.event(session, "call");
    body["contract_version"] = json!(agentfw::native::resource::NETWORK_CONTRACT);
    body["tool"] = json!("https_get");
    body["args"] = args;
    body["schema_sha256"] = json!(policy.profile.schema_sha256);
    body["resource_admission"] = serde_json::to_value(admission).unwrap();
    body
}

fn https_get_result(
    fixture: &Fixture,
    request: &Value,
    admitted: &Value,
    host_id: &Value,
    kind: &str,
    text: &str,
) -> Value {
    let content = json!({"jsonrpc":"2.0","id":host_id,
        "result":{"isError":kind == "error","content":[{"type":"text","text":text}]}})
    .to_string();
    let mut body = fixture.result(
        request["session_id"].as_str().unwrap(),
        admitted,
        "https_get",
        &request["args"],
        kind,
        &content,
    );
    body["contract_version"] = json!(agentfw::native::resource::NETWORK_CONTRACT);
    body["delivery"] = json!("mcp_host");
    body
}

fn sou83_original_write_fixture() -> (Fixture, Value) {
    let pinned: Value = serde_json::from_str(include_str!(
        "../../../../profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json"
    ))
    .unwrap();
    let write = pinned["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "write_file")
        .unwrap();
    let digest = agentfw::native::canonical_digest(&write["inputSchema"]);
    let format = "sw-mcp/filesystem-create-only/1";
    let registry = json!({
        "contract_version": CONTRACT,
        "registry_id": "filesystem-create-only-v1",
        "tools": [{
            "name":"write_file",
            "schema_sha256":digest,
            "action_class":"side_effecting",
            "result_provenance":"untrusted",
            "egress":[],
            "mcp_result_profile":format
        }]
    });
    let mut fixture = Fixture::new(ALLOW);
    let bytes = serde_json::to_vec(&registry).unwrap();
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
    (fixture, registry)
}

#[tokio::test]
async fn sou83_original_write_policy_transition_spends_old_authority_and_recovers() {
    for verdict in ["deny", "ask"] {
        let (fixture, registry) = sou83_original_write_fixture();
        let activate = |sequence, text: &str| {
            fixture
                .state
                .firewall
                .lock()
                .unwrap()
                .activate_managed_policy(
                    AgentPolicySet::from_yaml(text).unwrap(),
                    format!("sou83-revision-{sequence}"),
                    sequence,
                    sha256_hex(text.as_bytes()),
                );
        };
        activate(1, ALLOW);
        let mut start = fixture.event("sou83-policy", "session_start");
        start["policy_transition"] = json!(agentfw::policy_transition::CONTRACT);
        let (status, started) = fixture.post(&start).await;
        assert_allow(status, &started);
        let args = json!({"path":"/workspace/epoch.txt","content":"exact epoch bytes"});
        let mut call = fixture.call("sou83-policy", "write_file", &args);
        call["schema_sha256"] = registry["tools"][0]["schema_sha256"].clone();
        call["mcp_host_call_id"] = json!("epoch-before");
        let (status, old) = fixture.post(&call).await;
        assert_allow(status, &old);
        let original = |id: &str| {
            json!({"jsonrpc":"2.0","id":id,"result":{
            "content":[{"type":"text","text":"Successfully wrote"}],
            "structuredContent":{"content":"Successfully wrote"}}})
            .to_string()
        };
        let mut result = fixture.result(
            "sou83-policy",
            &old,
            "write_file",
            &args,
            "value",
            &original("epoch-before"),
        );
        result["delivery"] = json!("mcp_host");
        let changed = format!("default: allow\nagent_policies:\n  - name: changed-create\n    when: {{min_action_class: side_effecting}}\n    action: {verdict}\n");
        activate(2, &changed);
        let (status, refused) = fixture.post(&result).await;
        assert_eq!(status, StatusCode::OK, "{refused}");
        assert_eq!(refused["release"], false, "{refused}");
        assert_eq!(refused["verdict"], verdict);
        assert!(refused["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("native_policy_transition_result_refused")));
        let (_, spent) = fixture.post(&result).await;
        assert_eq!(spent["error_code"], "native_call_unknown_or_spent");
        call["mcp_host_call_id"] = json!("epoch-denied");
        let (_, blocked) = fixture.post(&call).await;
        assert_eq!(blocked["release"], false, "{blocked}");
        activate(3, ALLOW);
        // Restoring policy must not resurrect an already-spent grant.
        let (_, still_spent) = fixture.post(&result).await;
        assert_eq!(still_spent["error_code"], "native_call_unknown_or_spent");
        call["mcp_host_call_id"] = json!("epoch-after");
        let (status, fresh) = fixture.post(&call).await;
        assert_allow(status, &fresh);
        assert_ne!(fresh["call_id"], old["call_id"]);
        let mut continued = fixture.result(
            "sou83-policy",
            &fresh,
            "write_file",
            &args,
            "value",
            &original("epoch-after"),
        );
        continued["delivery"] = json!("mcp_host");
        let (status, released) = fixture.post(&continued).await;
        assert_eq!(status, StatusCode::OK, "{released}");
        assert_eq!(released["release"], true, "{released}");
        assert!(
            !fixture.dir.path().join("epoch.txt").exists(),
            "native admission alone must never publish original-create bytes"
        );
    }
}

#[tokio::test]
async fn sou83_original_write_reused_native_result_authority_is_spent_and_peer_continues() {
    let (fixture, registry) = sou83_original_write_fixture();
    fixture.start("sou83-spent-native").await;

    let args = json!({"path":"/workspace/approved.txt","content":"known approved bytes"});
    let mut call = fixture.call("sou83-spent-native", "write_file", &args);
    call["schema_sha256"] = registry["tools"][0]["schema_sha256"].clone();
    // Selected original MCP tools bind the exact host JSON-RPC ID at native call admission.
    call["mcp_host_call_id"] = json!("create-one");
    let (status, admitted) = fixture.post(&call).await;
    assert_allow(status, &admitted);
    let original = json!({"jsonrpc":"2.0","id":"create-one","result":{
        "content":[{"type":"text","text":"Successfully wrote"}],
        "structuredContent":{"content":"Successfully wrote"}
    }})
    .to_string();
    let mut result = fixture.result(
        "sou83-spent-native",
        &admitted,
        "write_file",
        &args,
        "value",
        &original,
    );
    // The selected native result contract is closed: no expected_* fields.
    result["delivery"] = json!("mcp_host");
    let (status, allowed) = fixture.post(&result).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["release"], true, "{allowed}");
    let (status, replay) = fixture.post(&result).await;
    assert_failure(status, &replay, StatusCode::CONFLICT);
    assert_eq!(replay["error_code"], "native_call_unknown_or_spent");

    let mut tampered = result.clone();
    tampered["content"] = json!(original.replace("Successfully wrote", "TAMPERED"));
    let (status, denied) = fixture.post(&tampered).await;
    assert_failure(status, &denied, StatusCode::CONFLICT);
    assert_eq!(denied["error_code"], "native_call_unknown_or_spent");

    let mut followup = fixture.call(
        "sou83-spent-native",
        "write_file",
        &json!({"path":"/workspace/other.txt","content":"another authorized call"}),
    );
    followup["schema_sha256"] = registry["tools"][0]["schema_sha256"].clone();
    followup["mcp_host_call_id"] = json!("create-two");
    let (status, continued) = fixture.post(&followup).await;
    assert_allow(status, &continued);
    assert_ne!(continued["call_id"], admitted["call_id"]);

    // A mismatch on an unused original-create receipt must fail and spend
    // that receipt, not just fail because the first successful call was spent.
    for mismatch in ["target", "content", "host"] {
        let host_id = format!("create-binding-{mismatch}");
        let mut request = call.clone();
        request["mcp_host_call_id"] = json!(host_id);
        let (status, grant) = fixture.post(&request).await;
        assert_allow(status, &grant);
        let original = json!({"jsonrpc":"2.0","id":host_id,"result":{
            "content":[{"type":"text","text":"Successfully wrote"}],
            "structuredContent":{"content":"Successfully wrote"}
        }})
        .to_string();
        let mut valid = fixture.result(
            "sou83-spent-native",
            &grant,
            "write_file",
            &args,
            "value",
            &original,
        );
        valid["delivery"] = json!("mcp_host");
        let mut altered = valid.clone();
        match mismatch {
            "target" => altered["args"]["path"] = json!("/workspace/substituted.txt"),
            "content" => altered["args"]["content"] = json!("substituted bytes"),
            _ => {
                let mut decoded: Value = serde_json::from_str(&original).unwrap();
                decoded["id"] = json!("foreign-host-call");
                altered["content"] = json!(decoded.to_string());
            }
        }
        let (status, denied) = fixture.post(&altered).await;
        assert_failure(status, &denied, StatusCode::CONFLICT);
        assert_eq!(
            denied["error_code"],
            if mismatch == "host" {
                "native_host_call_mismatch"
            } else {
                "native_call_binding_mismatch"
            }
        );
        let (status, replay) = fixture.post(&valid).await;
        assert_failure(status, &replay, StatusCode::CONFLICT);
        assert_eq!(replay["error_code"], "native_call_unknown_or_spent");
    }
}

#[tokio::test]
async fn https_get_v3_native_binds_original_host_session_and_exact_resources() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-one").await;
    fixture.start("https-two").await;
    let request = https_get_call(&fixture, &policy, "https-one");
    let (status, first) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        first["contract_version"],
        agentfw::native::resource::NETWORK_CONTRACT
    );
    assert_eq!(first["release"], true, "{first}");
    assert_eq!(
        first["resources_sha256"],
        agentfw::native::canonical_digest(&request["resource_admission"]["resources"])
    );
    assert!(first["binding_sha256"]
        .as_str()
        .is_some_and(agentfw::native::is_digest));

    let mut other = request.clone();
    other["resource_admission"]["host_call_id"] = json!(57);
    let (_, second) = fixture.post(&other).await;
    assert_eq!(second["release"], true, "{second}");
    assert_ne!(first["binding_sha256"], second["binding_sha256"]);
    other = request.clone();
    other["session_id"] = json!("https-two");
    let (_, third) = fixture.post(&other).await;
    assert_eq!(third["release"], true, "{third}");
    assert_ne!(first["binding_sha256"], third["binding_sha256"]);

    let mut result = https_get_result(
        &fixture,
        &request,
        &first,
        &json!("original-https-id"),
        "value",
        "{\"inventory\":7}",
    );
    result["session_id"] = json!("https-two");
    let (status, refused) = fixture.post(&result).await;
    assert_failure(status, &refused, StatusCode::CONFLICT);
    assert_eq!(refused["error_code"], "native_call_unknown_or_spent");
    result["session_id"] = json!("https-one");
    let (status, released) = fixture.post(&result).await;
    assert_eq!(status, StatusCode::OK, "{released}");
    assert_eq!(released["release"], true);
    assert_eq!(released["binding_sha256"], first["binding_sha256"]);
    assert_eq!(
        released["content_sha256"],
        sha256_hex(result["content"].as_str().unwrap().as_bytes())
    );
    let (status, replay) = fixture.post(&result).await;
    assert_failure(status, &replay, StatusCode::CONFLICT);
    assert_eq!(replay["error_code"], "native_call_unknown_or_spent");
}

#[tokio::test]
async fn https_get_v3_native_refuses_url_host_port_query_and_argument_substitution() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-url-refusals").await;
    let request = https_get_call(&fixture, &policy, "https-url-refusals");
    for url in [
        "https://other.example/document.json?edition=approved",
        "https://fixture.example:444/document.json?edition=approved",
        "https://fixture.example/other.json?edition=approved",
        "https://fixture.example/document.json?edition=replacement",
        "https://fixture.example/document.json",
        "https://fixture.example/document.json?edition=approved#fragment",
        "http://fixture.example/document.json?edition=approved",
    ] {
        let mut changed = request.clone();
        changed["args"]["url"] = json!(url);
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{url}: {refused}");
        assert_eq!(refused["release"], false, "{url}: {refused}");
        assert_eq!(
            refused["reason_codes"],
            json!(["native_https_url_not_allowed"])
        );
        assert!(refused["call_id"].is_null());
    }
    for extra in ["headers", "body", "method", "credentials"] {
        let mut changed = request.clone();
        changed["args"][extra] = json!("unreviewed");
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{extra}: {refused}");
        assert_eq!(refused["release"], false);
        assert!(refused["call_id"].is_null());
    }
    let (_, continued) = fixture.post(&request).await;
    assert_eq!(continued["release"], true, "{continued}");
}

#[tokio::test]
async fn https_get_v3_native_refuses_recomputed_address_and_policy_authority() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-authority-refusals").await;
    let request = https_get_call(&fixture, &policy, "https-authority-refusals");
    let args = &request["args"];
    let mut changed_address = serde_json::to_value(&policy).unwrap();
    changed_address["network"]["approved_addresses"] = json!(["93.184.216.35"]);
    let changed_address: agentfw::native::resource::Policy =
        serde_json::from_value(changed_address).unwrap();
    let mut changed_policy = policy.clone();
    changed_policy.classifier_sha256 = "b".repeat(64);
    let mut changed_trust = policy.clone();
    // A parseable owned certificate is enough for a no-network authority test;
    // the executor's handshake tests establish CA/hostname/expiry behavior.
    changed_trust.network.as_mut().unwrap().root_certificate_pem =
        Some(include_str!("../../../proxy/tests/fixtures/saml/local-idp-cert.pem").to_owned());
    let mut changed_private = serde_json::to_value(&changed_trust).unwrap();
    changed_private["network"]["approved_addresses"] = json!(["127.0.0.1"]);
    changed_private["network"]["private_endpoint"] = json!({
        "host":"fixture.example","port":443,"address":"127.0.0.1"});
    let changed_private: agentfw::native::resource::Policy =
        serde_json::from_value(changed_private).unwrap();
    for changed in [
        &changed_address,
        &changed_policy,
        &changed_trust,
        &changed_private,
    ] {
        let mut forged = request.clone();
        forged["resource_admission"]["network"] = serde_json::to_value(
            agentfw::native::resource::https_get_binding(changed, args).unwrap(),
        )
        .unwrap();
        assert_ne!(
            forged["resource_admission"]["network"],
            request["resource_admission"]["network"]
        );
        let (status, refused) = fixture.post(&forged).await;
        assert_eq!(status, StatusCode::OK, "{refused}");
        assert_eq!(refused["release"], false);
        assert_eq!(
            refused["reason_codes"],
            json!(["native_https_binding_mismatch"])
        );
        assert!(refused["call_id"].is_null());
    }
    for field in ["policy_sha256", "args_sha256", "authority_sha256"] {
        let mut changed = request.clone();
        changed["resource_admission"]["network"][field] = json!("b".repeat(64));
        let (_, refused) = fixture.post(&changed).await;
        assert_eq!(
            refused["reason_codes"],
            json!(["native_https_binding_mismatch"]),
            "{field}: {refused}"
        );
        assert!(refused["call_id"].is_null());
    }
}

#[tokio::test]
async fn https_get_v3_native_refuses_contract_downgrade_and_unknown_network_semantics() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-downshift").await;
    let request = https_get_call(&fixture, &policy, "https-downshift");
    for contract in [
        agentfw::native::resource::CONTRACT,
        agentfw::native::resource::CREATE_CONTRACT,
    ] {
        let mut changed = request.clone();
        changed["contract_version"] = json!(contract);
        let (status, refused) = fixture.post(&changed).await;
        assert_failure(status, &refused, StatusCode::BAD_REQUEST);
        assert_eq!(refused["error_code"], "native_resource_contract_mismatch");
    }
    let mut changed = request.clone();
    changed["contract_version"] = json!(agentfw::native::resource::CONTRACT);
    changed["resource_admission"]
        .as_object_mut()
        .unwrap()
        .remove("network");
    let (status, refused) = fixture.post(&changed).await;
    assert_failure(status, &refused, StatusCode::CONFLICT);
    assert_eq!(refused["error_code"], "native_resource_contract_required");
    changed = request.clone();
    changed["contract_version"] = json!(CONTRACT);
    changed
        .as_object_mut()
        .unwrap()
        .remove("resource_admission");
    let (status, refused) = fixture.post(&changed).await;
    assert_failure(status, &refused, StatusCode::CONFLICT);
    assert_eq!(refused["error_code"], "native_resource_contract_required");
    for (field, value) in [
        ("operation", "post"),
        ("action", "read"),
        ("executor_profile", "unreviewed"),
    ] {
        let mut changed = request.clone();
        changed["resource_admission"]["network"][field] = json!(value);
        let (status, refused) = fixture.post(&changed).await;
        assert_failure(status, &refused, StatusCode::BAD_REQUEST);
        assert_eq!(refused["error_code"], "native_resource_invalid");
    }
    let (_, allowed) = fixture.post(&request).await;
    assert_eq!(allowed["release"], true, "{allowed}");
}

#[tokio::test]
async fn https_get_v3_native_requires_explicit_egress_even_with_default_allow() {
    let (fixture, policy) = https_get_fixture(ALLOW);
    fixture.start("https-no-egress").await;
    let request = https_get_call(&fixture, &policy, "https-no-egress");
    let (status, refused) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["verdict"], "deny");
    assert_eq!(refused["release"], false);
    assert_eq!(
        refused["reason_codes"],
        json!(["native_https_egress_not_allowlisted"])
    );
    assert!(refused["call_id"].is_null());
}

#[tokio::test]
async fn https_get_v3_native_result_wrong_host_or_contract_spends_the_call() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-result-id").await;
    let request = https_get_call(&fixture, &policy, "https-result-id");
    for mismatch in ["host", "contract", "args"] {
        let (_, call) = fixture.post(&request).await;
        assert_eq!(call["release"], true, "{call}");
        let mut result = https_get_result(
            &fixture,
            &request,
            &call,
            &json!("original-https-id"),
            "value",
            "Useful owned document.",
        );
        match mismatch {
            "host" => {
                result["content"] = json!(json!({"jsonrpc":"2.0","id":"substitute",
                "result":{"content":[{"type":"text","text":"Useful owned document."}]}})
                .to_string())
            }
            "contract" => result["contract_version"] = json!(agentfw::native::resource::CONTRACT),
            _ => result["args"]["url"] = json!("https://fixture.example/substitute"),
        }
        let (status, refused) = fixture.post(&result).await;
        assert_failure(status, &refused, StatusCode::CONFLICT);
        assert_eq!(
            refused["error_code"],
            if mismatch == "host" {
                "native_host_call_mismatch"
            } else {
                "native_call_binding_mismatch"
            }
        );
        let corrected = https_get_result(
            &fixture,
            &request,
            &call,
            &json!("original-https-id"),
            "value",
            "Useful owned document.",
        );
        let (status, replay) = fixture.post(&corrected).await;
        assert_failure(status, &replay, StatusCode::CONFLICT);
        assert_eq!(replay["error_code"], "native_call_unknown_or_spent");
    }
}

#[tokio::test]
async fn https_get_v3_native_repeated_refusals_and_errors_preserve_call_capacity() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-capacity").await;
    let request = https_get_call(&fixture, &policy, "https-capacity");
    let mut refused_request = request.clone();
    refused_request["resource_admission"]["network"]["authority_sha256"] = json!("b".repeat(64));
    for _ in 0..70 {
        let (_, refused) = fixture.post(&refused_request).await;
        assert_eq!(refused["release"], false);
        assert!(refused["call_id"].is_null());
        let (_, call) = fixture.post(&request).await;
        assert_eq!(call["release"], true, "{call}");
        let result = https_get_result(
            &fixture,
            &request,
            &call,
            &json!("original-https-id"),
            "error",
            "https_get_timeout",
        );
        let (status, completed) = fixture.post(&result).await;
        assert_eq!(status, StatusCode::OK, "{completed}");
        assert_eq!(completed["release"], true);
    }
    let (_, call) = fixture.post(&request).await;
    let result = https_get_result(
        &fixture,
        &request,
        &call,
        &json!("original-https-id"),
        "value",
        "{\"inventory\":7}",
    );
    let (_, continued) = fixture.post(&result).await;
    assert_eq!(continued["release"], true, "{continued}");
    let (status, ended) = fixture
        .post(&fixture.event("https-capacity", "session_end"))
        .await;
    assert_allow(status, &ended);
    fixture.start("https-capacity").await;
    let (_, restarted) = fixture.post(&request).await;
    assert_eq!(restarted["release"], true);
    assert_ne!(call["binding_sha256"], restarted["binding_sha256"]);
    let (status, stale) = fixture.post(&result).await;
    assert_failure(status, &stale, StatusCode::CONFLICT);
    assert_eq!(stale["error_code"], "native_call_unknown_or_spent");
}

#[tokio::test]
async fn https_get_v3_native_inspects_the_actual_untrusted_result_before_release() {
    let policy_text = "agent_policies:\n  - name: fixture-https-injection\n    when: { detector: injection, facet: tool_result }\n    action: ask\negress_allowlist: [fixture.example]\ndefault: allow\n";
    let (fixture, policy) = https_get_fixture(policy_text);
    fixture.start("https-result-inspection").await;
    let request = https_get_call(&fixture, &policy, "https-result-inspection");
    let (_, call) = fixture.post(&request).await;
    assert_eq!(call["release"], true, "{call}");
    let result = https_get_result(
        &fixture,
        &request,
        &call,
        &json!("original-https-id"),
        "value",
        INJECTION,
    );
    let (status, held) = fixture.post(&result).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held["verdict"], "ask");
    assert_eq!(held["release"], false);
    assert_eq!(
        held["content_sha256"],
        sha256_hex(result["content"].as_str().unwrap().as_bytes())
    );
    let (status, replay) = fixture.post(&result).await;
    assert_failure(status, &replay, StatusCode::CONFLICT);
    assert_eq!(replay["error_code"], "native_call_unknown_or_spent");
    let (_, next) = fixture.post(&request).await;
    assert_eq!(next["release"], true, "{next}");
    let useful = https_get_result(
        &fixture,
        &request,
        &next,
        &json!("original-https-id"),
        "value",
        "Inventory contains seven red widgets.",
    );
    let (status, released) = fixture.post(&useful).await;
    assert_eq!(status, StatusCode::OK, "{released}");
    assert_eq!(released["release"], true);
}

#[test]
fn https_get_v3_native_registry_requires_the_closed_reviewed_profile() {
    let (_fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    let tool = json!({
        "name":"https_get","schema_sha256":policy.profile.schema_sha256,
        "action_class":"network","result_provenance":"untrusted",
        "egress":[{"pointer":"/url","kind":"url_host","optional":false}],
        "resource_policy":policy
    });
    for (pointer, value) in [
        ("/action_class", json!("read_only")),
        ("/result_provenance", json!("local_project")),
        ("/schema_sha256", json!("b".repeat(64))),
        ("/name", json!("generic_fetch")),
        ("/egress", json!([])),
        ("/egress/0/optional", json!(true)),
        ("/egress/0/kind", json!("email_domain")),
        ("/egress/0/pointer", json!("/other_url")),
        (
            "/resource_policy/profile/selectors/0/aliases",
            json!(["/other_url"]),
        ),
        ("/resource_policy/profile/selectors/0/optional", json!(true)),
        (
            "/resource_policy/profile/selectors/0/default",
            json!(HTTPS_NATIVE_URL),
        ),
        ("/resource_policy/profile/selectors/0/kind", json!("domain")),
        (
            "/resource_policy/profile/selectors/0/pointer",
            json!("/other_url"),
        ),
        (
            "/resource_policy/profile/selectors/0/allow_missing_leaf",
            json!(true),
        ),
        ("/resource_policy/executor_sha256", json!("b".repeat(64))),
        (
            "/resource_policy/network/approved_addresses",
            json!(["127.0.0.1"]),
        ),
        (
            "/resource_policy/allowed_resources/0/canonical",
            json!("https://fixture.example/substitute"),
        ),
        ("/resource_policy/allowed_resources/0/port", json!(444)),
        (
            "/resource_policy/allowed_resources/0/host",
            json!("substitute.example"),
        ),
        (
            "/resource_policy/execution",
            json!({"operation":"create_file","action":"write",
            "max_content_bytes":agentfw::native::resource::CREATE_FILE_MAX_CONTENT,
            "executor_profile":agentfw::native::resource::CREATE_FILE_EXECUTOR_PROFILE}),
        ),
    ] {
        let mut changed = tool.clone();
        // Some closed default fields are omitted from serialized policies. Add
        // them to the owned object rather than relying on pointer creation.
        if let Some(target) = changed.pointer_mut(pointer) {
            *target = value;
        } else {
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            changed
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), value);
        }
        let bytes = serde_json::to_vec(&json!({"contract_version":CONTRACT,
            "registry_id":"https-closed-profile","tools":[changed]}))
        .unwrap();
        assert!(
            NativeState::from_bytes(&bytes, &sha256_hex(&bytes), NATIVE_TOKEN.into()).is_err(),
            "accepted unreviewed startup authority at {pointer}"
        );
    }
    let mut unknown = tool;
    unknown["resource_policy"]["network"]["allow_all_private_addresses"] = json!(true);
    let bytes = serde_json::to_vec(&json!({"contract_version":CONTRACT,
        "registry_id":"https-no-unsafe-switch","tools":[unknown]}))
    .unwrap();
    assert!(NativeState::from_bytes(&bytes, &sha256_hex(&bytes), NATIVE_TOKEN.into()).is_err());
}

#[tokio::test]
async fn https_get_v3_native_rechecks_registry_schema_revisions_and_resource_evidence() {
    let (fixture, policy) = https_get_fixture(HTTPS_ALLOW);
    fixture.start("https-evidence").await;
    let request = https_get_call(&fixture, &policy, "https-evidence");
    for (field, value) in [
        ("server_id", json!("different-operator-server")),
        ("profile_sha256", json!("b".repeat(64))),
        ("executor_sha256", json!("b".repeat(64))),
        ("classifier_sha256", json!("b".repeat(64))),
    ] {
        let mut changed = request.clone();
        changed["resource_admission"][field] = value;
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{field}: {refused}");
        assert_eq!(
            refused["reason_codes"],
            json!(["native_resource_revision_mismatch"])
        );
        assert_eq!(refused["release"], false);
        assert!(refused["call_id"].is_null());
    }
    for (field, error) in [
        ("registry_sha256", "native_registry_mismatch"),
        ("schema_sha256", "native_schema_mismatch"),
    ] {
        let mut changed = request.clone();
        changed[field] = json!("b".repeat(64));
        let (status, refused) = fixture.post(&changed).await;
        assert_failure(status, &refused, StatusCode::CONFLICT);
        assert_eq!(refused["error_code"], error);
    }
    for (pointer, value) in [
        (
            "/resource_admission/resources/0/pointer",
            json!("/other_url"),
        ),
        (
            "/resource_admission/resources/0/source",
            json!("reviewed_default"),
        ),
        (
            "/resource_admission/resources/0/resource/host",
            json!("different.example"),
        ),
        ("/resource_admission/resources/0/resource/port", json!(444)),
        (
            "/resource_admission/resources/0/resource/canonical",
            json!("https://fixture.example/document.json?edition=substitute"),
        ),
    ] {
        let mut changed = request.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let (status, refused) = fixture.post(&changed).await;
        assert_eq!(status, StatusCode::OK, "{pointer}: {refused}");
        assert_eq!(
            refused["reason_codes"],
            json!(["native_resource_argument_mismatch"])
        );
        assert_eq!(refused["release"], false);
        assert!(refused["call_id"].is_null());
    }
    let (_, original) = fixture.post(&request).await;
    assert_eq!(original["release"], true, "{original}");
    // A trusted collector's discovery/classification identities are evidence;
    // all three must affect the reservation binding without becoming grants.
    for field in ["snapshot_sha256", "definition_sha256", "input_sha256"] {
        let mut changed = request.clone();
        changed["resource_admission"][field] = json!("b".repeat(64));
        let (_, admitted) = fixture.post(&changed).await;
        assert_eq!(admitted["release"], true, "{field}: {admitted}");
        assert_ne!(original["binding_sha256"], admitted["binding_sha256"]);
    }
}
