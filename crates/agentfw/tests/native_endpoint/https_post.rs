// SPDX-License-Identifier: Apache-2.0

use super::*;

fn https_post_fixture(firewall_policy: &str) -> (Fixture, agentfw::native::resource::Policy) {
    let mut fixture = Fixture::new(firewall_policy);
    let workspace = fixture.dir.path().canonicalize().unwrap();
    let schema_sha256 =
        agentfw::native::canonical_digest(&agentfw::native::resource::https_post_schema());
    let resource_policy = json!({
        "profile":{"server_id":"https-native-fixture","tool_name":"https_post",
            "schema_sha256":schema_sha256,"selectors":[{"pointer":"/url","kind":"url"}]},
        "workspace":workspace,"cwd":workspace,
        "executor_sha256":agentfw::mcp::https_post::executor_profile_sha256(),
        "classifier_sha256":"c".repeat(64),
        "allowed_resources":[url_resource(HTTPS_NATIVE_URL)["resource"]],
        "post":{"endpoint":{"exact_url":HTTPS_NATIVE_URL,"approved_addresses":["93.184.216.34"],
            "private_endpoint":null,"root_certificate_pem":null},"content_type":"text/plain","max_body_bytes":4096}
    });
    let policy = serde_json::from_value(resource_policy.clone()).unwrap();
    let mut configured = registry();
    configured["tools"].as_array_mut().unwrap().push(json!({
        "name":"https_post","schema_sha256":schema_sha256,"action_class":"network",
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

#[test]
fn https_post_rejects_other_operator_authorities_after_main_integration() {
    use agentfw::native::resource::{
        Policy, BINDING_CONTRACT, WINDOWS_READ_EXECUTOR_PROFILE, WINDOWS_READ_MAX_CONTENT,
    };
    let (_fixture, policy) = https_post_fixture("");
    let original = serde_json::to_value(&policy).unwrap();
    let execution = json!({"operation":"create_file", "action":"write",
        "max_content_bytes":agentfw::native::resource::CREATE_FILE_MAX_CONTENT,
        "executor_profile":agentfw::native::resource::CREATE_FILE_EXECUTOR_PROFILE});
    let mut binding = execution.clone();
    binding["contract_version"] = json!(BINDING_CONTRACT);
    binding["path_selector"] = json!("/path");
    binding["content_selector"] = json!("/content");
    binding["response_contract"] = json!("sw-native/response/text/1");
    let load = |resource_policy: Value| {
        let configured = json!({"contract_version": CONTRACT, "registry_id":"post-authority-integration",
            "tools":[{"name":"https_post", "schema_sha256":policy.profile.schema_sha256,
                "action_class":"network", "result_provenance":"untrusted",
                "egress":[{"pointer":"/url","kind":"url_host","optional":false}],
                "resource_policy":resource_policy}]});
        let bytes = serde_json::to_vec(&configured).unwrap();
        NativeState::from_bytes(&bytes, &sha256_hex(&bytes), NATIVE_TOKEN.into())
    };
    assert!(load(original.clone()).is_ok());
    for (field, authority) in [
        ("binding", binding),
        ("execution", execution),
        ("network", original["post"]["endpoint"].clone()),
        (
            "windows_read",
            json!({"executor_profile":WINDOWS_READ_EXECUTOR_PROFILE,
            "max_content_bytes":WINDOWS_READ_MAX_CONTENT}),
        ),
    ] {
        let mut dual = original.clone();
        dual[field] = authority;
        let parsed: Policy = serde_json::from_value(dual.clone()).unwrap();
        assert!(
            agentfw::native::resource::https_post_binding(
                &parsed,
                &json!({"url":HTTPS_NATIVE_URL,"body":"fixture"})
            )
            .is_err(),
            "{field}"
        );
        let error = match load(dual) {
            Ok(_) => panic!("accepted POST plus {field}"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "conflicting operator execution policies",
            "{field}"
        );
    }
}

fn https_post_call(
    fixture: &Fixture,
    policy: &agentfw::native::resource::Policy,
    session: &str,
) -> Value {
    let args =
        json!({"url":policy.post.as_ref().unwrap().endpoint.exact_url, "body":"exact UTF-8 body"});
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
        network: None,
        post: Some(agentfw::native::resource::https_post_binding(policy, &args).unwrap()),
        windows_read: None,
        macos_read: None,
    };
    let mut body = fixture.event(session, "call");
    body["contract_version"] = json!(agentfw::native::resource::POST_CONTRACT);
    body["tool"] = json!("https_post");
    body["args"] = args;
    body["schema_sha256"] = json!(policy.profile.schema_sha256);
    body["resource_admission"] = serde_json::to_value(admission).unwrap();
    body
}

fn https_post_result(
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
        "https_post",
        &request["args"],
        kind,
        &content,
    );
    body["contract_version"] = json!(agentfw::native::resource::POST_CONTRACT);
    body["delivery"] = json!("mcp_host");
    body
}

#[tokio::test]
async fn https_post_v6_binds_payload_and_single_use_result() {
    let (fixture, policy) = https_post_fixture(HTTPS_ALLOW);
    fixture.start("post-one").await;
    fixture.start("post-two").await;
    let request = https_post_call(&fixture, &policy, "post-one");
    for (pointer, value) in [
        ("/args/body", json!("different body")),
        ("/args/url", json!("https://fixture.example/substituted")),
        ("/resource_admission/post/method", json!("GET")),
        (
            "/resource_admission/post/content_type",
            json!("application/json"),
        ),
        ("/resource_admission/post/body_bytes", json!(0)),
        (
            "/resource_admission/post/body_sha256",
            json!("e".repeat(64)),
        ),
        (
            "/resource_admission/post/authority_sha256",
            json!("e".repeat(64)),
        ),
        (
            "/resource_admission/post/policy_sha256",
            json!("e".repeat(64)),
        ),
        ("/resource_admission/executor_sha256", json!("e".repeat(64))),
        ("/resource_admission/profile_sha256", json!("e".repeat(64))),
    ] {
        let mut changed = request.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let (_, denied) = fixture.post(&changed).await;
        assert_ne!(denied["release"], true, "{pointer}: {denied}");
    }
    let (status, allowed) = fixture.post(&request).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["release"], true, "{allowed}");
    let mut result = https_post_result(
        &fixture,
        &request,
        &allowed,
        &json!("original-https-id"),
        "value",
        "received",
    );
    result["session_id"] = json!("post-two");
    let (_, denied) = fixture.post(&result).await;
    assert_ne!(denied["release"], true);
    result["session_id"] = json!("post-one");
    let (_, released) = fixture.post(&result).await;
    assert_eq!(released["release"], true, "{released}");
    let (_, replay) = fixture.post(&result).await;
    assert_ne!(replay["release"], true);
}

#[tokio::test]
async fn https_post_v6_native_ask_deny_and_egress_floors() {
    for (firewall, verdict) in [
        (
            "agent_policies: []\negress_allowlist: []\ndefault: allow\n",
            "deny",
        ),
        (
            "agent_policies: []\negress_allowlist: [fixture.example]\ndefault: ask\n",
            "ask",
        ),
        (
            "agent_policies: []\negress_allowlist: [fixture.example]\ndefault: deny\n",
            "deny",
        ),
    ] {
        let (fixture, policy) = https_post_fixture(firewall);
        fixture.start("post-floor").await;
        let (_, reply) = fixture
            .post(&https_post_call(&fixture, &policy, "post-floor"))
            .await;
        assert_eq!(reply["release"], false, "{reply}");
        assert_eq!(reply["verdict"], verdict, "{reply}");
    }
}

#[tokio::test]
async fn https_post_v6_recomputed_authority_cannot_replace_operator_policy() {
    let (fixture, policy) = https_post_fixture(HTTPS_ALLOW);
    fixture.start("post-policy").await;
    let request = https_post_call(&fixture, &policy, "post-policy");
    for field in ["address", "content_type", "selector", "classifier"] {
        let mut replacement = policy.clone();
        match field {
            "address" => {
                replacement
                    .post
                    .as_mut()
                    .unwrap()
                    .endpoint
                    .approved_addresses = vec!["93.184.216.35".parse().unwrap()]
            }
            "content_type" => {
                replacement.post.as_mut().unwrap().content_type = "application/json".into()
            }
            "selector" => replacement.profile.selectors[0].pointer = "/body".into(),
            _ => replacement.classifier_sha256 = "b".repeat(64),
        }
        let mut forged = request.clone();
        if field == "content_type" {
            forged["args"]["body"] = json!("{} ");
        }
        forged["resource_admission"]["post"] = serde_json::to_value(
            agentfw::native::resource::https_post_binding(&replacement, &forged["args"]).unwrap(),
        )
        .unwrap();
        let (_, refused) = fixture.post(&forged).await;
        assert_eq!(refused["release"], false, "{field}: {refused}");
    }
    for version in [
        agentfw::native::resource::CONTRACT,
        agentfw::native::resource::NETWORK_CONTRACT,
    ] {
        let mut downgrade = request.clone();
        downgrade["contract_version"] = json!(version);
        let (_, refused) = fixture.post(&downgrade).await;
        assert_ne!(refused["release"], true, "{refused}");
    }
    let (_, allowed) = fixture.post(&request).await;
    assert_eq!(allowed["release"], true, "{allowed}");
}
