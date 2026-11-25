// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn resource_policy_checks_full_url_port_and_path_before_reservation() {
    let permitted = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) = resource_fixture(
        "retrieve_page",
        "/url",
        "url",
        json!([permitted["resource"]]),
    );
    fixture.start("resource-urls").await;
    for url in [
        "http://127.0.0.1:8001/allowed",
        "http://127.0.0.1:8000/other",
    ] {
        let body = resource_call(
            &fixture,
            "resource-urls",
            "retrieve_page",
            json!({"url":url}),
            resource_context(&profile, json!([url_resource(url)])),
        );
        let (status, reply) = fixture.post(&body).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["verdict"], "deny");
        assert_eq!(reply["release"], false);
        assert!(reply["call_id"].is_null());
        assert!(reply["binding_sha256"].is_null());
        assert!(reply.to_string().contains("native_resource_not_allowed"));
    }
    let body = resource_call(
        &fixture,
        "resource-urls",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:8000/allowed"}),
        resource_context(&profile, json!([permitted])),
    );
    let (status, reply) = fixture.post(&body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], true);
    assert_eq!(
        reply["contract_version"],
        agentfw::native::resource::CONTRACT
    );
    assert_eq!(
        reply["resources_sha256"],
        agentfw::native::canonical_digest(&body["resource_admission"]["resources"])
    );
}

#[tokio::test]
async fn resource_policy_checks_mailbox_not_only_its_domain() {
    let evidence = |address: &str| {
        json!({"pointer":"/to","source":"argument","resource":{
        "kind":"recipient","address":address,"domain":"fixture.invalid"}})
    };
    let allowed = evidence("allowed@fixture.invalid");
    let (fixture, profile) = resource_fixture(
        "send_email",
        "/to",
        "recipient",
        json!([allowed["resource"]]),
    );
    fixture.start("resource-mail").await;
    for (address, allow) in [
        ("other@fixture.invalid", false),
        ("allowed@fixture.invalid", true),
    ] {
        let call = resource_call(
            &fixture,
            "resource-mail",
            "send_email",
            json!({"to":address}),
            resource_context(&profile, json!([evidence(address)])),
        );
        let (status, reply) = fixture.post(&call).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["release"], allow);
        if !allow {
            assert!(reply["call_id"].is_null());
        }
    }
}

#[tokio::test]
async fn resource_policy_checks_canonical_path_and_does_not_allow_legacy_downgrade() {
    let mut fixture = Fixture::new(ALLOW);
    let root = fixture.dir.path().canonicalize().unwrap();
    for file in ["allowed.txt", "private.txt"] {
        std::fs::write(root.join(file), "synthetic").unwrap();
    }
    let profile = json!({"server_id":"resource-fixture","tool_name":"read_document","schema_sha256":schema(),
        "selectors":[{"pointer":"/path","kind":"path"}]});
    let mut reg = registry();
    reg["tools"][0]["resource_policy"] = json!({"profile":profile,"workspace":root,"cwd":root,
        "executor_sha256":"e".repeat(64),"classifier_sha256":"c".repeat(64),
        "allowed_resources":[{"kind":"path","canonical":root.join("allowed.txt")} ]});
    let bytes = reg.to_string().into_bytes();
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
    fixture.start("resource-files").await;
    let legacy = fixture.call(
        "resource-files",
        "read_document",
        &json!({"path":"allowed.txt"}),
    );
    let (status, reply) = fixture.post(&legacy).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_resource_contract_required");
    for (file, allow) in [("private.txt", false), ("allowed.txt", true)] {
        let canonical = root.join(file).canonicalize().unwrap();
        let context = resource_context(
            &profile,
            json!([{"pointer":"/path","source":"argument",
            "resource":{"kind":"path","canonical":canonical}}]),
        );
        let body = resource_call(
            &fixture,
            "resource-files",
            "read_document",
            json!({"path":file}),
            context,
        );
        let (status, reply) = fixture.post(&body).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["release"], allow);
    }
}

#[tokio::test]
async fn resource_context_cannot_forge_arguments_revisions_or_untyped_metadata() {
    let permitted = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) = resource_fixture(
        "retrieve_page",
        "/url",
        "url",
        json!([permitted["resource"]]),
    );
    fixture.start("resource-correlations").await;
    let original = resource_call(
        &fixture,
        "resource-correlations",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:8000/allowed"}),
        resource_context(&profile, json!([permitted])),
    );
    for field in ["profile_sha256", "executor_sha256", "classifier_sha256"] {
        let mut body = original.clone();
        body["resource_admission"][field] = json!("b".repeat(64));
        let (status, reply) = fixture.post(&body).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["release"], false);
        assert!(reply["call_id"].is_null());
        assert!(reply
            .to_string()
            .contains("native_resource_revision_mismatch"));
    }
    let mut changed = original.clone();
    changed["args"]["url"] = json!("http://127.0.0.1:8000/other");
    let (status, reply) = fixture.post(&changed).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["release"], false);
    assert!(reply
        .to_string()
        .contains("native_resource_argument_mismatch"));
    for resources in [json!([]), json!([1]), json!([{"kind":"not-a-resource"}])] {
        let mut body = original.clone();
        body["resource_admission"]["resources"] = resources;
        let (status, reply) = fixture.post(&body).await;
        assert_failure(status, &reply, StatusCode::BAD_REQUEST);
    }
    let mut legacy = fixture.call("resource-correlations", "retrieve_page", &original["args"]);
    legacy["resources"] = json!([1]);
    let (status, reply) = fixture.post(&legacy).await;
    assert_failure(status, &reply, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn denied_resource_calls_leave_capacity_for_a_useful_authorized_call() {
    let allowed = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) =
        resource_fixture("retrieve_page", "/url", "url", json!([allowed["resource"]]));
    fixture.start("resource-capacity").await;
    let denied = resource_call(
        &fixture,
        "resource-capacity",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:9000/no"}),
        resource_context(&profile, json!([url_resource("http://127.0.0.1:9000/no")])),
    );
    for _ in 0..70 {
        let (status, reply) = fixture.post(&denied).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["release"], false);
        assert!(reply["call_id"].is_null());
    }
    let permitted = resource_call(
        &fixture,
        "resource-capacity",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:8000/allowed"}),
        resource_context(&profile, json!([allowed])),
    );
    let (status, reply) = fixture.post(&permitted).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], true);
}

#[tokio::test]
async fn resource_call_binding_covers_original_identity_and_rejects_result_downgrade() {
    let allowed = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) =
        resource_fixture("retrieve_page", "/url", "url", json!([allowed["resource"]]));
    fixture.start("resource-bindings").await;
    let request = resource_call(
        &fixture,
        "resource-bindings",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:8000/allowed"}),
        resource_context(&profile, json!([allowed])),
    );
    let (_, first) = fixture.post(&request).await;
    assert_eq!(first["release"], true);
    let mut changed = request.clone();
    changed["resource_admission"]["host_call_id"] = json!("different-host-id");
    let (_, second) = fixture.post(&changed).await;
    assert_eq!(second["release"], true);
    assert_ne!(first["binding_sha256"], second["binding_sha256"]);
    let mut result = fixture.result(
        "resource-bindings",
        &first,
        "retrieve_page",
        &request["args"],
        "value",
        "synthetic response",
    );
    let (status, reply) = fixture.post(&result).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    result["contract_version"] = json!(agentfw::native::resource::CONTRACT);
    let (status, reply) = fixture.post(&result).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_call_unknown_or_spent");
    result["call_id"] = second["call_id"].clone();
    let (status, reply) = fixture.post(&result).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], true);
    assert_eq!(
        reply["contract_version"],
        agentfw::native::resource::CONTRACT
    );
}

#[tokio::test]
async fn resource_result_must_keep_the_bound_original_host_id() {
    let allowed = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) =
        resource_fixture("retrieve_page", "/url", "url", json!([allowed["resource"]]));
    fixture.start("resource-host-id").await;
    let args = json!({"url":"http://127.0.0.1:8000/allowed"});
    let request = resource_call(
        &fixture,
        "resource-host-id",
        "retrieve_page",
        args.clone(),
        resource_context(&profile, json!([allowed])),
    );
    for (id, expected) in [("wrong-host-id", false), ("original-host-id", true)] {
        let (_, call) = fixture.post(&request).await;
        assert_eq!(call["release"], true);
        let content = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"synthetic"}]}}).to_string();
        let mut result = fixture.result(
            "resource-host-id",
            &call,
            "retrieve_page",
            &args,
            "value",
            &content,
        );
        result["contract_version"] = json!(agentfw::native::resource::CONTRACT);
        result["delivery"] = json!("mcp_host");
        let (status, reply) = fixture.post(&result).await;
        assert_eq!(reply["release"], expected, "{reply}");
        if expected {
            assert_eq!(status, StatusCode::OK);
        } else {
            assert_eq!(reply["error_code"], "native_host_call_mismatch");
        }
    }
}

#[tokio::test]
async fn resource_metadata_respects_the_configured_record_byte_cap() {
    let allowed = url_resource("http://127.0.0.1:8000/allowed");
    let (mut fixture, profile) =
        resource_fixture("retrieve_page", "/url", "url", json!([allowed["resource"]]));
    Arc::get_mut(&mut fixture.state)
        .unwrap()
        .config
        .max_record_bytes = 128;
    fixture.start("resource-record-cap").await;
    let request = resource_call(
        &fixture,
        "resource-record-cap",
        "retrieve_page",
        json!({"url":"http://127.0.0.1:8000/allowed"}),
        resource_context(&profile, json!([allowed])),
    );
    let (status, reply) = fixture.post(&request).await;
    assert_failure(status, &reply, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply["error_code"], "native_record_over_cap");
}
