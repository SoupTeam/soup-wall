// SPDX-License-Identifier: Apache-2.0
use super::*;

fn discovered(description: &str) -> (NativeState, Value, Value) {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/mcp_inputs/nested_schema.json"
    ))
    .unwrap();
    let registry = json!({"contract_version":CONTRACT,"registry_id":"sou11-fixture","tools":[
        {"name":"inventory_lookup","schema_sha256":sha(canonical(&schema).to_string().as_bytes()),
            "action_class":"read_only","result_provenance":"untrusted","egress":[]}]});
    let bytes = registry.to_string().into_bytes();
    let native =
        NativeState::from_bytes(&bytes, &sha(&bytes), "fixture-token-1234567890".into()).unwrap();
    let result = json!({"tools":[{"name":"inventory_lookup","description":description,
        "inputSchema":schema,"annotations":{"title":"Synthetic","readOnlyHint":true}}]});
    (native, result, json!({"name":"fixture","version":"1"}))
}

struct UnreadStream(Arc<std::sync::atomic::AtomicUsize>);

impl tokio::io::AsyncRead for UnreadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}
impl AsyncBufRead for UnreadStream {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(&[]))
    }
    fn consume(self: Pin<&mut Self>, _: usize) {}
}

fn explicit_stream_config(server: &wiremock::MockServer) -> AdmissionCfg {
    let (native, _, _) = discovered("fixture");
    AdmissionCfg {
        host_session: None,
        child_authority: None,
        daemon_url: format!("{}/native/v1", server.uri()),
        manifest_url: format!("{}/mcp", server.uri()),
        manifest_token: "fixture".into(),
        server_id: "filesystem".into(),
        native,
        command: "deliberately-unselected-command".into(),
        args: Vec::new(),
        classifier: None,
        resource_profiles: BTreeMap::new(),
        approval: None,
        liveness_url: None,
        liveness_lease_seconds: None,
    }
}

fn unused_stream_profile() -> super::super::server_profile::ProfileConfig {
    super::super::server_profile::ProfileConfig {
        format: super::super::server_profile::FORMAT.into(),
        workspace: "/workspace".into(),
        workspace_identity: None,
        linked_worktree: None,
        filesystem_roots: None,
        workspace_snapshot: None,
        runtime_path: "/never-opened/runtime".into(),
        runtime_sha256: "a".repeat(64),
        package_root: "/never-opened/package".into(),
        package_tree_sha256: "b".repeat(64),
        bwrap_path: "/never-opened/bwrap".into(),
        bwrap_sha256: "c".repeat(64),
        libraries: Vec::new(),
        git: None,
        git_launcher: None,
    }
}

#[tokio::test]
async fn sou155_cancelled_owned_stream_never_enrolls_or_reads() {
    let server = wiremock::MockServer::start().await;
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let error = run_selected_streams(
        explicit_stream_config(&server),
        unused_stream_profile(),
        None,
        UnreadStream(reads.clone()),
        tokio::io::sink(),
        std::future::ready(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "native_mcp_terminated");
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn sou155_owned_streams_refuse_auth_before_reading_or_launching() {
    use wiremock::{
        matchers::{method, path},
        Mock, ResponseTemplate,
    };
    let server = wiremock::MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/native/v1"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let error = run_selected_streams(
        explicit_stream_config(&server),
        unused_stream_profile(),
        None,
        UnreadStream(reads.clone()),
        tokio::io::sink(),
        std::future::pending::<()>(),
    )
    .await
    .unwrap_err();
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(error.to_string().contains("401"));
}

#[tokio::test]
async fn sou155_owned_streams_close_exact_session_after_startup_refusal() {
    use wiremock::{
        matchers::{method, path},
        Mock, Request, ResponseTemplate,
    };
    let server = wiremock::MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/native/v1"))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({
                "contract_version": CONTRACT, "registry_sha256": body["registry_sha256"],
                "session_id": body["session_id"], "event": body["event"],
                "verdict":"allow", "enforced":true, "release":true,
                "call_id":null, "binding_sha256":null, "content_sha256":null,
                "reason_codes":[],
            }))
        })
        .expect(4)
        .mount(&server)
        .await;
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..2 {
        let error = run_selected_streams(
            explicit_stream_config(&server),
            unused_stream_profile(),
            None,
            UnreadStream(reads.clone()),
            tokio::io::sink(),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "MCP command differs from selected runtime"
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let requests = server.received_requests().await.unwrap();
    let rows = requests
        .iter()
        .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 4);
    for pair in rows.as_chunks::<2>().0 {
        assert_eq!(pair[0]["event"], "session_start");
        assert_eq!(pair[1]["event"], "session_end");
        assert_eq!(pair[0]["session_id"], pair[1]["session_id"]);
    }
    assert_ne!(rows[0]["session_id"], rows[2]["session_id"]);
}

#[test]
fn original_discovery_schema_and_annotations_are_retained() {
    let (native, result, info) = discovered("fixture description");
    let (_, snapshot) = manifest(&result, &native, &info, None).unwrap();
    let tool = &snapshot.tools["inventory_lookup"];
    assert_eq!(tool.definition, result["tools"][0]);
    assert_eq!(tool.schema, result["tools"][0]["inputSchema"]);
    assert_eq!(snapshot.server_info, info);
    assert_eq!(tool.description, "fixture description");
    let mut invocation = Invocation {
        server_id: "selected-local-server".into(),
        host_call_id: json!("original-id"),
        registry_sha256: "trusted-registry".into(),
        snapshot_sha256: snapshot.sha256.clone(),
        schema_sha256: tool.schema_sha256.clone(),
        tool: "inventory_lookup".into(),
        description: tool.description.clone(),
        schema: tool.schema.clone(),
        definition: tool.definition.clone(),
        server_info: info,
        definition_sha256: tool.definition_sha256.clone(),
        input_sha256: "input".into(),
        classifier_revision: Some("revision".into()),
        args: json!({"query":{"names":[],"limit":1}}),
        baseline: ActionClass::ReadOnly,
    };
    let semantic = invocation.semantic_input();
    assert_eq!(semantic["raw_arguments"], invocation.args);
    assert_eq!(
        semantic,
        json!({"tool_name":"inventory_lookup","raw_arguments":invocation.args,
        "tool_description":tool.description,"tool_schema":tool.schema,"server_id":"selected-local-server"})
    );
    invocation.host_call_id = json!("different-id");
    invocation.registry_sha256 = "different-registry".into();
    invocation.baseline = ActionClass::Destructive;
    assert_eq!(
        semantic,
        invocation.semantic_input(),
        "correlation and permissions are not semantic inputs"
    );
    assert_eq!(
        tool.definition_sha256,
        sha(canonical(&result["tools"][0]).to_string().as_bytes())
    );
}

#[test]
fn prediction_identity_binds_server_arguments_metadata_and_classifier_revision() {
    let (native, result, info) = discovered("first");
    let (_, snapshot) = manifest(&result, &native, &info, None).unwrap();
    let args = json!({"query":{"names":["alpha"],"limit":1}});
    let identity =
        |server: &str, snap: &Snapshot, args: &Value, source: &str, rev: Option<&str>| {
            prediction_identity(
                server,
                snap,
                &snap.tools["inventory_lookup"],
                "inventory_lookup",
                args,
                source,
                rev,
            )
        };
    let original = identity(
        "operator-selected",
        &snapshot,
        &args,
        "classifier",
        Some("rev1"),
    );
    assert_eq!(
        original,
        identity(
            "operator-selected",
            &snapshot,
            &args,
            "classifier",
            Some("rev1")
        )
    );
    for changed in [
        identity(
            "different-server",
            &snapshot,
            &args,
            "classifier",
            Some("rev1"),
        ),
        identity(
            "operator-selected",
            &snapshot,
            &json!({}),
            "classifier",
            Some("rev1"),
        ),
        identity(
            "operator-selected",
            &snapshot,
            &args,
            "classifier",
            Some("rev2"),
        ),
        identity(
            "operator-selected",
            &snapshot,
            &args,
            "other-classifier",
            Some("rev1"),
        ),
        identity("operator-selected", &snapshot, &args, "classifier", None),
    ] {
        assert_ne!(original, changed);
    }
    let mut updated = result.clone();
    updated["tools"][0]["annotations"]["readOnlyHint"] = json!(false);
    let (_, metadata_changed) = manifest(&updated, &native, &info, None).unwrap();
    assert_ne!(
        original,
        identity(
            "operator-selected",
            &metadata_changed,
            &args,
            "classifier",
            Some("rev1")
        )
    );
    let (_, server_changed) = manifest(
        &result,
        &native,
        &json!({"name":"fixture","version":"2"}),
        None,
    )
    .unwrap();
    assert_ne!(
        original,
        identity(
            "operator-selected",
            &server_changed,
            &args,
            "classifier",
            Some("rev1")
        )
    );
}

#[test]
fn changed_schema_tool_list_and_unsupported_annotations_require_readmission() {
    let (native, result, info) = discovered("first");
    let mut changed = result.clone();
    changed["tools"][0]["inputSchema"]["properties"]["new"] = json!({"type":"string"});
    assert!(manifest(&changed, &native, &info, None).is_err());
    changed = result.clone();
    changed["tools"] = json!([]);
    assert!(manifest(&changed, &native, &info, None).is_err());
    changed = result;
    changed["tools"][0]["annotations"]["customPermission"] = json!("allow");
    assert!(manifest(&changed, &native, &info, None).is_err());
}

#[test]
fn sou56_https_profile_requires_exact_read_prediction_and_retains_hard_denials() {
    let prediction = |actions: &[&str], unknown, uncertainty| Classification {
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        unknown,
        confidence: 0.95,
        uncertainty,
        reason: "bounded HTTPS scope regression".into(),
    };
    assert_eq!(
        compose_https_get_policy(
            &prediction(&["read"], false, 0.1),
            ActionClass::Network,
            true
        ),
        Ok(ProductionVerdict::Allow)
    );
    for actions in [&[][..], &["send_data"], &["read", "send_data"], &["write"]] {
        assert_eq!(
            compose_https_get_policy(&prediction(actions, false, 0.1), ActionClass::Network, true),
            Ok(ProductionVerdict::Ask)
        );
    }
    for actions in [&["delete"][..], &["read", "change_permissions"]] {
        assert_eq!(
            compose_https_get_policy(&prediction(actions, false, 0.1), ActionClass::Network, true),
            Ok(ProductionVerdict::Deny)
        );
    }
    assert_eq!(
        compose_https_get_policy(
            &prediction(&["read"], true, 0.1),
            ActionClass::Network,
            true
        ),
        Ok(ProductionVerdict::Ask)
    );
    assert_eq!(
        compose_https_get_policy(
            &prediction(&["read"], false, 0.9),
            ActionClass::Network,
            true
        ),
        Ok(ProductionVerdict::Ask)
    );
    assert_eq!(
        compose_https_get_policy(
            &prediction(&["read"], false, 0.1),
            ActionClass::ReadOnly,
            true
        ),
        Ok(ProductionVerdict::Ask)
    );
    assert_eq!(
        compose_https_get_policy(
            &prediction(&["read"], false, f64::NAN),
            ActionClass::Network,
            true
        ),
        Err("classifier_invalid")
    );
}

#[test]
fn sou54_write_authority_preserves_hard_denials_and_unknown_refusal() {
    let prediction = |actions: &[&str], unknown, uncertainty| Classification {
        actions: actions.iter().map(|value| (*value).to_owned()).collect(),
        unknown,
        confidence: 0.95,
        uncertainty,
        reason: "bounded policy regression".into(),
    };
    assert_eq!(
        compose_production_policy(
            &prediction(&["write"], false, 0.1),
            ActionClass::SideEffecting,
            false
        )
        .unwrap(),
        ProductionVerdict::Ask
    );
    assert_eq!(
        compose_scoped_production_policy(
            &prediction(&["write"], false, 0.1),
            ActionClass::SideEffecting,
            false,
            true
        )
        .unwrap(),
        ProductionVerdict::Allow
    );
    for actions in [
        &["delete"][..],
        &["write", "delete"],
        &["write", "change_permissions"],
        &["write", "send_data"],
    ] {
        assert_eq!(
            compose_scoped_production_policy(
                &prediction(actions, false, 0.95),
                ActionClass::SideEffecting,
                false,
                true
            )
            .unwrap(),
            ProductionVerdict::Deny
        );
    }
    for (actions, unknown, uncertainty) in [
        (&["write"][..], true, 0.1),
        (&["write"][..], false, 0.8),
        (&["read", "write"][..], false, 0.1),
        (&["read"][..], false, 0.1),
        (&[][..], false, 0.1),
    ] {
        assert_eq!(
            compose_scoped_production_policy(
                &prediction(actions, unknown, uncertainty),
                ActionClass::SideEffecting,
                false,
                true
            )
            .unwrap(),
            ProductionVerdict::Ask
        );
    }
    assert_eq!(
        compose_scoped_production_policy(
            &prediction(&["write"], false, 0.9),
            ActionClass::ReadOnly,
            false,
            true
        )
        .unwrap(),
        ProductionVerdict::Deny
    );
    for invalid in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
        assert_eq!(
            compose_scoped_production_policy(
                &prediction(&["write"], false, invalid),
                ActionClass::SideEffecting,
                false,
                true
            ),
            Err("classifier_invalid")
        );
    }
}

#[test]
fn compose_production_policy_rules() {
    let make_cl = |actions: Vec<&str>, unknown: bool, uncertainty: f64| Classification {
        actions: actions.into_iter().map(String::from).collect(),
        unknown,
        confidence: 0.95,
        uncertainty,
        reason: "synthetic reason".into(),
    };

    // delete -> Deny
    let cl = make_cl(vec!["delete"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::Destructive, false).unwrap(),
        ProductionVerdict::Deny
    );

    // write on read_only baseline -> Deny
    let cl = make_cl(vec!["write"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // write on read_only baseline with high uncertainty -> hard Deny (SOU-24)
    let cl = make_cl(vec!["write"], false, 0.9);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // write on other baseline -> Ask
    let cl = make_cl(vec!["write"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::SideEffecting, false).unwrap(),
        ProductionVerdict::Ask
    );

    // send_data with declared egress -> Allow
    let cl = make_cl(vec!["send_data"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::Network, true).unwrap(),
        ProductionVerdict::Allow
    );

    // send_data without declared egress and not network baseline -> Deny
    let cl = make_cl(vec!["send_data"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::SideEffecting, false).unwrap(),
        ProductionVerdict::Deny
    );

    // high uncertainty -> Ask
    let cl = make_cl(vec!["read"], false, 0.85);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Ask
    );

    // unknown -> Ask
    let cl = make_cl(vec![], true, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Ask
    );

    // read -> Allow
    let cl = make_cl(vec!["read"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Allow
    );

    // mixed: read + delete -> hard Deny
    let cl = make_cl(vec!["read", "delete"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // mixed: read + change_permissions -> hard Deny
    let cl = make_cl(vec!["read", "change_permissions"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // mixed: read + authorized send_data -> Allow
    let cl = make_cl(vec!["read", "send_data"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::Network, true).unwrap(),
        ProductionVerdict::Allow
    );

    // mixed: read + unauthorized send_data -> Deny
    let cl = make_cl(vec!["read", "send_data"], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // actions plus unknown: read + unknown -> Ask
    let cl = make_cl(vec!["read"], true, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Ask
    );

    // hard-deny takes precedence over unknown: delete + unknown -> hard Deny
    let cl = make_cl(vec!["delete"], true, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Deny
    );

    // Duplicate actions violate the core contract and never reach policy.
    let cl = make_cl(vec!["read", "read"], false, 0.05);
    assert_eq!(map_classification(&cl), Err("classifier_invalid"));
    assert_eq!(
        compose_production_policy(&cl, ActionClass::Network, true),
        Err("classifier_invalid")
    );

    // proven no-op (D07): empty actions, unknown=false -> Allow
    let cl = make_cl(vec![], false, 0.05);
    assert_eq!(
        compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
        ProductionVerdict::Allow
    );
}
