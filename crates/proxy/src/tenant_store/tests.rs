// SPDX-License-Identifier: Apache-2.0
use rusqlite::params;

use super::{
    base64url, BrowserSessionFederation, NewUsageEvent, NewUsageReconciliationImport,
    NewUsageReconciliationRecord, PolicyDeploymentAction, PolicySimulationCase,
    SamlAuthorizationPending, TenantLimits, TenantModelPolicy, TenantPolicyDocument,
    TenantRateLimit, TenantSpendLimit, TenantStore, UsagePricingStatus, UsageQuotaPolicy,
    UsageQuotaState, UsageReconciliationStatus, UsageRetentionPolicy, UsageTokenStatus,
    WorkspacePermission, WorkspaceRole,
};

fn priced_usage_event(tenant_id: &str, request_id: &str) -> NewUsageEvent {
    NewUsageEvent {
        tenant_id: tenant_id.into(),
        request_id: request_id.into(),
        provider_response_id: Some("resp_test_one".into()),
        provider: "openai".into(),
        path: "/v1/responses".into(),
        requested_model: "gpt-test".into(),
        provider_model: Some("gpt-test-2026-08-01".into()),
        input_tokens: Some(3),
        output_tokens: Some(4),
        token_status: UsageTokenStatus::Actual,
        pricing_status: UsagePricingStatus::Priced,
        model_price_version: Some("sha256:test-price-version".into()),
        input_usd_micros_per_million: Some(1_000_000),
        output_usd_micros_per_million: Some(2_000_000),
        cost_usd_micros: Some(11),
        created_at_unix: super::now_unix(),
    }
}

#[tokio::test]
async fn webhook_destinations_are_secret_once_and_deployments_enqueue_delivery() {
    let store = TenantStore::open(":memory:")
        .unwrap()
        .with_webhook_signing_key_base64url(&base64url(&[7; 32]))
        .unwrap();
    let tenant = store.create_tenant("Webhook tenant").unwrap();
    assert!(
        store
            .create_webhook_destination_async(&tenant.id, "https://hooks.example.test/events", &[])
            .await
            .unwrap()
            .secret
            .len()
            > 20
    );
    assert!(store
        .create_webhook_destination_async(&tenant.id, "https://localhost/events", &[])
        .await
        .is_err());
    let destinations = store
        .list_webhook_destinations_async(&tenant.id)
        .await
        .unwrap();
    assert_eq!(destinations.len(), 1);
    assert!(destinations[0].active);

    let version = store
        .create_policy_version(
            &tenant.id,
            "operator_one",
            TenantPolicyDocument::new(Some(TenantModelPolicy {
                allowed_models: vec!["gpt-test".into()],
            })),
        )
        .unwrap();
    store
        .approve_policy_version(&tenant.id, &version.id, "owner_one")
        .unwrap();
    store
        .deploy_policy_version(
            &tenant.id,
            &version.id,
            "owner_one",
            PolicyDeploymentAction::Activate,
        )
        .unwrap();
    let deliveries = store
        .list_webhook_deliveries_async(&tenant.id, 100)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].status.storage_value(), "pending");
    assert_eq!(deliveries[0].attempt_count, 0);
}

#[test]
fn usage_events_are_idempotent_immutable_and_separate_from_spend_counters() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Usage tenant").unwrap();
    let event = priced_usage_event(&tenant.id, "req_usage_one");
    assert!(store.append_usage_event(&event).unwrap());

    let mut conflicting_retry = event.clone();
    conflicting_retry.cost_usd_micros = Some(999);
    assert!(!store.append_usage_event(&conflicting_retry).unwrap());

    let stored = store.list_usage_events(&tenant.id, 100).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].request_id, "req_usage_one");
    assert_eq!(stored[0].cost_usd_micros, Some(11));
    assert_eq!(
        stored[0].model_price_version.as_deref(),
        Some("sha256:test-price-version")
    );
}

#[test]
fn usage_retention_requires_policy_and_protects_reconciled_evidence() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Retention tenant").unwrap();
    assert!(store
        .run_usage_retention(&tenant.id, "admin_owner", false)
        .is_err());
    assert!(store
        .set_usage_retention_policy(
            &tenant.id,
            "admin_owner",
            Some(UsageRetentionPolicy { retention_days: 29 }),
        )
        .is_err());
    store
        .set_usage_retention_policy(
            &tenant.id,
            "admin_owner",
            Some(UsageRetentionPolicy { retention_days: 30 }),
        )
        .unwrap();

    let old_timestamp = super::now_unix() - 31 * 86_400;
    let mut eligible = priced_usage_event(&tenant.id, "req_retention_eligible");
    eligible.provider_response_id = Some("resp_retention_eligible".into());
    eligible.created_at_unix = old_timestamp;
    store.append_usage_event(&eligible).unwrap();

    let mut protected = priced_usage_event(&tenant.id, "req_retention_protected");
    protected.provider_response_id = Some("resp_retention_protected".into());
    protected.created_at_unix = old_timestamp;
    store.append_usage_event(&protected).unwrap();

    let mut recent = priced_usage_event(&tenant.id, "req_retention_recent");
    recent.provider_response_id = Some("resp_retention_recent".into());
    store.append_usage_event(&recent).unwrap();

    store
        .import_usage_reconciliation(
            &tenant.id,
            "admin_owner",
            &NewUsageReconciliationImport {
                source: "provider-statement".into(),
                statement_id: "statement-retention".into(),
                records: vec![NewUsageReconciliationRecord {
                    source_record_id: "line-protected".into(),
                    provider: "openai".into(),
                    provider_response_id: "resp_retention_protected".into(),
                    input_tokens: Some(3),
                    output_tokens: Some(4),
                    cost_usd_micros: Some(11),
                }],
            },
        )
        .unwrap();

    let dry_run = store
        .run_usage_retention(&tenant.id, "admin_owner", false)
        .unwrap();
    assert!(!dry_run.executed);
    assert_eq!(dry_run.eligible_event_count, 1);
    assert_eq!(dry_run.protected_reconciliation_event_count, 1);
    assert_eq!(dry_run.deleted_event_count, 0);
    assert_eq!(store.list_usage_events(&tenant.id, 10).unwrap().len(), 3);

    let execution = store
        .run_usage_retention(&tenant.id, "admin_owner", true)
        .unwrap();
    assert!(execution.executed);
    assert_eq!(execution.eligible_event_count, 1);
    assert_eq!(execution.deleted_event_count, 1);
    let remaining = store.list_usage_events(&tenant.id, 10).unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(remaining
        .iter()
        .any(|event| event.request_id == "req_retention_protected"));
    assert!(remaining
        .iter()
        .any(|event| event.request_id == "req_retention_recent"));
    assert_eq!(
        store
            .list_usage_retention_runs(&tenant.id, 10)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn only_customer_owner_can_change_usage_retention_policy() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store.create_organization("Retention customer").unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Retention workspace")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store.create_workspace_principal("Retention owner").unwrap();
    let admin = store.create_workspace_principal("Retention admin").unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &admin.id, WorkspaceRole::Admin)
        .unwrap();
    let policy = Some(UsageRetentionPolicy { retention_days: 90 });
    assert!(store
        .set_workspace_usage_retention_policy(&workspace.id, &admin.id, policy.clone())
        .is_err());
    store
        .set_workspace_usage_retention_policy(&workspace.id, &owner.id, policy.clone())
        .unwrap();
    assert_eq!(store.usage_retention_policy(&tenant.id).unwrap(), policy);
    let audit = store.list_workspace_admin_audit(&workspace.id, 10).unwrap();
    assert_eq!(audit[0].action, "usage_retention_policy.set");
    assert_eq!(
        audit[0].actor_principal_id.as_deref(),
        Some(owner.id.as_str())
    );
}

#[tokio::test]
async fn utc_month_range_and_quota_alerts_are_exact_and_evidence_aware() {
    assert_eq!(super::current_utc_month_range(0).unwrap(), (0, 31 * 86_400));
    assert_eq!(
        super::current_utc_month_range(1_707_955_200).unwrap(),
        (1_706_745_600, 1_709_251_200)
    );

    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Quota tenant").unwrap();
    let policy = UsageQuotaPolicy {
        request_limit: Some(2),
        token_limit: Some(10),
        cost_usd_micros_limit: Some(20),
        alert_threshold_basis_points: 5_000,
    };
    store
        .set_usage_quota_policy(&tenant.id, "admin_owner", Some(policy.clone()))
        .unwrap();
    let mut actual = priced_usage_event(&tenant.id, "req_quota_actual");
    actual.provider_response_id = Some("resp_quota_actual".into());
    store.append_usage_event(&actual).unwrap();
    let status = store
        .usage_quota_status_async(&tenant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.policy, policy);
    assert_eq!(status.requests.unwrap().state, UsageQuotaState::Threshold);
    assert_eq!(status.tokens.unwrap().state, UsageQuotaState::Threshold);
    assert_eq!(
        status.cost_usd_micros.unwrap().state,
        UsageQuotaState::Threshold
    );
    assert!(status.attention_required);

    let mut missing = priced_usage_event(&tenant.id, "req_quota_missing");
    missing.provider_response_id = None;
    missing.input_tokens = None;
    missing.output_tokens = None;
    missing.token_status = UsageTokenStatus::Missing;
    missing.pricing_status = UsagePricingStatus::Unpriced;
    missing.cost_usd_micros = None;
    store.append_usage_event(&missing).unwrap();
    let status = store
        .usage_quota_status_async(&tenant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.requests.unwrap().state, UsageQuotaState::Exceeded);
    assert_eq!(
        status.tokens.unwrap().state,
        UsageQuotaState::EvidenceIncomplete
    );
    assert_eq!(
        status.cost_usd_micros.unwrap().state,
        UsageQuotaState::EvidenceIncomplete
    );
    assert_eq!(status.missing_token_events, 1);
    assert_eq!(status.unpriced_events, 1);
}

#[test]
fn only_customer_owner_can_change_usage_quota_policy() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store.create_organization("Quota customer").unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Quota workspace")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store.create_workspace_principal("Quota owner").unwrap();
    let admin = store.create_workspace_principal("Quota admin").unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &admin.id, WorkspaceRole::Admin)
        .unwrap();
    let policy = Some(UsageQuotaPolicy {
        request_limit: Some(1_000),
        token_limit: None,
        cost_usd_micros_limit: Some(50_000_000),
        alert_threshold_basis_points: 8_000,
    });
    assert!(store
        .set_workspace_usage_quota_policy(&workspace.id, &admin.id, policy.clone())
        .is_err());
    store
        .set_workspace_usage_quota_policy(&workspace.id, &owner.id, policy.clone())
        .unwrap();
    assert_eq!(store.usage_quota_policy(&tenant.id).unwrap(), policy);
    let audit = store.list_workspace_admin_audit(&workspace.id, 10).unwrap();
    assert_eq!(audit[0].action, "usage_quota_policy.set");
}

#[test]
fn usage_reporting_preserves_quality_gaps_and_exports_with_a_cursor() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Reporting tenant").unwrap();

    let mut first = priced_usage_event(&tenant.id, "req_report_one");
    first.created_at_unix = 172_800;
    assert!(store.append_usage_event(&first).unwrap());

    let mut duplicate_provider_response = first.clone();
    duplicate_provider_response.request_id = "req_report_two".into();
    assert!(store
        .append_usage_event(&duplicate_provider_response)
        .unwrap());

    let mut missing = first.clone();
    missing.request_id = "req_report_three".into();
    missing.provider_response_id = None;
    missing.input_tokens = None;
    missing.output_tokens = None;
    missing.token_status = UsageTokenStatus::Missing;
    missing.pricing_status = UsagePricingStatus::Unpriced;
    missing.cost_usd_micros = None;
    assert!(store.append_usage_event(&missing).unwrap());

    let report = store.usage_report(&tenant.id, 86_400, 259_200).unwrap();
    assert_eq!(report.totals.request_count, 3);
    assert_eq!(report.totals.actual_token_events, 2);
    assert_eq!(report.totals.missing_token_events, 1);
    assert_eq!(report.totals.priced_events, 2);
    assert_eq!(report.totals.unpriced_events, 1);
    assert_eq!(report.totals.provider_correlated_events, 2);
    assert_eq!(report.totals.input_tokens, 6);
    assert_eq!(report.totals.output_tokens, 8);
    assert_eq!(report.totals.priced_cost_usd_micros, 22);
    assert_eq!(report.daily.len(), 1);
    assert_eq!(report.daily[0].day_start_unix, 172_800);
    assert_eq!(report.models.len(), 1);
    assert_eq!(report.reconciliation.ready_events, 0);
    assert_eq!(report.reconciliation.review_required_events, 3);
    assert_eq!(report.reconciliation.missing_provider_response_id_events, 1);
    assert_eq!(
        report.reconciliation.duplicate_provider_response_id_groups,
        1
    );
    assert_eq!(
        report.reconciliation.duplicate_provider_response_id_events,
        2
    );

    let first_page = store
        .list_usage_events_range(&tenant.id, 86_400, 259_200, None, 2)
        .unwrap();
    assert_eq!(first_page.events.len(), 2);
    let cursor = first_page.next_after_id.expect("a third event remains");
    let second_page = store
        .list_usage_events_range(&tenant.id, 86_400, 259_200, Some(cursor), 2)
        .unwrap();
    assert_eq!(second_page.events.len(), 1);
    assert!(second_page.next_after_id.is_none());
    assert_eq!(second_page.events[0].request_id, "req_report_three");
}

#[test]
fn reconciliation_import_is_immutable_idempotent_and_classifies_every_record() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Reconciliation tenant").unwrap();
    let other_tenant = store.create_tenant("Other tenant").unwrap();

    let mut matched = priced_usage_event(&tenant.id, "req_reconcile_matched");
    matched.provider_response_id = Some("resp_matched".into());
    assert!(store.append_usage_event(&matched).unwrap());

    let mut mismatched = priced_usage_event(&tenant.id, "req_reconcile_mismatched");
    mismatched.provider_response_id = Some("resp_mismatched".into());
    assert!(store.append_usage_event(&mismatched).unwrap());

    let mut duplicate_one = priced_usage_event(&tenant.id, "req_reconcile_duplicate_one");
    duplicate_one.provider_response_id = Some("resp_duplicate".into());
    assert!(store.append_usage_event(&duplicate_one).unwrap());
    let mut duplicate_two = duplicate_one.clone();
    duplicate_two.request_id = "req_reconcile_duplicate_two".into();
    assert!(store.append_usage_event(&duplicate_two).unwrap());

    let import = NewUsageReconciliationImport {
        source: "provider-export".into(),
        statement_id: "statement-2026-08".into(),
        records: vec![
            NewUsageReconciliationRecord {
                source_record_id: "record-matched".into(),
                provider: "openai".into(),
                provider_response_id: "resp_matched".into(),
                input_tokens: Some(3),
                output_tokens: Some(4),
                cost_usd_micros: Some(11),
            },
            NewUsageReconciliationRecord {
                source_record_id: "record-mismatched".into(),
                provider: "openai".into(),
                provider_response_id: "resp_mismatched".into(),
                input_tokens: Some(30),
                output_tokens: Some(40),
                cost_usd_micros: Some(11),
            },
            NewUsageReconciliationRecord {
                source_record_id: "record-ambiguous".into(),
                provider: "openai".into(),
                provider_response_id: "resp_duplicate".into(),
                input_tokens: Some(3),
                output_tokens: Some(4),
                cost_usd_micros: None,
            },
            NewUsageReconciliationRecord {
                source_record_id: "record-orphan".into(),
                provider: "openai".into(),
                provider_response_id: "resp_missing_locally".into(),
                input_tokens: None,
                output_tokens: None,
                cost_usd_micros: Some(99),
            },
        ],
    };
    let run = store
        .import_usage_reconciliation(&tenant.id, "bootstrap_owner", &import)
        .unwrap();
    assert_eq!(run.record_count, 4);
    assert_eq!(run.matched_count, 1);
    assert_eq!(run.mismatched_count, 1);
    assert_eq!(run.orphan_count, 1);
    assert_eq!(run.ambiguous_count, 1);

    let mut reordered = import.clone();
    reordered.records.reverse();
    let replay = store
        .import_usage_reconciliation(&tenant.id, "another_operator", &reordered)
        .unwrap();
    assert_eq!(
        replay, run,
        "record ordering does not alter statement identity"
    );
    assert_eq!(
        store
            .list_usage_reconciliation_runs(&tenant.id, 10)
            .unwrap(),
        vec![run.clone()]
    );
    assert!(store
        .list_usage_reconciliation_runs(&other_tenant.id, 10)
        .unwrap()
        .is_empty());

    let observations = store
        .list_usage_reconciliation_observations(&tenant.id, &run.id, 10)
        .unwrap();
    assert_eq!(observations.len(), 4);
    assert!(observations.iter().any(|observation| {
        observation.status == UsageReconciliationStatus::Matched
            && observation.usage_event_id.is_some()
    }));
    assert!(observations.iter().any(|observation| {
        observation.status == UsageReconciliationStatus::Mismatched
            && observation.usage_event_id.is_some()
    }));
    assert!(observations.iter().any(|observation| {
        observation.status == UsageReconciliationStatus::Ambiguous
            && observation.usage_event_id.is_none()
    }));
    assert!(observations.iter().any(|observation| {
        observation.status == UsageReconciliationStatus::Orphan
            && observation.usage_event_id.is_none()
    }));

    let mut conflicting = import;
    conflicting.records[0].cost_usd_micros = Some(12);
    assert!(store
        .import_usage_reconciliation(&tenant.id, "bootstrap_owner", &conflicting)
        .is_err());
}

#[tokio::test]
async fn failed_usage_write_stays_visible_to_readiness() {
    let store = TenantStore::open(":memory:").unwrap();
    let event = priced_usage_event("missing_tenant", "req_usage_failure");

    assert!(store.append_usage_event_async(&event).await.is_err());
    assert_eq!(store.usage_ledger_status().failed_events, 1);
}

#[test]
fn issued_token_authenticates_then_revocation_takes_effect() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Acme").unwrap();
    let issued = store.issue_token(&tenant.id, "production").unwrap();
    let header = format!("Bearer {}", issued.token);

    assert_eq!(
        store.authenticate_bearer(Some(&header)).unwrap(),
        Some(super::TenantIdentity {
            tenant_id: tenant.id,
            tenant_name: "Acme".into(),
        })
    );
    assert!(store.revoke_token(&issued.id).unwrap());
    assert_eq!(store.authenticate_bearer(Some(&header)).unwrap(), None);
    assert!(!store.revoke_token(&issued.id).unwrap());
}

#[test]
fn scim_tokens_are_organization_scoped_expiring_and_revocable() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store.create_organization("SCIM organization").unwrap();
    let issued = store
        .issue_scim_token(
            &organization.id,
            "identity-provider",
            super::now_unix() + 3_600,
        )
        .unwrap();
    assert!(issued.token.starts_with("llmfw_scim_"));
    let header = format!("Bearer {}", issued.token);
    assert_eq!(
        store.authenticate_scim_bearer(Some(&header)).unwrap(),
        Some(super::ScimIdentity {
            organization_id: organization.id.clone(),
            token_id: issued.credential.id.clone(),
        })
    );
    let inventory = store.list_scim_tokens(&organization.id).unwrap();
    assert_eq!(inventory, vec![issued.credential.clone()]);
    assert!(store
        .issue_scim_token(&organization.id, "expired", super::now_unix())
        .is_err());
    assert!(store.revoke_scim_token(&issued.credential.id).unwrap());
    assert_eq!(store.authenticate_scim_bearer(Some(&header)).unwrap(), None);
}

#[test]
fn scim_users_start_without_workspace_access_and_deprovisioning_is_sticky() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("SCIM directory organization")
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "SCIM directory tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let credential = store
        .issue_scim_token(&organization.id, "directory", super::now_unix() + 3_600)
        .unwrap();
    let identity = store
        .authenticate_scim_bearer(Some(&format!("Bearer {}", credential.token)))
        .unwrap()
        .unwrap();
    let user = store
        .create_scim_user(
            &identity,
            "idp-opaque-user-1",
            "security.engineer@example.test",
            "Security Engineer",
            true,
        )
        .unwrap();
    assert_eq!(
        store.list_scim_users(&identity, 1, 100).unwrap().resources,
        vec![user.clone()]
    );
    assert!(!store
        .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
        .unwrap());

    // A role assignment is explicit and can only target the user's own
    // organization. The person never receives it from SCIM creation.
    store
        .set_workspace_membership(&workspace.id, &user.id, WorkspaceRole::Analyst)
        .unwrap();
    assert!(store
        .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
        .unwrap());
    let suspended = store
        .update_scim_user(
            &identity,
            &user.id,
            super::ScimUserUpdate {
                active: Some(false),
                ..super::ScimUserUpdate::default()
            },
        )
        .unwrap()
        .unwrap();
    assert!(!suspended.active);
    assert!(!store
        .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
        .unwrap());
    store
        .update_scim_user(
            &identity,
            &user.id,
            super::ScimUserUpdate {
                active: Some(true),
                ..super::ScimUserUpdate::default()
            },
        )
        .unwrap();
    assert!(
        !store
            .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
            .unwrap(),
        "reactivation must not restore a prior workspace role"
    );

    let other_organization = store.create_organization("Other organization").unwrap();
    let other_tenant = store
        .create_tenant_in_organization(&other_organization.id, "Other tenant")
        .unwrap();
    let other_workspace = store
        .workspace_for_tenant(&other_tenant.id)
        .unwrap()
        .unwrap();
    assert!(store
        .set_workspace_membership(&other_workspace.id, &user.id, WorkspaceRole::Analyst)
        .is_err());
}

#[test]
fn raw_token_is_not_a_database_lookup_key() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Acme").unwrap();
    let issued = store.issue_token(&tenant.id, "production").unwrap();
    assert!(issued.token.starts_with("llmfw_"));
    assert!(store
        .authenticate_bearer(Some("Bearer incorrect"))
        .unwrap()
        .is_none());
}

#[test]
fn issue_rejects_unknown_or_inactive_tenants() {
    let store = TenantStore::open(":memory:").unwrap();
    assert!(store.issue_token("missing", "production").is_err());
    assert!(store.create_tenant(" ").is_err());
}

#[test]
fn tenant_limits_and_privacy_safe_audit_are_persisted() {
    let store = TenantStore::open_with_audit_capacity(":memory:", 2).unwrap();
    let tenant = store.create_tenant("Acme").unwrap();
    let limits = TenantLimits {
        rate_limit: Some(TenantRateLimit {
            requests_per_window: 7,
            window_seconds: 60,
        }),
        spend_limit: Some(TenantSpendLimit {
            window_seconds: 86_400,
            max_usd_micros: 1_000_000,
            reserve_usd_micros_per_request: 50_000,
        }),
    };
    store.set_limits(&tenant.id, limits.clone()).unwrap();
    assert_eq!(store.limits_for(&tenant.id).unwrap(), limits);

    store
        .append_audit(&tenant.id, "/v1/chat/completions", "completed", 200, 12)
        .unwrap();
    store
        .append_audit(&tenant.id, "/v1/responses", "rejected", 429, 1)
        .unwrap();
    store
        .append_audit(&tenant.id, "/v1/messages", "completed", 200, 8)
        .unwrap();
    let audit = store.list_audit(&tenant.id, 100).unwrap();
    assert_eq!(audit.len(), 2, "configured retention applies");
    assert_eq!(audit[0].path, "/v1/messages");
    assert_eq!(audit[1].outcome, "rejected");
}

#[test]
fn tenant_model_policy_is_exact_persisted_and_can_be_cleared() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Acme").unwrap();
    let policy = TenantModelPolicy {
        allowed_models: vec!["gpt-5.6".into(), "gpt-5.6-mini".into()],
    };
    store
        .set_model_policy(&tenant.id, Some(policy.clone()))
        .unwrap();
    let loaded = store.model_policy_for(&tenant.id).unwrap().unwrap();
    assert_eq!(loaded, policy);
    assert!(loaded.permits("gpt-5.6"));
    assert!(!loaded.permits("gpt-5.6-preview"), "no prefix matching");
    store.set_model_policy(&tenant.id, None).unwrap();
    assert_eq!(store.model_policy_for(&tenant.id).unwrap(), None);
}

#[test]
fn policy_versions_require_approval_simulate_exactly_and_rollback_immutably() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Versioned policy tenant").unwrap();
    let first = store
        .create_policy_version(
            &tenant.id,
            "policy_author",
            TenantPolicyDocument::new(Some(TenantModelPolicy {
                allowed_models: vec!["gpt-safe".into()],
            })),
        )
        .unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(first.content_sha256.len(), 64);
    let preview = store
        .simulate_policy_version(
            &tenant.id,
            &first.id,
            vec![
                PolicySimulationCase {
                    requested_model: "gpt-safe".into(),
                },
                PolicySimulationCase {
                    requested_model: "gpt-other".into(),
                },
            ],
        )
        .unwrap();
    assert_eq!(preview.changed_count, 1);
    assert!(preview.results[0].candidate_permitted);
    assert!(!preview.results[1].candidate_permitted);
    assert!(store
        .deploy_policy_version(
            &tenant.id,
            &first.id,
            "policy_owner",
            PolicyDeploymentAction::Activate,
        )
        .is_err());
    store
        .approve_policy_version(&tenant.id, &first.id, "policy_owner")
        .unwrap();
    store
        .deploy_policy_version(
            &tenant.id,
            &first.id,
            "policy_owner",
            PolicyDeploymentAction::Activate,
        )
        .unwrap();
    assert!(store
        .model_policy_for(&tenant.id)
        .unwrap()
        .unwrap()
        .permits("gpt-safe"));

    let second = store
        .create_policy_version(
            &tenant.id,
            "policy_author",
            TenantPolicyDocument::new(Some(TenantModelPolicy {
                allowed_models: vec!["gpt-next".into()],
            })),
        )
        .unwrap();
    store
        .approve_policy_version(&tenant.id, &second.id, "policy_owner")
        .unwrap();
    store
        .deploy_policy_version(
            &tenant.id,
            &second.id,
            "policy_owner",
            PolicyDeploymentAction::Activate,
        )
        .unwrap();
    let rollback = store
        .deploy_policy_version(
            &tenant.id,
            &first.id,
            "policy_owner",
            PolicyDeploymentAction::Rollback,
        )
        .unwrap();
    assert_eq!(
        rollback.previous_version_id.as_deref(),
        Some(second.id.as_str())
    );
    assert_eq!(
        store.list_policy_deployments(&tenant.id, 10).unwrap()[0].action,
        PolicyDeploymentAction::Rollback
    );
    let security_events = store.list_security_events(&tenant.id, 0, 10).unwrap();
    assert_eq!(security_events.len(), 3);
    assert_eq!(security_events[0].sequence, 1);
    assert_eq!(security_events[2].payload["event_type"], "policy.deployed");
    assert_eq!(security_events[2].content_sha256.len(), 64);
    assert!(store
        .list_security_events(&tenant.id, security_events[0].sequence, 10)
        .unwrap()
        .iter()
        .all(|event| event.sequence > security_events[0].sequence));
    let exported = store
        .policy_version(&tenant.id, &first.id)
        .unwrap()
        .unwrap();
    assert!(exported.active);
    assert_eq!(exported.document, first.document);

    let connection = store.connection().unwrap();
    assert!(connection
        .execute(
            "UPDATE tenant_policy_versions SET content_sha256 = ?1 WHERE id = ?2",
            params!["0".repeat(64), &first.id],
        )
        .is_err());
}

#[test]
fn workspace_rbac_is_scoped_to_the_tenant_workspace() {
    let store = TenantStore::open(":memory:").unwrap();
    let acme = store.create_tenant("Acme").unwrap();
    let beta = store.create_tenant("Beta").unwrap();
    let acme_workspace = store.workspace_for_tenant(&acme.id).unwrap().unwrap();
    let beta_workspace = store.workspace_for_tenant(&beta.id).unwrap().unwrap();
    assert_eq!(
        acme_workspace.organization_id,
        super::BOOTSTRAP_ORGANIZATION_ID
    );
    assert_eq!(acme_workspace.tenant_id, acme.id);

    let alice = store.create_workspace_principal("Alice").unwrap();
    store
        .set_workspace_membership(&acme_workspace.id, &alice.id, WorkspaceRole::Owner)
        .unwrap();
    assert!(store
        .workspace_permits(
            &alice.id,
            &acme_workspace.id,
            WorkspacePermission::ManagePolicies
        )
        .unwrap());
    assert!(!store
        .workspace_permits(
            &alice.id,
            &beta_workspace.id,
            WorkspacePermission::ReadAudit
        )
        .unwrap());

    store
        .set_workspace_membership(&acme_workspace.id, &alice.id, WorkspaceRole::Analyst)
        .unwrap();
    assert!(store
        .workspace_permits(
            &alice.id,
            &acme_workspace.id,
            WorkspacePermission::ReadAudit
        )
        .unwrap());
    assert!(!store
        .workspace_permits(
            &alice.id,
            &acme_workspace.id,
            WorkspacePermission::ManagePolicies
        )
        .unwrap());

    let audit = store
        .list_workspace_admin_audit(&acme_workspace.id, 10)
        .unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].action, "membership.upsert");
    assert_eq!(
        audit[0].target_principal_id.as_deref(),
        Some(alice.id.as_str())
    );
    assert_eq!(audit[1].organization_id, acme_workspace.organization_id);
    assert!(store
        .list_workspace_admin_audit(&beta_workspace.id, 10)
        .unwrap()
        .is_empty());
}

#[test]
fn workspace_service_accounts_are_scoped_one_time_and_revocable() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Service account tenant").unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store.create_workspace_principal("Owner").unwrap();
    let developer = store.create_workspace_principal("Developer").unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &developer.id, WorkspaceRole::Developer)
        .unwrap();

    let issued = store
        .create_workspace_service_account(
            &workspace.id,
            &developer.id,
            "build-agent",
            super::now_unix() + 3_600,
        )
        .unwrap();
    assert!(issued.token.starts_with("llmfw_sa_"));
    let header = format!("Bearer {}", issued.token);
    assert_eq!(
        store.authenticate_bearer(Some(&header)).unwrap(),
        Some(super::TenantIdentity {
            tenant_id: tenant.id.clone(),
            tenant_name: tenant.name.clone(),
        })
    );
    assert_eq!(
        store
            .list_workspace_service_accounts(&workspace.id, &developer.id)
            .unwrap(),
        vec![issued.account.clone()]
    );
    assert_eq!(
        store
            .list_workspace_service_accounts(&workspace.id, &owner.id)
            .unwrap(),
        vec![issued.account.clone()]
    );
    assert!(store
        .revoke_workspace_service_account(&workspace.id, &issued.account.id, &developer.id)
        .unwrap());
    assert!(!store
        .revoke_workspace_service_account(&workspace.id, &issued.account.id, &owner.id)
        .unwrap());
    assert_eq!(store.authenticate_bearer(Some(&header)).unwrap(), None);
    assert!(!store
        .revoke_workspace_service_account(&workspace.id, &issued.account.id, &owner.id)
        .unwrap());
    assert!(store
        .create_workspace_service_account(
            &workspace.id,
            &developer.id,
            "expired",
            super::now_unix(),
        )
        .is_err());
}

#[test]
fn workspace_invitations_are_hash_only_owner_scoped_and_single_use() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("Invitation organization")
        .unwrap();
    let issuer = "https://id.example.test/invitations";
    store
        .set_organization_oidc_connection(
            &organization.id,
            issuer,
            "firewall-console",
            "https://console.example.test/auth/oidc/callback",
            true,
        )
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Invitation tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store
        .create_workspace_principal("Invitation owner")
        .unwrap();
    let analyst = store
        .create_workspace_principal("Existing analyst")
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &analyst.id, WorkspaceRole::Analyst)
        .unwrap();

    assert!(store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &analyst.id,
            "Not allowed",
            WorkspaceRole::Developer,
            super::now_unix() + 3_600,
        )
        .is_err());
    let revoked = store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "Revoked recipient",
            WorkspaceRole::Analyst,
            super::now_unix() + 3_600,
        )
        .unwrap();
    assert!(store
        .revoke_workspace_invitation_as_owner(&workspace.id, &revoked.invitation.id, &owner.id,)
        .unwrap());
    assert!(store
        .workspace_invitation_for_token(&revoked.token)
        .unwrap()
        .is_none());

    let issued = store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "New developer",
            WorkspaceRole::Developer,
            super::now_unix() + 3_600,
        )
        .unwrap();
    assert!(issued.token.starts_with("llmfw_invite_"));
    let raw_token_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM workspace_invitations
                 WHERE token_hash = CAST(?1 AS BLOB)",
            [&issued.token],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(raw_token_count, 0, "only an invitation hash is stored");
    assert_eq!(
        store
            .workspace_invitation_for_token(&issued.token)
            .unwrap()
            .map(|invitation| invitation.id),
        Some(issued.invitation.id.clone())
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let resend_candidate = store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "Resend candidate",
            WorkspaceRole::Analyst,
            super::now_unix() + 3_600,
        )
        .unwrap();
    let resent = runtime
        .block_on(store.resend_workspace_invitation_as_owner_async(
            &workspace.id,
            &resend_candidate.invitation.id,
            &owner.id,
            super::now_unix() + 7_200,
        ))
        .unwrap()
        .expect("an active invitation can be resent");
    assert_ne!(
        resent.token, resend_candidate.token,
        "resend must mint a new bearer"
    );
    assert_eq!(
        resent.invitation.recipient_label,
        resend_candidate.invitation.recipient_label
    );
    assert_eq!(resent.invitation.role, resend_candidate.invitation.role);
    assert!(
        store
            .workspace_invitation_for_token(&resend_candidate.token)
            .unwrap()
            .is_none(),
        "the old bearer is revoked immediately"
    );
    assert_eq!(
        store
            .workspace_invitation_for_token(&resent.token)
            .unwrap()
            .map(|invitation| invitation.id),
        Some(resent.invitation.id.clone())
    );
    let resent_inventory = store
        .list_workspace_invitations_as_owner(&workspace.id, &owner.id)
        .unwrap();
    assert!(resent_inventory.iter().any(|invitation| {
        invitation.id == resend_candidate.invitation.id
            && !invitation.active
            && invitation.revoked_at_unix.is_some()
    }));

    let other_tenant = store
        .create_tenant_in_organization(&organization.id, "Invitation other tenant")
        .unwrap();
    let other_workspace = store
        .workspace_for_tenant(&other_tenant.id)
        .unwrap()
        .unwrap();
    assert!(store
        .accept_workspace_invitation_oidc(
            &issued.invitation.id,
            &organization.id,
            &other_workspace.id,
            issuer,
            "new-developer-subject",
        )
        .unwrap()
        .is_none());
    assert!(store
        .workspace_invitation_for_token(&issued.token)
        .unwrap()
        .is_some());

    let access = store
        .accept_workspace_invitation_oidc(
            &issued.invitation.id,
            &organization.id,
            &workspace.id,
            issuer,
            "new-developer-subject",
        )
        .unwrap()
        .expect("a verified new OIDC identity can consume the invitation once");
    assert_eq!(access.organization_id, organization.id);
    assert_eq!(access.workspace_id, workspace.id);
    assert_eq!(access.role, WorkspaceRole::Developer);
    assert_eq!(
        store
            .workspace_principal_for_external_identity(issuer, "new-developer-subject")
            .unwrap()
            .map(|principal| principal.id),
        Some(access.principal_id.clone())
    );
    assert!(store
        .verified_identity_workspace_access(
            &organization.id,
            &workspace.id,
            issuer,
            "new-developer-subject",
        )
        .unwrap()
        .is_some());
    assert!(store
        .accept_workspace_invitation_oidc(
            &issued.invitation.id,
            &organization.id,
            &workspace.id,
            issuer,
            "new-developer-subject",
        )
        .unwrap()
        .is_none());
    assert!(store
        .workspace_invitation_for_token(&issued.token)
        .unwrap()
        .is_none());
    let invitations = store
        .list_workspace_invitations_as_owner(&workspace.id, &owner.id)
        .unwrap();
    let accepted = invitations
        .iter()
        .find(|invitation| invitation.id == issued.invitation.id)
        .unwrap();
    assert!(!accepted.active);
    assert_eq!(
        accepted.accepted_by_principal_id.as_deref(),
        Some(access.principal_id.as_str())
    );
    assert!(accepted.accepted_at_unix.is_some());
    let audit = store.list_workspace_admin_audit(&workspace.id, 20).unwrap();
    assert!(audit
        .iter()
        .any(|event| event.action == "invitation.create"));
    assert!(audit
        .iter()
        .any(|event| event.action == "invitation.revoke"));
    assert!(audit
        .iter()
        .any(|event| event.action == "invitation.accept"));
}

#[test]
fn saml_workspace_invitations_bind_only_after_verified_identity() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("SAML invitation organization")
        .unwrap();
    let issuer = "https://id.example.test/saml-invitations";
    store
        .set_organization_saml_connection(
            &organization.id,
            issuer,
            "<EntityDescriptor entityID=\"https://id.example.test/saml-invitations\"></EntityDescriptor>",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            true,
        )
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "SAML invitation tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store.create_workspace_principal("SAML owner").unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    let issued = store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "SAML recipient",
            WorkspaceRole::Analyst,
            super::now_unix() + 3_600,
        )
        .unwrap();

    assert!(store
        .workspace_invitation_for_token(&issued.token)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .workspace_invitation_for_federation_token(
                &issued.token,
                BrowserSessionFederation::Saml,
            )
            .unwrap()
            .map(|invitation| invitation.id),
        Some(issued.invitation.id.clone())
    );
    let pending = SamlAuthorizationPending {
        organization_id: organization.id.clone(),
        workspace_id: workspace.id.clone(),
        invitation_id: Some(issued.invitation.id.clone()),
        request_id: "_saml_invitation_request".to_owned(),
        idp_entity_id: issuer.to_owned(),
        expected_binding: "post".to_owned(),
        request_binding: "redirect".to_owned(),
        acs_url: "https://console.example.test/auth/saml/acs".to_owned(),
        acs_binding: "post".to_owned(),
    };
    store
        .reserve_saml_authorization_state("saml-invitation-state", &pending, super::now_unix() + 60)
        .unwrap();
    assert_eq!(
        store
            .consume_saml_authorization_state("saml-invitation-state")
            .unwrap(),
        Some(pending)
    );
    let access = store
        .accept_workspace_invitation_federated(
            &issued.invitation.id,
            &organization.id,
            &workspace.id,
            issuer,
            "saml-recipient-1",
            BrowserSessionFederation::Saml,
        )
        .unwrap()
        .expect("verified SAML identity can consume the invitation");
    assert_eq!(access.role, WorkspaceRole::Analyst);
    assert!(store
        .accept_workspace_invitation_federated(
            &issued.invitation.id,
            &organization.id,
            &workspace.id,
            issuer,
            "saml-recipient-2",
            BrowserSessionFederation::Saml,
        )
        .unwrap()
        .is_none());
}

#[test]
fn workspace_owner_can_manage_existing_members_but_cannot_remove_last_owner() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("Membership tenant").unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store.create_workspace_principal("Owner").unwrap();
    let member = store.create_workspace_principal("Member").unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &member.id, WorkspaceRole::Analyst)
        .unwrap();

    let members = store.list_workspace_members(&workspace.id).unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].principal_name, "Member");
    assert_eq!(members[1].principal_name, "Owner");
    assert!(members.iter().all(|member| member.active));

    let updated = store
        .update_workspace_membership_as_owner(
            &workspace.id,
            &owner.id,
            &member.id,
            WorkspaceRole::Developer,
            false,
        )
        .unwrap();
    assert_eq!(updated.role, WorkspaceRole::Developer);
    assert!(!updated.active);
    assert!(store
        .update_workspace_membership_as_owner(
            &workspace.id,
            &owner.id,
            &owner.id,
            WorkspaceRole::Admin,
            true,
        )
        .is_err());
    assert!(store
        .workspace_permits(
            &owner.id,
            &workspace.id,
            WorkspacePermission::ManageMembership
        )
        .unwrap());
    let audit = store.list_workspace_admin_audit(&workspace.id, 1).unwrap();
    assert_eq!(audit[0].action, "membership.update");
    assert_eq!(
        audit[0].actor_principal_id.as_deref(),
        Some(owner.id.as_str())
    );
    assert_eq!(
        audit[0].target_principal_id.as_deref(),
        Some(member.id.as_str())
    );
}

#[test]
fn organizations_isolate_workspaces_and_suspend_membership_changes() {
    let store = TenantStore::open(":memory:").unwrap();
    let acme = store.create_organization("Acme organization").unwrap();
    let beta = store.create_organization("Beta organization").unwrap();
    let acme_tenant = store
        .create_tenant_in_organization(&acme.id, "Acme production")
        .unwrap();
    let acme_workspace = store
        .workspace_for_tenant(&acme_tenant.id)
        .unwrap()
        .unwrap();
    assert_eq!(acme_workspace.organization_id, acme.id);
    assert!(store
        .list_organization_workspaces(&beta.id)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.list_organization_workspaces(&acme.id).unwrap(),
        vec![acme_workspace.clone()]
    );
    assert!(store
        .active_workspace_in_organization(&acme.id, &acme_workspace.id)
        .unwrap());
    assert!(!store
        .active_workspace_in_organization(&beta.id, &acme_workspace.id)
        .unwrap());

    assert!(store.set_organization_active(&acme.id, false).unwrap());
    assert!(!store
        .active_workspace_in_organization(&acme.id, &acme_workspace.id)
        .unwrap());
    assert!(store
        .create_tenant_in_organization(&acme.id, "must fail")
        .is_err());
    let principal = store.create_workspace_principal("Acme user").unwrap();
    assert!(store
        .set_workspace_membership(&acme_workspace.id, &principal.id, WorkspaceRole::Owner)
        .is_err());
    assert!(store
        .set_organization_active(super::BOOTSTRAP_ORGANIZATION_ID, false)
        .is_err());
}

#[test]
fn opening_a_legacy_tenant_database_backfills_bootstrap_workspaces() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!(
        "llm-firewall-legacy-backfill-{}-{}.sqlite",
        std::process::id(),
        super::now_unix()
    ));
    let _ = std::fs::remove_file(&path);
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE tenants (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL
                );
                INSERT INTO tenants (id, name, active, created_at_unix)
                VALUES ('tenant_legacy', 'Legacy tenant', 1, 1);",
        )?;
    }

    let store = TenantStore::open(&path)?;
    let workspace = store
        .workspace_for_tenant("tenant_legacy")?
        .ok_or_else(|| anyhow::anyhow!("legacy tenant workspace was not backfilled"))?;
    assert_eq!(workspace.id, "workspace_tenant_legacy");
    assert_eq!(workspace.organization_id, super::BOOTSTRAP_ORGANIZATION_ID);
    assert_eq!(workspace.tenant_id, "tenant_legacy");
    assert!(workspace.active);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn organization_oidc_connections_are_https_only_and_require_an_active_organization() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store.create_organization("OIDC organization").unwrap();
    let saved = store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test/tenant-a",
            "firewall-control-plane",
            "https://console.example.test/auth/callback",
            true,
        )
        .unwrap();
    assert_eq!(saved.organization_id, organization.id);
    assert_eq!(saved.issuer, "https://id.example.test/tenant-a");
    assert!(saved.active);
    assert_eq!(
        store
            .organization_oidc_connection(&organization.id)
            .unwrap(),
        Some(saved.clone())
    );
    assert!(store
        .set_organization_oidc_connection(
            &organization.id,
            "http://id.example.test",
            "client",
            "https://console.example.test/auth/callback",
            true,
        )
        .is_err());
    assert!(store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test?unexpected=query",
            "client",
            "https://console.example.test/auth/callback",
            true,
        )
        .is_err());
    assert!(store
        .set_organization_active(&organization.id, false)
        .unwrap());
    assert!(store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test/tenant-a",
            "client",
            "https://console.example.test/auth/callback",
            true,
        )
        .is_err());
    assert!(store
        .delete_organization_oidc_connection(&organization.id)
        .unwrap());
    assert_eq!(
        store
            .organization_oidc_connection(&organization.id)
            .unwrap(),
        None
    );
}

#[test]
fn oidc_authorization_states_are_hashed_short_lived_and_single_use() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("OIDC state organization")
        .unwrap();
    store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test/tenant-a",
            "firewall-control-plane",
            "https://console.example.test/auth/callback",
            true,
        )
        .unwrap();
    let state = "opaque-state-that-must-not-be-stored-raw";
    store
        .reserve_oidc_authorization_state(state, &organization.id, super::now_unix() + 60)
        .unwrap();
    let raw_state_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM oidc_authorization_states
                 WHERE CAST(state_hash AS TEXT) = ?1",
            [state],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        raw_state_count, 0,
        "only a domain-separated state hash is stored"
    );
    assert!(store
        .consume_oidc_authorization_state(state, &organization.id)
        .unwrap());
    assert!(!store
        .consume_oidc_authorization_state(state, &organization.id)
        .unwrap());
    assert!(store
        .reserve_oidc_authorization_state("expired-state", &organization.id, super::now_unix() - 1,)
        .is_err());
}

#[test]
fn saml_authorization_state_persists_pending_request_and_is_single_use() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("SAML state organization")
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "SAML state tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    store
        .set_organization_saml_connection(
            &organization.id,
            "https://id.example.test/saml",
            "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            true,
        )
        .unwrap();
    let pending = SamlAuthorizationPending {
        organization_id: organization.id.clone(),
        workspace_id: workspace.id.clone(),
        invitation_id: None,
        request_id: "_request-1".into(),
        idp_entity_id: "https://id.example.test/saml".into(),
        expected_binding: "post".into(),
        request_binding: "redirect".into(),
        acs_url: "https://console.example.test/auth/saml/acs".into(),
        acs_binding: "post".into(),
    };
    let state = "opaque-saml-state";
    store
        .reserve_saml_authorization_state(state, &pending, super::now_unix() + 60)
        .unwrap();
    let raw_state_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM saml_authorization_states
                 WHERE CAST(state_hash AS TEXT) = ?1",
            [state],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(raw_state_count, 0);
    assert_eq!(
        store.consume_saml_authorization_state(state).unwrap(),
        Some(pending)
    );
    assert_eq!(store.consume_saml_authorization_state(state).unwrap(), None);
}

#[test]
fn saml_identity_and_browser_session_require_the_active_saml_connection() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("SAML browser session organization")
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "SAML browser session tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let issuer = "https://id.example.test/saml";
    store
        .set_organization_saml_connection(
            &organization.id,
            issuer,
            "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            true,
        )
        .unwrap();
    let principal = store.create_workspace_principal("SAML member").unwrap();
    store
        .link_workspace_external_identity(&principal.id, issuer, "member-123")
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Admin)
        .unwrap();

    let access = store
        .verified_saml_identity_workspace_access(
            &organization.id,
            &workspace.id,
            issuer,
            "member-123",
        )
        .unwrap()
        .expect("active SAML identity has the explicit workspace membership");
    assert_eq!(access.role, WorkspaceRole::Admin);
    let session = store
        .issue_oidc_browser_session(
            &access,
            BrowserSessionFederation::Saml,
            super::now_unix() + 3_600,
        )
        .unwrap();
    assert!(store
        .authenticate_oidc_browser_session(&session.token)
        .unwrap()
        .is_some());

    store
        .set_organization_saml_connection(
            &organization.id,
            issuer,
            "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            false,
        )
        .unwrap();
    assert_eq!(
        store
            .authenticate_oidc_browser_session(&session.token)
            .unwrap(),
        None,
        "disabling SAML invalidates sessions established by SAML without affecting OIDC policy"
    );
}

#[test]
fn oidc_browser_sessions_are_hashed_revocable_and_recheck_rbac() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("OIDC session organization")
        .unwrap();
    store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test/session",
            "firewall-control-plane",
            "https://console.example.test/auth/oidc/callback",
            true,
        )
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Session production")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let principal = store.create_workspace_principal("Session user").unwrap();
    store
        .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Developer)
        .unwrap();
    let access = super::VerifiedWorkspaceAccess {
        organization_id: organization.id.clone(),
        workspace_id: workspace.id.clone(),
        principal_id: principal.id.clone(),
        role: WorkspaceRole::Developer,
    };
    let issued = store
        .issue_oidc_browser_session(
            &access,
            BrowserSessionFederation::Oidc,
            super::now_unix() + 3_600,
        )
        .unwrap();
    let raw_token_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM oidc_browser_sessions
                 WHERE CAST(session_hash AS TEXT) = ?1",
            [&issued.token],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(raw_token_count, 0, "only a session hash is stored");
    assert_eq!(
        store
            .authenticate_oidc_browser_session(&issued.token)
            .unwrap()
            .map(|session| session.access.role),
        Some(WorkspaceRole::Developer)
    );
    let rotated = store
        .rotate_oidc_browser_session(&issued.token, super::now_unix() + 3_600)
        .unwrap()
        .unwrap();
    assert!(store
        .authenticate_oidc_browser_session(&issued.token)
        .unwrap()
        .is_none());
    assert!(store
        .authenticate_oidc_browser_session(&rotated.token)
        .unwrap()
        .is_some());

    store
        .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Admin)
        .unwrap();
    assert_eq!(
        store
            .authenticate_oidc_browser_session(&rotated.token)
            .unwrap()
            .map(|session| session.access.role),
        Some(WorkspaceRole::Admin),
        "the cookie has no stale role claim"
    );
    assert!(store.revoke_oidc_browser_session(&rotated.token).unwrap());
    assert!(!store.revoke_oidc_browser_session(&rotated.token).unwrap());
    assert_eq!(
        store
            .authenticate_oidc_browser_session(&rotated.token)
            .unwrap(),
        None
    );

    let another = store
        .issue_oidc_browser_session(
            &access,
            BrowserSessionFederation::Oidc,
            super::now_unix() + 3_600,
        )
        .unwrap();
    store
        .set_organization_oidc_connection(
            &organization.id,
            "https://id.example.test/session",
            "firewall-control-plane",
            "https://console.example.test/auth/oidc/callback",
            false,
        )
        .unwrap();
    assert_eq!(
        store
            .authenticate_oidc_browser_session(&another.token)
            .unwrap(),
        None,
        "disabling the OIDC connection invalidates existing browser sessions"
    );
}

#[test]
fn external_identities_are_opaque_unique_and_ignore_inactive_principals() {
    let store = TenantStore::open(":memory:").unwrap();
    let alice = store.create_workspace_principal("Alice").unwrap();
    let binding = store
        .link_workspace_external_identity(
            &alice.id,
            "https://id.example.test/tenant-a",
            "00u-alice-opaque-subject",
        )
        .unwrap();
    assert_eq!(binding.principal_id, alice.id);
    assert_eq!(
        store
            .workspace_principal_for_external_identity(
                "https://id.example.test/tenant-a",
                "00u-alice-opaque-subject",
            )
            .unwrap(),
        Some(alice.clone())
    );
    let bob = store.create_workspace_principal("Bob").unwrap();
    assert!(store
        .link_workspace_external_identity(
            &bob.id,
            "https://id.example.test/tenant-a",
            "00u-alice-opaque-subject",
        )
        .is_err());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE workspace_principals SET active = 0 WHERE id = ?1",
            [&alice.id],
        )
        .unwrap();
    assert_eq!(
        store
            .workspace_principal_for_external_identity(
                "https://id.example.test/tenant-a",
                "00u-alice-opaque-subject",
            )
            .unwrap(),
        None
    );
}

#[test]
fn verified_oidc_identity_requires_the_selected_connection_and_membership() {
    let store = TenantStore::open(":memory:").unwrap();
    let acme = store.create_organization("Acme").unwrap();
    let beta = store.create_organization("Beta").unwrap();
    let issuer = "https://id.example.test/shared";
    for organization in [&acme, &beta] {
        store
            .set_organization_oidc_connection(
                &organization.id,
                issuer,
                "firewall-console",
                "https://console.example.test/auth/callback",
                true,
            )
            .unwrap();
    }
    let acme_tenant = store
        .create_tenant_in_organization(&acme.id, "Acme production")
        .unwrap();
    let acme_workspace = store
        .workspace_for_tenant(&acme_tenant.id)
        .unwrap()
        .unwrap();
    let beta_tenant = store
        .create_tenant_in_organization(&beta.id, "Beta production")
        .unwrap();
    let beta_workspace = store
        .workspace_for_tenant(&beta_tenant.id)
        .unwrap()
        .unwrap();
    let principal = store.create_workspace_principal("Acme operator").unwrap();
    store
        .link_workspace_external_identity(&principal.id, issuer, "opaque-subject")
        .unwrap();
    store
        .set_workspace_membership(&acme_workspace.id, &principal.id, WorkspaceRole::Admin)
        .unwrap();

    let access = store
        .verified_identity_workspace_access(&acme.id, &acme_workspace.id, issuer, "opaque-subject")
        .unwrap()
        .expect("the verified identity has an active Acme membership");
    assert_eq!(access.principal_id, principal.id);
    assert_eq!(access.role, WorkspaceRole::Admin);
    assert!(access.permits(WorkspacePermission::ManagePolicies));
    assert!(!access.permits(WorkspacePermission::ManageMembership));
    assert_eq!(
        store
            .verified_identity_workspace_access(
                &beta.id,
                &beta_workspace.id,
                issuer,
                "opaque-subject",
            )
            .unwrap(),
        None,
        "the same IdP subject must not cross organization/workspace boundaries"
    );

    store
        .set_organization_oidc_connection(
            &acme.id,
            issuer,
            "firewall-console",
            "https://console.example.test/auth/callback",
            false,
        )
        .unwrap();
    assert_eq!(
        store
            .verified_identity_workspace_access(
                &acme.id,
                &acme_workspace.id,
                issuer,
                "opaque-subject",
            )
            .unwrap(),
        None,
        "disabling an OIDC connection immediately revokes its login path"
    );
}

#[tokio::test]
#[ignore = "requires LLM_FW_TEST_POSTGRES_URL pointing at a disposable PostgreSQL instance"]
async fn postgres_control_plane_persists_tenants_tokens_policies_and_audit() {
    let url = std::env::var("LLM_FW_TEST_POSTGRES_URL")
        .expect("PostgreSQL integration test URL must be configured");
    let store = TenantStore::open_postgres_for_test(&url, 2).await.unwrap();
    let tenant = store
        .create_tenant_async(&format!("PostgreSQL {}", super::random_id("test")))
        .await
        .unwrap();
    let issued = store
        .issue_token_async(&tenant.id, "production")
        .await
        .unwrap();
    let header = format!("Bearer {}", issued.token);
    assert_eq!(
        store
            .authenticate_bearer_async(Some(&header))
            .await
            .unwrap(),
        Some(super::TenantIdentity {
            tenant_id: tenant.id.clone(),
            tenant_name: tenant.name.clone(),
        })
    );

    let limits = TenantLimits {
        rate_limit: Some(TenantRateLimit {
            requests_per_window: 7,
            window_seconds: 60,
        }),
        spend_limit: Some(TenantSpendLimit {
            window_seconds: 86_400,
            max_usd_micros: 1_000_000,
            reserve_usd_micros_per_request: 50_000,
        }),
    };
    store
        .set_limits_async(&tenant.id, limits.clone())
        .await
        .unwrap();
    assert_eq!(store.limits_for_async(&tenant.id).await.unwrap(), limits);

    let policy = TenantModelPolicy {
        allowed_models: vec!["gpt-test".into()],
    };
    store
        .set_model_policy_async(&tenant.id, Some(policy.clone()))
        .await
        .unwrap();
    assert_eq!(
        store.model_policy_for_async(&tenant.id).await.unwrap(),
        Some(policy)
    );
    let access = store
        .authenticate_access_async(Some(&header))
        .await
        .unwrap()
        .expect("active PostgreSQL token authenticates");
    assert_eq!(access.identity.tenant_id, tenant.id);
    assert_eq!(access.limits, limits);
    assert!(access
        .model_policy
        .as_ref()
        .is_some_and(|policy| policy.permits("gpt-test")));

    let usage_request_id = super::random_id("req_postgres_usage");
    let usage = priced_usage_event(&tenant.id, &usage_request_id);
    assert!(store.append_usage_event_async(&usage).await.unwrap());
    assert!(!store.append_usage_event_async(&usage).await.unwrap());
    let stored_usage = store.list_usage_events_async(&tenant.id, 10).await.unwrap();
    assert!(stored_usage
        .iter()
        .any(|event| event.request_id == usage_request_id && event.cost_usd_micros == Some(11)));

    let workspace = store
        .workspace_for_tenant_async(&tenant.id)
        .await
        .unwrap()
        .expect("a PostgreSQL tenant receives a workspace in the migration");
    let principal = store
        .create_workspace_principal_async("PostgreSQL owner")
        .await
        .unwrap();
    let external_identity = store
        .link_workspace_external_identity_async(
            &principal.id,
            "https://id.example.test/postgresql",
            &format!("postgres-subject-{}", super::random_id("test")),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .workspace_principal_for_external_identity_async(
                &external_identity.issuer,
                &external_identity.subject,
            )
            .await
            .unwrap(),
        Some(principal.clone())
    );
    store
        .set_workspace_membership_async(&workspace.id, &principal.id, WorkspaceRole::Owner)
        .await
        .unwrap();
    assert!(store
        .workspace_permits_async(
            &principal.id,
            &workspace.id,
            WorkspacePermission::ManageTenant
        )
        .await
        .unwrap());
    let workspace_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 10)
        .await
        .unwrap();
    assert_eq!(workspace_audit.len(), 1);
    assert_eq!(workspace_audit[0].action, "membership.upsert");

    let outsider = store
        .create_workspace_principal_async("PostgreSQL service-account outsider")
        .await
        .unwrap();
    let expires_at_unix = super::now_unix() + 3_600;
    assert!(store
        .create_workspace_service_account_async(
            &workspace.id,
            &outsider.id,
            "denied-machine",
            expires_at_unix,
        )
        .await
        .is_err());
    assert!(store
        .list_workspace_service_accounts_async(&workspace.id, &principal.id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_workspace_admin_audit_async(&workspace.id, 10)
            .await
            .unwrap(),
        workspace_audit,
        "denied service-account issuance must not append an audit event"
    );
    let service_account = store
        .create_workspace_service_account_async(
            &workspace.id,
            &principal.id,
            "retained-machine",
            expires_at_unix,
        )
        .await
        .unwrap();
    assert_eq!(service_account.account.workspace_id, workspace.id);
    assert_eq!(service_account.account.name, "retained-machine");
    assert_eq!(
        service_account.account.created_by_principal_id,
        principal.id
    );
    assert!(service_account.account.active);
    assert_eq!(service_account.account.expires_at_unix, expires_at_unix);
    assert!(service_account.account.revoked_at_unix.is_none());
    assert_eq!(
        store
            .list_workspace_service_accounts_async(&workspace.id, &principal.id)
            .await
            .unwrap(),
        vec![service_account.account.clone()],
        "issuance must return the metadata actually inserted in PostgreSQL"
    );
    let service_header = format!("Bearer {}", service_account.token);
    let service_access = store
        .authenticate_access_async(Some(&service_header))
        .await
        .unwrap()
        .expect("issued PostgreSQL service-account token authenticates");
    assert_eq!(service_access.identity.tenant_id, tenant.id);
    assert_eq!(service_access.limits, limits);
    assert!(service_access
        .model_policy
        .as_ref()
        .is_some_and(|policy| policy.permits("gpt-test")));
    let issued_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 10)
        .await
        .unwrap();
    assert_eq!(issued_audit.len(), 2);
    let create_event = issued_audit
        .iter()
        .find(|event| event.action == "service_account.create")
        .expect("issuance is audited once");
    assert_eq!(
        create_event.actor_principal_id.as_deref(),
        Some(principal.id.as_str())
    );
    assert_eq!(
        create_event.target_principal_id.as_deref(),
        Some(principal.id.as_str())
    );
    assert!(!store
        .revoke_workspace_service_account_async(
            &workspace.id,
            &service_account.account.id,
            &outsider.id,
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .list_workspace_admin_audit_async(&workspace.id, 10)
            .await
            .unwrap(),
        issued_audit,
        "denied revocation must not append an audit event"
    );
    assert!(store
        .authenticate_access_async(Some(&service_header))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .revoke_workspace_service_account_async(
            &workspace.id,
            &service_account.account.id,
            &principal.id,
        )
        .await
        .unwrap());
    assert!(store
        .authenticate_access_async(Some(&service_header))
        .await
        .unwrap()
        .is_none());
    let revoked_accounts = store
        .list_workspace_service_accounts_async(&workspace.id, &principal.id)
        .await
        .unwrap();
    assert_eq!(revoked_accounts.len(), 1);
    assert_eq!(revoked_accounts[0].id, service_account.account.id);
    assert!(!revoked_accounts[0].active);
    assert!(revoked_accounts[0].revoked_at_unix.is_some());
    let revoked_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 10)
        .await
        .unwrap();
    assert_eq!(revoked_audit.len(), 3);
    assert_eq!(
        revoked_audit
            .iter()
            .filter(|event| event.action == "service_account.revoke")
            .count(),
        1
    );
    assert!(!store
        .revoke_workspace_service_account_async(
            &workspace.id,
            &service_account.account.id,
            &principal.id,
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .list_workspace_admin_audit_async(&workspace.id, 10)
            .await
            .unwrap(),
        revoked_audit,
        "repeated revocation must not append another audit event"
    );

    let managed_member = store
        .create_workspace_principal_async("PostgreSQL managed member")
        .await
        .unwrap();
    store
        .set_workspace_membership_async(&workspace.id, &managed_member.id, WorkspaceRole::Analyst)
        .await
        .unwrap();
    let members = store
        .list_workspace_members_async(&workspace.id)
        .await
        .unwrap();
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|member| member.principal_id == managed_member.id));
    let updated_member = store
        .update_workspace_membership_as_owner_async(
            &workspace.id,
            &principal.id,
            &managed_member.id,
            WorkspaceRole::Developer,
            false,
        )
        .await
        .unwrap();
    assert_eq!(updated_member.role, WorkspaceRole::Developer);
    assert!(!updated_member.active);
    assert!(store
        .update_workspace_membership_as_owner_async(
            &workspace.id,
            &principal.id,
            &principal.id,
            WorkspaceRole::Admin,
            true,
        )
        .await
        .is_err());
    let workspace_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 1)
        .await
        .unwrap();
    assert_eq!(workspace_audit[0].action, "membership.update");
    assert_eq!(
        workspace_audit[0].actor_principal_id.as_deref(),
        Some(principal.id.as_str())
    );

    let customer_policy = TenantModelPolicy {
        allowed_models: vec!["gpt-customer-policy".into()],
    };
    store
        .set_workspace_model_policy_async(
            &workspace.id,
            &principal.id,
            Some(customer_policy.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        store.model_policy_for_async(&tenant.id).await.unwrap(),
        Some(customer_policy)
    );
    let policy_versions = store
        .list_policy_versions_async(&tenant.id, 10)
        .await
        .unwrap();
    assert!(policy_versions.iter().any(|version| {
        version.active
            && version.approved_by.as_deref() == Some(principal.id.as_str())
            && version.created_by == principal.id
    }));
    let workspace_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 1)
        .await
        .unwrap();
    assert_eq!(workspace_audit[0].action, "model_policy.set");
    assert_eq!(
        workspace_audit[0].actor_principal_id,
        Some(principal.id.clone())
    );
    let customer_limits = TenantLimits {
        rate_limit: Some(TenantRateLimit {
            requests_per_window: 11,
            window_seconds: 90,
        }),
        spend_limit: Some(TenantSpendLimit {
            window_seconds: 3_600,
            max_usd_micros: 2_000_000,
            reserve_usd_micros_per_request: 50_000,
        }),
    };
    store
        .set_workspace_limits_async(&workspace.id, &principal.id, customer_limits.clone())
        .await
        .unwrap();
    assert_eq!(
        store.limits_for_async(&tenant.id).await.unwrap(),
        customer_limits
    );
    let workspace_audit = store
        .list_workspace_admin_audit_async(&workspace.id, 1)
        .await
        .unwrap();
    assert_eq!(workspace_audit[0].action, "limits.set");
    assert_eq!(
        workspace_audit[0].actor_principal_id,
        Some(principal.id.clone())
    );
    store
        .set_workspace_membership_async(&workspace.id, &principal.id, WorkspaceRole::Developer)
        .await
        .unwrap();
    assert!(store
        .set_workspace_model_policy_async(&workspace.id, &principal.id, None)
        .await
        .is_err());
    assert!(store
        .set_workspace_limits_async(&workspace.id, &principal.id, TenantLimits::default())
        .await
        .is_err());

    let organization = store
        .create_organization_async(&format!("PostgreSQL org {}", super::random_id("test")))
        .await
        .unwrap();
    let scim_credential = store
        .issue_scim_token_async(
            &organization.id,
            "PostgreSQL identity provider",
            super::now_unix() + 3_600,
        )
        .await
        .unwrap();
    let scim_header = format!("Bearer {}", scim_credential.token);
    let scim_identity = store
        .authenticate_scim_bearer_async(Some(&scim_header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        scim_identity,
        super::ScimIdentity {
            organization_id: organization.id.clone(),
            token_id: scim_credential.credential.id.clone(),
        }
    );
    assert_eq!(
        store
            .list_scim_tokens_async(&organization.id)
            .await
            .unwrap(),
        vec![scim_credential.credential.clone()]
    );
    let scim_user = store
        .create_scim_user_async(
            &scim_identity,
            "postgres-idp-user",
            "postgres-user@example.test",
            "PostgreSQL SCIM user",
            true,
        )
        .await
        .unwrap();
    let scim_group = store
        .create_scim_group_async(
            &scim_identity,
            "postgres-idp-group",
            "PostgreSQL SCIM group",
            vec![scim_user.id.clone()],
        )
        .await
        .unwrap();
    assert_eq!(scim_group.member_ids, vec![scim_user.id.clone()]);
    let updated_group = store
        .update_scim_group_async(
            &scim_identity,
            &scim_group.id,
            super::ScimGroupUpdate {
                member_change: Some(super::ScimGroupMemberChange::Remove(vec![scim_user
                    .id
                    .clone()])),
                ..super::ScimGroupUpdate::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(updated_group.member_ids.is_empty());
    assert!(store
        .delete_scim_group_async(&scim_identity, &scim_group.id)
        .await
        .unwrap());
    assert!(store
        .revoke_scim_token_async(&scim_credential.credential.id)
        .await
        .unwrap());
    assert_eq!(
        store
            .authenticate_scim_bearer_async(Some(&scim_header))
            .await
            .unwrap(),
        None
    );
    let oidc_connection = store
        .set_organization_oidc_connection_async(
            &organization.id,
            "https://id.example.test/postgresql",
            "postgresql-firewall-console",
            "https://console.example.test/auth/callback",
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .organization_oidc_connection_async(&organization.id)
            .await
            .unwrap(),
        Some(oidc_connection)
    );
    let state = format!("postgres-state-{}", super::random_id("test"));
    store
        .reserve_oidc_authorization_state_async(&state, &organization.id, super::now_unix() + 60)
        .await
        .unwrap();
    assert!(store
        .consume_oidc_authorization_state_async(&state, &organization.id)
        .await
        .unwrap());
    assert!(!store
        .consume_oidc_authorization_state_async(&state, &organization.id)
        .await
        .unwrap());
    let organization_tenant = store
        .create_tenant_in_organization_async(
            &organization.id,
            &format!("PostgreSQL org tenant {}", super::random_id("test")),
        )
        .await
        .unwrap();
    let organization_workspace = store
        .workspace_for_tenant_async(&organization_tenant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(organization_workspace.organization_id, organization.id);
    store
        .set_workspace_membership_async(
            &organization_workspace.id,
            &principal.id,
            WorkspaceRole::Admin,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .verified_identity_workspace_access_async(
                &organization.id,
                &organization_workspace.id,
                &external_identity.issuer,
                &external_identity.subject,
            )
            .await
            .unwrap()
            .map(|access| access.role),
        Some(WorkspaceRole::Admin)
    );
    let invitation_owner = store
        .create_workspace_principal_async("PostgreSQL invitation owner")
        .await
        .unwrap();
    store
        .set_workspace_membership_async(
            &organization_workspace.id,
            &invitation_owner.id,
            WorkspaceRole::Owner,
        )
        .await
        .unwrap();
    let issued_invitation = store
        .create_workspace_invitation_as_owner_async(
            &organization_workspace.id,
            &invitation_owner.id,
            "PostgreSQL invited developer",
            WorkspaceRole::Developer,
            super::now_unix() + 600,
        )
        .await
        .unwrap();
    assert!(issued_invitation.token.starts_with("llmfw_invite_"));
    assert_eq!(
        store
            .list_workspace_invitations_as_owner_async(
                &organization_workspace.id,
                &invitation_owner.id,
            )
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .workspace_invitation_for_token_async(&issued_invitation.token)
            .await
            .unwrap()
            .map(|invitation| invitation.id),
        Some(issued_invitation.invitation.id.clone())
    );
    assert!(store
        .accept_workspace_invitation_oidc_async(
            &issued_invitation.invitation.id,
            &organization.id,
            &workspace.id,
            &external_identity.issuer,
            "postgres-invited-subject",
        )
        .await
        .unwrap()
        .is_none());
    assert!(store
        .workspace_invitation_for_token_async(&issued_invitation.token)
        .await
        .unwrap()
        .is_some());
    let invited_access = store
        .accept_workspace_invitation_oidc_async(
            &issued_invitation.invitation.id,
            &organization.id,
            &organization_workspace.id,
            &external_identity.issuer,
            "postgres-invited-subject",
        )
        .await
        .unwrap()
        .expect("PostgreSQL invitation accepts a verified identity");
    assert_eq!(invited_access.role, WorkspaceRole::Developer);
    assert!(store
        .workspace_invitation_for_token_async(&issued_invitation.token)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .accept_workspace_invitation_oidc_async(
            &issued_invitation.invitation.id,
            &organization.id,
            &organization_workspace.id,
            &external_identity.issuer,
            "postgres-invited-subject",
        )
        .await
        .unwrap()
        .is_none());
    let verified_access = store
        .verified_identity_workspace_access_async(
            &organization.id,
            &organization_workspace.id,
            &external_identity.issuer,
            &external_identity.subject,
        )
        .await
        .unwrap()
        .expect("PostgreSQL verified identity receives a browser session");
    let browser_session = store
        .issue_oidc_browser_session_async(
            &verified_access,
            BrowserSessionFederation::Oidc,
            super::now_unix() + 3_600,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .authenticate_oidc_browser_session_async(&browser_session.token)
            .await
            .unwrap()
            .map(|session| session.access.role),
        Some(WorkspaceRole::Admin)
    );
    assert!(store
        .revoke_oidc_browser_session_async(&browser_session.token)
        .await
        .unwrap());
    assert_eq!(
        store
            .authenticate_oidc_browser_session_async(&browser_session.token)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .list_organization_workspaces_async(&organization.id)
            .await
            .unwrap(),
        vec![organization_workspace]
    );
    assert!(store
        .set_organization_active_async(&organization.id, false)
        .await
        .unwrap());
    assert!(store
        .create_tenant_in_organization_async(&organization.id, "must fail")
        .await
        .is_err());

    store
        .append_audit_async(&tenant.id, "/v1/chat/completions", "completed", 200, 12)
        .await
        .unwrap();
    store
        .append_audit_async(&tenant.id, "/v1/responses", "rejected", 429, 1)
        .await
        .unwrap();
    store
        .append_audit_async(&tenant.id, "/v1/messages", "completed", 200, 8)
        .await
        .unwrap();
    let audit = store.list_audit_async(&tenant.id, 100).await.unwrap();
    assert_eq!(audit.len(), 2, "configured retention applies");
    assert_eq!(audit[0].path, "/v1/messages");
    assert_eq!(audit[1].outcome, "rejected");

    assert!(store.revoke_token_async(&issued.id).await.unwrap());
    assert_eq!(
        store
            .authenticate_bearer_async(Some(&header))
            .await
            .unwrap(),
        None
    );
}
