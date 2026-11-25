// SPDX-License-Identifier: Apache-2.0
use super::*;
use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};

#[tokio::test]
async fn managed_async_ack_retry_is_idempotent_but_stale_or_conflicting_is_refused() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("retry-test").unwrap();
    let issued = store
        .enroll_managed_agent_async(&tenant.id, "agent-a")
        .await
        .unwrap();
    let bearer = format!("Bearer {}", issued.token);
    assert!(store
        .authenticate_managed_agent_async(Some(&bearer))
        .await
        .unwrap()
        .is_some());
    let signer = ManagedIssuer {
        key_id: "k1".into(),
        pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
    };
    store
        .create_managed_revision_async(&tenant.id, "agent-a", "v1", "default: deny\n")
        .await
        .unwrap();
    store
        .approve_managed_revision_async(&tenant.id, "agent-a", "v1")
        .await
        .unwrap();
    store
        .deploy_managed_revision_async(&tenant.id, "agent-a", "v1", false, &signer)
        .await
        .unwrap();
    let bundle = store
        .deliver_managed_bundle_async(&tenant.id, "agent-a")
        .await
        .unwrap()
        .unwrap();
    let repeated = store
        .deliver_managed_bundle_async(&tenant.id, "agent-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&bundle).unwrap(),
        serde_json::to_value(&repeated).unwrap()
    );
    let mut report = AppliedReport {
        deployment_sequence: 1,
        revision: "v1".into(),
        policy_sha256: bundle.policy_sha256,
        status: "applied".into(),
    };
    assert!(store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    let before = store
        .list_managed_deployments_async(&tenant.id, "agent-a")
        .await
        .unwrap();
    assert!(store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    let after = store
        .list_managed_deployments_async(&tenant.id, "agent-a")
        .await
        .unwrap();
    assert_eq!(before[0].applied_at_unix, after[0].applied_at_unix);
    report.status = "rejected".into();
    assert!(!store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    assert!(store
        .deliver_managed_bundle_async(&tenant.id, "agent-a")
        .await
        .unwrap()
        .is_none());
    store
        .deploy_managed_revision_async(&tenant.id, "agent-a", "v1", false, &signer)
        .await
        .unwrap();
    report.status = "applied".into();
    assert!(!store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    report.deployment_sequence = 2;
    report.status = "rejected".into();
    assert!(store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    assert!(store
        .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
        .await
        .unwrap());
    assert!(store
        .revoke_managed_agent_async(&tenant.id, "agent-a")
        .await
        .unwrap());
    assert!(store
        .authenticate_managed_agent_async(Some(&bearer))
        .await
        .unwrap()
        .is_none());
}

#[test]
fn approved_deployment_is_signed_and_rollback_increases_sequence() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("managed-issuer-test").unwrap();
    store.enroll_managed_agent(&tenant.id, "agent-a").unwrap();
    store
        .create_managed_revision(&tenant.id, "agent-a", "v1", "default: deny\n")
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "agent-a", "v2", "default: allow\n")
        .unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
    let signer = ManagedIssuer {
        key_id: "k1".into(),
        pair,
    };
    assert!(store
        .deploy_managed_revision(&tenant.id, "agent-a", "v1", false, &signer)
        .is_err());
    assert!(store
        .approve_managed_revision(&tenant.id, "agent-a", "v1")
        .unwrap());
    assert!(store
        .approve_managed_revision(&tenant.id, "agent-a", "v2")
        .unwrap());
    let a = store
        .deploy_managed_revision(&tenant.id, "agent-a", "v1", false, &signer)
        .unwrap();
    assert_eq!(a.deployment_sequence, 1);
    let b = store
        .deliver_managed_bundle(&tenant.id, "agent-a")
        .unwrap()
        .unwrap();
    let signature = hex(signer.pair.sign(&b.transcript().unwrap()).as_ref());
    assert_eq!(signature, b.signature_hex);
    assert!(
        UnparsedPublicKey::new(&ED25519, signer.pair.public_key().as_ref())
            .verify(&b.transcript().unwrap(), &{
                let mut bytes = [0u8; 64];
                for (i, chunk) in b
                    .signature_hex
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .enumerate()
                {
                    bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()
                }
                bytes
            })
            .is_ok()
    );
    assert!(store
        .acknowledge_managed_bundle(
            &tenant.id,
            "agent-a",
            &AppliedReport {
                deployment_sequence: 1,
                revision: "v1".into(),
                policy_sha256: b.policy_sha256.clone(),
                status: "applied".into()
            }
        )
        .unwrap());
    store
        .deploy_managed_revision(&tenant.id, "agent-a", "v2", false, &signer)
        .unwrap();
    let r = store
        .deploy_managed_revision(&tenant.id, "agent-a", "v1", true, &signer)
        .unwrap();
    assert_eq!(r.deployment_sequence, 3);
    assert_eq!(r.action, "rollback");
    assert!(!store
        .acknowledge_managed_bundle(
            &tenant.id,
            "agent-a",
            &AppliedReport {
                deployment_sequence: 1,
                revision: "v1".into(),
                policy_sha256: b.policy_sha256,
                status: "applied".into()
            }
        )
        .unwrap());
    assert_eq!(
        store
            .list_managed_deployments(&tenant.id, "agent-a")
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn test_group_lifecycle_membership_and_revisions() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("group-tenant").unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

    // 1. Create group
    let group = store
        .create_managed_group(&tenant.id, "prod-agents", "Production Agents")
        .unwrap();
    assert_eq!(group.group_id, "prod-agents");
    assert_eq!(group.name, "Production Agents");

    // 2. Add members: pilot and standard
    let m1 = store
        .add_managed_group_member(&tenant.id, "prod-agents", "pilot-1", true)
        .unwrap();
    assert!(m1.is_pilot);
    let m2 = store
        .add_managed_group_member(&tenant.id, "prod-agents", "worker-1", false)
        .unwrap();
    assert!(!m2.is_pilot);

    let members = store
        .list_managed_group_members(&tenant.id, "prod-agents")
        .unwrap();
    assert_eq!(members.len(), 2);

    // 3. Group revisions
    let rev = store
        .create_managed_group_revision(&tenant.id, "prod-agents", "v1", "default: deny\n")
        .unwrap();
    assert_eq!(rev.revision, "v1");
    assert!(!rev.approved);

    assert!(store
        .approve_managed_group_revision(&tenant.id, "prod-agents", "v1")
        .unwrap());
}

#[test]
fn test_staged_group_rollout_pilot_success_promotes_to_standard() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("rollout-tenant").unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

    store
        .create_managed_group(&tenant.id, "cluster-a", "Cluster A")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "cluster-a", "pilot-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "cluster-a", "worker-1", false)
        .unwrap();

    let signer = ManagedIssuer {
        key_id: "k1".into(),
        pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
    };

    // Baseline revision v1 deployed to both
    store
        .create_managed_group_revision(&tenant.id, "cluster-a", "v1", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "cluster-a", "v1")
        .unwrap();

    // Target candidate revision v2
    store
        .create_managed_group_revision(&tenant.id, "cluster-a", "v2", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "cluster-a", "v2")
        .unwrap();

    // Start rollout
    let ro = store
        .start_managed_group_rollout(&tenant.id, "cluster-a", "v2", &signer)
        .unwrap();
    assert_eq!(ro.phase, RolloutPhase::Pilot);
    assert_eq!(ro.pilot_agents, vec!["pilot-1"]);
    assert_eq!(ro.standard_agents, vec!["worker-1"]);

    // Pilot received v2 deployment
    let p_bundle = store
        .deliver_managed_bundle(&tenant.id, "pilot-1")
        .unwrap()
        .unwrap();
    assert_eq!(p_bundle.revision, "v2");
    // Worker did NOT receive v2 deployment yet
    let w_bundle = store
        .deliver_managed_bundle(&tenant.id, "worker-1")
        .unwrap();
    assert!(w_bundle.is_none());

    // Pilot acknowledges applied
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &AppliedReport {
                deployment_sequence: p_bundle.deployment_sequence,
                revision: "v2".into(),
                policy_sha256: p_bundle.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Advance rollout
    let advanced = store
        .advance_managed_group_rollout(&tenant.id, "cluster-a", Some(&signer))
        .unwrap()
        .unwrap();
    assert_eq!(advanced.phase, RolloutPhase::Standard);

    // Now worker receives v2 deployment
    let w_bundle = store
        .deliver_managed_bundle(&tenant.id, "worker-1")
        .unwrap()
        .unwrap();
    assert_eq!(w_bundle.revision, "v2");

    // Worker acknowledges applied
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "worker-1",
            &AppliedReport {
                deployment_sequence: w_bundle.deployment_sequence,
                revision: "v2".into(),
                policy_sha256: w_bundle.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    let finished = store
        .get_managed_group_rollout(&tenant.id, "cluster-a")
        .unwrap()
        .unwrap();
    assert_eq!(finished.phase, RolloutPhase::Completed);
}

#[test]
fn test_staged_group_rollout_pilot_rejection_auto_rollbacks_and_spares_standard() {
    let store = TenantStore::open(":memory:").unwrap();
    let tenant = store.create_tenant("rollback-tenant").unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

    store
        .create_managed_group(&tenant.id, "cluster-b", "Cluster B")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "cluster-b", "pilot-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "cluster-b", "worker-1", false)
        .unwrap();

    let signer = ManagedIssuer {
        key_id: "k1".into(),
        pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
    };

    // Deploy initial baseline v1 to pilot-1
    store
        .create_managed_revision(&tenant.id, "pilot-1", "v1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pilot-1", "v1")
        .unwrap();
    let p_v1 = store
        .deploy_managed_revision(&tenant.id, "pilot-1", "v1", false, &signer)
        .unwrap();
    store.deliver_managed_bundle(&tenant.id, "pilot-1").unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &AppliedReport {
                deployment_sequence: p_v1.deployment_sequence,
                revision: "v1".into(),
                policy_sha256: p_v1.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Candidate revision v2 on group
    store
        .create_managed_group_revision(&tenant.id, "cluster-b", "v2", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "cluster-b", "v2")
        .unwrap();

    let ro = store
        .start_managed_group_rollout(&tenant.id, "cluster-b", "v2", &signer)
        .unwrap();
    assert_eq!(ro.phase, RolloutPhase::Pilot);

    // Pilot delivers bundle and REJECTS it
    let p_bundle = store
        .deliver_managed_bundle(&tenant.id, "pilot-1")
        .unwrap()
        .unwrap();
    assert_eq!(p_bundle.revision, "v2");

    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &AppliedReport {
                deployment_sequence: p_bundle.deployment_sequence,
                revision: "v2".into(),
                policy_sha256: p_bundle.policy_sha256.clone(),
                status: "rejected".into(),
            },
        )
        .unwrap();

    // Advance rollout: should detect rejection, trigger rollback to v1, set phase = RollingBack
    let ro_after = store
        .advance_managed_group_rollout(&tenant.id, "cluster-b", Some(&signer))
        .unwrap()
        .unwrap();
    assert_eq!(ro_after.phase, RolloutPhase::RollingBack);
    assert!(ro_after.failure_reason.unwrap().contains("rejected"));

    // Pilot now has a rollback deployment for v1 with higher sequence!
    let rollback_bundle = store
        .deliver_managed_bundle(&tenant.id, "pilot-1")
        .unwrap()
        .unwrap();
    assert_eq!(rollback_bundle.revision, "v1");
    assert!(rollback_bundle.deployment_sequence > p_bundle.deployment_sequence);

    // Pilot acknowledges the rollback deployment as applied
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &AppliedReport {
                deployment_sequence: rollback_bundle.deployment_sequence,
                revision: "v1".into(),
                policy_sha256: rollback_bundle.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Rollout is now confirmed RolledBack!
    let ro_confirmed = store
        .get_managed_group_rollout(&tenant.id, "cluster-b")
        .unwrap()
        .unwrap();
    assert_eq!(ro_confirmed.phase, RolloutPhase::RolledBack);

    // Worker was NEVER deployed candidate v2
    let worker_deployments = store
        .list_managed_deployments(&tenant.id, "worker-1")
        .unwrap();
    assert!(worker_deployments.is_empty());
}
