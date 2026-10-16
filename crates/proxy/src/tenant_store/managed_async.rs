// SPDX-License-Identifier: Apache-2.0
//! Backend dispatch for the existing managed Agent contract.
use super::*;
impl TenantStore {
    pub async fn enroll_managed_agent_async(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> anyhow::Result<IssuedAgentCredential> {
        match &self.postgres {
            Some(pg) => pg.enroll_managed_agent(tenant_id, agent_id).await,
            None => self.enroll_managed_agent(tenant_id, agent_id),
        }
    }
    pub async fn rotate_managed_agent_async(
        &self,
        tenant_id: &str,
        agent_id: &str,
        input: &RotationRequest,
    ) -> anyhow::Result<RotationOutcome> {
        match &self.postgres {
            Some(pg) => pg.rotate_managed_agent(tenant_id, agent_id, input).await,
            None => self.rotate_managed_agent(tenant_id, agent_id, input),
        }
    }
    pub async fn authenticate_managed_agent_async(
        &self,
        authorization: Option<&str>,
    ) -> anyhow::Result<Option<EnrolledAgent>> {
        match &self.postgres {
            Some(pg) => pg.authenticate_managed_agent(authorization).await,
            None => self.authenticate_managed_agent(authorization),
        }
    }
    pub async fn revoke_managed_agent_async(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => pg.revoke_managed_agent(tenant_id, agent_id).await,
            None => self.revoke_managed_agent(tenant_id, agent_id),
        }
    }
    pub async fn list_managed_agents_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<EnrolledAgent>> {
        match &self.postgres {
            Some(pg) => pg.list_managed_agents(tenant_id).await,
            None => self.list_managed_agents(tenant_id),
        }
    }
    pub async fn create_managed_revision_async(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        yaml: &str,
    ) -> anyhow::Result<ManagedRevision> {
        match &self.postgres {
            Some(pg) => {
                pg.create_managed_revision(tenant, agent, revision, yaml)
                    .await
            }
            None => self.create_managed_revision(tenant, agent, revision, yaml),
        }
    }
    pub async fn approve_managed_revision_async(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => pg.approve_managed_revision(tenant, agent, revision).await,
            None => self.approve_managed_revision(tenant, agent, revision),
        }
    }
    pub async fn deploy_managed_revision_async(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        rollback: bool,
        issuer: &ManagedIssuer,
    ) -> anyhow::Result<ManagedDeployment> {
        match &self.postgres {
            Some(pg) => {
                pg.deploy_managed_revision(tenant, agent, revision, rollback, issuer)
                    .await
            }
            None => self.deploy_managed_revision(tenant, agent, revision, rollback, issuer),
        }
    }
    pub async fn deliver_authorized_managed_bundle_async(
        &self,
        tenant: &str,
        agent: &str,
        bearer: &str,
    ) -> anyhow::Result<Option<SignedManagedBundle>> {
        match &self.postgres {
            Some(pg) => {
                pg.deliver_authorized_managed_bundle(tenant, agent, bearer)
                    .await
            }
            None => self.deliver_authorized_managed_bundle(tenant, agent, bearer),
        }
    }
    pub async fn acknowledge_authorized_managed_bundle_async(
        &self,
        tenant: &str,
        agent: &str,
        bearer: &str,
        report: &AppliedReport,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => {
                pg.acknowledge_authorized_managed_bundle(tenant, agent, bearer, report)
                    .await
            }
            None => self.acknowledge_authorized_managed_bundle(tenant, agent, bearer, report),
        }
    }
    pub async fn deliver_managed_bundle_async(
        &self,
        tenant: &str,
        agent: &str,
    ) -> anyhow::Result<Option<SignedManagedBundle>> {
        match &self.postgres {
            Some(pg) => pg.deliver_managed_bundle(tenant, agent).await,
            None => self.deliver_managed_bundle(tenant, agent),
        }
    }
    pub async fn acknowledge_managed_bundle_async(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => pg.acknowledge_managed_bundle(tenant, agent, report).await,
            None => self.acknowledge_managed_bundle(tenant, agent, report),
        }
    }
    pub async fn list_managed_deployments_async(
        &self,
        tenant: &str,
        agent: &str,
    ) -> anyhow::Result<Vec<ManagedDeployment>> {
        match &self.postgres {
            Some(pg) => pg.list_managed_deployments(tenant, agent).await,
            None => self.list_managed_deployments(tenant, agent),
        }
    }
    pub async fn create_managed_group_async(
        &self,
        tenant: &str,
        group_id: &str,
        name: &str,
    ) -> anyhow::Result<ManagedAgentGroup> {
        match &self.postgres {
            Some(pg) => pg.create_managed_group(tenant, group_id, name).await,
            None => self.create_managed_group(tenant, group_id, name),
        }
    }
    pub async fn list_managed_groups_async(
        &self,
        tenant: &str,
    ) -> anyhow::Result<Vec<ManagedAgentGroup>> {
        match &self.postgres {
            Some(pg) => pg.list_managed_groups(tenant).await,
            None => self.list_managed_groups(tenant),
        }
    }
    pub async fn get_managed_group_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<Option<ManagedAgentGroup>> {
        match &self.postgres {
            Some(pg) => pg.get_managed_group(tenant, group_id).await,
            None => self.get_managed_group(tenant, group_id),
        }
    }
    pub async fn delete_managed_group_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => pg.delete_managed_group(tenant, group_id).await,
            None => self.delete_managed_group(tenant, group_id),
        }
    }
    pub async fn add_managed_group_member_async(
        &self,
        tenant: &str,
        group_id: &str,
        agent_id: &str,
        is_pilot: bool,
    ) -> anyhow::Result<ManagedGroupMember> {
        match &self.postgres {
            Some(pg) => {
                pg.add_managed_group_member(tenant, group_id, agent_id, is_pilot)
                    .await
            }
            None => self.add_managed_group_member(tenant, group_id, agent_id, is_pilot),
        }
    }
    pub async fn remove_managed_group_member_async(
        &self,
        tenant: &str,
        group_id: &str,
        agent_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => {
                pg.remove_managed_group_member(tenant, group_id, agent_id)
                    .await
            }
            None => self.remove_managed_group_member(tenant, group_id, agent_id),
        }
    }
    pub async fn list_managed_group_members_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<Vec<ManagedGroupMember>> {
        match &self.postgres {
            Some(pg) => pg.list_managed_group_members(tenant, group_id).await,
            None => self.list_managed_group_members(tenant, group_id),
        }
    }
    pub async fn create_managed_group_revision_async(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
        yaml: &str,
    ) -> anyhow::Result<ManagedGroupRevision> {
        match &self.postgres {
            Some(pg) => {
                pg.create_managed_group_revision(tenant, group_id, revision, yaml)
                    .await
            }
            None => self.create_managed_group_revision(tenant, group_id, revision, yaml),
        }
    }
    pub async fn approve_managed_group_revision_async(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(pg) => {
                pg.approve_managed_group_revision(tenant, group_id, revision)
                    .await
            }
            None => self.approve_managed_group_revision(tenant, group_id, revision),
        }
    }
    pub async fn list_managed_group_revisions_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<Vec<ManagedGroupRevision>> {
        match &self.postgres {
            Some(pg) => pg.list_managed_group_revisions(tenant, group_id).await,
            None => self.list_managed_group_revisions(tenant, group_id),
        }
    }
    pub async fn start_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
        issuer: &ManagedIssuer,
    ) -> anyhow::Result<ManagedGroupRollout> {
        match &self.postgres {
            Some(pg) => {
                pg.start_managed_group_rollout(tenant, group_id, revision, issuer)
                    .await
            }
            None => self.start_managed_group_rollout(tenant, group_id, revision, issuer),
        }
    }
    pub async fn get_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<Option<ManagedGroupRollout>> {
        match &self.postgres {
            Some(pg) => pg.get_managed_group_rollout(tenant, group_id).await,
            None => self.get_managed_group_rollout(tenant, group_id),
        }
    }
    pub async fn advance_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: Option<&ManagedIssuer>,
    ) -> anyhow::Result<Option<ManagedGroupRollout>> {
        match &self.postgres {
            Some(pg) => {
                pg.advance_managed_group_rollout(tenant, group_id, issuer)
                    .await
            }
            None => self.advance_managed_group_rollout(tenant, group_id, issuer),
        }
    }
    pub async fn rollback_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> anyhow::Result<Option<ManagedGroupRollout>> {
        match &self.postgres {
            Some(pg) => {
                pg.rollback_managed_group_rollout(tenant, group_id, issuer)
                    .await
            }
            None => self.rollback_managed_group_rollout(tenant, group_id, issuer),
        }
    }
    pub async fn pause_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> anyhow::Result<Option<ManagedGroupRollout>> {
        match &self.postgres {
            Some(pg) => pg.pause_managed_group_rollout(tenant, group_id).await,
            None => self.pause_managed_group_rollout(tenant, group_id),
        }
    }
    pub async fn resume_managed_group_rollout_async(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> anyhow::Result<Option<ManagedGroupRollout>> {
        match &self.postgres {
            Some(pg) => {
                pg.resume_managed_group_rollout(tenant, group_id, issuer)
                    .await
            }
            None => self.resume_managed_group_rollout(tenant, group_id, issuer),
        }
    }
}
