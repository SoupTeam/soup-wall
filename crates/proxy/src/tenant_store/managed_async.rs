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
}
