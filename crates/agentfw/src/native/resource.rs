// SPDX-License-Identifier: Apache-2.0
//! Versioned resource authorization for an authenticated, trusted collector.
//! This checks permissions and correlation; it does not attest an executor sandbox.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::mcp::admission::Invocation;
use crate::mcp::resources::{
    extract, ExecutorContext, Resource, ResourceEvidence, ResourceProfile,
};

pub const CONTRACT: &str = "sw-native/resources/1";
pub const CREATE_CONTRACT: &str = "sw-native/resources/2";
pub const NETWORK_CONTRACT: &str = "sw-native/resources/3";
pub const CREATE_FILE_EXECUTOR_PROFILE: &str = "sw-native/create-file/linux-root-child/1";
// Keep the complete original content within the selected rule classifier's
// reviewed leaf bound; a truncated/unknown prediction must remain blocked.
pub const CREATE_FILE_MAX_CONTENT: usize = 4_096;

/// A semantic executor revision, not attestation of a running binary.
pub fn create_file_executor_sha256() -> String {
    super::hash(CREATE_FILE_EXECUTOR_PROFILE.as_bytes())
}

/// The one reviewed create operation. Byte limits are also checked on arguments;
/// JSON Schema's character limit alone is insufficient for multi-byte UTF-8.
pub fn create_file_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 4096},
            "content": {"type": "string", "maxLength": CREATE_FILE_MAX_CONTENT}
        },
        "required": ["path", "content"],
        "additionalProperties": false
    })
}

/// The only network operation installed by the v3 resource contract.
pub fn https_get_schema() -> Value {
    json!({"type":"object", "properties":{
        "url":{"type":"string", "minLength":1, "maxLength":2048}
    }, "required":["url"], "additionalProperties":false})
}

/// Exact network execution authority, additive to (never a replacement for)
/// native host/session/registry and single-use result correlation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkBinding {
    pub operation: String,
    pub action: String,
    pub executor_profile: String,
    pub policy_sha256: String,
    pub args_sha256: String,
    pub authority_sha256: String,
}

impl NetworkBinding {
    fn valid(&self) -> bool {
        self.operation == "https_get"
            && self.action == "get"
            && self.executor_profile == crate::mcp::https_get::EXECUTOR_PROFILE
            && [
                &self.policy_sha256,
                &self.args_sha256,
                &self.authority_sha256,
            ]
            .iter()
            .all(|digest| super::is_digest(digest))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOperation {
    CreateFile,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAction {
    Write,
}

/// Present only in the explicit v2 contract; absence preserves v1 read semantics.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub operation: ExecutionOperation,
    pub action: ExecutionAction,
    pub max_content_bytes: usize,
    pub executor_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub operation: ExecutionOperation,
    pub action: ExecutionAction,
    pub max_content_bytes: usize,
    pub executor_profile: String,
    pub policy_sha256: String,
    pub args_sha256: String,
    pub content_sha256: String,
    pub workspace_sha256: String,
}

impl ExecutionPolicy {
    fn supported(&self) -> bool {
        self.max_content_bytes == CREATE_FILE_MAX_CONTENT
            && self.executor_profile == CREATE_FILE_EXECUTOR_PROFILE
    }
}

impl ExecutionBinding {
    fn valid(&self) -> bool {
        self.max_content_bytes == CREATE_FILE_MAX_CONTENT
            && self.executor_profile == CREATE_FILE_EXECUTOR_PROFILE
            && [
                &self.policy_sha256,
                &self.args_sha256,
                &self.content_sha256,
                &self.workspace_sha256,
            ]
            .iter()
            .all(|digest| super::is_digest(digest))
    }
}

/// Immutable operator configuration, never accepted as a per-call grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub profile: ResourceProfile,
    pub workspace: PathBuf,
    pub cwd: PathBuf,
    pub executor_sha256: String,
    pub classifier_sha256: String,
    pub allowed_resources: Vec<Resource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<crate::mcp::https_get::HttpsGetAuthority>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub server_id: String,
    pub host_call_id: Value,
    pub profile_sha256: String,
    pub executor_sha256: String,
    pub classifier_sha256: String,
    pub snapshot_sha256: String,
    pub definition_sha256: String,
    pub input_sha256: String,
    pub resources: Vec<ResourceEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkBinding>,
}

impl Admission {
    pub fn contract(&self) -> &'static str {
        if self.network.is_some() {
            NETWORK_CONTRACT
        } else if self.execution.is_some() {
            CREATE_CONTRACT
        } else {
            CONTRACT
        }
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        let id = &self.host_call_id;
        if !super::identifier(&self.server_id)
            || !(id.is_i64()
                || id.is_u64()
                || id.as_str().is_some_and(|s| {
                    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
                }))
            || self.resources.is_empty()
            || self.resources.len() > 256
            || (self.network.is_some() && self.execution.is_some())
            || self
                .network
                .as_ref()
                .is_some_and(|network| !network.valid())
            || self
                .execution
                .as_ref()
                .is_some_and(|execution| !execution.valid())
            || serde_json::to_vec(self)
                .map_err(|_| "native_resource_invalid")?
                .len()
                > super::MAX_CONTENT
            || [
                &self.profile_sha256,
                &self.executor_sha256,
                &self.classifier_sha256,
                &self.snapshot_sha256,
                &self.definition_sha256,
                &self.input_sha256,
            ]
            .iter()
            .any(|digest| !super::is_digest(digest))
        {
            return Err("native_resource_invalid");
        }
        Ok(())
    }

    pub fn resources_sha256(&self) -> String {
        super::canonical_digest(
            &serde_json::to_value(&self.resources).expect("resources serialize"),
        )
    }
}

impl Policy {
    pub fn contract(&self) -> &'static str {
        if self.network.is_some() {
            NETWORK_CONTRACT
        } else if self.execution.is_some() {
            CREATE_CONTRACT
        } else {
            CONTRACT
        }
    }

    pub fn is_create_file(&self) -> bool {
        self.execution.is_some()
    }

    pub fn is_https_get(&self) -> bool {
        self.network.is_some()
    }

    pub fn validate(&self, tool: &super::Tool) -> anyhow::Result<()> {
        anyhow::ensure!(
            super::identifier(&self.profile.server_id)
                && self.profile.tool_name == tool.name
                && self.profile.schema_sha256 == tool.schema_sha256
                && !self.profile.selectors.is_empty()
                && self.profile.selectors.len() <= 32
                && self.workspace.is_absolute()
                && self.cwd.is_absolute()
                && self.workspace.is_dir()
                && self.cwd.is_dir()
                && self
                    .cwd
                    .canonicalize()?
                    .starts_with(self.workspace.canonicalize()?)
                && super::is_digest(&self.executor_sha256)
                && super::is_digest(&self.classifier_sha256)
                && !self.allowed_resources.is_empty()
                && self.allowed_resources.len() <= 256,
            "invalid operator resource policy"
        );
        anyhow::ensure!(
            self.execution.is_none() || self.network.is_none(),
            "conflicting operator execution policies"
        );
        if let Some(network) = &self.network {
            network.validate().map_err(anyhow::Error::msg)?;
            let selector = &self.profile.selectors[0];
            anyhow::ensure!(
                tool.name == "https_get"
                    && tool.action_class == soup_wall_agent::ActionClass::Network
                    && matches!(tool.result_provenance, super::ResultProvenance::Untrusted)
                    && tool.schema_sha256 == super::canonical_digest(&https_get_schema())
                    && self.executor_sha256 == crate::mcp::https_get::executor_profile_sha256()
                    && tool.egress.len() == 1
                    && tool.egress[0].pointer == "/url"
                    && matches!(tool.egress[0].kind, super::EgressKind::UrlHost)
                    && !tool.egress[0].optional
                    && self.profile.selectors.len() == 1
                    && selector.pointer == "/url"
                    && selector.kind == crate::mcp::resources::ResourceKind::Url
                    && selector.aliases.is_empty()
                    && !selector.optional
                    && selector.default.is_none()
                    && !selector.allow_missing_leaf
                    && self.allowed_resources.len() == 1,
                "invalid operator HTTPS GET policy"
            );
            let (canonical, host, port) = crate::mcp::resources::canonical_url(&network.exact_url)
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                self.allowed_resources[0]
                    == Resource::Url {
                        canonical,
                        host,
                        port
                    },
                "HTTPS GET authority must select one exact URL"
            );
        }
        if let Some(execution) = &self.execution {
            let selector = self
                .profile
                .selectors
                .first()
                .expect("nonempty validated above");
            anyhow::ensure!(
                execution.supported()
                    && tool.name == "create_file"
                    && tool.action_class == soup_wall_agent::ActionClass::SideEffecting
                    && tool.egress.is_empty()
                    && tool.schema_sha256 == super::canonical_digest(&create_file_schema())
                    && self.executor_sha256 == create_file_executor_sha256()
                    && self.profile.selectors.len() == 1
                    && selector.pointer == "/path"
                    && selector.kind == crate::mcp::resources::ResourceKind::Path
                    && selector.aliases.is_empty()
                    && !selector.optional
                    && selector.default.is_none()
                    && selector.allow_missing_leaf
                    && self.allowed_resources.len() == 1,
                "invalid operator create-file policy"
            );
            let root = create_file_workspace(&self.workspace, &self.cwd)
                .map_err(anyhow::Error::msg)?
                .0;
            let Resource::Path { canonical } = &self.allowed_resources[0] else {
                anyhow::bail!("create-file authority must select an exact path");
            };
            let destination = Path::new(canonical);
            anyhow::ensure!(
                destination.is_absolute()
                    && destination.parent() == Some(root.as_path())
                    && destination.file_name().is_some()
                    && destination.components().all(|component| !matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )),
                "create-file authority must select one direct workspace child"
            );
        }
        Ok(())
    }
}

/// No DNS lookup or request is performed here. The constrained executor checks
/// and pins the current resolved addresses against this immutable authority.
pub fn https_get_binding(policy: &Policy, args: &Value) -> Result<NetworkBinding, &'static str> {
    let authority = policy
        .network
        .as_ref()
        .ok_or("native_https_authority_missing")?;
    authority
        .validate()
        .map_err(|_| "native_https_authority_invalid")?;
    if policy.execution.is_some()
        || policy.executor_sha256 != crate::mcp::https_get::executor_profile_sha256()
    {
        return Err("native_https_executor_revision_mismatch");
    }
    let object = args.as_object().ok_or("native_https_arguments_invalid")?;
    if object.len() != 1 || args["url"].as_str() != Some(authority.exact_url.as_str()) {
        return Err("native_https_url_not_allowed");
    }
    Ok(NetworkBinding {
        operation: "https_get".into(),
        action: "get".into(),
        executor_profile: crate::mcp::https_get::EXECUTOR_PROFILE.into(),
        policy_sha256: super::canonical_digest(
            &serde_json::to_value(policy).expect("policy serializes"),
        ),
        args_sha256: super::canonical_digest(args),
        authority_sha256: authority
            .executor_id()
            .map_err(|_| "native_https_authority_invalid")?,
    })
}

/// Canonical operator paths plus stable filesystem identity. The constrained
/// executor separately pins/rechecks descriptors through the publication syscall.
fn create_file_workspace(workspace: &Path, cwd: &Path) -> Result<(PathBuf, String), &'static str> {
    for path in [workspace, cwd] {
        for ancestor in path.ancestors() {
            if std::fs::symlink_metadata(ancestor)
                .map_err(|_| "native_create_workspace_unavailable")?
                .file_type()
                .is_symlink()
            {
                return Err("native_create_workspace_link");
            }
        }
    }
    let root = workspace
        .canonicalize()
        .map_err(|_| "native_create_workspace_unavailable")?;
    let current = cwd
        .canonicalize()
        .map_err(|_| "native_create_workspace_unavailable")?;
    if !root.is_dir() || root.parent().is_none() || root != current {
        return Err("native_create_workspace_invalid");
    }
    let metadata = std::fs::metadata(&root).map_err(|_| "native_create_workspace_unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let identity =
            json!({"workspace":root,"cwd":current,"device":metadata.dev(),"inode":metadata.ino()});
        Ok((root, super::canonical_digest(&identity)))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err("native_create_platform_unsupported")
    }
}

/// Recompute v2 evidence from original arguments and immutable operator policy.
/// This is a necessary authorization check, never a path-only confinement claim.
pub fn create_file_binding(
    policy: &Policy,
    args: &Value,
) -> Result<ExecutionBinding, &'static str> {
    let execution = policy
        .execution
        .as_ref()
        .ok_or("native_create_authority_missing")?;
    if !execution.supported() || policy.executor_sha256 != create_file_executor_sha256() {
        return Err("native_create_executor_revision_mismatch");
    }
    let object = args.as_object().ok_or("native_create_arguments_invalid")?;
    if object.len() != 2 || !object.contains_key("path") || !object.contains_key("content") {
        return Err("native_create_arguments_invalid");
    }
    let path = args["path"]
        .as_str()
        .ok_or("native_create_arguments_invalid")?;
    let content = args["content"]
        .as_str()
        .ok_or("native_create_arguments_invalid")?;
    if content.len() > execution.max_content_bytes || path.is_empty() || path.len() > 4096 {
        return Err("native_create_arguments_over_cap");
    }
    let (root, workspace_sha256) = create_file_workspace(&policy.workspace, &policy.cwd)?;
    let context = ExecutorContext {
        os: std::env::consts::OS,
        workspace: &root,
        cwd: &root,
        fixed_destinations: true,
    };
    let invocation = Invocation {
        server_id: policy.profile.server_id.clone(),
        host_call_id: Value::Null,
        registry_sha256: String::new(),
        snapshot_sha256: String::new(),
        schema_sha256: policy.profile.schema_sha256.clone(),
        tool: policy.profile.tool_name.clone(),
        description: String::new(),
        schema: Value::Null,
        definition: Value::Null,
        server_info: Value::Null,
        definition_sha256: String::new(),
        input_sha256: String::new(),
        classifier_revision: None,
        args: args.clone(),
        baseline: soup_wall_agent::ActionClass::SideEffecting,
    };
    let derived = extract(&invocation, &policy.profile, &context);
    if !derived.complete() || derived.resources.len() != 1 {
        return Err("native_create_destination_invalid");
    }
    let Resource::Path { canonical } = &derived.resources[0].resource else {
        return Err("native_create_destination_invalid");
    };
    let destination = Path::new(canonical);
    if destination.parent() != Some(root.as_path()) {
        return Err("native_create_destination_unsupported");
    }
    let leaf = destination
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && name.len() <= 255)
        .ok_or("native_create_destination_unsupported")?;
    // Generic v1 extraction normalizes spelling. The v2 create profile only
    // accepts the original direct leaf or its exact canonical absolute path;
    // normalization must not hide aliases before the executor sees a target.
    if path != leaf && path != canonical {
        return Err("native_create_destination_unsupported");
    }
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("native_create_target_exists_or_unavailable"),
    }
    if !policy
        .allowed_resources
        .contains(&derived.resources[0].resource)
    {
        return Err("native_resource_not_allowed");
    }
    Ok(ExecutionBinding {
        operation: execution.operation,
        action: execution.action,
        max_content_bytes: execution.max_content_bytes,
        executor_profile: execution.executor_profile.clone(),
        policy_sha256: super::canonical_digest(
            &serde_json::to_value(policy).expect("policy serializes"),
        ),
        args_sha256: super::canonical_digest(args),
        content_sha256: super::hash(content.as_bytes()),
        workspace_sha256,
    })
}

/// Derive resources again from actual arguments and the operator's selectors.
/// A caller's well-formed array and a matching hash are not permissions.
pub fn authorize(
    policy: &Policy,
    tool: &super::Tool,
    registry_sha256: &str,
    args: &Value,
    admission: &Admission,
) -> Result<(), &'static str> {
    admission.validate_shape()?;
    if policy.contract() != admission.contract() {
        return Err("native_resource_contract_mismatch");
    }
    if let Some(bound) = &admission.execution {
        if &create_file_binding(policy, args)? != bound {
            return Err("native_create_binding_mismatch");
        }
    }
    if let Some(bound) = &admission.network {
        if &https_get_binding(policy, args)? != bound {
            return Err("native_https_binding_mismatch");
        }
    }
    let profile_sha256 = super::canonical_digest(
        &serde_json::to_value(&policy.profile).expect("profile serializes"),
    );
    if admission.server_id != policy.profile.server_id
        || admission.profile_sha256 != profile_sha256
        || admission.executor_sha256 != policy.executor_sha256
        || admission.classifier_sha256 != policy.classifier_sha256
    {
        return Err("native_resource_revision_mismatch");
    }
    let input = Invocation {
        server_id: admission.server_id.clone(),
        host_call_id: admission.host_call_id.clone(),
        registry_sha256: registry_sha256.into(),
        snapshot_sha256: admission.snapshot_sha256.clone(),
        schema_sha256: tool.schema_sha256.clone(),
        tool: tool.name.clone(),
        description: String::new(),
        schema: json!({}),
        definition: Value::Null,
        server_info: Value::Null,
        definition_sha256: admission.definition_sha256.clone(),
        input_sha256: admission.input_sha256.clone(),
        classifier_revision: Some(admission.classifier_sha256.clone()),
        args: args.clone(),
        baseline: tool.action_class,
    };
    // Semantic extraction only. Actual confinement remains the trusted collector's
    // responsibility; this Boolean neither installs nor certifies a sandbox.
    let context = ExecutorContext {
        os: std::env::consts::OS,
        workspace: &policy.workspace,
        cwd: &policy.cwd,
        fixed_destinations: true,
    };
    let derived = extract(&input, &policy.profile, &context);
    if !derived.complete() || derived.resources != admission.resources {
        return Err("native_resource_argument_mismatch");
    }
    if derived
        .resources
        .iter()
        .any(|evidence| !policy.allowed_resources.contains(&evidence.resource))
    {
        return Err("native_resource_not_allowed");
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, super::super::Tool, Policy) {
        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let root = workspace.canonicalize().unwrap();
        let schema_sha256 = super::super::canonical_digest(&create_file_schema());
        let tool: super::super::Tool = serde_json::from_value(json!({
            "name":"create_file", "schema_sha256":schema_sha256,
            "action_class":"side_effecting", "result_provenance":"local_project", "egress":[]
        }))
        .unwrap();
        let policy: Policy = serde_json::from_value(json!({
            "profile":{"server_id":"create-fixture", "tool_name":"create_file",
                "schema_sha256":schema_sha256, "selectors":[{"pointer":"/path", "kind":"path",
                "allow_missing_leaf":true}]},
            "workspace":root, "cwd":root,
            "executor_sha256":create_file_executor_sha256(), "classifier_sha256":"c".repeat(64),
            "allowed_resources":[{"kind":"path","canonical":root.join("new.txt")}],
            "execution":{"operation":"create_file","action":"write",
                "max_content_bytes":CREATE_FILE_MAX_CONTENT,"executor_profile":CREATE_FILE_EXECUTOR_PROFILE}
        })).unwrap();
        policy.validate(&tool).unwrap();
        (directory, tool, policy)
    }

    fn admission(policy: &Policy, args: &Value) -> Admission {
        let root = policy.workspace.canonicalize().unwrap();
        let invocation = Invocation {
            server_id: policy.profile.server_id.clone(),
            host_call_id: json!(17),
            registry_sha256: "r".repeat(64),
            snapshot_sha256: "s".repeat(64),
            schema_sha256: policy.profile.schema_sha256.clone(),
            tool: "create_file".into(),
            description: String::new(),
            schema: create_file_schema(),
            definition: Value::Null,
            server_info: Value::Null,
            definition_sha256: "d".repeat(64),
            input_sha256: "a".repeat(64),
            classifier_revision: Some(policy.classifier_sha256.clone()),
            args: args.clone(),
            baseline: soup_wall_agent::ActionClass::SideEffecting,
        };
        let resources = extract(
            &invocation,
            &policy.profile,
            &ExecutorContext {
                os: std::env::consts::OS,
                workspace: &root,
                cwd: &root,
                fixed_destinations: true,
            },
        )
        .resources;
        Admission {
            server_id: policy.profile.server_id.clone(),
            host_call_id: json!(17),
            profile_sha256: super::super::canonical_digest(
                &serde_json::to_value(&policy.profile).unwrap(),
            ),
            executor_sha256: policy.executor_sha256.clone(),
            classifier_sha256: policy.classifier_sha256.clone(),
            snapshot_sha256: "b".repeat(64),
            definition_sha256: "d".repeat(64),
            input_sha256: "a".repeat(64),
            resources,
            execution: Some(create_file_binding(policy, args).unwrap()),
            network: None,
        }
    }

    #[test]
    fn create_authority_requires_reviewed_schema_action_profile_and_executor() {
        let (_directory, tool, policy) = fixture();
        let mut wrong = tool.clone();
        wrong.action_class = soup_wall_agent::ActionClass::ReadOnly;
        assert!(policy.validate(&wrong).is_err());
        wrong = tool.clone();
        wrong.schema_sha256 = "a".repeat(64);
        assert!(policy.validate(&wrong).is_err());
        let mut changed = policy.clone();
        changed.executor_sha256 = "e".repeat(64);
        assert!(changed.validate(&tool).is_err());
        changed = policy.clone();
        changed.execution.as_mut().unwrap().max_content_bytes += 1;
        assert!(changed.validate(&tool).is_err());
        changed = policy.clone();
        changed.profile.selectors[0].allow_missing_leaf = false;
        assert!(changed.validate(&tool).is_err());
        changed = policy.clone();
        changed.profile.selectors[0]
            .aliases
            .push("/another_path".into());
        assert!(changed.validate(&tool).is_err());
        changed = policy.clone();
        changed
            .allowed_resources
            .push(changed.allowed_resources[0].clone());
        assert!(changed.validate(&tool).is_err());
        changed = policy;
        changed
            .execution
            .as_mut()
            .unwrap()
            .executor_profile
            .push_str("-replacement");
        assert!(changed.validate(&tool).is_err());
    }

    #[test]
    fn create_binding_is_v2_exact_and_uses_utf8_byte_bounds() {
        let (_directory, tool, policy) = fixture();
        let args = json!({"path":"new.txt","content":"Snowman: ☃\n"});
        let bound = admission(&policy, &args);
        assert_eq!(policy.contract(), CREATE_CONTRACT);
        assert_eq!(bound.contract(), CREATE_CONTRACT);
        assert_eq!(
            bound.execution.as_ref().unwrap().policy_sha256,
            super::super::canonical_digest(&serde_json::to_value(&policy).unwrap())
        );
        assert_eq!(
            bound.execution.as_ref().unwrap().args_sha256,
            super::super::canonical_digest(&args)
        );
        assert_eq!(
            bound.execution.as_ref().unwrap().content_sha256,
            super::super::hash("Snowman: ☃\n".as_bytes())
        );
        assert_eq!(
            authorize(&policy, &tool, &"r".repeat(64), &args, &bound),
            Ok(())
        );
        let at_limit = json!({"path":"new.txt","content":"a".repeat(CREATE_FILE_MAX_CONTENT)});
        assert!(create_file_binding(&policy, &at_limit).is_ok());
        let over = json!({"path":"new.txt","content":"☃".repeat(CREATE_FILE_MAX_CONTENT / 3 + 1)});
        assert_eq!(
            create_file_binding(&policy, &over).err(),
            Some("native_create_arguments_over_cap")
        );
        for invalid in [
            json!({"path":"new.txt"}),
            json!({"path":"new.txt","content":null}),
            json!({"path":"new.txt","content":"ok","append":true}),
        ] {
            assert_eq!(
                create_file_binding(&policy, &invalid).err(),
                Some("native_create_arguments_invalid")
            );
        }
    }

    #[test]
    fn create_authority_rejects_args_content_destination_and_workspace_substitution() {
        let (_directory, tool, policy) = fixture();
        let args = json!({"path":"new.txt","content":"original"});
        let mut bound = admission(&policy, &args);
        for changed in [
            json!({"path":"new.txt","content":"substitute"}),
            json!({"path":policy.workspace.join("new.txt"),"content":"original"}),
        ] {
            assert_eq!(
                authorize(&policy, &tool, &"r".repeat(64), &changed, &bound),
                Err("native_create_binding_mismatch")
            );
        }
        for field in [
            "workspace_sha256",
            "policy_sha256",
            "content_sha256",
            "args_sha256",
        ] {
            let mut substituted = serde_json::to_value(&bound).unwrap();
            substituted["execution"][field] = json!("a".repeat(64));
            let substituted: Admission = serde_json::from_value(substituted).unwrap();
            assert_eq!(
                authorize(&policy, &tool, &"r".repeat(64), &args, &substituted),
                Err("native_create_binding_mismatch"),
                "{field}"
            );
        }
        bound = admission(&policy, &args);
        bound.execution = None;
        assert_eq!(
            authorize(&policy, &tool, &"r".repeat(64), &args, &bound),
            Err("native_resource_contract_mismatch")
        );
        let substituted = json!({"path":"another.txt","content":"original"});
        assert_eq!(
            create_file_binding(&policy, &substituted).err(),
            Some("native_resource_not_allowed")
        );
        assert!(!policy.workspace.join("new.txt").exists());
    }

    #[test]
    fn create_authority_refuses_existing_nested_and_linked_destinations() {
        use std::os::unix::fs::symlink;
        let (_directory, _tool, policy) = fixture();
        let destination = policy.workspace.join("new.txt");
        let args = json!({"path":"new.txt","content":"new bytes"});
        std::fs::write(&destination, "unchanged").unwrap();
        assert_eq!(
            create_file_binding(&policy, &args).err(),
            Some("native_create_target_exists_or_unavailable")
        );
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "unchanged");
        std::fs::remove_file(&destination).unwrap();
        let nested = policy.workspace.join("nested");
        std::fs::create_dir(&nested).unwrap();
        assert_eq!(
            create_file_binding(&policy, &json!({"path":"nested/child.txt","content":"new"})).err(),
            Some("native_create_destination_unsupported")
        );
        symlink(nested.join("nonexistent"), &destination).unwrap();
        assert_eq!(
            create_file_binding(&policy, &args).err(),
            Some("native_create_destination_invalid")
        );
    }

    #[test]
    fn create_authority_rejects_normalized_path_spellings_before_execution() {
        let (_directory, _tool, policy) = fixture();
        let canonical = policy.workspace.join("new.txt");
        for path in ["new.txt".to_owned(), canonical.to_str().unwrap().to_owned()] {
            assert!(
                create_file_binding(&policy, &json!({"path":path,"content":"exact bytes"})).is_ok()
            );
        }
        for path in [
            "./new.txt".to_owned(),
            "new.txt/".to_owned(),
            format!("{}//new.txt", policy.workspace.display()),
            format!("{}/./new.txt", policy.workspace.display()),
        ] {
            assert_eq!(
                create_file_binding(&policy, &json!({"path":path,"content":"exact bytes"})).err(),
                Some("native_create_destination_unsupported"),
                "{path}"
            );
        }
        let mut longest = policy.clone();
        let leaf = "a".repeat(255);
        longest.allowed_resources = vec![Resource::Path {
            canonical: policy.workspace.join(&leaf).to_str().unwrap().to_owned(),
        }];
        assert!(
            create_file_binding(&longest, &json!({"path":leaf,"content":"exact bytes"})).is_ok()
        );
        let leaf = "☃".repeat(86);
        longest.allowed_resources = vec![Resource::Path {
            canonical: policy.workspace.join(&leaf).to_str().unwrap().to_owned(),
        }];
        assert!(
            create_file_binding(&longest, &json!({"path":leaf,"content":"exact bytes"})).is_err()
        );
        assert!(!canonical.exists());
    }

    #[test]
    fn create_binding_detects_replaced_workspace_inode_at_the_same_path() {
        let (directory, _tool, policy) = fixture();
        let args = json!({"path":"new.txt","content":"original"});
        let original = create_file_binding(&policy, &args).unwrap();
        let moved = directory.path().join("original-workspace");
        std::fs::rename(&policy.workspace, &moved).unwrap();
        std::fs::create_dir(&policy.workspace).unwrap();
        let replaced = create_file_binding(&policy, &args).unwrap();
        assert_ne!(original.workspace_sha256, replaced.workspace_sha256);
        std::fs::remove_dir_all(&moved).unwrap();
    }
}
