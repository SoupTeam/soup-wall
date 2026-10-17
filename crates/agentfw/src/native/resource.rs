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
pub const WINDOWS_READ_CONTRACT: &str = "sw-native/resources/4";
pub const WINDOWS_CREATE_CONTRACT: &str = "sw-native/resources/5";
pub const CREATE_FILE_EXECUTOR_PROFILE: &str = "sw-native/create-file/linux-root-child/1";
pub const WINDOWS_READ_EXECUTOR_PROFILE: &str = "sw-native/read-document/windows-handles/1";
pub const WINDOWS_CREATE_EXECUTOR_PROFILE: &str = "sw-native/create-file/windows-handles/1";
pub const READ_DOCUMENT_EXECUTOR_PROFILE: &str = "sw-native/read-document/direct/1";
pub const BINDING_CONTRACT: &str = "sw-native/binding/1";
pub const WINDOWS_READ_MAX_CONTENT: usize = super::MAX_CONTENT;
// Keep the complete original content within the selected rule classifier's
// reviewed leaf bound; a truncated/unknown prediction must remain blocked.
pub const CREATE_FILE_MAX_CONTENT: usize = 4_096;

/// A semantic executor revision, not attestation of a running binary.
pub fn create_file_executor_sha256() -> String {
    super::hash(CREATE_FILE_EXECUTOR_PROFILE.as_bytes())
}

/// A separate semantic revision preserves the existing Unix read contract.
pub fn windows_read_executor_sha256() -> String {
    super::hash(WINDOWS_READ_EXECUTOR_PROFILE.as_bytes())
}

/// A separate semantic revision preserves the existing Linux create contract.
pub fn windows_create_executor_sha256() -> String {
    super::hash(WINDOWS_CREATE_EXECUTOR_PROFILE.as_bytes())
}

/// The only read operation installed by the Windows handle-bound profile.
pub fn windows_read_schema() -> Value {
    json!({"type":"object", "properties":{
        "path":{"type":"string", "minLength":1, "maxLength":4096}
    }, "required":["path"], "additionalProperties":false})
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsReadPolicy {
    pub executor_profile: String,
    pub max_content_bytes: usize,
}

impl WindowsReadPolicy {
    fn supported(&self) -> bool {
        self.executor_profile == WINDOWS_READ_EXECUTOR_PROFILE
            && self.max_content_bytes == WINDOWS_READ_MAX_CONTENT
    }
}

/// Exact arguments, workspace and leaf file identity, additive to the native
/// session and single-use result binding. Retained handles carry attributes,
/// synchronize and execute/traverse rights for sharing locks, never FILE_READ_DATA.
/// The collector neither executes nor maps them and requests ReadFile access
/// only after Allow.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsReadBinding {
    pub executor_profile: String,
    pub max_content_bytes: usize,
    pub policy_sha256: String,
    pub args_sha256: String,
    pub workspace_sha256: String,
    pub target_sha256: String,
}

impl WindowsReadBinding {
    fn valid(&self) -> bool {
        self.executor_profile == WINDOWS_READ_EXECUTOR_PROFILE
            && self.max_content_bytes == WINDOWS_READ_MAX_CONTENT
            && [
                &self.policy_sha256,
                &self.args_sha256,
                &self.workspace_sha256,
                &self.target_sha256,
            ]
            .iter()
            .all(|digest| super::is_digest(digest))
    }
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
    ReadDocument,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAction {
    Write,
    Read,
}

/// Present only in the explicit v2 contract; absence preserves v1 read semantics.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub operation: ExecutionOperation,
    pub action: ExecutionAction,
    pub max_content_bytes: usize,
    pub executor_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_contract: Option<String>,
}

fn default_binding_contract() -> String {
    BINDING_CONTRACT.to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolBinding {
    #[serde(default = "default_binding_contract")]
    pub contract_version: String,
    pub operation: ExecutionOperation,
    #[serde(default)]
    pub action: Option<ExecutionAction>,
    pub path_selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_contract: Option<String>,
    #[serde(default)]
    pub executor_profile: Option<String>,
    #[serde(default)]
    pub max_content_bytes: Option<usize>,
}

impl ToolBinding {
    pub fn to_execution_policy(&self) -> ExecutionPolicy {
        let action = self.action.unwrap_or(match self.operation {
            ExecutionOperation::CreateFile => ExecutionAction::Write,
            ExecutionOperation::ReadDocument => ExecutionAction::Read,
        });
        let executor_profile =
            self.executor_profile
                .clone()
                .unwrap_or_else(|| match self.operation {
                    ExecutionOperation::CreateFile => CREATE_FILE_EXECUTOR_PROFILE.to_string(),
                    ExecutionOperation::ReadDocument => READ_DOCUMENT_EXECUTOR_PROFILE.to_string(),
                });
        let max_content_bytes = self.max_content_bytes.unwrap_or(match self.operation {
            ExecutionOperation::CreateFile => CREATE_FILE_MAX_CONTENT,
            ExecutionOperation::ReadDocument => super::MAX_CONTENT,
        });
        ExecutionPolicy {
            operation: self.operation,
            action,
            max_content_bytes,
            executor_profile,
            path_selector: Some(self.path_selector.clone()),
            content_selector: self.content_selector.clone(),
            response_contract: self.response_contract.clone(),
        }
    }
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
        (self.operation == ExecutionOperation::CreateFile
            && self.action == ExecutionAction::Write
            && self.max_content_bytes == CREATE_FILE_MAX_CONTENT
            && matches!(
                self.executor_profile.as_str(),
                CREATE_FILE_EXECUTOR_PROFILE | WINDOWS_CREATE_EXECUTOR_PROFILE
            ))
            || (self.operation == ExecutionOperation::ReadDocument
                && self.action == ExecutionAction::Read
                && self.max_content_bytes == super::MAX_CONTENT
                && matches!(
                    self.executor_profile.as_str(),
                    READ_DOCUMENT_EXECUTOR_PROFILE | WINDOWS_READ_EXECUTOR_PROFILE
                ))
    }
}

impl ExecutionBinding {
    fn valid(&self) -> bool {
        self.operation == ExecutionOperation::CreateFile
            && self.action == ExecutionAction::Write
            && self.max_content_bytes == CREATE_FILE_MAX_CONTENT
            && matches!(
                self.executor_profile.as_str(),
                CREATE_FILE_EXECUTOR_PROFILE | WINDOWS_CREATE_EXECUTOR_PROFILE
            )
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_read: Option<WindowsReadPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<ToolBinding>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_read: Option<WindowsReadBinding>,
}

impl Admission {
    pub fn contract(&self) -> &'static str {
        if self.windows_read.is_some() {
            WINDOWS_READ_CONTRACT
        } else if self.network.is_some() {
            NETWORK_CONTRACT
        } else if self
            .execution
            .as_ref()
            .is_some_and(|execution| execution.executor_profile == WINDOWS_CREATE_EXECUTOR_PROFILE)
        {
            WINDOWS_CREATE_CONTRACT
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
            || [
                self.network.is_some(),
                self.execution.is_some(),
                self.windows_read.is_some(),
            ]
            .into_iter()
            .filter(|present| *present)
            .count()
                > 1
            || self.windows_read.as_ref().is_some_and(|read| !read.valid())
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
    pub fn effective_execution(&self) -> Option<ExecutionPolicy> {
        self.binding
            .as_ref()
            .map(|b| b.to_execution_policy())
            .or_else(|| self.execution.clone())
    }

    pub fn contract(&self) -> &'static str {
        if self.is_windows_read() {
            WINDOWS_READ_CONTRACT
        } else if self.network.is_some() {
            NETWORK_CONTRACT
        } else if self.is_windows_create() {
            WINDOWS_CREATE_CONTRACT
        } else if self.is_create_file() {
            CREATE_CONTRACT
        } else {
            CONTRACT
        }
    }

    pub fn is_create_file(&self) -> bool {
        self.effective_execution()
            .as_ref()
            .is_some_and(|e| e.operation == ExecutionOperation::CreateFile)
    }

    pub fn is_https_get(&self) -> bool {
        self.network.is_some()
    }

    pub fn is_windows_read(&self) -> bool {
        self.windows_read.is_some()
            || self
                .effective_execution()
                .as_ref()
                .is_some_and(|e| e.executor_profile == WINDOWS_READ_EXECUTOR_PROFILE)
    }

    pub fn is_windows_create(&self) -> bool {
        self.effective_execution()
            .as_ref()
            .is_some_and(|execution| execution.executor_profile == WINDOWS_CREATE_EXECUTOR_PROFILE)
    }

    pub fn is_windows_handles(&self) -> bool {
        self.is_windows_read() || self.is_windows_create()
    }

    pub fn path_selector(&self) -> &str {
        if let Some(b) = &self.binding {
            return &b.path_selector;
        }
        if let Some(e) = &self.execution {
            if let Some(p) = &e.path_selector {
                return p.as_str();
            }
        }
        if let Some(first) = self.profile.selectors.first() {
            return &first.pointer;
        }
        "/path"
    }

    pub fn content_selector(&self) -> &str {
        if let Some(b) = &self.binding {
            if let Some(c) = &b.content_selector {
                return c.as_str();
            }
        }
        if let Some(e) = &self.execution {
            if let Some(c) = &e.content_selector {
                return c.as_str();
            }
        }
        "/content"
    }

    pub fn response_contract(&self) -> Option<&str> {
        if let Some(b) = &self.binding {
            return b.response_contract.as_deref();
        }
        if let Some(e) = &self.execution {
            return e.response_contract.as_deref();
        }
        None
    }

    pub fn is_read_bound_or_named(&self, name: &str) -> bool {
        if name == "read_document" {
            return true;
        }
        if let Some(b) = &self.binding {
            return b.operation == ExecutionOperation::ReadDocument
                && self.profile.tool_name == name;
        }
        if let Some(e) = &self.execution {
            return e.operation == ExecutionOperation::ReadDocument
                && self.profile.tool_name == name;
        }
        false
    }

    pub fn is_create_bound_or_named(&self, name: &str) -> bool {
        if name == "create_file" {
            return true;
        }
        if let Some(b) = &self.binding {
            return b.operation == ExecutionOperation::CreateFile && self.profile.tool_name == name;
        }
        if let Some(e) = &self.execution {
            return e.operation == ExecutionOperation::CreateFile && self.profile.tool_name == name;
        }
        false
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
                && super::is_digest(&self.executor_sha256)
                && super::is_digest(&self.classifier_sha256)
                && !self.allowed_resources.is_empty()
                && self.allowed_resources.len() <= 256,
            "invalid operator resource policy"
        );
        anyhow::ensure!(
            [
                self.execution.is_some() || self.binding.is_some(),
                self.network.is_some(),
                self.windows_read.is_some()
            ]
            .into_iter()
            .filter(|present| *present)
            .count()
                <= 1,
            "conflicting operator execution policies"
        );
        if let Some(binding) = &self.binding {
            anyhow::ensure!(
                binding.contract_version == BINDING_CONTRACT,
                "unsupported tool binding contract version"
            );
            if let Some(action) = binding.action {
                match binding.operation {
                    ExecutionOperation::CreateFile => anyhow::ensure!(
                        action == ExecutionAction::Write,
                        "create_file binding requires write action"
                    ),
                    ExecutionOperation::ReadDocument => anyhow::ensure!(
                        action == ExecutionAction::Read,
                        "read_document binding requires read action"
                    ),
                }
            }
        }
        if let Some(read) = &self.windows_read {
            anyhow::ensure!(
                cfg!(windows),
                "Windows read authority is unsupported on this platform"
            );
            let selector = &self.profile.selectors[0];
            anyhow::ensure!(
                read.supported()
                    && tool.name == self.profile.tool_name
                    && tool.action_class == soup_wall_agent::ActionClass::ReadOnly
                    && matches!(tool.result_provenance, super::ResultProvenance::Untrusted)
                    && tool.egress.is_empty()
                    && tool.schema_sha256 == super::canonical_digest(&windows_read_schema())
                    && self.executor_sha256 == windows_read_executor_sha256()
                    && self.workspace == self.cwd
                    && self.profile.selectors.len() == 1
                    && selector.pointer == "/path"
                    && selector.kind == crate::mcp::resources::ResourceKind::Path
                    && selector.aliases.is_empty()
                    && !selector.optional
                    && selector.default.is_none()
                    && !selector.allow_missing_leaf
                    && self.allowed_resources.len() == 1
                    && matches!(&self.allowed_resources[0], Resource::Path { .. }),
                "invalid operator Windows read policy"
            );
        }
        if self.is_windows_create() {
            anyhow::ensure!(
                cfg!(windows),
                "Windows create authority is unsupported on this platform"
            );
            let execution = self
                .effective_execution()
                .expect("Windows create policy selected");
            let path_sel = self.path_selector();
            let content_sel = self.content_selector();
            anyhow::ensure!(
                crate::mcp::resources::valid_pointer(path_sel)
                    && crate::mcp::resources::valid_pointer(content_sel),
                "invalid selector pointer"
            );
            anyhow::ensure!(
                path_sel != content_sel
                    && !path_sel.starts_with(&format!("{content_sel}/"))
                    && !content_sel.starts_with(&format!("{path_sel}/")),
                "ambiguous or overlapping selectors"
            );
            if let Some(resp) = self.response_contract() {
                anyhow::ensure!(
                    resp == "sw-native/response/text/1" || resp == "mcp/text_result/1",
                    "unsupported response contract"
                );
            }
            let selector = &self.profile.selectors[0];
            let is_legacy_win_create =
                tool.name == "create_file" && path_sel == "/path" && content_sel == "/content";
            if is_legacy_win_create {
                anyhow::ensure!(
                    tool.schema_sha256 == super::canonical_digest(&create_file_schema()),
                    "invalid operator Windows create policy"
                );
            }
            anyhow::ensure!(
                execution.supported()
                    && tool.name == self.profile.tool_name
                    && tool.action_class == soup_wall_agent::ActionClass::SideEffecting
                    && matches!(tool.result_provenance, super::ResultProvenance::Untrusted)
                    && tool.egress.is_empty()
                    && self.executor_sha256 == windows_create_executor_sha256()
                    && self.workspace == self.cwd
                    && self.profile.selectors.len() == 1
                    && selector.pointer == path_sel
                    && selector.kind == crate::mcp::resources::ResourceKind::Path
                    && selector.aliases.is_empty()
                    && !selector.optional
                    && selector.default.is_none()
                    && selector.allow_missing_leaf
                    && self.allowed_resources.len() == 1,
                "invalid operator Windows create policy"
            );
            let [Resource::Path { canonical }] = self.allowed_resources.as_slice() else {
                anyhow::bail!("Windows create authority must select an exact path");
            };
            #[cfg(windows)]
            let _pin = crate::windows_read::CreateParent::prepare(
                &self.workspace,
                &self.cwd,
                canonical.strip_prefix("\\\\?\\").unwrap_or(canonical),
                canonical,
            )?;
            #[cfg(not(windows))]
            let _ = canonical;
            // V5 authority comes only from retained NT handles, without any
            // later generic DOS path resolution or filesystem mutation.
            return Ok(());
        }
        // V4 validates and locks each component through the native executor.
        // Ordinary DOS path APIs are not used afterward: directory handles do
        // not prevent a drive-letter device mapping from being changed.
        #[cfg(windows)]
        let _windows_validation_pin = if self.is_windows_read() {
            let Resource::Path { canonical } = &self.allowed_resources[0] else {
                unreachable!("path authority validated above")
            };
            // This spelling is generated from trusted operator authority,
            // not accepted as an alias in original invocation arguments.
            let original = canonical.strip_prefix("\\\\?\\").unwrap_or(canonical);
            Some(crate::windows_read::PreparedRead::prepare(
                &self.workspace,
                &self.cwd,
                original,
                canonical,
            )?)
        } else {
            None
        };
        if !self.is_windows_read() {
            anyhow::ensure!(
                self.workspace.is_dir()
                    && self.cwd.is_dir()
                    && self
                        .cwd
                        .canonicalize()?
                        .starts_with(self.workspace.canonicalize()?),
                "invalid operator resource workspace"
            );
        }
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
        if self.is_create_file() && !self.is_windows_create() {
            let execution = self
                .effective_execution()
                .expect("create file policy selected");
            let path_sel = self.path_selector();
            let content_sel = self.content_selector();
            anyhow::ensure!(
                crate::mcp::resources::valid_pointer(path_sel)
                    && crate::mcp::resources::valid_pointer(content_sel),
                "invalid selector pointer"
            );
            anyhow::ensure!(
                path_sel != content_sel
                    && !path_sel.starts_with(&format!("{content_sel}/"))
                    && !content_sel.starts_with(&format!("{path_sel}/")),
                "ambiguous or overlapping selectors"
            );
            if let Some(resp) = self.response_contract() {
                anyhow::ensure!(
                    resp == "sw-native/response/text/1" || resp == "mcp/text_result/1",
                    "unsupported response contract"
                );
            }
            let selector = self
                .profile
                .selectors
                .first()
                .expect("nonempty validated above");
            let is_legacy_create =
                tool.name == "create_file" && path_sel == "/path" && content_sel == "/content";
            if is_legacy_create {
                anyhow::ensure!(
                    tool.schema_sha256 == super::canonical_digest(&create_file_schema()),
                    "invalid operator create-file policy"
                );
            }
            anyhow::ensure!(
                execution.supported()
                    && tool.name == self.profile.tool_name
                    && tool.action_class == soup_wall_agent::ActionClass::SideEffecting
                    && tool.egress.is_empty()
                    && self.executor_sha256 == create_file_executor_sha256()
                    && self.profile.selectors.len() == 1
                    && selector.pointer == path_sel
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
        if self
            .effective_execution()
            .as_ref()
            .is_some_and(|e| e.operation == ExecutionOperation::ReadDocument)
        {
            let execution = self.effective_execution().unwrap();
            let path_sel = self.path_selector();
            anyhow::ensure!(
                crate::mcp::resources::valid_pointer(path_sel),
                "invalid selector pointer"
            );
            if let Some(resp) = self.response_contract() {
                anyhow::ensure!(
                    resp == "sw-native/response/text/1" || resp == "mcp/text_result/1",
                    "unsupported response contract"
                );
            }
            let selector = self
                .profile
                .selectors
                .first()
                .expect("nonempty validated above");
            anyhow::ensure!(
                execution.supported()
                    && tool.name == self.profile.tool_name
                    && tool.action_class == soup_wall_agent::ActionClass::ReadOnly
                    && tool.egress.is_empty()
                    && self.profile.selectors.len() == 1
                    && selector.pointer == path_sel
                    && selector.kind == crate::mcp::resources::ResourceKind::Path
                    && selector.aliases.is_empty()
                    && !selector.optional
                    && selector.default.is_none()
                    && !selector.allow_missing_leaf
                    && !self.allowed_resources.is_empty(),
                "invalid operator read-document policy"
            );
            if execution.executor_profile == WINDOWS_READ_EXECUTOR_PROFILE {
                anyhow::ensure!(
                    self.executor_sha256 == windows_read_executor_sha256()
                        && self.workspace == self.cwd
                        && self.allowed_resources.len() == 1,
                    "invalid operator Windows read policy"
                );
            }
        }
        Ok(())
    }
}

fn windows_read_arguments<'a>(
    policy: &'a Policy,
    args: &'a Value,
) -> Result<(&'a str, &'a str), &'static str> {
    if !policy.is_windows_read() {
        return Err("native_windows_read_authority_missing");
    }
    let supported = if let Some(read) = &policy.windows_read {
        read.supported()
    } else if let Some(exec) = policy.effective_execution() {
        exec.supported()
    } else {
        false
    };
    if !supported
        || policy.network.is_some()
        || policy.executor_sha256 != windows_read_executor_sha256()
        || policy.workspace != policy.cwd
    {
        return Err("native_windows_read_executor_revision_mismatch");
    }
    let path_ptr = policy.path_selector();
    let is_legacy = policy.profile.tool_name == "read_document" && path_ptr == "/path";
    if is_legacy {
        let object = args
            .as_object()
            .ok_or("native_windows_read_arguments_invalid")?;
        if object.len() != 1 {
            return Err("native_windows_read_arguments_invalid");
        }
    }
    let path_val = crate::mcp::resources::selected(args, path_ptr)
        .map_err(|_| "native_windows_read_arguments_invalid")?
        .ok_or("native_windows_read_arguments_invalid")?;
    let original = path_val
        .as_str()
        .ok_or("native_windows_read_arguments_invalid")?;
    if original.is_empty() || original.len() > 4096 || original.chars().any(char::is_control) {
        return Err("native_windows_read_arguments_invalid");
    }
    let [Resource::Path { canonical }] = policy.allowed_resources.as_slice() else {
        return Err("native_windows_read_authority_invalid");
    };
    Ok((original, canonical))
}

/// Recompute v4 evidence without FILE_READ_DATA. The collector requests that
/// right and uses ReadFile only after both admission decisions allow it.
pub fn windows_read_binding(
    policy: &Policy,
    args: &Value,
) -> Result<WindowsReadBinding, &'static str> {
    let (original, canonical) = windows_read_arguments(policy, args)?;
    #[cfg(windows)]
    {
        let prepared = crate::windows_read::PreparedRead::prepare(
            &policy.workspace,
            &policy.cwd,
            original,
            canonical,
        )
        .map_err(|_| "native_windows_read_target_invalid")?;
        windows_read_binding_with_identity(policy, args, prepared.identity())
    }
    #[cfg(not(windows))]
    {
        let _ = (original, canonical);
        Err("native_windows_read_platform_unsupported")
    }
}

/// Build the same binding from the non-data-read handles retained by the
/// collector. Original argument spelling is included in `args_sha256`.
#[cfg(windows)]
pub(crate) fn windows_read_binding_with_identity(
    policy: &Policy,
    args: &Value,
    identity: &crate::windows_read::ReadIdentity,
) -> Result<WindowsReadBinding, &'static str> {
    let (_, canonical) = windows_read_arguments(policy, args)?;
    Ok(WindowsReadBinding {
        executor_profile: WINDOWS_READ_EXECUTOR_PROFILE.into(),
        max_content_bytes: WINDOWS_READ_MAX_CONTENT,
        policy_sha256: super::canonical_digest(
            &serde_json::to_value(policy).expect("policy serializes"),
        ),
        args_sha256: super::canonical_digest(args),
        workspace_sha256: super::canonical_digest(&json!({
            "workspace":policy.workspace,"cwd":policy.cwd,
            "volume_serial":identity.root_volume_serial,"file_id":identity.root_file_id,
        })),
        target_sha256: super::canonical_digest(&json!({
            "canonical":canonical,"volume_serial":identity.leaf_volume_serial,
            "file_id":identity.leaf_file_id,
        })),
    })
}

/// The fixed v4 selector is already resolved by the retained metadata handles.
/// Reuse that exact authority without reopening a DOS path for extraction.
#[cfg(windows)]
pub(crate) fn windows_read_evidence(
    policy: &Policy,
    args: &Value,
    identity: &crate::windows_read::ReadIdentity,
) -> Result<Vec<ResourceEvidence>, &'static str> {
    windows_read_binding_with_identity(policy, args, identity)?;
    Ok(vec![ResourceEvidence {
        pointer: policy.path_selector().into(),
        source: crate::mcp::resources::EvidenceSource::Argument,
        resource: policy.allowed_resources[0].clone(),
    }])
}

/// Validate the exact v5 arguments before any filesystem access. The executor
/// checks raw spelling and the absent direct child relative to pinned handles.
fn windows_create_arguments<'a>(
    policy: &'a Policy,
    args: &'a Value,
) -> Result<(&'a str, &'a str, &'a str), &'static str> {
    let execution = policy
        .effective_execution()
        .ok_or("native_windows_create_authority_missing")?;
    if !policy.is_windows_create()
        || !execution.supported()
        || policy.windows_read.is_some()
        || policy.network.is_some()
        || policy.executor_sha256 != windows_create_executor_sha256()
        || policy.workspace != policy.cwd
    {
        return Err("native_windows_create_executor_revision_mismatch");
    }
    let path_ptr = policy.path_selector();
    let content_ptr = policy.content_selector();
    let is_legacy = policy.profile.tool_name == "create_file"
        && path_ptr == "/path"
        && content_ptr == "/content";
    if is_legacy {
        let object = args
            .as_object()
            .ok_or("native_windows_create_arguments_invalid")?;
        if object.len() != 2 {
            return Err("native_windows_create_arguments_invalid");
        }
    }
    let path_val = crate::mcp::resources::selected(args, path_ptr)
        .map_err(|_| "native_windows_create_arguments_invalid")?
        .ok_or("native_windows_create_arguments_invalid")?;
    let original = path_val
        .as_str()
        .ok_or("native_windows_create_arguments_invalid")?;
    let content_val = crate::mcp::resources::selected(args, content_ptr)
        .map_err(|_| "native_windows_create_arguments_invalid")?
        .ok_or("native_windows_create_arguments_invalid")?;
    let content = content_val
        .as_str()
        .ok_or("native_windows_create_arguments_invalid")?;
    if original.is_empty()
        || original.len() > 4096
        || original.chars().any(char::is_control)
        || content.len() > CREATE_FILE_MAX_CONTENT
    {
        return Err("native_windows_create_arguments_invalid");
    }
    let [Resource::Path { canonical }] = policy.allowed_resources.as_slice() else {
        return Err("native_windows_create_authority_invalid");
    };
    Ok((original, canonical, content))
}

/// Independently derive v5 authority without creating a file or asking for
/// write access. The collector retains equivalent parent pins through Allow.
pub fn windows_create_binding(
    policy: &Policy,
    args: &Value,
) -> Result<ExecutionBinding, &'static str> {
    let (original, canonical, content) = windows_create_arguments(policy, args)?;
    #[cfg(windows)]
    {
        let prepared = crate::windows_create::PreparedCreate::prepare(
            &policy.workspace,
            &policy.cwd,
            original,
            canonical,
            content,
        )
        .map_err(|_| "native_windows_create_target_invalid")?;
        windows_create_binding_with_identity(policy, args, prepared.identity())
    }
    #[cfg(not(windows))]
    {
        let _ = (original, canonical, content);
        Err("native_windows_create_platform_unsupported")
    }
}

#[cfg(windows)]
pub(crate) fn windows_create_binding_with_identity(
    policy: &Policy,
    args: &Value,
    identity: &crate::windows_create::CreateIdentity,
) -> Result<ExecutionBinding, &'static str> {
    let (_, _, content) = windows_create_arguments(policy, args)?;
    Ok(ExecutionBinding {
        operation: ExecutionOperation::CreateFile,
        action: ExecutionAction::Write,
        max_content_bytes: CREATE_FILE_MAX_CONTENT,
        executor_profile: WINDOWS_CREATE_EXECUTOR_PROFILE.into(),
        policy_sha256: super::canonical_digest(
            &serde_json::to_value(policy).expect("policy serializes"),
        ),
        args_sha256: super::canonical_digest(args),
        content_sha256: super::hash(content.as_bytes()),
        workspace_sha256: super::canonical_digest(&json!({
            "workspace":policy.workspace,"cwd":policy.cwd,
            "volume_serial":identity.root_volume_serial,"file_id":identity.root_file_id,
        })),
    })
}

#[cfg(windows)]
pub(crate) fn windows_create_evidence(
    policy: &Policy,
    args: &Value,
    identity: &crate::windows_create::CreateIdentity,
) -> Result<Vec<ResourceEvidence>, &'static str> {
    windows_create_binding_with_identity(policy, args, identity)?;
    Ok(vec![ResourceEvidence {
        pointer: policy.path_selector().into(),
        source: crate::mcp::resources::EvidenceSource::Argument,
        resource: policy.allowed_resources[0].clone(),
    }])
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
        || policy.windows_read.is_some()
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
    if policy.is_windows_create() {
        return windows_create_binding(policy, args);
    }
    let execution = policy
        .effective_execution()
        .ok_or("native_create_authority_missing")?;
    if !execution.supported() || policy.executor_sha256 != create_file_executor_sha256() {
        return Err("native_create_executor_revision_mismatch");
    }
    let path_ptr = policy.path_selector();
    let content_ptr = policy.content_selector();
    let is_legacy = policy.profile.tool_name == "create_file"
        && path_ptr == "/path"
        && content_ptr == "/content";
    if is_legacy {
        let object = args.as_object().ok_or("native_create_arguments_invalid")?;
        if object.len() != 2 || !object.contains_key("path") || !object.contains_key("content") {
            return Err("native_create_arguments_invalid");
        }
    }
    let path_val = crate::mcp::resources::selected(args, path_ptr)
        .map_err(|_| "native_create_arguments_invalid")?
        .ok_or("native_create_arguments_invalid")?;
    let path = path_val.as_str().ok_or("native_create_arguments_invalid")?;
    let content_val = crate::mcp::resources::selected(args, content_ptr)
        .map_err(|_| "native_create_arguments_invalid")?
        .ok_or("native_create_arguments_invalid")?;
    let content = content_val
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
    // Keep the independently opened v5 parent alive throughout authorization.
    // No generic DOS path API is used for this contract.
    #[cfg(windows)]
    let windows_create_pin = if policy.is_windows_create() {
        let (original, canonical, content) = windows_create_arguments(policy, args)?;
        Some(
            crate::windows_create::PreparedCreate::prepare(
                &policy.workspace,
                &policy.cwd,
                original,
                canonical,
                content,
            )
            .map_err(|_| "native_windows_create_target_invalid")?,
        )
    } else {
        None
    };
    if let Some(bound) = &admission.execution {
        #[cfg(windows)]
        let derived = if let Some(prepared) = windows_create_pin.as_ref() {
            windows_create_binding_with_identity(policy, args, prepared.identity())?
        } else {
            create_file_binding(policy, args)?
        };
        #[cfg(not(windows))]
        let derived = create_file_binding(policy, args)?;
        if &derived != bound {
            return Err("native_create_binding_mismatch");
        }
    }
    if let Some(bound) = &admission.network {
        if &https_get_binding(policy, args)? != bound {
            return Err("native_https_binding_mismatch");
        }
    }
    // Keep the no-follow metadata pins alive through fixed v4 evidence checks.
    // V4 does not use generic extraction, which would resolve a DOS path again.
    #[cfg(windows)]
    let windows_read_pin = if admission.windows_read.is_some() {
        let (original, canonical) = windows_read_arguments(policy, args)?;
        Some(
            crate::windows_read::PreparedRead::prepare(
                &policy.workspace,
                &policy.cwd,
                original,
                canonical,
            )
            .map_err(|_| "native_windows_read_target_invalid")?,
        )
    } else {
        None
    };
    if let Some(bound) = &admission.windows_read {
        #[cfg(windows)]
        let derived_binding = windows_read_binding_with_identity(
            policy,
            args,
            windows_read_pin
                .as_ref()
                .expect("Windows read metadata pinned")
                .identity(),
        )?;
        #[cfg(not(windows))]
        let derived_binding = windows_read_binding(policy, args)?;
        if &derived_binding != bound {
            return Err("native_windows_read_binding_mismatch");
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
    #[cfg(windows)]
    if let Some(prepared) = windows_create_pin.as_ref() {
        let resources = windows_create_evidence(policy, args, prepared.identity())?;
        if resources != admission.resources {
            return Err("native_resource_argument_mismatch");
        }
        if resources
            .iter()
            .any(|evidence| !policy.allowed_resources.contains(&evidence.resource))
        {
            return Err("native_resource_not_allowed");
        }
        return Ok(());
    }
    #[cfg(windows)]
    if let Some(prepared) = windows_read_pin.as_ref() {
        let resources = windows_read_evidence(policy, args, prepared.identity())?;
        if resources != admission.resources {
            return Err("native_resource_argument_mismatch");
        }
        if resources
            .iter()
            .any(|evidence| !policy.allowed_resources.contains(&evidence.resource))
        {
            return Err("native_resource_not_allowed");
        }
        return Ok(());
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

#[cfg(test)]
mod windows_read_contract_tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, super::super::Tool, Policy) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let target = root.join("approved.txt");
        std::fs::write(&target, "approved bytes").unwrap();
        let schema = super::super::canonical_digest(&windows_read_schema());
        let tool = serde_json::from_value(json!({
            "name":"read_document", "schema_sha256":schema,
            "action_class":"read_only", "result_provenance":"untrusted", "egress":[]
        }))
        .unwrap();
        let policy = serde_json::from_value(json!({
            "profile":{"server_id":"windows-read-fixture","tool_name":"read_document",
                "schema_sha256":schema,"selectors":[{"pointer":"/path","kind":"path"}]},
            "workspace":root,"cwd":root,"executor_sha256":windows_read_executor_sha256(),
            "classifier_sha256":"c".repeat(64),
            "allowed_resources":[{"kind":"path","canonical":target}],
            "windows_read":{"executor_profile":WINDOWS_READ_EXECUTOR_PROFILE,
                "max_content_bytes":WINDOWS_READ_MAX_CONTENT}
        }))
        .unwrap();
        (directory, tool, policy)
    }

    #[test]
    fn windows_read_v4_binding_shape_preserves_distinct_contracts() {
        let read = WindowsReadBinding {
            executor_profile: WINDOWS_READ_EXECUTOR_PROFILE.into(),
            max_content_bytes: WINDOWS_READ_MAX_CONTENT,
            policy_sha256: "a".repeat(64),
            args_sha256: "b".repeat(64),
            workspace_sha256: "c".repeat(64),
            target_sha256: "d".repeat(64),
        };
        let mut admission: Admission = serde_json::from_value(json!({
            "server_id":"windows-read-fixture","host_call_id":1,
            "profile_sha256":"a".repeat(64),"executor_sha256":"b".repeat(64),
            "classifier_sha256":"c".repeat(64),"snapshot_sha256":"d".repeat(64),
            "definition_sha256":"e".repeat(64),"input_sha256":"f".repeat(64),
            "resources":[{"pointer":"/path","source":"argument",
                "resource":{"kind":"path","canonical":"approved.txt"}}],
            "windows_read":read
        }))
        .unwrap();
        assert_eq!(admission.contract(), WINDOWS_READ_CONTRACT);
        assert_eq!(admission.validate_shape(), Ok(()));
        for field in [
            "executor_profile",
            "max_content_bytes",
            "policy_sha256",
            "args_sha256",
            "workspace_sha256",
            "target_sha256",
        ] {
            let mut changed = serde_json::to_value(&admission).unwrap();
            changed["windows_read"][field] = if field == "max_content_bytes" {
                json!(WINDOWS_READ_MAX_CONTENT + 1)
            } else {
                json!("unsupported")
            };
            assert_eq!(
                serde_json::from_value::<Admission>(changed)
                    .unwrap()
                    .validate_shape(),
                Err("native_resource_invalid"),
                "{field}"
            );
        }
        admission.execution = Some(ExecutionBinding {
            operation: ExecutionOperation::CreateFile,
            action: ExecutionAction::Write,
            max_content_bytes: CREATE_FILE_MAX_CONTENT,
            executor_profile: CREATE_FILE_EXECUTOR_PROFILE.into(),
            policy_sha256: "a".repeat(64),
            args_sha256: "b".repeat(64),
            content_sha256: "c".repeat(64),
            workspace_sha256: "d".repeat(64),
        });
        assert_eq!(admission.validate_shape(), Err("native_resource_invalid"));
        admission.execution = None;
        admission.windows_read = None;
        assert_eq!(admission.contract(), CONTRACT);
    }

    #[test]
    fn windows_read_authority_requires_explicit_reviewed_semantics() {
        let (_directory, tool, policy) = fixture();
        assert_eq!(policy.contract(), WINDOWS_READ_CONTRACT);
        assert_eq!(policy.validate(&tool).is_ok(), cfg!(windows));
        for (field, value) in [
            ("name", json!("other_read")),
            ("schema_sha256", json!("a".repeat(64))),
            ("action_class", json!("side_effecting")),
            ("result_provenance", json!("local_system")),
        ] {
            let mut value_tool = json!({"name":"read_document",
                "schema_sha256":tool.schema_sha256,"action_class":"read_only",
                "result_provenance":"untrusted","egress":[]});
            value_tool[field] = value;
            let changed = serde_json::from_value(value_tool).unwrap();
            assert!(policy.validate(&changed).is_err(), "{field}");
        }
        for field in ["max_content_bytes", "executor_profile"] {
            let mut changed = serde_json::to_value(&policy).unwrap();
            changed["windows_read"][field] = if field == "max_content_bytes" {
                json!(WINDOWS_READ_MAX_CONTENT + 1)
            } else {
                json!("unsupported")
            };
            let changed: Policy = serde_json::from_value(changed).unwrap();
            assert!(changed.validate(&tool).is_err());
        }
        let mut changed = policy.clone();
        changed.profile.selectors[0]
            .aliases
            .push("/alternate".into());
        assert!(changed.validate(&tool).is_err());
        changed = policy.clone();
        changed
            .allowed_resources
            .push(changed.allowed_resources[0].clone());
        assert!(changed.validate(&tool).is_err());
        for args in [
            json!({}),
            json!({"path":null}),
            json!({"path":"approved.txt","extra":true}),
            json!({"path":"a".repeat(4097)}),
        ] {
            assert_eq!(
                windows_read_binding(&policy, &args),
                Err("native_windows_read_arguments_invalid")
            );
        }
        #[cfg(not(windows))]
        assert_eq!(
            windows_read_binding(&policy, &json!({"path":"approved.txt"})),
            Err("native_windows_read_platform_unsupported")
        );
    }
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
            windows_read: None,
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

#[cfg(test)]
mod windows_create_contract_tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, super::super::Tool, Policy) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let schema = super::super::canonical_digest(&create_file_schema());
        let tool = serde_json::from_value(json!({
            "name":"create_file", "schema_sha256":schema,
            "action_class":"side_effecting", "result_provenance":"untrusted", "egress":[]
        }))
        .unwrap();
        let policy = serde_json::from_value(json!({
            "profile":{"server_id":"windows-create-fixture","tool_name":"create_file",
                "schema_sha256":schema,"selectors":[{"pointer":"/path","kind":"path","allow_missing_leaf":true}]},
            "workspace":root,"cwd":root,"executor_sha256":windows_create_executor_sha256(),
            "classifier_sha256":"c".repeat(64),
            "allowed_resources":[{"kind":"path","canonical":root.join("approved.txt")}],
            "execution":{"operation":"create_file","action":"write",
                "executor_profile":WINDOWS_CREATE_EXECUTOR_PROFILE,"max_content_bytes":CREATE_FILE_MAX_CONTENT}
        })).unwrap();
        (directory, tool, policy)
    }

    #[test]
    fn windows_create_v5_binding_shape_keeps_linux_contract_distinct() {
        let mut admission: Admission = serde_json::from_value(json!({
            "server_id":"windows-create-fixture","host_call_id":1,
            "profile_sha256":"a".repeat(64),"executor_sha256":"b".repeat(64),
            "classifier_sha256":"c".repeat(64),"snapshot_sha256":"d".repeat(64),
            "definition_sha256":"e".repeat(64),"input_sha256":"f".repeat(64),
            "resources":[{"pointer":"/path","source":"argument",
                "resource":{"kind":"path","canonical":"approved.txt"}}],
            "execution":{"operation":"create_file","action":"write",
                "max_content_bytes":CREATE_FILE_MAX_CONTENT,
                "executor_profile":WINDOWS_CREATE_EXECUTOR_PROFILE,
                "policy_sha256":"a".repeat(64),"args_sha256":"b".repeat(64),
                "content_sha256":"c".repeat(64),"workspace_sha256":"d".repeat(64)}
        }))
        .unwrap();
        assert_eq!(admission.contract(), WINDOWS_CREATE_CONTRACT);
        assert_eq!(admission.validate_shape(), Ok(()));
        for field in [
            "executor_profile",
            "max_content_bytes",
            "policy_sha256",
            "args_sha256",
            "content_sha256",
            "workspace_sha256",
        ] {
            let mut changed = serde_json::to_value(&admission).unwrap();
            changed["execution"][field] = if field == "max_content_bytes" {
                json!(CREATE_FILE_MAX_CONTENT + 1)
            } else {
                json!("unsupported")
            };
            assert_eq!(
                serde_json::from_value::<Admission>(changed)
                    .unwrap()
                    .validate_shape(),
                Err("native_resource_invalid"),
                "{field}"
            );
        }
        admission.execution.as_mut().unwrap().executor_profile =
            CREATE_FILE_EXECUTOR_PROFILE.into();
        assert_eq!(admission.contract(), CREATE_CONTRACT);
        assert_eq!(admission.validate_shape(), Ok(()));
        admission.execution = None;
        assert_eq!(admission.contract(), CONTRACT);
    }

    #[test]
    fn windows_create_v5_policy_requires_explicit_closed_write_semantics() {
        let (_directory, tool, policy) = fixture();
        assert_eq!(policy.contract(), WINDOWS_CREATE_CONTRACT);
        assert!(policy.is_windows_create());
        assert!(policy.is_create_file());
        assert!(policy.is_windows_handles());
        assert_eq!(policy.validate(&tool).is_ok(), cfg!(windows));
        for (field, value) in [
            ("name", json!("other_create")),
            ("schema_sha256", json!("a".repeat(64))),
            ("action_class", json!("read_only")),
            ("result_provenance", json!("local_system")),
            (
                "egress",
                json!([{"pointer":"/path","kind":"url_host","optional":false}]),
            ),
        ] {
            let mut changed = json!({"name":"create_file","schema_sha256":tool.schema_sha256,
                "action_class":"side_effecting","result_provenance":"untrusted","egress":[]});
            changed[field] = value;
            assert!(
                policy
                    .validate(&serde_json::from_value(changed).unwrap())
                    .is_err(),
                "{field}"
            );
        }
        for changed in [
            json!({"max_content_bytes":CREATE_FILE_MAX_CONTENT + 1}),
            json!({"executor_profile":"sw-native/create-file/windows-handles/unknown"}),
        ] {
            let mut value = serde_json::to_value(&policy).unwrap();
            for (key, item) in changed.as_object().unwrap() {
                value["execution"][key] = item.clone();
            }
            assert!(serde_json::from_value::<Policy>(value)
                .unwrap()
                .validate(&tool)
                .is_err());
        }
        for (key, item) in [
            ("allow_missing_leaf", json!(false)),
            ("optional", json!(true)),
            ("aliases", json!(["/filename"])),
            ("default", json!("approved.txt")),
        ] {
            let mut changed = serde_json::to_value(&policy).unwrap();
            changed["profile"]["selectors"][0][key] = item;
            assert!(
                serde_json::from_value::<Policy>(changed)
                    .unwrap()
                    .validate(&tool)
                    .is_err(),
                "{key}"
            );
        }
        assert_ne!(
            create_file_executor_sha256(),
            windows_create_executor_sha256()
        );
    }

    #[test]
    fn windows_create_v5_arguments_enforce_original_fields_and_utf8_byte_cap() {
        let (_directory, _tool, policy) = fixture();
        let args = json!({"path":"approved.txt","content":"é".repeat(2048)});
        assert!(windows_create_arguments(&policy, &args).is_ok());
        for args in [
            json!({"path":"approved.txt","content":"é".repeat(2049)}),
            json!({"path":"approved.txt"}),
            json!({"path":"approved.txt","content":1}),
            json!({"path":"approved.txt","content":"ok","overwrite":true}),
            json!({"path":"","content":"ok"}),
            json!({"path":"a\n","content":"ok"}),
        ] {
            assert!(windows_create_arguments(&policy, &args).is_err(), "{args}");
        }
        let mut conflicting = policy;
        conflicting.windows_read = Some(WindowsReadPolicy {
            executor_profile: WINDOWS_READ_EXECUTOR_PROFILE.into(),
            max_content_bytes: WINDOWS_READ_MAX_CONTENT,
        });
        assert!(windows_create_arguments(&conflicting, &args).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_create_v5_binding_refuses_other_platforms_without_filesystem_effects() {
        let (directory, _tool, policy) = fixture();
        assert_eq!(
            create_file_binding(&policy, &json!({"path":"approved.txt","content":"ok"})),
            Err("native_windows_create_platform_unsupported")
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_create_v5_binding_covers_original_arguments_content_and_root_identity() {
        let (_directory, tool, policy) = fixture();
        let args = json!({"path":"approved.txt","content":"original"});
        let first = create_file_binding(&policy, &args).unwrap();
        let absolute = create_file_binding(
            &policy,
            &json!({"path":policy.workspace.join("approved.txt"),"content":"original"}),
        )
        .unwrap_err();
        assert_eq!(absolute, "native_windows_create_target_invalid");
        let root_text = policy.workspace.to_string_lossy();
        let original_absolute = root_text.strip_prefix("\\\\?\\").unwrap_or(&root_text);
        let absolute = create_file_binding(
            &policy,
            &json!({"path":format!("{original_absolute}\\approved.txt"),"content":"original"}),
        )
        .unwrap();
        assert_ne!(first.args_sha256, absolute.args_sha256);
        assert_eq!(first.workspace_sha256, absolute.workspace_sha256);
        let changed =
            create_file_binding(&policy, &json!({"path":"approved.txt","content":"changed"}))
                .unwrap();
        assert_ne!(first.content_sha256, changed.content_sha256);
        assert_ne!(first.args_sha256, changed.args_sha256);
        assert_eq!(first.workspace_sha256, changed.workspace_sha256);
        std::fs::write(policy.workspace.join("approved.txt"), "existing").unwrap();
        assert!(
            policy.validate(&tool).is_ok(),
            "existing destinations may be configured, never executed"
        );
        assert_eq!(
            create_file_binding(&policy, &args),
            Err("native_windows_create_target_invalid")
        );
    }
}
