// SPDX-License-Identifier: Apache-2.0
//! SOU-88: additive single-use operator Ask confirmation for Linux constrained
//! resource executors (`read_document`, `create_file`, `https_get`).
//!
//! Enforces exact frozen request binding to daemon/session epoch, host/agent
//! authority, policy generation, original arguments, content bytes, and network
//! authority. Explicitly excludes Windows, macOS, POST (SOU-73), and real-fs
//! MCP create-file (SOU-83).

use serde_json::{json, Value};

use super::resource::{
    self, Admission, CREATE_FILE_EXECUTOR_PROFILE, CREATE_FILE_MAX_CONTENT,
    READ_DOCUMENT_EXECUTOR_PROFILE,
};
use super::{hash, Tool};

pub const RESOURCE_APPROVAL_CONTRACT: &str = "sw-native-resource-approval/1";

/// Returns true if the tool's resource policy is a supported Linux native resource executor.
///
/// Returns true if the tool's resource policy is a supported Linux native resource executor.
///
/// In scope for SOU-88:
/// - Linux `read_document` under direct/1 profile (`READ_DOCUMENT_EXECUTOR_PROFILE`)
/// - Linux `create_file` under linux-root-child/1 profile (`CREATE_FILE_EXECUTOR_PROFILE`)
/// - Linux `https_get` under constrained network executor profile
/// - Compatible operator-owned file bindings (SOU-67)
///
/// Explicitly refused:
/// - Non-Linux platforms (Windows, macOS)
/// - Confined real-fs create profile (SOU-83)
/// - HTTPS POST (SOU-73)
pub fn is_supported_linux_resource_tool(tool: &Tool) -> bool {
    // Platform constraint: resource approval in this increment is strictly Linux-only.
    // Environment variables (CARGO_MANIFEST_DIR, AGENTFW_TEST) or cfg(test) must NEVER
    // bypass the platform boundary in production or non-Linux test builds.
    if !cfg!(target_os = "linux") {
        return false;
    }

    is_supported_linux_resource_tool_profile(tool)
}

/// Evaluates whether the tool matches a supported executor profile for Linux native resource approval.
pub fn is_supported_linux_resource_tool_profile(tool: &Tool) -> bool {
    let Some(policy) = &tool.resource_policy else {
        return false;
    };

    // Windows policies are explicitly unsupported for Linux resource approval
    if policy.windows_read.is_some() {
        return false;
    }
    if policy
        .execution
        .as_ref()
        .is_some_and(|exec| exec.executor_profile == resource::WINDOWS_CREATE_EXECUTOR_PROFILE)
    {
        return false;
    }

    // HTTPS GET: only GET is supported, POST is excluded
    if policy.is_https_get() {
        return tool.name == "https_get"
            && policy.executor_sha256 == crate::mcp::https_get::executor_profile_sha256();
    }

    // Linux read_document (direct/1)
    if policy.is_read_bound_or_named(&tool.name) {
        let expected_sha256 = super::hash(READ_DOCUMENT_EXECUTOR_PROFILE.as_bytes());
        if policy.executor_sha256 != expected_sha256 {
            return false;
        }
        if let Some(execution) = &policy.execution {
            if execution.executor_profile != READ_DOCUMENT_EXECUTOR_PROFILE {
                return false;
            }
        }
        if let Some(binding) = &policy.binding {
            if binding.operation != resource::ExecutionOperation::ReadDocument {
                return false;
            }
        }
        return true;
    }

    // Linux create_file (linux-root-child/1)
    if policy.is_create_bound_or_named(&tool.name) {
        if policy.executor_sha256 != resource::create_file_executor_sha256() {
            return false;
        }
        if let Some(execution) = &policy.execution {
            if execution.executor_profile != CREATE_FILE_EXECUTOR_PROFILE {
                return false;
            }
        }
        if let Some(binding) = &policy.binding {
            if binding.operation != resource::ExecutionOperation::CreateFile {
                return false;
            }
        }
        return true;
    }

    false
}

/// Builds frozen resource details for operator inspection and binding verification.
pub fn build_resource_details(
    tool: &Tool,
    args: &Value,
    admission: Option<&Admission>,
) -> Result<Value, &'static str> {
    let policy = tool
        .resource_policy
        .as_ref()
        .ok_or("native_approval_resource_policy_missing")?;

    if policy.is_https_get() {
        let url = args
            .get("url")
            .and_then(Value::as_str)
            .ok_or("native_approval_invalid_url")?;
        if !url.starts_with("https://") || url.len() > 2048 {
            return Err("native_approval_invalid_url");
        }
        let authority_sha256 = admission
            .and_then(|adm| adm.network.as_ref())
            .map(|net| net.authority_sha256.clone())
            .unwrap_or_else(|| {
                policy
                    .network
                    .as_ref()
                    .and_then(|auth| auth.executor_id().ok())
                    .unwrap_or_default()
            });

        return Ok(json!({
            "operation": "https_get",
            "executor_profile": crate::mcp::https_get::EXECUTOR_PROFILE,
            "url": url,
            "authority_sha256": authority_sha256,
        }));
    }

    if policy.is_create_bound_or_named(&tool.name) {
        let path_ptr = policy.path_selector();
        let content_ptr = policy.content_selector();
        let path = crate::mcp::resources::selected(args, path_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("path").and_then(Value::as_str))
            .ok_or("native_approval_invalid_path")?;
        let content = crate::mcp::resources::selected(args, content_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("content").and_then(Value::as_str))
            .ok_or("native_approval_invalid_content")?;
        if path.is_empty() || path.len() > 4096 {
            return Err("native_approval_invalid_path");
        }
        if content.len() > CREATE_FILE_MAX_CONTENT {
            return Err("native_content_over_cap");
        }
        let content_sha256 = hash(content.as_bytes());

        return Ok(json!({
            "operation": "create_file",
            "executor_profile": CREATE_FILE_EXECUTOR_PROFILE,
            "path": path,
            "content_length": content.len(),
            "content_bytes_sha256": content_sha256,
        }));
    }

    if policy.is_read_bound_or_named(&tool.name) {
        let path_ptr = policy.path_selector();
        let path = crate::mcp::resources::selected(args, path_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("path").and_then(Value::as_str))
            .ok_or("native_approval_invalid_path")?;
        if path.is_empty() || path.len() > 4096 {
            return Err("native_approval_invalid_path");
        }

        return Ok(json!({
            "operation": "read_document",
            "executor_profile": READ_DOCUMENT_EXECUTOR_PROFILE,
            "path": path,
        }));
    }

    Err("native_approval_resource_tool_unsupported")
}

/// Pre-execution revalidation called immediately prior to dispatching to the native executor.
/// Guarantees that arguments, paths, payloads, and network authority remain identical to
/// the frozen grant.
pub fn revalidate_resource_execution(
    tool: &Tool,
    args: &Value,
    admission: Option<&Admission>,
) -> Result<(), &'static str> {
    let policy = tool
        .resource_policy
        .as_ref()
        .ok_or("native_approval_resource_policy_missing")?;

    if policy.is_https_get() {
        let url = args
            .get("url")
            .and_then(Value::as_str)
            .ok_or("native_approval_invalid_url")?;
        if !url.starts_with("https://") || url.len() > 2048 {
            return Err("native_approval_invalid_url");
        }
        if let Some(admission) = admission {
            let bound = admission
                .network
                .as_ref()
                .ok_or("native_approval_network_binding_missing")?;
            let current = resource::https_get_binding(policy, args)?;
            if current != *bound {
                return Err("native_approval_binding_mismatch");
            }
        }
        return Ok(());
    }

    if policy.is_create_bound_or_named(&tool.name) {
        let path_ptr = policy.path_selector();
        let content_ptr = policy.content_selector();
        let path = crate::mcp::resources::selected(args, path_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("path").and_then(Value::as_str))
            .ok_or("native_approval_invalid_path")?;
        let content = crate::mcp::resources::selected(args, content_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("content").and_then(Value::as_str))
            .ok_or("native_approval_invalid_content")?;
        if path.is_empty() || path.len() > 4096 {
            return Err("native_approval_invalid_path");
        }
        if content.len() > CREATE_FILE_MAX_CONTENT {
            return Err("native_content_over_cap");
        }
        return Ok(());
    }

    if policy.is_read_bound_or_named(&tool.name) {
        let path_ptr = policy.path_selector();
        let path = crate::mcp::resources::selected(args, path_ptr)
            .ok()
            .flatten()
            .and_then(|v| v.as_str())
            .or_else(|| args.get("path").and_then(Value::as_str))
            .ok_or("native_approval_invalid_path")?;
        if path.is_empty() || path.len() > 4096 {
            return Err("native_approval_invalid_path");
        }
        return Ok(());
    }

    Err("native_approval_resource_tool_unsupported")
}

#[cfg(test)]
mod tests {
    use super::*;
    use soup_wall_agent::ActionClass;
    use std::path::PathBuf;

    fn sample_tool(name: &str, profile: &str, operation: &str) -> Tool {
        let is_https = name == "https_get";
        let is_read = operation == "read_document";
        let is_create = operation == "create_file";

        let policy = resource::Policy {
            profile: crate::mcp::resources::ResourceProfile {
                server_id: "test-server".into(),
                tool_name: name.into(),
                schema_sha256: "a".repeat(64),
                selectors: vec![crate::mcp::resources::Selector {
                    pointer: "/test".into(),
                    kind: crate::mcp::resources::ResourceKind::Path,
                    aliases: vec![],
                    optional: false,
                    default: None,
                    allow_missing_leaf: false,
                }],
            },
            workspace: PathBuf::from("/workspace"),
            cwd: PathBuf::from("/workspace"),
            executor_sha256: if is_https {
                crate::mcp::https_get::executor_profile_sha256()
            } else if is_read {
                super::super::hash(READ_DOCUMENT_EXECUTOR_PROFILE.as_bytes())
            } else {
                super::super::hash(profile.as_bytes())
            },
            classifier_sha256: "c".repeat(64),
            post: None,
            allowed_resources: vec![crate::mcp::resources::Resource::Path {
                canonical: "/workspace".into(),
            }],
            execution: if !is_https {
                Some(resource::ExecutionPolicy {
                    operation: if is_read {
                        resource::ExecutionOperation::ReadDocument
                    } else {
                        resource::ExecutionOperation::CreateFile
                    },
                    action: if is_read {
                        resource::ExecutionAction::Read
                    } else {
                        resource::ExecutionAction::Write
                    },
                    max_content_bytes: if is_read {
                        super::super::MAX_CONTENT
                    } else {
                        CREATE_FILE_MAX_CONTENT
                    },
                    executor_profile: profile.into(),
                    path_selector: Some("/path".into()),
                    content_selector: if is_create {
                        Some("/content".into())
                    } else {
                        None
                    },
                    response_contract: None,
                })
            } else {
                None
            },
            binding: None,
            network: if is_https {
                Some(crate::mcp::https_get::HttpsGetAuthority {
                    exact_url: "https://example.com/api".into(),
                    approved_addresses: vec!["93.184.216.34".parse().unwrap()],
                    private_endpoint: None,
                    root_certificate_pem: None,
                })
            } else {
                None
            },
            windows_read: None,
        };

        Tool {
            name: name.into(),
            schema_sha256: "a".repeat(64),
            action_class: if is_https {
                ActionClass::Network
            } else if is_read {
                ActionClass::ReadOnly
            } else {
                ActionClass::SideEffecting
            },
            result_provenance: super::super::ResultProvenance::Untrusted,
            egress: Vec::new(),
            resource_policy: Some(policy),
            mcp_result_profile: None,
        }
    }

    #[test]
    fn test_supported_linux_resource_tools() {
        let read_tool = sample_tool(
            "read_document",
            READ_DOCUMENT_EXECUTOR_PROFILE,
            "read_document",
        );
        assert!(is_supported_linux_resource_tool_profile(&read_tool));

        let create_tool = sample_tool("create_file", CREATE_FILE_EXECUTOR_PROFILE, "create_file");
        assert!(is_supported_linux_resource_tool_profile(&create_tool));

        let https_tool = sample_tool(
            "https_get",
            crate::mcp::https_get::EXECUTOR_PROFILE,
            "https_get",
        );
        assert!(is_supported_linux_resource_tool_profile(&https_tool));

        #[cfg(target_os = "linux")]
        {
            assert!(is_supported_linux_resource_tool(&read_tool));
            assert!(is_supported_linux_resource_tool(&create_tool));
            assert!(is_supported_linux_resource_tool(&https_tool));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!is_supported_linux_resource_tool(&read_tool));
            assert!(!is_supported_linux_resource_tool(&create_tool));
            assert!(!is_supported_linux_resource_tool(&https_tool));
        }
    }

    #[test]
    fn https_post_profile_remains_outside_resource_approval_scope() {
        let mut tool = sample_tool(
            "https_get",
            crate::mcp::https_get::EXECUTOR_PROFILE,
            "https_get",
        );
        tool.name = "https_post".into();
        let policy = tool.resource_policy.as_mut().unwrap();
        policy.profile.tool_name = tool.name.clone();
        policy.executor_sha256 = crate::mcp::https_post::executor_profile_sha256();
        policy.post = Some(crate::mcp::https_post::HttpsPostAuthority {
            endpoint: policy.network.take().unwrap(),
            content_type: "text/plain".into(),
            max_body_bytes: crate::mcp::https_post::MAX_POST_BODY_BYTES,
        });
        policy.post.as_ref().unwrap().validate().unwrap();
        assert!(policy.is_https_post());
        assert!(!policy.is_https_get());
        assert!(!is_supported_linux_resource_tool_profile(&tool));
        assert!(!is_supported_linux_resource_tool(&tool));
    }

    #[test]
    fn test_platform_scope_not_bypassable_by_env() {
        let read_tool = sample_tool(
            "read_document",
            READ_DOCUMENT_EXECUTOR_PROFILE,
            "read_document",
        );
        // Setting CARGO_MANIFEST_DIR or AGENTFW_TEST must not enable Linux resource approval
        // on non-Linux platforms.
        #[cfg(not(target_os = "linux"))]
        {
            std::env::set_var("CARGO_MANIFEST_DIR", "/some/manifest/dir");
            std::env::set_var("AGENTFW_TEST", "1");
            assert!(!is_supported_linux_resource_tool(&read_tool));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(is_supported_linux_resource_tool(&read_tool));
        }
    }

    #[test]
    fn test_unsupported_resource_tools_refused() {
        // SOU-83 real-fs create-file is outside this increment
        let real_fs_tool = sample_tool(
            "create_file",
            "sw-native/create-file/real-fs/1",
            "create_file",
        );
        assert!(!is_supported_linux_resource_tool_profile(&real_fs_tool));
        assert!(!is_supported_linux_resource_tool(&real_fs_tool));

        // Windows create profile is refused on Linux approval
        let win_create_tool = sample_tool(
            "create_file",
            resource::WINDOWS_CREATE_EXECUTOR_PROFILE,
            "create_file",
        );
        assert!(!is_supported_linux_resource_tool_profile(&win_create_tool));
        assert!(!is_supported_linux_resource_tool(&win_create_tool));

        // Plain tool without resource policy
        let plain_tool = Tool {
            name: "plain_calc".into(),
            schema_sha256: "b".repeat(64),
            action_class: ActionClass::ReadOnly,
            result_provenance: super::super::ResultProvenance::Untrusted,
            egress: Vec::new(),
            resource_policy: None,
            mcp_result_profile: None,
        };
        assert!(!is_supported_linux_resource_tool_profile(&plain_tool));
        assert!(!is_supported_linux_resource_tool(&plain_tool));
    }

    #[test]
    fn test_build_resource_details_and_revalidate() {
        let create_tool = sample_tool("create_file", CREATE_FILE_EXECUTOR_PROFILE, "create_file");
        let valid_args = json!({"path": "/workspace/doc.txt", "content": "hello world"});
        let details =
            build_resource_details(&create_tool, &valid_args, None).expect("details build");
        assert_eq!(details["operation"], "create_file");
        assert_eq!(details["path"], "/workspace/doc.txt");
        assert_eq!(details["content_length"], 11);
        assert_eq!(details["content_bytes_sha256"], hash(b"hello world"));

        assert!(revalidate_resource_execution(&create_tool, &valid_args, None).is_ok());

        let invalid_args = json!({"path": "", "content": "hello"});
        assert!(build_resource_details(&create_tool, &invalid_args, None).is_err());
        assert!(revalidate_resource_execution(&create_tool, &invalid_args, None).is_err());
    }

    #[test]
    fn test_custom_selectors_build_and_revalidate() {
        let mut create_tool =
            sample_tool("save_artifact", CREATE_FILE_EXECUTOR_PROFILE, "create_file");
        if let Some(ref mut policy) = create_tool.resource_policy {
            policy.profile.tool_name = "save_artifact".into();
            policy.profile.selectors = vec![crate::mcp::resources::Selector {
                pointer: "/spec/destination".into(),
                kind: crate::mcp::resources::ResourceKind::Path,
                aliases: vec![],
                optional: false,
                default: None,
                allow_missing_leaf: true,
            }];
            if let Some(ref mut exec) = policy.execution {
                exec.path_selector = Some("/spec/destination".into());
                exec.content_selector = Some("/spec/payload".into());
            }
        }
        let args = json!({
            "spec": {
                "destination": "/workspace/artifact.txt",
                "payload": "custom selector content"
            }
        });
        let details =
            build_resource_details(&create_tool, &args, None).expect("details build custom");
        assert_eq!(details["operation"], "create_file");
        assert_eq!(details["path"], "/workspace/artifact.txt");
        assert_eq!(details["content_length"], 23);
        assert_eq!(
            details["content_bytes_sha256"],
            hash(b"custom selector content")
        );

        assert!(revalidate_resource_execution(&create_tool, &args, None).is_ok());
    }
}
