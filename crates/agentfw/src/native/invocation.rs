// SPDX-License-Identifier: Apache-2.0
//! Native invocation semantics derived solely from installed reviewed profiles.

use serde_json::Value;
use soup_wall_agent::{
    ActionClass, AgentEvent, AgentFirewall, EventKind, NativeArgumentRoles, Outcome,
};

use super::Tool;
use crate::mcp::server_profile;

fn roles(tool: &Tool, args: &Value) -> Result<NativeArgumentRoles, &'static str> {
    if !matches!(
        tool.mcp_result_profile.as_deref(),
        Some(server_profile::FORMAT | server_profile::filesystem_roots::FORMAT)
    ) {
        return Ok(NativeArgumentRoles::CommandBearing);
    }
    // Recheck daemon-side as well as collector-side. No request field, tool
    // description or caller-provided read_only annotation can choose this path.
    // Existing startup validation also binds the registry to these exact pins.
    let validate = || -> anyhow::Result<()> {
        anyhow::ensure!(
            tool.action_class == ActionClass::ReadOnly
                && tool.egress.is_empty()
                && tool.resource_policy.is_none()
                && tool.workspace_profile.is_none()
                && matches!(tool.result_provenance, super::ResultProvenance::Untrusted),
            "unsupported literal authority"
        );
        let manifest = server_profile::original_manifest();
        let definition = manifest["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|definition| definition["name"] == tool.name)
            .ok_or_else(|| anyhow::anyhow!("unreviewed literal tool"))?;
        anyhow::ensure!(
            super::canonical_digest(&definition["inputSchema"]) == tool.schema_sha256,
            "literal schema mismatch"
        );
        let profiles = server_profile::classify_manifest(&manifest)?;
        profiles
            .get(&tool.name)
            .ok_or_else(|| anyhow::anyhow!("unreviewed literal profile"))?
            .validate_arguments(args)
    };
    validate().map_err(|_| "native_selected_arguments_invalid")?;
    // This is an executor-semantic table, not a name-based authority whitelist:
    // every selection above requires the pinned full schema/profile and values.
    // Only these reviewed literal string fields are exempt from shell effects.
    let fields: &'static [&'static str] = match tool.name.as_str() {
        "read_file"
        | "read_text_file"
        | "list_directory"
        | "list_directory_with_sizes"
        | "get_file_info" => &["path"],
        "read_multiple_files" => &["paths"],
        "search_files" => &["path", "pattern", "excludePatterns"],
        "directory_tree" => &["path", "excludePatterns"],
        "list_allowed_directories" => &[],
        _ => return Err("native_selected_arguments_invalid"),
    };
    Ok(NativeArgumentRoles::ValidatedLiteralFields(fields))
}

pub(super) fn inspect(
    firewall: &mut AgentFirewall,
    event: &AgentEvent,
    tool: &Tool,
    hosts: &[String],
) -> Result<Outcome, &'static str> {
    let EventKind::ToolCall { tool: name, args } = &event.kind else {
        return Err("native_invocation_required");
    };
    if name != &tool.name {
        return Err("native_tool_mismatch");
    }
    Ok(firewall.inspect_native_call_with_argument_roles(
        event,
        tool.action_class,
        hosts,
        roles(tool, args)?,
    ))
}
