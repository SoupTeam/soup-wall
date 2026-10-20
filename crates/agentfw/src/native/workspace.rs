// SPDX-License-Identifier: Apache-2.0
//! Pinned AgentDojo workspace semantics; logical objects are not OS grants.
use serde_json::{json, Value};

use super::{canonical_digest, Registry, ResultProvenance, Tool};

pub const PROFILE: &str = "agentdojo-workspace/1";
const INVENTORY: &str = include_str!("../../profiles/agentdojo-workspace-v1.json");

fn inventory() -> Value {
    serde_json::from_str(INVENTORY).expect("reviewed workspace inventory")
}

fn row(tool: &Tool) -> Result<Value, &'static str> {
    inventory()["tools"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["name"] == tool.name))
        .cloned()
        .ok_or("native_workspace_unknown_tool")
}

pub fn validate(tool: &Tool) -> anyhow::Result<()> {
    let row = row(tool).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        tool.workspace_profile.as_deref() == Some(PROFILE)
            && row["schema_sha256"] == tool.schema_sha256
            && canonical_digest(&row["schema"]) == tool.schema_sha256
            && row["action_class"] == serde_json::to_value(tool.action_class)?
            && matches!(tool.result_provenance, ResultProvenance::Untrusted)
            && row["egress"] == serde_json::to_value(&tool.egress)?
            && tool.resource_policy.is_none()
            && tool.mcp_result_profile.is_none(),
        "workspace declaration differs from reviewed original-tool semantics"
    );
    Ok(())
}

pub fn validate_registry(registry: &Registry) -> anyhow::Result<()> {
    if registry.registry_id == PROFILE || registry.tools.iter().any(|t| t.workspace_profile.is_some()) {
        anyhow::ensure!(
            registry.registry_id == PROFILE
                && registry.tools.len() == inventory()["tools"].as_array().unwrap().len()
                && registry.tools.iter().all(|t| t.workspace_profile.as_deref() == Some(PROFILE)),
            "workspace profile must cover the complete original suite"
        );
    }
    Ok(())
}

// Only validates the forms present in the compiled, hash-pinned schemas.
// Original Pydantic validation still runs before the collector calls admission.
fn shape(schema: &Value, root: &Value, value: &Value, depth: usize) -> bool {
    if depth > 12 {
        return false;
    }
    if let Some(reference) = schema["$ref"].as_str() {
        return reference
            .strip_prefix("#/$defs/")
            .is_some_and(|key| shape(&root["$defs"][key], root, value, depth + 1));
    }
    if let Some(choices) = schema["anyOf"].as_array() {
        return choices.iter().any(|s| shape(s, root, value, depth + 1));
    }
    if let Some(choices) = schema["enum"].as_array() {
        if !choices.contains(value) {
            return false;
        }
    }
    match schema["type"].as_str() {
        Some("string") => value.as_str().is_some_and(|s| s.len() <= 65_536),
        Some("null") => value.is_null(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("array") => value.as_array().is_some_and(|items| {
            items.len() <= 256
                && items
                    .iter()
                    .all(|v| shape(&schema["items"], root, v, depth + 1))
        }),
        Some("object") => value.as_object().is_some_and(|fields| {
            if let Some(props) = schema["properties"].as_object() {
                // Validated runtime arguments materialize all optional defaults.
                fields.len() == props.len()
                    && props.iter().all(|(k, s)| {
                        fields
                            .get(k)
                            .is_some_and(|v| shape(s, root, v, depth + 1))
                    })
            } else {
                fields.len() <= 32
            }
        }),
        _ => false,
    }
}

fn text(value: &Value) -> Result<&str, &'static str> {
    value
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or("native_workspace_resource_missing")
}

/// Complete typed extraction for the supported subset, after upstream defaults.
/// Collection scope explicitly denotes a dynamic query; it is not an empty grant.
pub fn extract(tool: &Tool, args: &Value) -> Result<Value, &'static str> {
    let row = row(tool)?;
    if row["supported"] != true {
        return Err("native_workspace_unsupported");
    }
    if !shape(&row["schema"], &row["schema"], args, 0) {
        return Err("native_workspace_validated_args_required");
    }
    let mut resources = vec![];
    for selector in row["resources"].as_array().expect("reviewed selectors") {
        let value = if let Some(pointer) = selector["pointer"].as_str() {
            text(args.pointer(pointer).ok_or("native_workspace_resource_missing")?)?
        } else {
            "*"
        };
        resources.push(json!({
            "kind":selector["kind"],"access":selector["access"],"value":value,
            "source":selector["pointer"].as_str().unwrap_or("reviewed_collection")
        }));
    }
    let mut destinations = vec![];
    for selector in &tool.egress {
        let selected = args
            .pointer(&selector.pointer)
            .ok_or("native_workspace_destination_missing")?;
        if selected.is_null() && selector.optional {
            continue;
        }
        let values = match selected {
            Value::Array(items) => items.iter().collect::<Vec<_>>(),
            Value::String(_) => vec![selected],
            _ => return Err("native_workspace_destination_invalid"),
        };
        if values.is_empty() && !selector.optional {
            return Err("native_workspace_destination_missing");
        }
        for value in values {
            let address = text(value)?;
            crate::mcp::resources::canonical_recipient(address)
                .map_err(|_| "native_workspace_destination_invalid")?;
            destinations.push(json!({"kind":"email","address":address,"source":selector.pointer}));
        }
    }
    if tool.name == "send_email" && !args["attachments"].is_null() {
        for (index, attachment) in args["attachments"]
            .as_array()
            .ok_or("native_workspace_attachment_invalid")?
            .iter()
            .enumerate()
        {
            // Original send_email treats ANY file_id as a file attachment, even
            // when type says event. Refuse ambiguous combinations instead.
            if attachment["type"] != "file"
                || attachment.as_object().is_none_or(|a| a.len() != 2)
            {
                return Err("native_workspace_attachment_unsupported");
            }
            resources.push(json!({"kind":"cloud_drive_file","access":"attach_reference",
                "value":text(&attachment["file_id"])?,
                "source":format!("/attachments/{index}/file_id")}));
        }
    }
    Ok(json!({"profile":PROFILE,"resources":resources,"destinations":destinations}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> Tool {
        let value = inventory();
        let row = value["tools"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap();
        serde_json::from_value(json!({"name":name,"schema_sha256":row["schema_sha256"],
            "action_class":row["action_class"],"result_provenance":"untrusted",
            "egress":row["egress"],"workspace_profile":PROFILE})).unwrap()
    }

    #[test]
    fn pinned_declarations_cannot_downgrade_provenance_schema_or_effect() {
        for row in inventory()["tools"].as_array().unwrap() {
            let mut t = tool(row["name"].as_str().unwrap());
            validate(&t).unwrap();
            t.result_provenance = ResultProvenance::LocalSystem;
            assert!(validate(&t).is_err());
            t.result_provenance = ResultProvenance::Untrusted;
            t.schema_sha256 = "0".repeat(64);
            assert!(validate(&t).is_err());
        }
        let mut t = tool("get_unread_emails");
        t.action_class = soup_wall_agent::ActionClass::ReadOnly;
        assert!(validate(&t).is_err());
    }

    #[test]
    fn all_recipients_and_nested_file_references_are_retained() {
        let args = json!({"recipients":["one@github.com","two@github.com"],"cc":["cc@github.com"],
            "bcc":["hidden@example.org"],"subject":"hello","body":"hello",
            "attachments":[{"type":"file","file_id":"13"},{"type":"file","file_id":"14"}]});
        let extracted = extract(&tool("send_email"), &args).unwrap();
        assert_eq!(extracted["destinations"].as_array().unwrap().len(), 4);
        assert_eq!(extracted["resources"].as_array().unwrap().len(), 3);
        assert_eq!(extracted["resources"][2]["value"], "14");
    }

    #[test]
    fn missing_ambiguous_and_environment_derived_destinations_refuse() {
        let t = tool("send_email");
        let good = json!({"recipients":["one@github.com"],"cc":null,"bcc":null,
            "subject":"","body":"","attachments":null});
        assert!(extract(&t, &good).is_ok());
        for (field, value) in [
            ("recipients", json!([])), ("bcc", json!([""])),
            ("attachments", json!([{"type":"event","event_details":{}}])),
            ("attachments", json!([{"type":"event","file_id":"13"}])),
        ] {
            let mut args = good.clone();
            args[field] = value;
            assert!(extract(&t, &args).is_err());
        }
        let mut missing = good;
        missing.as_object_mut().unwrap().remove("bcc");
        assert!(extract(&t, &missing).is_err());
        for name in ["create_calendar_event","cancel_calendar_event","reschedule_calendar_event"] {
            assert_eq!(extract(&tool(name), &json!({})).unwrap_err(),"native_workspace_unsupported");
        }
    }

    #[test]
    fn resource_ids_are_logical_and_collections_are_explicit() {
        let extracted = extract(&tool("get_file_by_id"), &json!({"file_id":"13"})).unwrap();
        assert_eq!(extracted["resources"][0]["kind"],"cloud_drive_file");
        assert!(extract(&tool("get_file_by_id"), &json!({"file_id":""})).is_err());
        let all = extract(&tool("list_files"), &json!({})).unwrap();
        assert_eq!(all["resources"][0]["value"],"*");
        assert_eq!(all["resources"][0]["source"],"reviewed_collection");
    }
}
