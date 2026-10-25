// SPDX-License-Identifier: Apache-2.0
//! SOU-83: opt-in exact original-server create-only schema selection.
//!
//! This module does not grant OS write authority. The separate per-call
//! upstream sandbox and publication boundary must be accepted before the
//! transport will dispatch a mutation.

use anyhow::{ensure, Context};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, PathBuf};

use serde::{Deserialize, Serialize};

use super::ToolProfile;

pub const FORMAT: &str = "sw-mcp/filesystem-create-only/1";
pub const MAX_CONTENT_BYTES: usize = 4096;
const MAX_LEAF_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSelection {
    /// A single normalized leaf within the explicitly selected workspace.
    pub leaf: String,
    pub virtual_target: String,
    pub content_sha256: String,
    pub content_bytes: usize,
}

/// Collector observation of the exact original-server mutation. This is part
/// of the native call/approval binding, not a brokered resource capability.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateResource {
    pub contract_version: String,
    pub workspace: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub target: String,
    pub content_sha256: String,
    pub content_bytes: usize,
    pub must_be_absent: bool,
}

impl CreateResource {
    pub const CONTRACT: &str = "sw-mcp/original-create-resource/1";

    #[cfg(target_os = "linux")]
    pub(crate) fn capture(
        workspace: &crate::sandbox::PinnedWorkspace,
        args: &Value,
    ) -> anyhow::Result<Self> {
        let selection = validate_request(args)?;
        ensure!(
            workspace.verify_root_identity(),
            "selected create root changed"
        );
        ensure!(
            matches!(std::fs::symlink_metadata(workspace.canonical().join(&selection.leaf)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "selected create target must be absent"
        );
        let resource = Self {
            contract_version: Self::CONTRACT.into(),
            workspace: workspace.canonical().to_path_buf(),
            device: workspace.dev(),
            inode: workspace.ino(),
            target: selection.virtual_target,
            content_sha256: selection.content_sha256,
            content_bytes: selection.content_bytes,
            must_be_absent: true,
        };
        resource.validate(args)?;
        Ok(resource)
    }

    pub(crate) fn validate(&self, args: &Value) -> anyhow::Result<()> {
        let selection = validate_request(args)?;
        ensure!(
            self.contract_version == Self::CONTRACT
                && self.must_be_absent
                && self.inode != 0
                && self.workspace.is_absolute()
                && self.workspace.parent().is_some()
                && self.workspace.components().collect::<PathBuf>().as_os_str()
                    == self.workspace.as_os_str()
                && self
                    .workspace
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                && self
                    .workspace
                    .to_str()
                    .is_some_and(|path| path.len() <= 4096 && !path.chars().any(char::is_control))
                && self.target == selection.virtual_target
                && self.content_bytes == selection.content_bytes
                && self.content_sha256 == selection.content_sha256,
            "invalid selected create resource"
        );
        Ok(())
    }
}

/// Keep the pinned ORIGINAL discovery bytes and all read-only original tools.
/// The only additional supported name is original `write_file`; the transport
/// still refuses execution until the separate per-operation boundary is live.
pub fn classify_manifest(value: &Value) -> anyhow::Result<BTreeMap<String, ToolProfile>> {
    let mut profiles = super::classify_manifest(value)?;
    let write = profiles
        .get_mut("write_file")
        .context("pinned original write_file missing")?;
    ensure!(
        write.input.is_some() && write.output.is_some(),
        "pinned original write_file schema unavailable"
    );
    write.unsupported_reason = None;
    Ok(profiles)
}

/// Deliberately narrower than the upstream write_file schema. Original path
/// and content keys are retained without rewriting the request or server
/// result; no optional/unknown arguments, path aliases or nested targets.
pub fn validate_request(value: &Value) -> anyhow::Result<CreateSelection> {
    let args = value
        .as_object()
        .context("write_file arguments must be an object")?;
    ensure!(
        args.len() == 2 && args.contains_key("path") && args.contains_key("content"),
        "create-only accepts exactly original path and content"
    );
    let path = args["path"]
        .as_str()
        .context("original write_file path must be text")?;
    let content = args["content"]
        .as_str()
        .context("original write_file content must be UTF-8")?;
    ensure!(
        content.len() <= MAX_CONTENT_BYTES,
        "create-only content exceeds 4096 UTF-8 bytes"
    );
    let leaf = path
        .strip_prefix("/workspace/")
        .context("create-only path must be /workspace/<leaf>")?;
    ensure!(
        !leaf.is_empty()
            && leaf.len() <= MAX_LEAF_BYTES
            && !leaf.starts_with('.')
            && leaf
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "create-only target must be one normalized, non-hidden ASCII leaf"
    );
    let content_sha256 = format!("{:x}", Sha256::digest(content.as_bytes()));
    Ok(CreateSelection {
        leaf: leaf.to_owned(),
        virtual_target: path.to_owned(),
        content_sha256,
        content_bytes: content.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opt_in_profile_retains_original_schema_and_mutation_floor() {
        let original = super::super::original_manifest();
        let normal = super::super::classify_manifest(&original).unwrap();
        let selected = classify_manifest(&original).unwrap();
        assert_eq!(normal.len(), selected.len());
        assert!(normal["write_file"].unsupported_reason.is_some());
        assert!(selected["write_file"].unsupported_reason.is_none());
        for name in ["edit_file", "move_file", "create_directory"] {
            assert!(selected[name].unsupported_reason.is_some());
        }
        for name in ["read_file", "read_text_file", "list_directory"] {
            assert!(selected[name].unsupported_reason.is_none());
        }
        let mut drift = original.clone();
        drift["tools"][0]["name"] = json!("some_other_tool");
        assert!(classify_manifest(&drift).is_err());
    }

    #[test]
    fn original_create_request_has_a_single_bounded_resource_identity() {
        let args = json!({"path":"/workspace/hello.txt","content":"hello 🌍"});
        let selected = validate_request(&args).unwrap();
        assert_eq!(selected.leaf, "hello.txt");
        assert_eq!(selected.virtual_target, "/workspace/hello.txt");
        assert_eq!(selected.content_bytes, "hello 🌍".len());
        assert_eq!(selected.content_sha256.len(), 64);
        assert!(validate_request(&json!({"path":"/workspace/empty","content":""})).is_ok());
        assert!(
            validate_request(&json!({"path":"/workspace/zero","content":"x".repeat(4096)})).is_ok()
        );
        assert!(
            validate_request(&json!({"path":"/workspace/zero","content":"x".repeat(4097)}))
                .is_err()
        );
        assert!(
            validate_request(&json!({"path":"/workspace/zero","content":"🌍".repeat(1025)}))
                .is_err()
        );
    }

    #[test]
    fn no_alias_extra_args_or_original_destructive_variants() {
        let invalid = [
            json!({"path":"/workspace/a","content":"x","append":false}),
            json!({"path":"/workspace/a","content":"x","overwrite":false}),
            json!({"path":"/workspace/a/b","content":"x"}),
            json!({"path":"/workspace/../escape","content":"x"}),
            json!({"path":"/workspace/./a","content":"x"}),
            json!({"path":"a","content":"x"}),
            json!({"path":"/tmp/a","content":"x"}),
            json!({"path":"/workspace/.env","content":"x"}),
            json!({"path":"/workspace/a\\b","content":"x"}),
            json!({"path":"/workspace/a:b","content":"x"}),
            json!({"path":"/workspace/a%2Fb","content":"x"}),
            json!({"path":"/workspace/a","content":12}),
            json!({"path":"/workspace/a"}),
            json!({"path":"/workspace/a","content":"x","recursive":false}),
            json!({"path":"/workspace/a","content":"x","mode":384}),
        ];
        for args in invalid {
            assert!(
                validate_request(&args).is_err(),
                "unexpected acceptance: {args}"
            );
        }
    }

    #[test]
    fn selection_does_not_modify_readonly_profile_or_exact_original_manifest() {
        let args = json!({"path":"/workspace/a.txt","content":"ok"});
        assert!(
            super::super::classify_manifest(&super::super::original_manifest()).unwrap()
                ["write_file"]
                .unsupported_reason
                .is_some()
        );
        assert!(validate_request(&args).is_ok());
        assert_eq!(
            super::super::original_manifest_for(FORMAT).unwrap(),
            super::super::original_manifest()
        );
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_create_resource_binds_exact_bytes_target_and_absent_only_semantics() {
        let args = json!({"path":"/workspace/a.txt","content":"café 🥣"});
        let selection = validate_request(&args).unwrap();
        let valid = CreateResource {
            contract_version: CreateResource::CONTRACT.into(),
            workspace: "/tmp/selected-root".into(),
            device: 1,
            inode: 2,
            target: selection.virtual_target,
            content_sha256: selection.content_sha256,
            content_bytes: selection.content_bytes,
            must_be_absent: true,
        };
        valid.validate(&args).unwrap();
        for (field, value) in [
            ("contract_version", json!("sw-native/create/2")),
            ("workspace", json!("/")),
            ("workspace", json!("relative")),
            ("workspace", json!("/tmp/../other")),
            ("inode", json!(0)),
            ("target", json!("/workspace/b.txt")),
            ("content_sha256", json!("0".repeat(64))),
            ("content_bytes", json!(7)),
            ("must_be_absent", json!(false)),
        ] {
            let mut changed = json!(valid);
            changed[field] = value;
            let changed: CreateResource = serde_json::from_value(changed).unwrap();
            assert!(changed.validate(&args).is_err(), "{field}");
        }
        let mut changed = args.clone();
        changed["content"] = json!("other");
        assert!(valid.validate(&changed).is_err());
        let mut changed = json!(valid);
        changed["overwrite"] = json!(true);
        assert!(serde_json::from_value::<CreateResource>(changed).is_err());
    }
}
