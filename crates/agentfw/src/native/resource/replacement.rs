// SPDX-License-Identifier: Apache-2.0
//! Additive, explicit replacement authority. Neither read nor create defaults
//! can select this operation. Serialized bindings are correlation, not permits.

use super::*;
use crate::mcp::replace_file::{self, Identity, RootIdentity};
use crate::mcp::resources::{valid_pointer, ResourceKind};
use soup_wall_agent::ActionClass;

pub const CONTRACT: &str = "sw-native/resources/9";
pub const POLICY_CONTRACT: &str = "sw-native/replace-file/binding/1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub contract_version: String,
    pub writer_exclusion: String,
    pub root: RootIdentity,
    pub old_sha256_selector: String,
    pub old_identity_selector: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub root: RootIdentity,
    pub old_identity: Identity,
    pub old_sha256: String,
    pub new_sha256: String,
    pub new_bytes: usize,
}

impl Binding {
    pub(super) fn valid(&self) -> bool {
        self.root.inode != 0
            && self.old_identity.inode != 0
            && self.old_identity.device == self.root.device
            && self.old_identity.size <= replace_file::MAX_BYTES as u64
            && self.new_bytes <= replace_file::MAX_BYTES
            && super::super::is_digest(&self.old_sha256)
            && super::super::is_digest(&self.new_sha256)
    }
}

pub struct Arguments<'a> {
    pub target: PathBuf,
    pub content: &'a str,
    pub old_sha256: &'a str,
    pub old_identity: Identity,
}

fn pointers<'a>(policy: &'a super::Policy, config: &'a Policy) -> [&'a str; 4] {
    [
        policy.path_selector(),
        policy.content_selector(),
        &config.old_sha256_selector,
        &config.old_identity_selector,
    ]
}

pub fn validate(policy: &super::Policy, tool: &super::super::Tool) -> anyhow::Result<()> {
    let exec = policy
        .execution
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("replacement execution missing"))?;
    let config = exec
        .replacement
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("replacement exclusion missing"))?;
    anyhow::ensure!(cfg!(target_os = "linux"), "replacement is Linux-only");
    anyhow::ensure!(
        config.contract_version == POLICY_CONTRACT
            && config.writer_exclusion == replace_file::EXCLUSION
            && config.root.inode != 0
            && exec.action == ExecutionAction::Write
            && exec.executor_profile == replace_file::PROFILE
            && exec.max_content_bytes == replace_file::MAX_BYTES
            && exec.path_selector.is_some()
            && exec.content_selector.is_some()
            && exec.response_contract.as_deref() == Some("sw-native/response/text/1")
            && policy.executor_sha256 == super::super::hash(replace_file::PROFILE.as_bytes())
            && tool.action_class == ActionClass::Destructive
            && tool.egress.is_empty()
            && tool.mcp_result_profile.is_none()
            && tool.workspace_profile.is_none()
            && matches!(
                tool.result_provenance,
                super::super::ResultProvenance::Untrusted
            )
            && !matches!(
                tool.name.as_str(),
                "create_file" | "read_document" | "https_get" | "https_post" | "write_file"
            )
            && policy.workspace == policy.cwd,
        "invalid replacement authority"
    );
    let selectors = pointers(policy, config);
    for (i, p) in selectors.iter().enumerate() {
        anyhow::ensure!(
            valid_pointer(p) && p.split('/').skip(1).all(|p| !p.is_empty()),
            "invalid replacement selector"
        );
        for q in &selectors[..i] {
            anyhow::ensure!(
                p != q && !p.starts_with(&format!("{q}/")) && !q.starts_with(&format!("{p}/")),
                "overlapping replacement selectors"
            );
        }
    }
    anyhow::ensure!(
        policy.profile.selectors.len() == 1 && policy.allowed_resources.len() == 1,
        "replacement requires one exact path"
    );
    let s = &policy.profile.selectors[0];
    anyhow::ensure!(
        s.pointer == selectors[0]
            && s.kind == ResourceKind::Path
            && s.aliases.is_empty()
            && !s.optional
            && s.default.is_none()
            && !s.allow_missing_leaf,
        "ambiguous replacement resource selector"
    );
    let Resource::Path { canonical } = &policy.allowed_resources[0] else {
        anyhow::bail!("replacement requires a path")
    };
    let path = Path::new(canonical);
    anyhow::ensure!(
        path.is_absolute()
            && path.parent() == Some(policy.workspace.as_path())
            && path.components().all(|p| !matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
        "replacement requires a direct child"
    );
    Ok(())
}

/// Consume every declared argument branch. No fallback selectors, arrays,
/// overlapping aliases, undeclared keys or optional/default values are accepted.
fn exact_arguments(value: &Value, remaining: &[&str]) -> bool {
    if remaining.contains(&"") {
        return remaining.len() == 1;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut expected = std::collections::BTreeMap::<String, Vec<&str>>::new();
    for path in remaining {
        let Some(path) = path.strip_prefix('/') else {
            return false;
        };
        let (key, tail) = path
            .split_once('/')
            .map(|(k, _)| (k, &path[k.len()..]))
            .unwrap_or((path, ""));
        expected
            .entry(key.replace("~1", "/").replace("~0", "~"))
            .or_default()
            .push(tail);
    }
    object.len() == expected.len()
        && expected
            .iter()
            .all(|(k, paths)| object.get(k).is_some_and(|v| exact_arguments(v, paths)))
}

pub fn arguments<'a>(
    policy: &super::Policy,
    args: &'a Value,
) -> Result<Arguments<'a>, &'static str> {
    let config = policy
        .execution
        .as_ref()
        .and_then(|e| e.replacement.as_ref())
        .ok_or("replace_authority_missing")?;
    let selectors = pointers(policy, config);
    if !exact_arguments(args, &selectors) {
        return Err("replace_arguments_undeclared_or_missing");
    }
    let path = args
        .pointer(selectors[0])
        .and_then(Value::as_str)
        .ok_or("replace_path_invalid")?;
    let content = args
        .pointer(selectors[1])
        .and_then(Value::as_str)
        .ok_or("replace_content_invalid")?;
    let old_sha256 = args
        .pointer(selectors[2])
        .and_then(Value::as_str)
        .filter(|s| super::super::is_digest(s))
        .ok_or("replace_old_digest_invalid")?;
    let old_identity: Identity = serde_json::from_value(
        args.pointer(selectors[3])
            .ok_or("replace_old_identity_missing")?
            .clone(),
    )
    .map_err(|_| "replace_old_identity_invalid")?;
    let Some(Resource::Path { canonical }) = policy.allowed_resources.first() else {
        return Err("replace_path_invalid");
    };
    let target = Path::new(canonical);
    let leaf = target
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("replace_path_invalid")?;
    if path != canonical && path != leaf {
        return Err("replace_path_not_allowed");
    }
    if content.len() > replace_file::MAX_BYTES || old_identity.size > replace_file::MAX_BYTES as u64
    {
        return Err("replace_content_over_cap");
    }
    Ok(Arguments {
        target: target.into(),
        content,
        old_sha256,
        old_identity,
    })
}

pub fn prepare(
    policy: &super::Policy,
    args: &Value,
) -> Result<replace_file::Prepared, &'static str> {
    let a = arguments(policy, args)?;
    let config = policy
        .execution
        .as_ref()
        .and_then(|e| e.replacement.as_ref())
        .ok_or("replace_authority_missing")?;
    replace_file::Prepared::prepare(
        &policy.workspace,
        &a.target,
        &config.root,
        &a.old_identity,
        a.old_sha256,
        a.content,
    )
    .map_err(|e| e.code)
}

pub fn binding(policy: &super::Policy, args: &Value) -> Result<ExecutionBinding, &'static str> {
    prepare(policy, args)?.preview().map_err(|e| e.code)?;
    frozen_binding(policy, args)
}

/// Descriptive correlation only. The live prepared/staged capability performs
/// filesystem checks; serialized expected facts cannot authorize publication.
pub fn frozen_binding(
    policy: &super::Policy,
    args: &Value,
) -> Result<ExecutionBinding, &'static str> {
    let selected = arguments(policy, args)?;
    let root = policy
        .execution
        .as_ref()
        .and_then(|e| e.replacement.as_ref())
        .ok_or("replace_authority_missing")?
        .root
        .clone();
    let plan = replace_file::Preview {
        executor_profile: replace_file::PROFILE,
        root,
        target: selected.target.to_string_lossy().into(),
        old_identity: selected.old_identity,
        old_sha256: selected.old_sha256.into(),
        new_sha256: replace_file::content_sha256(selected.content.as_bytes()),
        new_bytes: selected.content.len(),
        executing: false,
    };
    Ok(ExecutionBinding {
        operation: ExecutionOperation::ReplaceFile,
        action: ExecutionAction::Write,
        max_content_bytes: replace_file::MAX_BYTES,
        executor_profile: replace_file::PROFILE.into(),
        policy_sha256: super::super::canonical_digest(
            &serde_json::to_value(policy).expect("policy serializes"),
        ),
        args_sha256: super::super::canonical_digest(args),
        content_sha256: plan.new_sha256.clone(),
        workspace_sha256: super::super::canonical_digest(
            &serde_json::to_value(&plan.root).expect("identity serializes"),
        ),
        replacement: Some(Binding {
            root: plan.root,
            old_identity: plan.old_identity,
            old_sha256: plan.old_sha256,
            new_sha256: plan.new_sha256,
            new_bytes: plan.new_bytes,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_selectors_consume_every_argument_without_fallbacks() {
        let pointers = [
            "/spec/path",
            "/spec/content",
            "/expected/hash",
            "/expected/object",
        ];
        let valid = json!({"spec":{"path":"x","content":"new"},"expected":{"hash":"old","object":{"inode":123}}});
        assert!(exact_arguments(&valid, &pointers));
        for changed in [
            json!({"spec":{"path":"x","content":"new","extra":true},"expected":{"hash":"old","object":{}}}),
            json!({"spec":{"path":"x"},"expected":{"hash":"old","object":{}}}),
            json!({"spec":{"path":"x","content":"new"},"expected":{"hash":"old","object":{}},"content":"fallback"}),
            json!({"spec":["x","new"],"expected":{"hash":"old","object":{}}}),
        ] {
            assert!(!exact_arguments(&changed, &pointers));
        }
        assert!(exact_arguments(&json!({"a/b":{"c~d":1}}), &["/a~1b/c~0d"]));
    }
    #[test]
    fn replacement_binding_refuses_missing_old_facts_and_over_cap_new_content() {
        let mut binding = Binding {
            root: RootIdentity {
                device: 7,
                inode: 8,
            },
            old_identity: Identity {
                device: 7,
                inode: 9,
                size: 1,
                mtime_seconds: 1,
                mtime_nanoseconds: 2,
                ctime_seconds: 1,
                ctime_nanoseconds: 2,
                uid: 1,
                gid: 1,
                mode: 0o100600,
            },
            old_sha256: "a".repeat(64),
            new_sha256: "b".repeat(64),
            new_bytes: 1,
        };
        assert!(binding.valid());
        binding.new_bytes = replace_file::MAX_BYTES + 1;
        assert!(!binding.valid());
        binding.new_bytes = 1;
        binding.old_sha256.clear();
        assert!(!binding.valid());
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn replacement_never_falls_back_to_another_platform_executor() {
        assert_eq!(
            crate::mcp::replace_file::preview(Path::new("/tmp"), Path::new("/tmp/x"), "new")
                .unwrap_err()
                .code,
            "replace_platform_unsupported"
        );
    }
}
