// SPDX-License-Identifier: Apache-2.0
//! Strict descriptive plan and generated resource declarations. They are not
//! grants. The existing native broker still authorizes every invocation.
use crate::mcp::replace_file::{self, Identity, RootIdentity};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub const MAX_TARGETS: usize = 8;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub home: PathBuf,
    pub id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub python: Pin,
    pub python_version: String,
    pub classifier: Pin,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub identity: Identity,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub read: bool,
    pub create: bool,
    pub replacement: Option<Baseline>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format: String,
    #[serde(
        default,
        deserialize_with = "super::quota::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub mutation_quota: Option<super::quota::Limits>,
    pub exclusion: String,
    pub root: PathBuf,
    pub root_identity: RootIdentity,
    pub agent: Pin,
    pub claude: Pin,
    pub component: Component,
    pub policy_sha256: String,
    pub targets: Vec<Target>,
}
pub fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(replace_file::content_sha256(&canonical(value)?))
}
pub fn leaf(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            ((self.format == super::FORMAT && self.mutation_quota.is_none())
                || (self.format == super::QUOTA_PROFILE && self.mutation_quota.is_some()))
                && self.exclusion == replace_file::EXCLUSION,
            "edit_profile_contract"
        );
        if let Some(limits) = &self.mutation_quota {
            limits.validate()?;
        }
        ensure!(
            self.root.is_absolute() && self.root_identity.inode != 0,
            "edit_root_invalid"
        );
        ensure!(
            self.targets
                .iter()
                .any(|t| t.create || t.replacement.is_some()),
            "edit_mutation_selection_required"
        );
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= MAX_TARGETS,
            "edit_target_limit"
        );
        let mut names = BTreeSet::new();
        for t in &self.targets {
            ensure!(
                leaf(&t.name)
                    && names.insert(&t.name)
                    && (t.read || t.create || t.replacement.is_some()),
                "edit_target_invalid"
            );
            ensure!(
                !(t.create && t.replacement.is_some()),
                "edit_target_conflicting_operations"
            );
            if let Some(b) = &t.replacement {
                ensure!(
                    crate::native::is_digest(&b.sha256)
                        && b.identity.size <= 4096
                        && b.identity.inode != 0
                        && b.identity.device == self.root_identity.device,
                    "edit_baseline_invalid"
                );
            }
        }
        ensure!(
            self.targets.windows(2).all(|w| w[0].name < w[1].name),
            "edit_targets_not_sorted"
        );
        for pin in [
            &self.agent,
            &self.claude,
            &self.component.python,
            &self.component.classifier,
        ] {
            ensure!(
                pin.path.is_absolute() && crate::native::is_digest(&pin.sha256),
                "edit_runtime_pin_invalid"
            );
        }
        ensure!(
            crate::native::is_digest(&self.component.id)
                && crate::native::is_digest(&self.policy_sha256),
            "edit_profile_pin_invalid"
        );
        ensure!(
            self.component.home.is_absolute()
                && [&self.component.source_commit, &self.component.source_tree]
                    .iter()
                    .all(|s| s.len() == 40
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
            "edit_source_identity_invalid"
        );
        Ok(())
    }
    pub fn tools(&self) -> Value {
        let mut tools = Vec::new();
        for (i, t) in self.targets.iter().enumerate() {
            let path = json!({"type":"string","const":t.name,"minLength":1,"maxLength":128});
            if t.read {
                tools.push(json!({"name":format!("read_output_{i}"),"description":"Read the selected private output document.",
                    "inputSchema":{"type":"object","properties":{"path":path},"required":["path"],"additionalProperties":false}}));
            }
            for (operation, baseline) in [("create", None), ("replace", t.replacement.as_ref())] {
                if (operation == "create" && !t.create)
                    || (operation == "replace" && baseline.is_none())
                {
                    continue;
                }
                let mut properties =
                    json!({"path":path,"content":{"type":"string","maxLength":4096}});
                let mut required = vec!["path", "content"];
                if let Some(b) = baseline {
                    let fields = serde_json::to_value(&b.identity)
                        .expect("identity")
                        .as_object()
                        .expect("object")
                        .iter()
                        .map(|(k, v)| (k.clone(), json!({"type":"integer","const":v})))
                        .collect::<serde_json::Map<_, _>>();
                    properties["old_sha256"] =
                        json!({"type":"string","const":b.sha256,"minLength":64,"maxLength":64});
                    properties["old_identity"] = json!({"type":"object","required":fields.keys().collect::<Vec<_>>(),"properties":fields,"additionalProperties":false});
                    required.extend(["old_sha256", "old_identity"]);
                }
                tools.push(json!({"name":format!("{operation}_output_{i}"),
                    "description":if operation=="create" {"Create the exact selected private output with bounded text."} else {"Replace the exact selected private output using the required fixed old identity and digest."},
                    "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}}));
            }
        }
        json!(tools)
    }
    pub fn registry(&self) -> Result<Value> {
        self.validate()?;
        let mut tools = Vec::new();
        for definition in self.tools().as_array().expect("tools") {
            let name = definition["name"].as_str().expect("name");
            let index = name.rsplit('_').next().expect("index").parse::<usize>()?;
            let target = &self.targets[index];
            let replacing = name.starts_with("replace_");
            let creating = name.starts_with("create_");
            let executor = if replacing {
                replace_file::PROFILE
            } else if creating {
                crate::native::resource::CREATE_FILE_EXECUTOR_PROFILE
            } else {
                crate::native::resource::READ_DOCUMENT_EXECUTOR_PROFILE
            };
            let mut policy = json!({"profile":{"server_id":super::SERVER,"tool_name":name,"schema_sha256":digest(&definition["inputSchema"])?,
                    "selectors":[{"pointer":"/path","kind":"path","allow_missing_leaf":creating}]},
                "workspace":self.root,"cwd":self.root,"executor_sha256":replace_file::content_sha256(executor.as_bytes()),"classifier_sha256":self.component.classifier.sha256,
                "allowed_resources":[{"kind":"path","canonical":self.root.join(&target.name)}]});
            if replacing || creating {
                policy["execution"] = json!({"operation":if replacing {"replace_file"} else {"create_file"},"action":"write","max_content_bytes":4096,
                    "executor_profile":executor,"path_selector":"/path","content_selector":"/content","response_contract":"sw-native/response/text/1"});
                if replacing {
                    policy["execution"]["replacement"] = json!({"contract_version":crate::native::resource::replacement::POLICY_CONTRACT,
                    "writer_exclusion":self.exclusion,"root":self.root_identity,"old_sha256_selector":"/old_sha256","old_identity_selector":"/old_identity"});
                }
            } else {
                policy["binding"] = json!({"contract_version":crate::native::resource::BINDING_CONTRACT,"operation":"read_document","path_selector":"/path","executor_profile":executor});
            }
            tools.push(json!({"name":name,"schema_sha256":digest(&definition["inputSchema"])?,"action_class":if replacing {"destructive"} else if creating {"side_effecting"} else {"read_only"},
                "result_provenance":"untrusted","egress":[],"resource_policy":policy}));
        }
        Ok(
            json!({"contract_version":crate::native::CONTRACT,"registry_id":format!("installed-edit-{}",digest(self)?),"tools":tools}),
        )
    }
}

#[cfg(test)]
pub(super) fn fixture() -> Profile {
    let absolute = |name: &str| {
        if cfg!(windows) {
            PathBuf::from(r"C:\owned").join(name)
        } else {
            PathBuf::from("/owned").join(name)
        }
    };
    let pin = || Pin {
        path: absolute("runtime"),
        sha256: replace_file::content_sha256(crate::token::generate().as_bytes()),
    };
    Profile {
        format: super::FORMAT.into(),
        mutation_quota: None,
        exclusion: replace_file::EXCLUSION.into(),
        root: absolute("output"),
        root_identity: RootIdentity {
            device: 1,
            inode: 2,
        },
        agent: pin(),
        claude: pin(),
        component: Component {
            home: absolute("agent"),
            id: replace_file::content_sha256(crate::token::generate().as_bytes()),
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(40),
            python: pin(),
            python_version: "3.12.3".into(),
            classifier: pin(),
        },
        policy_sha256: replace_file::content_sha256(crate::token::generate().as_bytes()),
        targets: vec![Target {
            name: "draft.txt".into(),
            read: true,
            create: true,
            replacement: None,
        }],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_leaf_selection_has_no_alias_or_hidden_control_paths() {
        for name in ["result.txt", "new-output_1.json"] {
            assert!(leaf(name));
        }
        for name in ["", "..", "a/b", "../x", ".claude", "a\\b", "a b", "a\n"] {
            assert!(!leaf(name));
        }
    }
    #[test]
    fn create_schema_cannot_widen_target_or_hide_extra_arguments() {
        let p = fixture();
        p.validate().unwrap();
        let schema = crate::mcp::input::InputSchema::read(&p.tools()[1]["inputSchema"]).unwrap();
        schema
            .validate(&json!({"path":"draft.txt","content":"Selected output."}))
            .unwrap();
        for args in [
            json!({"path":"other.txt","content":"x"}),
            json!({"path":"../draft.txt","content":"x"}),
            json!({"path":"draft.txt","content":"x","other":1}),
            json!({"path":"draft.txt"}),
            json!({"path":"draft.txt","content":"x".repeat(4097)}),
        ] {
            assert!(schema.validate(&args).is_err());
        }
    }
    #[test]
    fn replacement_schema_freezes_old_object_and_rejects_changed_content_authority() {
        let mut p = fixture();
        p.targets[0].create = false;
        let identity = Identity {
            device: 1,
            inode: 3,
            size: 4,
            mtime_seconds: 1,
            mtime_nanoseconds: 2,
            ctime_seconds: 3,
            ctime_nanoseconds: 4,
            uid: 1000,
            gid: 1000,
            mode: 0o100600,
        };
        p.targets[0].replacement = Some(Baseline {
            identity: identity.clone(),
            sha256: replace_file::content_sha256(b"old!"),
        });
        p.validate().unwrap();
        let tools = p.tools();
        let schema = crate::mcp::input::InputSchema::read(&tools[1]["inputSchema"]).unwrap();
        let mut args = json!({"path":"draft.txt","content":"New summary.","old_identity":identity,"old_sha256":p.targets[0].replacement.as_ref().unwrap().sha256});
        schema.validate(&args).unwrap();
        args["old_identity"]["inode"] = json!(4);
        assert!(schema.validate(&args).is_err());
        args["old_identity"] = json!(identity);
        args["old_sha256"] = json!("f".repeat(64));
        assert!(schema.validate(&args).is_err());
        let old = digest(&p).unwrap();
        p.targets[0].replacement.as_mut().unwrap().identity.inode = 4;
        assert_ne!(digest(&p).unwrap(), old);
    }
    #[test]
    fn unreviewed_fields_conflicting_operations_and_missing_exclusion_are_refused() {
        let p = fixture();
        let mut value = serde_json::to_value(&p).unwrap();
        value["grant_all"] = json!(true);
        assert!(serde_json::from_value::<Profile>(value).is_err());
        for mutate in [0, 1, 2, 3] {
            let mut p = p.clone();
            match mutate {
                0 => p.exclusion.clear(),
                1 => p.targets[0].name = ".claude".into(),
                2 => p.targets.push(p.targets[0].clone()),
                _ => p.component.source_tree = "z".repeat(40),
            }
            assert!(p.validate().is_err());
        }
        let mut p = p;
        p.targets[0].create = false;
        assert!(p.validate().is_err());
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn edit_policy_preserves_every_independent_readonly_floor() {
        use soup_wall_agent::AgentPolicySet;
        let base = AgentPolicySet::from_yaml(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/pilot/linux-readonly-v1/policy.yaml"
        )))
        .unwrap();
        let edit = AgentPolicySet::from_yaml(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/pilot/linux-private-edit-v1/policy.yaml"
        )))
        .unwrap();
        let expected = serde_json::to_value(&base).unwrap();
        let actual = serde_json::to_value(&edit).unwrap();
        for floor in expected["agent_policies"]
            .as_array()
            .unwrap()
            .iter()
            .skip(2)
        {
            assert!(
                actual["agent_policies"].as_array().unwrap().contains(floor),
                "removed floor: {}",
                floor["name"]
            );
        }
        assert_eq!(actual["egress_allowlist"], expected["egress_allowlist"]);
        use soup_wall_agent::{
            ActionClass, AgentEvent, AgentFirewall, EventKind, Verdict, DEFAULT_TAINT_CAP,
        };
        let mut fw = AgentFirewall::new(edit, DEFAULT_TAINT_CAP);
        fw.try_register_provenance_context("owned-edit").unwrap();
        let ev = AgentEvent {
            session: "owned-edit".into(),
            agent: "private-output".into(),
            parent: None,
            seq: 1,
            at_ms: 0,
            kind: EventKind::ToolCall {
                tool: "replace_output_0".into(),
                args: json!({"path":"result.txt","content":"Bounded new report."}),
            },
        };
        assert_eq!(
            fw.inspect_native_call(&ev, ActionClass::Destructive, &[])
                .verdict,
            Verdict::Ask
        );
        assert_eq!(
            fw.inspect_native_call(&ev, ActionClass::SideEffecting, &[])
                .verdict,
            Verdict::Ask
        );
        assert_eq!(
            fw.inspect_native_call(&ev, ActionClass::PrivilegeChanging, &[])
                .verdict,
            Verdict::Deny
        );
        assert_eq!(
            fw.inspect_native_call(&ev, ActionClass::Network, &[])
                .verdict,
            Verdict::Deny
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_registry_is_accepted_without_any_filesystem_mutation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut profile = fixture();
        profile.root = root.clone();
        profile.root_identity = replace_file::inspect_workspace(&root).unwrap();
        let raw = canonical(&profile.registry().unwrap()).unwrap();
        crate::native::NativeState::from_bytes(
            &raw,
            &replace_file::content_sha256(&raw),
            crate::token::generate(),
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::write(root.join("draft.txt"), b"Old output.\n").unwrap();
        std::fs::set_permissions(
            root.join("draft.txt"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let before = replace_file::preview(&root, &root.join("draft.txt"), "").unwrap();
        profile.targets[0].create = false;
        profile.targets[0].replacement = Some(Baseline {
            identity: before.old_identity.clone(),
            sha256: before.old_sha256.clone(),
        });
        let raw = canonical(&profile.registry().unwrap()).unwrap();
        crate::native::NativeState::from_bytes(
            &raw,
            &replace_file::content_sha256(&raw),
            crate::token::generate(),
        )
        .unwrap();
        let after = replace_file::preview(&root, &root.join("draft.txt"), "").unwrap();
        assert_eq!(before.old_identity, after.old_identity);
        assert_eq!(before.old_sha256, after.old_sha256);
    }
}
