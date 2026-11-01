// SPDX-License-Identifier: Apache-2.0
//! Inert narrowing of an explicitly selected reviewed profile and policy.
//! No runtime, classifier worker, home discovery or activation is invoked.
mod io;
use crate::mcp::{admission::Strict, profile_author};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{
    policy::{AgentCondition, AgentRule},
    ActionClass, AgentPolicySet, Verdict,
};
use std::os::unix::fs::MetadataExt;
use std::{collections::BTreeSet, path::PathBuf};
use subtle::ConstantTimeEq;

const FORMAT: &str = "sw-operator-policy-candidate/1";
const CONSTRAINTS: &str = "sw-operator-policy-constraints/1";
const CAP: usize = 64 * 1024;
const FILES: &[&str] = &[
    "profile.json",
    "registry.json",
    "source-snapshot.json",
    "operator-declarations.json",
    "resource-profiles.json",
    "native-config.json",
];

#[derive(Args)]
pub struct Selection {
    /// Complete accepted `mcp-profile compile` bundle. Nothing is discovered.
    #[arg(long)]
    profile: PathBuf,
    /// Existing owner-private policy YAML, selected explicitly.
    #[arg(long)]
    policy: PathBuf,
}
#[derive(Args)]
pub struct Candidate {
    #[command(flatten)]
    selection: Selection,
    /// Strict versioned restrictions; never an arbitrary YAML patch.
    #[arg(long)]
    constraints: PathBuf,
    /// Existing sw-policy-offline-input/1 envelope (1..64 ordered events).
    #[arg(long)]
    examples: PathBuf,
    /// Exact new private export directory; preview binds its parent too.
    #[arg(long)]
    out: PathBuf,
    /// Explicitly disclose policy, tool and destination names on local stdout.
    #[arg(long)]
    show_private_scope: bool,
}
#[derive(Subcommand)]
pub enum Command {
    /// Inspect current profile, registry, schema and policy pins, without execution.
    Inspect(Selection),
    /// Read-only semantic diff and actual offline evaluator comparison.
    Preview(Candidate),
    /// Create a private inert candidate after exact preview confirmation.
    Create {
        #[command(flatten)]
        candidate: Candidate,
        #[arg(long)]
        confirm: String,
    },
    /// Reconstruct and verify an exported candidate against the current source.
    Validate {
        #[command(flatten)]
        candidate: Candidate,
        #[arg(long)]
        exported: PathBuf,
        #[arg(long)]
        expect_candidate: String,
    },
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Restrictions {
    format: String,
    deny_actions: Vec<ActionClass>,
    /// Tool-specific conditions are not supported by AgentPolicySet. A tool
    /// group is expressible only if it covers EVERY tool of each named class.
    deny_tools: Vec<String>,
    allowed_destinations: Option<Vec<String>>,
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn strict<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let Strict(value) = serde_json::from_slice(bytes).context("candidate_strict_json")?;
    Ok(serde_json::from_value(value).context("candidate_unsupported_fields_or_values")?)
}
fn rank(v: Verdict, fallback: Option<Verdict>) -> u8 {
    match soup_wall_agent::resolution::resolve(v, fallback, false) {
        Verdict::Deny => 3,
        Verdict::Ask => 2,
        Verdict::Allow => 0,
        Verdict::Escalate => 1,
    }
}
fn host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.ends_with('.')
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn restrict(
    base: &AgentPolicySet,
    profile: &profile_author::Profile,
    r: &Restrictions,
) -> Result<AgentPolicySet> {
    ensure!(
        r.format == CONSTRAINTS && r.deny_actions.len() <= 5 && r.deny_tools.len() <= 64,
        "candidate_constraint_contract_or_cap"
    );
    let actions: BTreeSet<_> = r.deny_actions.iter().copied().collect();
    ensure!(
        actions.len() == r.deny_actions.len(),
        "candidate_duplicate_action"
    );
    let tools: BTreeSet<_> = r.deny_tools.iter().collect();
    ensure!(
        tools.len() == r.deny_tools.len(),
        "candidate_duplicate_tool"
    );
    let mut tool_classes = BTreeSet::new();
    for name in &tools {
        let t = profile.tools.get(*name).context("candidate_unknown_tool")?;
        let class: ActionClass = serde_json::from_value(json!(t.action_class))?;
        tool_classes.insert(class);
    }
    for (name, t) in &profile.tools {
        let class: ActionClass = serde_json::from_value(json!(t.action_class))?;
        ensure!(
            !tool_classes.contains(&class) || r.deny_tools.contains(name),
            "candidate_partial_tool_class_unsupported"
        );
    }
    let mut candidate = base.clone();
    let mut added = Vec::new();
    for action in actions {
        added.push(AgentRule {
            name: format!("operator-candidate-deny-{action:?}"),
            when: AgentCondition {
                action_class: Some(action),
                ..Default::default()
            },
            action: Verdict::Deny,
            message: Some("Explicit local candidate restriction".into()),
            fallback: None,
        });
    }
    // Native argument inspection may upgrade a tool above its pinned baseline.
    // The floor deliberately includes every higher class too; otherwise a
    // prohibited tool could escape by supplying more dangerous arguments.
    if let Some(floor) = tool_classes.first().copied() {
        added.push(AgentRule {
            name: format!("operator-candidate-deny-tool-floor-{floor:?}"),
            when: AgentCondition {
                min_action_class: Some(floor),
                ..Default::default()
            },
            action: Verdict::Deny,
            message: Some("Explicit complete tool-class floor restriction".into()),
            fallback: None,
        });
    }
    if let Some(destinations) = &r.allowed_destinations {
        let unique: BTreeSet<_> = destinations.iter().collect();
        ensure!(
            unique.len() == destinations.len()
                && destinations.len() <= 128
                && destinations
                    .iter()
                    .all(|s| host(s) && base.egress_allowlist.contains(s)),
            "candidate_destination_not_exact_existing_host_subset"
        );
        // Narrowing an egress condition may make a formerly ineligible rule
        // match. Prove that this cannot pre-empt a stronger later decision.
        let mut previous = 3;
        for rule in &base.agent_policies {
            let next = rank(rule.action, rule.fallback);
            ensure!(
                rule.when.egress_not_allowlisted != Some(false) && next <= previous,
                "candidate_destination_policy_order_unsupported"
            );
            previous = next;
        }
        ensure!(
            rank(base.default, None) <= previous,
            "candidate_destination_default_unsupported"
        );
        candidate.egress_allowlist = destinations.clone();
        added.push(AgentRule {
            name: "operator-candidate-deny-other-destinations".into(),
            when: AgentCondition {
                egress_not_allowlisted: Some(true),
                ..Default::default()
            },
            action: Verdict::Deny,
            message: Some("Destination outside explicit candidate subset".into()),
            fallback: None,
        });
    }
    ensure!(!added.is_empty(), "candidate_empty_restrictions");
    added.extend(candidate.agent_policies);
    ensure!(added.len() <= 64, "candidate_policy_rule_cap");
    candidate.agent_policies = added;
    Ok(candidate)
}
struct Current {
    inputs: Vec<io::Input>,
    profile: profile_author::Profile,
    policy: AgentPolicySet,
}
impl Current {
    fn read(s: &Selection) -> Result<Self> {
        let mut inputs = Vec::new();
        for name in FILES {
            inputs.push(io::Input::read(&s.profile.join(name), 262144)?);
        }
        inputs.push(io::Input::read(&s.policy, CAP)?);
        profile_author::verify_compiled_bundle(&s.profile)
            .context("candidate_reviewed_profile_invalid")?;
        let rebuilt = profile_author::compiled_bundle_files(
            &s.profile.join("source-snapshot.json"),
            &s.profile.join("operator-declarations.json"),
            &s.profile,
        )?;
        for (name, expected) in rebuilt {
            let index = FILES
                .iter()
                .position(|n| *n == name)
                .context("candidate_bundle_inventory")?;
            ensure!(
                strict::<Value>(&inputs[index].bytes)? == strict::<Value>(&expected)?,
                "candidate_compiled_bundle_mismatch"
            );
        }
        let profile = profile_author::parse_profile_bytes(&inputs[0].bytes)?;
        ensure!(
            profile.registry_sha256 == sha(&inputs[1].bytes),
            "candidate_registry_identity_mismatch"
        );
        let policy = crate::offline_replay::policy(&inputs[6].bytes)?;
        for file in &inputs {
            file.recheck()?;
        }
        Ok(Self {
            inputs,
            profile,
            policy,
        })
    }
    fn pins(&self) -> Value {
        json!({"profile_sha256":sha(&self.inputs[0].bytes),
            "registry_sha256":sha(&self.inputs[1].bytes),
            "source_snapshot_sha256":self.profile.snapshot_sha256,
            "declaration_sha256":self.profile.declaration_sha256,
            "policy_sha256":sha(&self.inputs[6].bytes),
            "schemas":self.profile.tools.iter().map(|(name,t)| json!({"tool_sha256":sha(name.as_bytes()),
                "schema_sha256":t.schema_sha256,"action_class":t.action_class})).collect::<Vec<_>>()})
    }
}
struct Prepared {
    inputs: Vec<io::Input>,
    destination: Option<crate::private_export::Destination>,
    manifest: Vec<u8>,
    policy: Vec<u8>,
    restrictions: Vec<u8>,
    report: Value,
    digest: String,
}
impl Prepared {
    fn prepare(args: &Candidate, validating: bool) -> Result<Self> {
        let current = Current::read(&args.selection)?;
        ensure!(
            !args.out.starts_with(&args.selection.profile)
                && current.profile.tools.values().all(|t| t
                    .workspace
                    .as_ref()
                    .is_none_or(|w| !args.out.starts_with(w))),
            "candidate_export_overlaps_selected_source_or_project"
        );
        let restrictions = io::Input::read(&args.constraints, CAP)?;
        let examples = io::Input::read(&args.examples, crate::offline_replay::MAX_INPUT_BYTES)?;
        let constraints: Restrictions = strict(&restrictions.bytes)?;
        let narrowed = restrict(&current.policy, &current.profile, &constraints)?;
        let policy = serde_json::to_vec_pretty(&narrowed)?; // JSON is also unambiguous YAML.
        ensure!(policy.len() <= CAP, "candidate_policy_cap");
        let simulation = crate::offline_replay::simulate(
            &examples.bytes,
            &current.inputs[6].bytes,
            Some(&policy),
        )?;
        let destination = if validating {
            None
        } else {
            Some(crate::private_export::Destination::select(&args.out)?)
        };
        let destination_binding = if let Some(selected) = &destination {
            serde_json::to_value(selected.binding())?
        } else {
            let meta = crate::private_export::open_dir(
                args.out.parent().context("candidate_export_parent")?,
            )?
            .metadata()?;
            ensure!(
                meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
                "candidate_private_export_parent_required"
            );
            json!({"path":args.out,"parent_device":meta.dev(),"parent_inode":meta.ino(),
                "parent_uid":meta.uid(),"parent_gid":meta.gid(),"parent_mode":meta.mode()})
        };
        let pins = current.pins();
        let old_scope = json!({"tools":current.profile.tools.iter().map(|(n,t)| json!({
            "name_sha256":sha(n.as_bytes()),"action_class":t.action_class})).collect::<Vec<_>>(),
            "destinations_sha256":current.policy.egress_allowlist.iter().map(|h|sha(h.as_bytes())).collect::<Vec<_>>()});
        let new_scope = json!({"deny_actions":narrowed.agent_policies.iter()
            .take(narrowed.agent_policies.len()-current.policy.agent_policies.len())
            .filter_map(|r|r.when.action_class).collect::<Vec<_>>(),
            "deny_action_floors":narrowed.agent_policies.iter()
                .take(narrowed.agent_policies.len()-current.policy.agent_policies.len())
                .filter_map(|r|r.when.min_action_class).collect::<Vec<_>>(),
            "destinations_sha256":narrowed.egress_allowlist.iter().map(|h|sha(h.as_bytes())).collect::<Vec<_>>(),
            "tools_registry_unchanged":true,"tool_constraints":"complete_class_and_all_higher_action_classes"});
        let mut inputs = current.inputs;
        inputs.push(restrictions);
        inputs.push(examples);
        let restriction_bytes = serde_json::to_vec(&constraints)?;
        let manifest = serde_json::to_vec(&json!({"format":FORMAT,"active":false,"pins":pins,
            "input_bindings":inputs.iter().map(|i| &i.binding).collect::<Vec<_>>(),
            "policy_sha256":sha(&policy),"constraints_sha256":sha(&restriction_bytes),
            "export_destination":destination_binding,"examples_sha256":sha(&inputs[8].bytes)}))?;
        let digest = sha(&[
            b"agentfw/operator-policy-candidate/v1\0".as_slice(),
            &manifest,
        ]
        .concat());
        let mut report = json!({"format":FORMAT,"status":"preview","active":false,"executed":false,
            "protection_claim":false,"candidate_sha256":digest,"current":pins,
            "scope_diff":{"old":old_scope,"new":new_scope},"simulation":simulation,
            "activation":"separate_reviewed_activation_required"});
        if args.show_private_scope {
            report["private_scope"] = json!({"old_policy":current.policy,"new_policy":narrowed,
                "tools":current.profile.tools.keys().collect::<Vec<_>>()});
        }
        ensure!(
            serde_json::to_vec(&report)?.len() <= crate::offline_replay::MAX_OUTPUT_BYTES,
            "candidate_report_cap"
        );
        for input in &inputs {
            input.recheck()?;
        }
        Ok(Self {
            inputs,
            destination,
            manifest,
            policy,
            restrictions: restriction_bytes,
            report,
            digest,
        })
    }
    fn recheck(&self) -> Result<()> {
        for input in &self.inputs {
            input.recheck()?;
        }
        Ok(())
    }
    fn export(&self, confirm: &str) -> Result<()> {
        ensure!(
            crate::native::is_digest(confirm)
                && bool::from(confirm.as_bytes().ct_eq(self.digest.as_bytes())),
            "candidate_confirmation_changed"
        );
        self.destination
            .as_ref()
            .context("candidate_create_required")?
            .publish(
                &[
                    ("candidate.json", &self.manifest),
                    ("policy.yaml", &self.policy),
                    ("constraints.json", &self.restrictions),
                    ("candidate.sha256", self.digest.as_bytes()),
                ],
                || self.recheck(),
            )
    }
}
fn run_inner(command: Command) -> Result<()> {
    let report = match command {
        Command::Inspect(s) => {
            let current = Current::read(&s)?;
            json!({"format":FORMAT,"status":"inspected","active":false,"executed":false,"pins":current.pins()})
        }
        Command::Preview(args) => Prepared::prepare(&args, false)?.report,
        Command::Create { candidate, confirm } => {
            let prepared = Prepared::prepare(&candidate, false)?;
            prepared.export(&confirm)?;
            json!({"format":FORMAT,"status":"exported_inert","active":false,
                "executed":false,"candidate_sha256":prepared.digest})
        }
        Command::Validate {
            candidate,
            exported,
            expect_candidate,
        } => {
            let prepared = Prepared::prepare(&candidate, true)?;
            ensure!(
                exported == candidate.out
                    && crate::native::is_digest(&expect_candidate)
                    && bool::from(
                        expect_candidate
                            .as_bytes()
                            .ct_eq(prepared.digest.as_bytes())
                    ),
                "candidate_stale_source_or_confirmation"
            );
            let mut retained = Vec::new();
            for (name, expected) in [
                ("candidate.json", prepared.manifest.as_slice()),
                ("policy.yaml", prepared.policy.as_slice()),
                ("constraints.json", prepared.restrictions.as_slice()),
                ("candidate.sha256", prepared.digest.as_bytes()),
            ] {
                let input = io::Input::read(&exported.join(name), CAP)?;
                ensure!(input.bytes == expected, "candidate_export_changed");
                retained.push(input);
            }
            let names = std::fs::read_dir(&exported)?
                .take(5)
                .map(|entry| entry.map(|e| e.file_name()))
                .collect::<std::io::Result<BTreeSet<_>>>()?;
            ensure!(
                names
                    == [
                        "candidate.json",
                        "policy.yaml",
                        "constraints.json",
                        "candidate.sha256"
                    ]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect(),
                "candidate_export_inventory_changed"
            );
            for input in retained {
                input.recheck()?;
            }
            prepared.recheck()?;
            json!({"format":FORMAT,"status":"validated_inert","active":false,"executed":false,
                "candidate_sha256":prepared.digest})
        }
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Keep input names, policy text, endpoints and parser details off stderr.
pub fn run(command: Command) -> Result<()> {
    run_inner(command).map_err(|error| {
        let safe = error
            .chain()
            .find_map(|cause| {
                let message = cause.to_string();
                match message.as_str() {
                    "candidate_confirmation_changed" => Some("candidate_confirmation_changed"),
                    "candidate_source_changed" | "candidate_stale_source_or_confirmation" => {
                        Some("candidate_source_changed_repeat_preview")
                    }
                    "candidate_partial_tool_class_unsupported" => {
                        Some("candidate_partial_tool_class_unsupported")
                    }
                    "candidate_unknown_tool" => Some("candidate_unknown_tool"),
                    "candidate_destination_policy_order_unsupported"
                    | "candidate_destination_default_unsupported" => {
                        Some("candidate_destination_policy_order_unsupported")
                    }
                    "candidate_destination_not_exact_existing_host_subset" => {
                        Some("candidate_destination_not_exact_existing_host_subset")
                    }
                    "candidate_export_overlaps_selected_source_or_project" => {
                        Some("candidate_export_overlaps_selected_source_or_project")
                    }
                    "export_destination_exists_or_unavailable" => {
                        Some("candidate_export_destination_exists_or_unavailable")
                    }
                    "candidate_export_changed" | "candidate_export_inventory_changed" => {
                        Some("candidate_export_changed")
                    }
                    _ => None,
                }
            })
            .unwrap_or("candidate_input_or_export_refused");
        anyhow::anyhow!(safe)
    })
}

#[cfg(test)]
mod tests;
