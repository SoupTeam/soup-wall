// SPDX-License-Identifier: Apache-2.0
//! Local, finite component removal. Receipts establish only the enumerated
//! installation scope; user data and global Agent lifecycle are never targets.
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

mod inventory;
mod io;
mod journal;
mod processes;
use io::{Budget, Dir, Identity};

const FORMAT: &str = "sw-installed-pilot-removal/1";
const MAX_ENTRIES: usize = 256;

#[derive(Args, Debug)]
pub struct Cli {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
    /// Read-only exact inventory. No helper, provider, state write or process stop.
    Preview(Selection),
    /// Remove only this exact preview after fresh explicit operator consent.
    Apply {
        #[command(flatten)]
        selected: Selection,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        consent_remove: bool,
        /// Quiesce new launches, updates and arbitrary same-UID writers first.
        #[arg(long)]
        exclusive_maintenance: bool,
    },
    /// Read-only bounded object outcomes; never infer success from missing names.
    Status(Retained),
    /// Continue only original unchanged objects; uncertain objects stay uncertain.
    Resume {
        #[command(flatten)]
        retained: Retained,
        #[arg(long)]
        consent_remove: bool,
        #[arg(long)]
        exclusive_maintenance: bool,
    },
}
#[derive(Args, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Selection {
    /// Explicit owner-private Agent home. Only pilot-front-door is removable.
    #[arg(long)]
    home: PathBuf,
    /// Explicit preparation prefixes: inventory/retain only; never remove them.
    #[arg(long, required = true, num_args = 1)]
    prefix: Vec<PathBuf>,
    /// All operator-selected run-state roots, including custom read-only/edit roots.
    #[arg(long, required = true, num_args = 1)]
    state: Vec<PathBuf>,
    /// New private recovery directory outside every selected/data root.
    #[arg(long)]
    journal: PathBuf,
}
#[derive(Args, Debug)]
struct Retained {
    #[arg(long)]
    journal: PathBuf,
    /// Original preview confirmation; never select another plan implicitly.
    #[arg(long)]
    expect_plan: String,
    /// Private acknowledgement returned only by a fully completed removal.
    #[arg(long)]
    success_ack: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    identity: Identity,
    sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RetainedInventory {
    root: PathBuf,
    identity: Identity,
    entries: Vec<Entry>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    format: String,
    scope: String,
    selected: Selection,
    home: Identity,
    root: Identity,
    journal_parent: Identity,
    entries: Vec<Entry>,
    retained: Vec<RetainedInventory>,
    components: Vec<String>,
    exclusion: String,
}
fn canonical(v: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(v)?)?)
}
fn sha(raw: &[u8]) -> String {
    super::sha(raw)
}
fn same(a: &str, b: &str) -> bool {
    crate::native::is_digest(a)
        && crate::native::is_digest(b)
        && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn digest(plan: &Plan) -> Result<String> {
    let mut raw = b"agentfw/installed-pilot-removal/v1\0".to_vec();
    raw.extend(canonical(plan)?);
    Ok(sha(&raw))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let crate::mcp::admission::Strict(value) =
        serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("removal_record_invalid"))?;
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("removal_record_schema"))
}
fn separate(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "removal_overlapping_scope"
    );
    Ok(())
}
fn selected_roots(s: &Selection) -> Vec<PathBuf> {
    let mut roots = vec![s.home.clone()];
    roots.extend(s.prefix.clone());
    roots.extend(s.state.clone());
    roots
}
fn execute(cli: Cli) -> Result<Value> {
    ensure!(
        cfg!(target_arch = "x86_64") && unsafe { libc::geteuid() } != 0,
        "removal_native_linux_user_required"
    );
    let mut budget = Budget::new();
    match cli.action {
        Action::Preview(s) => {
            let plan = inventory::preview(&s, &mut budget)?;
            let blockers = processes::blockers(&plan, &mut budget)?;
            Ok(
                json!({"format":FORMAT,"status":if blockers.is_empty(){"preview"}else{"blocked"},
                "confirmation_sha256":if blockers.is_empty(){Some(digest(&plan)?)}else{None},
                "inventory":plan,"blockers":blockers,"executed":false,"provider_requests":0,
                "retained":["projects","outputs","exports","backups","audit_history","provider_credentials","agent_binary","prepared_generations"],
                "scope":"verified_front_door_component_only",
                "prerequisite_cleanup":"use_existing_receipt_aware_pilot_cleanup_separately"}),
            )
        }
        Action::Apply {
            selected,
            confirm,
            consent_remove,
            exclusive_maintenance,
        } => {
            ensure!(
                consent_remove && exclusive_maintenance,
                "removal_explicit_consent_required"
            );
            let plan = inventory::preview(&selected, &mut budget)?;
            ensure!(
                same(&digest(&plan)?, &confirm),
                "removal_stale_confirmation"
            );
            ensure!(
                processes::blockers(&plan, &mut budget)?.is_empty(),
                "removal_active_or_uncertain"
            );
            let j = journal::Journal::create(&plan, &confirm, &mut budget)?;
            j.apply(&mut budget)
        }
        Action::Status(r) => journal::Journal::open(&r, &mut budget)?.status(&mut budget),
        Action::Resume {
            retained,
            consent_remove,
            exclusive_maintenance,
        } => {
            ensure!(
                consent_remove && exclusive_maintenance,
                "removal_explicit_consent_required"
            );
            journal::Journal::open(&retained, &mut budget)?.apply(&mut budget)
        }
    }
}
pub fn run(cli: Cli) -> Result<()> {
    let may_remove = matches!(&cli.action, Action::Apply { .. } | Action::Resume { .. });
    let result = execute(cli).map_err(|e| {
        let code = e
            .chain()
            .map(ToString::to_string)
            .find(|s| {
                s.starts_with("removal_")
                    && s.len() <= 96
                    && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            })
            .unwrap_or_else(|| "removal_unsafe_or_unavailable".into());
        anyhow::anyhow!("{code}")
    });
    let (result, refusal) = match result {
        Ok(v) => (v, None),
        Err(e) => {
            let code = e.to_string();
            (
                json!({"format":FORMAT,"status":"refused","reason":code,"executed":if may_remove {Value::Null}else{json!(false)},"effects":if may_remove {"inspect_private_journal_effects_may_have_occurred"}else{"none"}}),
                Some(code),
            )
        }
    };
    let raw = serde_json::to_string(&result)?;
    ensure!(raw.len() <= 512 * 1024, "removal_response_cap");
    println!("{raw}");
    if let Some(code) = refusal {
        anyhow::bail!("{code}");
    }
    Ok(())
}
