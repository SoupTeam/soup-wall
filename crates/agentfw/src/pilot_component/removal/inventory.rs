// SPDX-License-Identifier: Apache-2.0
use super::{
    decode, ensure, separate, sha, Budget, Context, Dir, Entry, Plan, Result, RetainedInventory,
    Selection, FORMAT, MAX_ENTRIES,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn walk(root: &Path, base: &Path, entries: &mut Vec<Entry>, b: &mut Budget) -> Result<()> {
    b.tick(0)?;
    let dir = Dir::open(root)?;
    ensure!(
        root.components().count() - base.components().count() <= 16,
        "removal_depth_cap"
    );
    for name in dir.names()? {
        ensure!(entries.len() < MAX_ENTRIES, "removal_entry_cap");
        let id = dir.optional(&name)?.context("removal_inventory_changed")?;
        let relative = root
            .join(&name)
            .strip_prefix(base)?
            .to_str()
            .context("removal_invalid_name")?
            .to_string();
        ensure!(relative.len() <= 512, "removal_name_cap");
        if id.directory() {
            ensure!(
                id.device == Dir::open(base)?.id.device,
                "removal_nested_mount"
            );
            entries.push(Entry {
                name: relative,
                identity: id,
                sha256: None,
            });
            walk(&root.join(name), base, entries, b)?;
        } else {
            let (raw, identity) = dir.read(&name, 1024 * 1024, b)?;
            entries.push(Entry {
                name: relative,
                identity,
                sha256: Some(sha(&raw)),
            });
        }
    }
    Ok(())
}
pub(super) fn no_mounts(path: &Path) -> Result<()> {
    let raw = std::fs::read("/proc/self/mountinfo")?;
    ensure!(raw.len() <= 1024 * 1024, "removal_mount_inventory_cap");
    for line in std::str::from_utf8(&raw)?.lines() {
        let name = line
            .split_whitespace()
            .nth(4)
            .context("removal_mount_inventory_invalid")?;
        // Do not guess at escaped mount names: ambiguous ancestry blocks.
        ensure!(
            !name.contains('\\') || !path.to_string_lossy().contains(' '),
            "removal_mount_inventory_ambiguous"
        );
        ensure!(!Path::new(name).starts_with(path), "removal_nested_mount");
    }
    Ok(())
}
fn retained(path: &Path, b: &mut Budget) -> Result<RetainedInventory> {
    let d = Dir::open(path)?;
    let mut entries = vec![];
    for name in d.names()? {
        let id = d
            .optional(&name)?
            .context("removal_retained_inventory_changed")?;
        // Inventory only direct children. User contents are neither read nor removal targets.
        ensure!(
            id.uid == unsafe { libc::geteuid() }
                && (id.directory() || id.mode & libc::S_IFMT == libc::S_IFREG),
            "removal_retained_entry_unsafe"
        );
        entries.push(Entry {
            name,
            identity: id,
            sha256: None,
        });
    }
    if let Some(row) = entries.iter_mut().find(|e| e.name == "front-door.json") {
        let (raw, id) = d.read("front-door.json", 65536, b)?;
        let value: serde_json::Value = decode(&raw)?;
        ensure!(
            value["format"] == "sw-pilot-front-door/1",
            "removal_invalid_preparation_receipt"
        );
        let selection = Path::new(
            value["selection"]
                .as_str()
                .context("removal_invalid_preparation_receipt")?,
        );
        ensure!(
            selection.starts_with(path.join("preparation/generations"))
                && selection.file_name().is_some_and(|s| s == "selection.json"),
            "removal_selection_scope"
        );
        let parent = Dir::open(selection.parent().context("removal_selection_scope")?)?;
        let (selected, _) = parent.read("selection.json", 65536, b)?;
        ensure!(
            super::same(
                &sha(&selected),
                value["selection_sha256"].as_str().unwrap_or("")
            ),
            "removal_selection_changed"
        );
        let _: serde_json::Value = decode(&selected)?;
        row.identity = id;
        row.sha256 = Some(sha(&raw));
    }
    // Known generation receipts are inventoried, never their user workspaces.
    for kind in ["preparation", "native"] {
        if d.optional(kind)?.is_none() {
            continue;
        }
        let preparation = Dir::open(&path.join(kind))?;
        if preparation.optional("generations")?.is_none() {
            continue;
        }
        let generations = Dir::open(&path.join(kind).join("generations"))?;
        let names = generations.names()?;
        ensure!(names.len() <= 32, "removal_generation_cap");
        if preparation.optional("current.json")?.is_some() {
            let (raw, id) = preparation.read("current.json", 65536, b)?;
            let _: serde_json::Value = decode(&raw)?;
            entries.push(Entry {
                name: format!("{kind}/current.json"),
                identity: id,
                sha256: Some(sha(&raw)),
            });
        }
        for name in names {
            ensure!(
                super::super::is_hex(&name, 32),
                "removal_generation_identity_invalid"
            );
            let generation = Dir::open_readonly(&path.join(kind).join("generations").join(&name))?;
            let receipt = if kind == "preparation" {
                "selection.json"
            } else {
                "receipt.json"
            };
            let (raw, id) = generation.read(receipt, 65536, b)?;
            let value: serde_json::Value = decode(&raw)?;
            ensure!(
                value["format"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("sw-")),
                "removal_invalid_preparation_receipt"
            );
            entries.push(Entry {
                name: format!("{kind}/generations/{name}/{receipt}"),
                identity: id,
                sha256: Some(sha(&raw)),
            });
        }
    }
    Ok(RetainedInventory {
        root: path.into(),
        identity: d.id,
        entries,
    })
}
pub(super) fn preview(s: &Selection, b: &mut Budget) -> Result<Plan> {
    ensure!(
        !s.prefix.is_empty() && s.prefix.len() <= 4 && !s.state.is_empty() && s.state.len() <= 4,
        "removal_selection_cap"
    );
    let home = Dir::open(&s.home)?;
    let root = s.home.join("pilot-front-door");
    no_mounts(&root)?;
    let component = Dir::open(&root)?;
    let names = component.names()?;
    ensure!(
        names
            .iter()
            .all(|n| matches!(n.as_str(), "current.json" | "previous.json" | "components"))
            && names.iter().any(|n| n == "current.json")
            && names.iter().any(|n| n == "components"),
        "removal_interrupted_or_unexpected_installation"
    );
    let current: super::super::Pointer = component.json("current.json", 16384, b)?;
    ensure!(
        current.schema == super::super::POINTER_SCHEMA,
        "removal_invalid_component_receipt"
    );
    let mut pointers = vec![current.clone()];
    if names.iter().any(|n| n == "previous.json") {
        pointers.push(component.json("previous.json", 16384, b)?);
    }
    ensure!(
        pointers
            .iter()
            .all(|p| p.schema == super::super::POINTER_SCHEMA
                && super::super::is_hex(&p.component, 64)),
        "removal_invalid_component_receipt"
    );
    // Accepted verifier establishes genuine component structure and interpreter bytes; no execution.
    super::super::Store::new(&s.home).verify_component(&current.component, &current.python)?;
    let packages = Dir::open(&root.join("components"))?;
    let ids = packages.names()?;
    ensure!(
        !ids.is_empty()
            && ids.len() <= 8
            && ids.iter().all(|id| super::super::is_hex(id, 64))
            && pointers.iter().all(|p| ids.contains(&p.component)),
        "removal_component_inventory"
    );
    let mut expected = BTreeMap::<String, (Option<String>, Option<u64>, u32)>::new();
    expected.insert("components".into(), (None, None, 0o700));
    for n in names.iter().filter(|n| n.ends_with(".json")) {
        let (raw, id) = component.read(n, 16384, b)?;
        expected.insert(
            n.clone(),
            (Some(sha(&raw)), Some(raw.len() as u64), id.mode & 0o7777),
        );
    }
    for id in &ids {
        let dir = Dir::open(&root.join("components").join(id))?;
        let (raw, _) = dir.read("manifest.json", 65536, b)?;
        ensure!(
            super::same(&sha(&raw), id),
            "removal_component_manifest_changed"
        );
        let manifest = super::super::parse_manifest(&raw)?;
        let source = Dir::open(&root.join("components").join(id).join("tree"))?
            .read(super::super::SOURCE_FILE, 65536, b)?
            .0;
        super::super::check_source_identity(&manifest, &source)?;
        let p = format!("components/{id}");
        expected.insert(p.clone(), (None, None, 0o700));
        expected.insert(format!("{p}/tree"), (None, None, 0o700));
        expected.insert(
            format!("{p}/manifest.json"),
            (Some(id.clone()), Some(raw.len() as u64), 0o400),
        );
        for n in super::super::implied_dirs(&manifest) {
            expected.insert(format!("{p}/tree/{n}"), (None, None, 0o700));
        }
        for f in &manifest.files {
            expected.insert(
                format!("{p}/tree/{}", f.path),
                (Some(f.sha256.clone()), Some(f.size), f.mode_bits()),
            );
        }
    }
    let mut entries = vec![];
    walk(&root, &root, &mut entries, b)?;
    ensure!(
        entries.len() == expected.len(),
        "removal_unexpected_installation_entry"
    );
    for e in &entries {
        let (hash, size, mode) = expected
            .get(&e.name)
            .context("removal_unexpected_installation_entry")?;
        ensure!(
            e.identity.mode & 0o7777 == *mode
                && e.sha256 == *hash
                && size.is_none_or(|s| s == e.identity.size),
            "removal_component_changed"
        );
    }
    // Disable the selected entry first. The built-in Agent removal/status entry
    // remains available; neither its binary nor the recovery journal is deleted.
    entries.sort_by(|a, c| {
        let rank = |e: &Entry| {
            if e.name == "current.json" {
                0
            } else if e.name == "previous.json" {
                1
            } else if !e.identity.directory() {
                2
            } else {
                3
            }
        };
        rank(a)
            .cmp(&rank(c))
            .then_with(|| {
                c.name
                    .matches('/')
                    .count()
                    .cmp(&a.name.matches('/').count())
            })
            .then_with(|| a.name.cmp(&c.name))
    });
    entries.push(Entry {
        name: String::new(),
        identity: component.id.clone(),
        sha256: None,
    });
    let exe = std::env::current_exe()?.canonicalize()?;
    ensure!(
        !exe.starts_with(&root),
        "removal_entrypoint_self_removal_refused"
    );
    let parent = s.journal.parent().context("removal_journal_parent")?;
    let journal_parent = Dir::open(parent)?;
    ensure!(
        !journal_parent.id.object(&home.id)
            && !journal_parent.id.object(&component.id)
            && entries
                .iter()
                .filter(|e| e.identity.directory())
                .all(|e| !journal_parent.id.object(&e.identity)),
        "removal_journal_alias"
    );
    no_mounts(&s.journal)?;
    let leaf = s
        .journal
        .file_name()
        .and_then(|s| s.to_str())
        .context("removal_journal_name")?;
    ensure!(
        super::super::valid_path(leaf) && !leaf.contains('/') && parent.join(leaf) == s.journal,
        "removal_journal_name"
    );
    ensure!(
        journal_parent.optional(leaf)?.is_none(),
        "removal_journal_exists_use_status_or_resume"
    );
    let mut retained_roots = BTreeSet::new();
    for path in s.prefix.iter().chain(&s.state) {
        separate(path, &root)?;
        separate(&s.journal, path)?;
        ensure!(
            retained_roots.insert(path.clone()),
            "removal_duplicate_selection"
        );
    }
    separate(&s.journal, &s.home)?;
    let mut kept = vec![];
    for p in retained_roots {
        kept.push(retained(&p, b)?);
    }
    Ok(Plan {
        format: FORMAT.into(),
        scope: "verified_front_door_component_only".into(),
        selected: s.clone(),
        home: home.id,
        root: component.id,
        journal_parent: journal_parent.id.stable_directory(),
        entries,
        retained: kept,
        components: ids,
        exclusion: "explicit_quiesced_installation_no_new_launches_or_same_uid_writers".into(),
    })
}
pub(super) fn retained_recheck(plan: &Plan, b: &mut Budget) -> Result<()> {
    for old in &plan.retained {
        ensure!(
            retained(&old.root, b)? == *old,
            "removal_retained_scope_changed"
        );
    }
    ensure!(
        Dir::open(&plan.selected.home)?.id.object(&plan.home),
        "removal_home_changed"
    );
    Ok(())
}
