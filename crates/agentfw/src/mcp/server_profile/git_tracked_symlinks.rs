// SPDX-License-Identifier: Apache-2.0
//! Separately selected link objects. Validation never follows a worktree link.
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::git_local_clone::{self as clone, IndexEntry};

pub const FORMAT: &str = "sw-mcp/git-tracked-symlinks-readonly/1";
pub const EXECUTABLE: &str = "/mcp-runtime/git-tracked-symlinks";

/// Lexical resolution only. A later inventory membership check requires a
/// regular leaf and rules out link chains, cycles and symlinked parents.
pub fn target(path: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let safe = |part: &str| !matches!(part, ".git" | ".gitmodules" | ".gitattributes");
    ensure!(path.split('/').all(safe), "git_links_control_path");
    ensure!(
        !bytes.is_empty() && bytes.len() <= 256 && bytes.is_ascii(),
        "git_links_target_bounds"
    );
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        !text.starts_with('/') && text.split('/').count() <= 32,
        "git_links_target_absolute_or_depth"
    );
    let mut parts: Vec<_> = path.split('/').collect();
    parts.pop();
    for part in text.split('/') {
        ensure!(
            !part.is_empty()
                && safe(part)
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "git_links_target_component"
        );
        match part {
            "." => (),
            ".." => {
                ensure!(parts.pop().is_some(), "git_links_target_escape");
            }
            _ => parts.push(part),
        }
    }
    ensure!(!parts.is_empty(), "git_links_target_directory");
    Ok(parts.join("/"))
}

fn graph(links: &BTreeMap<String, Vec<u8>>, files: &BTreeSet<String>) -> anyhow::Result<()> {
    ensure!(links.len() <= 64, "git_links_count");
    // Retain filesystem traversal semantics before lexical cancellation: a
    // missing, regular or linked component cannot be made safe by a later `..`.
    let mut directories = BTreeSet::from([String::new()]);
    for path in files.iter().chain(links.keys()) {
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            ensure!(
                !files.contains(prefix) && !links.contains_key(prefix),
                "git_links_chain"
            );
            directories.insert(prefix.to_owned());
            parent = prefix;
        }
    }
    for (path, bytes) in links {
        let destination = target(path, bytes)?;
        ensure!(files.contains(&destination), "git_links_target_not_regular");
        let text = std::str::from_utf8(bytes)?;
        let mut parts: Vec<_> = path.split('/').collect();
        parts.pop();
        let components: Vec<_> = text.split('/').collect();
        for (position, component) in components.iter().enumerate() {
            match *component {
                "." => (),
                ".." => {
                    parts.pop();
                }
                name => parts.push(name),
            }
            if position + 1 < components.len() {
                ensure!(
                    directories.contains(&parts.join("/")),
                    "git_links_target_component_not_directory"
                );
            }
        }
    }
    Ok(())
}

pub fn validate_repository(root: &Path) -> anyhow::Result<()> {
    let inventory = clone::inventory(root, true)?;
    graph(&inventory.links, &inventory.files)
}

fn tree_entries(listing: &[u8]) -> anyhow::Result<Vec<IndexEntry>> {
    ensure!(
        listing.len() <= 4 * 1024 * 1024 && (listing.is_empty() || listing.ends_with(&[0])),
        "git_links_tree_bounds"
    );
    let mut index = Vec::new();
    for record in listing.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let record = std::str::from_utf8(record)?;
        let (header, path) = record.split_once('\t').context("git_links_tree_record")?;
        let fields: Vec<_> = header.split(' ').collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob",
            "git_links_tree_mode"
        );
        index.extend_from_slice(format!("{} {} 0\t{path}\0", fields[0], fields[2]).as_bytes());
    }
    clone::index_entries(&index, true)
}

fn check_entries(
    entries: Vec<IndexEntry>,
    inspect: &mut impl FnMut(&[&str], usize) -> anyhow::Result<Vec<u8>>,
    blobs: &mut BTreeMap<String, Vec<u8>>,
    attribute_bytes: &mut usize,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let mut links = BTreeMap::new();
    let mut files = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in entries {
        ensure!(paths.insert(entry.path.clone()), "git_links_duplicate_path");
        let attribute = entry.path.rsplit('/').next() == Some(".gitattributes");
        if entry.mode == "120000" || attribute {
            if !blobs.contains_key(&entry.oid) {
                ensure!(blobs.len() < 128, "git_links_blob_count");
                let blob = inspect(&["cat-file", "blob", &entry.oid], 8192)?;
                blobs.insert(entry.oid.clone(), blob);
            }
            let blob = &blobs[&entry.oid];
            if entry.mode == "120000" {
                target(&entry.path, blob)?;
                links.insert(entry.path, blob.clone());
            } else {
                *attribute_bytes += blob.len();
                ensure!(*attribute_bytes <= 262144, "git_clone_attributes_bounds");
                clone::validate_attributes(blob)?;
                files.insert(entry.path);
            }
        } else {
            files.insert(entry.path);
        }
    }
    graph(&links, &files)?;
    Ok(links)
}

/// The caller invokes only the pinned original Git, after OS restrictions.
/// Repository state is inspected anew, never reused as admission authority.
pub fn validate_invocation(
    root: &Path,
    mut inspect: impl FnMut(&[&str], usize) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    let before = clone::inventory(root, true)?;
    graph(&before.links, &before.files)?;
    let listing = inspect(&["ls-files", "--stage", "-z"], 4 * 1024 * 1024)?;
    ensure!(
        listing.is_empty() || listing.ends_with(&[0]),
        "git_links_index_record"
    );
    let index = clone::index_entries(&listing, true)?;
    let mut blobs = BTreeMap::<String, Vec<u8>>::new();
    let mut attribute_bytes = 0;
    ensure!(
        check_entries(index, &mut inspect, &mut blobs, &mut attribute_bytes)? == before.links,
        "git_links_index_worktree_mismatch"
    );
    // Include unreachable local commits accepted by the original full-SHA-1 contract.
    let mut trees = Vec::new();
    let objects = inspect(
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        ],
        4 * 1024 * 1024,
    )?;
    let mut count = 0;
    for record in std::str::from_utf8(&objects)?.lines() {
        count += 1;
        ensure!(count <= 32768, "git_links_object_count");
        let (oid, kind) = record.split_once(' ').context("git_links_object_record")?;
        ensure!(
            oid.len() == 40
                && oid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && matches!(kind, "blob" | "tree" | "commit" | "tag"),
            "git_links_object_record"
        );
        if kind == "commit" {
            ensure!(trees.len() < 64, "git_links_commit_count");
            trees.push(oid.to_owned());
        }
    }
    let mut tree_bytes = 0;
    for oid in trees {
        let tree = inspect(
            &["ls-tree", "-r", "-z", "--full-tree", &oid],
            4 * 1024 * 1024,
        )?;
        tree_bytes += tree.len();
        ensure!(tree_bytes <= 32 * 1024 * 1024, "git_links_history_bounds");
        check_entries(
            tree_entries(&tree)?,
            &mut inspect,
            &mut blobs,
            &mut attribute_bytes,
        )?;
    }
    let after = clone::inventory(root, true)?;
    ensure!(before.unchanged(&after), "git_links_identity_changed");
    graph(&after.links, &after.files)
}
