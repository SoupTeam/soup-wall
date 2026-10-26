// SPDX-License-Identifier: Apache-2.0
//! Explicit bounded ordinary-clone grammar; never a replacement for Git v1.
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "sw-mcp/git-local-clone-readonly/1";
pub const EXECUTABLE: &str = "/mcp-runtime/git";
pub const ORIGINAL_GIT: &str = "/mcp-runtime/original/git";

pub(super) fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-/.".contains(&b))
        && !value.contains("..")
        && value.split('/').all(|s| {
            !s.is_empty() && !s.starts_with('.') && !s.ends_with('.') && !s.ends_with(".lock")
        })
}

fn plain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| (32..=126).contains(&b) && !b"\"\\#;".contains(&b))
}

pub fn validate_config(bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(
        bytes.len() <= 8192 && bytes.is_ascii(),
        "git_clone_config_bounds"
    );
    let text = std::str::from_utf8(bytes)?;
    let mut section = String::new();
    let mut sections = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for raw in text.lines() {
        ensure!(
            !raw.bytes().any(|b| b.is_ascii_control() && b != b'\t'),
            "git_clone_config_syntax"
        );
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_ascii_lowercase();
            let supported = matches!(
                section.as_str(),
                "[core]" | "[user]" | "[remote \"origin\"]"
            ) || section
                .strip_prefix("[branch \"")
                .and_then(|s| s.strip_suffix("\"]"))
                .is_some_and(reference);
            ensure!(supported, "git_clone_config_section");
            ensure!(
                sections.insert(section.clone()),
                "git_clone_config_duplicate"
            );
            continue;
        }
        let (key, value) = line.split_once('=').context("git_clone_config_syntax")?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        ensure!(plain(value), "git_clone_config_syntax");
        ensure!(
            keys.insert((section.clone(), key.clone())),
            "git_clone_config_duplicate"
        );
        let valid = match (section.as_str(), key.as_str()) {
            ("[core]", "repositoryformatversion") => value == "0",
            ("[core]", "bare") => value.eq_ignore_ascii_case("false"),
            ("[core]", "filemode" | "logallrefupdates" | "ignorecase" | "precomposeunicode") => {
                value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")
            }
            ("[user]", "name" | "email") => true,
            ("[remote \"origin\"]", "fetch") => value == "+refs/heads/*:refs/remotes/origin/*",
            ("[remote \"origin\"]", "url") => {
                !value.bytes().any(|b| b.is_ascii_whitespace())
                    && !value.contains("::")
                    && (value.starts_with("https://")
                        || value.starts_with("ssh://")
                        || value.starts_with("git@") && value.contains(':'))
            }
            (s, "remote") if s.starts_with("[branch \"") => value == "origin",
            (s, "merge") if s.starts_with("[branch \"") => {
                value.strip_prefix("refs/heads/").is_some_and(reference)
            }
            _ => false,
        };
        ensure!(valid, "git_clone_config_value");
    }
    ensure!(
        keys.contains(&("[core]".into(), "repositoryformatversion".into()))
            && keys.contains(&("[core]".into(), "bare".into())),
        "git_clone_config_required"
    );
    Ok(())
}

pub fn validate_attributes(bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(
        bytes.len() <= 8192 && bytes.is_ascii(),
        "git_clone_attributes_bounds"
    );
    for raw in std::str::from_utf8(bytes)?.lines() {
        ensure!(
            !raw.bytes().any(|b| b.is_ascii_control() && b != b'\t'),
            "git_clone_attributes_syntax"
        );
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_ascii_whitespace();
        let pattern = words.next().context("git_clone_attributes_syntax")?;
        ensure!(
            pattern.len() <= 256
                && !pattern.starts_with('/')
                && !pattern.split('/').any(|s| s == ".." || s.is_empty())
                && pattern
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-./*?".contains(&b)),
            "git_clone_attributes_pattern"
        );
        let mut count = 0;
        for token in words {
            ensure!(
                matches!(
                    token,
                    "text" | "-text" | "text=auto" | "eol=lf" | "eol=crlf" | "binary" | "-diff"
                ),
                "git_clone_attributes_token"
            );
            count += 1;
        }
        ensure!((1..=8).contains(&count), "git_clone_attributes_syntax");
    }
    Ok(())
}

/// Inspect Git's original, NUL-delimited index inventory. No decoded shell text.
pub fn attribute_objects(listing: &[u8]) -> anyhow::Result<Vec<String>> {
    Ok(index_entries(listing, false)?
        .into_iter()
        .filter(|entry| entry.path.rsplit('/').next() == Some(".gitattributes"))
        .map(|entry| entry.oid)
        .collect())
}

pub(super) struct IndexEntry {
    pub mode: String,
    pub oid: String,
    pub path: String,
}

pub(super) fn index_entries(listing: &[u8], links: bool) -> anyhow::Result<Vec<IndexEntry>> {
    ensure!(listing.len() <= 4 * 1024 * 1024, "git_clone_index_bounds");
    let mut entries = Vec::new();
    let mut attributes = 0;
    let mut count = 0;
    for record in listing.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        count += 1;
        ensure!(count <= 32768, "git_clone_index_bounds");
        let text = std::str::from_utf8(record).context("git_clone_index_encoding")?;
        let (header, path) = text.split_once('\t').context("git_clone_index_syntax")?;
        let fields: Vec<_> = header.split(' ').collect();
        ensure!(
            fields.len() == 3
                && (matches!(fields[0], "100644" | "100755") || links && fields[0] == "120000")
                && fields[1].len() == 40
                && fields[1].bytes().all(|b| b.is_ascii_hexdigit())
                && fields[2] == "0",
            "git_clone_index_mode"
        );
        ensure!(
            !path.is_empty()
                && path.len() <= 4096
                && !path.starts_with('/')
                && !path.chars().any(char::is_control)
                && !path
                    .split('/')
                    .any(|s| matches!(s, "" | "." | ".." | ".git" | ".gitmodules")),
            "git_clone_index_path"
        );
        if path.rsplit('/').next() == Some(".gitattributes") {
            attributes += 1;
            ensure!(attributes <= 64, "git_clone_attributes_bounds");
        }
        entries.push(IndexEntry {
            mode: fields[0].into(),
            oid: fields[1].into(),
            path: path.into(),
        });
    }
    Ok(entries)
}

pub(super) fn same(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}

fn open(path: &Path, directory: bool) -> anyhow::Result<File> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        !before.is_symlink()
            && if directory {
                before.is_dir()
            } else {
                before.is_file()
            },
        "git_clone_file_type"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 });
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC
                | if directory { libc::O_DIRECTORY } else { 0 },
        );
    }
    let file = options.open(path)?;
    ensure!(
        same(&before, &file.metadata()?),
        "git_clone_identity_changed"
    );
    Ok(file)
}

fn directory_path(file: &File, fallback: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = fallback;
        PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        fallback.to_owned()
    }
}

fn contents(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = open(path, false)?;
    let before = file.metadata()?;
    ensure!(before.len() <= 8192, "git_clone_control_bounds");
    let mut bytes = Vec::new();
    (&mut file).take(8193).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8192
            && same(&before, &file.metadata()?)
            && same(&before, &fs::symlink_metadata(path)?),
        "git_clone_identity_changed"
    );
    Ok(bytes)
}

fn permitted(relative: &str, directory: bool) -> bool {
    if relative == ".git" {
        return directory;
    }
    if relative.split('/').skip(1).any(|s| s == ".git")
        || relative.split('/').any(|s| s == ".gitmodules")
    {
        return false;
    }
    if let Some(p) = relative.strip_prefix(".git/") {
        let first = p.split('/').next().unwrap_or("");
        if ![
            "HEAD",
            "config",
            "description",
            "index",
            "packed-refs",
            "logs",
            "objects",
            "refs",
            "hooks",
            "info",
            "branches",
            "COMMIT_EDITMSG",
            "FETCH_HEAD",
            "ORIG_HEAD",
        ]
        .contains(&first)
        {
            return false;
        }
        if p == "refs/replace" || p.starts_with("refs/replace/") {
            return false;
        }
        if let Some(name) = p.strip_prefix("hooks/") {
            return !directory && !name.contains('/') && name.ends_with(".sample");
        }
        if let Some(name) = p.strip_prefix("info/") {
            return name == "exclude" && !directory;
        }
        if let Some(name) = p.strip_prefix("objects/info/") {
            return name == "packs" && !directory;
        }
        if p.ends_with(".promisor") || p.ends_with(".lock") {
            return false;
        }
    }
    true
}

pub(super) struct Inventory {
    pub links: BTreeMap<String, Vec<u8>>,
    pub files: BTreeSet<String>,
    metadata: BTreeMap<String, Metadata>,
}

impl Inventory {
    pub(super) fn unchanged(&self, other: &Self) -> bool {
        self.links == other.links
            && self.files == other.files
            && self.metadata.len() == other.metadata.len()
            && self.metadata.iter().all(|(path, before)| {
                other
                    .metadata
                    .get(path)
                    .is_some_and(|after| same(before, after))
            })
    }
}

pub fn validate_repository(root: &Path) -> anyhow::Result<()> {
    inventory(root, false).map(|_| ())
}

pub(super) fn inventory(root: &Path, links: bool) -> anyhow::Result<Inventory> {
    #[allow(clippy::too_many_arguments)] // Existing bounded walk also collects the opt-in link proof.
    fn walk(
        path: &Path,
        relative: &str,
        depth: usize,
        count: &mut usize,
        attributes: &mut usize,
        bytes: &mut usize,
        controls: &mut BTreeSet<String>,
        links: bool,
        inventory: &mut Inventory,
    ) -> anyhow::Result<()> {
        ensure!(depth <= 32, "git_clone_depth_limit");
        let directory = open(path, true)?;
        let before = directory.metadata()?;
        if links {
            owned(&before)?;
            inventory.metadata.insert(relative.into(), before.clone());
        }
        let anchored = directory_path(&directory, path);
        for entry in fs::read_dir(&anchored)? {
            let entry = entry?;
            *count += 1;
            ensure!(*count <= 32768, "git_clone_entry_limit");
            let name = entry.file_name();
            let name = name.to_str().context("git_clone_path_encoding")?;
            let rel = if relative.is_empty() {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            ensure!(
                rel.len() <= 4096 && !rel.chars().any(char::is_control),
                "git_clone_path_bounds"
            );
            let meta = fs::symlink_metadata(entry.path())?;
            if links {
                owned(&meta)?;
                inventory.metadata.insert(rel.clone(), meta.clone());
            }
            if links && meta.is_symlink() {
                ensure!(
                    !rel.starts_with(".git/") && permitted(&rel, false),
                    "git_links_metadata"
                );
                let target = fs::read_link(entry.path())?;
                let target = target
                    .to_str()
                    .context("git_links_target_encoding")?
                    .as_bytes()
                    .to_vec();
                ensure!(
                    same(&meta, &fs::symlink_metadata(entry.path())?),
                    "git_links_identity_changed"
                );
                inventory.links.insert(rel, target);
                ensure!(inventory.links.len() <= 64, "git_links_count");
                continue;
            }
            ensure!(
                !meta.is_symlink() && (meta.is_dir() || meta.is_file()),
                "git_clone_file_type"
            );
            ensure!(
                permitted(&rel, meta.is_dir()),
                "git_clone_metadata_unsupported"
            );
            if rel == ".git/index" {
                ensure!(meta.len() <= 4 * 1024 * 1024, "git_clone_index_bounds");
            }
            if meta.is_dir() {
                walk(
                    &entry.path(),
                    &rel,
                    depth + 1,
                    count,
                    attributes,
                    bytes,
                    controls,
                    links,
                    inventory,
                )?;
            } else {
                if links && !rel.starts_with(".git/") {
                    inventory.files.insert(rel.clone());
                }
                if rel == ".git/config" {
                    validate_config(&contents(&entry.path())?)?;
                    controls.insert(rel);
                } else if name == ".gitattributes" {
                    ensure!(!rel.starts_with(".git/"), "git_clone_metadata_unsupported");
                    let data = contents(&entry.path())?;
                    *attributes += 1;
                    *bytes += data.len();
                    ensure!(
                        *attributes <= 64 && *bytes <= 262144,
                        "git_clone_attributes_bounds"
                    );
                    validate_attributes(&data)?;
                } else if rel == ".git/HEAD" {
                    controls.insert(rel);
                }
            }
        }
        ensure!(
            same(&before, &directory.metadata()?) && same(&before, &fs::symlink_metadata(path)?),
            "git_clone_identity_changed"
        );
        Ok(())
    }
    let mut controls = BTreeSet::new();
    let mut inventory = Inventory {
        links: BTreeMap::new(),
        files: BTreeSet::new(),
        metadata: BTreeMap::new(),
    };
    walk(
        root,
        "",
        0,
        &mut 0,
        &mut 0,
        &mut 0,
        &mut controls,
        links,
        &mut inventory,
    )?;
    ensure!(
        controls.contains(".git/config") && controls.contains(".git/HEAD"),
        "git_clone_standalone_required"
    );
    Ok(inventory)
}

fn owned(metadata: &Metadata) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && (metadata.is_symlink() || metadata.mode() & 0o022 == 0),
            "git_links_ownership"
        );
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}
