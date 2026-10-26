// SPDX-License-Identifier: Apache-2.0
//! Immutable inputs for the daemon-selected original filesystem runtime.
//! These snapshots establish consumed bytes, never content safety or permission.

#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, VecDeque};
#[cfg(any(target_os = "linux", test))]
use std::path::{Component, Path, PathBuf};

use anyhow::ensure;
#[cfg(any(target_os = "linux", test))]
use anyhow::Context;
use serde_json::json;

use super::server_profile::ProfileConfig;

pub const FORMAT: &str = "sw-mcp/sealed-original-closure/1";
// The locked original FS archive contains 4077 regular files (24,320,025 bytes).
// This opt-in contract has its own bounds; legacy owner/transport limits remain.
pub const MAX_ENTRIES: usize = 8192;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;

// The fixed Node command has no TS/custom loader or source-map option, clears
// NODE_OPTIONS, and the pinned JS closure contains no source-map enablement.
// Still capture and verify these bytes against the complete original manifest;
// omit only their non-runtime copies from the namespace image.
#[cfg(any(target_os = "linux", test))]
fn runtime_asset(path: &str) -> bool {
    !path.ends_with(".map")
        && !path.ends_with(".d.ts")
        && !path.ends_with(".d.cts")
        && !path.ends_with(".d.mts")
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
enum Entry {
    Directory,
    Link(String),
    #[cfg(target_os = "linux")]
    File(std::fs::File),
}

/// Not deserializable and not constructible from a client digest or manifest.
#[derive(Debug)]
pub(crate) struct Runtime {
    profile_digest: String,
    digest: String,
    #[cfg(target_os = "linux")]
    files: BTreeMap<String, std::fs::File>,
    #[cfg(target_os = "linux")]
    tree: BTreeMap<String, Entry>,
    bytes: u64,
    entries: usize,
}

impl Runtime {
    pub(crate) fn capture(profile: &ProfileConfig) -> anyhow::Result<Self> {
        ProfileConfig::read(&serde_json::to_vec(profile)?)?;
        ensure!(
            profile.format == super::server_profile::FORMAT
                && profile.git.is_none()
                && profile.git_launcher.is_none(),
            "verified_execution_profile_unsupported"
        );
        #[cfg(target_os = "linux")]
        {
            linux::capture(profile)
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("verified_execution_platform_unsupported")
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(profile: &ProfileConfig) -> Self {
        // Component fixture only. No launch capability or successful capture.
        Self {
            profile_digest: crate::native::canonical_digest(
                &serde_json::to_value(profile).unwrap(),
            ),
            digest: "a".repeat(64),
            bytes: 0,
            entries: 0,
            #[cfg(target_os = "linux")]
            files: Default::default(),
            #[cfg(target_os = "linux")]
            tree: Default::default(),
        }
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn metadata(&self) -> serde_json::Value {
        json!({"format":FORMAT,"closure_sha256":self.digest,
            "profile_sha256":self.profile_digest,"entries":self.entries,"bytes":self.bytes,
            "max_entries":MAX_ENTRIES,"max_bytes":MAX_BYTES})
    }
    pub(crate) fn matches(&self, profile: &ProfileConfig) -> bool {
        self.profile_digest
            == crate::native::canonical_digest(&serde_json::to_value(profile).expect("profile"))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bwrap(&self) -> anyhow::Result<std::fs::File> {
        linux::reopen(
            self.files
                .get("bwrap")
                .context("verified_execution_image_missing")?,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn mount(
        &self,
        command: &mut tokio::process::Command,
        pins: &mut Vec<std::fs::File>,
    ) -> anyhow::Result<Vec<std::os::fd::RawFd>> {
        use std::os::fd::AsRawFd;
        let mut sealed = Vec::new();
        command.args(["--size", &MAX_BYTES.to_string(), "--tmpfs", "/mcp-server"]);
        for (path, entry) in &self.tree {
            let destination = format!("/mcp-server/{path}");
            match entry {
                Entry::Directory => {
                    command.args(["--dir", &destination]);
                }
                Entry::Link(target) => {
                    command.args(["--symlink", target, &destination]);
                }
                Entry::File(file) => {
                    if !runtime_asset(path) {
                        continue;
                    }
                    let file = linux::reopen(file)?;
                    sealed.push(file.as_raw_fd());
                    command.args([
                        "--ro-bind-data",
                        &file.as_raw_fd().to_string(),
                        &destination,
                    ]);
                    pins.push(file);
                }
            }
        }
        command.args(["--remount-ro", "/mcp-server"]);
        for (path, file) in &self.files {
            if path == "bwrap" {
                continue;
            }
            let file = linux::reopen(file)?;
            sealed.push(file.as_raw_fd());
            let destination = if path == "runtime" {
                "/mcp-runtime/node"
            } else {
                path
            };
            // The ELF interpreter needs execute permission as well as read.
            command.args([
                "--perms",
                "0555",
                "--ro-bind-data",
                &file.as_raw_fd().to_string(),
                destination,
            ]);
            pins.push(file);
        }
        Ok(sealed)
    }
}

// Resolve links in the captured namespace, not through mutable host pathnames.
#[cfg(any(target_os = "linux", test))]
fn resolve_link(tree: &BTreeMap<String, Entry>, path: &str) -> anyhow::Result<()> {
    let mut todo: VecDeque<_> = Path::new(path)
        .components()
        .map(|c| c.as_os_str().to_owned())
        .collect();
    let mut done = PathBuf::new();
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        let mut components = Path::new(&part).components();
        match components
            .next()
            .context("verified_execution_link_invalid")?
        {
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(done.pop(), "verified_execution_link_escape");
            }
            Component::Normal(name) => {
                done.push(name);
                let key = done.to_str().context("verified_execution_path_invalid")?;
                match tree.get(key).context("verified_execution_link_missing")? {
                    Entry::Link(target) => {
                        links += 1;
                        ensure!(links <= 40, "verified_execution_link_cycle");
                        done.pop();
                        for item in Path::new(target).components().rev() {
                            todo.push_front(item.as_os_str().to_owned());
                        }
                    }
                    Entry::Directory => {}
                    #[cfg(target_os = "linux")]
                    Entry::File(_) => {
                        ensure!(todo.is_empty(), "verified_execution_link_not_directory");
                    }
                }
            }
            _ => anyhow::bail!("verified_execution_link_escape"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    const SEALS: i32 =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

    pub(super) fn reopen(file: &File) -> anyhow::Result<File> {
        // dup/try_clone shares an offset: concurrent bwrap data readers must
        // instead get independent open file descriptions of the sealed inode.
        let next = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let before = file.metadata()?;
        let after = next.metadata()?;
        ensure!(
            (before.dev(), before.ino()) == (after.dev(), after.ino())
                && unsafe { libc::fcntl(next.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "verified_execution_image_changed"
        );
        Ok(next)
    }

    fn snapshot(mut input: File, remaining: u64) -> anyhow::Result<(File, String, u64)> {
        let info = input.metadata()?;
        ensure!(
            info.is_file() && info.len() <= remaining,
            "verified_execution_asset_limit"
        );
        let raw = unsafe {
            libc::memfd_create(
                c"agentfw-original-image".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        ensure!(raw >= 0, "verified_execution_image_unavailable");
        let mut image = unsafe { File::from_raw_fd(raw) };
        let mut hasher = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .context("verified_execution_asset_limit")?;
            ensure!(count <= remaining, "verified_execution_asset_limit");
            hasher.update(&buffer[..n]);
            image.write_all(&buffer[..n])?;
        }
        ensure!(count == info.len(), "verified_execution_asset_changed");
        image.seek(SeekFrom::Start(0))?;
        ensure!(
            unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS) } == 0,
            "verified_execution_sealing_unavailable"
        );
        Ok((image, format!("{:x}", hasher.finalize()), count))
    }

    fn opened(path: &Path, directory: bool) -> anyhow::Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(
                libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | if directory {
                        libc::O_DIRECTORY
                    } else {
                        libc::O_NONBLOCK
                    },
            )
            .open(path)?)
    }

    fn walk(
        directory: &File,
        relative: &Path,
        tree: &mut BTreeMap<String, Entry>,
        records: &mut BTreeMap<String, Vec<u8>>,
        bytes: &mut u64,
        depth: usize,
    ) -> anyhow::Result<()> {
        ensure!(depth <= 32, "verified_execution_tree_depth");
        let root = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        for item in std::fs::read_dir(&root)? {
            ensure!(tree.len() < MAX_ENTRIES, "verified_execution_tree_limit");
            let item = item?;
            let child = relative.join(item.file_name());
            let name = child
                .to_str()
                .context("verified_execution_path_invalid")?
                .to_owned();
            ensure!(
                name.len() <= 4096 && !name.chars().any(char::is_control),
                "verified_execution_path_invalid"
            );
            ensure!(
                !tree.contains_key(&name),
                "verified_execution_duplicate_entry"
            );
            let path = root.join(item.file_name());
            let info = std::fs::symlink_metadata(&path)?;
            if info.file_type().is_symlink() {
                let target = std::fs::read_link(&path)?
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("verified_execution_link_invalid"))?;
                ensure!(
                    !target.is_empty()
                        && target.len() <= 4096
                        && !target.chars().any(char::is_control),
                    "verified_execution_link_invalid"
                );
                records.insert(name.clone(), format!("L\0{name}\0{target}\n").into_bytes());
                tree.insert(name, Entry::Link(target));
            } else if info.is_dir() {
                let pin = opened(&path, true)?;
                records.insert(name.clone(), format!("D\0{name}\n").into_bytes());
                tree.insert(name, Entry::Directory);
                walk(&pin, &child, tree, records, bytes, depth + 1)?;
            } else {
                ensure!(info.is_file(), "verified_execution_asset_type");
                let (image, digest, size) = snapshot(opened(&path, false)?, MAX_BYTES - *bytes)?;
                *bytes += size;
                records.insert(name.clone(), format!("F\0{name}\0{digest}\n").into_bytes());
                tree.insert(name, Entry::File(image));
            }
        }
        Ok(())
    }

    fn original_files() -> serde_json::Value {
        serde_json::from_slice(include_bytes!(
            "../../../../profiles/mcp/filesystem-readonly-v1/original-closure-files.json"
        ))
        .expect("shipped original closure manifest")
    }

    fn verify_original(
        tree: &BTreeMap<String, Entry>,
        records: &BTreeMap<String, Vec<u8>>,
        expected: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let files = expected["files"].as_object().expect("shipped files");
        let links = expected["bin_links"].as_object().expect("shipped links");
        let mut directories = std::collections::BTreeSet::new();
        for path in files
            .keys()
            .chain(links.keys())
            .map(String::as_str)
            .chain(std::iter::once("node_modules/.package-lock.json"))
        {
            let mut parent = Path::new(path).parent();
            while let Some(path) = parent {
                if !path.as_os_str().is_empty() {
                    directories.insert(path.to_str().expect("shipped path").to_owned());
                }
                parent = path.parent();
            }
        }
        for (path, digest) in files {
            let record =
                format!("F\0{path}\0{}\n", digest.as_str().expect("shipped digest")).into_bytes();
            ensure!(
                matches!(tree.get(path), Some(Entry::File(_)))
                    && records.get(path) == Some(&record),
                "verified_execution_not_original"
            );
        }
        for (path, entry) in tree {
            match entry {
                Entry::Directory => {
                    ensure!(directories.contains(path), "verified_execution_extra_input");
                }
                Entry::Link(target) => {
                    ensure!(
                        links.get(path).and_then(|v| v.as_str()) == Some(target),
                        "verified_execution_not_original"
                    );
                }
                Entry::File(_) if files.contains_key(path) => {}
                Entry::File(image) if path == "node_modules/.package-lock.json" => {
                    let mut raw = Vec::new();
                    reopen(image)?.take(131073).read_to_end(&mut raw)?;
                    ensure!(raw.len() <= 131072, "verified_execution_metadata_limit");
                    let metadata: serde_json::Value = serde_json::from_slice(&raw)?;
                    let lock: serde_json::Value = serde_json::from_slice(include_bytes!(
                        "../../../../profiles/mcp/filesystem-readonly-v1/package-lock.json"
                    ))
                    .expect("shipped lock");
                    let packages = metadata["packages"]
                        .as_object()
                        .context("verified_execution_metadata_invalid")?;
                    let wanted = lock["packages"].as_object().expect("shipped packages");
                    ensure!(
                        metadata["lockfileVersion"] == 3 && packages.len() + 1 == wanted.len(),
                        "verified_execution_metadata_invalid"
                    );
                    for (name, row) in packages {
                        let expected = wanted
                            .get(name)
                            .context("verified_execution_metadata_invalid")?;
                        ensure!(
                            !name.is_empty()
                                && ["version", "resolved", "integrity"]
                                    .iter()
                                    .all(|key| row.get(*key) == expected.get(*key)),
                            "verified_execution_metadata_invalid"
                        );
                    }
                }
                Entry::File(_) => anyhow::bail!("verified_execution_extra_input"),
            }
        }
        Ok(())
    }

    pub(super) fn capture(profile: &ProfileConfig) -> anyhow::Result<Runtime> {
        ensure!(
            profile.libraries.len() <= 32 && !profile.libraries.is_empty(),
            "verified_execution_library_limit"
        );
        let original = original_files();
        ensure!(
            original["node_sha256"].as_str() == Some(&profile.runtime_sha256),
            "verified_execution_not_original"
        );
        let root = opened(&profile.package_root, true)?;
        let mut tree = BTreeMap::new();
        let mut records = BTreeMap::new();
        let mut bytes = 0;
        walk(&root, Path::new(""), &mut tree, &mut records, &mut bytes, 0)?;
        let mut hash = Sha256::new();
        for value in records.values() {
            hash.update(value);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == profile.package_tree_sha256,
            "verified_execution_package_changed"
        );
        for (path, entry) in &tree {
            if matches!(entry, Entry::Link(_)) {
                resolve_link(&tree, path)?;
            }
        }
        verify_original(&tree, &records, &original)?;
        let mut files = BTreeMap::new();
        let mut inputs = vec![
            (
                "runtime".to_owned(),
                profile.runtime_path.clone(),
                profile.runtime_sha256.clone(),
            ),
            (
                "bwrap".to_owned(),
                profile.bwrap_path.clone(),
                profile.bwrap_sha256.clone(),
            ),
        ];
        for library in &profile.libraries {
            ensure!(
                ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
                    .iter()
                    .any(|base| library.path.starts_with(base) && library.path != Path::new(base)),
                "verified_execution_library_path"
            );
            inputs.push((
                library
                    .path
                    .to_str()
                    .context("verified_execution_path_invalid")?
                    .to_owned(),
                library.path.clone(),
                library.sha256.clone(),
            ));
        }
        for (name, path, expected) in inputs {
            let (image, digest, size) =
                snapshot(opened(&path.canonicalize()?, false)?, MAX_BYTES - bytes)?;
            ensure!(digest == expected, "verified_execution_runtime_changed");
            bytes += size;
            ensure!(
                files.insert(name, image).is_none(),
                "verified_execution_duplicate_input"
            );
        }
        ensure!(
            tree.len() + files.len() <= MAX_ENTRIES,
            "verified_execution_tree_limit"
        );
        let profile_digest = crate::native::canonical_digest(&serde_json::to_value(profile)?);
        let digest = crate::native::canonical_digest(
            &json!({"format":FORMAT,"profile_sha256":profile_digest,
            "package_tree_sha256":profile.package_tree_sha256,"package_mode":"0600-readonly-mount","runtime_mode":"0555",
            "mount":"sealed-runtime-assets-no-declarations-or-source-maps-v1","sandbox":"linux-bwrap","environment":"fixed-profile-v1"}),
        );
        Ok(Runtime {
            profile_digest,
            digest,
            entries: tree.len() + files.len(),
            files,
            tree,
            bytes,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn sealed_images_reject_write_and_have_independent_offsets() {
            let mut source = tempfile::tempfile().unwrap();
            source.write_all(b"original").unwrap();
            source.rewind().unwrap();
            let (image, _, _) = snapshot(source, 64).unwrap();
            assert!(image.try_clone().unwrap().write_all(b"forged").is_err());
            let mut a = reopen(&image).unwrap();
            let mut b = reopen(&image).unwrap();
            let mut text = String::new();
            a.read_to_string(&mut text).unwrap();
            assert_eq!(text, "original");
            text.clear();
            b.read_to_string(&mut text).unwrap();
            assert_eq!(text, "original");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_original_runtime_image_fits_the_pinned_bubblewrap_argument_limit() {
        let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../profiles/mcp/filesystem-readonly-v1/original-closure-files.json"
        ))
        .unwrap();
        let files = manifest["files"].as_object().unwrap();
        let runtime_files = files.keys().filter(|path| runtime_asset(path)).count();
        assert_eq!(files.len(), 4079);
        assert_eq!(runtime_files, 2439);
        let mut directories = std::collections::BTreeSet::new();
        for path in files
            .keys()
            .chain(manifest["bin_links"].as_object().unwrap().keys())
        {
            for parent in Path::new(path).ancestors().skip(1) {
                if !parent.as_os_str().is_empty() {
                    directories.insert(parent);
                }
            }
        }
        // 3 args/file (plus optional npm metadata), 2/directory, 3/bin link,
        // all 32 supported libraries with modes plus runtime, and fixed flags.
        let upper_bound = 3 * (runtime_files + 1)
            + 2 * directories.len()
            + 3 * manifest["bin_links"].as_object().unwrap().len()
            + 33 * 5
            + 200;
        assert!(
            upper_bound + 2 <= 9000,
            "including the private --info-fd pair: {upper_bound}"
        );
        for path in [
            "package.json",
            "node_modules/a/index.js",
            "node_modules/a/index.ts",
            "node_modules/a/README.md",
            "node_modules/a/index.cjs",
            "node_modules/a/module.wasm",
        ] {
            assert!(runtime_asset(path));
        }
        for path in ["index.d.ts", "index.d.cts", "index.d.mts", "index.js.map"] {
            assert!(!runtime_asset(path));
        }
    }
    #[test]
    fn captured_links_cannot_escape_or_cycle_through_other_links() {
        let mut tree = BTreeMap::from([
            ("a".into(), Entry::Directory),
            ("a/link".into(), Entry::Link("../b".into())),
            ("b".into(), Entry::Directory),
            (
                "b/link".into(),
                Entry::Link("../a/link/../../outside".into()),
            ),
        ]);
        assert!(resolve_link(&tree, "a/link").is_ok());
        assert!(resolve_link(&tree, "b/link").is_err());
        tree.insert("cycle".into(), Entry::Link("cycle".into()));
        assert!(resolve_link(&tree, "cycle").is_err());
        tree.insert("absolute".into(), Entry::Link("/workspace/input.js".into()));
        assert!(resolve_link(&tree, "absolute").is_err());
    }
}
