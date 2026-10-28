// SPDX-License-Identifier: Apache-2.0
//! Bounded, offline compatibility diagnostics. Never a launch authorization.
use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::mcp::server_profile;

pub const FORMAT: &str = "sw-pilot-workspace-inspection/1";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum GitProfileKind {
    V1,
    LocalClone,
    LocalRefs,
    Shallow,
    FileRevisions,
    TrackedSymlinks,
}

impl GitProfileKind {
    pub fn from_format(format: &str) -> Option<Self> {
        [
            Self::V1,
            Self::LocalClone,
            Self::LocalRefs,
            Self::Shallow,
            Self::FileRevisions,
            Self::TrackedSymlinks,
        ]
        .into_iter()
        .find(|kind| kind.format() == format)
    }

    pub fn format(self) -> &'static str {
        match self {
            Self::V1 => server_profile::git::FORMAT,
            Self::LocalClone => server_profile::git_local_clone::FORMAT,
            Self::LocalRefs => server_profile::git::LOCAL_REFS_FORMAT,
            Self::Shallow => server_profile::git::SHALLOW_FORMAT,
            Self::FileRevisions => server_profile::git::FILE_READS_FORMAT,
            Self::TrackedSymlinks => server_profile::git_tracked_symlinks::FORMAT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Supported,
    Conditional,
    Unsupported,
    Unavailable,
}

/// Finite vocabulary: never serialize an underlying error, path or config text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NativeLinuxRequired,
    CanonicalRootRequired,
    OwnedPrivateRootRequired,
    UnsafeLinkOrSpecialFile,
    SharedWriteAccess,
    GitStandaloneRequired,
    GitConfigUnsupported,
    GitAttributesUnsupported,
    GitSubmodulesUnsupported,
    GitWorktreeIndirectionUnsupported,
    GitObjectIndirectionUnsupported,
    GitNestedAttributesOrSubmodules,
    GitHooksUnsupported,
    GitShallowRequiresSelectedProfile,
    GitLocalMetadataUnsupported,
    InspectionBoundExceeded,
    SourceChanged,
    InspectionIoUnavailable,
    ValidatorUnavailable,
    SelectedProfileRequiresRuntimeProof,
    ProfileNotInspectedOffline,
}

impl Reason {
    fn state(self) -> State {
        match self {
            Self::NativeLinuxRequired
            | Self::InspectionBoundExceeded
            | Self::SourceChanged
            | Self::InspectionIoUnavailable
            | Self::ValidatorUnavailable => State::Unavailable,
            Self::SelectedProfileRequiresRuntimeProof => State::Conditional,
            _ => State::Unsupported,
        }
    }

    fn next_action(self) -> &'static str {
        match self {
            Self::NativeLinuxRequired => "Inspect on the selected native Linux host; do not infer WSL/storage support.",
            Self::CanonicalRootRequired => "Select an explicit canonical non-root directory without aliases or traversal.",
            Self::OwnedPrivateRootRequired | Self::SharedWriteAccess => "Select an operator-owned workspace without shared write access; no permission repair is performed.",
            Self::SourceChanged => "Stop concurrent writers and repeat inspection; never reuse this result for launch.",
            Self::InspectionBoundExceeded => "Select a smaller supported workspace; do not raise production limits to bypass refusal.",
            Self::SelectedProfileRequiresRuntimeProof => "Selected profile layout checks passed; the protected runtime must still validate index/object semantics before use.",
            Self::ProfileNotInspectedOffline => "Use the selected profile's existing qualification procedure; this inspector cannot establish its object-view proof offline.",
            Self::InspectionIoUnavailable | Self::ValidatorUnavailable => "Resolve inspection availability with the operator, then repeat; do not assume compatibility.",
            _ => "Select a separate repository compatible with the chosen profile; inspect the reported category without executing helpers or repairing this repository.",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Condition {
    pub role: &'static str,
    pub check: &'static str,
    pub state: State,
    pub reason: Option<Reason>,
    pub next_action: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ProfileIdentity {
    pub filesystem: &'static str,
    pub git: &'static str,
    pub identity_kind: &'static str,
    pub validator_sha256: String,
    pub installed_assets_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    /// Retains the old success token for existing callers; use `state` in v1 consumers.
    pub git_profile_format: &'static str,
    pub status: &'static str,
    pub state: State,
    pub profile: ProfileIdentity,
    pub checks: Vec<Condition>,
    pub executed: bool,
    pub launch_authorized: bool,
    pub runtime_protection_verified: bool,
    pub revalidate_at_launch: bool,
}

impl Report {
    /// Exit success establishes layout compatibility, including an explicit
    /// runtime-proof condition. It never permits use of the report for launch.
    pub fn is_layout_compatible(&self) -> bool {
        matches!(self.state, State::Supported | State::Conditional)
    }

    pub fn is_supported(&self) -> bool {
        self.state == State::Supported
    }

    fn record(&mut self, role: &'static str, check: &'static str, result: Result<(), Reason>) {
        let reason = result.err();
        self.checks.push(Condition {
            role,
            check,
            state: reason.map_or(State::Supported, Reason::state),
            next_action: reason.map_or(
                "Compatibility check only; protected startup must revalidate current inputs.",
                Reason::next_action,
            ),
            reason,
        });
    }

    fn finish(mut self) -> Self {
        // Incomplete inspection dominates a partial compatibility finding.
        self.state = [State::Unavailable, State::Unsupported, State::Conditional]
            .into_iter()
            .find(|state| self.checks.iter().any(|c| c.state == *state))
            .unwrap_or(State::Supported);
        self.status = match self.state {
            State::Supported => "supported-read-only",
            State::Conditional => "conditional",
            State::Unsupported => "unsupported",
            State::Unavailable => "unavailable",
        };
        self
    }
}

pub fn inspect(filesystem: &Path, git: &Path, selected: GitProfileKind) -> Report {
    inspect_inner(filesystem, git, selected, || {})
}

fn inspect_inner(
    filesystem: &Path,
    git: &Path,
    selected: GitProfileKind,
    between_checks: impl FnOnce(),
) -> Report {
    let mut identity = Sha256::new();
    for bytes in [
        include_bytes!("sandbox.rs").as_slice(),
        include_bytes!("mcp/server_profile/git.rs").as_slice(),
        include_bytes!("mcp/server_profile/git_local_clone.rs").as_slice(),
        include_bytes!("mcp/server_profile/git_tracked_symlinks.rs").as_slice(),
        include_bytes!("pilot_launcher.rs").as_slice(),
        include_bytes!("pilot_workspaces.rs").as_slice(),
    ] {
        identity.update((bytes.len() as u64).to_be_bytes());
        identity.update(bytes);
    }
    identity.update(selected.format().as_bytes());
    let mut report = Report {
        format: FORMAT,
        status: "unavailable",
        git_profile_format: selected.format(),
        state: State::Unavailable,
        profile: ProfileIdentity {
            filesystem: server_profile::FORMAT,
            git: selected.format(),
            identity_kind: "compiled-validator-contract",
            validator_sha256: format!("{:x}", identity.finalize()),
            installed_assets_verified: false,
        },
        checks: Vec::new(),
        executed: false,
        launch_authorized: false,
        runtime_protection_verified: false,
        revalidate_at_launch: true,
    };
    #[cfg(target_os = "linux")]
    linux::run(&mut report, filesystem, git, selected, between_checks);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (filesystem, git, between_checks);
        report.record("platform", "native_linux", Err(Reason::NativeLinuxRequired));
    }
    report.finish()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::{self, File, Metadata};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    const MAX_ENTRIES: usize = 32768;
    const MAX_DEPTH: usize = 32;
    const MAX_PATH_BYTES: usize = 4 * 1024 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp(u64, u64, u64, u32, u32, u32, i64, i64, i64, i64);

    fn stamp(m: &Metadata) -> Stamp {
        Stamp(
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }

    fn anchored(file: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()))
    }

    fn open_directory(parent: i32, name: &Path) -> Result<File, Reason> {
        let name =
            CString::new(name.as_os_str().as_bytes()).map_err(|_| Reason::CanonicalRootRequired)?;
        // No helper and no symlink following on the selected component.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(Reason::InspectionIoUnavailable);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    struct Capture {
        root: PathBuf,
        pin: File,
        entries: BTreeMap<PathBuf, Stamp>,
        allow_links: bool,
    }

    fn snapshot(pin: &File, allow_links: bool) -> Result<BTreeMap<PathBuf, Stamp>, Reason> {
        fn walk(
            pin: &File,
            relative: &Path,
            depth: usize,
            bytes: &mut usize,
            rows: &mut BTreeMap<PathBuf, Stamp>,
            allow_links: bool,
        ) -> Result<(), Reason> {
            if depth > MAX_DEPTH || rows.len() >= MAX_ENTRIES {
                return Err(Reason::InspectionBoundExceeded);
            }
            let before = pin
                .metadata()
                .map_err(|_| Reason::InspectionIoUnavailable)?;
            rows.insert(relative.to_owned(), stamp(&before));
            for entry in fs::read_dir(anchored(pin)).map_err(|_| Reason::InspectionIoUnavailable)? {
                let entry = entry.map_err(|_| Reason::InspectionIoUnavailable)?;
                let rel = relative.join(entry.file_name());
                *bytes += rel.as_os_str().len();
                if rows.len() >= MAX_ENTRIES
                    || *bytes > MAX_PATH_BYTES
                    || rel.as_os_str().len() > 4096
                {
                    return Err(Reason::InspectionBoundExceeded);
                }
                let m = fs::symlink_metadata(entry.path()).map_err(|_| Reason::SourceChanged)?;
                if !(m.is_file() || m.is_dir() || (allow_links && m.is_symlink())) {
                    return Err(Reason::UnsafeLinkOrSpecialFile);
                }
                if !m.is_symlink() && m.mode() & 0o022 != 0 {
                    return Err(Reason::SharedWriteAccess);
                }
                if m.is_dir() {
                    let child = open_directory(pin.as_raw_fd(), Path::new(&entry.file_name()))?;
                    if stamp(&m) != stamp(&child.metadata().map_err(|_| Reason::SourceChanged)?) {
                        return Err(Reason::SourceChanged);
                    }
                    walk(&child, &rel, depth + 1, bytes, rows, allow_links)?;
                } else {
                    rows.insert(rel, stamp(&m));
                }
            }
            if stamp(&before) != stamp(&pin.metadata().map_err(|_| Reason::SourceChanged)?) {
                return Err(Reason::SourceChanged);
            }
            Ok(())
        }
        let mut rows = BTreeMap::new();
        walk(pin, Path::new(""), 0, &mut 0, &mut rows, allow_links)?;
        Ok(rows)
    }

    impl Capture {
        fn begin(root: &Path, allow_links: bool) -> Result<Self, Reason> {
            let canonical = crate::sandbox::validate_workspace_path(root).map_err(|e| {
                if e.chain().any(|cause| cause.is::<std::io::Error>()) {
                    Reason::InspectionIoUnavailable
                } else {
                    Reason::CanonicalRootRequired
                }
            })?;
            if canonical.as_os_str() != root.as_os_str() {
                return Err(Reason::CanonicalRootRequired);
            }
            // Pin each ancestor component, so an ancestor swap cannot follow a link.
            let mut pin = open_directory(libc::AT_FDCWD, Path::new("/"))?;
            for component in root.components().skip(1) {
                pin = open_directory(pin.as_raw_fd(), Path::new(component.as_os_str()))?;
            }
            let m = pin
                .metadata()
                .map_err(|_| Reason::InspectionIoUnavailable)?;
            if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
                return Err(Reason::OwnedPrivateRootRequired);
            }
            if stamp(&m) != stamp(&fs::symlink_metadata(root).map_err(|_| Reason::SourceChanged)?) {
                return Err(Reason::SourceChanged);
            }
            let entries = snapshot(&pin, allow_links)?;
            Ok(Self {
                root: root.to_owned(),
                pin,
                entries,
                allow_links,
            })
        }

        fn unchanged(&self) -> Result<(), Reason> {
            if crate::sandbox::validate_workspace_path(&self.root)
                .ok()
                .as_ref()
                != Some(&self.root)
                || stamp(&fs::symlink_metadata(&self.root).map_err(|_| Reason::SourceChanged)?)
                    != self.entries[Path::new("")]
                || snapshot(&self.pin, self.allow_links).map_err(|_| Reason::SourceChanged)?
                    != self.entries
            {
                return Err(Reason::SourceChanged);
            }
            Ok(())
        }
    }

    fn validator_reason(error: &anyhow::Error) -> Reason {
        // Exact static production errors only. Unrecognized errors never pass and
        // are never echoed (I/O paths and config text may be sensitive).
        for error in error.chain() {
            let reason = match error.to_string().as_str() {
                "Git requires a standalone non-bare repository"
                | "git_clone_standalone_required" => Reason::GitStandaloneRequired,
                "git_attributes_unsupported" => Reason::GitAttributesUnsupported,
                "git_submodules_unsupported" => Reason::GitSubmodulesUnsupported,
                "git_worktree_indirection_unsupported" => Reason::GitWorktreeIndirectionUnsupported,
                "git_object_indirection_unsupported" => Reason::GitObjectIndirectionUnsupported,
                "nested Git attributes and submodule declarations are unsupported" => {
                    Reason::GitNestedAttributesOrSubmodules
                }
                "active Git hooks are unsupported" => Reason::GitHooksUnsupported,
                "shallow repositories require explicit opt-in" => {
                    Reason::GitShallowRequiresSelectedProfile
                }
                "Git repository depth limit"
                | "Git repository entry limit"
                | "Git config exceeds limit"
                | "git_clone_depth_limit"
                | "git_clone_entry_limit"
                | "git_clone_control_bounds"
                | "git_clone_index_bounds"
                | "git_clone_attributes_bounds"
                | "git_clone_config_bounds"
                | "git_clone_path_bounds" => Reason::InspectionBoundExceeded,
                "Git config must be a regular file, not a link or special file"
                | "Git config changed to a special file"
                | "Git repository links and special files are unsupported"
                | "git_clone_file_type" => Reason::UnsafeLinkOrSpecialFile,
                "only the bounded core Git config is supported"
                | "Git config section required"
                | "invalid Git config"
                | "unsupported Git configuration"
                | "git_clone_config_syntax"
                | "git_clone_config_section"
                | "git_clone_config_duplicate"
                | "git_clone_config_value"
                | "git_clone_config_required" => Reason::GitConfigUnsupported,
                "git_clone_metadata_unsupported"
                | "git_clone_attributes_syntax"
                | "git_clone_attributes_pattern"
                | "git_clone_attributes_token" => Reason::GitLocalMetadataUnsupported,
                "git_clone_identity_changed" => Reason::SourceChanged,
                _ => continue,
            };
            return reason;
        }
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        }) {
            Reason::GitStandaloneRequired
        } else if error.chain().any(|cause| cause.is::<std::io::Error>()) {
            Reason::InspectionIoUnavailable
        } else {
            Reason::ValidatorUnavailable
        }
    }

    pub(super) fn run(
        report: &mut Report,
        filesystem: &Path,
        git: &Path,
        selected: GitProfileKind,
        between_checks: impl FnOnce(),
    ) {
        let mut captures = Vec::new();
        for (role, root) in [("filesystem", filesystem), ("git", git)] {
            match Capture::begin(
                root,
                role == "git" && matches!(selected, GitProfileKind::TrackedSymlinks),
            ) {
                Ok(capture) => {
                    report.record(role, "canonical_owned_root_and_bounded_tree", Ok(()));
                    captures.push((role, capture));
                }
                Err(reason) => {
                    report.record(role, "canonical_owned_root_and_bounded_tree", Err(reason))
                }
            }
        }
        if let Some((_, capture)) = captures.iter().find(|(role, _)| *role == "git") {
            let root = anchored(&capture.pin);
            let result =
                crate::pilot_launcher::validate_selected_git_workspace(&root, selected.format())
                    .map_err(|e| validator_reason(&e));
            let layout_passed = result.is_ok();
            report.record("git", "selected_production_repository_validator", result);
            if layout_passed && !matches!(selected, GitProfileKind::V1) {
                report.record(
                    "git",
                    "index_and_object_semantics",
                    Err(Reason::SelectedProfileRequiresRuntimeProof),
                );
            }
        }
        between_checks();
        for (role, capture) in captures {
            report.record(role, "source_stable_across_inspection", capture.unchanged());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path().join("files");
        let git_root = temp.path().join("repository");
        fs::create_dir(&fs_root).unwrap();
        fs::create_dir_all(git_root.join(".git/objects/info")).unwrap();
        fs::set_permissions(&fs_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&git_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(fs_root.join("note"), "synthetic untrusted content").unwrap();
        fs::write(
            git_root.join(".git/config"),
            "[core]\nbare = false\nrepositoryformatversion = 0\n",
        )
        .unwrap();
        fs::write(git_root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        (temp, fs_root, git_root)
    }

    fn has(report: &Report, reason: Reason) -> bool {
        report.checks.iter().any(|c| c.reason == Some(reason))
    }

    #[test]
    fn supported_reuses_authority_but_never_authorizes_or_attests_runtime() {
        let (_temp, files, git) = fixture();
        server_profile::git::validate_repository(&git).unwrap();
        let report = inspect(&files, &git, GitProfileKind::V1);
        assert_eq!(report.state, State::Supported);
        assert_eq!(report.status, "supported-read-only");
        assert_eq!(report.checks.len(), 5);
        assert!(
            !report.executed && !report.launch_authorized && !report.runtime_protection_verified
        );
        assert!(report.revalidate_at_launch);
        assert_eq!(report.profile.validator_sha256.len(), 64);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains(files.to_str().unwrap()));
        assert!(!encoded.contains("synthetic untrusted content"));
    }

    #[test]
    fn safe_same_root_is_usable_for_both_roles() {
        let (_temp, _files, git) = fixture();
        assert!(inspect(&git, &git, GitProfileKind::V1).is_supported());
    }

    #[test]
    fn config_helpers_and_credentials_are_never_echoed_or_executed() {
        let (_temp, files, git) = fixture();
        for config in [
            "[core]\nfsmonitor = /private/never-execute\n",
            "[remote \"origin\"]\nurl = https://private-user:synthetic-token@example.invalid/repo\n",
            "[include]\npath = /private/config\n",
        ] {
            fs::write(git.join(".git/config"), config).unwrap();
            assert!(server_profile::git::validate_repository(&git).is_err());
            let report = inspect(&files, &git, GitProfileKind::V1);
            assert_eq!(report.state, State::Unsupported);
            assert!(has(&report, Reason::GitConfigUnsupported));
            let text = serde_json::to_string(&report).unwrap();
            for private in ["private-user", "synthetic-token", "example.invalid", "/private", "never-execute"] {
                assert!(!text.contains(private));
            }
            assert_eq!(fs::read_to_string(git.join(".git/config")).unwrap(), config);
        }
    }

    #[test]
    fn concrete_repository_categories_preserve_production_refusals() {
        for (path, reason) in [
            (".gitattributes", Reason::GitAttributesUnsupported),
            (".gitmodules", Reason::GitSubmodulesUnsupported),
            (".git/commondir", Reason::GitWorktreeIndirectionUnsupported),
            (".git/gitdir", Reason::GitWorktreeIndirectionUnsupported),
            (
                ".git/config.worktree",
                Reason::GitWorktreeIndirectionUnsupported,
            ),
            (
                ".git/objects/info/alternates",
                Reason::GitObjectIndirectionUnsupported,
            ),
            (
                ".git/objects/info/http-alternates",
                Reason::GitObjectIndirectionUnsupported,
            ),
            (".git/shallow", Reason::GitShallowRequiresSelectedProfile),
        ] {
            let (_temp, files, git) = fixture();
            fs::write(git.join(path), "synthetic-refusal").unwrap();
            assert!(server_profile::git::validate_repository(&git).is_err());
            let report = inspect(&files, &git, GitProfileKind::V1);
            assert_eq!(report.state, State::Unsupported, "{path}");
            assert!(has(&report, reason), "{path}: {report:?}");
        }
    }

    #[test]
    fn gitfile_and_absent_git_are_not_supported() {
        let (_temp, files, git) = fixture();
        fs::rename(git.join(".git"), git.join("saved-git")).unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::GitStandaloneRequired
        ));
        fs::write(git.join(".git"), "gitdir: /private/external\n").unwrap();
        let report = inspect(&files, &git, GitProfileKind::V1);
        assert!(has(&report, Reason::GitStandaloneRequired));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("/private/external"));
    }

    #[test]
    fn nested_attributes_and_active_hooks_refuse() {
        let (_temp, files, git) = fixture();
        fs::create_dir(git.join("nested")).unwrap();
        fs::write(git.join("nested/.gitattributes"), "* filter=custom").unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::GitNestedAttributesOrSubmodules
        ));
        fs::remove_file(git.join("nested/.gitattributes")).unwrap();
        fs::create_dir(git.join(".git/hooks")).unwrap();
        fs::write(git.join(".git/hooks/pre-commit"), "exit 99").unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::GitHooksUnsupported
        ));
    }

    #[test]
    fn links_special_files_and_shared_permissions_refuse() {
        let (temp, files, git) = fixture();
        symlink(temp.path(), git.join("outside-link")).unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::UnsafeLinkOrSpecialFile
        ));
        fs::remove_file(git.join("outside-link")).unwrap();
        fs::set_permissions(files.join("note"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::SharedWriteAccess
        ));
        fs::set_permissions(&files, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::OwnedPrivateRootRequired
        ));
    }

    #[test]
    fn fifo_is_refused_without_opening_or_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let (_temp, files, git) = fixture();
        let name = CString::new(files.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(has(
            &inspect(&files, &git, GitProfileKind::V1),
            Reason::UnsafeLinkOrSpecialFile
        ));
    }

    #[test]
    fn root_alias_traversal_and_host_root_are_refused() {
        let (temp, files, git) = fixture();
        let alias = temp.path().join("alias");
        symlink(&files, &alias).unwrap();
        for root in [alias, git.join("../files"), PathBuf::from("/")] {
            assert!(!inspect(&root, &git, GitProfileKind::V1).is_supported());
        }
    }

    #[test]
    fn deep_tree_and_oversized_config_are_unavailable() {
        let (_temp, files, git) = fixture();
        let mut nested = files.clone();
        for _ in 0..34 {
            nested = nested.join("d");
            fs::create_dir(&nested).unwrap();
        }
        let report = inspect(&files, &git, GitProfileKind::V1);
        assert_eq!(report.state, State::Unavailable);
        assert!(has(&report, Reason::InspectionBoundExceeded));
        fs::write(git.join(".git/config"), "x".repeat(8193)).unwrap();
        assert!(has(
            &inspect(&git, &git, GitProfileKind::V1),
            Reason::InspectionBoundExceeded
        ));
    }

    #[test]
    fn concurrent_content_change_is_unavailable_even_when_layout_passes() {
        let (_temp, files, git) = fixture();
        let report = inspect_inner(&files, &git, GitProfileKind::V1, || {
            fs::write(files.join("note"), "changed source during inspection").unwrap();
        });
        assert_eq!(report.state, State::Unavailable);
        assert!(has(&report, Reason::SourceChanged));
    }

    #[test]
    fn replaced_root_is_unavailable_and_peer_is_not_misreported() {
        let (temp, files, git) = fixture();
        let report = inspect_inner(&files, &git, GitProfileKind::V1, || {
            fs::rename(&files, temp.path().join("moved")).unwrap();
            fs::create_dir(&files).unwrap();
        });
        assert_eq!(report.state, State::Unavailable);
        assert!(report.checks.iter().any(|c| c.role == "git"
            && c.check == "source_stable_across_inspection"
            && c.state == State::Supported));
    }

    #[test]
    fn local_clone_remains_conditional_without_runtime_object_proof() {
        let (_temp, files, git) = fixture();
        fs::write(git.join(".git/config"), "[core]\nbare = false\nrepositoryformatversion = 0\n[remote \"origin\"]\nurl = https://synthetic-user:synthetic-token@example.invalid/repo\n").unwrap();
        let report = inspect(&files, &git, GitProfileKind::LocalClone);
        assert_eq!(report.state, State::Conditional);
        assert!(!report.is_supported());
        assert!(has(&report, Reason::SelectedProfileRequiresRuntimeProof));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("synthetic-token"));
        assert_eq!(
            inspect(&files, &git, GitProfileKind::V1).state,
            State::Unsupported
        );
    }

    #[test]
    fn separate_reviewed_profiles_use_selected_authority_and_retain_runtime_condition() {
        let (_temp, files, git) = fixture();
        for profile in [
            GitProfileKind::LocalRefs,
            GitProfileKind::Shallow,
            GitProfileKind::FileRevisions,
            GitProfileKind::TrackedSymlinks,
        ] {
            let report = inspect(&files, &git, profile);
            assert_eq!(report.state, State::Conditional);
            assert!(report.is_layout_compatible());
            assert_eq!(report.profile.git, profile.format());
            assert!(has(&report, Reason::SelectedProfileRequiresRuntimeProof));
        }
    }

    #[test]
    fn shallow_layout_requires_exact_selected_production_validator() {
        let (_temp, files, git) = fixture();
        fs::write(git.join(".git/shallow"), "a".repeat(40) + "\n").unwrap();
        assert_eq!(
            inspect(&files, &git, GitProfileKind::V1).state,
            State::Unsupported
        );
        let report = inspect(&files, &git, GitProfileKind::Shallow);
        assert_eq!(report.state, State::Conditional);
        assert!(report.is_layout_compatible());
        assert!(!report.launch_authorized);
    }

    #[test]
    fn tracked_links_use_production_graph_and_never_follow_outside_targets() {
        let (_temp, files, git) = fixture();
        fs::write(git.join("note"), "owned regular leaf").unwrap();
        symlink("note", git.join("link")).unwrap();
        assert_eq!(
            inspect(&files, &git, GitProfileKind::V1).state,
            State::Unsupported
        );
        assert_eq!(
            inspect(&files, &git, GitProfileKind::TrackedSymlinks).state,
            State::Conditional
        );
        fs::remove_file(git.join("link")).unwrap();
        symlink("/outside/never-open", git.join("link")).unwrap();
        assert!(!inspect(&files, &git, GitProfileKind::TrackedSymlinks).is_layout_compatible());
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: crate::pilot_launcher::PilotWorkspacesArgs,
    }

    #[test]
    fn accepted_cli_format_is_preserved_and_cannot_be_combined_with_short_kind() {
        let base = [
            "inspect",
            "--workspace",
            "/owned/files",
            "--git-workspace",
            "/owned/git",
        ];
        for kind in [
            GitProfileKind::V1,
            GitProfileKind::LocalClone,
            GitProfileKind::LocalRefs,
            GitProfileKind::Shallow,
            GitProfileKind::FileRevisions,
            GitProfileKind::TrackedSymlinks,
        ] {
            let args = Cli::try_parse_from(
                base.into_iter()
                    .chain(["--git-profile-format", kind.format()]),
            )
            .unwrap()
            .args;
            assert_eq!(
                GitProfileKind::from_format(&args.git_profile_format)
                    .unwrap()
                    .format(),
                kind.format()
            );
        }
        assert!(Cli::try_parse_from(
            base.into_iter()
                .chain(["--git-profile-kind", "local-clone"])
        )
        .is_ok());
        assert!(Cli::try_parse_from(base.into_iter().chain([
            "--git-profile-format",
            server_profile::git::FORMAT,
            "--git-profile-kind",
            "local-clone"
        ]))
        .is_err());
        for format in ["", "sw-mcp/git-readonly/1+file-revisions", "unknown"] {
            assert!(GitProfileKind::from_format(format).is_none());
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod platform_tests {
    #[test]
    fn unsupported_host_is_structured_unavailable_without_inspecting_paths() {
        let report = super::inspect(
            std::path::Path::new("private-root"),
            std::path::Path::new("private-git"),
            super::GitProfileKind::V1,
        );
        assert_eq!(report.state, super::State::Unavailable);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("private-root"));
    }
}
