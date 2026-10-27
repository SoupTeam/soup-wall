// SPDX-License-Identifier: Apache-2.0
//! Exact replacement under an explicitly declared private, cooperating-writer
//! boundary. Stat/hash followed by rename is NOT CAS against external writers.

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PROFILE: &str = "sw-native/replace-file/linux-private-root-child/1";
pub const EXCLUSION: &str = "operator-private-sole-writer+directory-flock/1";
pub const MAX_BYTES: usize = 4096;

pub fn content_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub executor_profile: &'static str,
    pub root: RootIdentity,
    pub target: String,
    pub old_identity: Identity,
    pub old_sha256: String,
    pub new_sha256: String,
    pub new_bytes: usize,
    pub executing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub committed: bool,
    pub staged_bytes: usize,
    pub cleanup_unresolved: bool,
}

impl Error {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            committed: false,
            staged_bytes: 0,
            cleanup_unresolved: false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "replacement refused: {} committed={} cleanup_unresolved={}",
            self.code, self.committed, self.cleanup_unresolved
        )
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Serialize)]
pub struct Commit {
    pub committed: bool,
    pub bytes_written: usize,
    pub file_synced: bool,
    pub directory_synced: bool,
}

/// No execution authorization is carried by a plan or prepared descriptor.
pub struct Prepared {
    #[cfg(target_os = "linux")]
    inner: linux::Prepared,
}

pub struct Staged {
    #[cfg(target_os = "linux")]
    inner: linux::Staged,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedReplacement { .. }")
    }
}
impl std::fmt::Debug for Staged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagedReplacement { .. }")
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for Staged {
    fn drop(&mut self) {}
}

impl Prepared {
    pub fn prepare(
        workspace: &Path,
        target: &Path,
        root: &RootIdentity,
        old_identity: &Identity,
        old_sha256: &str,
        content: &str,
    ) -> Result<Self, Error> {
        if content.len() > MAX_BYTES || old_identity.size > MAX_BYTES as u64 {
            return Err(Error::new("replace_content_over_cap"));
        }
        if !crate::native::is_digest(old_sha256) {
            return Err(Error::new("replace_old_digest_invalid"));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: linux::Prepared::prepare(
                    workspace,
                    target,
                    root,
                    old_identity,
                    old_sha256,
                    content,
                )?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workspace, target, root);
            Err(Error::new("replace_platform_unsupported"))
        }
    }

    pub fn preview(&self) -> Result<Preview, Error> {
        #[cfg(target_os = "linux")]
        {
            self.inner.verify()?;
            Ok(self.inner.preview())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::new("replace_platform_unsupported"))
        }
    }

    /// Writable staging is available only after actual native authorization.
    /// A detached staging worker cannot publish: its returned value must pass
    /// the broker's separate publication gate.
    pub fn stage(self) -> Result<Staged, Error> {
        #[cfg(target_os = "linux")]
        {
            Ok(Staged {
                inner: self.inner.stage(linux::Fault::None)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::new("replace_platform_unsupported"))
        }
    }
}

impl Staged {
    pub fn publish_before(self, deadline: std::time::Instant) -> Result<Commit, Error> {
        #[cfg(target_os = "linux")]
        {
            self.inner.publish(linux::Fault::None, deadline)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = deadline;
            Err(Error::new("replace_platform_unsupported"))
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use subtle::ConstantTimeEq;

    pub(super) struct Prepared {
        root: File,
        workspace: PathBuf,
        root_identity: RootIdentity,
        leaf: CString,
        old: File,
        identity: Identity,
        old_sha256: String,
        content: Vec<u8>,
    }

    pub(super) struct Staged {
        prepared: Prepared,
        // Independent open-file description: flock must never share a dup'd
        // description between concurrent writers, even in the same process.
        _lock: File,
        file: File,
        name: CString,
        named: bool,
    }

    pub(super) enum Fault {
        None,
        #[cfg(test)]
        StageWrite,
        #[cfg(test)]
        BeforePublish,
        #[cfg(test)]
        DirectorySync,
    }

    fn identity(m: &fs::Metadata) -> Identity {
        Identity {
            device: m.dev(),
            inode: m.ino(),
            size: m.len(),
            mtime_seconds: m.mtime(),
            mtime_nanoseconds: m.mtime_nsec(),
            ctime_seconds: m.ctime(),
            ctime_nanoseconds: m.ctime_nsec(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }

    fn no_xattrs(file: &File) -> Result<(), Error> {
        // Any attribute, including ACLs and capabilities, is unsupported.
        if unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) } != 0 {
            return Err(Error::new("replace_metadata_unsupported"));
        }
        Ok(())
    }

    fn private(file: &File, directory: bool) -> Result<fs::Metadata, Error> {
        let m = file
            .metadata()
            .map_err(|_| Error::new("replace_stat_failed"))?;
        if m.uid() != unsafe { libc::geteuid() }
            || m.gid() != unsafe { libc::getegid() }
            || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || if directory {
                !m.is_dir()
            } else {
                !m.is_file() || m.nlink() != 1
            }
        {
            return Err(Error::new("replace_metadata_unsupported"));
        }
        no_xattrs(file)?;
        Ok(m)
    }

    fn openat(dir: &File, name: &std::ffi::CStr, flags: i32) -> Result<File, Error> {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Error::new("replace_open_failed"));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_regular(dir: &File, name: &std::ffi::CStr) -> Result<File, Error> {
        let path = openat(dir, name, libc::O_PATH)?;
        let m = path
            .metadata()
            .map_err(|_| Error::new("replace_stat_failed"))?;
        if !m.is_file() || m.nlink() != 1 {
            return Err(Error::new("replace_regular_file_required"));
        }
        let file = openat(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        if identity(&private(&file, false)?) != identity(&m) {
            return Err(Error::new("replace_target_substituted"));
        }
        Ok(file)
    }

    fn trusted_root(path: &Path) -> Result<File, Error> {
        use std::os::unix::ffi::OsStrExt;
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::new("replace_workspace_invalid"));
        }
        let mut current = unsafe { File::from_raw_fd(fd) };
        if !path.is_absolute() {
            return Err(Error::new("replace_workspace_invalid"));
        }
        for component in path.components().skip(1) {
            let std::path::Component::Normal(name) = component else {
                return Err(Error::new("replace_workspace_alias"));
            };
            let name = CString::new(name.as_bytes())
                .map_err(|_| Error::new("replace_workspace_invalid"))?;
            current = openat(&current, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let m = current
                .metadata()
                .map_err(|_| Error::new("replace_stat_failed"))?;
            let trusted = m.uid() == 0 || m.uid() == unsafe { libc::geteuid() };
            let protected = m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0);
            if !trusted || !protected {
                return Err(Error::new("replace_ancestor_not_exclusive"));
            }
        }
        Ok(current)
    }

    fn clean_staging_inventory(root: &File, own: Option<&std::ffi::CStr>) -> Result<(), Error> {
        use std::os::fd::IntoRawFd;
        let fd = openat(root, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        let ptr = unsafe { libc::fdopendir(fd) };
        if ptr.is_null() {
            unsafe {
                libc::close(fd);
            };
            return Err(Error::new("replace_inventory_unavailable"));
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let directory = Directory(ptr);
        let mut count = 0;
        for _ in 0..=259 {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                return if unsafe { *libc::__errno_location() } == 0 {
                    Ok(())
                } else {
                    Err(Error::new("replace_inventory_unavailable"))
                };
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes().starts_with(b".soup-replace-") && own != Some(name) {
                return Err(Error::new("replace_staging_recovery_required"));
            }
            if name.to_bytes() != b"." && name.to_bytes() != b".." && own != Some(name) {
                count += 1;
                if count > 256 {
                    return Err(Error::new("replace_directory_inventory_over_cap"));
                }
            }
        }
        Err(Error::new("replace_directory_inventory_over_cap"))
    }

    fn digest(file: &File) -> Result<String, Error> {
        use std::os::unix::fs::FileExt;
        let mut bytes = vec![0u8; MAX_BYTES + 1];
        let mut n = 0;
        while n < bytes.len() {
            let got = file
                .read_at(&mut bytes[n..], n as u64)
                .map_err(|_| Error::new("replace_read_failed"))?;
            if got == 0 {
                break;
            }
            n += got;
        }
        if n > MAX_BYTES {
            return Err(Error::new("replace_old_over_cap"));
        }
        std::str::from_utf8(&bytes[..n]).map_err(|_| Error::new("replace_old_not_utf8"))?;
        Ok(content_sha256(&bytes[..n]))
    }

    /// Shared with create-only writers. Acquiring a lock is not filesystem
    /// mutation and does not grant authority to publish.
    pub(crate) fn writer_lock(root: &File) -> Result<File, Error> {
        lock(root, libc::LOCK_EX)
    }

    pub(crate) fn create_writer_lock(root: &File) -> Result<File, Error> {
        // Create-only publications retain their original parallel no-clobber
        // semantics. All of them conflict with an exclusive replacement.
        lock(root, libc::LOCK_SH)
    }

    fn lock(root: &File, mode: i32) -> Result<File, Error> {
        let lock = openat(root, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if unsafe { libc::flock(lock.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
            return Err(Error::new("replace_writer_busy"));
        }
        Ok(lock)
    }

    impl Prepared {
        pub(super) fn prepare(
            workspace: &Path,
            target: &Path,
            root_identity: &RootIdentity,
            expected: &Identity,
            old_sha256: &str,
            content: &str,
        ) -> Result<Self, Error> {
            // Pin using the accepted no-follow workspace implementation. Exact
            // canonical spelling and ancestor checks reject parser aliases.
            let pinned = crate::sandbox::PinnedWorkspace::open(workspace)
                .map_err(|_| Error::new("replace_workspace_invalid"))?;
            if pinned.canonical() != workspace {
                return Err(Error::new("replace_workspace_alias"));
            }
            let root = trusted_root(workspace)?;
            if target.parent() != Some(workspace) {
                return Err(Error::new("replace_direct_child_required"));
            }
            let text = target
                .to_str()
                .filter(|s| {
                    s.len() <= 4096 && !s.chars().any(char::is_control) && !s.contains('\\')
                })
                .ok_or_else(|| Error::new("replace_path_invalid"))?;
            let leaf = target
                .file_name()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty() && s.len() <= 255 && !s.starts_with(".soup-replace-"))
                .ok_or_else(|| Error::new("replace_path_invalid"))?;
            if workspace.join(leaf).to_str() != Some(text) {
                return Err(Error::new("replace_path_alias"));
            }
            let leaf = CString::new(leaf).map_err(|_| Error::new("replace_path_invalid"))?;
            let old = open_regular(&root, &leaf)?;
            let result = Self {
                root,
                workspace: workspace.into(),
                root_identity: root_identity.clone(),
                leaf,
                old,
                identity: expected.clone(),
                old_sha256: old_sha256.into(),
                content: content.as_bytes().to_vec(),
            };
            result.verify()?;
            Ok(result)
        }

        pub(super) fn verify(&self) -> Result<(), Error> {
            self.verify_with_stage(None)
        }

        fn verify_with_stage(&self, own: Option<&std::ffi::CStr>) -> Result<(), Error> {
            let m = private(&self.root, true)?;
            if m.dev() != self.root_identity.device || m.ino() != self.root_identity.inode {
                return Err(Error::new("replace_workspace_substituted"));
            }
            // Re-open every ancestor no-follow through accepted confinement.
            let current = crate::sandbox::PinnedWorkspace::open(&self.workspace)
                .map_err(|_| Error::new("replace_workspace_substituted"))?;
            if current.dev() != m.dev()
                || current.ino() != m.ino()
                || current.canonical() != self.workspace
            {
                return Err(Error::new("replace_workspace_substituted"));
            }
            let current = trusted_root(&self.workspace)?;
            let current = current
                .metadata()
                .map_err(|_| Error::new("replace_stat_failed"))?;
            if current.dev() != m.dev() || current.ino() != m.ino() {
                return Err(Error::new("replace_workspace_substituted"));
            }
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(self.root.as_raw_fd(), &mut stat) } != 0
                || !matches!(
                    stat.f_type as u64,
                    0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994
                )
            {
                return Err(Error::new("replace_filesystem_unsupported"));
            }
            let before = private(&self.old, false)?;
            if identity(&before) != self.identity || before.dev() != m.dev() {
                return Err(Error::new("replace_old_identity_changed"));
            }
            let current = open_regular(&self.root, &self.leaf)?;
            if identity(&private(&current, false)?) != self.identity {
                return Err(Error::new("replace_target_substituted"));
            }
            let actual = digest(&self.old)?;
            if !bool::from(actual.as_bytes().ct_eq(self.old_sha256.as_bytes())) {
                return Err(Error::new("replace_old_digest_changed"));
            }
            if identity(&private(&self.old, false)?) != self.identity {
                return Err(Error::new("replace_old_identity_changed"));
            }
            clean_staging_inventory(&self.root, own)?;
            Ok(())
        }

        pub(super) fn preview(&self) -> Preview {
            Preview {
                executor_profile: PROFILE,
                root: self.root_identity.clone(),
                target: self
                    .workspace
                    .join(self.leaf.to_str().expect("validated UTF-8"))
                    .to_string_lossy()
                    .into(),
                old_identity: self.identity.clone(),
                old_sha256: self.old_sha256.clone(),
                new_sha256: content_sha256(&self.content),
                new_bytes: self.content.len(),
                executing: false,
            }
        }

        pub(super) fn stage(self, _fault: Fault) -> Result<Staged, Error> {
            let lock = writer_lock(&self.root)?;
            self.verify()?;
            let name = CString::new(format!(".soup-replace-{}", crate::token::generate()))
                .expect("fixed alphabet");
            let file = openat(
                &self.root,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            )?;
            let mut staged = Staged {
                prepared: self,
                _lock: lock,
                file,
                name,
                named: true,
            };
            let mut bytes = 0;
            let result = (|| {
                private(&staged.file, false)?;
                #[cfg(test)]
                if matches!(_fault, Fault::StageWrite) {
                    return Err(Error::new("replace_stage_write_failed"));
                }
                while bytes < staged.prepared.content.len() {
                    let written = staged
                        .file
                        .write(&staged.prepared.content[bytes..])
                        .map_err(|_| Error::new("replace_stage_write_failed"))?;
                    if written == 0 {
                        return Err(Error::new("replace_stage_write_failed"));
                    }
                    bytes += written;
                }
                staged
                    .file
                    .sync_all()
                    .map_err(|_| Error::new("replace_stage_sync_failed"))?;
                staged.verify_stage()?;
                staged.prepared.verify_with_stage(Some(&staged.name))
            })();
            if let Err(mut error) = result {
                error.staged_bytes = bytes;
                error.cleanup_unresolved = !staged.cleanup();
                return Err(error);
            }
            Ok(staged)
        }
    }

    impl Staged {
        fn verify_stage(&self) -> Result<(), Error> {
            let m = private(&self.file, false)?;
            let by_name = open_regular(&self.prepared.root, &self.name)?;
            if identity(&private(&by_name, false)?) != identity(&m)
                || m.dev() != self.prepared.root_identity.device
                || m.len() != self.prepared.content.len() as u64
                || !bool::from(
                    digest(&self.file)?
                        .as_bytes()
                        .ct_eq(content_sha256(&self.prepared.content).as_bytes()),
                )
            {
                return Err(Error::new("replace_stage_changed"));
            }
            Ok(())
        }

        fn cleanup(&mut self) -> bool {
            if !self.named {
                return true;
            }
            let owned = self.file.metadata().ok();
            let current = openat(&self.prepared.root, &self.name, libc::O_PATH)
                .ok()
                .and_then(|f| f.metadata().ok());
            if !matches!((owned,current),(Some(a),Some(b)) if a.dev()==b.dev() && a.ino()==b.ino() && b.nlink()==1)
            {
                return false;
            }
            if unsafe { libc::unlinkat(self.prepared.root.as_raw_fd(), self.name.as_ptr(), 0) } != 0
            {
                return false;
            }
            self.named = false;
            true
        }

        pub(super) fn publish(
            mut self,
            _fault: Fault,
            deadline: std::time::Instant,
        ) -> Result<Commit, Error> {
            let result = (|| {
                self.prepared.verify_with_stage(Some(&self.name))?;
                self.verify_stage()?;
                #[cfg(test)]
                if matches!(_fault, Fault::BeforePublish) {
                    return Err(Error::new("replace_publish_failed"));
                }
                if std::time::Instant::now() >= deadline {
                    return Err(Error::new("replace_publication_expired"));
                }
                // Linearization point, valid ONLY under the declared sole-writer
                // boundary and the retained directory flock. No external CAS.
                if unsafe {
                    libc::renameat(
                        self.prepared.root.as_raw_fd(),
                        self.name.as_ptr(),
                        self.prepared.root.as_raw_fd(),
                        self.prepared.leaf.as_ptr(),
                    )
                } != 0
                {
                    return Err(Error::new("replace_publish_failed"));
                }
                self.named = false;
                #[cfg(test)]
                if matches!(_fault, Fault::DirectorySync) {
                    let mut e = Error::new("replace_committed_directory_sync_failed");
                    e.committed = true;
                    return Err(e);
                }
                let published =
                    open_regular(&self.prepared.root, &self.prepared.leaf).and_then(|file| {
                        let m = private(&file, false)?;
                        let staged = self
                            .file
                            .metadata()
                            .map_err(|_| Error::new("replace_committed_stat_failed"))?;
                        if m.dev() != staged.dev() || m.ino() != staged.ino() {
                            return Err(Error::new("replace_committed_target_changed"));
                        }
                        Ok(())
                    });
                published.map_err(|mut e| {
                    e.committed = true;
                    e
                })?;
                self.prepared.root.sync_all().map_err(|_| {
                    let mut e = Error::new("replace_committed_directory_sync_failed");
                    e.committed = true;
                    e
                })?;
                Ok(Commit {
                    committed: true,
                    bytes_written: self.prepared.content.len(),
                    file_synced: true,
                    directory_synced: true,
                })
            })();
            result.map_err(|mut error| {
                error.staged_bytes = self.prepared.content.len();
                error.cleanup_unresolved = !self.cleanup();
                error
            })
        }
    }

    impl Drop for Staged {
        fn drop(&mut self) {
            if !self.cleanup() {
                eprintln!(
                    "{{\"event\":\"mcp_replace_cleanup_unresolved\",\"cleanup_verified\":false}}"
                );
            }
        }
    }

    pub(super) fn observe(
        workspace: &Path,
        target: &Path,
        content: &str,
    ) -> Result<Preview, Error> {
        let pinned = crate::sandbox::PinnedWorkspace::open(workspace)
            .map_err(|_| Error::new("replace_workspace_invalid"))?;
        let root = RootIdentity {
            device: pinned.dev(),
            inode: pinned.ino(),
        };
        let leaf = target
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::new("replace_path_invalid"))?;
        let name = CString::new(leaf).map_err(|_| Error::new("replace_path_invalid"))?;
        let fd = pinned
            .duplicate_root_descriptor()
            .map_err(|_| Error::new("replace_workspace_invalid"))?;
        let old = open_regular(&fd, &name)?;
        let expected = identity(&private(&old, false)?);
        let hash = digest(&old)?;
        let prepared =
            super::Prepared::prepare(workspace, target, &root, &expected, &hash, content)?;
        prepared.preview()
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{create_writer_lock, writer_lock};

/// Read-only plan. This is deliberately independent of installation or policy.
pub fn preview(workspace: &Path, target: &Path, content: &str) -> Result<Preview, Error> {
    if content.len() > MAX_BYTES {
        return Err(Error::new("replace_content_over_cap"));
    }
    #[cfg(target_os = "linux")]
    {
        linux::observe(workspace, target, content)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (workspace, target);
        Err(Error::new("replace_platform_unsupported"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = dir.path().join("result.txt");
        fs::write(&target, b"old bounded result\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, target)
    }
    fn prepare(root: &Path, target: &Path, content: &str) -> Prepared {
        let p = preview(root, target, content).unwrap();
        Prepared::prepare(
            root,
            target,
            &p.root,
            &p.old_identity,
            &p.old_sha256,
            content,
        )
        .unwrap()
    }
    fn clean(root: &Path) {
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }

    #[test]
    fn replacement_preview_has_no_mutation_or_content_and_commit_changes_inode() {
        let (dir, target) = fixture();
        let old = fs::metadata(&target).unwrap().ino();
        let plan = preview(dir.path(), &target, "new useful result\n").unwrap();
        let public = serde_json::to_string(&plan).unwrap();
        assert!(!public.contains("old bounded result") && !public.contains("new useful result"));
        assert!(!plan.executing);
        assert_eq!(fs::metadata(&target).unwrap().ino(), old);
        clean(dir.path());
        let result = prepare(dir.path(), &target, "new useful result\n")
            .stage()
            .unwrap()
            .publish_before(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .unwrap();
        assert!(result.committed && result.directory_synced && result.file_synced);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new useful result\n");
        assert_ne!(fs::metadata(&target).unwrap().ino(), old);
        clean(dir.path());
    }
    #[test]
    fn replacement_stale_digest_identity_and_pending_content_change_refuse() {
        let (dir, target) = fixture();
        let plan = preview(dir.path(), &target, "new").unwrap();
        assert_eq!(
            Prepared::prepare(
                dir.path(),
                &target,
                &plan.root,
                &plan.old_identity,
                &"a".repeat(64),
                "new"
            )
            .unwrap_err()
            .code,
            "replace_old_digest_changed"
        );
        let p = prepare(dir.path(), &target, "new");
        fs::write(&target, b"changed").unwrap();
        assert_eq!(p.stage().unwrap_err().code, "replace_old_identity_changed");
        assert_eq!(fs::read_to_string(target).unwrap(), "changed");
        clean(dir.path());
    }
    #[test]
    fn replacement_competing_same_version_has_one_publication() {
        let (dir, target) = fixture();
        let a = prepare(dir.path(), &target, "first");
        let b = prepare(dir.path(), &target, "second");
        let staged = a.stage().unwrap();
        assert_eq!(b.stage().unwrap_err().code, "replace_writer_busy");
        staged
            .publish_before(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(fs::read_to_string(target).unwrap(), "first");
        clean(dir.path());
    }
    #[test]
    fn replacement_serializes_with_create_writers_and_releases_on_cancel() {
        let (dir, target) = fixture();
        let pinned = crate::sandbox::PinnedWorkspace::open(dir.path()).unwrap();
        let staged = prepare(dir.path(), &target, "new").stage().unwrap();
        let create = crate::mcp::create_file::PreparedCreate::prepare(
            &pinned,
            &dir.path().join("created"),
            "new",
        )
        .unwrap();
        assert!(create.stage().is_err());
        drop(staged);
        clean(dir.path());
        prepare(dir.path(), &target, "new")
            .stage()
            .unwrap()
            .publish_before(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .unwrap();
    }
    #[test]
    fn replacement_root_or_target_substitution_preserves_replacements() {
        let (dir, target) = fixture();
        let p = prepare(dir.path(), &target, "new");
        fs::rename(&target, dir.path().join("moved")).unwrap();
        fs::write(&target, "foreign").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(p.stage().is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "foreign");
        let (dir, target) = fixture();
        let p = prepare(dir.path(), &target, "new");
        let moved = dir.path().with_extension("saved");
        fs::rename(dir.path(), &moved).unwrap();
        fs::create_dir(dir.path()).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(p.stage().unwrap_err().code, "replace_workspace_substituted");
        assert_eq!(
            fs::read_to_string(moved.join("result.txt")).unwrap(),
            "old bounded result\n"
        );
        fs::remove_dir_all(moved).unwrap();
    }
    #[test]
    fn replacement_links_special_files_modes_and_attributes_refuse() {
        let (dir, target) = fixture();
        let plan = preview(dir.path(), &target, "new").unwrap();
        fs::hard_link(&target, dir.path().join("alias")).unwrap();
        assert!(Prepared::prepare(
            dir.path(),
            &target,
            &plan.root,
            &plan.old_identity,
            &plan.old_sha256,
            "new"
        )
        .is_err());
        fs::remove_file(dir.path().join("alias")).unwrap();
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("outside", &target).unwrap();
        assert!(preview(dir.path(), &target, "new").is_err());
        fs::remove_file(&target).unwrap();
        let name = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(preview(dir.path(), &target, "new").is_err());
        fs::remove_file(&target).unwrap();
        fs::write(&target, "old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(preview(dir.path(), &target, "new").is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let file = fs::File::open(&target).unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    c"user.sou159".as_ptr(),
                    c"x".as_ptr().cast(),
                    1,
                    0,
                )
            },
            0
        );
        assert_eq!(
            preview(dir.path(), &target, "new").unwrap_err().code,
            "replace_metadata_unsupported"
        );
    }
    #[test]
    fn replacement_stage_drop_and_faults_keep_old_while_post_commit_error_is_honest() {
        let (dir, target) = fixture();
        let old = fs::read(&target).unwrap();
        drop(prepare(dir.path(), &target, "new").stage().unwrap());
        clean(dir.path());
        assert_eq!(fs::read(&target).unwrap(), old);
        let p = prepare(dir.path(), &target, "new");
        let error = p.inner.stage(linux::Fault::StageWrite).err().unwrap();
        assert!(!error.committed && !error.cleanup_unresolved);
        clean(dir.path());
        let staged = prepare(dir.path(), &target, "new")
            .inner
            .stage(linux::Fault::None)
            .unwrap();
        let error = staged
            .publish(
                linux::Fault::BeforePublish,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .unwrap_err();
        assert!(!error.committed && !error.cleanup_unresolved);
        clean(dir.path());
        assert_eq!(fs::read(&target).unwrap(), old);
        let staged = prepare(dir.path(), &target, "new")
            .inner
            .stage(linux::Fault::None)
            .unwrap();
        let error = staged
            .publish(
                linux::Fault::DirectorySync,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .unwrap_err();
        assert!(error.committed && !error.cleanup_unresolved);
        clean(dir.path());
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }
    #[test]
    fn replacement_stage_tampering_preserves_foreign_inventory() {
        let (dir, target) = fixture();
        let staged = prepare(dir.path(), &target, "new").stage().unwrap();
        let stage = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p != &target)
            .unwrap();
        fs::remove_file(&stage).unwrap();
        fs::write(&stage, "foreign").unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
        let error = staged
            .publish_before(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .unwrap_err();
        assert!(error.cleanup_unresolved && !error.committed);
        assert_eq!(fs::read_to_string(stage).unwrap(), "foreign");
        assert_eq!(fs::read_to_string(target).unwrap(), "old bounded result\n");
    }
    #[test]
    fn replacement_byte_limits_and_utf8_refuse_without_staging() {
        let (dir, target) = fixture();
        assert!(preview(dir.path(), &target, &"x".repeat(MAX_BYTES + 1)).is_err());
        fs::write(&target, vec![0xff]).unwrap();
        assert_eq!(
            preview(dir.path(), &target, "new").unwrap_err().code,
            "replace_old_not_utf8"
        );
        clean(dir.path());
    }

    #[test]
    fn replacement_expired_publication_and_orphan_staging_refuse() {
        let (dir, target) = fixture();
        let staged = prepare(dir.path(), &target, "new").stage().unwrap();
        let error = staged
            .publish_before(std::time::Instant::now())
            .unwrap_err();
        assert_eq!(error.code, "replace_publication_expired");
        assert!(!error.committed);
        clean(dir.path());
        let orphan = dir.path().join(".soup-replace-old-operation");
        fs::write(&orphan, "retained private state").unwrap();
        assert_eq!(
            preview(dir.path(), &target, "new").unwrap_err().code,
            "replace_staging_recovery_required"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "old bounded result\n");
        assert_eq!(
            fs::read_to_string(orphan).unwrap(),
            "retained private state"
        );
    }
}
