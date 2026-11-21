// SPDX-License-Identifier: Apache-2.0
//! Linux-only held-directory journal; paths from source/model are never used.
use super::*;
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

pub(in crate::native) struct Ledger {
    root: File,
}
pub(in crate::native) struct Attempt<'a> {
    ledger: &'a Ledger,
    id: String,
    terminal: bool,
}

impl Ledger {
    pub(in crate::native) fn open(path: &std::path::Path) -> Result<Self> {
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = root.metadata()?;
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "gemini_ledger_permissions"
        );
        ensure!(
            unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "gemini_ledger_busy"
        );
        Ok(Self { root })
    }
    pub(in crate::native) fn identity(&self) -> Result<String> {
        let m = self.root.metadata()?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "gemini_ledger_permissions"
        );
        Ok(hash(&serde_json::to_vec(&(
            m.dev(),
            m.ino(),
            m.uid(),
            m.mode(),
        ))?))
    }
    pub(super) fn create(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.identity()?;
        ensure!(
            safe_name(name) && bytes.len() <= RESPONSE_LIMIT,
            "gemini_ledger_name_or_size"
        );
        let name = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.root.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(fd >= 0, "gemini_ledger_exists_or_unavailable");
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .map_err(|_| anyhow::anyhow!("gemini_ledger_write"))?;
        file.sync_all()
            .map_err(|_| anyhow::anyhow!("gemini_ledger_sync"))?;
        self.root
            .sync_all()
            .map_err(|_| anyhow::anyhow!("gemini_ledger_sync"))?;
        Ok(())
    }
    pub(super) fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.identity()?;
        ensure!(safe_name(name), "gemini_ledger_name");
        let name = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            anyhow::bail!("gemini_ledger_read");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && m.len() <= RESPONSE_LIMIT as u64,
            "gemini_ledger_file_permissions_or_size"
        );
        let mut bytes = Vec::new();
        file.take((RESPONSE_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= RESPONSE_LIMIT, "gemini_ledger_read_limit");
        Ok(Some(bytes))
    }
    pub(in crate::native) fn publication_refused(&self, id: &str) -> Result<()> {
        ensure!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "gemini_ledger_id"
        );
        self.create(
            &format!("{id}.publication-refused"),
            br#"{"state":"stale_after_journal","delivered":false}"#,
        )
    }
    pub(in crate::native) fn reserve(&self, p: &Prepared) -> Result<Attempt<'_>> {
        approved_source(&p.source)?;
        ensure!(
            p.profile == profile_hash() && Instant::now() < p.deadline,
            "gemini_binding"
        );
        let id = hash(p.source.as_bytes()); // Exact whole-frame gate prevents alternate spellings.
        self.create(&format!("{id}.started"),&serde_json::to_vec(&json!({"state":"started_unknown","profile":p.profile,"source":id,"source_bytes":p.source.len(),"request_sha256":hash(&p.body),"attempt":p.nonce,"usd_ceiling":0}))?)?;
        Ok(Attempt {
            ledger: self,
            id,
            terminal: false,
        })
    }
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}
impl Attempt<'_> {
    pub(in crate::native) fn failure(&self, error: &anyhow::Error) -> Result<()> {
        // Never persist arbitrary library messages, URLs or credential text.
        self.ledger.create(
            &format!("{}.failure", self.id),
            super::transport::failure_code(error).as_bytes(),
        )
    }
    pub(in crate::native) fn raw(&self, body: &[u8]) -> Result<()> {
        ensure!(body.len() <= RESPONSE_LIMIT, "gemini_response_limit");
        // Raw private provider envelope includes returned modelVersion and usage;
        // persist even blocked/invalid output, before parsing or publication.
        self.ledger.create(&format!("{}.response", self.id), body)
    }
    pub(in crate::native) fn finish(mut self, state: &str) -> Result<()> {
        ensure!(
            matches!(
                state,
                "valid_untrusted" | "invalid" | "transport_unknown" | "stale" | "quota_stop"
            ),
            "gemini_terminal_state"
        );
        self.ledger.create(
            &format!("{}.terminal", self.id),
            &serde_json::to_vec(&json!({"state":state,"source":self.id,"usd_ceiling":0}))?,
        )?;
        self.terminal = true;
        Ok(())
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            // Best effort only: started_unknown is already durable and sufficient
            // to prohibit replay even if process death prevents this marker.
            let _ = self.ledger.create(
                &format!("{}.terminal", self.id),
                br#"{"state":"cancelled_unknown","usd_ceiling":0}"#,
            );
        }
    }
}

#[test]
fn gemini_protected_ledger_permissions_symlink_lock_cancel_and_raw() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let ledger = Ledger::open(dir.path()).unwrap();
    assert!(Ledger::open(dir.path()).is_err());
    let p = super::tests::prepared();
    let attempt = ledger.reserve(&p).unwrap();
    attempt
        .failure(&anyhow::anyhow!("secret synthetic diagnostic"))
        .unwrap();
    assert_eq!(
        ledger
            .read(&format!("{}.failure", hash(p.source.as_bytes())))
            .unwrap()
            .unwrap(),
        b"gemini_transport_unclassified"
    );
    attempt.raw(b"invalid provider JSON").unwrap();
    drop(attempt);
    assert!(ledger.reserve(&p).is_err());
    let id = hash(p.source.as_bytes());
    assert_eq!(
        std::fs::read(dir.path().join(format!("{id}.response"))).unwrap(),
        b"invalid provider JSON"
    );
    assert_eq!(
        std::fs::metadata(dir.path().join(format!("{id}.response")))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    drop(ledger);
    let ledger = Ledger::open(dir.path()).unwrap();
    assert!(ledger.reserve(&p).is_err());
    assert_eq!(
        ledger.read(&format!("{id}.response")).unwrap().unwrap(),
        b"invalid provider JSON"
    );
    symlink(
        dir.path().join(format!("{id}.response")),
        dir.path().join("response-link"),
    )
    .unwrap();
    assert!(ledger.read("response-link").is_err());
    std::fs::hard_link(
        dir.path().join(format!("{id}.response")),
        dir.path().join("response-hardlink"),
    )
    .unwrap();
    assert!(ledger.read(&format!("{id}.response")).is_err());
    ledger.create("public-mode", b"{}").unwrap();
    std::fs::set_permissions(
        dir.path().join("public-mode"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(ledger.read("public-mode").is_err());
    drop(ledger);
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("link");
    symlink(dir.path(), &link).unwrap();
    assert!(Ledger::open(&link).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Ledger::open(dir.path()).is_err());
}
