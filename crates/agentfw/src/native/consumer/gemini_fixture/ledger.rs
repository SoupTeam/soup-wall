// SPDX-License-Identifier: Apache-2.0
//! Linux-only held-directory journal; paths from source/model are never used.
use super::*;
use std::{
    fs::File,
    io::Write,
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
    fn create(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.identity()?;
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
impl Attempt<'_> {
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
    drop(ledger);
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("link");
    symlink(dir.path(), &link).unwrap();
    assert!(Ledger::open(&link).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Ledger::open(dir.path()).is_err());
}
