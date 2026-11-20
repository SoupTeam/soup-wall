// SPDX-License-Identifier: Apache-2.0
//! Ephemeral credential pipe from a personally armed, quota-bounded supervisor.
use super::*;
use std::{
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    key: String,
    config_sha256: String,
    project: String,
    model: String,
    pub(super) expires: u64,
    pub(super) max_new_rows: usize,
    parent_pid: u32,
    job: String,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl Grant {
    fn validate(&self, config: &[u8], project: &str, now: u64) -> Result<()> {
        ensure!(
            self.config_sha256 == hash(config) && self.project == project && self.model == MODEL,
            "gemini_session_binding"
        );
        ensure!(
            self.expires > now
                && self.expires <= now + 4 * 3600
                && (1..=30).contains(&self.max_new_rows),
            "gemini_session_budget_or_expiry"
        );
        ensure!(
            !self.job.is_empty()
                && self.job.len() <= 80
                && self
                    .job
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "gemini_session_job"
        );
        ensure!(
            (20..=256).contains(&self.key.len())
                && self
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'),
            "gemini_session_key_shape"
        );
        Ok(())
    }
    pub(super) fn take_key(&mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.key))
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"contract":"sw-personal-memory-session/1","job":self.job,"config_sha256":self.config_sha256,"project":self.project,"model":self.model,"expires":self.expires,"max_new_rows":self.max_new_rows})
    }
}
pub(super) fn receive(config: &[u8], project: &str) -> Result<Option<Grant>> {
    let Some(raw_fd) = std::env::var_os("SOUP_WALL_GEMINI_SESSION_FD") else {
        return Ok(None);
    };
    let fd: i32 = raw_fd
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("gemini_session_fd"))?
        .parse()?;
    ensure!(fd >= 3, "gemini_session_fd");
    // SAFETY: the explicit session launcher transfers ownership of this inherited FD.
    let mut pipe = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = pipe.metadata()?;
    ensure!(
        meta.mode() & libc::S_IFMT == libc::S_IFIFO && meta.uid() == unsafe { libc::geteuid() },
        "gemini_session_pipe"
    );
    unsafe {
        libc::fcntl(pipe.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut pipe).take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "gemini_session_size");
    let grant: Grant = serde_json::from_slice(&bytes)?;
    ensure!(
        grant.parent_pid == unsafe { libc::getppid() } as u32,
        "gemini_session_parent"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    grant.validate(config, project, now)?;
    Ok(Some(grant))
}
#[test]
fn gemini_session_grant_rejects_wrong_scope_expiry_and_budget() {
    let bytes = b"synthetic config";
    let base = json!({"key":"synthetic_only_key_1234567890","config_sha256":hash(bytes),"project":"test-project","model":MODEL,"expires":1100,"max_new_rows":2,"parent_pid":1,"job":"job-1"});
    let mut valid: Grant = serde_json::from_value(base.clone()).unwrap();
    valid.validate(bytes, "test-project", 1000).unwrap();
    assert!(!valid.receipt().to_string().contains("synthetic_only_key"));
    let key = valid.take_key();
    assert!(valid.key.is_empty());
    drop(key);
    for (field, value) in [
        ("model", json!("other")),
        ("project", json!("other")),
        ("config_sha256", json!(hash(b"other"))),
        ("expires", json!(999)),
        ("expires", json!(20000)),
        ("max_new_rows", json!(0)),
        ("max_new_rows", json!(31)),
        ("job", json!("../escape")),
    ] {
        let mut v = base.clone();
        v[field] = value;
        assert!(serde_json::from_value::<Grant>(v)
            .unwrap()
            .validate(bytes, "test-project", 1000)
            .is_err());
    }
}

#[test]
fn gemini_session_pipe_roundtrip_and_scope_rejection() {
    use std::io::Write;
    for mode in ["valid", "wrong-config", "wrong-parent"] {
        let mut fds = [-1; 2];
        // SAFETY: two writable integer slots; ownership transferred to File below.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = json!({"key":"synthetic_session_pipe_1234567890","config_sha256":hash(if mode=="wrong-config" {b"other"} else {b"fixture"}),"project":"test-project","model":MODEL,"expires":now+60,"max_new_rows":1,"parent_pid":if mode=="wrong-parent" {0} else {std::process::id()},"job":"offline-pipe"});
        write
            .write_all(&serde_json::to_vec(&payload).unwrap())
            .unwrap();
        drop(write);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "native::consumer::gemini_fixture::controller::session::gemini_session_pipe_child",
                "--ignored",
                "--exact",
            ])
            .env("SOUP_WALL_GEMINI_SESSION_FD", read.as_raw_fd().to_string())
            .env(
                "SOUP_WALL_SESSION_TEST_VALID",
                if mode == "valid" { "1" } else { "0" },
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
#[test]
#[ignore = "offline synthetic pipe child invoked by parent"]
fn gemini_session_pipe_child() {
    let received = receive(b"fixture", "test-project");
    if std::env::var("SOUP_WALL_SESSION_TEST_VALID").unwrap() == "1" {
        let mut g = received.unwrap().unwrap();
        let key = g.take_key();
        assert_eq!(key.as_str(), "synthetic_session_pipe_1234567890");
        assert!(g.key.is_empty());
    } else {
        assert!(received.is_err());
    }
}
