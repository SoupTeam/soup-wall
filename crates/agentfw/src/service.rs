// SPDX-License-Identifier: Apache-2.0
//! Opt-in Linux user services. State locks are never held across systemctl waits.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::lifecycle::{sha256_file, Manager};

const STATE: &str = "ownership.json";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PROPERTIES: &str = "LoadState,FragmentPath,DropInPaths,Transient,NeedDaemonReload,MainPID,ActiveState,SubState,Result,ControlGroup,UnitFileState,NRestarts";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    format_version: u32,
    uid: u32,
    home: PathBuf,
    unit: PathBuf,
    unit_digest: String,
    launcher: PathBuf,
    launcher_digest: String,
    unit_identity: Option<Identity>,
    launcher_identity: Option<Identity>,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Installing,
    Installed,
    Removing,
}

#[derive(Serialize)]
pub struct Preview {
    pub home: PathBuf,
    pub unit_name: String,
    pub unit_path: PathBuf,
    pub launcher: PathBuf,
    pub unit: String,
    pub starts_automatically: bool,
}

pub struct Service {
    home: PathBuf,
    root: PathBuf,
    unit_dir: PathBuf,
    name: String,
}

/// Even an invalid ownership record reserves the profile until explicitly repaired.
pub fn registered(home: &Path) -> bool {
    fs::symlink_metadata(home.join("service").join(STATE)).is_ok()
}

pub fn require_unregistered(home: &Path) -> Result<()> {
    ensure!(!registered(home), "profile has a registered service; use agentfw service commands (uninstall before lifecycle removal or migration)");
    Ok(())
}

impl Service {
    pub fn new(home: &Path) -> Result<Self> {
        Self::with_unit_dir(home, user_home()?.join(".config/systemd/user"))
    }

    fn with_unit_dir(home: &Path, unit_dir: PathBuf) -> Result<Self> {
        check_directory(home)?;
        let home = home.canonicalize()?;
        let name = format!(
            "agentfw-{}.service",
            digest(home.as_os_str().as_encoded_bytes())
        );
        Ok(Self {
            root: home.join("service"),
            home,
            unit_dir,
            name,
        })
    }

    fn launcher(&self) -> PathBuf {
        self.root.join("agentfw-launcher")
    }
    fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(&self.name)
    }
    fn manager(&self) -> Manager {
        Manager::new(&self.home)
    }

    pub fn preview(&self) -> Result<Preview> {
        let launcher = quote(&self.launcher())?;
        let home = quote(&self.home)?;
        let unit = format!("[Unit]\nDescription=Soup Wall Agent\nStartLimitIntervalSec=60s\nStartLimitBurst=3\n\n[Service]\nType=exec\nExecStart={launcher} service --home {home} launch\nExecStartPost={launcher} service --home {home} ready\nExecStop={launcher} service --home {home} shutdown\nRestart=always\nRestartSec=2s\nTimeoutStartSec=35s\nTimeoutStopSec=30s\nKillMode=control-group\nUMask=0077\nStandardOutput=null\nStandardError=null\n");
        Ok(Preview {
            home: self.home.clone(),
            unit_name: self.name.clone(),
            unit_path: self.unit_path(),
            launcher: self.launcher(),
            unit,
            starts_automatically: false,
        })
    }

    pub fn install(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        manager_available()?;
        if registered(&self.home) {
            let record = self.load()?;
            ensure!(
                record.phase == Phase::Installed,
                "service installation is incomplete; uninstall its recorded files before retrying"
            );
            self.verify(&record)?;
            self.verify_loaded()?;
            return Ok(());
        }
        let status = self.manager().status()?;
        ensure!(
            status.detail == "installed and stopped" && !status.interrupted,
            "install and recover the Agent lifecycle first"
        );
        ensure!(
            status.process.is_none(),
            "stop or recover the existing lifecycle process before installing a service"
        );
        let existing = self.show()?;
        ensure!(
            property(&existing, "LoadState") == "not-found"
                && property(&existing, "DropInPaths").is_empty(),
            "a unit with this name already exists"
        );
        ensure!(
            !exists(&self.unit_path())? && !exists(&self.launcher())?,
            "unowned service files already exist"
        );
        make_directory(&self.unit_dir)?;
        let preview = self.preview()?;
        let source = std::env::current_exe()?;
        owned_file(&source)?;
        let mut record = Ownership {
            format_version: 1,
            uid: uid(),
            home: self.home.clone(),
            unit: self.unit_path(),
            unit_digest: digest(preview.unit.as_bytes()),
            launcher: self.launcher(),
            launcher_digest: sha256_file(&source)?,
            unit_identity: None,
            launcher_identity: None,
            phase: Phase::Installing,
        };
        let lifecycle = self.manager();
        let state_lock = lifecycle.lock()?;
        // Recheck under the same lock used by legacy lifecycle mutations.
        // The service record reserves this profile before that lock is released.
        require_unregistered(&self.home)?;
        lifecycle.service_installable()?;
        self.save(&record)?;
        drop(state_lock);
        let mut launcher = create_private(&record.launcher)?;
        std::io::copy(&mut File::open(source)?, &mut launcher)?;
        launcher.set_permissions(fs::Permissions::from_mode(0o700))?;
        launcher.sync_all()?;
        let mut unit = create_private(&record.unit)?;
        unit.write_all(preview.unit.as_bytes())?;
        unit.sync_all()?;
        record.launcher_identity = Some(identity(&record.launcher)?);
        record.unit_identity = Some(identity(&record.unit)?);
        self.verify(&record)?;
        self.save(&record)?;
        control(&["daemon-reload"])?;
        self.verify_loaded()?;
        record.phase = Phase::Installed;
        self.save(&record)
    }

    pub fn uninstall(&self) -> Result<()> {
        if !registered(&self.home) {
            return Ok(());
        }
        let _operation = self.operation_lock()?;
        let mut record = self.load()?;
        manager_available()?;
        self.verify_remaining(&record)?;
        let shown = self.show()?;
        if property(&shown, "LoadState") != "not-found" {
            self.verify_loaded()?;
            ensure!(
                property(&shown, "MainPID") == "0"
                    && matches!(property(&shown, "ActiveState"), "inactive" | "failed"),
                "stop the service before uninstalling it"
            );
        }
        record.phase = Phase::Removing;
        self.save(&record)?;
        for path in [&record.unit, &record.launcher] {
            if exists(path)? {
                fs::remove_file(path)?;
            }
        }
        control(&["daemon-reload"])?;
        fs::remove_file(self.root.join(STATE))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn operation_lock(&self) -> Result<File> {
        make_directory(&self.root)?;
        let path = self.root.join("operation.lock");
        if exists(&path)? {
            owned_file(&path)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.try_lock()
            .context("another service operation is in progress")?;
        Ok(file)
    }

    fn load(&self) -> Result<Ownership> {
        check_directory(&self.root)?;
        let path = self.root.join(STATE);
        owned_file(&path)?;
        let record: Ownership =
            serde_json::from_slice(&fs::read(path)?).context("invalid service ownership record")?;
        ensure!(
            record.format_version == 1
                && record.uid == uid()
                && record.home == self.home
                && record.unit == self.unit_path()
                && record.launcher == self.launcher(),
            "service ownership does not match this profile and user"
        );
        ensure!(
            record.unit_digest == digest(self.preview()?.unit.as_bytes()),
            "recorded unit does not match the supported service definition"
        );
        Ok(record)
    }

    fn save(&self, record: &Ownership) -> Result<()> {
        let temp = self.root.join(format!(".{}.tmp", crate::token::generate()));
        let mut file = create_private(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(record)?)?;
        file.sync_all()?;
        let path = self.root.join(STATE);
        if exists(&path)? {
            owned_file(&path)?;
        }
        fs::rename(temp, path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn verify(&self, record: &Ownership) -> Result<()> {
        verify_file(
            &record.unit,
            &record.unit_digest,
            record.unit_identity.as_ref(),
        )?;
        verify_file(
            &record.launcher,
            &record.launcher_digest,
            record.launcher_identity.as_ref(),
        )
    }

    fn verify_remaining(&self, record: &Ownership) -> Result<()> {
        for (path, hash, id) in [
            (
                &record.unit,
                &record.unit_digest,
                record.unit_identity.as_ref(),
            ),
            (
                &record.launcher,
                &record.launcher_digest,
                record.launcher_identity.as_ref(),
            ),
        ] {
            if exists(path)? {
                verify_file(path, hash, id)?;
            } else {
                ensure!(
                    record.phase != Phase::Installed,
                    "owned service file is missing"
                );
            }
        }
        Ok(())
    }

    fn show(&self) -> Result<BTreeMap<String, String>> {
        let text = systemctl(&["show", &self.name, "--property", PROPERTIES], true)?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line
                .split_once('=')
                .context("invalid systemctl properties")?;
            ensure!(
                values.insert(key.to_owned(), value.to_owned()).is_none(),
                "duplicate systemctl property"
            );
        }
        for key in PROPERTIES.split(',') {
            ensure!(
                values.contains_key(key),
                "missing systemctl property: {key}"
            );
        }
        Ok(values)
    }

    fn verify_loaded(&self) -> Result<BTreeMap<String, String>> {
        let shown = self.show()?;
        ensure!(
            property(&shown, "LoadState") == "loaded"
                && property(&shown, "FragmentPath")
                    == self
                        .unit_path()
                        .to_str()
                        .context("unit path is not UTF-8")?,
            "systemd loaded a different or unavailable unit"
        );
        ensure!(
            property(&shown, "DropInPaths").is_empty()
                && property(&shown, "Transient") == "no"
                && property(&shown, "NeedDaemonReload") == "no",
            "unit has overrides or changed settings; refusing service management"
        );
        ensure!(
            property(&shown, "UnitFileState") == "static",
            "service has unexpected enablement or unit links"
        );
        Ok(shown)
    }
}

fn property<'a>(shown: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    shown.get(key).map(String::as_str).unwrap_or("")
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn user_home() -> Result<PathBuf> {
    // Reentrant lookup avoids HOME overrides used for disposable Agent profiles.
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwuid_r(
            uid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    ensure!(
        code == 0 && !result.is_null(),
        "cannot determine the current user's service directory"
    );
    let record = unsafe { record.assume_init() };
    let path = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }.to_str()?;
    Ok(PathBuf::from(path))
}

fn quote(path: &Path) -> Result<String> {
    let value = path.to_str().context("service paths must be UTF-8")?;
    ensure!(
        path.is_absolute() && !value.chars().any(char::is_control),
        "service paths must be absolute without control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn check_parents(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        if parent.as_os_str().is_empty() {
            continue;
        }
        ensure!(
            fs::symlink_metadata(parent)?.is_dir(),
            "service path has a symlink or non-directory parent"
        );
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<()> {
    check_parents(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid() && metadata.mode() & 0o022 == 0,
        "service directory must be owned by this user and not writable by others"
    );
    Ok(())
}

fn make_directory(path: &Path) -> Result<()> {
    if !exists(path)? {
        if let Some(parent) = path.parent() {
            if !exists(parent)? {
                make_directory(parent)?;
            }
        }
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    check_directory(path)
}

fn owned_file(path: &Path) -> Result<fs::Metadata> {
    check_parents(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "service file is foreign, linked, or writable by others: {}",
        path.display()
    );
    Ok(metadata)
}

fn create_private(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

fn identity(path: &Path) -> Result<Identity> {
    let metadata = owned_file(path)?;
    Ok(Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        digest: sha256_file(path)?,
    })
}

fn verify_file(path: &Path, hash: &str, expected: Option<&Identity>) -> Result<()> {
    let actual = identity(path)?;
    ensure!(
        actual.digest == hash && expected.is_none_or(|value| value == &actual),
        "owned service file changed or was replaced: {}",
        path.display()
    );
    Ok(())
}

fn manager_available() -> Result<()> {
    systemctl(&["show", "--property=Version"], false)
        .context("user systemd manager is unavailable; run in a Linux user session")?;
    Ok(())
}
fn control(args: &[&str]) -> Result<()> {
    systemctl(args, false).map(|_| ())
}

fn systemctl(args: &[&str], allow_missing: bool) -> Result<String> {
    let mut child = Command::new(SYSTEMCTL)
        .args(["--user", "--no-pager", "--no-ask-password"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot execute systemctl --user")?;
    let mut stdout = child.stdout.take().context("missing systemctl output")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        (&mut stdout)
            .take(65537)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("systemctl timed out; operation may be incomplete, inspect before retrying");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("systemctl output reader failed"))??;
    ensure!(
        status.success() || (allow_missing && status.code() == Some(4)),
        "systemctl operation failed ({status}); inspect the service state"
    );
    ensure!(
        bytes.len() <= 65536,
        "systemctl output exceeded the safety limit"
    );
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_preserves_literals_and_rejects_controls() {
        assert_eq!(
            quote(Path::new("/tmp/a b%$\"\\")).unwrap(),
            "\"/tmp/a b%%$$\\\"\\\\\""
        );
        assert!(quote(Path::new("/tmp/a\nb")).is_err());
        assert!(quote(Path::new("relative")).is_err());
    }
    #[test]
    fn preview_is_nonmutating_and_profiles_are_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let a = Service::with_unit_dir(temp.path(), temp.path().join("units")).unwrap();
        let preview = a.preview().unwrap();
        assert!(!a.root.exists());
        assert!(!preview.unit.contains("[Install]"));
        assert!(preview.unit.contains("Type=exec"));
        assert!(!preview.unit.contains("lifecycle start"));
        let other = tempfile::tempdir().unwrap();
        assert_ne!(
            a.name,
            Service::with_unit_dir(other.path(), other.path().join("units"))
                .unwrap()
                .name
        );
    }
    #[test]
    fn invalid_ownership_still_blocks_legacy_operations() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("service")).unwrap();
        fs::write(temp.path().join("service/ownership.json"), "invalid").unwrap();
        let manager = Manager::new(temp.path());
        assert!(manager
            .start()
            .unwrap_err()
            .to_string()
            .contains("registered service"));
        assert!(manager
            .remove()
            .unwrap_err()
            .to_string()
            .contains("registered service"));
        assert!(manager
            .recover()
            .unwrap_err()
            .to_string()
            .contains("registered service"));
    }

    #[test]
    fn replaced_or_linked_files_are_never_owned() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, "owned").unwrap();
        let id = identity(&path).unwrap();
        fs::rename(&path, temp.path().join("old")).unwrap();
        fs::write(&path, "owned").unwrap();
        assert!(verify_file(&path, &id.digest, Some(&id)).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(temp.path().join("old"), &path).unwrap();
        assert!(identity(&path).is_err());
    }
}
