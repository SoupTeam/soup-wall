// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Options {
    #[arg(long)]
    pub path: PathBuf,
    #[arg(long)]
    pub server: String,
    #[arg(long)]
    pub home: PathBuf,
    #[arg(long)]
    pub agent: PathBuf,
    #[arg(long)]
    pub probe_tool: Option<String>,
    #[arg(long, requires = "probe_tool")]
    pub probe_args: Option<String>,
}

#[derive(clap::Subcommand)]
pub enum Command {
    Preview(Options),
    Connect(Options),
    Inspect(Options),
    Disconnect(Options),
}

pub fn run(command: Command) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (operation, options) = match command {
            Command::Preview(o) => ("preview", o),
            Command::Connect(o) => ("connect", o),
            Command::Inspect(o) => ("inspect", o),
            Command::Disconnect(o) => ("disconnect", o),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(linux::run(operation, &options))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        anyhow::ensure!(
            report.status != "unavailable" && report.status != "unknown",
            "connection could not be verified"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        anyhow::bail!(
            "MCP connection transactions require Linux; use an explicit WSL2 Linux profile"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Options;
    use anyhow::{ensure, Context, Result};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    const LIMIT: usize = 1024 * 1024;

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn hash(value: &Value) -> String {
        sha(&serde_json::to_vec(value).expect("JSON value serializes"))
    }

    fn parse(bytes: &[u8]) -> Result<Value> {
        ensure!(bytes.len() <= LIMIT, "configuration exceeds 1 MiB");
        let super::super::admission::Strict(value) = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid or duplicate JSON fields"))?;
        Ok(value)
    }

    fn open_at(dir: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File> {
        let name = CString::new(name.as_bytes()).context("invalid path")?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0o600,
            )
        };
        ensure!(
            fd >= 0,
            "cannot open selected file safely: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn directory(path: &Path) -> Result<File> {
        ensure!(path.is_absolute(), "an absolute path is required");
        let mut dir = File::open("/")?;
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY)?
                }
                _ => anyhow::bail!("path aliases are unsupported"),
            }
        }
        Ok(dir)
    }

    fn private(meta: &Metadata) -> Result<()> {
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "file must be owned, private, regular and single-link"
        );
        ensure!(meta.len() <= LIMIT as u64, "file exceeds 1 MiB");
        Ok(())
    }

    fn read_at(dir: &File, name: &std::ffi::OsStr) -> Result<(Vec<u8>, Metadata)> {
        let file = open_at(dir, name, libc::O_RDONLY)?;
        let meta = file.metadata()?;
        private(&meta)?;
        let mut bytes = Vec::new();
        file.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= LIMIT, "file exceeds 1 MiB");
        Ok((bytes, meta))
    }

    fn read_private(path: &Path) -> Result<Vec<u8>> {
        let dir = directory(path.parent().context("missing parent")?)?;
        Ok(read_at(&dir, path.file_name().context("missing filename")?)?.0)
    }

    fn executable(path: &Path) -> Result<String> {
        let dir = directory(path.parent().context("missing executable parent")?)?;
        let mut file = open_at(
            &dir,
            path.file_name().context("missing executable name")?,
            libc::O_RDONLY,
        )?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o022 == 0
                && meta.mode() & 0o111 != 0
                && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
                && meta.len() <= 512 * 1024 * 1024,
            "unsafe or unavailable executable"
        );
        let mut hasher = Sha256::new();
        let mut buffer = [0; 65536];
        let mut total = 0;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count;
            ensure!(total <= 512 * 1024 * 1024, "executable grew beyond limit");
            hasher.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        ensure!(
            meta.len() == after.len()
                && meta.mtime_nsec() == after.mtime_nsec()
                && meta.ctime_nsec() == after.ctime_nsec()
                && meta.mtime() == after.mtime()
                && meta.ctime() == after.ctime(),
            "executable changed while hashing"
        );
        Ok(format!("{:x}", hasher.finalize()))
    }

    struct ConfigFile {
        dir: File,
        path: PathBuf,
        bytes: Vec<u8>,
        meta: Metadata,
        value: Value,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Publication {
        version: u8,
        path: PathBuf,
        archive: String,
        before_sha256: String,
        proposed_sha256: String,
        before_dev: u64,
        before_ino: u64,
        proposed_dev: u64,
        proposed_ino: u64,
    }

    impl ConfigFile {
        fn read(path: &Path) -> Result<Self> {
            let dir = directory(path.parent().context("missing config parent")?)?;
            let dm = dir.metadata()?;
            ensure!(
                dm.uid() == unsafe { libc::geteuid() } && dm.mode() & 0o022 == 0,
                "config directory must be owned and not writable by other users"
            );
            let (bytes, meta) = read_at(&dir, path.file_name().context("missing filename")?)?;
            let value = parse(&bytes)?;
            Ok(Self {
                dir,
                path: path.to_owned(),
                bytes,
                meta,
                value,
            })
        }

        fn entry(&self, name: &str) -> Result<Value> {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
                "invalid server name"
            );
            let servers = self
                .value
                .get("mcpServers")
                .and_then(Value::as_object)
                .context("mcpServers must be an object")?;
            ensure!(servers.len() <= 256, "too many MCP servers");
            let entry = servers.get(name).context("selected server not found")?;
            validate_entry(entry)?;
            Ok(entry.clone())
        }

        fn replacement(&self, name: &str, entry: &Value) -> Result<Vec<u8>> {
            validate_entry(entry)?;
            let mut next = self.value.clone();
            next["mcpServers"][name] = entry.clone();
            let bytes = serde_json::to_vec_pretty(&next)?;
            ensure!(bytes.len() <= LIMIT, "updated config exceeds 1 MiB");
            Ok(bytes)
        }

        fn snapshot_unchanged(&self, name: &str, owner: &Option<Owner>) -> Result<()> {
            self.unchanged()?;
            ensure!(
                self.state(name)? == *owner,
                "ownership changed during operation"
            );
            Ok(())
        }

        fn state_name(&self, name: &str) -> String {
            format!(
                ".soup-wall-{}.json",
                sha(format!("{}\0{name}", self.path.display()).as_bytes())
            )
        }

        fn unchanged(&self) -> Result<()> {
            let current_parent = directory(self.path.parent().context("missing parent")?)?;
            let dm = self.dir.metadata()?;
            let cm = current_parent.metadata()?;
            ensure!(
                dm.dev() == cm.dev() && dm.ino() == cm.ino(),
                "config directory changed"
            );
            let (bytes, meta) = read_at(
                &self.dir,
                self.path.file_name().context("missing filename")?,
            )?;
            ensure!(
                meta.ino() == self.meta.ino()
                    && meta.dev() == self.meta.dev()
                    && bytes == self.bytes,
                "config changed during operation"
            );
            Ok(())
        }

        fn replace(&mut self, name: &str, entry: &Value) -> Result<()> {
            self.unchanged()?;
            let bytes = self.replacement(name, entry)?;
            self.publish(&bytes)?;
            let current = Self::read(&self.path)?;
            ensure!(current.bytes == bytes, "config changed after replacement");
            *self = current;
            Ok(())
        }

        fn publication_name(&self) -> String {
            format!(
                ".soup-wall-publication-{}.json",
                sha(self.path.as_os_str().as_bytes())
            )
        }

        fn publication(&self) -> Result<Option<Publication>> {
            let name = self.publication_name();
            match std::fs::symlink_metadata(self.path.parent().unwrap().join(&name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
                Ok(_) => {
                    let value = parse(&read_at(&self.dir, name.as_ref())?.0)?;
                    let record: Publication = serde_json::from_value(value)
                        .context("invalid publication journal; retain it for recovery")?;
                    ensure!(
                        record.version == 1
                            && record.path == self.path
                            && record.archive.starts_with(".soup-wall-version-")
                            && record.archive.len() <= 128
                            && record
                                .archive
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                        "invalid publication journal; retain it for recovery"
                    );
                    Ok(Some(record))
                }
            }
        }

        fn write_new(dir: &File, name: &str, bytes: &[u8]) -> Result<Metadata> {
            let mut file = open_at(
                dir,
                name.as_ref(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(file.metadata()?)
        }

        fn finish_publication(&self, record: &Publication) -> Result<()> {
            let archive = open_at(
                &self.dir,
                record.archive.as_ref(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let dm = archive.metadata()?;
            ensure!(
                dm.uid() == unsafe { libc::geteuid() } && dm.mode() & 0o077 == 0,
                "publication archive must be owned and private"
            );
            let before = read_at(&archive, "snapshot.json".as_ref())?.0;
            let proposed = read_at(&archive, "proposed.json".as_ref())?.0;
            let (exchanged, meta) = read_at(&archive, "exchanged.json".as_ref())?;
            self.unchanged()?;
            ensure!(
                sha(&before) == record.before_sha256 && sha(&proposed) == record.proposed_sha256,
                "publication snapshots changed; retain the journal and archive"
            );
            let before_exchange = self.bytes == before
                && self.meta.dev() == record.before_dev
                && self.meta.ino() == record.before_ino
                && exchanged == proposed
                && meta.dev() == record.proposed_dev
                && meta.ino() == record.proposed_ino;
            let after_exchange = self.bytes == proposed
                && self.meta.dev() == record.proposed_dev
                && self.meta.ino() == record.proposed_ino
                && exchanged == before
                && meta.dev() == record.before_dev
                && meta.ino() == record.before_ino;
            ensure!(
                before_exchange || after_exchange,
                "publication conflict; retain the journal and all versions in {}",
                record.archive
            );
            archive.sync_all()?;
            self.dir.sync_all()?;
            let name = CString::new(self.publication_name())?;
            ensure!(
                unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
                "cannot clear publication journal"
            );
            self.dir.sync_all()?;
            Ok(())
        }

        fn publish(&self, bytes: &[u8]) -> Result<()> {
            ensure!(
                self.publication()?.is_none(),
                "pending publication requires recovery"
            );
            let archive_name = format!(".soup-wall-version-{}", crate::token::generate());
            let archive_c = CString::new(archive_name.as_bytes())?;
            ensure!(
                unsafe { libc::mkdirat(self.dir.as_raw_fd(), archive_c.as_ptr(), 0o700) } == 0,
                "cannot create private publication archive"
            );
            let archive = open_at(
                &self.dir,
                archive_name.as_ref(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            Self::write_new(&archive, "snapshot.json", &self.bytes)?;
            Self::write_new(&archive, "proposed.json", bytes)?;
            let proposed = Self::write_new(&archive, "exchanged.json", bytes)?;
            let record = Publication {
                version: 1,
                path: self.path.clone(),
                archive: archive_name,
                before_sha256: sha(&self.bytes),
                proposed_sha256: sha(bytes),
                before_dev: self.meta.dev(),
                before_ino: self.meta.ino(),
                proposed_dev: proposed.dev(),
                proposed_ino: proposed.ino(),
            };
            let journal = serde_json::to_vec_pretty(&record)?;
            Self::write_new(&archive, "manifest.json", &journal)?;
            archive.sync_all()?;
            self.dir.sync_all()?;
            Self::write_new(&self.dir, &self.publication_name(), &journal)?;
            self.dir.sync_all()?;
            self.unchanged()?;
            let from = CString::new("exchanged.json")?;
            let to = CString::new(
                self.path
                    .file_name()
                    .context("missing filename")?
                    .as_bytes(),
            )?;
            ensure!(
                unsafe {
                    libc::renameat2(
                        archive.as_raw_fd(),
                        from.as_ptr(),
                        self.dir.as_raw_fd(),
                        to.as_ptr(),
                        libc::RENAME_EXCHANGE,
                    )
                } == 0,
                "config exchange failed; publication journal retained: {}",
                std::io::Error::last_os_error()
            );
            archive.sync_all()?;
            self.dir.sync_all()?;
            let current = Self::read(&self.path)?;
            current.finish_publication(&record)?;
            ensure!(
                current.bytes == bytes
                    && current.meta.ino() == proposed.ino()
                    && current.meta.dev() == proposed.dev(),
                "config changed at publication; versions retained"
            );
            Ok(())
        }

        fn validate_transaction(&self, owner: &Owner) -> Result<()> {
            self.replacement(&owner.server, &owner.original)?;
            self.replacement(&owner.server, &owner.wrapped)?;
            let mut longest = owner.clone();
            longest.phase = "pending_disconnect".into();
            ensure!(
                serde_json::to_vec_pretty(&longest)?.len() <= LIMIT,
                "ownership metadata exceeds 1 MiB"
            );
            Ok(())
        }

        fn atomic(&self, name: &std::ffi::OsStr, bytes: &[u8]) -> Result<()> {
            ensure!(
                Some(name) != self.path.file_name(),
                "config updates require retained publication"
            );
            let temporary = format!(".soup-wall-stage-{}", crate::token::generate());
            let mut file = open_at(
                &self.dir,
                temporary.as_ref(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            let outcome = (|| -> Result<()> {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                file.write_all(bytes)?;
                file.sync_all()?;
                let from = CString::new(temporary.as_bytes())?;
                let to = CString::new(name.as_bytes())?;
                ensure!(
                    unsafe {
                        libc::renameat(
                            self.dir.as_raw_fd(),
                            from.as_ptr(),
                            self.dir.as_raw_fd(),
                            to.as_ptr(),
                        )
                    } == 0,
                    "atomic rename failed"
                );
                self.dir.sync_all()?;
                Ok(())
            })();
            let temporary = CString::new(temporary)?;
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), temporary.as_ptr(), 0);
            }
            outcome
        }

        fn state(&self, name: &str) -> Result<Option<Owner>> {
            let filename = self.state_name(name);
            let path = self.path.parent().unwrap().join(&filename);
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => anyhow::bail!("ownership metadata unavailable"),
                Ok(_) => {
                    let bytes = read_at(&self.dir, filename.as_ref())?.0;
                    let value = parse(&bytes)?;
                    let owner: Owner = serde_json::from_value(value)
                        .map_err(|_| anyhow::anyhow!("invalid ownership metadata"))?;
                    ensure!(
                        owner.version == 1
                            && owner.path == self.path
                            && owner.server == name
                            && owner.original_sha256 == hash(&owner.original)
                            && owner.wrapped_sha256 == hash(&owner.wrapped),
                        "ownership metadata does not match"
                    );
                    ensure!(
                        [
                            "pending_connect",
                            "connected",
                            "pending_disconnect",
                            "disconnected"
                        ]
                        .contains(&owner.phase.as_str()),
                        "unknown transaction phase"
                    );
                    Ok(Some(owner))
                }
            }
        }

        fn save(&self, owner: &Owner) -> Result<()> {
            self.unchanged()?;
            let bytes = serde_json::to_vec_pretty(owner)?;
            ensure!(bytes.len() <= LIMIT, "ownership metadata exceeds 1 MiB");
            self.atomic(self.state_name(&owner.server).as_ref(), &bytes)
        }

        fn lock(&self) -> Result<File> {
            let file = open_at(
                &self.dir,
                ".soup-wall-mcp.lock".as_ref(),
                libc::O_RDWR | libc::O_CREAT,
            )?;
            private(&file.metadata()?)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "another connection operation is active"
            );
            Ok(file)
        }
    }

    fn validate_entry(entry: &Value) -> Result<()> {
        let map = entry.as_object().context("server must be an object")?;
        ensure!(
            map.keys()
                .all(|k| ["command", "args", "type", "env"].contains(&k.as_str())),
            "unsupported selected server field"
        );
        ensure!(
            map.get("type").is_none_or(|v| v == "stdio"),
            "only stdio is supported"
        );
        ensure!(map.get("env").is_none_or(|v| v.as_object().is_some_and(|m| m.is_empty())), "selected server environment must be empty; credentials cannot enter child environments");
        let command = map
            .get("command")
            .and_then(Value::as_str)
            .context("command must be a string")?;
        ensure!(
            !command.is_empty()
                && command.len() <= 4096
                && !command.contains('\0')
                && Path::new(command).is_absolute(),
            "command must be a bounded absolute executable path"
        );
        if let Some(args) = map.get("args") {
            let args = args.as_array().context("args must be an array")?;
            ensure!(
                args.len() <= 256
                    && args.iter().all(|a| a
                        .as_str()
                        .is_some_and(|s| s.len() <= 16384 && !s.contains('\0'))),
                "invalid or excessive arguments"
            );
        }
        Ok(())
    }

    #[derive(Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        version: u8,
        path: PathBuf,
        server: String,
        phase: String,
        original: Value,
        wrapped: Value,
        original_sha256: String,
        wrapped_sha256: String,
        agent: PathBuf,
        home: PathBuf,
        agent_sha256: String,
        registry_sha256: String,
        native_config_sha256: String,
    }

    #[derive(Serialize)]
    pub(super) struct Report {
        pub status: &'static str,
        operation: String,
        config_sha256: String,
        selected_sha256: String,
        server_id: String,
        agent_sha256: Option<String>,
        registry_sha256: Option<String>,
        probe_result_sha256: Option<String>,
        elapsed_ms: u128,
        detail: &'static str,
    }

    struct Native {
        binary: String,
        registry: String,
        config: String,
    }

    async fn preflight(o: &Options) -> Result<Native> {
        let binary = executable(&o.agent)?;
        ensure!(
            o.home.file_name().is_some_and(|v| v == ".agentfw"),
            "home must be the explicit .agentfw directory"
        );
        let bytes = read_private(&o.home.join("config.yaml"))?;
        let cfg =
            crate::Config::from_yaml(std::str::from_utf8(&bytes).context("invalid native config")?)
                .map_err(|_| anyhow::anyhow!("invalid native configuration"))?;
        ensure!(
            cfg.enforce && !cfg.judge.enabled,
            "enforcing native configuration required"
        );
        let installed = cfg
            .native
            .as_ref()
            .context("pinned native registry required")?;
        let native_token = read_private(&o.home.join("native-token"))?;
        let token = read_private(&o.home.join("token"))?;
        let native_token = std::str::from_utf8(&native_token)?.trim().to_owned();
        ensure!(!native_token.is_empty(), "native token is empty");
        crate::native::NativeState::load(installed, native_token)
            .map_err(|_| anyhow::anyhow!("native registry unavailable or invalid"))?;
        let expected = crate::protection_status::Expectations {
            config_sha256: Some(crate::protection_status::config_digest(&cfg)),
            binary_sha256: Some(binary.clone()),
            registry_sha256: Some(installed.registry_sha256.clone()),
            ..Default::default()
        };
        let snapshot = crate::protection_status::query(
            &cfg,
            std::str::from_utf8(&token)?.trim(),
            &expected,
            Duration::from_secs(2),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("enforcing Agent preflight unavailable or identity mismatch")
        })?;
        ensure!(
            snapshot.mode == crate::protection_status::Mode::Enforcing,
            "Agent is not enforcing"
        );
        Ok(Native {
            binary,
            registry: installed.registry_sha256.clone(),
            config: sha(&bytes),
        })
    }

    fn wrapped(entry: &Value, o: &Options, id: &str) -> Result<Value> {
        executable(Path::new(
            entry["command"].as_str().context("missing command")?,
        ))?;
        ensure!(
            !entry["args"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "--native-admission")),
            "entry is already wrapped without matching ownership"
        );
        let mut result = entry.clone();
        result["command"] = json!("/usr/bin/env");
        let profile = o.home.parent().context("missing profile parent")?;
        let mut args = vec![
            json!("-i"),
            json!("PATH=/usr/bin:/bin"),
            json!(format!("HOME={}", profile.display())),
            json!(format!("USERPROFILE={}", profile.display())),
            json!(o.agent),
            json!("mcp"),
            json!("--id"),
            json!(id),
            json!("--native-admission"),
            json!("--"),
            entry["command"].clone(),
        ];
        args.extend(entry["args"].as_array().into_iter().flatten().cloned());
        result["args"] = Value::Array(args);
        validate_entry(&result)?;
        Ok(result)
    }

    async fn probe(entry: &Value, tool: &str, args: &str) -> Result<String> {
        ensure!(tool.len() <= 128 && !tool.is_empty(), "invalid probe tool");
        let arguments = parse(args.as_bytes())?;
        ensure!(arguments.is_object(), "probe arguments must be an object");
        let mut child =
            tokio::process::Command::new(entry["command"].as_str().context("missing command")?)
                .args(
                    entry["args"]
                        .as_array()
                        .context("missing arguments")?
                        .iter()
                        .map(|v| v.as_str().unwrap_or_default()),
                )
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
        let outcome = tokio::time::timeout(Duration::from_secs(8), async {
            let mut input = child.stdin.take().context("missing stdin")?;
            let mut output = BufReader::new(child.stdout.take().context("missing stdout")?);
            let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"soup-wall-connection","version":"1"}}});
            let frames = [
                init,
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
                json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":tool,"arguments":arguments}}),
            ];
            let mut last = Value::Null;
            for frame in frames {
                input.write_all(format!("{}\n", frame).as_bytes()).await?;
                input.flush().await?;
                if frame.get("id").is_some() {
                    let mut bytes = Vec::new();
                    loop {
                        ensure!(bytes.len() < LIMIT, "probe response exceeds limit");
                        let byte = output.read_u8().await?;
                        if byte == b'\n' { break; }
                        bytes.push(byte);
                    }
                    let reply = parse(&bytes)?;
                    ensure!(reply["id"] == frame["id"] && reply.get("error").is_none() && reply.get("result").is_some(), "probe refused or invalid response");
                    last = reply;
                }
            }
            ensure!(last["result"]["isError"] != true, "probe call was refused");
            Ok::<_, anyhow::Error>(hash(&last["result"]))
        }).await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        outcome.context("probe timed out")?
    }

    pub(super) async fn run(operation: &str, o: &Options) -> Result<Report> {
        let start = Instant::now();
        ensure!(
            o.probe_tool.is_none() || operation == "inspect",
            "controlled requests are only supported by inspect"
        );
        let mut config = ConfigFile::read(&o.path)?;
        let _lock = if ["connect", "disconnect"].contains(&operation) {
            Some(config.lock()?)
        } else {
            None
        };
        if let Some(record) = config.publication()? {
            ensure!(_lock.is_some(), "unfinished publication; run connect or disconnect to recover, retaining all versions");
            config.finish_publication(&record)?;
        }
        let entry = config.entry(&o.server)?;
        let mut owner = config.state(&o.server)?;
        let id = format!(
            "claude-{}",
            &sha(format!("{}\0{}", o.path.display(), o.server).as_bytes())[..24]
        );
        let mut report = Report {
            status: "unknown",
            operation: operation.to_owned(),
            config_sha256: sha(&config.bytes),
            selected_sha256: hash(&entry),
            server_id: id.clone(),
            agent_sha256: None,
            registry_sha256: None,
            probe_result_sha256: None,
            elapsed_ms: 0,
            detail: "connection identity is unknown",
        };
        if operation == "disconnect" {
            let Some(mut state) = owner.clone() else {
                ensure!(
                    !entry["args"]
                        .as_array()
                        .is_some_and(|args| args.iter().any(|v| v == "--native-admission")),
                    "wrapped entry has no matching ownership; state is unknown"
                );
                report.status = "disconnected";
                report.detail = "no owned change to restore";
                config.snapshot_unchanged(&o.server, &owner)?;
                report.elapsed_ms = start.elapsed().as_millis();
                return Ok(report);
            };
            config.snapshot_unchanged(&o.server, &owner)?;
            config.validate_transaction(&state)?;
            if hash(&entry) != state.original_sha256 {
                ensure!(
                    hash(&entry) == state.wrapped_sha256,
                    "selected entry changed; conflict preserved"
                );
                state.phase = "pending_disconnect".into();
                config.save(&state)?;
                config.replace(&o.server, &state.original)?;
            }
            state.phase = "disconnected".into();
            config.save(&state)?;
            owner = Some(state);
            report.status = "disconnected";
            report.detail = "original entry restored; unrelated settings preserved";
        } else if operation == "preview" {
            if let Some(state) = &owner {
                ensure!(
                    hash(&entry) == state.wrapped_sha256 || hash(&entry) == state.original_sha256,
                    "selected entry changed; conflict preserved"
                );
                config.validate_transaction(state)?;
            } else {
                let next = wrapped(&entry, o, &id)?;
                config.replacement(&o.server, &next)?;
            }
            report.status = "preview";
            report.detail = "selected stdio command will use the native collector; original arguments retained; child environment cleared";
        } else {
            let native = preflight(o).await;
            let snapshot = config.snapshot_unchanged(&o.server, &owner);
            if operation == "inspect" && snapshot.is_err() {
                report.detail = "configuration or ownership changed during inspection";
                report.elapsed_ms = start.elapsed().as_millis();
                return Ok(report);
            }
            snapshot?;
            if operation == "inspect" && native.is_err() {
                report.status = "unavailable";
                report.detail = "Agent preflight unavailable or identity mismatch";
            } else {
                let native = native?;
                report.agent_sha256 = Some(native.binary.clone());
                report.registry_sha256 = Some(native.registry.clone());
                if operation == "connect" {
                    if let Some(state) = &owner {
                        ensure!(
                            state.agent == o.agent
                                && state.home == o.home
                                && state.agent_sha256 == native.binary
                                && state.registry_sha256 == native.registry
                                && state.native_config_sha256 == native.config,
                            "selected Agent or native configuration changed"
                        );
                        ensure!(
                            hash(&entry) == state.wrapped_sha256
                                || hash(&entry) == state.original_sha256,
                            "selected entry changed; conflict preserved"
                        );
                    } else {
                        let next = wrapped(&entry, o, &id)?;
                        config.snapshot_unchanged(&o.server, &owner)?;
                        owner = Some(Owner {
                            version: 1,
                            path: o.path.clone(),
                            server: o.server.clone(),
                            phase: "pending_connect".into(),
                            original_sha256: hash(&entry),
                            wrapped_sha256: hash(&next),
                            original: entry.clone(),
                            wrapped: next,
                            agent: o.agent.clone(),
                            home: o.home.clone(),
                            agent_sha256: native.binary,
                            registry_sha256: native.registry,
                            native_config_sha256: native.config,
                        });
                    }
                    let state = owner.as_mut().unwrap();
                    config.validate_transaction(state)?;
                    state.phase = "pending_connect".into();
                    config.save(state)?;
                    if hash(&entry) != state.wrapped_sha256 {
                        config.replace(&o.server, &state.wrapped)?;
                    }
                    state.phase = "connected".into();
                    config.save(state)?;
                    report.status = "configured";
                    report.detail = "native wrapper configured; execution is not inferred";
                } else if let Some(state) = &owner {
                    if state.phase == "connected"
                        && hash(&entry) == state.wrapped_sha256
                        && state.agent == o.agent
                        && state.home == o.home
                        && state.agent_sha256 == native.binary
                        && state.registry_sha256 == native.registry
                        && state.native_config_sha256 == native.config
                    {
                        report.status = "configured";
                        report.detail = "owned configuration and Agent identities match";
                        if let Some(tool) = &o.probe_tool {
                            match probe(&entry, tool, o.probe_args.as_deref().unwrap_or("{}")).await
                            {
                                Ok(hash) => {
                                    report.status = "verified_for_this_probe";
                                    report.probe_result_sha256 = Some(hash);
                                    report.detail =
                                        "controlled request returned a permitted result";
                                }
                                Err(_) => {
                                    report.status = "unavailable";
                                    report.detail = "controlled request failed or was refused";
                                }
                            }
                        }
                    }
                }
            }
        }
        let snapshot = config.snapshot_unchanged(&o.server, &owner);
        if operation == "inspect" && snapshot.is_err() {
            report.status = "unknown";
            report.probe_result_sha256 = None;
            report.detail = "configuration or ownership changed during inspection";
        } else {
            snapshot?;
        }
        report.config_sha256 = sha(&config.bytes);
        report.selected_sha256 = hash(&config.entry(&o.server)?);
        report.elapsed_ms = start.elapsed().as_millis();
        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn fixture() -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("profile with spaces.json");
            std::fs::write(&path, br#"{"mcpServers":{"local":{"command":"/usr/bin/python3.11","args":["-u","space argument"]},"other":{"command":"untouched","env":{"TOKEN":"unrelated-secret"}}},"settings":{"theme":"light"}}"#).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            (dir, path)
        }

        fn ownership(config: &ConfigFile) -> Owner {
            let entry = config.entry("local").unwrap();
            Owner {
                version: 1,
                path: config.path.clone(),
                server: "local".into(),
                phase: "connected".into(),
                original_sha256: hash(&entry),
                wrapped_sha256: hash(&entry),
                original: entry.clone(),
                wrapped: entry,
                agent: PathBuf::from("/usr/bin/env"),
                home: PathBuf::from("/tmp/.agentfw"),
                agent_sha256: "a".repeat(64),
                registry_sha256: "b".repeat(64),
                native_config_sha256: "c".repeat(64),
            }
        }

        #[test]
        fn wrapped_argument_limit_is_checked_before_writing() {
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let executable = std::fs::canonicalize("/usr/bin/env").unwrap();
            let options = Options {
                path: path.clone(),
                server: "local".into(),
                home: PathBuf::from("/tmp/.agentfw"),
                agent: executable.clone(),
                probe_tool: None,
                probe_args: None,
            };
            let entry = json!({"command": executable, "args": vec!["x"; 245]});
            let next = wrapped(&entry, &options, "test").unwrap();
            assert_eq!(next["args"].as_array().unwrap().len(), 256);
            assert!(config.replacement("local", &next).is_ok());
            let entry = json!({"command": executable, "args": vec!["x"; 246]});
            assert!(validate_entry(&entry).is_ok());
            assert!(wrapped(&entry, &options, "test").is_err());
            assert_eq!(std::fs::read(&path).unwrap(), config.bytes);
            assert!(config.state("local").unwrap().is_none());
        }

        #[test]
        fn oversized_transaction_does_not_create_ownership() {
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let mut owner = ownership(&config);
            owner.wrapped["args"] = json!(vec!["x".repeat(16000); 64]);
            owner.original = owner.wrapped.clone();
            assert!(config.replacement("local", &owner.wrapped).is_ok());
            assert!(config.validate_transaction(&owner).is_err());
            assert!(config.state("local").unwrap().is_none());
            assert_eq!(std::fs::read(&path).unwrap(), config.bytes);
        }

        #[test]
        fn oversized_proposed_config_is_rejected_before_writing() {
            let (_dir, path) = fixture();
            let mut config = ConfigFile::read(&path).unwrap();
            config.value["padding"] = json!("x".repeat(LIMIT - 1024));
            let entry = json!({"command":"/usr/bin/env", "args":["x".repeat(2048)]});
            assert!(config.replacement("local", &entry).is_err());
            assert!(config.state("local").unwrap().is_none());
            assert_eq!(std::fs::read(&path).unwrap(), config.bytes);
        }

        #[test]
        fn read_only_snapshot_detects_config_and_ownership_changes() {
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let mut owner = ownership(&config);
            config.save(&owner).unwrap();
            let expected = Some(owner.clone());
            config.snapshot_unchanged("local", &expected).unwrap();
            owner.phase = "pending_disconnect".into();
            config.save(&owner).unwrap();
            assert!(config.snapshot_unchanged("local", &expected).is_err());
            config.snapshot_unchanged("local", &Some(owner)).unwrap();
            std::fs::write(&path, b"{}").unwrap();
            assert!(config.snapshot_unchanged("local", &expected).is_err());
            assert!(config.save(expected.as_ref().unwrap()).is_err());
        }

        #[test]
        fn replacement_refreshes_snapshot_for_following_state_write() {
            let (_dir, path) = fixture();
            let mut config = ConfigFile::read(&path).unwrap();
            let owner = ownership(&config);
            config.replace("local", &owner.wrapped).unwrap();
            config.save(&owner).unwrap();
            config.snapshot_unchanged("local", &Some(owner)).unwrap();
        }

        #[test]
        fn strict_json_rejects_duplicates_at_every_depth() {
            for bytes in [
                br#"{"a":1,"a":2}"#.as_slice(),
                br#"{"a":{"x":1,"x":2}}"#,
                b"[] trailing",
                b"",
            ] {
                assert!(parse(bytes).is_err());
            }
        }

        #[test]
        fn excessive_json_is_rejected() {
            assert!(parse(&vec![b' '; LIMIT + 1]).is_err());
        }

        #[test]
        fn selected_transport_and_arguments_are_strict() {
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            assert_eq!(config.entry("local").unwrap()["args"][1], "space argument");
            for bad in [
                json!({"command":"relative"}),
                json!({"command":"/usr/bin/env","type":"http"}),
                json!({"command":"/usr/bin/env","args":[1]}),
                json!({"command":"/usr/bin/env","env":{"API_KEY":"secret"}}),
                json!({"command":"/usr/bin/env","url":"http://localhost"}),
            ] {
                let mut altered = ConfigFile::read(&path).unwrap();
                altered.value["mcpServers"]["local"] = bad;
                assert!(altered.entry("local").is_err());
            }
        }

        #[test]
        fn symlink_file_is_refused() {
            let (dir, path) = fixture();
            let linked = dir.path().join("link.json");
            symlink(path, &linked).unwrap();
            assert!(ConfigFile::read(&linked).is_err());
        }

        #[test]
        fn symlink_parent_is_refused() {
            let (dir, _path) = fixture();
            let linked = dir.path().join("alias");
            symlink(dir.path(), &linked).unwrap();
            assert!(directory(&linked).is_err());
        }

        #[test]
        fn hardlink_file_is_refused() {
            let (dir, path) = fixture();
            std::fs::hard_link(&path, dir.path().join("hard")).unwrap();
            assert!(ConfigFile::read(&path).is_err());
        }

        #[test]
        fn public_config_is_refused() {
            let (_dir, path) = fixture();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ConfigFile::read(&path).is_err());
        }

        #[test]
        fn fifo_does_not_block_reader() {
            let (dir, _) = fixture();
            let path = dir.path().join("pipe");
            let c = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(ConfigFile::read(&path).is_err());
        }

        #[test]
        fn concurrent_lock_is_refused() {
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let first = config.lock().unwrap();
            assert!(config.lock().is_err());
            drop(first);
            assert!(config.lock().is_ok());
        }

        #[test]
        fn external_edit_is_preserved() {
            let (_dir, path) = fixture();
            let mut config = ConfigFile::read(&path).unwrap();
            let mut changed = config.value.clone();
            changed["settings"]["theme"] = json!("dark");
            std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(config.replace("local", &json!({})).is_err());
            assert_eq!(ConfigFile::read(&path).unwrap().value, changed);
        }

        #[test]
        fn selected_change_preserves_unrelated_settings() {
            let (_dir, path) = fixture();
            let mut config = ConfigFile::read(&path).unwrap();
            let before = config.value.clone();
            config
                .replace("local", &json!({"command":"/usr/bin/env","args":[]}))
                .unwrap();
            let after = ConfigFile::read(&path).unwrap();
            assert_eq!(
                before["mcpServers"]["other"],
                after.value["mcpServers"]["other"]
            );
            assert_eq!(before["settings"], after.value["settings"]);
            assert_eq!(after.meta.mode() & 0o777, 0o600);
        }

        #[test]
        fn a_writer_holding_the_old_inode_keeps_its_version_after_publication() {
            let (dir, path) = fixture();
            let mut config = ConfigFile::read(&path).unwrap();
            let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            let before = config.bytes.clone();
            config
                .replace("local", &json!({"command":"/usr/bin/env","args":[]}))
                .unwrap();
            let proposed = std::fs::read(&path).unwrap();
            writer.set_len(0).unwrap();
            writer.write_all(b"external committed version").unwrap();
            writer.sync_all().unwrap();
            let archive = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".soup-wall-version-")
                })
                .unwrap();
            assert_eq!(
                std::fs::read(archive.join("snapshot.json")).unwrap(),
                before
            );
            assert_eq!(
                std::fs::read(archive.join("proposed.json")).unwrap(),
                proposed
            );
            assert_eq!(
                std::fs::read(archive.join("exchanged.json")).unwrap(),
                b"external committed version"
            );
            assert_eq!(std::fs::read(path).unwrap(), proposed);
            assert!(config.publication().unwrap().is_none());
        }

        #[test]
        fn publication_boundary_conflicts_and_crashes_retain_versions() {
            if let Some(path) = std::env::var_os("SW_PUBLICATION_CHILD") {
                let mut config = ConfigFile::read(Path::new(&path)).unwrap();
                let error = config
                    .replace("local", &json!({"command":"/usr/bin/env","args":[]}))
                    .unwrap_err();
                assert!(
                    error.to_string().contains("publication conflict"),
                    "{error:?}"
                );
                return;
            }
            let build = tempfile::tempdir().unwrap();
            let library = build.path().join("publication.so");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/fixtures/connection_publication.c");
            let output = std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
                .arg(source)
                .arg("-ldl")
                .arg("-o")
                .arg(&library)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            for mode in [
                "write-before",
                "replace-before",
                "held-write-after",
                "write-after",
                "crash-before",
                "crash-after",
            ] {
                let (dir, path) = fixture();
                let before = std::fs::read(&path).unwrap();
                let mut external: Value = serde_json::from_slice(&before).unwrap();
                external["settings"]["theme"] = json!("external committed edit");
                let payload = dir.path().join("external.json");
                let bytes = serde_json::to_vec(&external).unwrap();
                std::fs::write(&payload, &bytes).unwrap();
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "mcp::connection::linux::tests::publication_boundary_conflicts_and_crashes_retain_versions", "--nocapture"])
                    .env("LD_PRELOAD", &library).env("SW_PUBLICATION_MODE", mode)
                    .env("SW_PUBLICATION_EDIT", &payload).env("SW_PUBLICATION_CHILD", &path)
                    .output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(match mode {
                        "crash-before" => 86,
                        "crash-after" => 87,
                        _ => 0,
                    }),
                    "{mode}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let config = ConfigFile::read(&path).unwrap();
                let record = config.publication().unwrap().unwrap();
                let archive = dir.path().join(&record.archive);
                let proposed = std::fs::read(archive.join("proposed.json")).unwrap();
                let displaced = std::fs::read(archive.join("exchanged.json")).unwrap();
                assert_eq!(
                    std::fs::read(archive.join("snapshot.json")).unwrap(),
                    before,
                    "{mode}"
                );
                if mode.starts_with("crash-") {
                    config.finish_publication(&record).unwrap();
                    assert!(config.publication().unwrap().is_none());
                    assert_eq!(
                        config.bytes,
                        if mode == "crash-before" {
                            before
                        } else {
                            proposed
                        }
                    );
                } else {
                    assert!(
                        displaced == bytes || config.bytes == bytes,
                        "{mode}: external version lost"
                    );
                    assert!(config.finish_publication(&record).is_err(), "{mode}");
                    assert!(config.publication().unwrap().is_some(), "{mode}");
                    assert_eq!(
                        std::fs::read(archive.join("exchanged.json")).unwrap(),
                        displaced
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), config.bytes);
                }
            }
        }

        #[test]
        fn failed_rename_preserves_destination() {
            let (dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let target = dir.path().join("directory");
            std::fs::create_dir(&target).unwrap();
            assert!(config.atomic("directory".as_ref(), b"new").is_err());
            assert!(target.is_dir());
            assert!(!std::fs::read_dir(dir.path()).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".soup-wall-stage")));
        }

        #[test]
        fn unsupported_paths_and_server_names_are_refused() {
            assert!(directory(Path::new("relative")).is_err());
            let (_dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            for name in ["", "../local", "local\n", "missing"] {
                assert!(config.entry(name).is_err());
            }
        }

        #[test]
        fn malformed_ownership_is_not_ignored() {
            let (dir, path) = fixture();
            let config = ConfigFile::read(&path).unwrap();
            let state = dir.path().join(config.state_name("local"));
            std::fs::write(&state, b"{}").unwrap();
            std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(config.state("local").is_err());
        }

        #[tokio::test]
        async fn invalid_native_config_does_not_print_values() {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join(".agentfw");
            std::fs::create_dir(&home).unwrap();
            let path = home.join("config.yaml");
            std::fs::write(&path, "port: private-value-must-not-appear\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let options = Options {
                path: dir.path().join("unused.json"),
                server: "demo".into(),
                home,
                agent: PathBuf::from("/usr/bin/env"),
                probe_tool: None,
                probe_args: None,
            };
            let error = preflight(&options).await.err().unwrap();
            assert!(!format!("{error:?}").contains("private-value"));
        }
    }
}
