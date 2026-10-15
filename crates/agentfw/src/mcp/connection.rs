// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_SERVERS: usize = 256;

#[derive(Debug, Serialize)]
pub struct Preview {
    pub config: String,
    pub server: String,
    pub command: String,
    pub args_count: usize,
    pub supported: bool,
    pub already_connected: bool,
    pub original_digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ownership {
    version: u8,
    config: PathBuf,
    server: String,
    original_digest: String,
    original_entry: Value,
    wrapped_digest: String,
}

fn digest(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON values serialize");
    format!("{:x}", Sha256::digest(bytes))
}

fn read_config(path: &Path) -> anyhow::Result<Value> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read config {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() as usize > MAX_CONFIG_BYTES {
        bail!("config must be a regular file no larger than 1 MiB")
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid MCP host configuration JSON"))
}

fn servers(value: &mut Value) -> anyhow::Result<&mut Map<String, Value>> {
    let root = value
        .as_object_mut()
        .context("MCP config must be a JSON object")?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("mcpServers must be a JSON object")?;
    if servers.len() > MAX_SERVERS {
        bail!("too many configured MCP servers")
    }
    Ok(servers)
}

fn selected(value: &Value, name: &str) -> anyhow::Result<Value> {
    let root = value
        .as_object()
        .context("MCP config must be a JSON object")?;
    let servers = root
        .get("mcpServers")
        .and_then(Value::as_object)
        .context("mcpServers must be a JSON object")?;
    let entry = servers
        .get(name)
        .context("selected MCP server was not found")?;
    let map = entry
        .as_object()
        .context("selected MCP server must be an object")?;
    map.get("command")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .context("selected server needs a command")?;
    let args = match map.get("args") {
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .context("server args must be an array")?,
        None => &[],
    };
    if args.iter().any(|v| !v.is_string()) {
        bail!("server args must contain strings")
    }
    if map.get("url").is_some() || map.get("type").is_some_and(|v| v != "stdio") {
        bail!("only stdio MCP servers are supported")
    }
    Ok(entry.clone())
}

fn ownership_path(config: &Path) -> PathBuf {
    let mut path = config.as_os_str().to_os_string();
    path.push(".soup-wall-mcp.json");
    PathBuf::from(path)
}

struct OperationLock(PathBuf);

impl OperationLock {
    fn acquire(config: &Path) -> anyhow::Result<Self> {
        let mut path = config.as_os_str().to_os_string();
        path.push(".soup-wall-mcp.lock");
        let path = PathBuf::from(path);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("another MCP configuration operation is active: {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)?;
    Ok(())
}

fn save_config(path: &Path, value: &Value) -> anyhow::Result<()> {
    write_atomic(path, serde_json::to_vec_pretty(value)?.as_slice())
}

pub fn preview(path: &Path, name: &str) -> anyhow::Result<Preview> {
    let value = read_config(path)?;
    let entry = selected(&value, name)?;
    let command = entry["command"].as_str().unwrap_or_default().to_owned();
    let args_count = entry["args"].as_array().map_or(0, Vec::len);
    let original_digest = digest(&entry);
    let already_connected = fs::read(ownership_path(path))
        .ok()
        .and_then(|b| serde_json::from_slice::<Ownership>(&b).ok())
        .is_some_and(|o| {
            o.config == path && o.server == name && o.original_digest == original_digest
        });
    Ok(Preview {
        config: path.display().to_string(),
        server: name.to_owned(),
        command,
        args_count,
        supported: true,
        already_connected,
        original_digest,
    })
}

pub fn connect(path: &Path, name: &str, wrapper: &Path) -> anyhow::Result<Preview> {
    let _lock = OperationLock::acquire(path)?;
    let mut value = read_config(path)?;
    let entry = selected(&value, name)?;
    let original_digest = digest(&entry);
    let state = ownership_path(path);
    if let Ok(bytes) = fs::read(&state) {
        let owner: Ownership =
            serde_json::from_slice(&bytes).context("invalid MCP ownership record")?;
        if owner.config == path && owner.server == name {
            if digest(&entry) == owner.wrapped_digest {
                return Ok(Preview {
                    config: path.display().to_string(),
                    server: name.to_owned(),
                    command: entry["command"].as_str().unwrap_or_default().to_owned(),
                    args_count: entry["args"].as_array().map_or(0, Vec::len),
                    supported: true,
                    already_connected: true,
                    original_digest: owner.original_digest,
                });
            }
            if owner.original_digest == original_digest {
                return preview(path, name);
            }
        }
        bail!("existing MCP ownership record does not match this config")
    }
    let command = entry["command"].as_str().unwrap_or_default().to_owned();
    let args = entry["args"].as_array().cloned().unwrap_or_default();
    let args_count = args.len();
    let server_id = format!("claude-{}", &original_digest[..16]);
    let mut wrapped = entry
        .as_object()
        .cloned()
        .context("selected MCP server must be an object")?;
    wrapped.insert(
        "command".into(),
        Value::String(wrapper.display().to_string()),
    );
    wrapped.insert(
        "args".into(),
        serde_json::json!([
            "mcp",
            "--id",
            server_id,
            "--native-admission",
            "--",
            command
        ]),
    );
    if let Some(items) = wrapped.get_mut("args").and_then(Value::as_array_mut) {
        items.extend(args);
    }
    let wrapped = Value::Object(wrapped);
    let wrapped_digest = digest(&wrapped);
    servers(&mut value)?.insert(name.to_owned(), wrapped);
    save_config(path, &value)?;
    write_atomic(
        &state,
        serde_json::to_vec_pretty(&Ownership {
            version: 1,
            config: path.to_path_buf(),
            server: name.to_owned(),
            original_digest: original_digest.clone(),
            original_entry: entry,
            wrapped_digest,
        })?
        .as_slice(),
    )?;
    Ok(Preview {
        config: path.display().to_string(),
        server: name.to_owned(),
        command,
        args_count,
        supported: true,
        already_connected: false,
        original_digest,
    })
}

pub fn disconnect(path: &Path, name: &str) -> anyhow::Result<()> {
    let _lock = OperationLock::acquire(path)?;
    let state = ownership_path(path);
    let owner: Ownership = serde_json::from_slice(
        &fs::read(&state).context("MCP connection is not managed by Soup Wall")?,
    )?;
    if owner.config != path || owner.server != name {
        bail!("MCP ownership record does not match the selected config")
    }
    let mut value = read_config(path)?;
    let current = selected(&value, name)?;
    if digest(&current) != owner.wrapped_digest {
        bail!("selected MCP entry changed after connect; refusing to overwrite it")
    }
    servers(&mut value)?.insert(name.to_owned(), owner.original_entry);
    save_config(path, &value)?;
    fs::remove_file(state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> PathBuf {
        let path = dir.join("claude.json");
        fs::write(&path, br#"{"mcpServers":{"local":{"command":"server","args":["--safe"],"type":"stdio"},"other":{"command":"other"}}}"#).unwrap();
        path
    }

    #[test]
    fn connect_is_idempotent_and_disconnect_restores_only_selected_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path());
        let before = read_config(&path).unwrap();
        let preview = connect(&path, "local", Path::new("/bin/agentfw")).unwrap();
        assert!(!preview.already_connected);
        let repeated = connect(&path, "local", Path::new("/bin/agentfw")).unwrap();
        assert!(repeated.already_connected);
        assert_eq!(preview.original_digest, repeated.original_digest);
        disconnect(&path, "local").unwrap();
        let after = read_config(&path).unwrap();
        assert_eq!(after["mcpServers"]["local"], before["mcpServers"]["local"]);
        assert_eq!(after["mcpServers"]["other"], before["mcpServers"]["other"]);
    }

    #[test]
    fn disconnect_refuses_user_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path());
        connect(&path, "local", Path::new("/bin/agentfw")).unwrap();
        let mut value = read_config(&path).unwrap();
        value["mcpServers"]["local"]["args"] = serde_json::json!(["user-edit"]);
        save_config(&path, &value).unwrap();
        assert!(disconnect(&path, "local").is_err());
        assert_eq!(
            read_config(&path).unwrap()["mcpServers"]["local"]["args"],
            serde_json::json!(["user-edit"])
        );
    }
}
