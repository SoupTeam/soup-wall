// SPDX-License-Identifier: Apache-2.0
#[cfg(any(target_os = "linux", test))]
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", test))]
use serde_json::Value;
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
mod jsonc;

/// Configuration syntax only; the host name never authenticates authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    #[default]
    Claude,
    Codex,
    Gemini,
    Opencode,
    Copilot,
}

impl Host {
    #[cfg(target_os = "linux")]
    pub(super) fn is_claude(&self) -> bool {
        *self == Self::Claude
    }
    pub fn server_id(self, path: &Path, server: &str) -> String {
        let legacy = super::server_id(path, server);
        match self {
            Self::Claude => legacy,
            Self::Codex => legacy.replacen("claude-", "codex-", 1),
            Self::Gemini => legacy.replacen("claude-", "gemini-", 1),
            Self::Opencode => legacy.replacen("claude-", "opencode-", 1),
            Self::Copilot => legacy.replacen("claude-", "copilot-", 1),
        }
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn servers_key(self) -> &'static str {
        match self {
            Self::Claude | Self::Gemini | Self::Copilot => "mcpServers",
            Self::Codex => "mcp_servers",
            Self::Opencode => "mcp",
        }
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn parse(self, bytes: &[u8]) -> Result<Value> {
        match self {
            Self::Claude | Self::Copilot => {
                let super::super::admission::Strict(value) = serde_json::from_slice(bytes)
                    .map_err(|_| anyhow::anyhow!("invalid or duplicate JSON fields"))?;
                Ok(value)
            }
            Self::Gemini | Self::Opencode => jsonc::parse(bytes),
            Self::Codex => toml_edit::de::from_slice(bytes)
                .map_err(|_| anyhow::anyhow!("invalid or duplicate TOML fields")),
        }
    }
    // Canonical launch records keep the existing private journal and probe path.
    // Only the selected OpenCode 1.19.6 entry is decoded; unrelated fields stay raw.
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn decode(self, entry: &Value) -> Result<Value> {
        if self == Self::Copilot {
            let map = entry
                .as_object()
                .context("selected Copilot server must be an object")?;
            ensure!(
                map.keys()
                    .all(|k| ["type", "command", "args", "env", "tools"].contains(&k.as_str()))
                    && matches!(entry["type"].as_str(), Some("local" | "stdio"))
                    && map
                        .get("tools")
                        .is_none_or(|v| v == &serde_json::json!(["*"])),
                "unsupported selected Copilot server field, transport or filter"
            );
            let mut out = entry.clone();
            out.as_object_mut().unwrap().remove("type");
            out.as_object_mut().unwrap().remove("tools");
            return Ok(out);
        }
        if self != Self::Opencode {
            return Ok(entry.clone());
        }
        let map = entry
            .as_object()
            .context("selected OpenCode server must be an object")?;
        ensure!(
            map.keys()
                .all(|k| ["type", "command", "environment"].contains(&k.as_str()))
                && entry["type"] == "local",
            "unsupported selected OpenCode server field or transport"
        );
        let command = entry["command"]
            .as_array()
            .filter(|a| !a.is_empty())
            .context("OpenCode command must be a nonempty array")?;
        let mut out = serde_json::json!({"command": command[0], "args": command[1..]});
        if let Some(env) = map.get("environment") {
            out["env"] = env.clone();
        }
        Ok(out)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn validate(self, entry: &Value) -> Result<()> {
        if self == Self::Copilot {
            ensure!(
                std::iter::once(&entry["command"])
                    .chain(entry["args"].as_array().into_iter().flatten())
                    .all(|v| v.as_str().is_none_or(|s| !s.contains("${"))),
                "Copilot launch interpolation is unsupported"
            );
        }
        if self == Self::Opencode {
            // OpenCode resolves these strings before spawning the wrapper. A
            // reviewed launch must not turn into environment/file-derived argv.
            ensure!(
                std::iter::once(&entry["command"])
                    .chain(entry["args"].as_array().into_iter().flatten())
                    .all(|v| v
                        .as_str()
                        .is_none_or(|s| !s.contains("{env:") && !s.contains("{file:"))),
                "OpenCode launch interpolation is unsupported"
            );
        }
        if self != Self::Claude {
            // Do not silently reinterpret cwd, env_vars, filters or approval flags.
            ensure!(
                entry.as_object().is_some_and(|m| m
                    .keys()
                    .all(|k| ["command", "args", "env"].contains(&k.as_str()))),
                "unsupported selected host server field"
            );
        }
        Ok(())
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn replace(self, bytes: &[u8], name: &str, entry: &Value) -> Result<Vec<u8>> {
        match self {
            Self::Claude => {
                let mut value = self.parse(bytes)?;
                value[self.servers_key()][name] = entry.clone();
                Ok(serde_json::to_vec_pretty(&value)?)
            }
            Self::Gemini => jsonc::replace(bytes, self.servers_key(), name, entry),
            Self::Copilot => {
                let mut encoded = self.parse(bytes)?[self.servers_key()][name].clone();
                self.decode(&encoded)?;
                let map = encoded
                    .as_object_mut()
                    .context("missing selected Copilot server")?;
                for key in ["command", "args", "env"] {
                    if let Some(value) = entry.get(key) {
                        map.insert(key.to_string(), value.clone());
                    } else {
                        map.remove(key);
                    }
                }
                jsonc::replace(bytes, self.servers_key(), name, &encoded)
            }
            Self::Opencode => {
                let mut command = vec![entry["command"].clone()];
                command.extend(entry["args"].as_array().into_iter().flatten().cloned());
                let mut encoded = serde_json::json!({"type":"local", "command":command});
                if let Some(env) = entry.get("env") {
                    encoded["environment"] = env.clone();
                }
                jsonc::replace(bytes, self.servers_key(), name, &encoded)
            }
            Self::Codex => {
                let mut doc = std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                    .context("invalid TOML configuration")?;
                let selected = doc
                    .get_mut(self.servers_key())
                    .and_then(toml_edit::Item::as_table_like_mut)
                    .and_then(|t| t.get_mut(name))
                    .and_then(toml_edit::Item::as_table_like_mut)
                    .context("selected Codex server must be a table")?;
                // Only launch fields change; unrelated source text remains intact.
                for key in ["command", "args"] {
                    if let Some(value) = entry.get(key) {
                        let value = if key == "command" {
                            toml_edit::Value::from(value.as_str().context("invalid command")?)
                        } else {
                            let mut array = toml_edit::Array::new();
                            for arg in value.as_array().context("invalid arguments")? {
                                array.push(arg.as_str().context("invalid argument")?);
                            }
                            toml_edit::Value::Array(array)
                        };
                        let mut item = toml_edit::Item::Value(value);
                        if let Some(old) = selected.get(key).and_then(toml_edit::Item::as_value) {
                            *item.as_value_mut().unwrap().decor_mut() = old.decor().clone();
                        }
                        selected.insert(key, item);
                    } else {
                        selected.remove(key);
                    }
                }
                let output = doc.to_string().into_bytes();
                ensure!(
                    self.parse(&output)?[self.servers_key()][name] == *entry,
                    "TOML replacement did not preserve selected entry"
                );
                Ok(output)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn preserves_unrelated_text_and_quoted_names() {
        let input = b"# profile\nmodel = 'fixture' # keep\n[mcp_servers.'local.test']\ncommand = '/usr/bin/python3' # launch\nargs = ['a b']\n[mcp_servers.other]\ncommand = 'untouched'\nenv = { TOKEN = 'synthetic-secret' } # keep secret\n";
        let original = Host::Codex.parse(input).unwrap()["mcp_servers"]["local.test"].clone();
        let next = json!({"command":"/usr/bin/env", "args":["-i", "a b", "quote\"newline\n"]});
        let output = Host::Codex.replace(input, "local.test", &next).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.starts_with("# profile\nmodel = 'fixture' # keep\n"));
        assert!(text.ends_with("[mcp_servers.other]\ncommand = 'untouched'\nenv = { TOKEN = 'synthetic-secret' } # keep secret\n"));
        assert!(text.contains("# launch"));
        let restored = Host::Codex
            .replace(&output, "local.test", &original)
            .unwrap();
        assert_eq!(
            Host::Codex.parse(&restored).unwrap(),
            Host::Codex.parse(input).unwrap()
        );
    }
    #[test]
    fn inline_tables_and_absent_arguments_round_trip() {
        let input = b"mcp_servers = { s = {command = '/bin/true'}, other = {url = 'https://example.invalid'} }\n";
        let original = json!({"command":"/bin/true"});
        let wrapped = json!({"command":"/usr/bin/env", "args":["-i", "/bin/true"]});
        let output = Host::Codex.replace(input, "s", &wrapped).unwrap();
        let restored = Host::Codex.replace(&output, "s", &original).unwrap();
        assert_eq!(
            Host::Codex.parse(&restored).unwrap(),
            Host::Codex.parse(input).unwrap()
        );
    }
    #[test]
    fn rejects_ambiguous_inputs_without_echoing_secrets() {
        for input in [
            b"secret='private'\nsecret='second'".as_slice(),
            b"secret='private",
        ] {
            assert!(!Host::Codex
                .parse(input)
                .unwrap_err()
                .to_string()
                .contains("private"));
        }
        for field in [
            "type",
            "env_vars",
            "cwd",
            "url",
            "enabled",
            "enabled_tools",
            "unknown",
        ] {
            assert!(Host::Codex
                .validate(&json!({"command":"/bin/true",field:true}))
                .is_err());
        }
        assert_ne!(
            Host::Codex.server_id(Path::new("/a"), "s"),
            Host::Claude.server_id(Path::new("/a"), "s")
        );
    }

    #[test]
    fn opencode_array_launch_roundtrip_preserves_unrelated_jsonc() {
        let prefix = "{/* keep */\"mcp\":{\"demo\":";
        let suffix = ",\"other\":{\"type\":\"remote\",\"url\":\"https://example.invalid\",\"headers\":{\"token\":\"synthetic-secret\"}},},\"model\":\"owned/fixture\",}";
        let original = json!({"type":"local","command":["/usr/bin/python3","argument with spaces"],"environment":{}});
        let input = format!("{prefix}{original}{suffix}");
        let decoded = Host::Opencode.decode(&original).unwrap();
        assert_eq!(
            decoded,
            json!({"command":"/usr/bin/python3","args":["argument with spaces"],"env":{}})
        );
        for arg in ["{env:OWNED_FIXTURE}", "prefix{file:/owned/value}"] {
            assert!(Host::Opencode
                .validate(&json!({"command":"/bin/true","args":[arg]}))
                .is_err());
        }
        let wrapped = json!({"command":"/usr/bin/env","args":["-i","/private/agentfw"],"env":{}});
        let output = Host::Opencode
            .replace(input.as_bytes(), "demo", &wrapped)
            .unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.starts_with(prefix) && text.ends_with(suffix));
        assert_eq!(
            Host::Opencode
                .decode(&Host::Opencode.parse(&output).unwrap()["mcp"]["demo"])
                .unwrap(),
            wrapped
        );
        let restored = Host::Opencode.replace(&output, "demo", &decoded).unwrap();
        assert_eq!(
            Host::Opencode.parse(&restored).unwrap(),
            Host::Opencode.parse(input.as_bytes()).unwrap()
        );
        for bad in [
            json!({"type":"remote","command":["/bin/true"]}),
            json!({"type":"local","command":[]}),
            json!({"type":"local","command":"/bin/true"}),
            json!({"type":"local","command":["/bin/true"],"enabled":false}),
            json!({"type":"local","command":["/bin/true"],"cwd":"/owned"}),
        ] {
            assert!(Host::Opencode.decode(&bad).is_err());
        }
    }

    #[test]
    fn copilot_retains_transport_selector_and_unrelated_source() {
        for transport in ["local", "stdio"] {
            let original = json!({"type":transport,"command":"/usr/bin/python3","args":["argument"],"tools":["*"],"env":{}});
            let prefix = "{\"mcpServers\":{\"demo\":";
            let suffix=",\"other\":{\"url\":\"https://example.invalid\",\"headers\":{\"TOKEN\":\"synthetic-secret\"}}},\"setting\":true}";
            let bytes = format!("{prefix}{original}{suffix}");
            let decoded = Host::Copilot.decode(&original).unwrap();
            Host::Copilot.validate(&decoded).unwrap();
            let wrapped =
                json!({"command":"/usr/bin/env","args":["-i","/private/agentfw"],"env":{}});
            let output = Host::Copilot
                .replace(bytes.as_bytes(), "demo", &wrapped)
                .unwrap();
            let text = std::str::from_utf8(&output).unwrap();
            assert!(text.starts_with(prefix) && text.ends_with(suffix));
            let selected = Host::Copilot.parse(&output).unwrap()["mcpServers"]["demo"].clone();
            assert_eq!(selected["type"], transport);
            assert_eq!(selected["tools"], json!(["*"]));
            assert_eq!(Host::Copilot.decode(&selected).unwrap(), wrapped);
            let restored = Host::Copilot.replace(&output, "demo", &decoded).unwrap();
            assert_eq!(
                Host::Copilot.parse(&restored).unwrap(),
                Host::Copilot.parse(bytes.as_bytes()).unwrap()
            );
            let mut filtered = original;
            filtered["tools"] = json!(["read_document"]);
            assert!(Host::Copilot.decode(&filtered).is_err());
        }
        assert!(Host::Copilot
            .decode(&json!({"type":"http","command":"/bin/true"}))
            .is_err());
        assert!(Host::Copilot
            .validate(&json!({"command":"/bin/true","args":["${OWNED_FIXTURE}"]}))
            .is_err());
    }
}
