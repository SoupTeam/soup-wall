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
        }
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn servers_key(self) -> &'static str {
        match self {
            Self::Claude | Self::Gemini => "mcpServers",
            Self::Codex => "mcp_servers",
        }
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn parse(self, bytes: &[u8]) -> Result<Value> {
        match self {
            Self::Claude => {
                let super::super::admission::Strict(value) = serde_json::from_slice(bytes)
                    .map_err(|_| anyhow::anyhow!("invalid or duplicate JSON fields"))?;
                Ok(value)
            }
            Self::Gemini => jsonc::parse(bytes),
            Self::Codex => toml_edit::de::from_slice(bytes)
                .map_err(|_| anyhow::anyhow!("invalid or duplicate TOML fields")),
        }
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn validate(self, entry: &Value) -> Result<()> {
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
                        let mut value = if key == "command" {
                            toml_edit::Value::from(value.as_str().context("invalid command")?)
                        } else {
                            let mut array = toml_edit::Array::new();
                            for arg in value.as_array().context("invalid arguments")? {
                                array.push(arg.as_str().context("invalid argument")?);
                            }
                            toml_edit::Value::Array(array)
                        };
                        if let Some(old) = selected
                            .get_mut(key)
                            .and_then(toml_edit::Item::as_value_mut)
                        {
                            *value.decor_mut() = old.decor().clone();
                            *old = value;
                        } else {
                            selected.insert(key, toml_edit::Item::Value(value));
                        }
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
        let input = b"# profile\nmodel = 'fixture' # keep\n[mcp_servers.'local.test']\n# selected command\ncommand = '/usr/bin/python3' # launch\nargs = ['a b']\n[mcp_servers.other]\ncommand = 'untouched'\nenv = { TOKEN = 'synthetic-secret' } # keep secret\n";
        let original = Host::Codex.parse(input).unwrap()["mcp_servers"]["local.test"].clone();
        let next = json!({"command":"/usr/bin/env", "args":["-i", "a b", "quote\"newline\n"]});
        let output = Host::Codex.replace(input, "local.test", &next).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.starts_with("# profile\nmodel = 'fixture' # keep\n"));
        assert!(text.ends_with("[mcp_servers.other]\ncommand = 'untouched'\nenv = { TOKEN = 'synthetic-secret' } # keep secret\n"));
        assert!(text.contains("# selected command\ncommand"));
        assert!(text.contains("# launch"));
        let restored = Host::Codex
            .replace(&output, "local.test", &original)
            .unwrap();
        assert!(std::str::from_utf8(&restored)
            .unwrap()
            .contains("# selected command\ncommand"));
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
}
