# Untrusted project configuration in the Linux pilot (SOU-117)

`agentfw pilot-launch` treats the selected repository as data. Its executable
configuration comes from the operator's explicit installed profiles, policy,
classifier and daemon home. Project text never expands child authority.

## Supported host and configuration inventory

The supported production host is the repository lockfile's Claude Code **2.1.251**
Linux x86_64 native executable, SHA-256
`fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7`.
The launcher hashes the executable before launch. Other hosts/platforms receive
an explicit unsupported error. Existing hidden command-fixture/mock options
remain test-only escape hatches and carry no production isolation claim.

The exact executable's `--help` is checked in the Linux qualification; a newer
CLI reference is not evidence about this pinned binary. See the upstream
[CLI reference](https://code.claude.com/docs/en/cli-reference) and
[settings reference](https://code.claude.com/docs/en/settings) for terminology.

| Discovery surface | Pilot boundary |
| --- | --- |
| User `~/.claude/settings.json`, `~/.claude.json`, credentials, plugins and caches | A new private HOME and CLAUDE_CONFIG_DIR for every launch; original user files are outside discovery. |
| Project and local `.claude/settings.json`, `.claude/settings.local.json`, including ancestors and nested projects | `--restricted` plus `--setting-sources ""`; no project/user settings sources. |
| Project `.mcp.json`, user MCP definitions, plugin MCP servers | `--strict-mcp-config` selects only the two generated collectors. |
| Hooks, project commands, skills and enabled plugins/marketplaces | Restricted mode, an explicit private settings file with `disableAllHooks: true` and no enabled plugins; inherited customization variables are cleared. |
| `CLAUDE.md`, nested context, memory and bundled agents/skills | Existing context/memory/agent disabling flags remain. Repository text received through an allowed read remains untrusted data. |
| `/etc/claude-code/managed-settings.json`, `managed-settings.d`, `managed-mcp.json` | Explicit unsupported refusal before host execution, including symlinks and unreadable entries. Managed precedence cannot silently restore hooks or servers. |
| Ambient PATH, shell startup, loader, Python and Claude customization variables | Host environment starts empty; fixed `/usr/bin:/bin` PATH, private HOME/TMPDIR, fixed isolation variables. |
| Provider connection | Only operator-provided ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_BASE_URL, HTTP_PROXY, HTTPS_PROXY, NO_PROXY and SSL_CERT_FILE are carried. These must be trusted operator inputs. Project settings cannot supply them. |

Built-in tools remain disabled with `--tools ""`. The allowed tool list,
server-specific signed grants, registry/policy identity checks, result inspection
and original read-only server sandboxes remain in force. The host can launch
only the two explicitly configured collectors. The classifier interpreter is taken
from the validated Git profile; ambient AGENTFW_CLASSIFIER_PYTHON cannot replace it. The launcher creates its private
state atomically with mode 0700 outside the canonical workspace; a TMPDIR
symlink into the project is refused. Signals are registered before creating the
host's separate process group, and each run cleans up its own group and state.

This is a configuration-execution boundary. The pilot does not classify project
text as trusted instructions and does not claim that a live model will always
ignore semantic prompt injection. Provider credentials are available to the
trusted pinned host; an operator-selected hostile provider URL is outside this
boundary. Concurrent replacement of trusted installed executables or a
machine administrator changing `/etc` during a run is outside the repository
attacker model.

## Independent qualification

`scripts/qualify-project-isolation.py` uses the actual pinned host and original
installed filesystem/Git servers, an owned scripted loopback provider, synthetic
canaries and disposable repositories. It does not use a paid model, a user
repository or a real secret.

The owned receiver and command marker are positively calibrated before attack
cases. The cases cover an ordinary repository, project settings, an actual
nested project launch, cancellation, and a repeated launch. Attack files include
hook commands, MCP definitions, provider/environment/PATH overrides, user config,
plugin marketplace/hooks, commands and skills. The provider deliberately proposes
both built-in Bash and an extra MCP tool after useful original-server reads.

Acceptance requires correlated useful filesystem bytes and Git status, explicit
refusals for both ungranted tools, calibrated original-server wire observations,
an actual kernel read, zero escape-command execs, zero command markers/receiver
deliveries, cleanup of observed owned processes/private state, and unchanged
project, synthetic user configuration and unrelated process/file controls.
Configuration probes disabled by restricted mode are recorded as ignored
execution sources, rather than proof that the live model resisted their text.
Unsuccessful runs remain failed evidence. Raw traces and credentials stay private;
only bounded results and hashes are retained. This qualification measures host
mechanisms under a scripted provider, not live-model effectiveness.
