# Offline command help

`agent-command-help.py` uses one versioned catalog for installed help and shell completion. Lookup and completion are read-only.

```text
python scripts/agent-command-help.py list
python scripts/agent-command-help.py topic doctor
python scripts/agent-command-help.py completion --shell bash
python scripts/agent-command-help.py completion --shell zsh
python scripts/agent-command-help.py completion --shell fish
```

Review the output before installing it. Save it to a new user-selected file and source or install it explicitly. The tool never edits shell startup files, profiles, tokens, paths, run IDs, or host settings. It does not start the Agent, MCP, Claude, a provider, or a network request. A stale catalog is refused.
