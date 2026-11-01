# SOU-208 Command Help

## Goal

Provide one bounded offline catalog for installed command help and safe Bash, Zsh, and Fish completion.

## Files

- `scripts/agent-command-help.py`: versioned catalog, topic lookup, and completion output.
- `scripts/test_agent_command_help.py`: parser, shell, stale-catalog, and hostile-input tests.
- `docs/operations/AGENT_COMMAND_HELP.md`: installation and shell export instructions.

## Steps

1. Keep public command names, flags, modes, confirmations, and platform limits in one versioned catalog.
2. Refuse stale or malformed catalogs before lookup or completion.
3. Emit shell-specific candidates without eval, command substitution, paths, tokens, profiles, or run IDs.
4. Make lookup and completion read-only and require an explicit output file for export.
5. Test nested commands, invalid confirmation, hostile catalog data, and unchanged user files.

## Verification

- `python scripts/test_agent_command_help.py`
- `python scripts/agent-command-help.py --help`
