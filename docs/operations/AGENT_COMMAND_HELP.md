# Offline command discovery

Choose a reviewed installed component and its trusted SHA-256. Python discovery calls its parser factory; Rust discovery invokes only that binary with nested `--help`. Review and trust the component and its dependencies before selection. The audit hook detects common process/network operations during Python lookup; it is not a sandbox for arbitrary Python code.

```sh
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST list
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST topic provider update
python3 -B agent-command-help.py --agentfw INSTALL/bin/agentfw --sha256 DIGEST list
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST completion --shell bash
```

Replace DIGEST with the trusted component hash. A changed component is refused. Python flags and required arguments come from argparse; Rust names and flags come from its help output. A maximum of 256 command nodes and eight Rust nesting levels is supported. The existing parser still owns confirmation and execution rules. Discovery never invokes a suggested operation.

Generate completion for `bash`, `zsh` or `fish`. Candidates contain only validated public names and flags. Bash/Zsh completion currently offers the bounded public vocabulary; it does not infer argument values or enumerate local state. Fish uses separate command and option declarations.

To save output without overwriting an existing file, use shell noclobber and a new private destination:

```sh
umask 077
set -C
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST completion --shell bash > NEW_COMPLETION_FILE
```

Review the file, then source it explicitly in Bash, or place it in a user-selected shell completion directory. No automatic installation or dotfile edit occurs. Zsh requires `compinit`; Fish uses its `complete` builtin. Native shell parsing and the installed Rust binary remain pending qualification. Existing tests cover a synthetic installed Python parser, stale digest and attempted child execution; the accepted pilot parser was also queried locally.
