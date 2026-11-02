# Offline command discovery

The installable guided-pilot component includes `scripts/agent-command-help.py` and this guide. Use the helper from the verified installed component tree, alongside its `scripts/pilot.py` and `scripts/pilot_update.py`; no source checkout or separate script download is needed. The trusted digests remain explicit, as in the examples below.

Choose a reviewed installed component and its trusted SHA-256. Python discovery calls its parser factory; Rust discovery invokes only that binary with nested `--help`. Review and trust the component and its dependencies before selection. The audit hook detects common process/network operations during Python lookup; it is not a sandbox for arbitrary Python code.

```sh
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST list
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST topic provider update
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST --update-sha256 UPDATE_DIGEST topic update rollback
python3 -B agent-command-help.py --agentfw INSTALL/bin/agentfw --sha256 DIGEST list
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST completion --shell bash
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST completion --shell bash --context provider
```

Replace DIGEST with the trusted component hash. A changed component is refused. Python flags and required arguments come from argparse; Rust names and flags come from its help output. A maximum of 256 command nodes and eight Rust nesting levels is supported. The existing parser still owns confirmation and execution rules. Discovery never invokes a suggested operation.

Generate completion for `bash`, `zsh` or `fish`. The generated functions select the immediate command subtree from shell token arrays. After an option has been supplied, completion conservatively offers no further candidates rather than guessing private argument values. Candidates contain only validated public names and flags. Pass `--context` to export a fixed subtree; unknown contexts are refused. No profile, path, run ID, token or prompt value is used for completion.

To include delegated update operations, supply the trusted SHA-256 of the adjacent `pilot_update.py` as `--update-sha256`. Discovery captures its actual parser before argument parsing or execution. The catalog records both component hashes. Effect labels describe command behavior; the original command still enforces its confirmation and version binding requirements.

To save output without overwriting an existing file, use shell noclobber and a new private destination:

```sh
umask 077
set -C
python3 -B agent-command-help.py --pilot INSTALL/scripts/pilot.py --sha256 DIGEST completion --shell bash > NEW_COMPLETION_FILE
```

Review the file, then source it explicitly in Bash, or place it in a user-selected shell completion directory. No automatic installation or dotfile edit occurs. Zsh requires `compinit`; Fish uses its `complete` builtin. Rust catalogs register completion for `agentfw`; Python catalogs register for `pilot`.

Qualification uses Bash 5.x, Zsh 5.9 and Fish 3.7.0 on Ubuntu 24.04. The two additional shells are extracted from hash-pinned Ubuntu packages into a temporary directory; no package setup scripts or dotfiles are changed. Other versions are not qualified. Run `bash scripts/qualify-command-shells.sh` with `AGENTFW_TEST_BINARY` set to the selected built binary. Required shells must be present, so their absence fails qualification rather than silently satisfying acceptance.

The installed Python catalog is queried outside checkout and its generated completion is parsed by all three shells. The installed Rust tree is checked against actual nested help, lifecycle/edit/Ask arguments and missing-binding refusals. Discovery controls reject stale components, process launch, network lookup and file writes. These checks validate discovery and safe parser refusal; they do not claim that help lookup performs an edit, grants approval or exercises a provider.
