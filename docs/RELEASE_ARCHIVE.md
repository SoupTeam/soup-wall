# Use a downloaded Soup Wall binary archive

This is the offline operator entry point for the four public archive targets:
Linux x86_64 GNU, macOS Apple Silicon, macOS Intel, and Windows x86_64 MSVC.
Read the release's external `SHA256SUMS` before extraction. The included
`release-docs.json` records the source commit, target and staged file hashes;
it is an integrity inventory, not an independent signature or release approval.

## Run the included programs

Open a terminal **inside the extracted archive directory**. On Linux/macOS:

```sh
./llm-firewall preflight
./agentfw preflight
```

On native Windows PowerShell:

```powershell
.\llm-firewall.exe preflight
.\agentfw.exe preflight
```

Gateway preflight reads the included `firewall.yaml` and
`policies/default.yaml`; it opens no listener and makes no provider request.
Agent preflight diagnoses the current user installation and may report that
the Agent has not been installed or started. Extraction alone does not install
or activate protection. `soup-wall-gateway` is an alias of `llm-firewall`;
`soup-wall-bench` is also included. Windows names end in `.exe`.

For a local Agent, run `./agentfw install` followed by `./agentfw serve`
(PowerShell: `.\agentfw.exe install`, `.\agentfw.exe serve`). Apply the hook
configuration and token instructions printed by `install` to your own host.
The default is **shadow mode**. The Claude Code hook fails open when the daemon
is unavailable. Confirm installation, mode and host integration before relying
on enforcement. Read the [lifecycle guide](operations/AGENT_LIFECYCLE.md),
[Windows installation guide](operations/WINDOWS_AGENT_ACCEPTANCE.md), and
[security boundary](../SECURITY.md).

Start the local Gateway with `./llm-firewall` or `.\llm-firewall.exe` after
preflight succeeds. Defaults bind to `127.0.0.1:8080`; model requests contact
the configured provider and can incur charges. See [self-hosting](SELF_HOSTING.md),
[upgrades and rollback](UPGRADING.md), and the
[production runbook](operations/PRODUCTION_RUNBOOK.md).

## Offline guides and separately required assets

The [product README](../README.md), [canonical guide index](README.md), and
the public operator guides are included. Local images and heading links work
after extraction. The canonical
sources remain editable in the source repository; only deterministic link
adaptation and an archive-context note are applied to their archive copies.
CI, benchmark, historical evidence and implementation references use online
URLs pinned to the exact source commit. Those references, external
vendor documentation and badges require a network.

Examples that invoke Cargo, `target/release/`, Python under `scripts/`, Compose
under `deploy/`, or other source paths are **source-checkout procedures**, not
commands supplied by this binary archive. Use the root executables above for
archive operation. Procedure guides explain what additional assets they need;
their presence does not mean that those assets are packaged or qualified here.

In particular, the [Linux pilot walkthrough](operations/PILOT_QUICKSTART.md)
documents source preparation. The Linux archive also supplies a same-source
Git launcher, verified pilot component and v2 binary/source receipts. Follow the
[installed front door](operations/PILOT_INSTALLED_FRONT_DOOR.md) to install the
bundled component and select `--candidate-receipt` without a checkout, Cargo or
libtest. Original MCP servers, Python/Node dependencies, Claude Code and pinned
native Git/bubblewrap remain separately declared prerequisites. The
supported pilot is native Ubuntu 24.04 x86_64. A Linux archive running in WSL
does not establish supported-pilot acceptance. macOS and native Windows are
outside that two-server Linux pilot; Windows has its separate
[onboarding workflow](operations/WINDOWS_ONBOARDING.md), and macOS has its
[launchd lifecycle](operations/AGENT_LAUNCHD.md). Model weights, provider
credentials, customer identity configuration and private evidence are excluded.

Keep [LICENSE](../LICENSE), [NOTICE](../NOTICE), the bundled
[cryptography notice](../vendor/kryptering/LICENSE), and
[source attribution guidance](PROVENANCE.md) with redistributed materials.
The archive documentation check does not certify optional runtime assets,
license clearance, native execution on another platform or live-model efficacy.

## Verify packaging locally without publication

From a clean source checkout, supply a directory containing your four built
programs (including the Gateway alias), `firewall.yaml`, `policies/default.yaml`,
`LICENSE`, `NOTICE`, `README.md` and `third-party/kryptering/LICENSE` exactly as
the existing release workflow stages them. Then run:

```sh
commit=$(git rev-parse HEAD)
# Linux only: after the existing release build with Rust 1.99.1.
python3 -B scripts/linux_candidate.py stage --directory "$stage" \
  --binaries target/x86_64-unknown-linux-gnu/release --expected-commit "$commit"
python3 -B scripts/release_docs.py stage --directory "$stage" \
  --expected-commit "$commit" --target x86_64-unknown-linux-gnu
tar --format=ustar -czf "$archive" -C "$(dirname "$stage")" "$(basename "$stage")"
python3 -B scripts/release_docs.py check-archive --archive "$archive" \
  --archive-root "$(basename "$stage")" --expected-commit "$commit" \
  --target x86_64-unknown-linux-gnu
```

The focused `linux-candidate` option of the existing Real filesystem MCP workflow
builds this release lane, checks the existing publication-readiness archive
binding, extracts into an owned fresh directory and qualifies the installed
frozen `linux-v1` pilot with public fixtures and a scripted provider. It creates
no tag, release or image and does not claim final publication readiness. TL owns
the final reviewed source's Ready matrix, CodeQL and candidate admission.

For macOS, omit the Linux-only pilot staging step and use the matching target
for its tar archive. Windows uses
`x86_64-pc-windows-msvc`, `.exe` names and the existing `7z a -tzip` step.
The same bounded checker extracts and verifies all four target formats without
executing their binaries. A local all-target structure regression is:

```sh
python3 -B -m unittest discover -s scripts/tests -p test_release_docs.py -v
```

The explicit input list and canonical LF Markdown/SVG text hashes live in
`deploy/release-docs-manifest.json`. Intentional source-guide edits require a
reviewed `python3 scripts/release_docs.py refresh-manifest` update; this changes
hashes and classified references only, never adds new bundled documents.
Missing or stale hashes fail the staging check.
The contract's digest uses canonical parsed JSON, so clean LF and CRLF
checkouts verify the same inventory.
The checker rejects undeclared omissions, changed hashes, unsafe archive paths,
links, duplicates, case collisions, missing assets and broken local anchors.
It neither downloads dependencies nor creates a release, tag or registry push.
