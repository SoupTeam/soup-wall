# Shared VPS CI

`VPS CI` is a supplemental lane on the team's existing Windows Server 2025 host.
One **organization-scoped** runner serves SoupZero, Soup Wall and Soup R&D, so
GitHub serializes their jobs on one worker. The previous SoupZero-only runner
cannot accept jobs from this repository. Merely copying its label is insufficient.
Do not run a second worker concurrently on this host.

The host keeps the existing `D:\CI` bootstrap, NETWORK SERVICE identity, Python,
Rust/MSVC, caches and owned `SoupZero-CI-Linux` WSL distro. Organization migration
is an operator action; the repository workflow does not reinstall Windows tools,
register services, change execution policy, or grant administrator privileges.

## Activate after host migration and review

The organization runner group must include only `SoupTeam/SoupZero`,
`SoupTeam/soup-wall` and `SoupTeam/soup-rnd`, with public repositories explicitly
enabled. Its single worker needs the default Windows/X64 labels plus `soup-vps`
and the existing `soupzero-ci` compatibility label. Keep it quarantined from all
repositories while migrating the service; verify the service account/environment
before enabling access. Public fork workflows must require maintainer approval;
the new lane itself never runs on a PR, fork, arbitrary ref or public PR artifact.

After the runner is online, human review is complete and this workflow is on main:

```sh
gh variable set SOUP_VPS_CI_ENABLED --repo SoupTeam/soup-wall --body true
gh workflow run vps-ci.yml --repo SoupTeam/soup-wall --ref main -f suite=smoke
gh workflow run vps-ci.yml --repo SoupTeam/soup-wall --ref main -f suite=full
gh run list --repo SoupTeam/soup-wall --workflow vps-ci.yml --limit 5
```

An absent/false activation variable skips the lane before allocating a runner.
A skipped result is not executed acceptance. To disable future starts, remove
the variable; this does not cancel work already running.

## Scope and resources

- **Push to main:** native Windows build of the actual Agent/Gateway, Agent CLI,
  adapter tests, and the existing owned-loopback Gateway acceptance. This is
  smoke evidence, following the main cost policy; it is not full qualification.
- **Manual `suite=full`:** default-feature formatting/Clippy and Windows workspace
  tests, then the complete existing Python driver/benchmark suites and docs check
  in the owned Linux distro. Windows Rust fixtures retain their own Windows
  Python venv on PATH; the POSIX suite uses a separate disposable Linux venv.
- **Existing hosted CI:** remains responsible for PR qualification, all features,
  native Linux/macOS, Windows ACL/standard-user acceptance, containers/services,
  managed CodeQL and release gates. Neither VPS mode replaces those checks.

The source is the event's fixed main SHA, checked against the clean initial
checkout. Unmerged branches cannot select this lane. Cargo compilation and test
parallelism are two. Cache is outside checkout under
`D:\CI\cache\ecosystem\soup-wall\cargo-target`; no GitHub cache action prunes
shared Rustup binaries. The 90-minute bound starts at job allocation, not queue
creation. Queue order is controlled by GitHub's single worker, not by a
cross-repository `concurrency` key.

Windows fixture dependencies use the existing driver pins; Linux adds only
missing git/python3-venv/openssl packages inside the owned distro. Python venvs
and checkout copies are isolated from product environments. No model, dataset,
provider credential, release secret or signing configuration is required.

## Evidence and compatibility

Artifacts include source/tree/runner identity, scope, native logs and nested
Linux step/count reports, retained for 14 days. Venvs and caches are excluded.
Linux passes/skips are distinct from Windows results; zero executed passing
unittest cases refuse success. The owned distro is stopped in normal and error
cleanup, without global WSL shutdown or affecting another distro.

This main/manual-only workflow is explicitly outside the SOU-91 PR registration
inventory. Its source-contract test rejects a later PR trigger unless that
integration is redesigned. `.github/` changes still select full existing PR
qualification. The SOU-91 activation variable, ruleset, required checks, CodeQL
thresholds and application runtime admission remain unchanged.

The WSL transport retains the SoupZero CI ownership contract from its runner
setup; the driver runner and strict result parser were prepared for this shared
host. Historical probe results keep their original source/control SHAs and do
not establish execution of a later repository head. A repo-owned VPS run after
activation is still required to demonstrate final routing and current-source
execution.
