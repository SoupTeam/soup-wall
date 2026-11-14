# Installed private-edit self-test evidence

Native Ubuntu and actual WSL2 Ubuntu 24.04 both passed eight of eight product
cases and five of five installed qualification controls on exact source
`23db5b6d55d62d6545dd7bee222e4a453f98ac6f` (tree
`16131804dc19067bf1b68f4368a4383e42c48a76`). Both runs invoked the installed
command outside the checkout with the genuine pinned Claude binary and an owned
scripted provider. The following evidence commit changes documentation only.

- [Native attempt 7 summary](native-attempt-07.json): eight of eight product cases and
  five of five installed qualification controls passed. Native Rust tests,
  Clippy and formatting passed. The downloaded artifact SHA-256 and all ZIP CRCs
  were independently checked, then the exact-source reports were validated.
- [Native product report](native-attempt-07-report.json): useful create/replace/read,
  Ask reject/replay, both quota ceilings, exact Stop with a useful peer,
  stopped authority, combined owner/daemon loss and fresh recovery. All owned
  processes stopped, synthetic state was removed, and installed state,
  projects and unrelated sentinels were preserved.
- [Native qualification report](native-attempt-07-qualification.json): installed
  identity, inert preview, foreign/tampered selection refusal, the genuine
  installed run and changed-helper refusal without fallback.
- [Independent review](review.json): bounded review findings and their fixes.
- [WSL attempt 3 summary](wsl-attempt-03.json): independent actual WSL2 success,
  with the original [8/8 product report](wsl-attempt-03-report.json),
  [5/5 qualification](wsl-attempt-03-qualification.json), and
  [source checks](wsl-attempt-03-source-checks.json).

Both runs passed 27 preparation, 34 helper, nine qualification-validator, six
component and three Rust CLI tests, agentfw Clippy across all targets, and Rust
formatting. The WSL preflight suite passed eight tests; its one non-WSL refusal
control is intentionally skipped on an actual WSL host.

WSL used an ordinary user, Linux ext4 inputs and outputs, and the existing
namespace/security settings. An explicitly authorized temporary global resource
cap of 4 GiB RAM and four CPUs allowed its VM to start. The temporary
configuration was removed and the originally stopped VM was stopped again; see
the [restoration record](wsl-host-restoration.json). This qualifies the tested
resource conditions, without a host security-policy change.

The [successful workflow](https://github.com/SoupTeam/soup-wall/actions/runs/40886850670)
is a focused development run. Final shared Ready CI, CodeQL, admission and merge
remain maintainer-owned.

## Preserved preceding attempts

| Attempt | Source | Outcome | Evidence |
| --- | --- | --- | --- |
| 1 | `20a8aa24` | Missing native rustfmt component; runtime not reached | [Summary](native-attempt-01.json) |
| 2 | `6c81eb1f` | Three cases passed; sampler treated a short-lived ancestry observation as cleanup failure | [Summary](native-attempt-02.json), [product report](native-attempt-02-report.json), [qualification](native-attempt-02-qualification.json) |
| 3 | `639553bc` | Create passed; replacement observation incomplete; cleanup and preservation passed | [Summary](native-attempt-03.json), [product report](native-attempt-03-report.json), [qualification](native-attempt-03-qualification.json) |
| 4 | `32ede21c` | Three cases passed; test confused native authorization with quota reservation | [Summary](native-attempt-04.json), [product report](native-attempt-04-report.json), [qualification](native-attempt-04-qualification.json) |

The earlier [native attempt 5](native-attempt-05.json) passed on `b71084b7`,
before explicit WSL support. [Native attempt 6](native-attempt-06.json) failed
before runtime because a fixture classified a lexical Python alias instead of
its canonical target. The [original WSL attempt](wsl-attempt.json) remains an
incomplete VM-startup failure. [WSL attempt 2](wsl-attempt-02.json) preserved a
safe refusal of the multiply linked Cargo build-output Agent, with its original
[product report](wsl-attempt-02-report.json),
[qualification](wsl-attempt-02-qualification.json), and
[source checks](wsl-attempt-02-source-checks.json).

The successful WSL run used separate single-link installed copies of the exact
built binaries and a fresh accepted preparation generation. No guard, policy,
quota or runtime deadline was weakened. The accepted edit route is the native
private-output API. Original filesystem/Git runtime pins are validated
separately; this does not establish mutations through those original servers or
whole-pilot qualification.

Original reports are retained with their original results and hashes. Later
corrections do not turn failed or incomplete attempts into passes. Reports
contain hashes, bounded counts and process identities, without private paths,
prompts, payloads, provider configuration or authority tokens. Hashes describe
the original artifact bytes; check Git blob bytes if checkout newline conversion
is enabled.
