# Installed private-edit self-test evidence

The successful native Ubuntu run tested exact source
`b71084b7577d4d7d3a8de5f2cace4ac00bbc4598` (tree
`ddd418f9149ede6563650e94b75027e3d35d0b58`), outside the checkout with the genuine
pinned Claude binary and the owned scripted provider. The final evidence commit
adds reports and documentation only; it does not change the tested code.

- [Attempt 5 summary](native-attempt-05.json): eight of eight product cases and
  five of five installed qualification controls passed. Native Rust tests,
  Clippy and formatting passed. The downloaded artifact SHA-256 and all ZIP CRCs
  were independently checked, then the exact-source reports were validated.
- [Product report](native-attempt-05-report.json): useful create/replace/read,
  Ask reject/replay, both quota ceilings, exact Stop with a useful peer,
  stopped authority, combined owner/daemon loss and fresh recovery. All owned
  processes stopped, synthetic state was removed, and installed state,
  projects and unrelated sentinels were preserved.
- [Qualification report](native-attempt-05-qualification.json): installed
  identity, inert preview, foreign/tampered selection refusal, the genuine
  installed run and changed-helper refusal without fallback.
- [Independent review](review.json): bounded review findings and their fixes.
- [WSL attempt](wsl-attempt.json): the observed WSL2 environment could not start
  the later build because of `ERROR_NO_SYSTEM_RESOURCES`. This remains
  incomplete. Native success is not WSL qualification.

The [successful workflow](https://github.com/SoupTeam/soup-wall/actions/runs/40860696278)
is a focused development run. Final shared Ready CI, CodeQL, admission and merge
remain maintainer-owned.

## Preserved preceding attempts

| Attempt | Source | Outcome | Evidence |
| --- | --- | --- | --- |
| 1 | `20a8aa24` | Missing native rustfmt component; runtime not reached | [Summary](native-attempt-01.json) |
| 2 | `6c81eb1f` | Three cases passed; sampler treated a short-lived ancestry observation as cleanup failure | [Summary](native-attempt-02.json), [product report](native-attempt-02-report.json), [qualification](native-attempt-02-qualification.json) |
| 3 | `639553bc` | Create passed; replacement observation incomplete; cleanup and preservation passed | [Summary](native-attempt-03.json), [product report](native-attempt-03-report.json), [qualification](native-attempt-03-qualification.json) |
| 4 | `32ede21c` | Three cases passed; test confused native authorization with quota reservation | [Summary](native-attempt-04.json), [product report](native-attempt-04-report.json), [qualification](native-attempt-04-qualification.json) |

Original reports are retained with their original results and hashes. Later
corrections do not turn failed or incomplete attempts into passes. Reports
contain hashes, bounded counts and process identities, without private paths,
prompts, payloads, provider configuration or authority tokens. Hashes describe
the original artifact bytes; check Git blob bytes if checkout newline conversion
is enabled.
