# SOU-136 membership lifetime evidence

Development is Draft. No native success is claimed before the focused Ubuntu
qualification completes on the exact candidate source.

- `local-development.json` records the passing macOS development checks and their
  platform limitations, exact subject/log hashes and corrected environment failures.
- `native-attempts.json` preserves unsuccessful native runs separately from any
  later candidate qualification. Full failed original-server ledgers are retained
  in the `attempt-*.json` files.
- `original-failure.json` preserves the original failed run and finite observations.
- The accepted-source regression overlay is
  `scripts/fixtures/sou136-accepted-open-regression.patch`. It keeps the accepted
  open-decision body unchanged and injects a real stale-proc open error at that
  boundary. Its expected failure is not an unmodified end-to-end replay.
- The focused native driver checkpoints all 159 planned attempts: 70 original
  cycles per server, 14 bounded peer segments, two restored-capacity cases and three
  separately identified resource/membership controls. A failed attempt cannot be
  replaced by a later pass.
- Local Python grader controls use constructed observations and mocks. macOS
  builds cannot establish Linux process, cgroup or pidfd behavior.

See the [English kernel argument](../../LINUX_BUDGET_PROCESS_LIFETIME.md) for the
bounded exit proof, identity/namespace checks, unchanged limits and exclusions.
The 147-case positive on `dfb6194` used sparse peer probes and was rejected by
review; it is retained as historical evidence, not current acceptance.

Native artifacts must retain exact source, binary, driver/config/profile hashes,
all attempted cycles, unexpected closures and independently graded cleanup.
