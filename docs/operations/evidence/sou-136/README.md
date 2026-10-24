# SOU-136 membership lifetime evidence

Development remains Draft for final source review/admission by the team lead.
The focused segmented Ubuntu qualification passed on
`eb4a520e9d97a675e83d9f70a358b41687ed4c7b`: **159 pass, 0 fail, 0 incomplete**,
70 filesystem + 70 Git crash/reconnect cycles, 14 bounded peer segments with
useful responses before and after every crash, two fresh restored-capacity
clients, real memory/PID-pressure and membership-violation controls. No unexpected
closures occurred; all owned processes/leaves and the delegation were removed.
The longest peer lifetime was 118234 ms within the unchanged 600000 ms limit.

- [native-qualified-report.json](native-qualified-report.json) retains every case,
  exact source/runtime/driver/config/profile hashes and finite independent observations.
- [native-qualified-receipt.json](native-qualified-receipt.json) records independent
  regrading, artifact identity, all 14 peer bounds and non-document Git blobs.
  Later evidence-only commits do not pretend to be a newly executed source.
- The `sou136-before-regression.*` and `sou136-after-regression.log` files retain
  the expected real-kernel ESRCH refusal on the accepted decision and 23 passing
  Linux budget tests. The explicit delegated membership control is run separately
  among the 159 cases. Strict Linux agentfw all-target clippy passed.
- The candidate/runtime identity text files contain only build artifact hashes.

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
