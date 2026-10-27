# SOU-161 installed private-output edit qualification

Implementation and development qualification are in progress. No native host
acceptance or Ready-for-review result is claimed by this initial evidence entry.

The finite native qualification is `scripts/qualify-installed-edit.py`; it is
inert unless explicitly invoked with `--run`. Its registered Ubuntu job installs
exact bytes outside the checkout and runs with read-only source, private scratch
and a private network namespace. It uses genuine pinned Claude Code and an owned
scripted provider; no paid inference or customer data.

Failed native attempts, source/binary correlation and the eventual complete
report will be retained here after inspecting the actual artifact. Local
compiler/test failures are retained in isolated development scratch; they are
not counted as passed qualification. Final shared Ready/admission belongs to the
reviewer, as specified in Linear SOU-161.
