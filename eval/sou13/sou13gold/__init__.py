# SPDX-License-Identifier: Apache-2.0
"""SOU-13 versioned gold-label addenda: validation and a read-only gold view.

Kept outside `sou13/` and `scripts/` (CP1 freeze globs) and outside the hash-pinned CP2 tools. It reads
exported development label rows and never modifies frozen records, exports or manifests. No addendum has been
issued; this package is the interface a future, separately approved addendum must satisfy."""
