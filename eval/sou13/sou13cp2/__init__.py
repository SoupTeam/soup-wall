"""SOU-13 Checkpoint 2, Phase 1: family taxonomy, leakage-safe split manifest, exports, coverage.

Lives OUTSIDE `sou13/` and `scripts/` on purpose: the Checkpoint 1 freeze hashes every file matching
`sou13/*.py` and `scripts/*.py`, so CP2 code must not touch them. CP1 modules are imported read-only."""
from pathlib import Path

VERSION = '0.4-cp2-phase1-draft'
ROOT = Path(__file__).resolve().parents[1]
