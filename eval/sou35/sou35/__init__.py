"""SOU-35: fresh family-held-out synthetic tool-call dataset (Day 1 scaffold, draft).

Reuses the frozen SOU-13 CP2 interpreter and helpers by import only. Nothing under eval/sou13 is modified.
The custody guard runs before eval/sou13 is put on sys.path, so no sou13cp2 module can be imported from a
checkout that holds the consumed sealed test."""
import sys
from pathlib import Path

from . import guard

VERSION = '0.1-sou35-day1-draft'
DATASET_VERSION = '0.1-sou35-candidate'
ROOT = Path(__file__).resolve().parents[1]
SOU13_ROOT = ROOT.parent / 'sou13'

guard.check(SOU13_ROOT)
if str(SOU13_ROOT) not in sys.path:
    sys.path.insert(0, str(SOU13_ROOT))
