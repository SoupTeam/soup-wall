# SOU-13 source (candidate)

This folder holds the implementation, schemas, validators and tests for the SOU-13 family-held-out pilot. The
documentation is in [docs/benchmarks/sou13](../../docs/benchmarks/sou13/README.md). No dataset, label export,
review worksheet or sealed material is versioned here. The scoped [`.gitignore`](.gitignore) keeps local
copies out of Git.

| Path | Content |
| --- | --- |
| `sou13/`, `scripts/` | CP1 source; **frozen**, so every byte is pinned by the CP1 freeze |
| `sou13cp2/`, `scripts_cp2/` | CP2 taxonomy, semantics, splits, leakage, exports, freeze, anchor and handoff |
| `sou13gold/` | Versioned gold-label addenda: validation, drafting and the authorised gold development export (approved CP2 private v1 issued; not committed here) |
| `schema/` | Draft 2020-12 schemas |
| `tests/`, `tests_cp2/` | unittest suites; `_testsupport.py` gates tests on named private artifacts |
| `run_tests.py` | Exact test ledger for the public and private modes |

This folder is the project root for both frozen inventories. Do not add files to `sou13/` or `scripts/`, and
keep the source modules byte-identical to the frozen tree (`tests_cp2/test_freeze_inventory.py`).

```sh
python -m pip install -r eval/sou13/requirements-cp2.txt
python eval/sou13/run_tests.py
```
