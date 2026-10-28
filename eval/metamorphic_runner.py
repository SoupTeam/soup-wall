# SPDX-License-Identifier: Apache-2.0
"""SOU-128 metamorphic contract gate, built on the accepted evaluator (stdlib only).

Every case is evaluated by eval_runner.evaluate_case(); this module adds only what the
evaluator cannot express:
  * relations between the outcomes of related cases (an original against each transformed case),
  * the same corpus through the existing classifier worker framing (sw-classifier-worker/1),
  * raw-byte parsing-boundary probes and worker frame probes,
  * re-verification of every cited source by sha256 before any assertion is trusted.

Modes are kept separate. "direct" calls classify() in-process, as eval_runner does. "worker" runs the
daemon's own WORKER_BOOTSTRAP text (read from crates/agentfw/src/classifier_runtime/worker.rs) under
that file's REQUEST/START deadlines. It is driven by this harness, not by the Rust daemon, so it is
not native policy, not original-server execution and not production MCP admission. Case labels stay
pending; only source-backed relations are asserted.

Exit codes: 0 = every executed assertion passed; 1 = an assertion, probe or mode-parity check failed;
            2 = an unexpected technical error; 3 = invalid input, source drift or usage error.

usage:
  python3 eval/metamorphic_runner.py [--corpus F] [--relations F] [--modes direct,worker]
      [--classifier generic=PATH] [--classifier git=PATH] [--out-dir DIR]
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import platform
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.dont_write_bytecode = True
import eval_runner as ER  # noqa: E402  (the accepted evaluator; never modified here)

CORPUS = ROOT / "eval/fixtures/sou128_metamorphic_dev_v0.4.json"
RELATIONS = ROOT / "eval/fixtures/sou128_relations_v0.4.json"
CLASSIFIERS = {"generic": ROOT / "rule_baseline/rule_baseline.py",
               "git": ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"}
WORKER_PY = ROOT / "rule_baseline/runtime/worker.py"
WORKER_RS = ROOT / "crates/agentfw/src/classifier_runtime/worker.rs"
PROTOCOL = "sw-classifier-worker/1"
RISKY = {"write", "delete", "send_data", "change_permissions"}
KINDS = {"equal_outcome": 2, "metadata_invariant": 2, "preserve_risk_mark_unknown": 2,
         "no_silent_loss_past_bound": 2, "technical_failure_channel": 1, "observe": None}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@functools.lru_cache(maxsize=None)  # a few files are cited many times per run
def source_sha256(rel: str) -> str | None:
    """Identity of a repository source: sha256 of its committed blob, on every platform.

    A Windows core.autocrlf working copy holds different bytes from the LF blob a Linux checkout holds,
    so raw disk bytes are not a portable identity. The blob is used only when the working copy has no
    content change (git diff accounts for line-ending conversion); otherwise, or outside a git checkout,
    the bytes on disk are hashed, which then differ from any committed citation and are reported as drift.
    """
    path = ROOT / rel
    if not path.is_file():
        return None
    try:
        clean = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", rel], capture_output=True, timeout=60)
        if clean.returncode == 0:
            blob = subprocess.run(["git", "-C", str(ROOT), "cat-file", "blob", f"HEAD:{rel}"], capture_output=True, timeout=60)
            if blob.returncode == 0:
                return sha256(blob.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    return sha256(path.read_bytes())


def expand(payload: dict) -> bytes:
    """Exact probe bytes: hex, optionally followed by fill_hex * fill_count and suffix_hex."""
    return (bytes.fromhex(payload["hex"]) + bytes.fromhex(payload.get("fill_hex", "")) * payload.get("fill_count", 0)
            + bytes.fromhex(payload.get("suffix_hex", "")))


def wire(event: Any) -> bytes:
    """Semantic input bytes with member order as given (the daemon itself re-serializes; see the audit)."""
    return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- classifier modes
def direct_classifier(path: Path) -> Callable[[Any], Any]:
    """Execute the classifier bytes under a non-main name, as the worker bootstrap does."""
    space = {"__name__": "sou128_direct_classifier", "__file__": path.name}
    exec(compile(path.read_bytes(), path.name, "exec"), space)  # noqa: S102 - the classifier under test
    return space["classify"]


def bootstrap_source() -> tuple[str, dict]:
    text = WORKER_RS.read_text(encoding="utf-8")
    match = re.search(r'^const WORKER_BOOTSTRAP: &str = r#"(.*?)^"#;$', text, re.S | re.M)
    deadlines = {name: int(ms) for name, ms in re.findall(
        r"^(?:pub )?const (REQUEST_DEADLINE|START_DEADLINE): Duration = Duration::from_millis\((\d+)\);$", text, re.M)}
    if not match or set(deadlines) != {"REQUEST_DEADLINE", "START_DEADLINE"}:
        raise ValueError("worker bootstrap or deadlines not found in " + WORKER_RS.relative_to(ROOT).as_posix())
    return match.group(1), deadlines


class Worker:
    """One persistent worker process running the accepted framing over an exact copy of the classifier."""

    def __init__(self, classifier: Path):
        self.code, self.deadlines = bootstrap_source()
        self.dir = Path(tempfile.mkdtemp(prefix="sou128-worker-"))
        shutil.copyfile(classifier, self.dir / "rule_baseline.py")
        shutil.copyfile(WORKER_PY, self.dir / "worker.py")
        self.classifier_sha = sha256((self.dir / "rule_baseline.py").read_bytes())
        self.worker_sha = sha256((self.dir / "worker.py").read_bytes())
        self.proc, self.next_id, self.restarts, self.timeouts, self.protocol_errors = None, 0, 0, 0, 0

    def _start(self) -> None:
        self.proc = subprocess.Popen([sys.executable, "-I", "-c", self.code, str(self.dir), self.classifier_sha, self.worker_sha],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, args=(self.proc, self.lines), daemon=True).start()
        ready = self._line(self.deadlines["START_DEADLINE"])
        if ready != {"v": PROTOCOL, "ready": True, "classifier_sha256": self.classifier_sha}:
            raise RuntimeError(f"worker ready frame invalid: {ready!r}")

    @staticmethod
    def _read(proc, lines) -> None:
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    def _line(self, deadline_ms: int):
        try:
            line = self.lines.get(timeout=deadline_ms / 1000)
        except queue.Empty:
            return "timeout"
        return None if line is None else json.loads(line.decode("utf-8"))

    def classify_bytes(self, payload: bytes) -> Any:
        if self.proc is None or self.proc.poll() is not None:
            if self.proc is not None:
                self.restarts += 1
            self._start()
        self.next_id += 1
        request = {"v": PROTOCOL, "id": self.next_id, "input_sha256": sha256(payload),
                   "input_json": payload.decode("utf-8")}
        self.proc.stdin.write(json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        self.proc.stdin.flush()
        reply = self._line(self.deadlines["REQUEST_DEADLINE"])
        if reply == "timeout":
            # The daemon's deadline elapsed: an explicit classifier_timeout envelope, never a classification.
            self.timeouts += 1
            self.stop()
            return {"status": "error", "actions": [], "unknown": True,
                    "failure": {"code": "classifier_timeout", "detail": "worker reply exceeded REQUEST_DEADLINE"}}
        if (not isinstance(reply, dict) or reply.get("v") != PROTOCOL or reply.get("id") != self.next_id
                or reply.get("input_sha256") != request["input_sha256"] or not isinstance(reply.get("result_json"), str)):
            raise RuntimeError(f"worker reply not bound to the request: {reply!r}")
        return json.loads(reply["result_json"])

    def classify(self, event: Any) -> Any:
        try:
            return self.classify_bytes(wire(event))
        except (RuntimeError, ValueError, OSError):
            # Framing or process failure: counted separately, then surfaced as a technical error.
            self.protocol_errors += 1
            self.stop()
            raise

    def raw_frame(self, frame: bytes) -> dict:
        """A fresh process receives one raw frame line; report replies and exit status."""
        self.stop()
        self._start()
        self.proc.stdin.write(frame + b"\n")
        self.proc.stdin.close()
        replies = []
        while True:
            line = self._line(self.deadlines["REQUEST_DEADLINE"])
            if line is None or line == "timeout":
                break
            replies.append(line)
        try:
            code = self.proc.wait(timeout=self.deadlines["REQUEST_DEADLINE"] / 1000)
        except subprocess.TimeoutExpired:
            code = "timeout"
        self.stop()
        return {"replies": len(replies), "exit_code": code}

    def stop(self) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait()
            for stream in (self.proc.stdin, self.proc.stdout):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
            self.proc = None

    def close(self) -> None:
        self.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


def single_shot(classifier: Path, payload: bytes, deadline_ms: int) -> Any:
    try:
        done = subprocess.run([sys.executable, "-I", str(classifier)], input=payload + b"\n", capture_output=True,
                              timeout=deadline_ms / 1000 * 10)
    except subprocess.TimeoutExpired:
        return {"status": "error", "failure": {"code": "classifier_timeout", "detail": "single-shot process timed out"}}
    lines = done.stdout.decode("utf-8", "replace").splitlines()
    return json.loads(lines[0]) if len(lines) == 1 else {"invalid_single_shot_output": lines[:3], "exit_code": done.returncode}


# ---------------------------------------------------------------- relations
def outcome(rec: dict) -> tuple:
    if rec["technical_error"] is not None:
        return ("technical_failure", rec["failure_channel"])
    return ("classification", rec["predicted_status"], tuple(rec["predicted_actions"]), rec["predicted_unknown"])


def judge(rel: dict, recs: list[dict]) -> tuple[str, str]:
    kind = rel["kind"]
    outs = [outcome(r) for r in recs]
    if kind == "observe":
        return "observed", "recorded only"
    if kind == "technical_failure_channel":
        o = outs[0]
        if o[0] == "classification":
            return "fail", "masked as a classification instead of a technical failure"
        return ("pass", f"channel {o[1]}") if o[1] in ER.FAILURE_CODES else ("fail", f"channel not established: {o[1]}")
    if any(o[0] == "technical_failure" for o in outs) and kind != "no_silent_loss_past_bound":
        return "fail", "technical failure on a case that must classify: " + ", ".join(str(o[1]) for o in outs if o[0] != "classification")
    a, b = outs
    if kind == "equal_outcome":
        return ("pass", "equal") if a == b else ("fail", f"{a} != {b}")
    if kind == "metadata_invariant":
        return ("pass", "actions and unknown unchanged") if a[2:] == b[2:] else ("fail", f"description changed {a[2:]} -> {b[2:]}")
    if kind == "preserve_risk_mark_unknown":
        risky = set(a[2]) & RISKY
        if not risky:
            return "fail", "inconclusive: the source shows no risky action to preserve"
        if not risky <= set(b[2]):
            return "fail", f"risky actions lost: {sorted(risky - set(b[2]))}"
        return ("pass", "risk kept, unknown set") if b[3] is True else ("fail", "unknown component added but unknown is false")
    if kind == "no_silent_loss_past_bound":
        if a[0] != "classification":
            return "fail", "the within-bound source did not classify"
        if b[0] == "technical_failure":
            return ("pass", f"technical failure {b[1]}") if b[1] in ER.FAILURE_CODES else ("fail", f"unestablished channel {b[1]}")
        if b[3] is True or set(a[2]) <= set(b[2]):
            return "pass", "uncertainty added or actions kept"
        return "fail", f"certain result with fewer actions past the bound: {a[2]} -> {b[2]}"
    raise ValueError(kind)


# ---------------------------------------------------------------- validation and provenance
def validate(corpus: dict, rels: dict) -> list[str]:
    errs = ER.validate_fixture(corpus, CORPUS.name)
    cases = {c["id"]: c for c in corpus.get("cases", []) if isinstance(c, dict)}
    if rels.get("format") != "sou128-relations/1" or rels.get("corpus") != corpus.get("fixture_version"):
        errs.append("relations file does not belong to this corpus")
    seen = set()
    for r in rels.get("relations", []):
        if r["id"] in seen:
            errs.append(f"duplicate relation id {r['id']}")
        seen.add(r["id"])
        if r["kind"] not in KINDS:
            errs.append(f"{r['id']}: unknown kind {r['kind']}")
            continue
        if KINDS[r["kind"]] is not None and len(r["members"]) != KINDS[r["kind"]]:
            errs.append(f"{r['id']}: {r['kind']} needs {KINDS[r['kind']]} members")
        if any(m not in cases for m in r["members"]):
            errs.append(f"{r['id']}: unknown member")
        elif len({cases[m]["evaluator_only"]["classifier"] for m in r["members"]}) != 1:
            errs.append(f"{r['id']}: members use different classifiers")
        if r["kind"] != "observe" and not r.get("sources"):
            errs.append(f"{r['id']}: an asserted relation needs a source")
    for c in cases.values():
        if c["expectation_status"] != "pending":
            errs.append(f"{c['id']}: this development corpus promotes no label; expectation_status must stay pending")
        if c["evaluator_only"].get("classifier") not in CLASSIFIERS:
            errs.append(f"{c['id']}: unknown classifier")
    return errs


def source_drift(rels: dict) -> list[str]:
    drift = []
    cited = [s for r in rels["relations"] for s in r["sources"]]
    cited += [s for p in rels["boundary_probes"] + rels["worker_frame_probes"] for s in p["sources"]]
    for s in cited:
        if s.get("sha256") is None:
            continue  # an external standard (e.g. RFC 8259), cited by name only
        path = ROOT / s["path"]
        actual = source_sha256(s["path"])
        if actual != s["sha256"]:
            drift.append(f"{s['path']}: cited {s['sha256']}, now {actual}")
    return sorted(set(drift))


# ---------------------------------------------------------------- run
CANDIDATE_BLOCKER = ("The SOU-97 candidate (rule_baseline/pilot_readonly_v1/rule_baseline.py, pilot_readonly_v1.1) exists only "
                     "in unmerged Draft PR #213. It is not imported, and no other classifier is substituted for it. Select an "
                     "explicit file with --candidate NAME=PATH once a reviewed candidate is available on the base branch.")


def identity(classifiers: dict[str, Path]) -> dict:
    out = {}
    for k, p in sorted(classifiers.items()):
        inside = p.resolve().is_relative_to(ROOT)
        rel = p.resolve().relative_to(ROOT).as_posix() if inside else p.name
        out[k] = {"path": rel, "sha256": source_sha256(rel) if inside else sha256(p.read_bytes())}
    return out


def evaluate_set(cases: list[dict], rels: dict, modes: list[str], classifiers: dict[str, Path]) -> tuple[dict, dict, int]:
    """Evaluate one classifier selection in each mode: case records, relations and accounting."""
    failure_members = {m for r in rels["relations"] if r["kind"] == "technical_failure_channel" for m in r["members"]}
    status, out, outcomes = 0, {}, {}
    for mode in modes:
        workers = {}
        try:
            if mode == "direct":
                fns = {k: direct_classifier(p) for k, p in classifiers.items()}
            else:
                workers = {k: Worker(p) for k, p in classifiers.items()}
                fns = {k: w.classify for k, w in workers.items()}
            recs = [ER.evaluate_case(c, fns[c["evaluator_only"]["classifier"]], mode) for c in cases]
        finally:
            stats = {k: {"restarts": w.restarts, "timeouts": w.timeouts, "protocol_errors": w.protocol_errors}
                     for k, w in workers.items()}
            for w in workers.values():
                w.close()
        rec_by_id = {r["id"]: r for r in recs}
        outcomes[mode] = {r["id"]: outcome(r) for r in recs}
        results = []
        for rel in rels["relations"]:
            verdict, why = judge(rel, [rec_by_id[m] for m in rel["members"]])
            outs = [outcome(rec_by_id[m]) for m in rel["members"]]
            results.append({"id": rel["id"], "kind": rel["kind"], "verdict": verdict, "detail": why,
                            "review_status": rel["review_status"],
                            # An equality between abstentions holds but shows nothing about classification.
                            "informative": verdict != "pass" or not all(o[0] == "classification" and o[3] and not o[2] for o in outs),
                            "members": [[m, list(o)] for m, o in zip(rel["members"], outs)]})
        unexpected = [{"id": r["id"], "error": r["technical_error"]} for r in recs
                      if r["technical_error"] is not None and r["id"] not in failure_members]
        tally = {k: sum(1 for x in results if x["verdict"] == k) for k in ("pass", "fail", "observed")}
        tally["pass_vacuous"] = sum(1 for x in results if x["verdict"] == "pass" and not x["informative"])
        by_kind = {}
        for x in results:
            row = by_kind.setdefault(x["kind"], {"pass": 0, "pass_vacuous": 0, "fail": 0, "observed": 0})
            row[x["verdict"]] += 1
            row["pass_vacuous"] += x["verdict"] == "pass" and not x["informative"]
        out[mode] = {"relations": results, "tally": tally, "by_kind": dict(sorted(by_kind.items())),
                     "unexpected_technical_errors": unexpected, "worker_stats": stats,
                     "accounting": accounting(recs, results, failure_members, stats),
                     "evaluator_overall": ER.summarize(recs)["overall"],
                     "cases": {r["id"]: list(outcome(r)) for r in recs}}
        if tally["fail"]:
            status = max(status, 1)
        if unexpected or any(s["protocol_errors"] for s in stats.values()):
            status = max(status, 2)
    return out, outcomes, status


def parity(outcomes: dict) -> dict:
    first, *rest = outcomes
    ids = outcomes[first]
    return {"compared": list(outcomes),
            "divergent_cases": sorted(c for c in ids for m in rest if outcomes[m][c] != outcomes[first][c])}


def accounting(recs: list[dict], results: list[dict], failure_members: set, stats: dict) -> dict:
    """Exact counts with denominators. Losses are relative to the observed source case, never to a label."""
    classified = [r for r in recs if r["technical_error"] is None]
    technical = [r for r in recs if r["technical_error"] is not None]
    channels = {}
    for r in technical:
        key = ("expected" if r["id"] in failure_members else "unexpected") + ":" + str(r["failure_channel"])
        channels[key] = channels.get(key, 0) + 1
    pairs = [x for x in results if len(x["members"]) == 2]
    both = [x for x in pairs if all(o[0] == "classification" for _, o in x["members"])]
    losses = []
    for x in both:
        (a_id, a), (b_id, b) = x["members"]
        lost = sorted(set(a[2]) - set(b[2]))
        if lost:
            losses.append({"relation": x["id"], "kind": x["kind"], "source": a_id, "variant": b_id, "lost": lost,
                           "risky_lost": sorted(set(lost) & RISKY), "variant_unknown": b[3], "verdict": x["verdict"],
                           "uncertainty_added": b[3] is True and a[3] is not True})
    return {
        "labels": {"scored": sum(r["expectation_status"] in ER.SCORED for r in recs),
                   "pending": sum(r["expectation_status"] == "pending" for r in recs),
                   "note": "no label is reviewed ground truth; label-relative misses are not computed"},
        "cases": {"total": len(recs), "classified": len(classified),
                  "certain_actions": sum(1 for r in classified if not r["predicted_unknown"] and r["predicted_actions"]),
                  "proven_noop": sum(1 for r in classified if not r["predicted_unknown"] and not r["predicted_actions"]),
                  "partial_unknown": sum(1 for r in classified if r["predicted_unknown"] and r["predicted_actions"]),
                  "abstention": sum(1 for r in classified if r["predicted_unknown"] and not r["predicted_actions"]),
                  "technical_failure": len(technical), "technical_failure_by_channel": dict(sorted(channels.items()))},
        "protocol_errors": sum(s.get("protocol_errors", 0) for s in stats.values()),
        "timeouts": sum(s.get("timeouts", 0) for s in stats.values()),
        "relation_pairs": {"total": len(pairs), "both_classified": len(both), "with_technical_member": len(pairs) - len(both),
                           "known_action_losses": losses,
                           "known_action_losses_without_uncertainty": [l for l in losses if not l["variant_unknown"]],
                           "risky_action_losses": [l for l in losses if l["risky_lost"]]},
    }


def compare(base: dict, cand: dict, base_mode: dict, cand_mode: dict) -> dict:
    """Baseline vs explicitly selected candidate, case by case and relation by relation (no labels)."""
    changed = []
    for cid in base:
        a, b = base[cid], cand[cid]
        if a == b:
            continue
        row = {"case": cid, "baseline": list(a), "candidate": list(b)}
        if a[0] == b[0] == "classification":
            row.update(lost=sorted(set(a[2]) - set(b[2])), gained=sorted(set(b[2]) - set(a[2])),
                       risky_lost=sorted((set(a[2]) - set(b[2])) & RISKY), unknown=[a[3], b[3]])
        changed.append(row)
    verdicts = {x["id"]: x["verdict"] for x in base_mode["relations"]}
    moved = [{"relation": x["id"], "baseline": verdicts[x["id"]], "candidate": x["verdict"], "detail": x["detail"]}
             for x in cand_mode["relations"] if x["verdict"] != verdicts[x["id"]]]
    return {"cases_compared": len(base), "cases_changed": changed, "risky_losses": [c for c in changed if c.get("risky_lost")],
            "relation_changes": moved, "relation_regressions": [m for m in moved if m["candidate"] == "fail"]}


def run(corpus_path: Path, relations_path: Path, modes: list[str], classifiers: dict[str, Path],
        candidate: dict[str, Path] | None = None) -> tuple[dict, int]:
    corpus_raw, rels_raw = corpus_path.read_bytes(), relations_path.read_bytes()
    corpus, rels = json.loads(corpus_raw), json.loads(rels_raw)
    errors = validate(corpus, rels) + source_drift(rels)
    bootstrap, deadlines = bootstrap_source()
    report: dict[str, Any] = {
        "format": "sou128-metamorphic-report/1",
        "identities": {
            "corpus": {"path": corpus_path.name, "sha256": sha256(corpus_raw), "fixture_version": corpus.get("fixture_version")},
            "relations": {"path": relations_path.name, "sha256": sha256(rels_raw)},
            "eval_runner_sha256": source_sha256("eval/eval_runner.py"),
            "metamorphic_runner_sha256": source_sha256("eval/metamorphic_runner.py"),
            "classifiers": identity(classifiers),
            "worker_py_sha256": source_sha256(WORKER_PY.relative_to(ROOT).as_posix()),
            "worker_rs_sha256": source_sha256(WORKER_RS.relative_to(ROOT).as_posix()),
            "worker_bootstrap_sha256": sha256(bootstrap.encode("utf-8")),
            "worker_deadlines_ms": deadlines,
        },
        "environment": {"python": platform.python_version(), "platform": platform.system() + "-" + platform.machine()},
        "scope": "development gate: classifier outputs only; no native policy, MCP admission or original-server effect is observed",
        "validation_errors": errors,
    }
    if errors:
        report["verdict"] = "INVALID"
        return report, 3
    cases = corpus["cases"]
    report["modes"], base_outcomes, status = evaluate_set(cases, rels, modes, classifiers)
    if len(base_outcomes) > 1:
        report["mode_parity"] = parity(base_outcomes)
        status = max(status, 1 if report["mode_parity"]["divergent_cases"] else 0)
    if candidate:
        cand = {**classifiers, **candidate}
        cand_modes, cand_outcomes, cand_status = evaluate_set(cases, rels, modes, cand)
        report["candidate"] = {"status": "run", "classifiers": identity(cand), "modes": cand_modes,
                               "comparison": {m: compare(base_outcomes[m], cand_outcomes[m], report["modes"][m], cand_modes[m])
                                              for m in modes}}
        if len(cand_outcomes) > 1:
            report["candidate"]["mode_parity"] = parity(cand_outcomes)
            cand_status = max(cand_status, 1 if report["candidate"]["mode_parity"]["divergent_cases"] else 0)
        status = max(status, cand_status)
    else:
        report["candidate"] = {"status": "not_run", "blocker": CANDIDATE_BLOCKER}
    # Each classifier's own single-shot and worker boundaries, by the same probes and rules:
    # generic under boundary_probes, Git under boundary_probes_git (it has its own main()).
    sections = [(report, classifiers)] + ([(report["candidate"], cand)] if candidate else [])
    for section, selected in sections:
        if section is not report:
            section["boundary_probes_classifier"] = identity({"generic": selected["generic"]})["generic"]
        section["boundary_probes"] = probe_boundaries(rels, selected["generic"], deadlines)
        section["boundary_probes_git_classifier"] = identity({"git": selected["git"]})["git"]
        section["boundary_probes_git"] = probe_boundaries(rels, selected["git"], deadlines)
        if any(p["verdict"] == "fail" for p in section["boundary_probes"] + section["boundary_probes_git"]):
            status = max(status, 1)
    report["verdict"] = {0: "PASS", 1: "FAIL", 2: "TECHNICAL_ERROR"}[status]
    report["not_claimed"] = ["label correctness (all labels pending)", "native policy or authority decisions",
                             "production MCP admission (Rust) behaviour", "original-server execution",
                             "candidate classifier (SOU-97 #213 is not merged)",
                             "latency thresholds (none approved; measurements, if requested, are in latency.json)"]
    return report, status


def probe_boundaries(rels: dict, classifier: Path, deadlines: dict) -> list[dict]:
    out = []
    worker = Worker(classifier)
    try:
        for p in rels["boundary_probes"]:
            raw = expand(p["payload"])
            if sha256(raw) != p["payload_sha256"]:
                out.append({"id": p["id"], "verdict": "fail", "detail": "payload does not match its recorded sha256"})
                continue
            observed = {"single_shot": single_shot(classifier, raw, deadlines["REQUEST_DEADLINE"])}
            try:
                raw.decode("utf-8")
                observed["worker_input"] = worker.classify_bytes(raw)
            except UnicodeDecodeError:
                observed["worker_input"] = "not_frameable: input_json must be a UTF-8 JSON string"
            channels = {k: (ER.failure_channel(v, False) if isinstance(v, dict) and v.get("status") == "error" else
                            ("classification" if isinstance(v, dict) and ER.check_output(v) is None else str(v)[:80]))
                        for k, v in observed.items()}
            if p["expected"] == "technical_failure":
                applicable = {k: c for k, c in channels.items() if not c.startswith("not_frameable")}
                ok = all(c in ER.FAILURE_CODES for c in applicable.values())
                verdict, detail = ("pass" if ok else "fail"), channels
            else:
                accepted = [k for k, c in channels.items() if c == "classification"]
                verdict = "blocked"
                detail = {"enforced_at": "mcp_admission (Rust; not executed by this gate)", "python_boundaries": channels,
                          "known_gap": f"accepted and classified by {accepted}" if accepted else None}
            out.append({"id": p["id"], "expected": p["expected"], "verdict": verdict, "detail": detail})
        for f in rels["worker_frame_probes"]:
            seen = worker.raw_frame(f["frame"].encode("utf-8"))
            ok = seen == {"replies": 0, "exit_code": 3}
            out.append({"id": f["id"], "expected": f["expected"], "verdict": "pass" if ok else "fail", "detail": seen})
    finally:
        worker.close()
    return out


def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile (no interpolation)."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, -(-len(ordered) * q // 100) - 1)]


def stats_ms(samples: list[float], deadline_ms: int | None) -> dict:
    return {"n": len(samples), "p50_ms": percentile(samples, 50), "p95_ms": percentile(samples, 95),
            "max_ms": max(samples) if samples else None,
            "over_deadline": None if deadline_ms is None else sum(s > deadline_ms for s in samples)}


def measure_latency(cases: list[dict], classifiers: dict[str, Path], repeats: int, cold: int) -> dict:
    """Batch size 1, sequential. Warm: after one unmeasured pass. Cold: a fresh process per sample."""
    import os
    import time
    _, deadlines = bootstrap_source()
    out = {"method": {"batch_size": 1, "warm_repeats": repeats, "cold_samples": cold, "percentile": "nearest-rank",
                      "clock": "time.perf_counter_ns", "deadlines_ms": deadlines,
                      "note": "measured on this host only; no relative latency threshold is applied"},
           "environment": {"platform": platform.platform(), "python": platform.python_version(),
                           "implementation": platform.python_implementation(), "machine": platform.machine(),
                           "processor": platform.processor() or None, "cpu_count": os.cpu_count()},
           "profiles": {}}
    for name, path in sorted(classifiers.items()):
        subset = [c for c in cases if c["evaluator_only"]["classifier"] == name]
        inputs = [c["input"] for c in subset]
        fn = direct_classifier(path)
        for event in inputs:
            fn(json.loads(json.dumps(event)))
        warm_direct = []
        for _ in range(repeats):
            for event in inputs:
                copy_ = json.loads(json.dumps(event))
                t = time.perf_counter_ns()
                fn(copy_)
                warm_direct.append((time.perf_counter_ns() - t) / 1e6)
        cold_direct = []
        for i in range(cold):
            payload = wire(inputs[i % len(inputs)]) + b"\n"
            t = time.perf_counter_ns()
            subprocess.run([sys.executable, "-I", str(path)], input=payload, capture_output=True, timeout=60)
            cold_direct.append((time.perf_counter_ns() - t) / 1e6)
        worker, warm_worker = Worker(path), []
        try:
            for event in inputs:
                worker.classify(event)
            for _ in range(repeats):
                for event in inputs:
                    t = time.perf_counter_ns()
                    worker.classify(event)
                    warm_worker.append((time.perf_counter_ns() - t) / 1e6)
            warm_timeouts = worker.timeouts
        finally:
            worker.close()
        cold_ready, cold_first, cold_timeouts = [], [], 0
        for i in range(cold):
            w = Worker(path)
            try:
                t = time.perf_counter_ns()
                w._start()  # the daemon's START_DEADLINE covers spawn until the ready frame
                cold_ready.append((time.perf_counter_ns() - t) / 1e6)
                t = time.perf_counter_ns()
                w.classify(inputs[i % len(inputs)])  # then REQUEST_DEADLINE covers the first call
                cold_first.append((time.perf_counter_ns() - t) / 1e6)
                cold_timeouts += w.timeouts
            finally:
                w.close()
        out["profiles"][name] = {
            "classifier_sha256": sha256(path.read_bytes()), "cases": len(inputs),
            "direct_warm_in_process": stats_ms(warm_direct, None),
            "direct_cold_process_per_call": stats_ms(cold_direct, None),
            "worker_warm_round_trip": {**stats_ms(warm_worker, deadlines["REQUEST_DEADLINE"]), "timeouts": warm_timeouts},
            "worker_cold_start_to_ready": stats_ms(cold_ready, deadlines["START_DEADLINE"]),
            "worker_cold_first_reply": {**stats_ms(cold_first, deadlines["REQUEST_DEADLINE"]), "timeouts": cold_timeouts},
        }
    return out


def render_markdown(report: dict, latency: dict | None = None) -> str:
    ids = report["identities"]
    lines = ["# SOU-128 metamorphic gate (development)", "", f"Verdict: **{report['verdict']}**", "",
             report["scope"], "", "## Identities", ""]
    lines += [f"- corpus `{ids['corpus']['path']}` `{ids['corpus']['sha256']}`",
              f"- relations `{ids['relations']['path']}` `{ids['relations']['sha256']}`",
              f"- eval_runner.py `{ids['eval_runner_sha256']}`; metamorphic_runner.py `{ids['metamorphic_runner_sha256']}`",
              f"- worker.py `{ids['worker_py_sha256']}`; bootstrap `{ids['worker_bootstrap_sha256']}`; deadlines {ids['worker_deadlines_ms']}"]
    lines += [f"- classifier {k}: `{v['path']}` `{v['sha256']}`" for k, v in ids["classifiers"].items()]
    for mode, m in report.get("modes", {}).items():
        lines += ["", f"## Mode `{mode}`", "", f"Relations: {m['tally']} (pass_vacuous = equal abstentions, included in pass)", "",
                  "| kind | pass | of which vacuous | fail | observed |", "|---|---|---|---|---|"]
        lines += [f"| {k} | {v['pass']} | {v['pass_vacuous']} | {v['fail']} | {v['observed']} |" for k, v in m["by_kind"].items()]
        fails = [x for x in m["relations"] if x["verdict"] == "fail"]
        lines += ["", "Failures:" if fails else "Failures: none"] + [f"- `{x['id']}` ({x['kind']}): {x['detail']}" for x in fails]
        lines += [f"- unexpected technical error `{e['id']}`: {e['error']}" for e in m["unexpected_technical_errors"]]
        acc = m["accounting"]
        c, rp = acc["cases"], acc["relation_pairs"]
        lines += ["", f"Cases {c['total']}: certain {c['certain_actions']}, proven no-op {c['proven_noop']}, partial unknown "
                      f"{c['partial_unknown']}, abstention {c['abstention']}, technical failure {c['technical_failure']} "
                      f"{c['technical_failure_by_channel']}; protocol errors {acc['protocol_errors']}; timeouts {acc['timeouts']}.",
                  f"Labels: {acc['labels']['scored']} scored, {acc['labels']['pending']} pending ({acc['labels']['note']}).",
                  f"Relation pairs {rp['total']} ({rp['both_classified']} both classified): known-action losses "
                  f"{len(rp['known_action_losses'])}, of which without added uncertainty "
                  f"{len(rp['known_action_losses_without_uncertainty'])}; risky-action losses {len(rp['risky_action_losses'])}."]
    if "mode_parity" in report:
        lines += ["", f"Mode parity {report['mode_parity']['compared']}: divergent cases {report['mode_parity']['divergent_cases'] or 'none'}"]
    cand = report.get("candidate", {})
    lines += ["", "## Candidate", ""]
    if cand.get("status") == "run":
        lines += [f"- {k}: `{v['path']}` `{v['sha256']}`" for k, v in cand["classifiers"].items()]
        for mode, cmp_ in cand["comparison"].items():
            lines.append(f"- {mode}: {len(cmp_['cases_changed'])}/{cmp_['cases_compared']} cases changed, risky losses "
                         f"{len(cmp_['risky_losses'])}, relation regressions {len(cmp_['relation_regressions'])}")
        for name, key in (("generic", "boundary_probes"), ("git", "boundary_probes_git")):
            lines.append(f"- {name} boundary probes: " + ", ".join(f"{p['id']} {p['verdict']}" for p in cand.get(key, [])))
    else:
        lines.append(f"Not run: {cand.get('blocker')}")
    if latency:
        lines += ["", "## Latency (batch 1, this host only)", "", f"Environment: {latency['environment']}", "",
                  "| profile | measurement | n | p50 ms | p95 ms | max ms | over deadline |", "|---|---|---|---|---|---|---|"]
        timed = [("baseline", latency["profiles"])] + ([("candidate", latency["candidate"]["profiles"])] if "candidate" in latency else [])
        for side, profiles in timed:
            for prof, rows in profiles.items():
                for k, v in rows.items():
                    if isinstance(v, dict):
                        lines.append(f"| {side} {prof} | {k} | {v['n']} | {v['p50_ms']:.3f} | {v['p95_ms']:.3f} | {v['max_ms']:.3f} | {v['over_deadline']} |")
    lines += ["", "## Boundary probes", "", "| classifier | probe | expected | verdict |", "|---|---|---|---|"]
    for name, key in (("generic", "boundary_probes"), ("git", "boundary_probes_git")):
        lines += [f"| {name} | {p['id']} | {p.get('expected')} | {p['verdict']} |" for p in report.get(key, [])]
    lines += ["", "Not claimed: " + "; ".join(report.get("not_claimed", [])), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--relations", type=Path, default=RELATIONS)
    ap.add_argument("--modes", default="direct,worker")
    ap.add_argument("--classifier", action="append", default=[], metavar="NAME=PATH",
                    help="override a classifier (generic, git); the default is the accepted baseline")
    ap.add_argument("--candidate", action="append", default=[], metavar="NAME=PATH",
                    help="explicitly selected candidate for one classifier (generic, git), compared with the baseline")
    ap.add_argument("--latency", action="store_true", help="also measure batch-1 latency into latency.json")
    ap.add_argument("--latency-repeats", type=int, default=5)
    ap.add_argument("--latency-cold", type=int, default=20)
    ap.add_argument("--out-dir", type=Path, default=Path("target/sou128"))
    a = ap.parse_args(argv)
    modes = [m for m in a.modes.split(",") if m]

    def selection(items, flag):
        chosen = {}
        for item in items:
            name, _, path = item.partition("=")
            if name not in CLASSIFIERS or not Path(path).is_file():
                ap.error(f"{flag} {item!r}: expected generic=PATH or git=PATH to an existing file")
            chosen[name] = Path(path)
        return chosen
    classifiers = {**CLASSIFIERS, **selection(a.classifier, "--classifier")}
    candidate = selection(a.candidate, "--candidate")
    if not modes or set(modes) - {"direct", "worker"}:
        ap.error("--modes must list direct and/or worker")
    if a.latency_repeats < 1 or a.latency_cold < 1:
        ap.error("--latency-repeats and --latency-cold must be at least 1")
    report, status = run(a.corpus, a.relations, modes, classifiers, candidate)
    a.out_dir.mkdir(parents=True, exist_ok=True)
    if a.latency and status != 3:
        cases = json.loads(a.corpus.read_bytes())["cases"]
        latency = measure_latency(cases, classifiers, a.latency_repeats, a.latency_cold)
        latency["classifiers"] = identity(classifiers)
        if candidate:
            # Same method and deadlines, after the baseline; only the profiles the candidate replaces.
            latency["candidate"] = {"classifiers": identity(candidate),
                                    "profiles": measure_latency(cases, candidate, a.latency_repeats, a.latency_cold)["profiles"]}
        (a.out_dir / "latency.json").write_bytes((json.dumps(latency, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        report_latency = latency
    else:
        report_latency = None
    (a.out_dir / "report.json").write_bytes((json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    (a.out_dir / "summary.md").write_bytes(render_markdown(report, report_latency).encode("utf-8"))
    for e in report.get("validation_errors", []):
        print("invalid:", e, file=sys.stderr)
    for mode, m in report.get("modes", {}).items():
        print(f"{mode}: relations {m['tally']}; unexpected technical errors {len(m['unexpected_technical_errors'])}")
    def tally(probes):
        return {k: sum(p["verdict"] == k for p in probes) for k in ("pass", "fail", "blocked")}
    for label, section in (("", report), ("candidate ", report.get("candidate", {}))):
        if "boundary_probes" in section:
            print(f"{label}boundary probes: generic {tally(section['boundary_probes'])}; "
                  f"git {tally(section.get('boundary_probes_git', []))}")
    print(f"verdict {report.get('verdict', 'INVALID')}; wrote {a.out_dir / 'report.json'}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
