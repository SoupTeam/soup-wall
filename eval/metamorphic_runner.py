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

CORPUS = ROOT / "eval/fixtures/sou128_metamorphic_dev_v0.3.json"
RELATIONS = ROOT / "eval/fixtures/sou128_relations_v0.3.json"
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
        self.proc, self.next_id, self.restarts, self.timeouts = None, 0, 0, 0

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
        return self.classify_bytes(wire(event))

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
            errs.append(f"{c['id']}: v0.3 promotes no label; expectation_status must stay pending")
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
        actual = sha256(path.read_bytes()) if path.is_file() else None
        if actual != s["sha256"]:
            drift.append(f"{s['path']}: cited {s['sha256']}, now {actual}")
    return sorted(set(drift))


# ---------------------------------------------------------------- run
def run(corpus_path: Path, relations_path: Path, modes: list[str], classifiers: dict[str, Path]) -> tuple[dict, int]:
    corpus_raw, rels_raw = corpus_path.read_bytes(), relations_path.read_bytes()
    corpus, rels = json.loads(corpus_raw), json.loads(rels_raw)
    errors = validate(corpus, rels) + source_drift(rels)
    bootstrap, deadlines = bootstrap_source()
    report: dict[str, Any] = {
        "format": "sou128-metamorphic-report/1",
        "identities": {
            "corpus": {"path": corpus_path.name, "sha256": sha256(corpus_raw), "fixture_version": corpus.get("fixture_version")},
            "relations": {"path": relations_path.name, "sha256": sha256(rels_raw)},
            "eval_runner_sha256": sha256(Path(ER.__file__).read_bytes()),
            "metamorphic_runner_sha256": sha256(Path(__file__).read_bytes()),
            "classifiers": {k: {"path": p.resolve().relative_to(ROOT).as_posix() if p.resolve().is_relative_to(ROOT) else p.name,
                                "sha256": sha256(p.read_bytes())} for k, p in sorted(classifiers.items())},
            "worker_py_sha256": sha256(WORKER_PY.read_bytes()),
            "worker_rs_sha256": sha256(WORKER_RS.read_bytes()),
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
    by_id = {c["id"]: c for c in cases}
    failure_members = {m for r in rels["relations"] if r["kind"] == "technical_failure_channel" for m in r["members"]}
    status = 0
    report["modes"] = {}
    per_mode_outcomes = {}
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
            stats = {k: {"restarts": w.restarts, "timeouts": w.timeouts} for k, w in workers.items()}
            for w in workers.values():
                w.close()
        rec_by_id = {r["id"]: r for r in recs}
        per_mode_outcomes[mode] = {r["id"]: outcome(r) for r in recs}
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
        report["modes"][mode] = {"relations": results, "tally": tally, "by_kind": dict(sorted(by_kind.items())),
                                 "unexpected_technical_errors": unexpected, "worker_stats": stats,
                                 "evaluator_overall": ER.summarize(recs)["overall"],
                                 "cases": {r["id"]: list(outcome(r)) for r in recs}}
        if tally["fail"]:
            status = max(status, 1)
        if unexpected:
            status = max(status, 2)
    if len(per_mode_outcomes) > 1:
        first, *rest = per_mode_outcomes
        divergent = sorted(cid for cid in by_id for m in rest if per_mode_outcomes[m][cid] != per_mode_outcomes[first][cid])
        report["mode_parity"] = {"compared": list(per_mode_outcomes), "divergent_cases": divergent}
        if divergent:
            status = max(status, 1)
    report["boundary_probes"] = probe_boundaries(rels, classifiers["generic"], deadlines)
    if any(p["verdict"] == "fail" for p in report["boundary_probes"]):
        status = max(status, 1)
    report["verdict"] = {0: "PASS", 1: "FAIL", 2: "TECHNICAL_ERROR"}[status]
    report["not_claimed"] = ["label correctness (all labels pending)", "native policy or authority decisions",
                             "production MCP admission (Rust) behaviour", "original-server execution",
                             "candidate classifier (SOU-97 #213 is not merged)", "latency"]
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


def render_markdown(report: dict) -> str:
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
    if "mode_parity" in report:
        lines += ["", f"Mode parity {report['mode_parity']['compared']}: divergent cases {report['mode_parity']['divergent_cases'] or 'none'}"]
    lines += ["", "## Boundary probes", "", "| probe | expected | verdict |", "|---|---|---|"]
    lines += [f"| {p['id']} | {p.get('expected')} | {p['verdict']} |" for p in report.get("boundary_probes", [])]
    lines += ["", "Not claimed: " + "; ".join(report.get("not_claimed", [])), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--relations", type=Path, default=RELATIONS)
    ap.add_argument("--modes", default="direct,worker")
    ap.add_argument("--classifier", action="append", default=[], metavar="NAME=PATH",
                    help="override a classifier (generic, git); the default is the accepted baseline")
    ap.add_argument("--out-dir", type=Path, default=Path("target/sou128"))
    a = ap.parse_args(argv)
    modes = [m for m in a.modes.split(",") if m]
    classifiers = dict(CLASSIFIERS)
    for item in a.classifier:
        name, _, path = item.partition("=")
        if name not in CLASSIFIERS or not Path(path).is_file():
            ap.error(f"--classifier {item!r}: expected generic=PATH or git=PATH to an existing file")
        classifiers[name] = Path(path)
    if not modes or set(modes) - {"direct", "worker"}:
        ap.error("--modes must list direct and/or worker")
    report, status = run(a.corpus, a.relations, modes, classifiers)
    a.out_dir.mkdir(parents=True, exist_ok=True)
    (a.out_dir / "report.json").write_bytes((json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    (a.out_dir / "summary.md").write_bytes(render_markdown(report).encode("utf-8"))
    for e in report.get("validation_errors", []):
        print("invalid:", e, file=sys.stderr)
    for mode, m in report.get("modes", {}).items():
        print(f"{mode}: relations {m['tally']}; unexpected technical errors {len(m['unexpected_technical_errors'])}")
    probes = report.get("boundary_probes", [])
    print("boundary probes:", {k: sum(p["verdict"] == k for p in probes) for k in ("pass", "fail", "blocked")})
    print(f"verdict {report.get('verdict', 'INVALID')}; wrote {a.out_dir / 'report.json'}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
