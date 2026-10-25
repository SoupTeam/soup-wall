#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the SOU-123 payloads by running the ORIGINAL Git and filesystem MCP servers.

The committed payloads are the frozen artifact; this script exists so another engineer can
re-derive them from owned synthetic repositories/files. Requires the pinned original servers
(see docs/operations/RESULT_INSPECTION_CORPUS.md). Nothing is downloaded here.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus
from mcp_client import call

BUDGET = 262144
WS = "/tmp/sou123/ws"
REPO = "/tmp/sou123/repo"
PATHS = dict(py="src/service.py", md="README.md", yaml="config/service.yaml", js="src/app.js",
             go="config/config.go", ci=".github/workflows/ci.yml", txt="NOTES.txt", json="config/storage.json",
             padded="data/table.csv")
FS_OTHERS = ["md", "py", "txt"]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build_lines(kind, name):
    if kind == "padded":
        return []
    return list(corpus.HOSTS[kind](name))


def insert(lines, at, block):
    at = len(lines) if at is None else min(at, len(lines))
    return lines[:at] + block + lines[at:]


def pad_lines(width_last, count=3000):
    rows = ["row-%05d,%s" % (i, "x" * 60) for i in range(count)]
    return rows + ["tail," + "y" * width_last]


def run(cmd, env=None):
    subprocess.run(cmd, env=env, check=True, capture_output=True)


def git_env(a):
    env = dict(os.environ)
    env["PATH"] = str(Path(a.git).parent) + os.pathsep + env["PATH"]
    for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        env[k] = "/dev/null"
    for who in ("AUTHOR", "COMMITTER"):
        env[f"GIT_{who}_NAME"] = "Corpus Author"
        env[f"GIT_{who}_EMAIL"] = "corpus@example.invalid"
        env[f"GIT_{who}_DATE"] = "2026-10-23T09:00:00+00:00"
    return env


def write(root, relative, lines):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def git_payload(a, pair, block, pad):
    env = git_env(a)
    shutil.rmtree(REPO, ignore_errors=True)
    Path(REPO).mkdir(parents=True)
    host = pair["host"]
    rel = PATHS[host]
    if host == "padded":
        base = ["name,value", "alpha,1"]
        final = base + pad_lines(pad) + block
    else:
        base = build_lines(host, "sample")
        final = insert(base, pair["at"], block)
    for c in (["init", "-q", "-b", "main"], ["config", "core.autocrlf", "false"]):
        run(["git", "-C", REPO] + c, env)
    write(REPO, rel, base)
    write(REPO, "CHANGELOG.md", ["# Changelog", "", "- 2.3 initial import"])
    run(["git", "-C", REPO, "add", "-A"], env)
    run(["git", "-C", REPO, "commit", "-qm", "Initial import"], env)
    write(REPO, rel, final)
    write(REPO, "CHANGELOG.md", ["# Changelog", "", "- 2.4 minor maintenance", "- 2.3 initial import"])
    run(["git", "-C", REPO, "add", "-A"], env)
    run(["git", "-C", REPO, "commit", "-qm", "Maintenance update"], env)
    if pair["surface"] == "git_show":
        tool, args = "git_show", {"revision": "HEAD"}
    else:
        tool, args = "git_diff", {"target": "HEAD~1", "context_lines": 3}
    py = str(Path(a.git_python))
    senv = dict(env)
    result = call([py, "-m", "mcp_server_git", "--repository", REPO], tool, dict(args, repo_path=REPO), env=senv)
    text = result["content"][0]["text"]
    assert result.get("isError") is False, result
    return tool, dict(args, repo_path=REPO), text


def fs_workspace(pair, block, pad, root):
    """Write the owned synthetic files of one filesystem pair under `root`; return their absolute paths."""
    shutil.rmtree(root, ignore_errors=True)
    names = []
    kinds = list(FS_OTHERS)
    kinds[pair["file_index"]] = pair["host"]
    for i, kind in enumerate(kinds):
        rel = "f%d_%s" % (i, PATHS[kind].replace("/", "_"))
        if i == pair["file_index"]:
            if kind == "padded":
                lines = ["name,value"] + pad_lines(pad) + block
            elif kind == "json":
                doc = {"storage": {"path": "/var/lib/sample", "retention_days": 14, "description": block[0]}, "limits": {"max_body_bytes": 1048576}}
                lines = json.dumps(doc, indent=2).split("\n")
            else:
                lines = insert(build_lines(kind, "sample"), pair["at"], block)
        else:
            lines = build_lines(kind, "other%d" % i)
        write(root, rel, lines)
        names.append(str(Path(root) / rel))
    return names


def fs_payload(a, pair, block, pad):
    names = fs_workspace(pair, block, pad, WS)
    env = dict(os.environ)
    result = call([a.node, a.fs_server, WS], "read_multiple_files", {"paths": names}, env=env)
    text = result["content"][0]["text"]
    assert result["structuredContent"]["content"] == text
    return "read_multiple_files", {"paths": names}, text


def make(a, pair, variant):
    block = pair[variant]
    fn = git_payload if pair["surface"].startswith("git") else fs_payload
    if pair["host"] != "padded":
        return fn(a, pair, block, 0)
    pad = 10
    for _ in range(4):
        tool, args, text = fn(a, pair, block, pad)
        delta = BUDGET - len(text.encode("utf-8"))
        if delta == 0:
            return tool, args, text
        pad += delta
    raise SystemExit("could not reach exactly %d bytes for %s" % (BUDGET, pair["id"]))


def side(pair_id):
    return "attack" if int(sha(pair_id.encode())[0], 16) % 2 == 0 else "benign"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    for n in ("git", "git-python", "node", "fs-server"):
        p.add_argument("--" + n, required=True)
    a = p.parse_args()
    a.git_python, a.fs_server = a.git_python, a.fs_server
    out = Path(a.out)
    (out / "payloads").mkdir(parents=True, exist_ok=True)
    cases = []
    for pair in corpus.PAIRS:
        first = side(pair["id"])
        for variant in ("benign", "attack"):
            tool, args, text = make(a, pair, variant)
            letter = "a" if variant == first else "b"
            case_id = "%s-%s" % (pair["id"], letter)
            data = text.encode("utf-8")
            (out / "payloads" / (case_id + ".txt")).write_bytes(data)
            cases.append(dict(case_id=case_id, pair_id=pair["id"], class_="semantic", surface=pair["surface"], tool=tool,
                              arguments=args, label=variant, category=pair["category"], language=pair["lang"],
                              position=pair["position"], size_bytes=len(data), sha256=sha(data), task=pair["task"],
                              forbidden_effect=pair["forbidden"], rationale=pair["rationale"],
                              host=pair["host"]))
    # technical cases
    benign12 = dict(next(x for x in corpus.PAIRS if x["id"] == "f12"))
    for t in corpus.TECHNICAL:
        if t["kind"] == "protocol_error":
            result = call([a.node, a.fs_server, WS], "read_multiple_files", {"paths": [WS + "/does-not-exist.txt"]})
            text, tool, args = result["content"][0]["text"], "read_multiple_files", {"paths": [WS + "/does-not-exist.txt"]}
        else:
            src = next(x for x in corpus.PAIRS if x["id"] == ("f12" if t["surface"] != "git_show" else "g12"))
            tool, args, text = make(a, src, "benign")
            text = text + "\n"
        data = text.encode("utf-8")
        (out / "payloads" / (t["id"] + ".txt")).write_bytes(data)
        cases.append(dict(case_id=t["id"], pair_id=None, class_="technical", surface=t["surface"], tool=tool, arguments=args,
                          label="not_semantic", category=t["kind"], language="en", position="n/a", size_bytes=len(data),
                          sha256=sha(data), task="n/a", forbidden_effect="n/a", rationale=t["note"], host="n/a"))
    manifest = dict(format="sw-result-inspection-corpus/1", public_development_only=True, budget_bytes=BUDGET, cases=cases)
    for c in manifest["cases"]:
        c["class"] = c.pop("class_")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("cases", len(cases))


if __name__ == "__main__":
    main()
