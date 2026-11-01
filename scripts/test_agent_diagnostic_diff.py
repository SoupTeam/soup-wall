import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).parent
TOOL = ROOT / "agent-diagnostic-diff.py"

def bundle(root, source, extra=None):
    root.mkdir()
    data = {"schema": "sw-agent-diagnostic-bundle/1", "source": source, "scope": "pilot", "policy": "deny", "daemon": "ready"}
    data.update(extra or {})
    (root / "manifest.json").write_text(json.dumps(data), encoding="utf-8")

def run(a, b, out):
    return subprocess.run([sys.executable, str(TOOL), str(a), str(b), "--json-out", str(out / "x.json"), "--markdown-out", str(out / "x.md")], capture_output=True, text=True)

def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); out = root / "out"; out.mkdir()
        a, b = root / "a", root / "b"; bundle(a, "old"); bundle(b, "new", {"policy": "ask"})
        result = run(a, b, out); assert result.returncode == 0, result.stderr
        assert json.loads((out / "x.json").read_text())["comparison"]["changed"][0]["field"] == "source"
        bad = root / "bad"; bundle(bad, "bad", {"token": "secret"})
        assert run(a, bad, out).returncode == 2
        link = root / "link"; bundle(link, "link")
        try:
            (link / "evil.json").symlink_to(a / "manifest.json")
        except OSError:
            pass
        else:
            assert run(a, link, out).returncode == 2
    print("diagnostic diff tests passed")

if __name__ == "__main__": main()
