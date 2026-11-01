import json, subprocess, sys
from pathlib import Path
TOOL = Path(__file__).parent / "agent-command-help.py"
def run(*args): return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)
def main():
    assert run("list").returncode == 0
    assert "doctor" in run("topic", "doctor").stdout
    assert run("completion", "--shell", "bash").returncode == 0
    assert run("completion", "--shell", "zsh").returncode == 0
    assert run("completion", "--shell", "fish").returncode == 0
    stale = json.dumps({"schema": "sw-agent-command-catalog/1", "version": "old", "commands": []})
    assert run("list", "--catalog-json", stale).returncode == 2
    hostile = json.dumps({"schema": "sw-agent-command-catalog/1", "version": "0.3.0", "commands": [{"name": "x;touch", "flags": []}]})
    assert run("list", "--catalog-json", hostile).returncode == 2
    print("command help tests passed")
if __name__ == "__main__": main()
