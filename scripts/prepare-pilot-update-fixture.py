import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UPDATE = load("update_fixture_coordinator", "pilot_update.py")
QUAL = load("update_fixture_host", "qualify-pilot-front-door.py")


def call(words, cwd, env):
    result = subprocess.run([str(word) for word in words], cwd=cwd, env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=1200)
    if result.returncode:
        raise ValueError("fixture_command_failed:" + result.stdout.decode("utf-8", "replace")[-1000:]
                         + result.stderr.decode("utf-8", "replace")[-500:])
    return json.loads(result.stdout.decode().splitlines()[-1])


def prepare(args):
    UPDATE.require(args.output.is_absolute() and not args.output.exists()
                   and not args.output.is_relative_to(ROOT), "new_external_fixture_required")
    args.output.mkdir(mode=0o700)
    home = args.output / "home"
    home.mkdir(mode=0o700)
    env = QUAL.qualification_environment(home)
    project, repository = args.output / "project", args.output / "repository"
    project.mkdir(mode=0o700)
    repository.mkdir(mode=0o700)
    (project / "README.md").write_text("Owned coordinated update fixture\n")
    (repository / "tracked.txt").write_text("Owned history\n")
    for words in (("init", "-q", str(repository)), ("-C", str(repository), "add", "tracked.txt"),
                  ("-C", str(repository), "commit", "-qm", "Owned update history")):
        subprocess.run([str(args.git), *words], env=env, check=True, capture_output=True, timeout=30)
    records = []
    for label, source, receipt in (("a", args.source_a, args.build_a), ("b", ROOT, args.build_b)):
        build = json.loads(receipt.read_text())
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        prefix = args.output / ("prepared-" + label)
        component = args.output / ("helper-" + label + ".tar")
        built = call([sys.executable, "-B", source / "scripts/build-pilot-front-door.py",
                      "--out", component], source, env)
        UPDATE.require(built["commit"] == commit, "fixture_component_source_mismatch")
        words = [sys.executable, "-B", source / "scripts/pilot.py", "prepare", "--apply",
                 "--prefix", prefix, "--expected-commit", commit, "--node-archive", args.node_archive,
                 "--bwrap", args.bwrap, "--git", args.git, "--claude", args.claude,
                 "--python", Path(sys.executable).resolve(),
                 "--filesystem-workspace", project, "--git-workspace", repository,
                 "--python-archive", args.python_archive, "--npm-cache", args.npm_cache,
                 "--wheelhouse", args.wheelhouse]
        for role in ("agentfw", "git_launcher", "sandbox_tests"):
            words += ["--" + role.replace("_", "-"), build[role]]
        prepared = call(words, source, env)
        UPDATE.require(prepared["status"] == "prepared-not-active", "fixture_preparation_failed")
        value = UPDATE.make_inventory(prefix, component, built["archive_sha256"], commit, "candidate-" + label)
        path = args.output / ("inventory-" + label + ".json")
        with path.open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        records.append({"inventory": str(path), "component": built, "prepared": prepared})
    entry = json.loads(args.build_b.read_text())["agentfw"]
    entry_home = args.output / "bootstrap"
    entry_home.mkdir(mode=0o700)
    call([entry, "pilot-component", "--home", entry_home, "install",
          args.output / "helper-b.tar", "--sha256", records[1]["component"]["archive_sha256"],
          "--python", Path(sys.executable).resolve()], home, env)
    result = {"status": "prepared-not-qualified", "sets": records, "entry_agent": entry,
              "entry_home": str(entry_home), "fixture_root": str(args.output),
              "expected_text": "Owned coordinated update fixture"}
    (args.output / "inputs.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Prepare disposable update fixtures from explicit local inputs.")
    for name in ("source-a", "build-a", "build-b", "node-archive", "bwrap", "git", "claude",
                 "python-archive", "npm-cache", "wheelhouse", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        load("update_fixture_platform", "prepare-installed-pilot.py").supported_platform()
        prepare(args)
        return 0
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": str(error)[:1500]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
