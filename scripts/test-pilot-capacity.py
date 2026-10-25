"""Exercise capacity refusal on a small private mount without filling host storage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
import pilot_capacity as capacity

ROOT = Path(__file__).resolve().parents[1]


def worker(root, standard_uid=None):
    mounted = False
    try:
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "size=16m,nr_inodes=4096",
                        "tmpfs", str(root)], check=True, capture_output=True, timeout=10)
        mounted = True
        root.chmod(0o700)
        if standard_uid is not None:
            import pwd
            account = pwd.getpwuid(standard_uid)
            if os.geteuid() != 0 or standard_uid <= 0:
                raise ValueError("root mount setup and a standard UID are required")
            os.chown(root, account.pw_uid, account.pw_gid)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        probe = capacity.plan([capacity.Demand("build", root, 0)], 0)
        if probe["reason"] == "unsafe_destination":
            return {"status": "not_verified", "reason": "namespace_ancestor_ownership_unmapped"}
        marker = root / "current.json"
        marker.write_bytes(b"previous-generation")
        unrelated = root / "unrelated"
        unrelated.write_bytes(b"retain")
        starts = 0
        child_marker = root / "child-started"
        try:
            with capacity.Guard([capacity.Demand("build", root, 32 * capacity.MIB)], 0):
                starts += 1
                subprocess.run([sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
                                str(child_marker)], check=True, timeout=5)
        except capacity.Refusal as error:
            refused = error.report
        else:
            raise AssertionError("oversized preparation was admitted")
        if refused["reason"] != "low_space" or starts or child_marker.exists():
            raise AssertionError("low-space refusal started work or returned the wrong reason")
        if marker.read_bytes() != b"previous-generation" or unrelated.read_bytes() != b"retain":
            raise AssertionError("prior files changed")
        small = capacity.plan([capacity.Demand("build", root, 4096)], capacity.MIB)
        if small["status"] not in ("sufficient", "unknown"):
            raise AssertionError("unexpected small-budget observation")
        return {"status": "passed", "low_space_zero_work": True, "prior_files_unchanged": True,
                "observation_uid": os.geteuid(),
                "mount_limit_bytes": 16 * capacity.MIB, "host_disk_filled": False,
                "small_budget_observation": small,
                "scope": "private tmpfs observation; no downloads or real compiler build"}
    finally:
        if mounted and os.geteuid() == 0:
            subprocess.run(["/usr/bin/umount", str(root)], check=True, capture_output=True, timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--private-mount", action="store_true", help="use an isolated root mount namespace for setup")
    parser.add_argument("--standard-uid", type=int, help="drop to this existing standard account after mounting")
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker, args.standard_uid), sort_keys=True))
        return 0
    if sys.platform != "linux" or (os.geteuid() == 0) != args.private_mount:
        print(json.dumps({"status": "not_verified", "reason": "non_root_linux_required"}))
        return 2
    names = ("pilot_capacity.py", "test-pilot-capacity.py", "prepare-native-pilot-prerequisites.py",
             "build-native-pilot-inputs.py", "prepare-installed-pilot.py", "tests/test_pilot_capacity.py")
    identity = {name: hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() for name in names}
    with tempfile.TemporaryDirectory(prefix="sw-capacity-") as temporary:
        namespace = [] if args.private_mount else ["--user", "--map-root-user"]
        identity_args = ["--standard-uid", str(args.standard_uid)] if args.standard_uid is not None else []
        result = subprocess.run(["/usr/bin/unshare", *namespace, "--mount", "--propagation", "private", "--fork",
            sys.executable, "-B", str(Path(__file__).resolve()), "--worker", temporary, *identity_args],
            capture_output=True, timeout=30)
    if result.returncode:
        report = {"status": "failed", "reason": "private_mount_fixture_failed",
                  "exit_code": result.returncode}
    else:
        report = json.loads(result.stdout)
    print(json.dumps({"format": "sw-pilot-capacity-evidence/1", "source_files_sha256": identity,
        "environment": "WSL" if "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower()
                       else "Linux", "result": report}, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
