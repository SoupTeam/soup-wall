# scripts/generate_inventory.py
import subprocess
import json
import datetime
import sys
import argparse
import os
import hashlib

MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT = 60

REQUIRED_RECEIPT_FILES = {"upstream-initialize.json", "upstream-tools-list.json", "requirements.lock"}

def run_cmd(cmd_list, timeout=DEFAULT_TIMEOUT, allowed_exit_codes=(0,)):
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        stdout = result.stdout[:MAX_OUTPUT_BYTES].strip()
        stderr = result.stderr[:MAX_OUTPUT_BYTES].strip()
        if result.returncode not in allowed_exit_codes:
            return {"status": "failed", "exit_code": result.returncode, "stdout": stdout, "stderr": stderr}
        return {"status": "success", "stdout": stdout, "exit_code": result.returncode}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def compute_sha256(filepath):
    try:
        with open(filepath, "rb") as f:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b""): hasher.update(chunk)
            return hasher.hexdigest()
    except Exception: return None

def count_lockfile_packages(filepath, is_cargo):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            if is_cargo: return f.read().count("[[package]]")
            return len([line for line in f if "==" in line and not line.strip().startswith("#")])
    except Exception: return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()

    try:
        with open(args.receipt, "r") as f: receipt = json.load(f)
    except Exception as e:
        print(f"FAILED to read receipt {args.receipt}: {e}", file=sys.stderr)
        sys.exit(1)

    receipt_dir = os.path.dirname(args.receipt) or "."
    inventory = {
        "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")},
        "coverage": {"finite_graph": {}}, "receipt_verification": {}, "advisories": {}, "licenses": {}
    }
    has_failures = False

    # 1. Exact Installation Selection & Finite Graph Validation (Rust/Python/Node/original-server/Git/bwrap)
    package_name = receipt.get("package")
    python_data = receipt.get("python", {})
    git_version = receipt.get("git_version")

    if package_name != "mcp-server-git":
        print(f"ERROR: Unrelated package selection '{package_name}'. Expected 'mcp-server-git'.", file=sys.stderr)
        has_failures = True
    if not python_data.get("version"):
        print("ERROR: Unrelated or missing python graph.", file=sys.stderr)
        has_failures = True
    if not git_version or git_version == "not-a-version":
        print("ERROR: Unrelated or missing git_version.", file=sys.stderr)
        has_failures = True

    inventory["coverage"]["finite_graph"]["original_server"] = package_name
    inventory["coverage"]["finite_graph"]["python"] = python_data
    inventory["coverage"]["finite_graph"]["git"] = git_version

    tools_list_path = os.path.join(receipt_dir, "upstream-tools-list.json")
    if os.path.exists(tools_list_path):
        with open(tools_list_path, "r") as f:
            tools = json.load(f)
            inventory["coverage"]["finite_graph"]["tools"] = tools
            tools_str = json.dumps(tools).lower()
            if "node" not in tools_str or ("bwrap" not in tools_str and "bubblewrap" not in tools_str):
                print("ERROR: Node or bwrap missing from tools graph.", file=sys.stderr)
                has_failures = True
    else:
        print("ERROR: Missing upstream-tools-list.json for graph coverage.", file=sys.stderr)
        has_failures = True

    # 2. File Digest Validation
    files_dict = receipt.get("files", {})
    missing_reqs = REQUIRED_RECEIPT_FILES - set(files_dict.keys())
    if not files_dict or missing_reqs:
        print(f"ERROR: Incomplete receipt coverage. Missing: {missing_reqs}", file=sys.stderr)
        has_failures = True
    else:
        file_checks = {}
        for fname, expected_hash in files_dict.items():
            fpath = os.path.join(receipt_dir, fname)
            actual_hash = compute_sha256(fpath)
            if actual_hash != expected_hash:
                file_checks[fname] = {"status": "hash_mismatch"}
                has_failures = True
            else: file_checks[fname] = {"status": "verified", "sha256": actual_hash}
        inventory["receipt_verification"]["files"] = file_checks

    # Pre-compute exact package counts from physical lockfiles to correlate against scanners
    req_path = os.path.join(receipt_dir, "requirements.lock")
    expected_cargo_count = count_lockfile_packages("Cargo.lock", True)
    expected_pypi_count = count_lockfile_packages(req_path, False)

    if expected_cargo_count == 0 or expected_pypi_count == 0:
        print("ERROR: Lockfiles are empty or unparseable. Finite graph unresolved.", file=sys.stderr)
        has_failures = True

    # 3. Cargo Audit Verification
    print("Running cargo audit...")
    cargo_audit_res = run_cmd(["cargo", "audit", "--json"])
    if cargo_audit_res["status"] == "success":
        try:
            rust_data = json.loads(cargo_audit_res["stdout"])
            inventory["advisories"]["rust"] = rust_data
            audited_count = rust_data.get("lockfile", {}).get("dependency-count", 0)
            if audited_count != expected_cargo_count:
                print(f"ERROR: Cargo audit scanned {audited_count} dependencies, but lockfile requires {expected_cargo_count}.", file=sys.stderr)
                has_failures = True
            if rust_data.get("vulnerabilities", {}).get("found", False):
                has_failures = True
        except json.JSONDecodeError: has_failures = True
    else: has_failures = True

    # 4. Cargo Deny Verification (Exact Notice/License Inventory)
    print("Running cargo deny...")
    cargo_deny_res = run_cmd(["cargo", "deny", "check", "licenses"])
    if cargo_deny_res["status"] == "success": inventory["licenses"]["rust_status"] = "ok"
    else: has_failures = True

    # 5. OSV Scanner Full Correlation
    print("Running OSV Scanner...")
    osv_cmd = ["osv-scanner", "-f", "json", "--all-packages"]
    if os.path.exists("Cargo.lock"): osv_cmd.append("--lockfile=Cargo.lock")
    if os.path.exists(req_path): osv_cmd.append(f"--lockfile=requirements.txt:{req_path}")

    osv_res = run_cmd(osv_cmd, allowed_exit_codes=(0, 1))
    if osv_res["status"] == "success":
        raw_out = osv_res["stdout"].strip()
        if raw_out and not raw_out.startswith("{"):
            start = raw_out.find("{")
            if start != -1: raw_out = raw_out[start:]
        try:
            osv_data = json.loads(raw_out)
            inventory["advisories"]["osv_universal"] = osv_data
            if "results" not in osv_data:
                has_failures = True
            else:
                osv_cargo_count = 0
                osv_pypi_count = 0
                vulns_found = False
                
                for result in osv_data.get("results", []):
                    src_path = result.get("source", {}).get("path", "")
                    pkgs = result.get("packages", [])
                    if "Cargo.lock" in src_path: osv_cargo_count += len(pkgs)
                    elif "requirements.lock" in src_path: osv_pypi_count += len(pkgs)
                        
                    for pkg in pkgs:
                        for vuln in pkg.get("vulnerabilities", []):
                            is_info = False
                            if vuln.get("database_specific", {}).get("informational") == "unmaintained": is_info = True
                            for aff in vuln.get("affected", []):
                                if aff.get("database_specific", {}).get("informational") == "unmaintained": is_info = True
                            if not is_info:
                                vulns_found = True
                
                if osv_cargo_count != expected_cargo_count:
                    print(f"ERROR: OSV PyPI count ({osv_cargo_count}) != expected graph ({expected_cargo_count}).", file=sys.stderr)
                    has_failures = True
                if osv_pypi_count != expected_pypi_count:
                    print(f"ERROR: OSV Cargo count ({osv_pypi_count}) != expected graph ({expected_pypi_count}).", file=sys.stderr)
                    has_failures = True
                if vulns_found:
                    has_failures = True
        except json.JSONDecodeError: has_failures = True
    else: has_failures = True

    with open("runtime_inventory.json", "w") as f: json.dump(inventory, f, indent=2)
    if has_failures:
        print("ERROR: Scanners failed, timed out, or missed expected coverage graphs.", file=sys.stderr)
        sys.exit(1)
    print("SUCCESS: Inventory verified.")
    sys.exit(0)

if __name__ == "__main__":
    main()