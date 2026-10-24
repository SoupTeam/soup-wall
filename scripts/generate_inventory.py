import subprocess
import json
import datetime
import sys
import argparse
import os
import hashlib

MAX_OUTPUT_BYTES = 10 * 1024
DEFAULT_TIMEOUT = 60

def run_cmd(cmd_list, timeout=DEFAULT_TIMEOUT, allowed_exit_codes=(0,)):
    try:
        result = subprocess.run(
            cmd_list, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        
        stdout = result.stdout[:MAX_OUTPUT_BYTES].strip()
        stderr = result.stderr[:MAX_OUTPUT_BYTES].strip()
        
        if result.returncode not in allowed_exit_codes:
            return {
                "status": "failed", 
                "exit_code": result.returncode, 
                "stdout": stdout, 
                "stderr": stderr
            }
            
        return {"status": "success", "stdout": stdout, "exit_code": result.returncode}
        
    except subprocess.TimeoutExpired as e:
        return {
            "status": "timeout", 
            "error": f"Command exceeded {timeout}s",
            "stdout": e.stdout.decode('utf-8', errors='ignore')[:MAX_OUTPUT_BYTES] if e.stdout else ""
        }
    except FileNotFoundError:
        return {"status": "missing_executable", "error": f"'{cmd_list[0]}' not found"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def compute_sha256(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, help="Path to the accepted pilot receipt JSON")
    args = parser.parse_args()

    try:
        with open(args.receipt, 'r') as f:
            receipt = json.load(f)
    except Exception as e:
        print(f"FAILED to read receipt {args.receipt}: {e}", file=sys.stderr)
        sys.exit(1)

    if not receipt:
        print("ERROR: Receipt is empty.", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    receipt_dir = os.path.dirname(args.receipt) or "."
    
    inventory = {
        "metadata": {
            "timestamp": timestamp,
            "receipt_source": args.receipt,
            "commit": run_cmd(["git", "rev-parse", "HEAD"]).get("stdout", "unknown")
        },
        "receipt_verification": {},
        "advisories": {},
        "licenses": {}
    }

    has_failures = False

    # 1. File Digest Verification
    files_dict = receipt.get("files", {})
    if not files_dict:
        inventory["receipt_verification"]["status"] = "failed"
        inventory["receipt_verification"]["error"] = "No 'files' defined in receipt to verify."
        has_failures = True
    else:
        file_checks = {}
        for fname, expected_hash in files_dict.items():
            fpath = os.path.join(receipt_dir, fname)
            actual_hash = compute_sha256(fpath)
            
            if actual_hash is None:
                file_checks[fname] = {"status": "missing"}
                has_failures = True
            elif actual_hash != expected_hash:
                file_checks[fname] = {"status": "hash_mismatch", "expected": expected_hash, "actual": actual_hash}
                has_failures = True
            else:
                file_checks[fname] = {"status": "verified", "sha256": actual_hash}
        
        inventory["receipt_verification"]["files"] = file_checks
        if not has_failures:
            inventory["receipt_verification"]["status"] = "success"
        else:
            inventory["receipt_verification"]["status"] = "failed"

    # 2. Rust Security Audit
    print("Running cargo audit...")
    cargo_audit_res = run_cmd(["cargo", "audit", "--json"])
    if cargo_audit_res["status"] == "success":
        try:
            inventory["advisories"]["rust"] = json.loads(cargo_audit_res["stdout"])
        except json.JSONDecodeError:
            inventory["advisories"]["rust"] = {"status": "failed", "error": "Invalid JSON from cargo audit"}
            has_failures = True
    else:
        inventory["advisories"]["rust"] = cargo_audit_res
        has_failures = True

    # 3. Rust License Check
    print("Running cargo deny...")
    cargo_deny_res = run_cmd(["cargo", "deny", "check", "licenses"])
    if cargo_deny_res["status"] == "success":
        inventory["licenses"]["rust_status"] = "ok"
    else:
        inventory["licenses"]["rust_status"] = cargo_deny_res
        has_failures = True

    # 4. Universal OSV Scan
    print("Running OSV Scanner...")
    osv_cmd = ["osv-scanner", "-f", "json"]
    
    if os.path.exists("Cargo.lock"):
        osv_cmd.append("--lockfile=Cargo.lock")
        
    if "requirements.lock" in files_dict:
        lock_path = os.path.join(receipt_dir, "requirements.lock")
        if os.path.exists(lock_path):
            osv_cmd.append(f"--lockfile=requirements.txt:{lock_path}")

    if len(osv_cmd) == 3: 
        osv_cmd.extend(["-r", receipt_dir])

    osv_res = run_cmd(osv_cmd, allowed_exit_codes=(0, 1))
    
    if osv_res["status"] == "success":
        try:
            inventory["advisories"]["osv_universal"] = json.loads(osv_res["stdout"])
        except json.JSONDecodeError:
            inventory["advisories"]["osv_universal"] = {"status": "failed", "error": "Invalid JSON from osv-scanner"}
            has_failures = True
    else:
        inventory["advisories"]["osv_universal"] = osv_res
        has_failures = True

    output_file = "runtime_inventory.json"
    with open(output_file, "w") as f:
        json.dump(inventory, f, indent=2)
    
    print(f"Inventory saved to {output_file}")

    if has_failures:
        print("ERROR: Scanners failed, timed out, or found unresolved issues/missing coverage.", file=sys.stderr)
        sys.exit(1)
    else:
        print("SUCCESS: Inventory verified.")
        sys.exit(0)

if __name__ == "__main__":
    main()