#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit Linux operator launcher. Never accepts or retrieves an API key."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    models = parser.add_mutually_exclusive_group()
    models.add_argument("--flash-lite", action="store_true", help="Explicit separate Gemini 2.5 Flash-Lite experiment; config model must match.")
    models.add_argument("--flash-lite-35", action="store_true", help="Explicit Gemini 3.5 Flash-Lite experiment.")
    models.add_argument("--flash-lite-35-compact", action="store_true", help="Separate Gemini 3.5 Flash-Lite compact raw-quote prompt experiment; requires a fresh journal.")
    models.add_argument("--flash-lite-35-catalog", action="store_true", help="Separate Gemini 3.5 Flash-Lite exact-source quote enum experiment; requires a fresh journal.")
    models.add_argument("--flash-lite-35-coverage", action="store_true", help="Separate full-source and duplicate-tail coverage experiment; requires a fresh journal.")
    models.add_argument("--flash-lite-35-evidence", action="store_true", help="Separate note coverage and evidence-support comparison; requires a fresh journal.")
    models.add_argument("--flash-lite-35-support", action="store_true", help="Separate full-source and untrusted quotation-index comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-code-context", action="store_true", help="Separate untrusted inline-code context comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-attribution", action="store_true", help="Separate source-attribution comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-facts", action="store_true", help="Separate logical-file and diff-fact comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-grounded", action="store_true", help="Separate evidence-first source summary comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-cited", action="store_true", help="Separate action-citation and consistency comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-contextual", action="store_true", help="Separate source-context citation comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-budgeted", action="store_true", help="Separate occurrence-budgeted request-first comparison; fresh journal required.")
    models.add_argument("--flash-lite-35-anchored", action="store_true", help="Separate four-quote citation-referenced comparison; fresh journal required.")
    args = parser.parse_args()
    if sys.platform != "linux" or "CI" in os.environ:
        parser.error("Requires the operator's qualified Linux terminal; not CI.")
    # Refuse before building when there is no controlling terminal.
    try:
        with open("/dev/tty", "rb", buffering=0):
            pass
    except OSError:
        parser.error("A personal controlling terminal is required.")
    config = args.config.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    build = subprocess.run(
        ["cargo", "test", "--locked", "-p", "agentfw", "--lib", "--no-run",
         "--message-format=json"] + (["--features", "sou218-gemini35-budgeted"] if args.flash_lite_35_budgeted else ["--features", "sou218-gemini35-anchored"] if args.flash_lite_35_anchored else ["--features", "sou218-gemini35-contextual"] if args.flash_lite_35_contextual else ["--features", "sou218-gemini35-cited"] if args.flash_lite_35_cited else ["--features", "sou218-gemini35-grounded"] if args.flash_lite_35_grounded else ["--features", "sou218-gemini35-facts"] if args.flash_lite_35_facts else ["--features", "sou218-gemini35-attribution"] if args.flash_lite_35_attribution else ["--features", "sou218-gemini35-code-context"] if args.flash_lite_35_code_context else ["--features", "sou218-gemini35-support"] if args.flash_lite_35_support else ["--features", "sou218-gemini35-evidence"] if args.flash_lite_35_evidence else ["--features", "sou218-gemini35-coverage"] if args.flash_lite_35_coverage else ["--features", "sou218-gemini35-catalog"] if args.flash_lite_35_catalog else ["--features", "sou218-gemini35-compact"] if args.flash_lite_35_compact else ["--features", "sou218-gemini35-lite"] if args.flash_lite_35 else ["--features", "sou218-gemini25-lite"] if args.flash_lite else []), cwd=root, stdout=subprocess.PIPE, text=True,
        check=True,
    )
    binaries = []
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if (item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "agentfw"
                and item.get("profile", {}).get("test") and item.get("executable")):
            binaries.append(item["executable"])
    if len(binaries) != 1:
        raise SystemExit("Expected exactly one agentfw library test executable.")
    env = dict(os.environ)
    env["SOUP_WALL_GEMINI_MANUAL_CONFIG"] = str(config)
    # Inherit terminal streams: never capture, forward or persist the key.
    result = subprocess.run([
        binaries[0], "pilot-launch",
        "native::consumer::gemini_fixture::controller::operator::manual_public_gemini_operator",
        "--ignored", "--exact", "--nocapture", "--test-threads=1",
    ], cwd=root, env=env)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
