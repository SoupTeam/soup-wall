#!/bin/bash
set -euo pipefail

RECORD=$1
MANIFEST=$2
EXPECTED_TAG=$3
EXPECTED_SHA=$4

if [ ! -f "$RECORD" ]; then
  echo "CRITICAL: Missing acceptance record ($RECORD)"
  exit 1
fi

DECISION=$(jq -r '.decision // "none"' "$RECORD")
if [ "$DECISION" != "approved" ]; then
  echo "CRITICAL: Candidate unapproved (decision: $DECISION)"
  exit 1
fi

# SOU-26: Gate status checks
for gate in product operator license; do
  STATUS=$(jq -r ".gates.${gate} // \"missing\"" "$RECORD")
  if [ "$STATUS" != "passed" ]; then
    echo "CRITICAL: Required gate '$gate' is '$STATUS' (must be 'passed')"
    exit 1
  fi
done

# SOU-26: Evidence check
EVIDENCE=$(jq -r '.evidence_ref // "none"' "$RECORD")
if [ "$EVIDENCE" == "none" ] || [ -z "$EVIDENCE" ]; then
  echo "CRITICAL: Missing reviewed evidence reference"
  exit 1
fi

# Identity bindings checks
MAN_TAG=$(jq -r '.tag' "$MANIFEST")
if [ "$MAN_TAG" != "$EXPECTED_TAG" ]; then
  echo "CRITICAL: Manifest tag ($MAN_TAG) does not match expected workflow tag ($EXPECTED_TAG)"
  exit 1
fi

MAN_SHA=$(jq -r '.source_sha' "$MANIFEST")
if [ "$MAN_SHA" != "$EXPECTED_SHA" ]; then
  echo "CRITICAL: Manifest source SHA ($MAN_SHA) does not match expected checkout commit ($EXPECTED_SHA)"
  exit 1
fi

REC_SHA=$(jq -r '.source_sha' "$RECORD")
if [ "$REC_SHA" != "$MAN_SHA" ]; then
  echo "CRITICAL: Source SHA mismatch! Expected $MAN_SHA, got $REC_SHA"
  exit 1
fi

# Exact Inventory Enforcement
EXPECTED_FILENAMES=(
  "soup-wall-${MAN_TAG}-x86_64-unknown-linux-gnu.tar.gz"
  "soup-wall-${MAN_TAG}-aarch64-apple-darwin.tar.gz"
  "soup-wall-${MAN_TAG}-x86_64-apple-darwin.tar.gz"
  "soup-wall-${MAN_TAG}-x86_64-pc-windows-msvc.zip"
  "soup-wall-core.cdx.json"
  "soup-wall-agent.cdx.json"
  "agentfw.cdx.json"
  "soup-wall-adapter.cdx.json"
  "soup-wall-bench.cdx.json"
  "llm-firewall.cdx.json"
  "soup-wall-image.tar"
)

TOTAL_FOUND=$(jq -r '.checksums | length' "$MANIFEST")
if [ "$TOTAL_FOUND" -ne 11 ]; then
  echo "CRITICAL: Candidate must contain exactly 11 distinct artifacts, found $TOTAL_FOUND"
  exit 1
fi

# Securely read jq output into a bash array.
# If an attacker injects an embedded \n inside a JSON string, jq -r expands it,
# creating >11 elements in this Bash array, which we immediately catch.
readarray -t CHECKSUM_LINES < <(jq -r '.checksums[]' "$MANIFEST")

if [ "${#CHECKSUM_LINES[@]}" -ne 11 ]; then
  echo "CRITICAL: Embedded newline detected (line count mismatch). Expected 11, got ${#CHECKSUM_LINES[@]}"
  exit 1
fi

declare -A FOUND_FILES

# [P1] Strict Single-Line Grammar & Traversal Protection
echo "Verifying exact inventory binding..."
for line in "${CHECKSUM_LINES[@]}"; do
  # Require exact canonical filename format, single line, no spaces/specials in filename
  if [[ ! "$line" =~ ^([a-f0-9]{64})\ \ ([a-zA-Z0-9_.-]+)$ ]]; then
    echo "CRITICAL: Invalid checksum line grammar or control character detected: $line"
    exit 1
  fi

  HASH_PART="${BASH_REMATCH[1]}"
  FILE_PART="${BASH_REMATCH[2]}"

  # Reject unsafe paths (directory traversal, absolute paths)
  if [[ "$FILE_PART" == *"/"* ]] || [[ "$FILE_PART" == *"\\"* ]] || [[ "$FILE_PART" == *".."* ]]; then
    echo "CRITICAL: Non-canonical unsafe path detected: $FILE_PART"
    exit 1
  fi

  if [ ! -f "$FILE_PART" ] || [ -L "$FILE_PART" ]; then
    echo "CRITICAL: Missing, non-regular, or symlink artifact: $FILE_PART"
    exit 1
  fi

  FOUND_FILES["$FILE_PART"]="$HASH_PART"
done

# Ensure every expected canonical file was present and mapped
for expected_file in "${EXPECTED_FILENAMES[@]}"; do
  if [[ -z "${FOUND_FILES[$expected_file]:-}" ]]; then
    echo "CRITICAL: Missing required canonical file exact match: $expected_file"
    exit 1
  fi
done

REC_HASHES=$(jq -c '.checksums | sort' "$RECORD")
MAN_HASHES=$(jq -c '.checksums | sort' "$MANIFEST")
if [ "$REC_HASHES" != "$MAN_HASHES" ]; then
  echo "CRITICAL: Artifact checksums mismatch!"
  exit 1
fi

echo "SUCCESS: Product acceptance validated for exact complete candidate."