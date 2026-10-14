#!/bin/bash
set -euo pipefail

RECORD=$1
MANIFEST=$2
EXPECTED_TAG=$3
EXPECTED_SHA=$4
API_CONTEXT=${5:-""}
MODE=${6:-"full"}

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

# [P2] Strict API Identity Binding (Run ID, Attempt, Artifact ID, Job Status)
if [ -n "$API_CONTEXT" ] && [ -f "$API_CONTEXT" ]; then
  REC_RUN_ID=$(jq -r '.run_id // "none"' "$RECORD")
  REC_ATTEMPT=$(jq -r '.run_attempt // "none"' "$RECORD")
  REC_ARTIFACT_ID=$(jq -r '.artifact_id // "none"' "$RECORD")

  if [ "$REC_RUN_ID" == "none" ] || [ "$REC_ATTEMPT" == "none" ] || [ "$REC_ARTIFACT_ID" == "none" ]; then
    echo "CRITICAL: Acceptance record missing run_id, run_attempt, or artifact_id"
    exit 1
  fi

  API_RUN_ID=$(jq -r '.run_id' "$API_CONTEXT")
  API_ATTEMPT=$(jq -r '.run_attempt' "$API_CONTEXT")
  API_PATH=$(jq -r '.workflow_path' "$API_CONTEXT")
  API_EVENT=$(jq -r '.event' "$API_CONTEXT")
  API_REPO=$(jq -r '.repository' "$API_CONTEXT")
  API_JOB=$(jq -r '.prepare_job_status' "$API_CONTEXT")
  API_ARTIFACT_ID=$(jq -r '.artifact_id' "$API_CONTEXT")

  if [ "$API_PATH" != ".github/workflows/release.yml" ]; then
    echo "CRITICAL: Untrusted workflow path ($API_PATH)"
    exit 1
  fi
  if [ "$API_EVENT" != "push" ] && [ "$API_EVENT" != "workflow_dispatch" ]; then
    echo "CRITICAL: Invalid preparation event ($API_EVENT)"
    exit 1
  fi
  if [ "$API_REPO" != "SoupTeam/soup-wall" ]; then
    echo "CRITICAL: Untrusted repository ($API_REPO)"
    exit 1
  fi
  if [ "$API_JOB" != "success" ]; then
    echo "CRITICAL: Prepare & Freeze Candidate job did not succeed (was $API_JOB)"
    exit 1
  fi
  if [ "$REC_RUN_ID" != "$API_RUN_ID" ]; then
    echo "CRITICAL: Run ID mismatch (Record: $REC_RUN_ID != API: $API_RUN_ID)"
    exit 1
  fi
  if [ "$REC_ATTEMPT" != "$API_ATTEMPT" ]; then
    echo "CRITICAL: Attempt mismatch (Record: $REC_ATTEMPT != API: $API_ATTEMPT)"
    exit 1
  fi
  if [ "$REC_ARTIFACT_ID" != "$API_ARTIFACT_ID" ]; then
    echo "CRITICAL: Artifact ID mismatch (Record: $REC_ARTIFACT_ID != API: $API_ARTIFACT_ID)"
    exit 1
  fi
fi

if [ "$MODE" == "api-only" ]; then
  echo "SUCCESS: API Identity strictly validated before artifact download."
  exit 0
fi

# Identity & Manifest checks
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

# Securely read jq output into a bash array
readarray -t CHECKSUM_LINES < <(jq -r '.checksums[]' "$MANIFEST")

if [ "${#CHECKSUM_LINES[@]}" -ne 11 ]; then
  echo "CRITICAL: Embedded newline detected (line count mismatch). Expected 11, got ${#CHECKSUM_LINES[@]}"
  exit 1
fi

declare -A FOUND_FILES

# [P1] Strict Single-Line Grammar & Traversal Protection
echo "Verifying exact inventory binding..."
for line in "${CHECKSUM_LINES[@]}"; do
  if [[ ! "$line" =~ ^([a-f0-9]{64})\ \ ([a-zA-Z0-9_.-]+)$ ]]; then
    echo "CRITICAL: Invalid checksum line grammar or control character detected: $line"
    exit 1
  fi

  HASH_PART="${BASH_REMATCH[1]}"
  FILE_PART="${BASH_REMATCH[2]}"

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