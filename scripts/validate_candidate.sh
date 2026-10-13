#!/bin/bash
set -euo pipefail

RECORD=$1
MANIFEST=$2

if [ ! -f "$RECORD" ]; then
  echo "CRITICAL: Missing acceptance record ($RECORD)"
  exit 1
fi

DECISION=$(jq -r '.decision // "none"' "$RECORD")
if [ "$DECISION" != "approved" ]; then
  echo "CRITICAL: Candidate unapproved (decision: $DECISION)"
  exit 1
fi

for gate in product operator license; do
  STATUS=$(jq -r ".gates.${gate} // \"missing\"" "$RECORD")
  if [ "$STATUS" != "passed" ]; then
    echo "CRITICAL: Required gate '$gate' is '$STATUS' (must be 'passed')"
    exit 1
  fi
done

EVIDENCE=$(jq -r '.evidence_ref // "none"' "$RECORD")
if [ "$EVIDENCE" == "none" ] || [ -z "$EVIDENCE" ]; then
  echo "CRITICAL: Missing reviewed evidence reference"
  exit 1
fi

REC_SHA=$(jq -r '.source_sha' "$RECORD")
MAN_SHA=$(jq -r '.source_sha' "$MANIFEST")
if [ "$REC_SHA" != "$MAN_SHA" ]; then
  echo "CRITICAL: Source SHA mismatch! Expected $MAN_SHA, got $REC_SHA"
  exit 1
fi

# Inventory integrity checks
ARCHIVE_COUNT=$(jq -r '[.checksums[] | select(endswith(".tar.gz") or endswith(".zip"))] | length' "$MANIFEST")
SBOM_COUNT=$(jq -r '[.checksums[] | select(endswith(".cdx.json"))] | length' "$MANIFEST")
IMAGE_COUNT=$(jq -r '[.checksums[] | select(endswith("soup-wall-image.tar"))] | length' "$MANIFEST")

if [ "$ARCHIVE_COUNT" -lt 4 ]; then
  echo "CRITICAL: Missing platform archives in candidate (found $ARCHIVE_COUNT, expected 4)"
  exit 1
fi
if [ "$SBOM_COUNT" -lt 6 ]; then
  echo "CRITICAL: Missing SBOMs in candidate (found $SBOM_COUNT, expected 6)"
  exit 1
fi
if [ "$IMAGE_COUNT" -lt 1 ]; then
  echo "CRITICAL: Missing OCI image in candidate"
  exit 1
fi

REC_HASHES=$(jq -c '.checksums | sort' "$RECORD")
MAN_HASHES=$(jq -c '.checksums | sort' "$MANIFEST")
if [ "$REC_HASHES" != "$MAN_HASHES" ]; then
  echo "CRITICAL: Artifact checksums mismatch!"
  exit 1
fi

echo "SUCCESS: Product acceptance validated for exact complete candidate."