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

REC_HASHES=$(jq -c '.checksums | sort' "$RECORD")
MAN_HASHES=$(jq -c '.checksums | sort' "$MANIFEST")
if [ "$REC_HASHES" != "$MAN_HASHES" ]; then
  echo "CRITICAL: Artifact checksums mismatch (including OCI image identity)!"
  exit 1
fi

echo "SUCCESS: Product acceptance validated for exact candidate."