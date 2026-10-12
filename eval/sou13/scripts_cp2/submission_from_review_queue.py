#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Transcribe the independent reviewer's completed CP2 review queue into a reviewer submission (owner only).

  python scripts_cp2/submission_from_review_queue.py --queue CANDIDATE_REVIEW_QUEUE.csv --exports DIR \
      --reviewer NAME --decision-id ID --submitted-at YYYY-MM-DD [--expect-cases N] --out reviewer_submission.json

--queue is the queue as completed and returned by the reviewer. DIR is the CP2 export directory whose frozen
label rows the queue's proposed values must equal. --reviewer, --decision-id and --submitted-at are copied from
the reviewer's recorded decision; they are never defaulted. --expect-cases fails the run unless exactly N cases
were accepted. See sou13gold/review_queue.py for the transcription rules. The output must lie outside every Git
work tree and is never overwritten. Only counts and digests are printed; no label values.
Exit status 1 on any error.
"""
import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # never leave generated files in the checkout
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.hashing import file_sha, sha  # noqa: E402
from sou13gold.addendum import AddendumError, placeholder_errors  # noqa: E402
from sou13gold.cli import emit  # noqa: E402
from sou13gold.draft import SUBMISSION_SCHEMA  # noqa: E402
from sou13gold.files import GoldFileError, dumps, read_export, write_new  # noqa: E402
from sou13gold.review_queue import transcribe  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--queue', type=Path, required=True)
    ap.add_argument('--exports', type=Path, required=True)
    ap.add_argument('--reviewer', required=True)
    ap.add_argument('--decision-id', required=True)
    ap.add_argument('--submitted-at', required=True)
    ap.add_argument('--expect-cases', type=int)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args(argv)
    _, rows, _, errors = read_export(args.exports)
    errors += placeholder_errors('reviewer decision', {'decision_id': args.decision_id, 'approver': args.reviewer,
                                                       'statement': 'given'})
    if errors:
        emit({'result': 'FAIL', 'errors': errors})
        return 1
    try:
        submission, report = transcribe(args.queue.read_text(encoding='utf-8-sig'), rows, args.reviewer,
                                        args.decision_id, args.submitted_at)
        from sou13cp2.schemas import errors as schema_errors
        e = [f'submission: schema: {x}' for x in schema_errors(submission, SUBMISSION_SCHEMA)]
        if args.expect_cases is not None and report['accepted_cases'] != args.expect_cases:
            e.append(f'{report["accepted_cases"]} accepted cases, expected exactly {args.expect_cases}')
        if e:
            raise AddendumError(e)
        write_new(args.out, dumps(submission))
    except (AddendumError, GoldFileError) as exc:
        emit({'result': 'FAIL', 'errors': getattr(exc, 'errors', [str(exc)])})
        return 1
    emit({'result': 'WRITTEN', 'out': args.out.name, 'queue_sha256': file_sha(args.queue),
          'submission_sha256': sha(submission), **report})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
