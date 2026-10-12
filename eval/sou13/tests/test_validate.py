import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sou13.build import (FREEZE, QUEUE, check_arguments, definition_hash, freeze_reproducibility_view,  # noqa: E402
                         input_errors, write_all)
from sou13.cases import CONTRACT  # noqa: E402
from sou13.hashing import file_sha, sha  # noqa: E402
from sou13.validate import open_question_ids, record_errors, validate  # noqa: E402
from _testsupport import CP1_DATA, CP1_FREEZE, CP1_REVIEW, OPEN_QUESTIONS, requires  # noqa: E402

SCHEMA = json.loads((ROOT / 'schema' / 'case.schema.json').read_text(encoding='utf-8'))


def load(rel):
    return [json.loads(x) for x in (ROOT / rel).read_text(encoding='utf-8').splitlines() if x.strip()]


@requires(CP1_DATA, CP1_FREEZE, CP1_REVIEW, OPEN_QUESTIONS)
class RepositoryArtifacts(unittest.TestCase):
    def test_validator_passes_on_committed_artifacts(self):
        report = validate(ROOT)
        self.assertEqual(report['result'], 'PASS', report['errors'])
        self.assertEqual(report['counts']['pending'], ['S13V03-SUP-S1', 'S13V03-SUP-S3'])
        self.assertEqual(report['counts']['confirmed'], 0)
        self.assertEqual(report['counts']['review_rows_with_decisions'], 0)

    def test_records_match_schema_top_level(self):
        for r in load('data/dev16.jsonl') + load('data/dev_supplementary.jsonl'):
            self.assertEqual(set(r), set(SCHEMA['required']))

    def test_rebuild_reproduces_byte_identical_files(self):
        freeze = json.loads((ROOT / FREEZE).read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as tmp:
            write_all(tmp)
            for rel, digest in freeze['files_sha256'].items():
                self.assertEqual(file_sha(Path(tmp) / rel), digest, rel)
            rebuilt = json.loads((Path(tmp) / FREEZE).read_text(encoding='utf-8'))
            # Everything except build-environment provenance must match exactly.
            self.assertEqual(freeze_reproducibility_view(rebuilt), freeze_reproducibility_view(freeze))
            self.assertRegex(rebuilt['built_with_python'], r'^3\.\d+\.\d+')

    def test_reproducibility_view_ignores_only_provenance(self):
        freeze = json.loads((ROOT / FREEZE).read_text(encoding='utf-8'))
        other_python = {**freeze, 'built_with_python': '3.13.5'}
        self.assertEqual(freeze_reproducibility_view(other_python), freeze_reproducibility_view(freeze))
        for field, value in [('files_sha256', {**freeze['files_sha256'], 'data/dev16.jsonl': '0' * 64}),
                             ('source_sha256_lf_normalised', {**freeze['source_sha256_lf_normalised'], 'sou13/x.py': 'y'}),
                             ('contract', {**freeze['contract'], 'sha256': '0' * 64}),
                             ('counts', {**freeze['counts'], 'confirmed': 1})]:
            changed = {**freeze, field: value}
            self.assertNotEqual(freeze_reproducibility_view(changed), freeze_reproducibility_view(freeze), field)

    def test_review_queue_fields_blank(self):
        text = (ROOT / QUEUE).read_bytes().decode('utf-8-sig')
        self.assertEqual(len(text.strip().splitlines()), 1 + 19)


@requires(CP1_DATA, OPEN_QUESTIONS)
class TamperDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oq = open_question_ids(ROOT)
        cls.rec = load('data/dev16.jsonl')[0]

    def errs(self, mutate):
        r = copy.deepcopy(self.rec)
        mutate(r)
        return record_errors(r, self.oq)

    def test_clean_record_has_no_errors(self):
        self.assertEqual(record_errors(self.rec, self.oq), [])

    def test_fake_confirmed_rejected(self):
        self.assertTrue(self.errs(lambda r: r.update(label_status='confirmed')))

    def test_confirmed_by_annotator_rejected(self):
        def m(r):
            r['label_status'] = 'confirmed'
            r['review'].update(reviewer=r['review']['annotator'], reviewed_at='2026-10-10T12:00+05:00', decision='accept')
        self.assertTrue(self.errs(m))

    def test_review_fields_without_status_rejected(self):
        self.assertTrue(self.errs(lambda r: r['review'].update(reviewer='someone')))

    def test_label_flip_rejected(self):
        self.assertTrue(self.errs(lambda r: r['annotation']['per_action_targets'].update(write=True)))

    def test_mask_tamper_rejected(self):
        self.assertTrue(self.errs(lambda r: r['annotation']['known_mask'].update(write=0)))

    def test_input_tamper_rejected(self):
        self.assertTrue(self.errs(lambda r: r['input'].update(tool_description='changed')))

    def test_evidence_tamper_rejected(self):
        self.assertTrue(self.errs(lambda r: r['evidence']['execution']['unexplained'].append('x')))

    def test_non_train_split_rejected(self):
        self.assertTrue(self.errs(lambda r: r.update(split='test')))

    def test_pending_without_documented_question_rejected(self):
        def m(r):
            r['label_status'] = 'pending'
            r['open_questions'] = ['Q-DOES-NOT-EXIST']
        self.assertTrue(self.errs(m))

    def test_forbidden_actions_must_stay_pending(self):
        s1 = [r for r in load('data/dev_supplementary.jsonl') if r['id'] == 'S13V03-SUP-S1'][0]
        self.assertEqual(record_errors(s1, self.oq), [])
        s1['label_status'] = 'provisional'
        self.assertTrue(record_errors(s1, self.oq))

    def test_obsolete_contract_binding_rejected(self):
        # Any digest other than the current contract's must be rejected; a visibly synthetic one stands in for
        # an obsolete contract (no specific historical contract is implied).
        obsolete = hashlib.sha256(b'obsolete-contract-fixture').hexdigest()
        self.assertNotEqual(obsolete, CONTRACT['sha256'])
        errors = self.errs(lambda r: r['contract'].update(sha256=obsolete))
        self.assertTrue(errors)
        self.assertTrue(any('contract reference mismatch' in e for e in errors), errors)

    def test_obsolete_section_reference_rejected(self):
        self.assertTrue(self.errs(lambda r: r['annotation']['contract_rules'].append('§4.6')))

    def test_semantics_not_from_registry_rejected(self):
        def m(r):
            r['input']['server_id'] = 'impostor-server'
            r['hashes']['input_sha256'] = sha(r['input'])
            r['hashes']['definition_sha256'] = definition_hash(r['input'])
        self.assertTrue(any('admitted-tool registry' in x for x in self.errs(m)))

    def test_tampered_file_fails_whole_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            for sub in ('data', 'review', 'docs'):
                shutil.copytree(ROOT / sub, Path(tmp) / sub)
            p = Path(tmp) / 'data' / 'dev16.jsonl'
            p.write_bytes(p.read_bytes().replace(b'"read": true', b'"read": false', 1))
            report = validate(tmp)
            self.assertEqual(report['result'], 'FAIL')


class InputProfile(unittest.TestCase):
    """SOU-10 §1.2: description optional/null, pinned_schema and server_id optional; malformed input rejected."""
    BASE = {'tool_name': 'fetch_url', 'tool_schema': {'type': 'object', 'properties': {'url': {'type': 'string'}},
                                                      'required': ['url'], 'additionalProperties': False},
            'raw_arguments': {'url': 'https://status.example.test/x'}}

    def ok(self, **changes):
        inp = {**self.BASE, **changes}
        return input_errors(inp) + check_arguments(inp)

    def test_minimal_input_accepted(self):
        self.assertEqual(self.ok(), [])

    def test_optional_fields_accepted(self):
        self.assertEqual(self.ok(tool_description=None), [])
        self.assertEqual(self.ok(tool_description='text'), [])
        self.assertEqual(self.ok(server_id='synthetic-statuspage'), [])
        self.assertEqual(self.ok(pinned_schema=self.BASE['tool_schema']), [])

    def test_malformed_input_rejected(self):
        self.assertTrue(self.ok(tool_name=''))
        self.assertTrue(self.ok(tool_name=None))
        self.assertTrue(self.ok(tool_description=7))
        self.assertTrue(self.ok(server_id=''))
        self.assertTrue(self.ok(pinned_schema='not-a-schema'))
        self.assertTrue(self.ok(extra_field=1))
        self.assertTrue(input_errors({k: v for k, v in self.BASE.items() if k != 'tool_schema'}))

    def test_object_profile_rejects_null_and_schema_violations(self):
        self.assertTrue(self.ok(raw_arguments=None))
        self.assertTrue(self.ok(raw_arguments={'url': 5}))
        self.assertTrue(self.ok(raw_arguments={'url': 'u', 'more': 1}))
        strict = {'type': 'object', 'properties': {'url': {'type': 'string'}}, 'required': ['url', 'tag'],
                  'additionalProperties': False}
        self.assertTrue(self.ok(pinned_schema=strict))  # arguments must satisfy pinned_schema too


if __name__ == '__main__':
    unittest.main()
