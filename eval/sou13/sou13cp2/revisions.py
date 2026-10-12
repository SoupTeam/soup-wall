"""Integration of the 2026-10-10 technical review of CP1 (and relayed contract clarifications) into CP2.

CP1 files are never modified. For every CP1-derived record CP2 adds:
  evaluation          how the record may be used in evaluation (role, semantic-accuracy eligibility, pilot export)
  technical_reviews   the imported review decision for this record, with reviewer type and source digests
A record whose labels the review asked to revise becomes a `cp1_record_revised` record: the same id, every
change listed with its before/after value, and the original CP1 record recoverable from the change list
(its sha256 is checked against `cp1_record_sha256`).

Nothing here confirms a label. The review is an AI-assisted technical review (not human confirmation) and
the contract clarifications were relayed by the task owner, not supplied as a signed record."""
import copy
import csv
import io
import json

from sou13.hashing import sha
from sou13.labels import ACTIONS

from . import ROOT

REVIEW_DIR = 'cp2/review/technical_review_KAZDANTOK_2026-10-10'
REVIEW_CSV = 'DEV16_REVIEW_QUEUE_TECHNICAL.csv'
REVIEW_KIND = 'ai_assisted_technical_review_not_human_confirmation'
REVIEW_REF = 'technical review for @KAZDANTOK, 2026-10-10 (REVIEW_REPORT.txt)'
CLARIFICATION_REF = ('contract clarification by @Nari_Ab as relayed by the SOU-13 task owner on 2026-10-10; '
                     'no signed record of it is in the repository')
CP2_DATASET_VERSION = '0.4-cp2-candidate'
ROLES = ('classification', 'technical_error_check', 'admission_rejection_test', 'set_valued_oracle')

# Records whose evaluation role is not plain classification (labels unchanged unless listed in REVISIONS).
EVALUATION_OVERRIDES = {
    'S13V03-DEV-09': {
        'role': 'admission_rejection_test', 'in_semantic_accuracy': False, 'expected_admission': 'rejected',
        'reason': 'Unadmitted identity: admission refusal is a separate test, not an unknown classification. The '
                  'classification example is replaced by an admitted opaque fixture (fam.unknown.workspace_tidy).',
        'policy_source': [REVIEW_REF, CLARIFICATION_REF]},
    'S13V03-SUP-S2': {
        'role': 'technical_error_check', 'in_semantic_accuracy': False,
        'reason': 'Invalid object-argument profile -> classifier_invalid before policy; outside semantic accuracy.',
        'policy_source': [REVIEW_REF]},
    'S13V03-SUP-S3': {
        'role': 'set_valued_oracle', 'in_semantic_accuracy': False,
        'accepted_outputs': [{'name': 'retain_recognized', 'actions': ['read'], 'unknown': True},
                             {'name': 'full_abstention', 'actions': [], 'unknown': True}],
        'retained_recognized_actions': ['read'],
        'coverage_tracking': 'report abstention coverage and retained recognized actions separately from accuracy',
        'policy_status': 'pending_formal_acceptance',
        'reason': 'D05/§5.3 accepts either retaining the safely recognized read or full abstention; both require '
                  'unknown=true. Gold labels are unchanged; no false label is introduced.',
        'policy_source': [REVIEW_REF, CLARIFICATION_REF]},
}


def evaluation_for(record):
    """Evaluation metadata. Pilot export = plain classification with a provisional label only."""
    rid = record['id']
    if rid in EVALUATION_OVERRIDES:
        ev = copy.deepcopy(EVALUATION_OVERRIDES[rid])
    elif record['expected_outcome'] == 'technical_error':
        ev = {'role': 'technical_error_check', 'in_semantic_accuracy': False,
              'reason': 'technical-error record; outside semantic accuracy'}
    else:
        ev = {'role': 'classification', 'in_semantic_accuracy': True,
              'reason': 'classification record' + ('' if record['label_status'] == 'provisional'
                                                   else f" ({record['label_status']}: excluded from the pilot export)")}
    ev['in_pilot_export'] = ev['role'] == 'classification' and record['label_status'] == 'provisional'
    return ev


def _review_provenance(root):
    return json.loads((root / REVIEW_DIR / 'IMPORT_PROVENANCE.json').read_text(encoding='utf-8'))


def technical_reviews(root=ROOT):
    """{case_id: [review entry]} from the imported review queue (empty dict if the review is not imported)."""
    p = root / REVIEW_DIR / REVIEW_CSV
    if not p.exists():
        return {}
    prov = _review_provenance(root)
    out = {}
    for row in csv.DictReader(io.StringIO(p.read_bytes().decode('utf-8-sig'))):
        out[row['case_id']] = [{
            'review_kind': REVIEW_KIND, 'reviewer': row['reviewer_name'], 'requested_by': '@KAZDANTOK',
            'decision': row['overall_decision_accept_revise_pending'],
            'label_decisions': {**{a: row[f'{a}_decision'] for a in ACTIONS}, 'unknown': row['unknown_decision']},
            'evidence_confirmed': row['evidence_confirmed_Y_N'], 'notes': row['disagreement_notes'],
            'alternative_interpretation': row['alternative_interpretation'], 'reviewed_at': row['review_timestamp'],
            'source_file_sha256': prov['files_sha256'][REVIEW_CSV],
            'source_archive_sha256': prov['source_archive_sha256'],
            'confirms_labels': False}]
    return out


# ---- label revisions requested by the review ------------------------------------------------------------------
_ABSENT = {'__absent__': True}


def _get(d, path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return _ABSENT
        d = d[k]
    return d


def _set(d, path, value):
    for k in path[:-1]:
        d = d[k]
    if value == _ABSENT:
        d.pop(path[-1], None)
    else:
        d[path[-1]] = copy.deepcopy(value)


def _revise_s1(r):
    """SUP-S1: an offline declaration for an opaque, unexecuted summariser is not an enforced network boundary,
    so send_data is not established (null). The observed read and unknown=true are kept; forbidden_actions
    (an unapproved SOU-13 convention) is dropped. Nothing becomes a known negative."""
    comp = r['evidence']['execution']['opaque_component']
    a = r['annotation']
    return {
        ('dataset_version',): CP2_DATASET_VERSION,
        ('annotation', 'per_action_targets', 'send_data'): None,
        ('annotation', 'known_mask', 'send_data'): 0,
        ('annotation', 'label_evidence', 'send_data'): {
            'value': None, 'basis': 'opaque_component', 'strength': 'not_established',
            'refs': [f'opaque:{comp}', 'technical review 2026-10-10: offline declaration is not an enforced '
                                       'network boundary; send_data not established']},
        ('annotation', 'forbidden_actions'): _ABSENT,
        ('annotation', 'contract_rules'): [x for x in a['contract_rules'] if 'forbidden_actions' not in x],
        ('annotation', 'rationale'): ('Чтение документа установлено трассой; summariser — непрозрачный компонент, не '
                                      'исполнялся. Объявление «нет сети» не является принудительной сетевой границей, '
                                      'поэтому send_data не установлен (null), как и write/delete/change_permissions; '
                                      'unknown=true (§3.1, D01). forbidden_actions не используется (ревизия по '
                                      'техническому ревью 2026-10-10).'),
        ('scenario_tags',): [t for t in r['scenario_tags'] if t not in ('known_negative_under_unknown',
                                                                        'forbidden_actions')],
        ('evidence_strength',): 'execution+not_established',
        ('open_questions',): ['Q-ADMISSION', 'Q-CP2-REVIEW-ADOPTION'],
    }


REVISIONS = {'S13V03-SUP-S1': (_revise_s1, 'technical review 2026-10-10 decision "revise" (send_data=null; '
                                           'no forbidden_actions); status stays pending until the owner adopts it')}


def revise(cp1_record):
    """(revised record without CP2 fields, revision metadata) or (None, None) if the record is not revised."""
    if cp1_record['id'] not in REVISIONS:
        return None, None
    fn, reason = REVISIONS[cp1_record['id']]
    out = copy.deepcopy(cp1_record)
    changes = []
    for path, after in sorted(fn(cp1_record).items()):
        before = _get(cp1_record, path)
        if before == after:
            continue
        _set(out, path, after)
        changes.append({'path': list(path), 'before': None if before == _ABSENT else before,
                        'before_absent': before == _ABSENT, 'after': None if after == _ABSENT else after,
                        'after_absent': after == _ABSENT})
    return out, {'changes': changes, 'reason': reason, 'basis': [REVIEW_REF], 'confirms_labels': False}


def revision_errors(record, cp2_fields):
    """The original CP1 record must be exactly recoverable from the change list."""
    src = record['source_material']
    current = {k: v for k, v in record.items() if k not in cp2_fields}
    original = copy.deepcopy(current)
    e = []
    for ch in src['revision']['changes']:
        path = tuple(ch['path'])
        now = _get(current, path)
        expected_now = _ABSENT if ch['after_absent'] else ch['after']
        if now != expected_now:
            e.append(f'revision change {path} not reflected in the record')
        _set(original, path, _ABSENT if ch['before_absent'] else ch['before'])
    if sha(original) != src['cp1_record_sha256']:
        e.append('revision does not reconstruct the CP1 record (undeclared change or wrong before-values)')
    if record['id'] not in REVISIONS:
        e.append('record is marked revised but no revision is declared for it')
    return e
