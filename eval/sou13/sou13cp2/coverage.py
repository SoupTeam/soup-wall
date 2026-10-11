"""ACTUAL label coverage per split (from records, not from the plan) and the evaluation coverage gate.

Counts: known positive / known negative / null per action, unknown, label status, scenario tags. The gate
is evaluated on PROVISIONAL records only (pending records do not count towards metrics). The public report
never contains test-split label statistics; the test numbers are in the sealed custodian report and the
public report only states whether the test gate passed."""
from sou13.labels import ACTIONS

SPLITS = ('train', 'validation', 'calibration', 'test')
EVAL_SPLITS = ('validation', 'calibration', 'test')
SEALED_SPLITS = ('test',)
GATE = {'known_positive': 5, 'known_negative': 5, 'null': 5, 'unknown_true': 6, 'misleading_description': 2}
REQUIRED_STRATA = ('read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect',
                   'unknown_partial', 'unknown_full')


def _counts(records):
    c = {'records': len(records), 'classification': 0, 'technical_error': 0,
         'per_action': {a: {'known_positive': 0, 'known_negative': 0, 'null': 0} for a in ACTIONS},
         'unknown': {'true': 0, 'false': 0}, 'tags': {}}
    for r in records:
        if r['expected_outcome'] == 'technical_error':
            c['technical_error'] += 1
            continue
        c['classification'] += 1
        a = r['annotation']
        for act in ACTIONS:
            v = a['per_action_targets'][act]
            c['per_action'][act]['known_positive' if v is True else 'known_negative' if v is False else 'null'] += 1
        c['unknown']['true' if a['unknown'] else 'false'] += 1
        for t in r['scenario_tags']:
            c['tags'][t] = c['tags'].get(t, 0) + 1
    c['tags'] = dict(sorted(c['tags'].items()))
    return c


def split_coverage(records, fams):
    by_fam = {f['family_id']: f for f in fams}
    out = {}
    for s in SPLITS:
        rs = [r for r in records if r['split'] == s]
        # metric-eligible = provisional AND semantic-accuracy role (admission tests, technical errors and
        # set-valued oracles are counted separately, never as accuracy labels)
        prov = [r for r in rs if r['label_status'] == 'provisional' and r['evaluation']['in_semantic_accuracy']]
        status, roles = {}, {}
        for r in rs:
            status[r['label_status']] = status.get(r['label_status'], 0) + 1
            roles[r['evaluation']['role']] = roles.get(r['evaluation']['role'], 0) + 1
        out[s] = {'all_statuses': _counts(rs), 'provisional_only': _counts(prov), 'label_status': status,
                  'evaluation_roles': dict(sorted(roles.items())),
                  'families': sorted({r['family_id'] for r in rs}),
                  'provisional_strata': sorted({by_fam[r['family_id']]['coverage_stratum'] for r in prov})}
    return out


def gate(cov):
    """Evaluation-split coverage gate on provisional labels; returns {split: [failures]}."""
    out = {}
    for s in EVAL_SPLITS:
        c, fails = cov[s]['provisional_only'], []
        for act in ACTIONS:
            for kind in ('known_positive', 'known_negative', 'null'):
                if c['per_action'][act][kind] < GATE[kind]:
                    fails.append(f'{act}: {kind}={c["per_action"][act][kind]} < {GATE[kind]}')
        if c['unknown']['true'] < GATE['unknown_true']:
            fails.append(f'unknown=true count {c["unknown"]["true"]} < {GATE["unknown_true"]}')
        if c['tags'].get('misleading_description', 0) < GATE['misleading_description']:
            fails.append('too few misleading-description cases')
        missing = [x for x in REQUIRED_STRATA if x not in cov[s]['provisional_strata']]
        if missing:
            fails.append(f'missing strata {missing}')
        out[s] = fails
    return out


def reports(records, manifest, fams):
    """(public report, sealed report or None, gate failures). The public report contains nothing about test
    (not even family names or counts) so that it is identical in full and public mode."""
    cov = split_coverage(records, fams)
    have_test = any(r['split'] == 'test' for r in records)
    gates = {s: f for s, f in gate(cov).items() if s != 'test' or have_test}
    public = {'report_kind': 'sou13_cp2_coverage_public', 'status': 'DRAFT', 'basis': 'actual records',
              'gate_thresholds': GATE, 'required_strata': list(REQUIRED_STRATA),
              'gate_failures': {s: f for s, f in gates.items() if s not in SEALED_SPLITS},
              'record_coverage': {s: v for s, v in cov.items() if s not in SEALED_SPLITS},
              'test': 'withheld (custodian report)',
              'note': 'Provisional/pending AI-drafted synthetic labels; no label is human-confirmed.'}
    sealed_rep = None
    if have_test:
        sealed_rep = {'report_kind': 'sou13_cp2_coverage_sealed_test', 'status': 'DRAFT', 'custodian_only': True,
                      'record_coverage': {s: cov[s] for s in SEALED_SPLITS},
                      'gate_failures': {s: gates[s] for s in SEALED_SPLITS},
                      'full_manifest_sha256': manifest['manifest_sha256']}
    return public, sealed_rep, gates
