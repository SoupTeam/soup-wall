"""Pool-bound semantic decision register. Recorded decisions are NOT authenticated signatures.

The register is private custodian material. Only an externally verifiable human decision may
be entered as ``accepted``. This file is NOT a Gold addendum and does not promote labels.

Two formats are recognised. ``v1`` (question decisions + accepted case reviews) is preserved
unchanged and still validates, but records no evidence basis, so no case is primary-eligible
under it. ``v2`` adds a per-case review status and a human evidence basis bound to the exact
record digest and the record inventory; it is required for primary scoring.

Evidence strata (``evidence_stratum``) are the single source of truth for primary scoring,
split coverage and export. They are computed only from a ``Ledger``: an immutable snapshot that
``load``/``validate`` build after the complete register has passed validation against the pool
and the exact record inventory. A raw register dict is refused, so no unvalidated register can
be represented as primary evidence. Every basis describes SYNTHETIC evidence: no SOU-35 case executes
a real tool, so ``interface_supported`` never means observed real-tool or MCP behaviour.
"""
import copy
import datetime
import re

from . import adapters, custody

VERSION_V1 = 'sou35-semantic-rulings-v1'
VERSION_V2 = 'sou35-semantic-rulings-v2'
VERSION = VERSION_V1  # historical name; new registers use VERSION_V2
SCOPE = 'sou35_synthetic_candidate_pool'
STATUSES = frozenset({'accepted', 'pending', 'rejected'})
ELIGIBILITY_POLICY = 'sou35-strata-v1'
# An explicitly named evaluation view, never an amendment to SOU-10 D04.
# It requires a profile-bound grouped-review import receipt. All mechanical
# ceilings, question gates, diagnostic exclusions and coverage rules still apply.
SCHEMA_SEMANTICS_POLICY = 'sou35-synthetic-schema-semantics-v1'
ELIGIBILITY_POLICIES = frozenset({ELIGIBILITY_POLICY, SCHEMA_SEMANTICS_POLICY})

# Case-level evidence basis (v2), strongest first. All are synthetic-program evidence.
#   interface_supported  the label follows from what the classifier input exposes (identity, schema, argument
#                        values) under the accepted contract rules, confirmed by the controlled synthetic trace
#   program_only         the reviewed program determines the label but the determinant is hidden from the input
#   information_limited  neither the visible input nor the reviewed program settles the label beyond `unknown`
BASES = ('interface_supported', 'program_only', 'information_limited')
CASE_STATUSES = frozenset({'accepted', 'pending', 'rejected', 'disputed'})

PRIMARY = 'primary'
TECHNICAL = 'technical_error'
DISPUTED = 'diagnostic_disputed'
PROGRAM_ONLY = 'diagnostic_program_only'
INFORMATION_LIMITED = 'diagnostic_information_limited'
UNRESOLVED = 'unresolved_ruling'
REJECTED = 'rejected'
UNREVIEWED = 'unreviewed'
BASIS_UNRECORDED = 'basis_unrecorded'
STRATA = (PRIMARY, TECHNICAL, DISPUTED, PROGRAM_ONLY, INFORMATION_LIMITED, UNRESOLVED, REJECTED, UNREVIEWED,
          BASIS_UNRECORDED)
_BASIS_STRATUM = {'interface_supported': PRIMARY, 'program_only': PROGRAM_ONLY,
                  'information_limited': INFORMATION_LIMITED}

_AI_IDENTITY = re.compile(r'ai[\s_-]*assist|claude|gpt|codex|llm|copilot|gemini')
_ISO_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$')


class RulingsError(ValueError):
    pass


def _iso_datetime(value):
    """A real calendar date-time with an explicit offset: shape check AND datetime parsing."""
    if not isinstance(value, str) or not _ISO_TIME.match(value):
        return False
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + '+00:00' if value.endswith('Z') else value)
    except ValueError:
        return False
    return parsed.tzinfo is not None
_ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')


def is_ai_identity(name):
    """Deny-list for reviewer/approver/authorizer text. Recorded text only: this is not authentication."""
    return not isinstance(name, str) or bool(_AI_IDENTITY.search(name.strip().casefold()))


def digest(register):
    return adapters.sha(register)


def errors(register, decls, records=None):
    if not isinstance(register, dict):
        return ['semantic rulings register is required']
    if register.get('version') == VERSION_V2:
        return _v2_errors(register, decls, records)
    if register.get('version') != VERSION_V1:
        return ['semantic rulings register version/scope mismatch']
    return _v1_errors(register, decls)


def _v1_errors(register, decls):
    e = []
    if register.get('version') != VERSION_V1 or register.get('scope') != SCOPE:
        e.append('semantic rulings register version/scope mismatch')
    if register.get('pool_digest') != custody.pool_digest(decls):
        e.append('semantic rulings register is not bound to the current pool')
    ds = register.get('decisions')
    if not isinstance(ds, list):
        return e + ['decisions must be a list']
    seen = set()
    for d in ds:
        if not isinstance(d, dict) or not isinstance(d.get('question_id'), str) or not d['question_id']:
            e.append('invalid semantic question entry')
            continue
        question = d['question_id']
        if question in seen:
            e.append('duplicate semantic question decision')
        seen.add(question)
        if not isinstance(d.get('status'), str) or d['status'] not in STATUSES:
            e.append('invalid semantic decision status')
        if d.get('status') == 'accepted':
            fields = ('reviewed_by', 'reviewed_at', 'decision_ref')
            if not all(isinstance(d.get(k), str) and d[k].strip() for k in fields):
                e.append('accepted decision requires external human decision metadata')
            elif d['reviewed_by'].lower().startswith('ai_assisted'):
                e.append('AI assistant cannot accept a semantic ruling')
    reviews = register.get('reviewed_cases')
    if not isinstance(reviews, list):
        e.append('case-level evidence review attestations are required')
    else:
        ids = set()
        for item in reviews:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
                e.append('invalid reviewed case entry')
                continue
            if item['id'] in ids:
                e.append('duplicate reviewed case id')
            ids.add(item['id'])
            if item.get('status') != 'accepted':
                e.append('reviewed case entry must be accepted')
            if not (isinstance(item.get('row_sha256'), str) and custody.HEX64.match(item['row_sha256'])):
                e.append('reviewed case is missing its exact record digest')
            fields = ('reviewed_by', 'reviewed_at', 'decision_ref')
            if not all(isinstance(item.get(k), str) and item[k].strip() for k in fields):
                e.append('reviewed case needs an external reviewer decision reference')
            elif item['reviewed_by'].lower().startswith('ai_assisted'):
                e.append('AI assistant cannot independently review case evidence')
    return e


def _human_decision_errors(item, what):
    if not all(isinstance(item.get(k), str) and item[k].strip() for k in ('reviewed_by', 'reviewed_at', 'decision_ref')):
        return [f'{what} needs an external human reviewer, time and decision reference']
    e = []
    if item.get('reviewer_kind') != 'human' or is_ai_identity(item['reviewed_by']):
        e.append(f'{what} must be made by a human reviewer, not an AI assistant')
    if not _iso_datetime(item['reviewed_at']):
        e.append(f'{what} reviewed_at must be an ISO-8601 timestamp')
    return e


def _v2_errors(register, decls, records):
    """Messages never name a case or family: refusals may reach a console."""
    from .manifest import record_inventory_digest
    e = []
    if register.get('scope') != SCOPE:
        e.append('semantic rulings register version/scope mismatch')
    if register.get('pool_digest') != custody.pool_digest(decls):
        e.append('semantic rulings register is not bound to the current pool')
    if not isinstance(register.get('eligibility_policy'), str) or register['eligibility_policy'] not in ELIGIBILITY_POLICIES:
        e.append('semantic rulings register names an unknown eligibility policy')
    if records is None:
        return e + ['a v2 register can only be validated against the record inventory']
    if register.get('record_inventory_sha256') != record_inventory_digest(records):
        e.append('semantic rulings register is not bound to the current record inventory')
    ds = register.get('decisions')
    if not isinstance(ds, list):
        return e + ['decisions must be a list']
    seen = set()
    for d in ds:
        if not isinstance(d, dict) or not isinstance(d.get('question_id'), str) or not d['question_id']:
            e.append('invalid semantic question entry')
            continue
        if d['question_id'] in seen:
            e.append('duplicate semantic question decision')
        seen.add(d['question_id'])
        if not isinstance(d.get('status'), str) or d['status'] not in STATUSES:
            e.append('invalid semantic decision status')
        elif d['status'] != 'pending':
            e += _human_decision_errors(d, 'semantic decision')
    reviews = register.get('reviewed_cases')
    if not isinstance(reviews, list):
        return e + ['case-level evidence review entries are required']
    by_id = {r['id']: r for r in records}
    ids = set()
    for item in reviews:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
            e.append('invalid reviewed case entry')
            continue
        if item['id'] in ids:
            e.append('duplicate reviewed case id')
        ids.add(item['id'])
        record = by_id.get(item['id'])
        if record is None:
            e.append('reviewed case entry names no record of the current inventory')
            continue
        if not (isinstance(item.get('row_sha256'), str) and custody.HEX64.match(item['row_sha256'])):
            e.append('reviewed case is missing its exact record digest')
        elif item['row_sha256'] != adapters.sha(record):
            e.append('reviewed case digest does not match its exact record')
        status = item.get('status')
        if not isinstance(status, str) or status not in CASE_STATUSES:
            e.append('invalid case review status')
            continue
        refs = item.get('ai_technical_review_refs', [])
        if not isinstance(refs, list) or not all(isinstance(x, str) and x for x in refs):
            e.append('ai_technical_review_refs must be a list of references')
        basis = item.get('evidence_basis')
        if basis is not None and (not isinstance(basis, str) or basis not in BASES):
            e.append('invalid evidence basis')
        if status == 'pending':
            continue
        e += _human_decision_errors(item, 'case review')
        if status != 'accepted':
            continue
        if item.get('independent_of_generation') is not True:
            e.append('accepted case review must be independent of generation')
        considered = item.get('questions_considered')
        if not isinstance(considered, list) or not all(isinstance(q, str) for q in considered) or                 not set(record['open_questions']) <= set(considered):
            e.append('accepted case review does not consider every open question of its record')
        if record['expected_outcome'] == 'technical_error':
            if basis is not None:
                e.append('technical-error case review must not carry a semantic evidence basis')
        elif basis is None:
            e.append('accepted classification case review requires an evidence basis')
    from . import group_review
    if not e:
        e += group_review.import_errors(register)
    return e


class Ledger:
    """Immutable snapshot of a register that passed ``errors`` in full. Build it only with ``load``/``validate``.

    Lookups are precomputed, so a stratum costs one record digest instead of a scan of the register."""
    __slots__ = ('_register', '_digest', '_decisions', '_cases')

    def __init__(self, register, _token=None):
        if _token is not _VALIDATED:
            raise TypeError('a Ledger is created only by rulings.load/validate')
        frozen = copy.deepcopy(register)
        object.__setattr__(self, '_register', frozen)
        object.__setattr__(self, '_digest', digest(frozen))
        object.__setattr__(self, '_decisions', {d['question_id']: d for d in frozen['decisions']})
        object.__setattr__(self, '_cases', {d['id']: d for d in frozen['reviewed_cases']})

    def __setattr__(self, name, value):
        raise AttributeError('a validated Ledger is immutable')

    @property
    def version(self):
        return self._register['version']

    @property
    def digest(self):
        return self._digest

    @property
    def eligibility_policy(self):
        return self._register.get('eligibility_policy', ELIGIBILITY_POLICY)

    def decision(self, question_id):
        return copy.deepcopy(self._decisions.get(question_id))

    def entry(self, case_id):
        return copy.deepcopy(self._cases.get(case_id))


_VALIDATED = object()


def validate(register, decls, records=None):
    """-> (Ledger or None, errors). The register is validated once, completely, before any stratum exists."""
    e = errors(register, decls, records)
    return (None, e) if e else (Ledger(register, _VALIDATED), [])


def load(register, decls, records=None):
    ledger, e = validate(register, decls, records)
    if ledger is None:
        raise RulingsError(f'semantic rulings register invalid: {e}')
    return ledger


def _maps(register):
    if isinstance(register, Ledger):
        return register._decisions, register._cases
    decisions = {d['question_id']: d for d in register['decisions']}
    return decisions, {d.get('id'): d for d in register.get('reviewed_cases', []) if isinstance(d, dict)}


def _case_review(record, register):
    """The entry reviewing exactly this record (id and row digest), else None."""
    entry = _maps(register)[1].get(record['id'])
    if entry is None or entry.get('row_sha256') != adapters.sha(record):
        return None
    return entry


def unresolved(record, register):
    """Return unresolved question IDs; output must remain owner-only when it names questions.

    Accepts a raw register or a Ledger. Necessary, NOT sufficient, for primary scoring (``evidence_stratum``)."""
    decisions = _maps(register)[0]
    issues = [q for q in record['open_questions']
              if q not in decisions or decisions[q]['status'] != 'accepted']
    case_review = _case_review(record, register) or {}
    if case_review.get('status') != 'accepted':
        issues.append('unreviewed_case_evidence')
    return issues


def is_admissible(record, register):
    """Accepted questions and an accepted exact-digest case review. Necessary, not sufficient."""
    return not unresolved(record, register)


def excluded_from_primary_scoring(record):
    """V3 P0: unmodelled-mode *full* unknown stays diagnostic, never primary-scored.

    Do not exclude partial unknowns with established actions. This predicate is an
    eligibility safeguard, NOT a human semantic ruling or a declaration of Gold.
    Private candidate coverage is verified by an owner-only preflight, not embedded here.
    Future equivalent cases are deliberately fail-closed pending their own adjudication.
    """
    if record.get('expected_outcome') != 'classification':
        return False
    if 'Q-S35-UNMODELLED-MODE' not in record.get('open_questions', ()):
        return False
    if 'unmodelled_mode' not in record.get('scenario_tags', ()):
        return False
    annotation = record.get('annotation') or {}
    targets = annotation.get('per_action_targets')
    return (annotation.get('unknown') is True and isinstance(targets, dict)
            and set(targets) == set(_ACTIONS)
            and all(targets[action] is None for action in _ACTIONS))


class _Stop(Exception):
    pass


def _reached_when_steps(program, args):
    """`when` steps the synthetic execution reaches. Control flow in the interpreter depends on the arguments only;
    anything not statically resolvable (a switch on an @variable, a non-list foreach) explores every branch."""
    out = []

    def run(steps):
        for step in steps:
            op = step.get('op')
            if op == 'opaque':
                raise _Stop
            if op == 'when':
                out.append(step)
                run(step['then'] if args.get(step['arg']) == step['equals'] else step.get('else', []))
            elif op == 'foreach':
                items = args.get(step['arg'])
                if not isinstance(items, list):
                    _explore(step['do'])
                elif items:
                    run(step['do'])
            elif op == 'switch':
                on = step['on']
                if isinstance(on, str) and on.startswith('$') and on[1:] in args:
                    val = str(args[on[1:]])
                elif isinstance(on, (str, bool, int, float)) and not (isinstance(on, str) and on[:1] in '$@'):
                    val = str(on)
                else:  # @variable, composite or unresolvable reference
                    for sub in step['cases'].values():
                        _explore(sub)
                    continue
                if val not in step['cases']:
                    raise _Stop  # unmodelled case: the interpreter stops at an opaque component
                run(step['cases'][val])

    def _explore(steps):
        try:
            run(steps)
        except _Stop:
            pass

    try:
        run(program)
    except _Stop:
        pass
    return out


def mechanical_ceiling(record):
    """Strongest basis the mechanics allow. It only ever LOWERS a human basis, never raises one.

    A reached optional `when` whose argument is absent is a hidden default unless the admitted schema declares a
    `default` under which an applying executor would take the same branch as the synthetic execution did
    (absent -> None). A consistent schema annotation alone never makes a case primary: the human basis decides."""
    if record.get('expected_outcome') != 'classification':
        return 'interface_supported'
    inp = record['input']
    args = inp['raw_arguments'] if isinstance(inp.get('raw_arguments'), dict) else {}
    props = (inp.get('tool_schema') or {}).get('properties') or {}
    for step in _reached_when_steps(record['evidence']['program'], args):
        if step['arg'] in args:
            continue
        prop = props.get(step['arg'])
        if not isinstance(prop, dict) or 'default' not in prop:
            return 'program_only'
        if (prop['default'] == step['equals']) != (None == step['equals']):  # noqa: E711 (interpreter semantics)
            return 'program_only'
    return 'interface_supported'


def _weaker(a, b):
    return a if BASES.index(a) >= BASES.index(b) else b


def evidence_stratum(record, register):
    """The single authoritative stratum of one record under one VALIDATED Ledger (first match wins)."""
    if not isinstance(register, Ledger):
        raise TypeError('validated rulings ledger required (rulings.load)')
    if excluded_from_primary_scoring(record):
        return DISPUTED
    status = (_case_review(record, register) or {}).get('status')
    if status == 'rejected':
        return REJECTED
    if status == 'disputed':
        return DISPUTED
    if status != 'accepted':
        return UNREVIEWED
    if not is_admissible(record, register):
        return UNRESOLVED
    review = _case_review(record, register)
    if record['expected_outcome'] == 'technical_error':
        return TECHNICAL
    if register.version != VERSION_V2:
        return BASIS_UNRECORDED
    basis = review.get('evidence_basis')
    if basis not in BASES:
        return BASIS_UNRECORDED
    return _BASIS_STRATUM[_weaker(basis, mechanical_ceiling(record))]


def primary_scoring_admissible(record, register):
    """Accepted human review is necessary but not sufficient: the evidence basis and mechanical safeguards decide."""
    return evidence_stratum(record, register) == PRIMARY
