"""Deterministic assembly of Checkpoint 1 records, review queue, review package and freeze."""
import csv
import hashlib
import inspect
import io
import json
import platform
from pathlib import Path

from . import VERSION
from .cases import CASES, CONTRACT, REVIEW_ATTENTION
from .fixtures import REGISTRY, admission_record, admitted_fixture, fixture_functions, fixture_source_sha
from .hashing import file_sha, sha
from .labels import ACTIONS, contract_view, known_mask, to_contract_with_forbidden
from .sandbox import execute, labels_from_execution, run_canaries

ROOT = Path(__file__).resolve().parents[1]
DATA_FILES = {'dev16': 'data/dev16.jsonl', 'supplementary': 'data/dev_supplementary.jsonl'}
QUEUE = 'review/DEV16_REVIEW_QUEUE.csv'
PACKAGE = 'review/DEV16_REVIEW_PACKAGE.md'
FREEZE = 'data/freeze.json'
SOURCE_GLOBS = ('sou13/*.py', 'scripts/*.py')
REVIEW_FIELDS = ['reviewer_name', 'read_decision', 'write_decision', 'delete_decision', 'send_data_decision',
                 'change_permissions_decision', 'unknown_decision', 'evidence_confirmed_Y_N',
                 'overall_decision_accept_revise_pending', 'disagreement_notes', 'alternative_interpretation',
                 'review_timestamp']
INPUT_PROFILE = 'object_arguments_fixture_profile'  # SOU-10 §1.2: object-argument profiles reject null
INPUT_REQUIRED = ('tool_name', 'tool_schema', 'raw_arguments')
INPUT_OPTIONAL = ('tool_description', 'pinned_schema', 'server_id')
SHELL_FIXTURE = 'posix_sh_model'


class BuildError(ValueError):
    pass


def input_errors(inp):
    """Structural input check per SOU-10 §1.2 (independent of the argument profile)."""
    if not isinstance(inp, dict):
        return ['input must be an object']
    errors = [f'missing input field {k}' for k in INPUT_REQUIRED if k not in inp]
    errors += [f'unsupported input field {k}' for k in sorted(set(inp) - set(INPUT_REQUIRED) - set(INPUT_OPTIONAL))]
    if not isinstance(inp.get('tool_name'), str) or not inp.get('tool_name', '').strip():
        errors.append('tool_name must be a nonempty string')
    if 'tool_description' in inp and inp['tool_description'] is not None and not isinstance(inp['tool_description'], str):
        errors.append('tool_description must be text, null, or absent')
    if 'server_id' in inp and (not isinstance(inp['server_id'], str) or not inp['server_id']):
        errors.append('server_id, when present, must be a nonempty string')
    for key in ('tool_schema', 'pinned_schema'):
        if key in inp and not (isinstance(inp[key], dict) and inp[key].get('type') == 'object'):
            errors.append(f'{key} must be an object schema')
    return errors


def _schema_errors(args, sch, label):
    if not isinstance(sch, dict):
        return [f'{label}: not an object schema']
    errors, props = [], sch.get('properties', {})
    for key in sch.get('required', []):
        if key not in args:
            errors.append(f'{label}: missing required field {key}')
    for key, value in args.items():
        if key not in props:
            if sch.get('additionalProperties') is False:
                errors.append(f'{label}: undeclared field {key}')
            continue
        declared = props[key].get('type', [])
        declared = [declared] if isinstance(declared, str) else declared
        jt = ('object' if isinstance(value, dict) else 'array' if isinstance(value, list)
              else 'string' if isinstance(value, str) else 'boolean' if isinstance(value, bool)
              else 'number' if isinstance(value, (int, float)) else 'null')
        if jt not in declared:
            errors.append(f'{label}: {key}: {jt} not in {declared}')
    return errors


def check_arguments(inp):
    """Arguments vs the object-argument profile and the admitted schema(s).

    Type-check logic adapted from the earlier v0.2 pilot (not included in this archive). When
    `pinned_schema` is present the arguments must satisfy it as well as `tool_schema` (SOU-13 convention)."""
    args = inp.get('raw_arguments')
    if not isinstance(args, dict):
        return [f'{INPUT_PROFILE}: raw_arguments must be an object, got {type(args).__name__}']
    errors = _schema_errors(args, inp['tool_schema'], 'tool_schema')
    if 'pinned_schema' in inp:
        errors += _schema_errors(args, inp['pinned_schema'], 'pinned_schema')
    return errors


def definition_hash(inp):
    view = {'tool_name': inp['tool_name'], 'tool_description': inp.get('tool_description'),
            'tool_schema': inp['tool_schema']}
    if 'pinned_schema' in inp:
        view['pinned_schema'] = inp['pinned_schema']
    return sha(view)


def derive(spec, coverage):
    src = spec['evidence_source']
    kind = src['kind']
    inp = spec['input']
    admitted = admitted_fixture(inp.get('server_id'), inp['tool_name'])
    if kind == 'fixture':
        if admitted != src['fixture']:
            raise BuildError(f"{spec['id']}: fixture {src['fixture']} is not the admitted semantics for this tool "
                             f"(registry: {admitted}); name/description cannot select semantics")
        fn, default_world = REGISTRY[admitted]
        world = src.get('world', default_world)
        rec = execute(fn, inp['raw_arguments'], world)
        strength = 'model_execution' if admitted == SHELL_FIXTURE else 'execution'
        targets, unknown, label_ev = labels_from_execution(rec, coverage['by_action'], strength)
        evidence = {'kind': 'controlled_execution', 'fixture_id': admitted,
                    'fixture_source_sha256': fixture_source_sha(admitted), 'world_initial': world,
                    'preconditions': src.get('preconditions', []),
                    'tool_admission': admission_record(inp.get('server_id'), inp['tool_name']),
                    'execution': rec, 'instrumentation_coverage_sha256': coverage['sha256'],
                    'executed_real_tool': False}
        if admitted == SHELL_FIXTURE:
            evidence['semantics_model'] = ('deterministic POSIX sh subset model (sou13/fixtures.py posix_sh_model); '
                                           'no real shell is executed')
            evidence['author_segments'] = src['author_segments']
    elif kind == 'no_established_semantics':
        if admitted is not None:
            raise BuildError(spec['id'] + ': tool is admitted, so semantics are established')
        targets, unknown = {a: None for a in ACTIONS}, True
        label_ev = {a: {'value': None, 'basis': 'no_established_semantics', 'strength': 'not_established',
                        'refs': [src['reason']]} for a in ACTIONS}
        evidence = {'kind': 'no_established_semantics', 'reason': src['reason'], 'tool_admission': None}
    elif kind == 'input_validation':
        errors = input_errors(inp) + check_arguments(inp)
        if not errors:
            raise BuildError(spec['id'] + ': technical-error case does not violate its input profile/schema')
        return None, None, None, {'kind': 'input_validation', 'input_profile': INPUT_PROFILE,
                                  'schema_violations': errors}
    else:
        raise BuildError('unknown evidence kind ' + kind)
    return targets, unknown, label_ev, evidence


def strength_summary(label_ev):
    if label_ev is None:
        return 'input_validation'
    return '+'.join(sorted({e['strength'] for e in label_ev.values()}))


def build_record(spec, coverage):
    if input_errors(spec['input']):
        raise BuildError(f"{spec['id']}: malformed input {input_errors(spec['input'])}")
    targets, unknown, label_ev, evidence = derive(spec, coverage)
    technical = spec.get('expected_outcome') == 'technical_error'
    if technical:
        annotation = {'per_action_targets': None, 'known_mask': None, 'unknown': None, 'contract_view': None,
                      'label_evidence': None}
    else:
        if check_arguments(spec['input']):
            raise BuildError(f"{spec['id']}: arguments violate the input profile/schema")
        if targets != spec['proposed']['targets'] or unknown != spec['proposed']['unknown']:
            # Same-author consistency check (spec vs synthetic fixture), not an independent second source.
            raise BuildError(f"{spec['id']}: fixture-trace labels {targets}/{unknown} differ from proposed "
                             f"{spec['proposed']}")
        annotation = {'per_action_targets': targets, 'known_mask': known_mask(targets), 'unknown': unknown,
                      'contract_view': contract_view(targets, unknown), 'label_evidence': label_ev}
        if 'forbidden_actions' in spec:
            derived = to_contract_with_forbidden(targets, unknown)[2]
            if derived != spec['forbidden_actions']:
                raise BuildError(spec['id'] + ': forbidden_actions disagree with labels')
            annotation['forbidden_actions'] = spec['forbidden_actions']
    annotation.update({'rationale': spec['rationale'], 'contract_rules': spec['contract_rules']})
    open_questions = list(spec.get('open_questions', []))
    if evidence.get('tool_admission') and 'Q-ADMISSION' not in open_questions:
        open_questions.append('Q-ADMISSION')  # every registry-backed label rests on the synthetic registry
    inp = spec['input']
    return {
        'id': spec['id'], 'dataset_version': VERSION, 'split': 'train', 'subset': spec['subset'],
        'evaluation_group': spec['evaluation_group'], 'scenario_tags': spec['scenario_tags'],
        'input_profile': INPUT_PROFILE,
        'input': inp,
        'hashes': {'input_sha256': sha(inp), 'arguments_sha256': sha(inp['raw_arguments']),
                   'definition_sha256': definition_hash(inp)},
        'expected_outcome': 'technical_error' if technical else 'classification',
        'technical_error': spec.get('technical_error'),
        'annotation': annotation,
        'evidence': evidence,
        'evidence_strength': strength_summary(label_ev),
        'label_status': spec.get('label_status', 'provisional'),
        'open_questions': open_questions,
        'review': {'annotator': 'ai_assisted_synthetic_draft', 'reviewer': None, 'reviewed_at': None,
                   'decision': None, 'second_reviewer': None, 'adjudication': None},
        'contract': {k: CONTRACT[k] for k in ('version', 'sha256', 'commit', 'blob')},
        'provenance': {'origin': 'sou13_v03_new_synthetic', 'production_data': False, 'prior_sou5_fixture_reused': False,
                       'domains': 'example.test only', 'license': 'pending owner decision'},
    }


def build_records():
    coverage = run_canaries()
    if not all(coverage['by_action'].values()):
        raise BuildError(f'instrumentation canaries failed: {coverage}')
    return [build_record(s, coverage) for s in CASES], coverage


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n' for r in rows)


def fmt(v):
    return 'null' if v is None else str(v).lower()


def review_queue(records):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(['case_id', 'subset', 'label_status', 'evaluation_group', 'reviewer_attention', 'tool_name',
                'raw_arguments'] + [f'proposed_{a}' for a in ACTIONS]
               + ['proposed_unknown', 'proposed_technical_error', 'evidence_kind', 'evidence_strength', 'open_questions']
               + REVIEW_FIELDS)
    for r in records:
        t = r['annotation']['per_action_targets'] or {a: None for a in ACTIONS}
        w.writerow([r['id'], r['subset'], r['label_status'], r['evaluation_group'],
                    'high' if r['id'] in REVIEW_ATTENTION else '', r['input']['tool_name'],
                    json.dumps(r['input']['raw_arguments'], ensure_ascii=False, sort_keys=True)]
                   + [fmt(t[a]) for a in ACTIONS]
                   + [fmt(r['annotation']['unknown']), r['technical_error'] or '', r['evidence']['kind'],
                      r['evidence_strength'], ';'.join(r['open_questions'])] + [''] * len(REVIEW_FIELDS))
    return buf.getvalue()


FIXTURE_FILE = 'sou13/fixtures.py'
# Reviewer-facing meaning of evidence strengths. Stored values are unchanged; none of them means
# that a real MCP tool or a real shell was observed.
STRENGTH_TEXT = {
    'execution': 'исполнение синтетической фикстуры (не реальный MCP-инструмент)',
    'model_execution': 'исполнение детерминированной модели POSIX sh (реальный shell не запускался)',
    'environment_declaration': 'объявление окружения (компонент не исполнялся)',
    'not_established': 'не установлено',
}


def lf_file_sha(rel):
    return hashlib.sha256((ROOT / rel).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def fixture_sources(name):
    """[(function name, first line, last line, LF source)] for the code hashed as this fixture."""
    out = []
    for fn in fixture_functions(name):
        lines, first = inspect.getsourcelines(fn)
        out.append((fn.__name__, first, first + len(lines) - 1, ''.join(lines).replace('\r\n', '\n').rstrip('\n')))
    return out


def case_limitations(r):
    if r['expected_outcome'] == 'technical_error':
        return ['Проверяется только структура входа (§1.2, §3.2); семантика инструмента не исполняется.']
    ev, a = r['evidence'], r['annotation']
    t = a['per_action_targets']
    if ev['kind'] != 'controlled_execution':
        return ['Gold зависит от внешнего (синтетического) реестра допущенных инструментов, которого нет во входе '
                'классификатора; префикс `unregistered-` в server_id может служить shortcut (аудит M3).']
    out = ['Синтетическая семантика: метки и фикстура написаны одним автором; совпадение трассы с метками — '
           'проверка согласованности, а не независимое подтверждение. Поведение реального MCP-инструмента не '
           'наблюдалось (`executed_real_tool=false`).']
    if any(v is False for v in t.values()):
        out.append('`false` верно только внутри заявленной семантики фикстуры; guard и raw-access audit неполны и '
                   'не являются security boundary (`docs/EVIDENCE_MODEL.md`, «Ограничения sandbox»).')
    if ev['fixture_id'] == SHELL_FIXTURE:
        out.append('Модель POSIX sh — подмножество с известными дефектами разбора (кавычки/экранирование, `#` '
                   'внутри слова, `$VAR`, аварийные исключения; аудит H3–H5). Команда этого кейса эти дефекты не '
                   'затрагивает; на другие команды результат не переносится.')
    if any(v is None for v in t.values()):
        out.append('Какой компонент непрозрачен — выбор автора фикстуры; во входе классификатора это не видно '
                   '(аудит M3).')
    if ev['execution']['disabled_actions']:
        out.append('Отрицание по объявлению окружения: непрозрачный компонент не исполнялся (Q-ENV).')
    return out


def _trace_text(trace):
    if not trace:
        return '(пусто: ни одного события эффекта)'
    return '; '.join(f"#{e['seq']} {e['event']}" + (f" {e.get('table')}/{e.get('key')}" if e.get('table') else '')
                     + (f" [{e.get('mode') or e.get('view')}]" if ('mode' in e or 'view' in e) else '')
                     + (f" → {e['recipient']}" if 'recipient' in e else '')
                     + (f" {e['component']}" if 'component' in e else '') for e in trace)


def review_package(records):
    fx_sha = lf_file_sha(FIXTURE_FILE)
    out = ['# SOU-13 v0.3 — пакет ревью Checkpoint 1 (16 dev + S1–S3)', '',
           '**Статус: provisional, НЕ проверено человеком.** Метки сгенерированы ассистентом по заданной синтетической '
           f"семантике и правилам контракта SOU-10 {CONTRACT['version']} (main, commit `{CONTRACT['commit'][:12]}`, "
           f"sha256 `{CONTRACT['sha256'][:12]}…`); ссылки на разделы — по тексту этого контракта. Решения ревьюера "
           'вносятся только в `DEV16_REVIEW_QUEUE.csv` (см. `HANDOFF_README.md`, `docs/REVIEW_PROTOCOL.md`). '
           'Все кейсы — split=train. Семантика инструментов берётся из синтетического реестра допущенных инструментов, '
           'а не из имени/описания; сам реестр — синтетическое допущение, требующее проверки человеком (Q-ADMISSION).', '',
           '## Как читать evidence', '',
           '«Исполнение» здесь — вызов **синтетической фикстуры** (функция Python того же автора) или детерминированной '
           '**модели POSIX sh** в in-memory sandbox. Это не наблюдение реального MCP-инструмента и не запуск реального '
           'shell. Совпадение трассы с метками означает согласованность спецификации и фикстуры одного автора: '
           'заведомо неверная, но согласованная пара «метка + фикстура» проходит сборку, тесты и валидатор '
           '(AI-аудит, K1). Проверять нужно саму семантику фикстуры по контракту.', '',
           '| Значение `strength` | Что означает |', '|---|---|']
    out += [f'| `{k}` | {v} |' for k, v in STRENGTH_TEXT.items()]
    out += ['', f'Исходный код фикстур: `{FIXTURE_FILE}`, SHA-256 файла (LF) `{fx_sha}`. '
            '`fixture_source_sha256` в записи — sha256 канонического JSON списка исходников функций фикстуры '
            '(`fixtures.fixture_source_sha`).', '',
            '## Требуют особого внимания ревьюера', '']
    out += [f'- **{cid}**: {note}' for cid, note in REVIEW_ATTENTION.items()]
    out += ['']
    shell_appendix = False
    for r in records:
        a = r['annotation']
        flag = ' — ⚠ требует особого внимания' if r['id'] in REVIEW_ATTENTION else ''
        out += [f"## {r['id']} — {r['input']['tool_name']} ({r['subset']}, {r['label_status']}){flag}", '']
        if r['id'] in REVIEW_ATTENTION:
            out += [f"> **Внимание ревьюера.** {REVIEW_ATTENTION[r['id']]}", '']
        out += [f"- Группа: `{r['evaluation_group']}`; теги: {', '.join(r['scenario_tags'])}; правила: {', '.join(a['contract_rules'])}",
                f"- Описание (недоверенное): «{r['input'].get('tool_description')}»",
                f"- Аргументы: `{json.dumps(r['input']['raw_arguments'], ensure_ascii=False, sort_keys=True)}`"]
        if r['expected_outcome'] == 'technical_error':
            out += [f"- Ожидается техническая ошибка: `{r['technical_error']}`; нарушения схемы: {r['evidence']['schema_violations']}"]
        else:
            t, ev = a['per_action_targets'], r['evidence']
            out += ['- Предложено (provisional):', '',
                    '  | | ' + ' | '.join(ACTIONS) + ' | unknown |', '  |---|' + '---|' * (len(ACTIONS) + 1),
                    '  | метка | ' + ' | '.join(fmt(t[k]) for k in ACTIONS) + f" | {fmt(a['unknown'])} |",
                    '  | known_mask | ' + ' | '.join(str(a['known_mask'][k]) for k in ACTIONS) + ' | — |', '',
                    f"- contract_view: `{json.dumps(a['contract_view'])}`"]
            if 'forbidden_actions' in a:
                out += [f"- forbidden_actions (не утверждено, SOU13-CONV-FORBIDDEN-ACTIONS): {a['forbidden_actions']}"]
            strengths = sorted({e['strength'] for e in a['label_evidence'].values()})
            out += [f"- Evidence: `{ev['kind']}`, сила: `{r['evidence_strength']}` — "
                    + '; '.join(STRENGTH_TEXT[s] for s in strengths),
                    '- Evidence по меткам: ' + '; '.join(
                        f"{k}={fmt(a['label_evidence'][k]['value'])} ← `{a['label_evidence'][k]['basis']}`"
                        + ''.join(f' {x}' for x in a['label_evidence'][k]['refs'] if x.startswith('trace#'))
                        for k in ACTIONS)]
            if ev['kind'] == 'controlled_execution':
                ex, adm = ev['execution'], ev['tool_admission']
                out += [f"- Допуск: `{adm['entry']['server_id']}/{adm['entry']['tool_name']}` → `{adm['entry']['semantics']}` "
                        f"(реестр, {adm['trust_basis']})"]
                if ev.get('semantics_model'):
                    out += [f"- Модель: {ev['semantics_model']}"]
                if ev['preconditions']:
                    out += [f"- Предусловия мира: {'; '.join(ev['preconditions'])}"]
                if ev.get('author_segments'):
                    out += ['- Разбор автора: ' + '; '.join(f"`{s['text']}` → {s['effects'] or '—'}" for s in ev['author_segments'])]
                srcs = fixture_sources(ev['fixture_id'])
                out += [f"- Фикстура `{ev['fixture_id']}`: `{FIXTURE_FILE}` "
                        + ', '.join(f'`{n}` (строки {b}–{e})' for n, b, e, _ in srcs)
                        + f"; fixture_source_sha256 `{ev['fixture_source_sha256']}`",
                        f"- Исход синтетического исполнения: `{ex['outcome']}`, diff объяснён: {ex['state_diff_explained']}, "
                        f"нарушений guard: {len(ex['guard_violations'])}, trace_sha256 `{ex['trace_sha256'][:16]}…`",
                        f"- Трасса: {_trace_text(ex['trace'])}"]
                if ev['fixture_id'] == SHELL_FIXTURE:
                    shell_appendix = True
                    out += ['- Исходный код модели sh: «Приложение A» в конце файла.']
                else:
                    code = '\n\n'.join(src for _, _, _, src in srcs)
                    out += ['', '  ```python'] + [('  ' + line) if line else '' for line in code.split('\n')] + ['  ```', '']
            else:
                out += [f"- Причина: {ev['reason']}",
                        '- Исходный код: нет (инструмент не допущен в реестре; фикстура не существует и не исполнялась).']
        out += [f"- Обоснование: {a['rationale']}", '- Ограничения:'] + [f'  - {x}' for x in case_limitations(r)]
        if r['open_questions']:
            out += [f"- Открытые вопросы: {', '.join(r['open_questions'])} (см. `docs/OPEN_QUESTIONS.md`)"]
        out += ['- **Решение ревьюера** (вносится в `DEV16_REVIEW_QUEUE.csv`; здесь не заполнено):',
                '  - read / write / delete / send_data / change_permissions / unknown: ____',
                '  - evidence достаточно (Y/N): ____',
                '  - accept / revise / pending: ____',
                '  - **Альтернативные интерпретации / существенные разногласия** (колонка `alternative_interpretation`): ____',
                '']
    if shell_appendix:
        out += ['## Приложение A — модель POSIX sh (`posix_sh_model`)', '',
                f"`{FIXTURE_FILE}`, fixture_source_sha256 `{fixture_source_sha(SHELL_FIXTURE)}`; "
                'константы `SH_SEPARATORS`, `SH_OUT_OF_SCOPE`, `SH_UNMODELLED` — в том же файле.', '', '```python',
                '\n\n'.join(f'# {FIXTURE_FILE}:{b}-{e}\n{src}' for _, b, e, src in fixture_sources(SHELL_FIXTURE)),
                '```', '']
    return '\n'.join(out)


# Freeze fields that record the build environment as provenance only. They are kept in
# freeze.json but excluded when checking that a rebuild reproduces the dataset.
FREEZE_PROVENANCE_ONLY = ('built_with_python',)


def freeze_reproducibility_view(freeze):
    """Freeze content that must be identical across rebuilds on any supported Python."""
    return {k: v for k, v in freeze.items() if k not in FREEZE_PROVENANCE_ONLY}


def source_hashes(root):
    files = sorted(p for g in SOURCE_GLOBS for p in root.glob(g))
    return {p.relative_to(root).as_posix(): sha(p.read_text(encoding='utf-8').replace('\r\n', '\n')) for p in files}


def write_all(out_root=ROOT):
    out_root = Path(out_root)
    records, coverage = build_records()
    outputs = {path: jsonl([r for r in records if r['subset'] == subset]) for subset, path in DATA_FILES.items()}
    outputs[QUEUE] = review_queue(records)
    outputs[PACKAGE] = review_package(records)
    for rel, text in outputs.items():
        p = out_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode('utf-8-sig' if rel == QUEUE else 'utf-8'))
    freeze = {
        'dataset_version': VERSION, 'contract': CONTRACT,
        'files_sha256': {rel: file_sha(out_root / rel) for rel in sorted(outputs)},
        'source_sha256_lf_normalised': source_hashes(ROOT),
        'canary_coverage': coverage,
        'counts': {'dev16': sum(r['subset'] == 'dev16' for r in records),
                   'supplementary': sum(r['subset'] == 'supplementary' for r in records),
                   'pending': sorted(r['id'] for r in records if r['label_status'] == 'pending'),
                   'confirmed': sum(r['label_status'] == 'confirmed' for r in records)},
        'built_with_python': platform.python_version(),
        'human_reviewed': 0,
    }
    (out_root / FREEZE).write_bytes((json.dumps(freeze, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8'))
    return freeze
