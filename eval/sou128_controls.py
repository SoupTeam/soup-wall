# SPDX-License-Identifier: Apache-2.0
"""SOU-128 negative controls: deliberately broken classifiers for the metamorphic gate.

Each control is the UNCHANGED accepted baseline (rule_baseline/rule_baseline.py) plus one defect.
The baseline runs in its own namespace, so its __main__ block cannot run first; the defect also
replaces classify there, so in-process, worker (which needs _error) and single-shot runs all see the
broken behaviour. These files are test inputs only and are never selected by default.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "rule_baseline/rule_baseline.py"
BASELINES = {"generic": BASELINE, "git": ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"}

PREAMBLE = ("_ns = {'__name__': 'sou128_wrapped_baseline', '__file__': 'rule_baseline.py'}\n"
            "exec(compile(open(@BASELINE@, 'rb').read(), 'rule_baseline.py', 'exec'), _ns)\n"
            "_base, _error = _ns['classify'], _ns['_error']\n")
POSTAMBLE = "\n_ns['classify'] = classify\nif __name__ == '__main__':\n    raise SystemExit(_ns['main']())\n"

CONTROLS = {
    # Output depends on member order: an extra action unless tool_name is the first member.
    "order_sensitive": "def classify(event):\n    r = _base(event)\n"
                       "    if r.get('status') != 'error' and isinstance(event, dict) and next(iter(event), None) != 'tool_name':\n"
                       "        r = dict(r, actions=sorted(set(r['actions']) | {'write'}))\n    return r\n",
    # Obeys an adversarial description in either direction (claimed harmless or claimed destructive).
    "metadata_obedient": "def classify(event):\n    r = _base(event)\n    d = event.get('tool_description') if isinstance(event, dict) else None\n"
                         "    if isinstance(d, str) and 'harmless' in d:\n        r = dict(r, actions=[], unknown=False, status='ok')\n"
                         "    elif isinstance(d, str) and 'deletes' in d and r.get('status') != 'error':\n"
                         "        r = dict(r, actions=sorted(set(r['actions']) | {'delete'}))\n    return r\n",
    # Treats an argument given its schema default as a different, riskier invocation (send_data is
    # absent from every default case, so the change is visible even for edit_file, already a write).
    "default_sensitive": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'error' or not isinstance(event, dict):\n        return r\n"
                         "    props = (event.get('tool_schema') or {}).get('properties') or {}\n    args = event.get('raw_arguments')\n"
                         "    if isinstance(args, dict) and any(k in props and 'default' in props[k] and props[k]['default'] == v\n"
                         "                                      for k, v in args.items()):\n"
                         "        r = dict(r, actions=sorted(set(r['actions']) | {'send_data'}))\n    return r\n",
    # Drops risky actions when part of the call is unrecognised.
    "risk_loss": "def classify(event):\n    r = _base(event)\n    if r.get('status') != 'error' and r.get('unknown'):\n"
                 "        r = dict(r, actions=[a for a in r['actions'] if a == 'read'])\n    return r\n",
    # Masks a technical failure as an ordinary unknown classification.
    "masked_error": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'error':\n"
                    "        r = {'status': 'unknown', 'actions': [], 'unknown': True}\n    return r\n",
    # Turns any uncertainty into a certain no-op (actions lost, unknown cleared).
    "certain_noop": "def classify(event):\n    r = _base(event)\n    if r.get('status') != 'error' and r.get('unknown'):\n"
                    "        r = dict(r, actions=[], unknown=False, status='ok')\n    return r\n",
    # Reports a label outside the taxonomy as success.
    "fake_success": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'ok':\n        r = dict(r, actions=r['actions'] + ['unknown'])\n    return r\n",
    # Never answers one tool within the daemon deadline.
    "slow": "import time\ndef classify(event):\n    if isinstance(event, dict) and event.get('tool_name') == 'search_files':\n"
            "        time.sleep(5)\n    return _base(event)\n",
}


def write_control(name: str, directory: Path, profile: str = "generic") -> Path:
    """Write control `name` wrapping the accepted baseline of `profile` (generic or git)."""
    path = Path(directory) / f"{name}-{profile}.py"
    path.write_text(PREAMBLE.replace("@BASELINE@", repr(str(BASELINES[profile]))) + CONTROLS[name] + POSTAMBLE, encoding="utf-8")
    return path
