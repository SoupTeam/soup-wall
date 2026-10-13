# SPDX-License-Identifier: Apache-2.0
"""Static-only SOU-18 merge-gate canary. Never run, import, deploy or merge."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/sou18-static-canary")
def intentional_static_finding():
    # Intentionally unsafe scanner fixture. Never invoke this function or merge this PR.
    return str(eval(request.args.get("expression", "0")))
