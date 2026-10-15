# SPDX-License-Identifier: Apache-2.0
"""Intentional scanner finding. Never execute, deploy or merge this branch."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/sou18-static-canary")
def intentional_static_finding():
    # Controlled code-injection finding for the existing CodeQL merge rule only.
    return str(eval(request.args.get("expression", "0")))
