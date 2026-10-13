# SPDX-License-Identifier: Apache-2.0
"""Static-only SOU-18 merge-gate canary. Never run, import, deploy or merge."""

from flask import Flask

app = Flask(__name__)


@app.get("/sou18-static-canary")
def clean_canary():
    return "SOU-18 clean code-scanning fixture"
