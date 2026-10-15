# SPDX-License-Identifier: Apache-2.0
"""Static-only SOU-18 merge-rule canary. Never execute or merge this branch."""


def clean_canary(value):
    return str(value)
