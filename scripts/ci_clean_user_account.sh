#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Per-job ordinary-user fixture for the explicit native clean-user qualification.
set -euo pipefail
umask 077
phase=${1:?provide setup, qualify, after or export}
case "$phase" in setup|qualify|after|export) ;; *) exit 2 ;; esac
test "${GITHUB_EVENT_NAME:-}" = workflow_dispatch
test "${SOU216_CLEAN_USER_FOCUS:-}" = clean-user
test "${SOU216_NATIVE_PREPARATION:-}" = true
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]{0,18}$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]{0,5}$ ]]
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
/usr/bin/python3.12 -I -B scripts/ci_bwrap_userns.py check
runner_uid="$(id -u)"
account="sw216-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
base="/var/tmp/$account"
owned="$base/owned"
source="$owned/source"
evidence="$owned/evidence"
inputs="$owned/inputs"

if [[ "$phase" == setup ]]; then
    if getent passwd "$account" >/dev/null || getent group "$account" >/dev/null; then
        echo 'qualification user or group already exists' >&2
        exit 1
    fi
    test ! -e "$base" && test ! -L "$base"
    test "$(/usr/bin/git rev-parse HEAD)" = "$GITHUB_SHA"
    test "$(/usr/bin/git -C "$SOU216_RUNTIME_SOURCE" rev-parse HEAD)" = "$GITHUB_SHA"
    sudo -n /usr/sbin/useradd --no-create-home --no-log-init --user-group \
        --home-dir "$owned/home" --shell /usr/sbin/nologin -- "$account"
fi

uid="$(id -u "$account")"
gid="$(id -g "$account")"
test "$uid" -ge 1000 && test "$uid" != "$runner_uid"
test "$(id -G "$account")" = "$gid"

if [[ "$phase" == setup ]]; then
    sudo -n /usr/bin/install -d -m 0711 -o "$runner_uid" -g "$(id -g)" -- "$base"
    sudo -n /usr/bin/install -d -m 0700 -o "$uid" -g "$gid" -- "$owned" "$owned/home" "$evidence" "$inputs"
    # The runner can feed already selected bytes without granting the fixture
    # account access to its worktree, checkout credentials or other job files.
    /usr/bin/git -C "$SOU216_RUNTIME_SOURCE" bundle create "$base/source.bundle" HEAD
    sudo -n /usr/bin/chown "$uid:$gid" -- "$base/source.bundle"
    sudo -n /usr/bin/install -m 0400 -o "$uid" -g "$gid" -- "$SOU216_SOURCE_RECEIPT" "$inputs/receipt.json"
    sudo -n /usr/bin/install -m 0400 -o "$uid" -g "$gid" -- "$RUNNER_TEMP/sou111-assets/node.tar.xz" "$inputs/node.tar.xz"
    sudo -n /usr/bin/install -m 0500 -o "$uid" -g "$gid" -- "$SOU119_AGENTFW" "$inputs/agentfw"
    sudo -n /usr/bin/install -m 0500 -o "$uid" -g "$gid" -- "$SOU119_GIT_LAUNCHER" "$inputs/git-launcher"
    sudo -n /usr/bin/install -m 0500 -o "$uid" -g "$gid" -- "$SOU119_SANDBOX_TESTS" "$inputs/sandbox-tests"
    sudo -n /usr/bin/install -m 0500 -o "$uid" -g "$gid" -- "$SOU115_GIT" "$inputs/git"
    sudo -n /usr/bin/install -m 0500 -o "$uid" -g "$gid" -- \
        "$RUNNER_TEMP/sou111-assets/claude/node_modules/@anthropic-ai/claude-code-linux-x64/claude" "$inputs/claude"
fi

# sudo runs as the Actions UID's elevation, never as a process whose real UID
# is the fixture UID. setpriv drops all credential slots before the ordinary
# workload. The native scanner still sees the host's original /proc.
run_as_user() {
    sudo -n /usr/bin/setpriv --reuid "$uid" --regid "$gid" --clear-groups -- \
        /usr/bin/env -i PATH=/usr/bin:/bin HOME="$owned/home" LANG=C.UTF-8 \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GITHUB_ACTIONS=true CI=true RUNNER_OS=Linux RUNNER_ARCH=X64 \
        "GITHUB_RUN_ID=$GITHUB_RUN_ID" "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" "GITHUB_JOB=$GITHUB_JOB" \
        "SOUP_CI_RUNNER_ENVIRONMENT=$SOUP_CI_RUNNER_ENVIRONMENT" "RUNNER_TEMP=$evidence" \
        "ImageVersion=${ImageVersion:-}" "SOU216_CI_USER_SESSION_REPORT=$evidence/sou216-user-session/report.json" "$@"
}

case "$phase" in
    setup)
        run_as_user /usr/bin/git init -q "$source"
        run_as_user /usr/bin/git -C "$source" fetch -q --no-tags -- "$base/source.bundle" HEAD
        run_as_user /usr/bin/git -C "$source" checkout -q --detach "$GITHUB_SHA"
        test "$(run_as_user /usr/bin/git -C "$source" rev-parse HEAD)" = "$GITHUB_SHA"
        test -z "$(run_as_user /usr/bin/git -C "$source" status --porcelain)"
        run_as_user /usr/bin/python3.12 -I -B "$source/scripts/ci_pilot_user_session.py" --before-clean-user --recipient sou243
        ;;
    qualify)
        run_as_user /usr/bin/python3.12 -I -B "$source/scripts/qualify-installed-front-door.py" \
            --run --clean-user-only --runtime-source "$source" --source-build-receipt "$inputs/receipt.json" \
            --runtime-source-commit "$GITHUB_SHA" --expected-commit "$GITHUB_SHA" \
            --output "$evidence/sou216-clean-user" --component-python /usr/bin/python3.12 \
            --strace /usr/bin/strace --git "$inputs/git" --bwrap "$SOU111_BWRAP" \
            --agentfw "$inputs/agentfw" --git-launcher "$inputs/git-launcher" --sandbox-tests "$inputs/sandbox-tests" \
            --node-archive "$inputs/node.tar.xz" --claude "$inputs/claude" --python /usr/bin/python3.12 --allow-download
        ;;
    after)
        run_as_user /usr/bin/python3.12 -I -B "$source/scripts/ci_pilot_user_session.py" --after-cleanup --recipient sou243
        ;;
    export)
        if run_as_user /usr/bin/test -d "$evidence/sou216-clean-user/custody"; then
            cert="$source/scripts/fixtures/sou243-custody-recipient.crt"
            expected=5de07c5f15b1f7c15970769001e527aadacf91a32a826f840932c5cc379db5b2
            test "$(run_as_user /usr/bin/sha256sum "$cert" | cut -d ' ' -f1)" = "$expected"
            test "$(/usr/bin/sha256sum scripts/fixtures/sou243-custody-recipient.crt | cut -d ' ' -f1)" = "$expected"
            mkdir -p "$RUNNER_TEMP/sou216-clean-user"
            run_as_user /usr/bin/tar -C "$evidence/sou216-clean-user" -cf - custody \
                | /usr/bin/openssl cms -encrypt -binary -aes-256-gcm \
                    -out "$RUNNER_TEMP/sou216-clean-user/installed-custody.cms" -outform DER \
                    scripts/fixtures/sou243-custody-recipient.crt
        fi
        for relative in sou216-user-session/report.json sou216-user-session/private-provenance.cms \
                        sou216-user-session-after-cleanup/report.json sou216-user-session-after-cleanup/private-provenance.cms \
                        sou216-clean-user/report.json sou216-clean-user/catalog-service/expected.private.json \
                        sou216-clean-user/release-ledger/expected.private.json \
                        sou216-clean-user/walkthrough/report.json sou216-clean-user/ask/qualification.json; do
            if run_as_user /usr/bin/test -f "$evidence/$relative"; then
                mkdir -p "$RUNNER_TEMP/${relative%/*}"
                run_as_user /usr/bin/cat -- "$evidence/$relative" > "$RUNNER_TEMP/$relative"
            fi
        done
        ;;
esac
