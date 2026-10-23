#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${SOUP_CI_RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  printf '%s\n' 'A disposable GitHub-hosted runner is required.' >&2
  exit 2
fi

account="sw121${GITHUB_RUN_ID}"
fixture="$(mktemp -d /tmp/sw121-ci.XXXXXXXX)"
[[ "$fixture" == /tmp/sw121-ci.* && -d "$fixture" && ! -L "$fixture" ]]
commit="$(git -C "$GITHUB_WORKSPACE" rev-parse HEAD)"
sudo useradd --no-create-home --user-group --shell /usr/sbin/nologin "$account"
trap 'sudo userdel "$account"' EXIT

git clone --quiet --no-local --depth 1 "$GITHUB_WORKSPACE" "$fixture/source"
git -C "$fixture/source" checkout --quiet --detach "$commit"
cp "$RUNNER_TEMP/sou111-assets/git.tar.xz" "$fixture/git.tar.xz"
cp "$RUNNER_TEMP/sou111-assets/bwrap.tar.xz" "$fixture/bwrap.tar.xz"
cp -a "$RUNNER_TEMP/sou111-assets/build-tools" "$fixture/build-tools"
cp -a "$RUNNER_TEMP/sou111-assets/libcap" "$fixture/libcap"
ln -sfn "$fixture/libcap/usr/lib/x86_64-linux-gnu" "$fixture/libcap/usr/lib64"
sudo chown -R "$account:$account" "$fixture"
mkdir -m 700 "$RUNNER_TEMP/sou121-cleanup"
account_uid="$(id -u "$account")"
account_gid="$(id -g "$account")"

status=0
(
  cd /tmp
  sudo setpriv --reuid "$account_uid" --regid "$account_gid" --clear-groups env -i \
    HOME="$fixture" PATH="$fixture/build-tools/bin:/usr/bin:/bin" LANG=C.UTF-8 \
    /usr/bin/python3 -B "$fixture/source/scripts/qualify-pilot-cleanup.py" --run \
      --output "$fixture/result" --expected-commit "$commit" \
      --git-archive "$fixture/git.tar.xz" --bwrap-archive "$fixture/bwrap.tar.xz" \
      --pkg-config-libdir "$fixture/libcap/usr/lib/x86_64-linux-gnu/pkgconfig" \
      --pkg-config-sysroot "$fixture/libcap" --meson-pythonpath "$fixture/build-tools"
) || status=$?
for report in report.json dry-run.json; do
  if sudo test -f "$fixture/result/$report"; then
    sudo install -m 600 -o "$(id -u)" -g "$(id -g)" \
      "$fixture/result/$report" "$RUNNER_TEMP/sou121-cleanup/$report"
  fi
done
exit "$status"
