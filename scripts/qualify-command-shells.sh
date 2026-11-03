#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/command-shells.XXXXXX")
fetch() {
    local directory=$1 package=$2 digest=$3
    curl --fail --silent --show-error --location --proto '=https' \
        "https://archive.ubuntu.com/ubuntu/pool/$directory/$package" -o "$root/$package"
    printf '%s  %s\n' "$digest" "$root/$package" | sha256sum --check --strict
    dpkg-deb --extract "$root/$package" "$root/runtime"
}
fetch main/z/zsh zsh_5.9-6ubuntu2_amd64.deb bd5cc8dd3a01a6db38c0a815d75202c356a9c7f378674ba7bed9bc86dcba8af0
fetch main/z/zsh zsh-common_5.9-6ubuntu2_all.deb 56d160585b417af0cc04d7372f74a3b734609d7cc43ef8ea6e92bfdfc27f77c3
fetch universe/f/fish fish_3.7.0-1_amd64.deb da21699b9750e8d90b7306192267e72900c1d51c1849b4fa1a680363a8d50cde
fetch universe/f/fish fish-common_3.7.0-1_all.deb 38fdb2f1a820e65b93d6ef99063e8d070998eb70c34e2ddacf35294ddbf935a4
export PATH="$root/runtime/bin:$root/runtime/usr/bin:$PATH"
export AGENTFW_REQUIRE_SHELLS=1
bash --version | head -n 1
zsh --version
fish --version
python3 -B -m unittest scripts.test_agent_command_help -v
