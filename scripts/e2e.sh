#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: bash scripts/e2e.sh [quick|docker|all] [test-filter]\n' >&2
  exit 2
}

mode=${1:-quick}
case "$mode" in
  quick|docker|all) ;;
  *) usage ;;
esac
if [[ "$mode" == all && $# -gt 1 || $# -gt 2 ]]; then
  usage
fi
filter=${2:-}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/wtf-e2e.XXXXXXXX")
trap 'rm -rf -- "$root"' EXIT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$repo/target"}

# Installation and shell hooks are tested under temporary roots; Cargo uses
# its existing offline dependency cache and the workspace's shared build cache.
cargo install --debug --offline --locked --path "$repo/crates/wtf-cli" --root "$root/install"
export WTF_E2E_BIN="$root/install/bin/wtf"

if [[ "$mode" == quick || "$mode" == all ]]; then
  if [[ -n "$filter" ]]; then
    cargo test --offline --locked -p wtf --test e2e_scenarios "$filter"
    cargo test --offline --locked -p wtf --test systemd_e2e "$filter"
    cargo test --offline --locked -p wtf --test docker_bind_e2e "$filter"
    cargo test --offline --locked -p wtf --test docker_port_e2e "$filter"
  else
    cargo test --offline --locked -p wtf --test e2e_scenarios
    cargo test --offline --locked -p wtf --test systemd_e2e
    cargo test --offline --locked -p wtf --test docker_bind_e2e
    cargo test --offline --locked -p wtf --test docker_port_e2e
  fi
fi
if [[ "$mode" == docker || "$mode" == all ]]; then
  export WTF_E2E_DOCKER=1
  if [[ -n "$filter" ]]; then
    cargo test --offline --locked -p wtf --test e2e_docker "$filter" -- --ignored
  else
    cargo test --offline --locked -p wtf --test e2e_docker -- --ignored
  fi
fi
