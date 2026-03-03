#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
PERSIST_LIB="${ROOT_DIR}/installer/v07/lib/persist.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "${expected}" != "${actual}" ]]; then
    fail "${label}: expected='${expected}' actual='${actual}'"
  fi
}

assert_contains() {
  local text="$1"
  local needle="$2"
  local label="$3"
  if [[ "${text}" != *"${needle}"* ]]; then
    fail "${label}: expected to contain '${needle}'"
  fi
}

[[ -f "${COMMON_LIB}" ]] || fail "missing common lib"
[[ -f "${PERSIST_LIB}" ]] || fail "missing persist lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/persist.sh
source "${PERSIST_LIB}"

assert_eq "/home/node/.openclaw" "$(v07_container_config_dir official)" "official config dir"
assert_eq "/home/node/openclaw/workspace" "$(v07_container_workspace_dir official)" "official workspace"
assert_eq "/root/.openclaw" "$(v07_container_config_dir chinese)" "chinese config dir"
assert_eq "/root/.openclaw/workspace" "$(v07_container_workspace_dir chinese)" "chinese workspace"

HOME="/tmp/test-home"
assert_eq "/tmp/test-home/.openclaw" "$(v07_host_data_dir linux 0 openclaw_demo)" "linux data dir"
assert_eq "/opt/1panel/apps/openclaw_demo" "$(v07_host_data_dir linux 1 openclaw_demo)" "1panel data dir"

mounts=$(v07_build_core_mounts official "/opt/1panel/apps/openclaw_demo")
assert_contains "${mounts}" "/opt/1panel/apps/openclaw_demo:/home/node/.openclaw" "official mounts include config"
assert_contains "${mounts}" "/opt/1panel/apps/openclaw_demo/workspace:/home/node/openclaw/workspace" "official mounts include workspace"

echo "[PASS] installer v0.7 persist tests"
