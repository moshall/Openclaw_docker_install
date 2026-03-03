#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for lib in common config detect image port persist compose docker report action; do
  file="${ROOT_DIR}/installer/v07/lib/${lib}.sh"
  [[ -f "${file}" ]] || {
    echo "[FAIL] missing lib: ${file}" >&2
    exit 1
  }
  # shellcheck disable=SC1090
  source "${file}"
done

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_contains() {
  local text="$1"
  local needle="$2"
  local label="$3"
  if [[ "${text}" != *"${needle}"* ]]; then
    fail "${label}: expected to contain '${needle}'"
  fi
}

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

V07_DRY_RUN=1
ENV_OS="linux"
ENV_1PANEL="0"
ENV_ARCH="amd64"
CFG_APP_NAME="openclaw_lifecycle"
CFG_SOURCE="chinese"
CFG_CHANNEL="nightly"
CFG_VERSION_REQUEST=""
CFG_DATA_DIR="${tmpdir}/data"
CFG_HOST_PORT="7150"
CFG_PORT_RESERVED_1="7151"
CFG_PORT_RESERVED_2="7152"
CFG_PORT_RESERVED_3="7153"
CFG_EASYCLAW_ENABLED="0"
CFG_EASYCLAW_PORT=""
CFG_ACCESS_MODE="remote"
CFG_AUTH_TOKEN=""

# upgrade
V07_TEST_STEP_LOG="${tmpdir}/upgrade.steps"
: > "${V07_TEST_STEP_LOG}"
v07_action_upgrade
upgrade_steps=$(cat "${V07_TEST_STEP_LOG}")
assert_contains "${upgrade_steps}" "compose_down" "upgrade step compose_down"
assert_contains "${upgrade_steps}" "compose_up" "upgrade step compose_up"
assert_contains "${upgrade_steps}" "write_report" "upgrade step report"

# rebuild
V07_TEST_STEP_LOG="${tmpdir}/rebuild.steps"
: > "${V07_TEST_STEP_LOG}"
v07_action_rebuild
rebuild_steps=$(cat "${V07_TEST_STEP_LOG}")
assert_contains "${rebuild_steps}" "compose_down" "rebuild step compose_down"
assert_contains "${rebuild_steps}" "compose_up" "rebuild step compose_up"
assert_contains "${rebuild_steps}" "write_report" "rebuild step report"

# uninstall full
V07_TEST_STEP_LOG="${tmpdir}/uninstall.steps"
: > "${V07_TEST_STEP_LOG}"
CFG_UNINSTALL_MODE="full"
v07_action_uninstall
uninstall_steps=$(cat "${V07_TEST_STEP_LOG}")
assert_contains "${uninstall_steps}" "compose_down" "uninstall step compose_down"
assert_contains "${uninstall_steps}" "delete_data" "uninstall delete_data"
assert_contains "${uninstall_steps}" "write_report" "uninstall step report"

echo "[PASS] installer v0.7 lifecycle tests"
