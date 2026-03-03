#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
CONFIG_LIB="${ROOT_DIR}/installer/v07/lib/config.sh"
DETECT_LIB="${ROOT_DIR}/installer/v07/lib/detect.sh"
IMAGE_LIB="${ROOT_DIR}/installer/v07/lib/image.sh"
PORT_LIB="${ROOT_DIR}/installer/v07/lib/port.sh"
PERSIST_LIB="${ROOT_DIR}/installer/v07/lib/persist.sh"
COMPOSE_LIB="${ROOT_DIR}/installer/v07/lib/compose.sh"
DOCKER_LIB="${ROOT_DIR}/installer/v07/lib/docker.sh"
REPORT_LIB="${ROOT_DIR}/installer/v07/lib/report.sh"
ACTION_LIB="${ROOT_DIR}/installer/v07/lib/action.sh"

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

for f in "${COMMON_LIB}" "${CONFIG_LIB}" "${DETECT_LIB}" "${IMAGE_LIB}" "${PORT_LIB}" "${PERSIST_LIB}" "${COMPOSE_LIB}" "${DOCKER_LIB}" "${REPORT_LIB}" "${ACTION_LIB}"; do
  [[ -f "$f" ]] || fail "missing lib: $f"
done

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/config.sh
source "${CONFIG_LIB}"
# shellcheck source=installer/v07/lib/detect.sh
source "${DETECT_LIB}"
# shellcheck source=installer/v07/lib/image.sh
source "${IMAGE_LIB}"
# shellcheck source=installer/v07/lib/port.sh
source "${PORT_LIB}"
# shellcheck source=installer/v07/lib/persist.sh
source "${PERSIST_LIB}"
# shellcheck source=installer/v07/lib/compose.sh
source "${COMPOSE_LIB}"
# shellcheck source=installer/v07/lib/docker.sh
source "${DOCKER_LIB}"
# shellcheck source=installer/v07/lib/report.sh
source "${REPORT_LIB}"
# shellcheck source=installer/v07/lib/action.sh
source "${ACTION_LIB}"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

V07_DRY_RUN=1
ENV_OS="linux"
ENV_1PANEL="1"
ENV_ARCH="amd64"
CFG_APP_NAME="openclaw_install_flow"
CFG_SOURCE="official"
CFG_CHANNEL="custom"
CFG_VERSION_REQUEST="260226"
CFG_DATA_DIR="${tmpdir}/data"
CFG_HOST_PORT="7134"
CFG_PORT_RESERVED_1="7135"
CFG_PORT_RESERVED_2="7136"
CFG_PORT_RESERVED_3="7137"
CFG_EASYCLAW_ENABLED="1"
CFG_EASYCLAW_PORT="7138"
CFG_ACCESS_MODE="remote"
CFG_AUTH_TOKEN="test-token"
CFG_UNINSTALL_MODE="safe"
V07_TEST_STEP_LOG="${tmpdir}/steps.log"
: > "${V07_TEST_STEP_LOG}"

export OPENCLAWCTL_TEST_OFFICIAL_TAGS="latest,2026.2.26"
v07_action_install
unset OPENCLAWCTL_TEST_OFFICIAL_TAGS

steps=$(cat "${V07_TEST_STEP_LOG}")
assert_contains "${steps}" "prepare_dirs" "step prepare_dirs"
assert_contains "${steps}" "pull_image" "step pull_image"
assert_contains "${steps}" "generate_compose" "step generate_compose"
assert_contains "${steps}" "compose_up" "step compose_up"
assert_contains "${steps}" "wait_healthy" "step wait_healthy"
assert_contains "${steps}" "write_config" "step write_config"
assert_contains "${steps}" "write_report" "step write_report"

echo "[PASS] installer v0.7 install flow tests"
