#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${SCRIPT_PATH:-/root/openclawctl.sh}"
WORKDIR="${WORKDIR:-/root/openclaw-modular-regression-$(date +%Y%m%d%H%M%S)}"
LOG_DIR="${WORKDIR}/logs"
TAG_SET="${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-latest,beta,2026.2.26,2026.2.6}"

mkdir -p "${WORKDIR}" "${LOG_DIR}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

assert_cmd() {
  "$@" >/dev/null 2>&1 || fail "command failed: $*"
}

assert_contains_file() {
  local file="$1"
  local needle="$2"
  grep -q -- "${needle}" "${file}" || fail "expected ${file} to contain: ${needle}"
}

run_wizard_cfg() {
  local wizard="$1"
  local cfg="$2"
  local log_file="$3"
  OPENCLAWCTL_STRICT_NONINTERACTIVE=1 OPENCLAWCTL_AUTO_INSTALL_DOCKER=1 \
    OPENCLAWCTL_TEST_OFFICIAL_TAGS="${TAG_SET}" \
    bash "${SCRIPT_PATH}" --wizard "${wizard}" --config-file "${cfg}" \
    >"${log_file}" 2>&1
}

extract_strict_report() {
  local log_file="$1"
  grep -Eo 'STRICT_REPORT_PATH=.*' "${log_file}" | tail -n1 | cut -d= -f2-
}

cleanup_target() {
  local name="$1"
  local data_dir="$2"
  docker rm -f "${name}" >/dev/null 2>&1 || true
  rm -rf "${data_dir}"
}

echo "[INFO] modular regression start: $(date -Iseconds)"
echo "[INFO] workdir: ${WORKDIR}"

NAME="openclaw_mod_rt"
DATA_DIR="/opt/openclaw/apps/${NAME}"
cleanup_target "${NAME}" "${DATA_DIR}"
mkdir -p /opt/openclaw/apps

# Scenario 1: low-version install
cat > "${WORKDIR}/install-low.cfg" <<'CFG'
SOURCE_CHOICE=1
CHANNEL_CHOICE=3
OFFICIAL_TAG=260205
NAME=openclaw_mod_rt
DATA_DIR=/opt/openclaw/apps/openclaw_mod_rt
HOST_PORT=4513
CONTAINER_PORT=18789
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=modular-install-token
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
SOFTWARE_SET=gh
SKILL_SET=
EXTRA_PORTS=
CFG
run_wizard_cfg install "${WORKDIR}/install-low.cfg" "${LOG_DIR}/install-low.log"
docker ps --filter "name=^${NAME}$" --format '{{.Names}}' | grep -q "${NAME}" || fail "${NAME} not running after low-version install"

# Scenario 2: high-version upgrade + software keepalive
cat > "${WORKDIR}/upgrade-high.cfg" <<'CFG'
SOURCE_CHOICE=1
CHANNEL_CHOICE=3
OFFICIAL_TAG=260226
NAME=openclaw_mod_rt
DATA_DIR=/opt/openclaw/apps/openclaw_mod_rt
HOST_PORT=4513
CONTAINER_PORT=18789
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=
CFG
run_wizard_cfg upgrade "${WORKDIR}/upgrade-high.cfg" "${LOG_DIR}/upgrade-high.log"
docker ps --filter "name=^${NAME}$" --format '{{.Names}}' | grep -q "${NAME}" || fail "${NAME} not running after high-version upgrade"
assert_cmd docker exec "${NAME}" sh -lc 'command -v gh'

# Scenario 3: persist rebuild with easyclaw port-conflict fallback evidence
cat > "${WORKDIR}/persist.conflict.cfg" <<'CFG'
NAME=openclaw_mod_rt
IMAGE=docker.io/1panel/openclaw:beta
HOST_PORT=4513
CONTAINER_PORT=18789
DATA_DIR=/opt/openclaw/apps/openclaw_mod_rt
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=
CFG
OPENCLAWCTL_TEST_OCCUPIED_PORTS=4231 \
  run_wizard_cfg persist "${WORKDIR}/persist.conflict.cfg" "${LOG_DIR}/persist.conflict.log"
assert_contains_file "${LOG_DIR}/persist.conflict.log" "5231:4231"

# Scenario 4: strict non-interactive adopt report
cat > "${WORKDIR}/adopt.cfg" <<'CFG'
NAME=openclaw_mod_rt
CFG
run_wizard_cfg adopt "${WORKDIR}/adopt.cfg" "${LOG_DIR}/adopt.log"
STRICT_REPORT_PATH=$(extract_strict_report "${LOG_DIR}/adopt.log")
[[ -n "${STRICT_REPORT_PATH}" ]] || fail "STRICT_REPORT_PATH missing in adopt log"
[[ -f "${STRICT_REPORT_PATH}" ]] || fail "strict report not found: ${STRICT_REPORT_PATH}"
assert_contains_file "${STRICT_REPORT_PATH}" '"action"'
assert_contains_file "${STRICT_REPORT_PATH}" '"status"'

echo "[PASS] modular real-host regression done"
echo "LOG_DIR=${LOG_DIR}"
echo "STRICT_REPORT_PATH=${STRICT_REPORT_PATH}"
echo "PORT_MAPPING_EVIDENCE=$(docker port "${NAME}" 4231/tcp 2>/dev/null || true)"
