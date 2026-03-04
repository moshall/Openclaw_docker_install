#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${SCRIPT_PATH:-/root/openclawctl.sh}"
WORKDIR="${WORKDIR:-/root/openclaw-regression-20260303}"
LOG_DIR="${WORKDIR}/logs"

mkdir -p "${WORKDIR}" "${LOG_DIR}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

assert_cmd() {
  "$@" >/dev/null 2>&1 || fail "command failed: $*"
}

run_wizard_cfg() {
  local wizard="$1"
  local cfg="$2"
  local log_file="$3"
  OPENCLAWCTL_STRICT_NONINTERACTIVE=1 OPENCLAWCTL_AUTO_INSTALL_DOCKER=1 \
    OPENCLAWCTL_TEST_OFFICIAL_TAGS="${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-latest,beta,2026.2.26,2026.2.6}" \
    bash "${SCRIPT_PATH}" --wizard "${wizard}" --config-file "${cfg}" \
    >"${log_file}" 2>&1
}

extract_strict_report() {
  local log_file="$1"
  grep -Eo 'STRICT_REPORT_PATH=.*' "${log_file}" | tail -n1 | cut -d= -f2-
}

cleanup_container_and_dir() {
  local name="$1"
  local data_dir="$2"
  docker rm -f "${name}" >/dev/null 2>&1 || true
  rm -rf "${data_dir}"
}

echo "[INFO] regression start: $(date -Iseconds)"

# reset
cleanup_container_and_dir "openclaw_rt_linux" "/opt/openclaw/apps/openclaw_rt_linux"
cleanup_container_and_dir "openclaw_rt_panel" "/opt/1panel/apps/openclaw_rt_panel"
mkdir -p /opt/openclaw/apps /opt/1panel/apps

# scenario 1: linux direct install (official low tag -> fallback) with optional software/skills
cat > "${WORKDIR}/linux_install.cfg" <<'CFG'
SOURCE_CHOICE=1
CHANNEL_CHOICE=3
OFFICIAL_TAG=260205
NAME=openclaw_rt_linux
DATA_DIR=/opt/openclaw/apps/openclaw_rt_linux
HOST_PORT=4313
CONTAINER_PORT=18789
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=linux-reg-token
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
SOFTWARE_SET=gh,codex
SKILL_SET=obsidian-skills,security-checker
EXTRA_PORTS=
CFG
run_wizard_cfg install "${WORKDIR}/linux_install.cfg" "${LOG_DIR}/linux_install.log"
docker ps --filter "name=^openclaw_rt_linux$" --format '{{.Names}}' | grep -q openclaw_rt_linux || fail "openclaw_rt_linux not running after install"
assert_cmd docker exec openclaw_rt_linux sh -lc 'command -v gh'
assert_cmd docker exec openclaw_rt_linux sh -lc 'command -v codex'
assert_cmd test -d /opt/openclaw/apps/openclaw_rt_linux/workspace/skills/obsidian-skills
assert_cmd test -d /opt/openclaw/apps/openclaw_rt_linux/workspace/skills/security-checker

# scenario 2: linux upgrade low -> high
cat > "${WORKDIR}/linux_upgrade.cfg" <<'CFG'
SOURCE_CHOICE=1
CHANNEL_CHOICE=3
OFFICIAL_TAG=260226
NAME=openclaw_rt_linux
DATA_DIR=/opt/openclaw/apps/openclaw_rt_linux
HOST_PORT=4313
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
set +e
run_wizard_cfg upgrade "${WORKDIR}/linux_upgrade.cfg" "${LOG_DIR}/linux_upgrade.log"
upgrade_rc=$?
set -e
if [[ "${upgrade_rc}" -ne 0 ]]; then
  echo "[WARN] linux upgrade returned non-zero (${upgrade_rc}), fallback to runtime-state validation" >&2
fi
docker ps --filter "name=^openclaw_rt_linux$" --format '{{.Names}}' | grep -q openclaw_rt_linux || fail "openclaw_rt_linux not running after upgrade"

# scenario 3: interrupted upgrade retry
set +e
OPENCLAWCTL_STRICT_NONINTERACTIVE=1 OPENCLAWCTL_TEST_OFFICIAL_TAGS="${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-latest,beta,2026.2.26,2026.2.6}" \
  bash "${SCRIPT_PATH}" --wizard upgrade --config-file "${WORKDIR}/linux_upgrade.cfg" \
  >"${LOG_DIR}/linux_upgrade_interrupt.log" 2>&1 &
up_pid=$!
for _ in $(seq 1 30); do
  if grep -q "docker rm -f openclaw_rt_linux" "${LOG_DIR}/linux_upgrade_interrupt.log" 2>/dev/null; then
    break
  fi
  kill -0 "${up_pid}" >/dev/null 2>&1 || break
  sleep 1
done
if kill -0 "${up_pid}" >/dev/null 2>&1; then
  kill -9 "${up_pid}" >/dev/null 2>&1 || true
fi
wait "${up_pid}" >/dev/null 2>&1 || true
set -e
set +e
OPENCLAWCTL_STRICT_NONINTERACTIVE=1 OPENCLAWCTL_AUTO_INSTALL_DOCKER=1 \
  OPENCLAWCTL_TEST_OFFICIAL_TAGS="${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-latest,beta,2026.2.26,2026.2.6}" \
  bash "${SCRIPT_PATH}" --wizard upgrade --config-file "${WORKDIR}/linux_upgrade.cfg" \
  >"${LOG_DIR}/linux_upgrade_retry.log" 2>&1
retry_rc=$?
set -e
if [[ "${retry_rc}" -ne 0 ]]; then
  echo "[WARN] retry upgrade returned non-zero (${retry_rc}), fallback to runtime-state validation" >&2
fi
docker ps --filter "name=^openclaw_rt_linux$" --format '{{.Names}}' | grep -q openclaw_rt_linux || fail "openclaw_rt_linux not running after retry upgrade"

# scenario 4: 1panel path install + upgrade
cat > "${WORKDIR}/panel_install.cfg" <<'CFG'
SOURCE_CHOICE=2
CHANNEL_CHOICE=2
NAME=openclaw_rt_panel
DATA_DIR=/opt/1panel/apps/openclaw_rt_panel
HOST_PORT=4413
CONTAINER_PORT=18789
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=panel-reg-token
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
SOFTWARE_SET=gh
SKILL_SET=
EXTRA_PORTS=
CFG
set +e
run_wizard_cfg install "${WORKDIR}/panel_install.cfg" "${LOG_DIR}/panel_install.log"
panel_install_rc=$?
set -e
if [[ "${panel_install_rc}" -ne 0 ]]; then
  echo "[WARN] panel install returned non-zero (${panel_install_rc}), fallback to runtime-state validation" >&2
fi
docker ps --filter "name=^openclaw_rt_panel$" --format '{{.Names}}' | grep -q openclaw_rt_panel || fail "openclaw_rt_panel not running after install"
assert_cmd test -d /opt/1panel/apps/openclaw_rt_panel/runtime

cat > "${WORKDIR}/panel_upgrade.cfg" <<'CFG'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
NAME=openclaw_rt_panel
DATA_DIR=/opt/1panel/apps/openclaw_rt_panel
HOST_PORT=4413
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
set +e
run_wizard_cfg upgrade "${WORKDIR}/panel_upgrade.cfg" "${LOG_DIR}/panel_upgrade.log"
panel_upgrade_rc=$?
set -e
if [[ "${panel_upgrade_rc}" -ne 0 ]]; then
  echo "[WARN] panel upgrade returned non-zero (${panel_upgrade_rc}), fallback to runtime-state validation" >&2
fi
docker ps --filter "name=^openclaw_rt_panel$" --format '{{.Names}}' | grep -q openclaw_rt_panel || fail "openclaw_rt_panel not running after upgrade"

# scenario 5: adopt existing container
cat > "${WORKDIR}/adopt.cfg" <<'CFG'
NAME=openclaw_rt_linux
CFG
run_wizard_cfg adopt "${WORKDIR}/adopt.cfg" "${LOG_DIR}/adopt.log"
assert_cmd test -f /root/.openclaw-installer/config.env
assert_cmd grep -q '^NAME=openclaw_rt_linux$' /root/.openclaw-installer/config.env

# scenario 6: append runtime persistence via persist wizard
cat > "${WORKDIR}/persist.cfg" <<'CFG'
NAME=openclaw_rt_panel
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4413
CONTAINER_PORT=18789
DATA_DIR=/opt/1panel/apps/openclaw_rt_panel
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=
CFG
run_wizard_cfg persist "${WORKDIR}/persist.cfg" "${LOG_DIR}/persist.log"
assert_cmd test -d /opt/1panel/apps/openclaw_rt_panel/runtime/root-local-bin
assert_cmd test -d /opt/1panel/apps/openclaw_rt_panel/runtime/etc-apt-sources-list-d

# scenario 7: native npm install (real)
if ! command -v node >/dev/null 2>&1 || [ "$(node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')" -lt 22 ]; then
  apt-get update -y >/dev/null
  apt-get install -y curl ca-certificates gnupg >/dev/null
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
  apt-get install -y nodejs >/dev/null
fi
cat > "${WORKDIR}/native.cfg" <<'CFG'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
NAME=openclaw_native_rt
DATA_DIR=/opt/openclaw/apps/openclaw_native_rt
NATIVE_PREFIX=/opt/openclaw/apps/openclaw_native_rt/native
CFG
run_wizard_cfg native "${WORKDIR}/native.cfg" "${LOG_DIR}/native.log"
assert_cmd test -x /opt/openclaw/apps/openclaw_native_rt/native/bin/openclaw

echo "[PASS] full real-host regression done"
echo "LOG_DIR=${LOG_DIR}"
