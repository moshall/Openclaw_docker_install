#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT_PATH="${ROOT_DIR}/installer/v07/openclaw-install.sh"

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

[[ -f "${SCRIPT_PATH}" ]] || fail "missing script"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

set +e
strict_fail_output=$(OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash "${SCRIPT_PATH}" --dry-run 2>&1)
strict_fail_status=$?
set -e
if [[ "${strict_fail_status}" -eq 0 ]]; then
  fail "strict mode should fail without wizard/config"
fi
assert_contains "${strict_fail_output}" "STRICT_NONINTERACTIVE 模式要求同时提供 --wizard 与 --config-file" "strict required args"

cfg_file="${tmpdir}/install.cfg"
cat > "${cfg_file}" <<CFG
CFG_ACTION=install
CFG_APP_NAME=openclaw_report_demo
CFG_SOURCE=official
CFG_CHANNEL=custom
CFG_VERSION_REQUEST=260226
CFG_DATA_DIR=${tmpdir}/data
CFG_HOST_PORT=7160
CFG_PORT_RESERVED_1=7161
CFG_PORT_RESERVED_2=7162
CFG_PORT_RESERVED_3=7163
CFG_EASYCLAW_ENABLED=0
CFG_ACCESS_MODE=remote
CFG_AUTH_TOKEN=report-token
CFG_UNINSTALL_MODE=safe
CFG

output=$(OPENCLAWCTL_STRICT_NONINTERACTIVE=1 OPENCLAWCTL_TEST_OFFICIAL_TAGS='latest,2026.2.26' bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${cfg_file}" 2>&1)
assert_contains "${output}" "STRICT_REPORT_PATH=" "strict report path output"
report_path=$(printf '%s\n' "${output}" | grep -o 'STRICT_REPORT_PATH=.*' | tail -n1 | cut -d= -f2-)
[[ -f "${report_path}" ]] || fail "strict report file not created"

report_content=$(cat "${report_path}")
assert_contains "${report_content}" '"strict_noninteractive": true' "strict report flag"
assert_contains "${report_content}" '"action": "install"' "action field"
assert_contains "${report_content}" '"requested_image": "ghcr.io/openclaw/openclaw:2026.2.26"' "requested image field"

echo "[PASS] installer v0.7 report tests"
