#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT_PATH="${ROOT_DIR}/installer/v07/openclaw-install.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    fail "expected output to contain: ${needle}"
  fi
}

[[ -f "${SCRIPT_PATH}" ]] || fail "missing script: ${SCRIPT_PATH}"

help_output=$(bash "${SCRIPT_PATH}" --help)
assert_contains "${help_output}" "OpenClaw 一键安装向导"
assert_contains "${help_output}" "--dry-run"
assert_contains "${help_output}" "--non-interactive"

echo "[PASS] installer v0.7 smoke tests"
