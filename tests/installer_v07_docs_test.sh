#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MIGRATION_DOC="${ROOT_DIR}/docs/rewrite-v0.7/migration.md"
CHECKLIST_DOC="${ROOT_DIR}/docs/rewrite-v0.7/release-checklist.md"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_file_contains() {
  local file="$1"
  local needle="$2"
  grep -q -- "${needle}" "${file}" || fail "expected '${needle}' in ${file}"
}

[[ -f "${MIGRATION_DOC}" ]] || fail "missing migration doc"
[[ -f "${CHECKLIST_DOC}" ]] || fail "missing release checklist"

assert_file_contains "${MIGRATION_DOC}" "installer/v07/openclaw-install.sh"
assert_file_contains "${MIGRATION_DOC}" "openclawctl.sh"
assert_file_contains "${MIGRATION_DOC}" "v1.3.0"
assert_file_contains "${CHECKLIST_DOC}" "installer_v07_report_test.sh"
assert_file_contains "${CHECKLIST_DOC}" "interrupted-upgrade retry"

echo "[PASS] installer v0.7 docs tests"
