#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
PERSIST_LIB="${ROOT_DIR}/installer/v07/lib/persist.sh"
COMPOSE_LIB="${ROOT_DIR}/installer/v07/lib/compose.sh"

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

[[ -f "${COMMON_LIB}" ]] || fail "missing common lib"
[[ -f "${PERSIST_LIB}" ]] || fail "missing persist lib"
[[ -f "${COMPOSE_LIB}" ]] || fail "missing compose lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/persist.sh
source "${PERSIST_LIB}"
# shellcheck source=installer/v07/lib/compose.sh
source "${COMPOSE_LIB}"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

compose_file="${tmpdir}/docker-compose.yml"
v07_generate_compose_file \
  "${compose_file}" \
  "openclaw_demo" \
  "ghcr.io/openclaw/openclaw:2026.3.1" \
  "official" \
  "/opt/1panel/apps/openclaw_demo" \
  "7134" "7135" "7136" "7137" \
  "1" "7138"

content=$(cat "${compose_file}")
assert_contains "${content}" "image: ghcr.io/openclaw/openclaw:2026.3.1" "image"
assert_contains "${content}" "- \"7134:18789\"" "main port"
assert_contains "${content}" "- \"7135:7201\"" "reserved1"
assert_contains "${content}" "- \"7136:7202\"" "reserved2"
assert_contains "${content}" "- \"7137:7203\"" "reserved3"
assert_contains "${content}" "- \"7138:4231\"" "easyclaw port"
assert_contains "${content}" "/opt/1panel/apps/openclaw_demo:/home/node/.openclaw" "config mount"
assert_contains "${content}" "/opt/1panel/apps/openclaw_demo/workspace:/home/node/openclaw/workspace" "workspace mount"

echo "[PASS] installer v0.7 compose tests"
