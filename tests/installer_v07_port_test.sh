#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT_LIB="${ROOT_DIR}/installer/v07/lib/port.sh"
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"

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

[[ -f "${COMMON_LIB}" ]] || fail "missing common lib"
[[ -f "${PORT_LIB}" ]] || fail "missing port lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/port.sh
source "${PORT_LIB}"

# mock check_port: 7100-7102 occupied, 7103 free
v07_check_port() {
  local p="$1"
  case "${p}" in
    7100|7101|7102|7104) return 1 ;;
    *) return 0 ;;
  esac
}

free_port=$(v07_find_free_port 7100 7105)
assert_eq "7103" "${free_port}" "find_free_port"

v07_allocate_port_block 7103
assert_eq "7103" "${CFG_PORT_HOST}" "host port"
assert_eq "7105" "${CFG_PORT_RESERVED_1}" "reserved1"
assert_eq "7106" "${CFG_PORT_RESERVED_2}" "reserved2"
assert_eq "7107" "${CFG_PORT_RESERVED_3}" "reserved3"

# fallback random list when range full
v07_check_port() {
  local p="$1"
  [[ "${p}" == "50011" ]]
}
V07_TEST_RANDOM_PORTS="50010,50011,50012"
fallback_port=$(v07_find_free_port 7100 7100)
assert_eq "50011" "${fallback_port}" "fallback random port"
unset V07_TEST_RANDOM_PORTS

echo "[PASS] installer v0.7 port tests"
