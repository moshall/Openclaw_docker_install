#!/usr/bin/env bash

set -euo pipefail

CFG_PORT_HOST=""
CFG_PORT_RESERVED_1=""
CFG_PORT_RESERVED_2=""
CFG_PORT_RESERVED_3=""

v07_check_port() {
  local port="$1"

  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ":[0-9]*${port}[[:space:]]" && return 1
    ss -uln 2>/dev/null | grep -q ":[0-9]*${port}[[:space:]]" && return 1
    return 0
  fi

  if command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | grep -q ":${port}[[:space:]]" && return 1
    netstat -uln 2>/dev/null | grep -q ":${port}[[:space:]]" && return 1
    return 0
  fi

  if (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

v07_find_free_port() {
  local start="${1:-7100}"
  local end="${2:-7200}"
  local port
  for port in $(seq "${start}" "${end}"); do
    if v07_check_port "${port}"; then
      printf '%s\n' "${port}"
      return 0
    fi
  done

  v07_log_warn "${start}-${end} 端口段全部占用，尝试随机高位端口"
  local candidates="${V07_TEST_RANDOM_PORTS:-}"
  if [[ -n "${candidates}" ]]; then
    IFS=',' read -r -a test_ports <<< "${candidates}"
    for port in "${test_ports[@]}"; do
      if v07_check_port "${port}"; then
        printf '%s\n' "${port}"
        return 0
      fi
    done
    return 1
  fi

  local i random_port
  for i in $(seq 1 20); do
    random_port=$((RANDOM % 10000 + 50000))
    if v07_check_port "${random_port}"; then
      printf '%s\n' "${random_port}"
      return 0
    fi
  done
  return 1
}

v07_allocate_port_block() {
  local host_port="$1"
  local -a reserved=()
  local candidate=$((host_port + 1))
  while [[ "${#reserved[@]}" -lt 3 ]]; do
    if v07_check_port "${candidate}"; then
      reserved+=("${candidate}")
    fi
    candidate=$((candidate + 1))
    if [[ "${candidate}" -gt 65535 ]]; then
      break
    fi
  done

  CFG_PORT_HOST="${host_port}"
  CFG_PORT_RESERVED_1="${reserved[0]:-}"
  CFG_PORT_RESERVED_2="${reserved[1]:-}"
  CFG_PORT_RESERVED_3="${reserved[2]:-}"
}
