#!/usr/bin/env bash

set -euo pipefail

v07_now_utc() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

v07_log() {
  local level="$1"
  shift || true
  printf '[%s] [%s] %s\n' "$(v07_now_utc)" "${level}" "$*"
}

v07_log_info() {
  v07_log INFO "$@"
}

v07_log_warn() {
  v07_log WARN "$@" >&2
}

v07_log_error() {
  v07_log ERROR "$@" >&2
}

v07_run_cmd() {
  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] %q' "$1"
    shift || true
    local arg
    for arg in "$@"; do
      printf ' %q' "${arg}"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

v07_require_cmd() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1
}

v07_json_escape() {
  local raw="${1:-}"
  raw=${raw//\\/\\\\}
  raw=${raw//"/\\"}
  raw=${raw//$'\n'/\\n}
  raw=${raw//$'\r'/\\r}
  raw=${raw//$'\t'/\\t}
  printf '%s' "${raw}"
}
