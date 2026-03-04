#!/usr/bin/env bash

print_cmd() {
  local rendered=()
  local arg
  for arg in "$@"; do
    rendered+=("$(printf '%q' "$arg")")
  done
  printf '%s\n' "${rendered[*]}"
}

run_cmd() {
  print_cmd "$@"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    "$@"
  fi
}

run_cmd_brief() {
  local label="$1"
  shift
  printf '[RUN] %s\n' "${label}"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    "$@"
  fi
}

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_error() {
  printf '[ERROR] %s\n' "$*" >&2
}

run_optional_step() {
  local label="$1"
  shift
  local rc
  set +e
  "$@"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log_error "${label}失败（已跳过，不影响主流程）"
    return "${rc}"
  fi
  return 0
}

json_escape() {
  local raw="${1:-}"
  printf '%s' "${raw}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r//g; s/\n/\\n/g'
}

join_with_semicolon() {
  local out=""
  local item
  for item in "$@"; do
    [[ -z "${item}" ]] && continue
    if [[ -z "${out}" ]]; then
      out="${item}"
    else
      out="${out}; ${item}"
    fi
  done
  printf '%s\n' "${out}"
}
