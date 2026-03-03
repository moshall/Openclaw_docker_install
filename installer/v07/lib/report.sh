#!/usr/bin/env bash

set -euo pipefail

v07_strict_noninteractive_enabled() {
  [[ "${OPENCLAWCTL_STRICT_NONINTERACTIVE:-0}" == "1" || "${V07_NON_INTERACTIVE:-0}" == "1" ]]
}

v07_report_path() {
  local data_dir="$1"
  printf '%s\n' "${data_dir}/runtime/strict-report.json"
}

v07_detect_container_actual_image() {
  local name="$1"
  docker inspect -f '{{.Config.Image}}' "${name}" 2>/dev/null || true
}

v07_detect_container_status() {
  local name="$1"
  docker inspect -f '{{.State.Status}}' "${name}" 2>/dev/null || echo "not_found"
}

v07_write_strict_report() {
  local action="$1"
  local status="$2"
  local notes="${3:-}"

  local report_file
  report_file=$(v07_report_path "${CFG_DATA_DIR}")
  mkdir -p "$(dirname "${report_file}")"

  local actual_image=""
  local container_status="not_found"
  local actual_version=""

  if [[ "${V07_DRY_RUN:-0}" == "0" ]]; then
    actual_image=$(v07_detect_container_actual_image "${CFG_APP_NAME}")
    container_status=$(v07_detect_container_status "${CFG_APP_NAME}")
    if [[ -n "${actual_image}" && "${actual_image}" == *:* ]]; then
      actual_version="${actual_image##*:}"
    fi
  fi

  cat > "${report_file}" <<EOR
{
  "generated_at_utc": "$(v07_now_utc)",
  "strict_noninteractive": $(v07_strict_noninteractive_enabled && echo true || echo false),
  "dry_run": ${V07_DRY_RUN:-0},
  "action": "$(v07_json_escape "${action}")",
  "status": "$(v07_json_escape "${status}")",
  "container_name": "$(v07_json_escape "${CFG_APP_NAME}")",
  "data_dir": "$(v07_json_escape "${CFG_DATA_DIR}")",
  "requested_image": "$(v07_json_escape "${CFG_DOCKER_IMAGE}")",
  "actual_image": "$(v07_json_escape "${actual_image}")",
  "actual_version": "$(v07_json_escape "${actual_version}")",
  "container_status": "$(v07_json_escape "${container_status}")",
  "host_port": "$(v07_json_escape "${CFG_HOST_PORT}")",
  "auth_token_present": $( [[ -n "${CFG_AUTH_TOKEN}" ]] && echo true || echo false ),
  "notes": "$(v07_json_escape "${notes}")"
}
EOR

  printf 'STRICT_REPORT_PATH=%s\n' "${report_file}"
}
