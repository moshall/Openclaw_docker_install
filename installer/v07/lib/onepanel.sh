#!/usr/bin/env bash

set -euo pipefail

v07_1panel_api_default_base() {
  printf '%s\n' "${V07_1PANEL_API_BASE:-http://127.0.0.1:9999}"
}

v07_1panel_build_compose_payload() {
  local app_name="$1"
  local compose_content="$2"
  printf '{"name":"%s","compose":"%s"}\n' "$(v07_json_escape "${app_name}")" "$(v07_json_escape "${compose_content}")"
}

v07_1panel_api_available() {
  local api_base="$1"
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  local response
  response=$(curl -fsSL "${api_base}/health" 2>/dev/null || true)
  [[ -n "${response}" ]] || return 1
  [[ "${response}" == *'"code":0'* ]]
}

v07_1panel_apply_compose_api() {
  local api_base="$1"
  local token="$2"
  local payload="$3"

  local url="${api_base}/compose/create"
  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    v07_run_cmd echo curl -X POST "${url}" -H "Authorization: Bearer ${token}" -d "${payload}"
    return 0
  fi

  local response
  response=$(curl -fsSL -X POST "${url}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${token}" \
    -d "${payload}" 2>/dev/null || true)
  [[ -n "${response}" ]] || return 1
  [[ "${response}" == *'"code":0'* ]]
}

v07_1panel_apply_compose_with_fallback() {
  local api_base="$1"
  local token="$2"
  local app_name="$3"
  local compose_content="$4"
  local compose_file="$5"

  local payload
  payload=$(v07_1panel_build_compose_payload "${app_name}" "${compose_content}")

  if v07_1panel_api_available "${api_base}" && v07_1panel_apply_compose_api "${api_base}" "${token}" "${payload}"; then
    v07_log_info "1Panel API 已创建/更新 Compose 应用: ${app_name}"
    return 0
  fi

  mkdir -p "$(dirname "${compose_file}")"
  printf '%s\n' "${compose_content}" > "${compose_file}"
  v07_log_warn "1Panel API 不可用，已回退为 Compose 文件导入模式: ${compose_file}"
}
