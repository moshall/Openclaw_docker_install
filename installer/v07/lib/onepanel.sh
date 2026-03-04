#!/usr/bin/env bash

set -euo pipefail

v07_1panel_api_default_base() {
  printf '%s\n' "${V07_1PANEL_API_BASE:-http://127.0.0.1:28888}"
}

v07_1panel_build_compose_payload_v1() {
  local app_name="$1"
  local compose_content="$2"
  printf '{"name":"%s","file":"%s","description":"%s"}\n' \
    "$(v07_json_escape "${app_name}")" \
    "$(v07_json_escape "${compose_content}")" \
    "$(v07_json_escape "OpenClaw installer v0.7 managed app")"
}

v07_1panel_build_compose_payload_legacy() {
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
  response=$(curl -fsSL "${api_base}/api/v1/health" 2>/dev/null || true)
  [[ -n "${response}" ]] || response=$(curl -fsSL "${api_base}/health" 2>/dev/null || true)
  [[ -n "${response}" ]] || return 1
  [[ "${response}" == *'"code":0'* || "${response}" == *'"status":"ok"'* || "${response}" == *"ok"* ]]
}

v07_1panel_validate_token() {
  local api_base="$1"
  local token="$2"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${token}" \
    "${api_base}/api/v1/users/profile" 2>/dev/null || true)
  [[ "${code}" == "200" ]]
}

v07_1panel_apply_compose_api_v1() {
  local api_base="$1"
  local token="$2"
  local payload="$3"

  local url="${api_base}/api/v1/containers/compose"
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
  [[ "${response}" == *'"code":0'* || "${response}" == *'"success":true'* || "${response}" == *'"message"'* ]]
}

v07_1panel_apply_compose_api_legacy() {
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
  [[ "${response}" == *'"code":0'* || "${response}" == *'"success":true'* ]]
}

v07_1panel_apply_compose_with_fallback() {
  local api_base="$1"
  local token="$2"
  local app_name="$3"
  local compose_content="$4"
  local compose_file="$5"

  local payload_v1 payload_legacy
  payload_v1=$(v07_1panel_build_compose_payload_v1 "${app_name}" "${compose_content}")
  payload_legacy=$(v07_1panel_build_compose_payload_legacy "${app_name}" "${compose_content}")

  if v07_1panel_api_available "${api_base}"; then
    if [[ -n "${token}" ]] && v07_1panel_validate_token "${api_base}" "${token}" && v07_1panel_apply_compose_api_v1 "${api_base}" "${token}" "${payload_v1}"; then
      v07_log_info "1Panel API(v1) 已创建/更新 Compose 应用: ${app_name}"
      return 0
    fi
    if [[ -n "${token}" ]] && v07_1panel_apply_compose_api_legacy "${api_base}" "${token}" "${payload_legacy}"; then
      v07_log_info "1Panel API(legacy) 已创建/更新 Compose 应用: ${app_name}"
      return 0
    fi
  fi

  mkdir -p "$(dirname "${compose_file}")"
  printf '%s\n' "${compose_content}" > "${compose_file}"
  v07_log_warn "1Panel API 不可用，已回退为 Compose 文件导入模式: ${compose_file}"
}
