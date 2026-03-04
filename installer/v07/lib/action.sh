#!/usr/bin/env bash

set -euo pipefail

v07_step() {
  local step="$1"
  if [[ -n "${V07_TEST_STEP_LOG:-}" ]]; then
    printf '%s\n' "${step}" >> "${V07_TEST_STEP_LOG}"
  fi
}

v07_is_1panel_mode() {
  case "${CFG_1PANEL_MODE:-auto}" in
    force_on|1|true) echo "1" ;;
    force_off|0|false) echo "0" ;;
    *) echo "${ENV_1PANEL:-0}" ;;
  esac
}

v07_should_use_1panel_api() {
  [[ "$(v07_is_1panel_mode)" == "1" && "${CFG_1PANEL_DEPLOY_MODE:-compose}" == "api" ]]
}

v07_apply_compose_deployment() {
  if v07_should_use_1panel_api; then
    local api_base token compose_content
    api_base="${CFG_1PANEL_API_BASE:-$(v07_1panel_api_default_base)}"
    token="${CFG_1PANEL_API_TOKEN:-${CFG_1PANEL_TOKEN:-}}"
    compose_content=$(cat "${CFG_COMPOSE_FILE}")
    v07_step onepanel_apply_api
    v07_1panel_apply_compose_with_fallback "${api_base}" "${token}" "${CFG_APP_NAME}" "${compose_content}" "${CFG_COMPOSE_FILE}"
    return 0
  fi

  v07_step compose_up
  v07_docker_compose_up "${CFG_COMPOSE_FILE}"
}

v07_prepare_context() {
  local action="$1"
  v07_init_runtime_config_defaults

  local is_1panel
  is_1panel=$(v07_is_1panel_mode)

  if [[ -z "${CFG_DATA_DIR}" ]]; then
    CFG_DATA_DIR=$(v07_host_data_dir "${ENV_OS:-linux}" "${is_1panel}" "${CFG_APP_NAME}")
  fi

  if [[ -z "${CFG_HOST_PORT}" ]]; then
    CFG_HOST_PORT=$(v07_find_free_port 7100 7200)
  fi

  if [[ -z "${CFG_PORT_RESERVED_1}" || -z "${CFG_PORT_RESERVED_2}" || -z "${CFG_PORT_RESERVED_3}" ]]; then
    v07_allocate_port_block "${CFG_HOST_PORT}"
  fi

  if [[ "${CFG_EASYCLAW_ENABLED}" == "1" && -z "${CFG_EASYCLAW_PORT}" ]]; then
    CFG_EASYCLAW_PORT=$((CFG_HOST_PORT + 4))
  fi

  local channel="${CFG_CHANNEL}"
  if [[ "${CFG_SOURCE}" == "chinese" && "${CFG_CHANNEL}" == "beta" ]]; then
    channel="nightly"
  fi

  v07_resolve_image "${CFG_SOURCE}" "${channel}" "${CFG_VERSION_REQUEST}" >/dev/null

  CFG_RUNTIME_DIR="${CFG_DATA_DIR}/runtime"
  CFG_COMPOSE_FILE="${CFG_RUNTIME_DIR}/${V07_COMPOSE_FILE_BASENAME}"

  v07_log_info "[context] action=${action} app=${CFG_APP_NAME} image=${CFG_DOCKER_IMAGE} data_dir=${CFG_DATA_DIR}"
}

v07_write_action_report() {
  local action="$1"
  local status="$2"
  local notes="${3:-}"
  v07_step write_report
  v07_write_strict_report "${action}" "${status}" "${notes}"
}

v07_action_install() {
  v07_prepare_context "install"

  v07_step prepare_dirs
  v07_ensure_runtime_dirs "${CFG_DATA_DIR}" "${CFG_RUNTIME_DIR}"

  v07_step pull_image
  v07_docker_pull_image "${CFG_DOCKER_IMAGE}"

  v07_step generate_compose
  v07_generate_compose_file "${CFG_COMPOSE_FILE}" "${CFG_APP_NAME}" "${CFG_DOCKER_IMAGE}" "${CFG_SOURCE}" "${CFG_DATA_DIR}" "${CFG_HOST_PORT}" "${CFG_PORT_RESERVED_1}" "${CFG_PORT_RESERVED_2}" "${CFG_PORT_RESERVED_3}" "${CFG_EASYCLAW_ENABLED}" "${CFG_EASYCLAW_PORT}" >/dev/null

  v07_apply_compose_deployment

  v07_step wait_healthy
  if ! v07_wait_container_healthy "${CFG_APP_NAME}" 90; then
    v07_write_action_report "install" "failed" "container startup timeout"
    return 1
  fi

  v07_step write_config
  v07_save_runtime_config >/dev/null

  v07_write_action_report "install" "success"
}

v07_action_upgrade() {
  v07_prepare_context "upgrade"

  v07_step prepare_dirs
  v07_ensure_runtime_dirs "${CFG_DATA_DIR}" "${CFG_RUNTIME_DIR}"

  v07_step pull_image
  v07_docker_pull_image "${CFG_DOCKER_IMAGE}"

  v07_step compose_down
  v07_docker_compose_down "${CFG_COMPOSE_FILE}"

  v07_step generate_compose
  v07_generate_compose_file "${CFG_COMPOSE_FILE}" "${CFG_APP_NAME}" "${CFG_DOCKER_IMAGE}" "${CFG_SOURCE}" "${CFG_DATA_DIR}" "${CFG_HOST_PORT}" "${CFG_PORT_RESERVED_1}" "${CFG_PORT_RESERVED_2}" "${CFG_PORT_RESERVED_3}" "${CFG_EASYCLAW_ENABLED}" "${CFG_EASYCLAW_PORT}" >/dev/null

  v07_apply_compose_deployment

  v07_step wait_healthy
  if ! v07_wait_container_healthy "${CFG_APP_NAME}" 90; then
    v07_write_action_report "upgrade" "failed" "container startup timeout"
    return 1
  fi

  v07_step write_config
  v07_save_runtime_config >/dev/null

  v07_write_action_report "upgrade" "success"
}

v07_action_rebuild() {
  v07_prepare_context "rebuild"

  v07_step prepare_dirs
  v07_ensure_runtime_dirs "${CFG_DATA_DIR}" "${CFG_RUNTIME_DIR}"

  v07_step compose_down
  v07_docker_compose_down "${CFG_COMPOSE_FILE}"

  v07_step generate_compose
  v07_generate_compose_file "${CFG_COMPOSE_FILE}" "${CFG_APP_NAME}" "${CFG_DOCKER_IMAGE}" "${CFG_SOURCE}" "${CFG_DATA_DIR}" "${CFG_HOST_PORT}" "${CFG_PORT_RESERVED_1}" "${CFG_PORT_RESERVED_2}" "${CFG_PORT_RESERVED_3}" "${CFG_EASYCLAW_ENABLED}" "${CFG_EASYCLAW_PORT}" >/dev/null

  v07_apply_compose_deployment

  v07_step wait_healthy
  if ! v07_wait_container_healthy "${CFG_APP_NAME}" 90; then
    v07_write_action_report "rebuild" "failed" "container startup timeout"
    return 1
  fi

  v07_step write_config
  v07_save_runtime_config >/dev/null

  v07_write_action_report "rebuild" "success"
}

v07_action_uninstall() {
  v07_init_runtime_config_defaults
  if [[ -z "${CFG_DATA_DIR}" ]]; then
    local is_1panel
    is_1panel=$(v07_is_1panel_mode)
    CFG_DATA_DIR=$(v07_host_data_dir "${ENV_OS:-linux}" "${is_1panel}" "${CFG_APP_NAME}")
  fi
  CFG_RUNTIME_DIR="${CFG_DATA_DIR}/runtime"
  CFG_COMPOSE_FILE="${CFG_RUNTIME_DIR}/${V07_COMPOSE_FILE_BASENAME}"

  v07_step compose_down
  v07_docker_compose_down "${CFG_COMPOSE_FILE}"

  if [[ "${CFG_UNINSTALL_MODE}" == "full" ]]; then
    v07_step delete_data
    v07_run_cmd rm -rf "${CFG_DATA_DIR}"
  fi

  v07_write_action_report "uninstall" "success"
}

v07_action_status() {
  v07_init_runtime_config_defaults
  v07_run_cmd docker ps --filter "name=^${CFG_APP_NAME}$"
}

v07_action_logs() {
  v07_init_runtime_config_defaults
  v07_container_logs "${CFG_APP_NAME}" 120
}

v07_detect_host_port_from_container() {
  local name="$1"
  local mapping
  mapping=$(docker port "${name}" 18789/tcp 2>/dev/null | head -n1 || true)
  if [[ "${mapping}" =~ :([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

v07_detect_data_dir_from_container() {
  local name="$1"
  local mounts source destination
  mounts=$(docker inspect -f '{{range .Mounts}}{{println .Source "|" .Destination}}{{end}}' "${name}" 2>/dev/null || true)
  while IFS='|' read -r source destination; do
    source=$(echo "${source}" | xargs 2>/dev/null || true)
    destination=$(echo "${destination}" | xargs 2>/dev/null || true)
    [[ -z "${source}" || -z "${destination}" ]] && continue
    if [[ "${destination}" == "/root/.openclaw" || "${destination}" == "/home/node/.openclaw" ]]; then
      printf '%s\n' "${source}"
      return 0
    fi
  done <<< "${mounts}"
  return 1
}

v07_action_adopt() {
  v07_init_runtime_config_defaults
  if [[ "${V07_DRY_RUN:-0}" == "0" ]] && ! docker inspect "${CFG_APP_NAME}" >/dev/null 2>&1; then
    v07_write_action_report "adopt" "failed" "container not found"
    return 1
  fi

  if [[ -z "${CFG_DOCKER_IMAGE}" ]]; then
    if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
      CFG_DOCKER_IMAGE="ghcr.io/1186258278/openclaw-zh:latest"
    else
      CFG_DOCKER_IMAGE=$(docker inspect -f '{{.Config.Image}}' "${CFG_APP_NAME}" 2>/dev/null || true)
    fi
  fi
  if [[ "${CFG_DOCKER_IMAGE}" == *"openclaw-zh"* ]]; then
    CFG_SOURCE="chinese"
    CFG_CHANNEL="${CFG_CHANNEL:-stable}"
  else
    CFG_SOURCE="official"
    CFG_CHANNEL="${CFG_CHANNEL:-stable}"
  fi

  if [[ -z "${CFG_DATA_DIR}" ]]; then
    CFG_DATA_DIR=$(v07_detect_data_dir_from_container "${CFG_APP_NAME}" || true)
  fi
  if [[ -z "${CFG_DATA_DIR}" ]]; then
    local is_1panel
    is_1panel=$(v07_is_1panel_mode)
    CFG_DATA_DIR=$(v07_host_data_dir "${ENV_OS:-linux}" "${is_1panel}" "${CFG_APP_NAME}")
  fi

  if [[ -z "${CFG_HOST_PORT}" ]]; then
    CFG_HOST_PORT=$(v07_detect_host_port_from_container "${CFG_APP_NAME}" || true)
  fi
  [[ -n "${CFG_HOST_PORT}" ]] || CFG_HOST_PORT=$(v07_find_free_port 7100 7200)
  v07_allocate_port_block "${CFG_HOST_PORT}"

  CFG_RUNTIME_DIR="${CFG_DATA_DIR}/runtime"
  CFG_COMPOSE_FILE="${CFG_RUNTIME_DIR}/${V07_COMPOSE_FILE_BASENAME}"
  v07_step write_config
  v07_save_runtime_config >/dev/null
  v07_write_action_report "adopt" "success"
}

v07_action_persist() {
  v07_prepare_context "persist"

  v07_step prepare_dirs
  v07_ensure_runtime_dirs "${CFG_DATA_DIR}" "${CFG_RUNTIME_DIR}"

  v07_step compose_down
  v07_docker_compose_down "${CFG_COMPOSE_FILE}"

  v07_step generate_compose
  v07_generate_compose_file "${CFG_COMPOSE_FILE}" "${CFG_APP_NAME}" "${CFG_DOCKER_IMAGE}" "${CFG_SOURCE}" "${CFG_DATA_DIR}" "${CFG_HOST_PORT}" "${CFG_PORT_RESERVED_1}" "${CFG_PORT_RESERVED_2}" "${CFG_PORT_RESERVED_3}" "${CFG_EASYCLAW_ENABLED}" "${CFG_EASYCLAW_PORT}" >/dev/null

  v07_apply_compose_deployment

  v07_step wait_healthy
  if ! v07_wait_container_healthy "${CFG_APP_NAME}" 90; then
    v07_write_action_report "persist" "failed" "container startup timeout"
    return 1
  fi

  v07_step write_config
  v07_save_runtime_config >/dev/null
  v07_write_action_report "persist" "success"
}

v07_native_channel_tag() {
  local source="$1"
  local channel="$2"
  case "${source}" in
    official)
      [[ "${channel}" == "beta" ]] && printf 'beta\n' || printf 'latest\n'
      ;;
    *)
      [[ "${channel}" == "nightly" ]] && printf 'nightly\n' || printf 'latest\n'
      ;;
  esac
}

v07_action_native() {
  v07_init_runtime_config_defaults
  local package_name
  if [[ "${CFG_SOURCE}" == "official" ]]; then
    package_name="openclaw"
  else
    package_name="@qingchencloud/openclaw-zh"
  fi
  local tag
  tag="${CFG_VERSION_REQUEST:-}"
  [[ -n "${tag}" ]] || tag=$(v07_native_channel_tag "${CFG_SOURCE}" "${CFG_CHANNEL}")
  local package_ref="${package_name}@${tag}"

  if [[ -z "${CFG_DATA_DIR}" ]]; then
    local is_1panel
    is_1panel=$(v07_is_1panel_mode)
    CFG_DATA_DIR=$(v07_host_data_dir "${ENV_OS:-linux}" "${is_1panel}" "${CFG_APP_NAME}")
  fi
  local native_prefix="${CFG_DATA_DIR}/native"
  v07_run_cmd mkdir -p "${native_prefix}"
  if [[ "${V07_DRY_RUN:-0}" == "0" ]] && ! command -v npm >/dev/null 2>&1; then
    v07_write_action_report "native" "failed" "npm not found"
    return 1
  fi
  v07_run_cmd npm install -g --prefix "${native_prefix}" "${package_ref}"
  v07_write_action_report "native" "success"
}

v07_action_info() {
  v07_init_runtime_config_defaults
  if [[ -z "${CFG_DATA_DIR}" ]]; then
    local is_1panel
    is_1panel=$(v07_is_1panel_mode)
    CFG_DATA_DIR=$(v07_host_data_dir "${ENV_OS:-linux}" "${is_1panel}" "${CFG_APP_NAME}")
  fi
  local report_file
  report_file=$(v07_report_path "${CFG_DATA_DIR}")
  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    printf 'STRICT_REPORT_PATH=%s\n' "${report_file}"
    return 0
  fi
  if [[ -f "${report_file}" ]]; then
    cat "${report_file}"
  else
    printf 'STRICT_REPORT_PATH=%s\n' "${report_file}"
    v07_log_warn "strict report 不存在，请先执行 install/upgrade/rebuild"
  fi
}

v07_run_action() {
  local action="$1"
  case "${action}" in
    install) v07_action_install ;;
    upgrade) v07_action_upgrade ;;
    rebuild) v07_action_rebuild ;;
    uninstall) v07_action_uninstall ;;
    status) v07_action_status ;;
    logs) v07_action_logs ;;
    adopt) v07_action_adopt ;;
    persist) v07_action_persist ;;
    native) v07_action_native ;;
    info) v07_action_info ;;
    *)
      v07_log_error "不支持的动作: ${action}"
      return 1
      ;;
  esac
}
