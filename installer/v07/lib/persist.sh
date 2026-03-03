#!/usr/bin/env bash

set -euo pipefail

v07_container_config_dir() {
  local source="${1:-chinese}"
  case "${source}" in
    official) printf '/home/node/.openclaw\n' ;;
    chinese) printf '/root/.openclaw\n' ;;
    *)
      v07_log_error "未知镜像源: ${source}"
      return 1
      ;;
  esac
}

v07_container_workspace_dir() {
  local source="${1:-chinese}"
  case "${source}" in
    official) printf '/home/node/openclaw/workspace\n' ;;
    chinese) printf '/root/.openclaw/workspace\n' ;;
    *)
      v07_log_error "未知镜像源: ${source}"
      return 1
      ;;
  esac
}

v07_host_data_dir() {
  local os_name="${1:-linux}"
  local is_1panel="${2:-0}"
  local app_name="${3:-openclaw}"

  if [[ "${os_name}" == "linux" && "${is_1panel}" == "1" ]]; then
    printf '/opt/1panel/apps/%s\n' "${app_name}"
    return 0
  fi

  printf '%s\n' "${HOME}/.openclaw"
}

v07_host_workspace_dir() {
  local data_dir="$1"
  printf '%s/workspace\n' "${data_dir}"
}

v07_build_core_mounts() {
  local source="$1"
  local data_dir="$2"
  local cfg_dir ws_dir
  cfg_dir=$(v07_container_config_dir "${source}")
  ws_dir=$(v07_container_workspace_dir "${source}")

  cat <<MOUNTS
${data_dir}:${cfg_dir}
$(v07_host_workspace_dir "${data_dir}"):${ws_dir}
MOUNTS
}
