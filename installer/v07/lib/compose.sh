#!/usr/bin/env bash

set -euo pipefail

v07_template_replace() {
  local content="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped=$(printf '%s' "${value}" | sed -e 's/[\/&]/\\&/g')
  printf '%s' "${content}" | sed -e "s/${key}/${escaped}/g"
}

v07_render_compose_yaml() {
  local app_name="$1"
  local image="$2"
  local source="$3"
  local data_dir="$4"
  local port_main="$5"
  local port_r1="$6"
  local port_r2="$7"
  local port_r3="$8"
  local easyclaw_enabled="${9:-0}"
  local easyclaw_port="${10:-}"

  local template_file
  template_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/templates/docker-compose.yml.tmpl"
  [[ -f "${template_file}" ]] || {
    v07_log_error "compose 模板不存在: ${template_file}"
    return 1
  }

  local container_cfg_dir container_ws_dir host_ws_dir
  container_cfg_dir=$(v07_container_config_dir "${source}")
  container_ws_dir=$(v07_container_workspace_dir "${source}")
  host_ws_dir=$(v07_host_workspace_dir "${data_dir}")

  local easy_line=""
  if [[ "${easyclaw_enabled}" == "1" && -n "${easyclaw_port}" ]]; then
    easy_line="      - \"${easyclaw_port}:4231\""
  fi

  local content
  content=$(cat "${template_file}")
  content=$(v07_template_replace "${content}" "__APP_NAME__" "${app_name}")
  content=$(v07_template_replace "${content}" "__IMAGE__" "${image}")
  content=$(v07_template_replace "${content}" "__PORT_MAIN__" "${port_main}")
  content=$(v07_template_replace "${content}" "__PORT_R1__" "${port_r1}")
  content=$(v07_template_replace "${content}" "__PORT_R2__" "${port_r2}")
  content=$(v07_template_replace "${content}" "__PORT_R3__" "${port_r3}")
  content=$(v07_template_replace "${content}" "__EASYCLAW_PORT_LINE__" "${easy_line}")
  content=$(v07_template_replace "${content}" "__DATA_DIR__" "${data_dir}")
  content=$(v07_template_replace "${content}" "__WORKSPACE_DIR__" "${host_ws_dir}")
  content=$(v07_template_replace "${content}" "__CONTAINER_CONFIG_DIR__" "${container_cfg_dir}")
  content=$(v07_template_replace "${content}" "__CONTAINER_WORKSPACE_DIR__" "${container_ws_dir}")

  printf '%s\n' "${content}"
}

v07_generate_compose_file() {
  local output_file="$1"
  shift

  local compose_yaml
  compose_yaml=$(v07_render_compose_yaml "$@")

  mkdir -p "$(dirname "${output_file}")"
  printf '%s\n' "${compose_yaml}" > "${output_file}"
  printf '%s\n' "${output_file}"
}
