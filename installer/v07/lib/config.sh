#!/usr/bin/env bash

set -euo pipefail

V07_APP_NAME_DEFAULT="openclaw"
V07_DATA_DIR_LINUX_DEFAULT="${HOME}/.openclaw"
V07_WORKSPACE_DIR_LINUX_DEFAULT="${HOME}/openclaw/workspace"
V07_COMPOSE_FILE_BASENAME="docker-compose.yml"

v07_default_config_dir() {
  printf '%s\n' "${HOME}/.openclaw-installer"
}

v07_default_config_file() {
  printf '%s\n' "$(v07_default_config_dir)/config.env"
}

v07_load_config_file() {
  local config_file="$1"
  [[ -f "${config_file}" ]] || return 1

  # shellcheck disable=SC1090
  source "${config_file}"
  return 0
}

v07_init_runtime_config_defaults() {
  CFG_APP_NAME="${CFG_APP_NAME:-${V07_APP_NAME_DEFAULT}}"
  CFG_SOURCE="${CFG_SOURCE:-chinese}"
  CFG_CHANNEL="${CFG_CHANNEL:-stable}"
  CFG_VERSION_REQUEST="${CFG_VERSION_REQUEST:-}"
  CFG_ACCESS_MODE="${CFG_ACCESS_MODE:-remote}"
  CFG_AUTH_TOKEN="${CFG_AUTH_TOKEN:-}"
  CFG_HOST_PORT="${CFG_HOST_PORT:-}"
  CFG_PORT_RESERVED_1="${CFG_PORT_RESERVED_1:-}"
  CFG_PORT_RESERVED_2="${CFG_PORT_RESERVED_2:-}"
  CFG_PORT_RESERVED_3="${CFG_PORT_RESERVED_3:-}"
  CFG_EASYCLAW_ENABLED="${CFG_EASYCLAW_ENABLED:-0}"
  CFG_EASYCLAW_PORT="${CFG_EASYCLAW_PORT:-}"
  CFG_UNINSTALL_MODE="${CFG_UNINSTALL_MODE:-safe}"
  CFG_1PANEL_MODE="${CFG_1PANEL_MODE:-auto}"
  CFG_1PANEL_DEPLOY_MODE="${CFG_1PANEL_DEPLOY_MODE:-compose}"
  CFG_DATA_DIR="${CFG_DATA_DIR:-}"
  CFG_VERSION_TAG="${CFG_VERSION_TAG:-}"
  CFG_DOCKER_IMAGE="${CFG_DOCKER_IMAGE:-}"
  CFG_COMPOSE_FILE="${CFG_COMPOSE_FILE:-}"
  CFG_RUNTIME_DIR="${CFG_RUNTIME_DIR:-}"
}

v07_export_config_lines() {
  cat <<EOF
CFG_APP_NAME=${CFG_APP_NAME}
CFG_SOURCE=${CFG_SOURCE}
CFG_CHANNEL=${CFG_CHANNEL}
CFG_VERSION_REQUEST=${CFG_VERSION_REQUEST}
CFG_VERSION_TAG=${CFG_VERSION_TAG}
CFG_DOCKER_IMAGE=${CFG_DOCKER_IMAGE}
CFG_ACCESS_MODE=${CFG_ACCESS_MODE}
CFG_AUTH_TOKEN=${CFG_AUTH_TOKEN}
CFG_HOST_PORT=${CFG_HOST_PORT}
CFG_PORT_RESERVED_1=${CFG_PORT_RESERVED_1}
CFG_PORT_RESERVED_2=${CFG_PORT_RESERVED_2}
CFG_PORT_RESERVED_3=${CFG_PORT_RESERVED_3}
CFG_EASYCLAW_ENABLED=${CFG_EASYCLAW_ENABLED}
CFG_EASYCLAW_PORT=${CFG_EASYCLAW_PORT}
CFG_UNINSTALL_MODE=${CFG_UNINSTALL_MODE}
CFG_1PANEL_MODE=${CFG_1PANEL_MODE}
CFG_1PANEL_DEPLOY_MODE=${CFG_1PANEL_DEPLOY_MODE}
CFG_DATA_DIR=${CFG_DATA_DIR}
CFG_COMPOSE_FILE=${CFG_COMPOSE_FILE}
CFG_RUNTIME_DIR=${CFG_RUNTIME_DIR}
EOF
}

v07_save_runtime_config() {
  local config_file
  config_file="${V07_CONFIG_FILE:-$(v07_default_config_file)}"
  v07_write_config_file "${config_file}" "$(v07_export_config_lines)"
  printf '%s\n' "${config_file}"
}

v07_write_config_file() {
  local config_file="$1"
  shift || true
  mkdir -p "$(dirname "${config_file}")"
  printf '%s\n' "$@" > "${config_file}"
}
