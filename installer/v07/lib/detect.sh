#!/usr/bin/env bash

set -euo pipefail

ENV_OS="unknown"
ENV_DISTRO="unknown"
ENV_DISTRO_VERSION="unknown"
ENV_ARCH="unknown"
ENV_1PANEL="0"
ENV_1PANEL_VERSION=""
ENV_DOCKER="0"
ENV_DOCKER_VERSION=""
ENV_DOCKER_COMPOSE="0"
ENV_NODE=""
ENV_EXISTING_INSTALL="0"
ENV_OPENCLAW_RUNNING="0"

v07_map_arch() {
  local raw_arch="$1"
  case "${raw_arch}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "${raw_arch}" ;;
  esac
}

v07_detect_os() {
  local uname_s
  uname_s=$(uname -s 2>/dev/null || echo "unknown")
  case "${uname_s}" in
    Linux) ENV_OS="linux" ;;
    Darwin) ENV_OS="macos" ;;
    *) ENV_OS="unknown" ;;
  esac

  local uname_m
  uname_m=$(uname -m 2>/dev/null || echo "unknown")
  ENV_ARCH=$(v07_map_arch "${uname_m}")
}

v07_detect_distro() {
  local os_release_file="${V07_TEST_OS_RELEASE_FILE:-/etc/os-release}"
  if [[ -f "${os_release_file}" ]]; then
    local id version_id
    id=$(awk -F '=' '$1=="ID" {gsub(/"/,"",$2); print $2}' "${os_release_file}" | tail -n1)
    version_id=$(awk -F '=' '$1=="VERSION_ID" {gsub(/"/,"",$2); print $2}' "${os_release_file}" | tail -n1)
    [[ -n "${id}" ]] && ENV_DISTRO="${id}"
    [[ -n "${version_id}" ]] && ENV_DISTRO_VERSION="${version_id}"
  fi
}

v07_detect_1panel() {
  if command -v 1pctl >/dev/null 2>&1 || [[ -d /opt/1panel ]]; then
    ENV_1PANEL="1"
  else
    ENV_1PANEL="0"
  fi

  if [[ "${ENV_1PANEL}" == "1" ]] && command -v 1pctl >/dev/null 2>&1; then
    ENV_1PANEL_VERSION=$(1pctl version 2>/dev/null | head -n1 || true)
  else
    ENV_1PANEL_VERSION=""
  fi
}

v07_detect_docker() {
  if command -v docker >/dev/null 2>&1; then
    ENV_DOCKER="1"
    ENV_DOCKER_VERSION=$(docker --version 2>/dev/null | head -n1 || true)
  else
    ENV_DOCKER="0"
    ENV_DOCKER_VERSION=""
  fi

  if [[ "${ENV_DOCKER}" == "1" ]] && docker compose version >/dev/null 2>&1; then
    ENV_DOCKER_COMPOSE="1"
  else
    ENV_DOCKER_COMPOSE="0"
  fi
}

v07_detect_node() {
  if command -v node >/dev/null 2>&1; then
    ENV_NODE=$(node --version 2>/dev/null | head -n1 || true)
  else
    ENV_NODE=""
  fi
}

v07_detect_existing_install() {
  local config_file
  config_file=$(v07_default_config_file)
  if [[ -n "${V07_CONFIG_FILE:-}" ]]; then
    config_file="${V07_CONFIG_FILE}"
  fi

  if [[ -f "${config_file}" ]]; then
    ENV_EXISTING_INSTALL="1"
  else
    ENV_EXISTING_INSTALL="0"
  fi
}

v07_detect_openclaw_running() {
  local container_name="${V07_APP_NAME_DEFAULT}"
  if [[ -n "${CFG_APP_NAME:-}" ]]; then
    container_name="${CFG_APP_NAME}"
  fi

  if [[ "${ENV_DOCKER}" == "1" ]] && docker ps --filter "name=^${container_name}$" --format '{{.Names}}' 2>/dev/null | grep -q .; then
    ENV_OPENCLAW_RUNNING="1"
  else
    ENV_OPENCLAW_RUNNING="0"
  fi
}

v07_detect_environment() {
  v07_detect_os
  v07_detect_distro
  v07_detect_1panel
  v07_detect_docker
  v07_detect_node
  v07_detect_existing_install
  v07_detect_openclaw_running
}

v07_print_env_summary() {
  local docker_label="❌"
  local panel_label="❌"
  [[ "${ENV_DOCKER}" == "1" ]] && docker_label="✅"
  [[ "${ENV_1PANEL}" == "1" ]] && panel_label="✅"

  printf '环境：%s %s (%s)\n' "${ENV_DISTRO}" "${ENV_DISTRO_VERSION}" "${ENV_ARCH}"
  printf 'Docker：%s | 1Panel：%s\n' "${docker_label}" "${panel_label}"
}
