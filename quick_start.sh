#!/usr/bin/env bash
set -euo pipefail

OPENCLAWCTL_REPO="${OPENCLAWCTL_REPO:-moshall/Openclaw_docker_install}"
OPENCLAWCTL_REF="${OPENCLAWCTL_REF:-main}"
OPENCLAWCTL_ENTRY_SCRIPT="${OPENCLAWCTL_ENTRY_SCRIPT:-openclawctl.sh}"
OPENCLAWCTL_QUICKSTART_SOURCE_DIR="${OPENCLAWCTL_QUICKSTART_SOURCE_DIR:-}"

tmp_quickstart_dir=""

log_info() {
  if [[ "${OPENCLAWCTL_QUICKSTART_QUIET:-0}" != "1" ]]; then
    printf '[quick-start] %s\n' "$*" >&2
  fi
}

log_error() {
  printf '[quick-start][ERROR] %s\n' "$*" >&2
}

cleanup_tmp_dir() {
  if [[ -n "${tmp_quickstart_dir}" && -d "${tmp_quickstart_dir}" ]]; then
    rm -rf "${tmp_quickstart_dir}"
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_url() {
  local url="$1"
  local output_file="$2"
  if has_cmd curl; then
    curl -fsSL "${url}" -o "${output_file}"
    return $?
  fi
  if has_cmd wget; then
    wget -qO "${output_file}" "${url}"
    return $?
  fi
  return 1
}

detect_source_dir_from_archive() {
  local archive_file="$1"
  local extract_dir="$2"
  tar -xzf "${archive_file}" -C "${extract_dir}"
  find "${extract_dir}" -mindepth 1 -maxdepth 1 -type d | head -n1
}

resolve_remote_source_dir() {
  tmp_quickstart_dir=$(mktemp -d)
  trap cleanup_tmp_dir EXIT
  local archive_file="${tmp_quickstart_dir}/openclawctl-src.tar.gz"
  local extracted_root="${tmp_quickstart_dir}/extract"
  mkdir -p "${extracted_root}"

  local -a candidate_urls=(
    "https://codeload.github.com/${OPENCLAWCTL_REPO}/tar.gz/refs/heads/${OPENCLAWCTL_REF}"
    "https://codeload.github.com/${OPENCLAWCTL_REPO}/tar.gz/refs/tags/${OPENCLAWCTL_REF}"
    "https://codeload.github.com/${OPENCLAWCTL_REPO}/tar.gz/${OPENCLAWCTL_REF}"
  )

  local url
  for url in "${candidate_urls[@]}"; do
    if download_url "${url}" "${archive_file}"; then
      log_info "已下载源码包: ${url}"
      local source_dir
      source_dir=$(detect_source_dir_from_archive "${archive_file}" "${extracted_root}")
      if [[ -n "${source_dir}" && -d "${source_dir}" ]]; then
        printf '%s\n' "${source_dir}"
        return 0
      fi
    fi
  done

  log_error "无法下载仓库 ${OPENCLAWCTL_REPO}（ref=${OPENCLAWCTL_REF}）"
  log_error "请检查网络、仓库地址，或设置 OPENCLAWCTL_QUICKSTART_SOURCE_DIR 指向本地源码目录"
  return 1
}

resolve_source_dir() {
  if [[ -n "${OPENCLAWCTL_QUICKSTART_SOURCE_DIR}" ]]; then
    if [[ ! -d "${OPENCLAWCTL_QUICKSTART_SOURCE_DIR}" ]]; then
      log_error "指定的本地源码目录不存在: ${OPENCLAWCTL_QUICKSTART_SOURCE_DIR}"
      return 1
    fi
    printf '%s\n' "${OPENCLAWCTL_QUICKSTART_SOURCE_DIR}"
    return 0
  fi

  resolve_remote_source_dir
}

validate_source_layout() {
  local source_dir="$1"
  if [[ ! -f "${source_dir}/${OPENCLAWCTL_ENTRY_SCRIPT}" ]]; then
    log_error "未找到入口脚本: ${source_dir}/${OPENCLAWCTL_ENTRY_SCRIPT}"
    return 1
  fi
  if [[ ! -d "${source_dir}/lib/openclawctl" ]]; then
    log_error "未找到模块目录: ${source_dir}/lib/openclawctl"
    return 1
  fi
  return 0
}

main() {
  local source_dir
  source_dir=$(resolve_source_dir) || exit 1
  validate_source_layout "${source_dir}" || exit 1

  chmod +x "${source_dir}/${OPENCLAWCTL_ENTRY_SCRIPT}" >/dev/null 2>&1 || true

  log_info "启动 OpenClaw 菜单（repo=${OPENCLAWCTL_REPO}, ref=${OPENCLAWCTL_REF}）"
  bash "${source_dir}/${OPENCLAWCTL_ENTRY_SCRIPT}" "$@"
}

main "$@"
