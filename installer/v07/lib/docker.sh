#!/usr/bin/env bash

set -euo pipefail

v07_ensure_runtime_dirs() {
  local data_dir="$1"
  local runtime_dir="$2"
  v07_run_cmd mkdir -p "${data_dir}" "${runtime_dir}" "${data_dir}/workspace"
}

v07_docker_pull_image() {
  local image="$1"
  v07_run_cmd docker pull "${image}"
}

v07_docker_compose_up() {
  local compose_file="$1"
  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    v07_run_cmd echo docker compose -f "${compose_file}" up -d
    return 0
  fi
  docker compose -f "${compose_file}" up -d
}

v07_docker_compose_down() {
  local compose_file="$1"
  if [[ ! -f "${compose_file}" ]]; then
    return 0
  fi
  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    v07_run_cmd echo docker compose -f "${compose_file}" down
    return 0
  fi
  docker compose -f "${compose_file}" down
}

v07_wait_container_healthy() {
  local container_name="$1"
  local timeout_secs="${2:-60}"

  if [[ "${V07_DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi

  local start_ts
  start_ts=$(date +%s)
  while true; do
    if docker ps --filter "name=^${container_name}$" --format '{{.Names}}' | grep -q .; then
      return 0
    fi
    if (( $(date +%s) - start_ts > timeout_secs )); then
      return 1
    fi
    sleep 1
  done
}

v07_container_logs() {
  local container_name="$1"
  local lines="${2:-80}"
  v07_run_cmd docker logs --tail "${lines}" "${container_name}"
}
