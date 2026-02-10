#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
DEFAULT_HOST_PORT="4113"
DEFAULT_CONTAINER_PORT="18789"
DEFAULT_RESTART_POLICY="unless-stopped"
EASY_CLI_REPO="https://github.com/moshall/Openclaw_Easy_Cli"

print_cmd() {
  local rendered=()
  local arg
  for arg in "$@"; do
    rendered+=("$(printf '%q' "$arg")")
  done
  printf '%s\n' "${rendered[*]}"
}

run_cmd() {
  print_cmd "$@"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    "$@"
  fi
}

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_error() {
  printf '[ERROR] %s\n' "$*" >&2
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

read_with_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  printf '%s [%s]: ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
}

read_required() {
  local prompt="$1"
  local value
  while true; do
    printf '%s: ' "${prompt}" >&2
    IFS= read -r value
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
    log_error "该项不能为空"
  done
}

read_choice_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  printf '%s [%s]: ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
}

resolve_image() {
  local source_choice="$1"
  local channel_choice="$2"

  if [[ "${source_choice}" == "1" && "${channel_choice}" == "1" ]]; then
    printf '%s\n' "docker.io/openclaw/openclaw:latest"
    return
  fi

  if [[ "${source_choice}" == "1" && "${channel_choice}" == "2" ]]; then
    printf '%s\n' "docker.io/openclaw/openclaw:beta"
    return
  fi

  if [[ "${source_choice}" == "2" && "${channel_choice}" == "1" ]]; then
    printf '%s\n' "ghcr.io/1186258278/openclaw-zh:latest"
    return
  fi

  if [[ "${source_choice}" == "2" && "${channel_choice}" == "2" ]]; then
    printf '%s\n' "ghcr.io/1186258278/openclaw-zh:nightly"
    return
  fi

  log_error "版本选择无效"
  return 1
}

remove_container_if_exists() {
  local name="$1"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd docker rm -f "${name}"
    return
  fi

  if docker ps -a --format '{{.Names}}' | grep -Fxq "${name}"; then
    run_cmd docker rm -f "${name}"
  else
    log_info "容器 ${name} 不存在，跳过删除"
  fi
}

bootstrap_openclaw_config() {
  local image="$1"
  local data_dir="$2"
  local container_port="$3"
  local gateway_bind="$4"
  local token="$5"

  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw setup
  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.mode local
  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.port "${container_port}"
  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.bind "${gateway_bind}"
  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.mode token
  run_cmd docker run --rm -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.token "${token}"
}

run_gateway_container() {
  local name="$1"
  local image="$2"
  local host_port="$3"
  local container_port="$4"
  local data_dir="$5"

  run_cmd docker run -d \
    --name "${name}" \
    --restart "${DEFAULT_RESTART_POLICY}" \
    -p "${host_port}:${container_port}" \
    -v "${data_dir}:/root/.openclaw" \
    --add-host=host.docker.internal:host-gateway \
    "${image}" \
    openclaw gateway run
}

install_easy_cli() {
  local data_dir="$1"
  local target_dir="${data_dir}/Openclaw_Easy_Cli"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd git clone "${EASY_CLI_REPO}" "${target_dir}"
    return
  fi

  if [[ -d "${target_dir}/.git" ]]; then
    run_cmd git -C "${target_dir}" pull
  else
    run_cmd git clone "${EASY_CLI_REPO}" "${target_dir}"
  fi
}

check_and_upgrade_easy_cli() {
  local data_dir="$1"
  local target_dir="${data_dir}/Openclaw_Easy_Cli"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd git -C "${target_dir}" fetch --all --prune
    run_cmd git -C "${target_dir}" rev-list --left-right --count HEAD...@{upstream}
    run_cmd git -C "${target_dir}" pull --ff-only
    return
  fi

  if [[ ! -d "${target_dir}/.git" ]]; then
    log_info "未发现 Easy CLI 仓库，跳过升级检查: ${target_dir}"
    return
  fi

  run_cmd git -C "${target_dir}" fetch --all --prune

  local upstream
  upstream=$(git -C "${target_dir}" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
  if [[ -z "${upstream}" ]]; then
    log_info "Easy CLI 未配置上游分支，跳过版本检查"
    return
  fi

  local counts ahead behind
  counts=$(git -C "${target_dir}" rev-list --left-right --count HEAD...@{upstream})
  read -r ahead behind <<<"${counts}"

  if [[ -n "${behind}" && "${behind}" -gt 0 ]]; then
    log_info "检测到 Easy CLI 可升级（落后 ${behind} 个提交），开始升级"
    run_cmd git -C "${target_dir}" pull --ff-only
  else
    log_info "Easy CLI 已是最新"
  fi
}

validate_yes_no() {
  local input="$1"
  if [[ "${input}" != "y" && "${input}" != "Y" ]]; then
    return 1
  fi
  return 0
}

detect_existing_data_dir() {
  local name="$1"
  local fallback="$2"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s\n' "${fallback}"
    return
  fi

  local detected
  detected=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/root/.openclaw"}}{{.Source}}{{end}}{{end}}' "${name}" 2>/dev/null || true)
  if [[ -n "${detected}" ]]; then
    printf '%s\n' "${detected}"
  else
    printf '%s\n' "${fallback}"
  fi
}

detect_existing_ports() {
  local name="$1"
  local fallback_host="$2"
  local fallback_container="$3"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
    return
  fi

  local line
  line=$(docker port "${name}" 2>/dev/null | head -n 1 || true)
  if [[ -z "${line}" ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
    return
  fi

  local container_port host_port
  container_port=$(printf '%s' "${line}" | sed -E 's#^([0-9]+)/tcp.*#\1#')
  host_port=$(printf '%s' "${line}" | sed -E 's#.*:([0-9]+)$#\1#')

  if [[ -z "${container_port}" || -z "${host_port}" ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
  else
    printf '%s,%s\n' "${host_port}" "${container_port}"
  fi
}

is_container_running() {
  local name="$1"

  case "${OPENCLAWCTL_RUNNING_STATE:-}" in
    running) return 0 ;;
    stopped) return 1 ;;
  esac

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi

  local running
  running=$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)
  [[ "${running}" == "true" ]]
}

install_wizard() {
  echo "\n=== 新装 ==="
  echo "版本来源:"
  echo "  1) 官方"
  echo "  2) 中文版"
  local source_choice
  source_choice=$(read_choice_default "请选择" "2")

  echo "版本通道:"
  echo "  1) 稳定版"
  echo "  2) 最新版"
  local channel_choice
  channel_choice=$(read_choice_default "请选择" "1")

  local image
  image=$(resolve_image "${source_choice}" "${channel_choice}") || return

  local host_port
  host_port=$(read_with_default "宿主机端口" "${DEFAULT_HOST_PORT}")

  local container_port
  container_port=$(read_with_default "OpenClaw 容器内部端口" "${DEFAULT_CONTAINER_PORT}")

  local name
  name=$(read_required "Docker 容器名")

  local data_dir
  data_dir=$(read_with_default "持久化目录" "/opt/1panel/apps/${name}")

  echo "网络绑定:"
  echo "  1) local"
  echo "  2) lan"
  local bind_choice
  bind_choice=$(read_choice_default "请选择" "2")

  local gateway_bind
  if [[ "${bind_choice}" == "1" ]]; then
    gateway_bind="local"
  else
    gateway_bind="lan"
  fi

  echo "是否安装 Easy CLI (默认是):"
  echo "  1) 是"
  echo "  2) 否"
  local easy_choice
  easy_choice=$(read_choice_default "请选择" "1")

  echo "Token 方式:"
  echo "  1) 自动生成"
  echo "  2) 手动输入"
  local token_mode
  token_mode=$(read_choice_default "请选择" "1")

  local token
  if [[ "${token_mode}" == "2" ]]; then
    token=$(read_required "请输入 token")
  else
    token=$(generate_token)
  fi

  echo "\n--- 配置预览 ---"
  echo "镜像: ${image}"
  echo "容器名: ${name}"
  echo "端口映射: ${host_port}:${container_port}"
  echo "持久化目录: ${data_dir}"
  echo "gateway.bind: ${gateway_bind}"
  echo "Easy CLI: $([[ "${easy_choice}" == "1" ]] && echo "是" || echo "否")"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  run_cmd mkdir -p "${data_dir}"
  run_cmd docker pull "${image}"
  remove_container_if_exists "${name}"
  bootstrap_openclaw_config "${image}" "${data_dir}" "${container_port}" "${gateway_bind}" "${token}"
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}"

  if [[ "${easy_choice}" == "1" ]]; then
    install_easy_cli "${data_dir}"
  fi

  printf 'TOKEN=%s\n' "${token}"
  printf 'URL=http://<server-ip>:%s/?token=%s\n' "${host_port}" "${token}"
}

upgrade_wizard() {
  echo "\n=== 升级（安全升级） ==="
  local name
  name=$(read_required "请输入要升级的容器名")

  if is_container_running "${name}"; then
    log_info "检测到容器 ${name} 正在运行，升级会中断当前任务。"
    printf '是否继续升级? (y/N): '
    local running_confirm
    IFS= read -r running_confirm
    if ! validate_yes_no "${running_confirm}"; then
      log_info "已取消升级"
      return
    fi
  fi

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  local detected_host_port="${port_pair%%,*}"
  local detected_container_port="${port_pair##*,}"

  echo "目标版本来源:"
  echo "  1) 官方"
  echo "  2) 中文版"
  local source_choice
  source_choice=$(read_choice_default "请选择" "2")

  echo "目标版本通道:"
  echo "  1) 稳定版"
  echo "  2) 最新版"
  local channel_choice
  channel_choice=$(read_choice_default "请选择" "1")

  local image
  image=$(resolve_image "${source_choice}" "${channel_choice}") || return

  local host_port
  host_port=$(read_with_default "宿主机端口" "${detected_host_port}")

  local container_port
  container_port=$(read_with_default "OpenClaw 容器内部端口" "${detected_container_port}")

  local data_dir
  data_dir=$(read_with_default "持久化目录（安全升级会复用）" "${detected_data_dir}")

  echo "是否检查并升级 Easy CLI (默认是):"
  echo "  1) 是"
  echo "  2) 否"
  local easy_cli_upgrade
  easy_cli_upgrade=$(read_choice_default "请选择" "1")

  echo "\n--- 升级预览 ---"
  echo "容器名: ${name}"
  echo "目标镜像: ${image}"
  echo "端口映射: ${host_port}:${container_port}"
  echo "持久化目录(保留): ${data_dir}"
  echo "Easy CLI 检查升级: $([[ "${easy_cli_upgrade}" == "1" ]] && echo "是" || echo "否")"
  printf '确认执行安全升级? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  run_cmd mkdir -p "${data_dir}"
  run_cmd docker pull "${image}"
  remove_container_if_exists "${name}"
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}"

  run_cmd docker ps --filter "name=${name}"
  run_cmd docker logs --tail 30 "${name}"
  run_cmd docker exec "${name}" openclaw --version

  if [[ "${easy_cli_upgrade}" == "1" ]]; then
    check_and_upgrade_easy_cli "${data_dir}"
  fi
}

uninstall_wizard() {
  echo "\n=== 卸载 ==="
  local name
  name=$(read_required "请输入要卸载的容器名")

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  echo "卸载模式:"
  echo "  1) 安全卸载（仅删容器，保留持久化目录）"
  echo "  2) 完整卸载（删容器 + 删持久化目录）"
  local mode
  mode=$(read_choice_default "请选择" "1")

  local data_dir
  data_dir=$(read_with_default "持久化目录" "${detected_data_dir}")

  echo "\n二次确认：请输入容器名 ${name}"
  local confirm_name
  confirm_name=$(read_required "确认容器名")
  if [[ "${confirm_name}" != "${name}" ]]; then
    log_error "二次确认失败，已取消"
    return
  fi

  remove_container_if_exists "${name}"
  if [[ "${mode}" == "2" ]]; then
    run_cmd rm -rf "${data_dir}"
  fi
}

easy_cli_only_upgrade_wizard() {
  echo "\n=== 仅升级 Easy CLI ==="
  local name
  name=$(read_required "请输入容器名（用于定位持久化目录）")

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local data_dir
  data_dir=$(read_with_default "Easy CLI 所在持久化目录" "${detected_data_dir}")

  echo "\n--- 任务预览 ---"
  echo "容器名: ${name}"
  echo "Easy CLI 目录: ${data_dir}/Openclaw_Easy_Cli"
  printf '确认仅升级 Easy CLI? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  check_and_upgrade_easy_cli "${data_dir}"
}

show_main_menu() {
  echo
  echo "==============================="
  echo " OpenClaw 交互式部署助手"
  echo "==============================="
  echo "1) 新装"
  echo "2) 升级（安全升级）"
  echo "3) 卸载"
  echo "4) 仅升级 Easy CLI"
  echo "0) 退出"
}

main_loop() {
  local choice
  while true; do
    show_main_menu
    choice=$(read_choice_default "请选择功能" "0")

    case "${choice}" in
      1) install_wizard ;;
      2) upgrade_wizard ;;
      3) uninstall_wizard ;;
      4) easy_cli_only_upgrade_wizard ;;
      0)
        log_info "已退出"
        return
        ;;
      *)
        log_error "无效选择"
        ;;
    esac
  done
}

parse_global_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --help|-h)
        echo "用法: bash openclawctl.sh [--dry-run]"
        echo "默认进入交互式菜单。"
        exit 0
        ;;
      *)
        log_error "未知参数: $1"
        echo "用法: bash openclawctl.sh [--dry-run]"
        exit 1
        ;;
    esac
  done
}

parse_global_flags "$@"
main_loop
