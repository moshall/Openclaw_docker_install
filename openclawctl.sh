#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DRY_RUN=0
DEFAULT_HOST_PORT="4113"
DEFAULT_CONTAINER_PORT="18789"
DEFAULT_RESTART_POLICY="unless-stopped"
EASYCLAW_REPO="https://github.com/moshall/easyclaw.git"
EASYCLAW_DEFAULT_WEB_PORT="4231"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_1="7201"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_2="7202"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_3="7203"
CLAUDECODEUI_NPM_PACKAGE="@siteboon/claude-code-ui"
TASKMASTER_NPM_PACKAGE="task-master-ai"
DEFAULT_DEP_SET="npm uv"
DEFAULT_ENABLE_BIN_PERSIST="1"
DEFAULT_ENABLE_ENV_PERSIST="2"
DEFAULT_ENABLE_APT_CONFIG_PERSIST="2"
DEFAULT_ENABLE_CACHE_PERSIST="2"
OFFICIAL_OPENCLAW_REPO_DEFAULT="1panel/openclaw"
OPENCLAWCTL_TUI_BIN="${OPENCLAWCTL_TUI_BIN:-}"
SELECTED_WIZARD=""
CONFIG_FILE=""
OPTIONAL_COMPONENTS_FILE="${OPENCLAWCTL_COMPONENTS_FILE:-${SCRIPT_DIR}/config/optional-components.conf}"
DEFAULT_OPTIONAL_SOFTWARE_ALL="gh claude codex opencode gemini notebooklm easyclaw claudecodeui obsidian ralph"
DEFAULT_OPTIONAL_SKILL_ALL="obsidian-skills security-checker"
OPTIONAL_SOFTWARE_ALL="${DEFAULT_OPTIONAL_SOFTWARE_ALL}"
OPTIONAL_SKILL_ALL="${DEFAULT_OPTIONAL_SKILL_ALL}"
OPTIONAL_SOFTWARE_CATALOG=""
OPTIONAL_SKILL_CATALOG=""

source "${SCRIPT_DIR}/lib/openclawctl/bootstrap.sh"
source "${SCRIPT_DIR}/lib/openclawctl/common.sh"
source "${SCRIPT_DIR}/lib/openclawctl/io.sh"
source "${SCRIPT_DIR}/lib/openclawctl/image.sh"
source "${SCRIPT_DIR}/lib/openclawctl/persist.sh"
source "${SCRIPT_DIR}/lib/openclawctl/components.sh"
source "${SCRIPT_DIR}/lib/openclawctl/deps.sh"
source "${SCRIPT_DIR}/lib/openclawctl/ops.sh"
source "${SCRIPT_DIR}/lib/openclawctl/wizard.sh"

strict_noninteractive_mode_enabled() {
  [[ "${OPENCLAWCTL_STRICT_NONINTERACTIVE:-0}" == "1" ]]
}

strict_report_path() {
  local data_dir="$1"
  printf '%s\n' "${data_dir}/runtime/strict-report.json"
}

deployment_info_path() {
  printf '%s\n' "${HOME}/.openclaw-installer/deployment-info.txt"
}

host_platform() {
  local os
  os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
  case "${os}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    *) echo "unknown" ;;
  esac
}

find_recommended_host_port() {
  local start="${1:-7100}"
  local end="${2:-7200}"
  local port
  for port in $(seq "${start}" "${end}"); do
    if is_host_port_available "${port}"; then
      echo "${port}"
      return 0
    fi
  done
  echo "${DEFAULT_HOST_PORT}"
}

is_1panel_environment() {
  [[ -d "/opt/1panel/apps" || -x "/usr/local/bin/1panel" || -d "/usr/local/1panel" ]]
}

default_data_root() {
  if [[ -n "${OPENCLAWCTL_DATA_ROOT:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_DATA_ROOT}"
    return
  fi

  if is_1panel_environment; then
    echo "/opt/1panel/apps"
    return
  fi

  case "$(host_platform)" in
    darwin) echo "${HOME}/.openclaw/apps" ;;
    linux) echo "/opt/openclaw/apps" ;;
    *) echo "/opt/1panel/apps" ;;
  esac
}

default_data_dir_for_name() {
  local name="$1"
  printf '%s/%s\n' "$(default_data_root)" "${name}"
}

official_openclaw_repo_path() {
  local repo="${OPENCLAW_OFFICIAL_REPO:-${OFFICIAL_OPENCLAW_REPO_DEFAULT}}"
  repo="${repo#docker.io/}"
  repo="${repo#/}"
  if [[ "${repo}" != */* ]]; then
    repo="${OFFICIAL_OPENCLAW_REPO_DEFAULT}"
  fi
  printf '%s\n' "${repo}"
}

official_openclaw_image() {
  local tag="$1"
  printf 'docker.io/%s:%s\n' "$(official_openclaw_repo_path)" "${tag}"
}

append_diagnostics_log() {
  local data_dir="$1"
  local message="$2"
  local log_file="${data_dir}/runtime/diagnostics.log"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "诊断日志(预览): ${message}"
    return
  fi
  run_cmd mkdir -p "${data_dir}/runtime"
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${message}" >> "${log_file}"
}

write_last_report() {
  local action="$1"
  local status="$2"
  local container_name="$3"
  local data_dir="$4"
  local image="${5:-}"
  local host_port="${6:-}"
  local container_port="${7:-}"
  local token="${8:-}"
  local url="${9:-}"
  shift 9
  local notes
  notes=$(join_with_semicolon "$@")
  local report_file="${data_dir}/runtime/last_report.json"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "执行报告(预览): action=${action}, status=${status}, container=${container_name}"
    if strict_noninteractive_mode_enabled; then
      printf 'STRICT_REPORT_PATH=%s\n' "$(strict_report_path "${data_dir}")"
    fi
    return
  fi

  run_cmd mkdir -p "${data_dir}/runtime"
  cat > "${report_file}" <<EOF
{
  "generated_at_utc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "action": "$(json_escape "${action}")",
  "status": "$(json_escape "${status}")",
  "container_name": "$(json_escape "${container_name}")",
  "data_dir": "$(json_escape "${data_dir}")",
  "image": "$(json_escape "${image}")",
  "host_port": "$(json_escape "${host_port}")",
  "container_port": "$(json_escape "${container_port}")",
  "token": "$(json_escape "${token}")",
  "url": "$(json_escape "${url}")",
  "notes": "$(json_escape "${notes}")"
}
EOF

  if strict_noninteractive_mode_enabled; then
    write_strict_noninteractive_report "${action}" "${status}" "${container_name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${token}" "${url}" "${notes}"
  fi
}

write_strict_noninteractive_report() {
  local action="$1"
  local status="$2"
  local container_name="$3"
  local data_dir="$4"
  local requested_image="$5"
  local host_port="$6"
  local container_port="$7"
  local token="$8"
  local url="$9"
  local notes="${10:-}"

  local report_file
  report_file=$(strict_report_path "${data_dir}")

  local actual_image=""
  local actual_version=""
  local container_status="not_found"
  if [[ -n "${container_name}" ]] && container_exists "${container_name}"; then
    container_status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    actual_image=$(docker inspect -f '{{.Config.Image}}' "${container_name}" 2>/dev/null || true)
    actual_version=$(detect_openclaw_version "${container_name}")
  fi

  local token_present="false"
  [[ -n "${token}" ]] && token_present="true"

  cat > "${report_file}" <<EOF
{
  "generated_at_utc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "strict_noninteractive": true,
  "selected_wizard": "$(json_escape "${SELECTED_WIZARD}")",
  "config_file": "$(json_escape "${CONFIG_FILE}")",
  "dry_run": ${DRY_RUN},
  "action": "$(json_escape "${action}")",
  "status": "$(json_escape "${status}")",
  "container_name": "$(json_escape "${container_name}")",
  "data_dir": "$(json_escape "${data_dir}")",
  "requested_image": "$(json_escape "${requested_image}")",
  "actual_image": "$(json_escape "${actual_image}")",
  "actual_version": "$(json_escape "${actual_version}")",
  "container_status": "$(json_escape "${container_status}")",
  "host_port": "$(json_escape "${host_port}")",
  "container_port": "$(json_escape "${container_port}")",
  "token_present": ${token_present},
  "url": "$(json_escape "${url}")",
  "notes": "$(json_escape "${notes}")"
}
EOF
  printf 'STRICT_REPORT_PATH=%s\n' "${report_file}"
}

write_deployment_info() {
  local action="$1"
  local status="$2"
  local container_name="$3"
  local data_dir="$4"
  local image="$5"
  local host_port="$6"
  local container_port="$7"
  local token="$8"
  local extra_ports="$9"
  local info_file
  info_file=$(deployment_info_path)

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "DEPLOYMENT_INFO_PATH=${info_file}"
    return 0
  fi

  local access_host access_url local_url generated_at
  access_host=$(detect_access_host)
  access_url="http://${access_host}:${host_port}"
  local_url="http://localhost:${host_port}"
  if [[ -n "${token}" ]]; then
    access_url="${access_url}/?token=${token}"
    local_url="${local_url}/?token=${token}"
  fi
  generated_at=$(date "+%Y-%m-%d %H:%M:%S %Z")

  local installed_software_set software_summary skill_summary
  installed_software_set=$(load_software_profile "${data_dir}")
  software_summary=$(software_set_summary "${installed_software_set}")
  skill_summary=$(skill_set_summary "$(load_skill_profile "${data_dir}")")

  run_cmd mkdir -p "$(dirname "${info_file}")"
  cat > "${info_file}" <<EOF
OpenClaw 部署信息
生成时间：${generated_at}
═══════════════════════════════════════════════════════════

【基础信息】
  操作：      ${action}
  状态：      ${status}
  容器名：    ${container_name}
  镜像：      ${image}
  数据目录：  ${data_dir}

【访问信息】
  Dashboard： ${access_url}
  本地访问：  ${local_url}
  连接 Token： ${token:-<未显式输出>}

【端口映射】
  主服务：    ${host_port} -> 容器 ${container_port}
  扩展端口：  ${extra_ports:-<无>}

【扩展能力】
  可选软件：  ${software_summary}
  Skills：    ${skill_summary}

【常用命令】
  查看状态：  docker ps --filter name=^${container_name}$
  查看日志：  docker logs -f ${container_name}
  进入容器：  docker exec -it ${container_name} bash
  查看此文件：cat ${info_file}
═══════════════════════════════════════════════════════════
EOF
  echo "DEPLOYMENT_INFO_PATH=${info_file}"
}

show_deployment_info() {
  local info_file
  info_file=$(deployment_info_path)
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "deployment-info path: ${info_file}"
    return 0
  fi
  if [[ ! -f "${info_file}" ]]; then
    log_error "未找到部署信息文件: ${info_file}"
    return 1
  fi
  cat "${info_file}"
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

is_safe_path_text() {
  local value="$1"
  [[ -n "${value}" && "${value}" != *$'\n'* && "${value}" != *$'\r'* ]]
}

stdin_is_tty() {
  if [[ "${OPENCLAWCTL_ASSUME_TTY:-0}" == "1" ]]; then
    return 0
  fi
  [[ -t 0 ]]
}

stdout_is_tty() {
  if [[ "${OPENCLAWCTL_ASSUME_TTY:-0}" == "1" ]]; then
    return 0
  fi
  [[ -t 1 ]]
}

is_interactive_session() {
  stdin_is_tty && stdout_is_tty
}

enforce_strict_noninteractive_mode() {
  if ! strict_noninteractive_mode_enabled; then
    return 0
  fi
  OPENCLAWCTL_FORCE_SHELL=1
  if [[ -z "${SELECTED_WIZARD}" || -z "${CONFIG_FILE}" ]]; then
    log_error "STRICT_NONINTERACTIVE 模式要求同时提供 --wizard 与 --config-file"
    exit 1
  fi
}

resolve_tui_binary() {
  if [[ -n "${OPENCLAWCTL_TUI_BIN}" && -x "${OPENCLAWCTL_TUI_BIN}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TUI_BIN}"
    return 0
  fi
  local root_dir
  root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  local candidate
  for candidate in \
    "${root_dir}/.bin/openclawctl" \
    "${root_dir}/bin/openclawctl" \
    "${root_dir}/openclawctl"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  if built_tui_bin=$(build_tui_binary_if_possible "${root_dir}"); then
    printf '%s\n' "${built_tui_bin}"
    return 0
  fi
  return 1
}

build_tui_binary_if_possible() {
  local root_dir="$1"
  local source_file="${root_dir}/cmd/openclawctl/main.go"
  local output_bin="${root_dir}/.bin/openclawctl"
  local go_mod="${root_dir}/go.mod"
  local go_sum="${root_dir}/go.sum"

  [[ -f "${source_file}" && -f "${go_mod}" ]] || return 1
  command -v go >/dev/null 2>&1 || return 1

  if [[ -x "${output_bin}" && "${output_bin}" -nt "${source_file}" && "${output_bin}" -nt "${go_mod}" && ( ! -f "${go_sum}" || "${output_bin}" -nt "${go_sum}" ) ]]; then
    printf '%s\n' "${output_bin}"
    return 0
  fi

  if [[ "${OPENCLAWCTL_DISABLE_TUI_BUILD:-0}" == "1" ]]; then
    return 1
  fi

  mkdir -p "${root_dir}/.bin" "${root_dir}/.gocache" "${root_dir}/.gomodcache"
  if GOCACHE="${root_dir}/.gocache" GOMODCACHE="${root_dir}/.gomodcache" GOTOOLCHAIN=auto go build -o "${output_bin}" "${root_dir}/cmd/openclawctl" >/dev/null 2>&1; then
    printf '%s\n' "${output_bin}"
    return 0
  fi
  return 1
}

maybe_exec_tui() {
  if [[ "${OPENCLAWCTL_FORCE_SHELL:-0}" == "1" || "${OPENCLAWCTL_TUI_ACTIVE:-0}" == "1" ]]; then
    return 1
  fi
  if ! is_interactive_session; then
    return 1
  fi

  local tui_bin
  if ! tui_bin=$(resolve_tui_binary); then
    return 1
  fi

  OPENCLAWCTL_TUI_ACTIVE=1 exec "${tui_bin}" --shell-script "$0" "$@"
}

choice_to_yes_no() {
  local value="$1"
  if [[ "${value}" == "1" ]]; then
    echo "是"
  else
    echo "否"
  fi
}

dep_choice_label() {
  local dep_set="$1"
  local dep="$2"
  if dep_enabled "${dep_set}" "${dep}"; then
    echo "已选"
  else
    echo "未选"
  fi
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

  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw setup
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.mode local
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.port "${container_port}"
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.bind "${gateway_bind}"
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.mode token
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.token "${token}"
}

run_openclaw_doctor_fix() {
  local image="$1"
  local data_dir="$2"
  run_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw doctor --fix
}

run_openclaw_config_set_compat() {
  local image="$1"
  local data_dir="$2"
  local key="$3"
  local value="$4"

  print_cmd docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set "${key}" "${value}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi

  local output rc
  set +e
  output=$(docker run --rm --user root -v "${data_dir}:/root/.openclaw" "${image}" openclaw config set "${key}" "${value}" 2>&1)
  rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    [[ -n "${output}" ]] && printf '%s\n' "${output}"
    return 0
  fi

  if [[ "${output}" == *"Unrecognized key"* || "${output}" == *"unknown key"* || "${output}" == *"Unknown key"* ]]; then
    log_info "当前镜像版本不支持配置键 ${key}，已自动跳过"
    return 0
  fi

  [[ -n "${output}" ]] && printf '%s\n' "${output}" >&2
  return "${rc}"
}

ensure_gateway_controlui_compat() {
  local image="$1"
  local data_dir="$2"
  local gateway_bind="$3"

  if [[ "${gateway_bind}" == "local" ]]; then
    return 0
  fi

  if [[ -n "${OPENCLAWCTL_ALLOWED_ORIGINS:-}" ]]; then
    run_openclaw_config_set_compat "${image}" "${data_dir}" "gateway.controlUi.allowedOrigins" "${OPENCLAWCTL_ALLOWED_ORIGINS}"
  else
    run_openclaw_config_set_compat "${image}" "${data_dir}" "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback" "true"
  fi

  if [[ -n "${OPENCLAWCTL_TRUSTED_PROXIES:-}" ]]; then
    run_openclaw_config_set_compat "${image}" "${data_dir}" "gateway.trustedProxies" "${OPENCLAWCTL_TRUSTED_PROXIES}"
  fi
}

run_gateway_container() {
  local name="$1"
  local image="$2"
  local host_port="$3"
  local container_port="$4"
  local data_dir="$5"
  local enable_bin_persist="${6:-${DEFAULT_ENABLE_BIN_PERSIST}}"
  local enable_env_persist="${7:-${DEFAULT_ENABLE_ENV_PERSIST}}"
  local extra_ports="${8:-}"
  local enable_apt_cfg_persist="${9:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local enable_cache_persist="${10:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local volume_args=()
  local port_args=("-p" "${host_port}:${container_port}")
  local persist_node_modules_mount="1"

  if [[ "${enable_bin_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/root-local-bin" "${data_dir}/runtime/root-go-bin" "${data_dir}/runtime/root-cargo-bin"
    volume_args+=("-v" "${data_dir}/runtime/root-local-bin:/root/.local/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-go-bin:/root/go/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-cargo-bin:/root/.cargo/bin")
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    if should_persist_node_modules_mount "${image}"; then
      persist_node_modules_mount="1"
    else
      persist_node_modules_mount="0"
      log_info "[persist] 检测到 zh 镜像，已跳过 /usr/local/lib/node_modules 持久化挂载（避免覆盖镜像内 openclaw 入口）"
    fi

    run_cmd mkdir -p "${data_dir}/runtime/usr-local-go" \
      "${data_dir}/runtime/root-local-lib" \
      "${data_dir}/runtime/root-local-share-uv" \
      "${data_dir}/runtime/root-local-pipx" \
      "${data_dir}/runtime/root-local-share-pipx" \
      "${data_dir}/runtime/root-rustup" \
      "${data_dir}/runtime/root-config" \
      "${data_dir}/runtime/root-ssh" \
      "${data_dir}/runtime/root-docker" \
      "${data_dir}/runtime/root-aws" \
      "${data_dir}/runtime/root-kube"
    run_cmd touch "${data_dir}/runtime/root-gitconfig" \
      "${data_dir}/runtime/root-netrc" \
      "${data_dir}/runtime/root-npmrc" \
      "${data_dir}/runtime/root-pypirc"
    volume_args+=("-v" "${data_dir}/runtime/usr-local-go:/usr/local/go")
    if [[ "${persist_node_modules_mount}" == "1" ]]; then
      run_cmd mkdir -p "${data_dir}/runtime/usr-local-lib-node-modules"
      volume_args+=("-v" "${data_dir}/runtime/usr-local-lib-node-modules:/usr/local/lib/node_modules")
    fi
    volume_args+=("-v" "${data_dir}/runtime/root-local-lib:/root/.local/lib")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-uv:/root/.local/share/uv")
    volume_args+=("-v" "${data_dir}/runtime/root-local-pipx:/root/.local/pipx")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-pipx:/root/.local/share/pipx")
    volume_args+=("-v" "${data_dir}/runtime/root-rustup:/root/.rustup")
    volume_args+=("-v" "${data_dir}/runtime/root-config:/root/.config")
    volume_args+=("-v" "${data_dir}/runtime/root-ssh:/root/.ssh")
    volume_args+=("-v" "${data_dir}/runtime/root-gitconfig:/root/.gitconfig")
    volume_args+=("-v" "${data_dir}/runtime/root-docker:/root/.docker")
    volume_args+=("-v" "${data_dir}/runtime/root-aws:/root/.aws")
    volume_args+=("-v" "${data_dir}/runtime/root-kube:/root/.kube")
    volume_args+=("-v" "${data_dir}/runtime/root-netrc:/root/.netrc")
    volume_args+=("-v" "${data_dir}/runtime/root-npmrc:/root/.npmrc")
    volume_args+=("-v" "${data_dir}/runtime/root-pypirc:/root/.pypirc")
  fi

  if [[ "${enable_apt_cfg_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/etc-apt-sources-list-d" "${data_dir}/runtime/etc-apt-keyrings"
    volume_args+=("-v" "${data_dir}/runtime/etc-apt-sources-list-d:/etc/apt/sources.list.d")
    volume_args+=("-v" "${data_dir}/runtime/etc-apt-keyrings:/etc/apt/keyrings")
  fi

  if [[ "${enable_cache_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/root-npm-cache" "${data_dir}/runtime/root-go-pkg-mod" "${data_dir}/runtime/root-cargo-registry" "${data_dir}/runtime/root-cargo-git"
    volume_args+=("-v" "${data_dir}/runtime/root-npm-cache:/root/.npm")
    volume_args+=("-v" "${data_dir}/runtime/root-go-pkg-mod:/root/go/pkg/mod")
    volume_args+=("-v" "${data_dir}/runtime/root-cargo-registry:/root/.cargo/registry")
    volume_args+=("-v" "${data_dir}/runtime/root-cargo-git:/root/.cargo/git")
  fi

  if [[ -n "${extra_ports}" ]]; then
    local mapping
    for mapping in ${extra_ports}; do
      [[ -z "${mapping}" ]] && continue
      port_args+=("-p" "${mapping}")
    done
  fi

  run_cmd docker run -d \
    --name "${name}" \
    --user root \
    --restart "${DEFAULT_RESTART_POLICY}" \
    "${port_args[@]}" \
    -v "${data_dir}:/root/.openclaw" \
    "${volume_args[@]}" \
    --add-host=host.docker.internal:host-gateway \
    "${image}" \
    openclaw gateway run
}

easyclaw_target_dir() {
  local data_dir="$1"
  echo "${data_dir}/software/easyclaw"
}

easyclaw_container_install_dir() {
  echo "/root/.openclaw/software/easyclaw"
}

run_easyclaw_install_script() {
  local container_name="$1"
  local script='set -e
need_python=0
if ! command -v python3 >/dev/null 2>&1; then
  need_python=1
fi
need_pip=0
if command -v pip3 >/dev/null 2>&1; then
  need_pip=0
elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
  need_pip=0
else
  need_pip=1
fi
python_can_create_venv() {
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  local tmpd
  tmpd=$(mktemp -d /tmp/openclaw-easyclaw-venv-check.XXXXXX 2>/dev/null || true)
  if [ -z "$tmpd" ]; then
    python3 -m venv -h >/dev/null 2>&1
    return $?
  fi
  local rc=0
  python3 -m venv "$tmpd/probe" >/dev/null 2>&1 || rc=$?
  rm -rf "$tmpd" >/dev/null 2>&1 || true
  [ "$rc" -eq 0 ]
}
need_venv=0
if command -v python3 >/dev/null 2>&1; then
  python_can_create_venv || need_venv=1
else
  need_venv=1
fi
pm=""
if command -v apt-get >/dev/null 2>&1; then
  pm="apt"
elif command -v apk >/dev/null 2>&1; then
  pm="apk"
elif command -v dnf >/dev/null 2>&1; then
  pm="dnf"
elif command -v yum >/dev/null 2>&1; then
  pm="yum"
fi
if [ "$need_python" -eq 1 ] || [ "$need_pip" -eq 1 ] || [ "$need_venv" -eq 1 ]; then
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y python3 python3-pip
      if [ "$need_venv" -eq 1 ]; then
        apt-get install -y python3-venv || true
        if command -v python3 >/dev/null 2>&1 && ! python3 -m venv -h >/dev/null 2>&1; then
          py_minor="$(python3 -c '\''import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")'\'' 2>/dev/null || true)"
          if [ -n "$py_minor" ]; then
            apt-get install -y "python${py_minor}-venv" || true
          fi
        fi
      fi
      if [ "$need_pip" -eq 1 ] && command -v python3 >/dev/null 2>&1 && ! python3 -m pip --version >/dev/null 2>&1; then
        python3 -m ensurepip --upgrade || true
      fi
      ;;
    apk)
      apk add --no-cache python3 py3-pip py3-virtualenv
      ;;
    dnf)
      dnf install -y python3 python3-pip python3-virtualenv || dnf install -y python3 python3-pip
      ;;
    yum)
      yum install -y python3 python3-pip python3-virtualenv || yum install -y python3 python3-pip
      ;;
    *)
      echo "[easyclaw] no supported package manager found for python3/python3-pip/python3-venv"
      exit 1
      ;;
  esac
fi
if [ "$need_venv" -eq 1 ] && ! python_can_create_venv; then
  echo "[easyclaw] python venv is still unavailable after dependency install"
  exit 1
fi

easyclaw_venv_dir="/root/.openclaw/software/easyclaw/.venv"
if [ -d "$easyclaw_venv_dir" ]; then
  if [ ! -x "$easyclaw_venv_dir/bin/python3" ] || [ ! -x "$easyclaw_venv_dir/bin/pip" ]; then
    rm -rf "$easyclaw_venv_dir"
  fi
fi
if [ ! -d "$easyclaw_venv_dir" ]; then
  python3 -m venv "$easyclaw_venv_dir" >/dev/null 2>&1 || true
fi
if [ ! -x "$easyclaw_venv_dir/bin/pip" ] && [ -x "$easyclaw_venv_dir/bin/python3" ]; then
  "$easyclaw_venv_dir/bin/python3" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
if [ ! -x "$easyclaw_venv_dir/bin/pip" ]; then
  rm -rf "$easyclaw_venv_dir"
  python3 -m venv "$easyclaw_venv_dir" >/dev/null 2>&1 || true
fi
if [ ! -x "$easyclaw_venv_dir/bin/pip" ]; then
  echo "[easyclaw] python virtualenv is broken: missing pip in ${easyclaw_venv_dir}"
  exit 1
fi

cd /root/.openclaw/software/easyclaw
EASYCLAW_INSTALL_DIR=/root/.openclaw/software/easyclaw \
EASYCLAW_BIN_DIR=/usr/local/bin \
OPENCLAW_HOME=/root/.openclaw \
EASYCLAW_WEB_PORT='"${EASYCLAW_DEFAULT_WEB_PORT}"' \
bash install.sh'
  run_cmd_brief "docker exec ${container_name} bash -lc <easyclaw-install-script>" \
    docker exec "${container_name}" bash -lc "${script}"
}

install_easyclaw() {
  local container_name="$1"
  local data_dir="$2"
  local target_dir
  target_dir=$(easyclaw_target_dir "${data_dir}")

  run_cmd mkdir -p "$(dirname "${target_dir}")"

  if [[ "${OPENCLAWCTL_TEST_FORCE_EASYCLI_FAIL:-0}" == "1" ]]; then
    return 1
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -d "${target_dir}/.git" ]]; then
      run_cmd git -C "${target_dir}" pull --ff-only
    else
      run_cmd git clone "${EASYCLAW_REPO}" "${target_dir}"
    fi
    run_easyclaw_install_script "${container_name}"
    return
  fi

  if [[ -d "${target_dir}/.git" ]]; then
    run_cmd git -C "${target_dir}" pull --ff-only
  else
    run_cmd git clone "${EASYCLAW_REPO}" "${target_dir}"
  fi
  run_easyclaw_install_script "${container_name}"
}

check_and_upgrade_easyclaw() {
  local container_name="$1"
  local data_dir="$2"
  local target_dir
  target_dir=$(easyclaw_target_dir "${data_dir}")

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ ! -d "${target_dir}/.git" ]]; then
      run_cmd git clone "${EASYCLAW_REPO}" "${target_dir}"
    fi
    run_cmd git -C "${target_dir}" fetch --all --prune
    run_cmd git -C "${target_dir}" rev-list --left-right --count HEAD...@{upstream}
    run_cmd git -C "${target_dir}" pull --ff-only
    run_easyclaw_install_script "${container_name}"
    return
  fi

  if [[ ! -d "${target_dir}/.git" ]]; then
    log_info "未发现 EasyClaw 仓库，开始自动安装: ${target_dir}"
    install_easyclaw "${container_name}" "${data_dir}"
    return
  fi

  run_cmd git -C "${target_dir}" fetch --all --prune

  local upstream
  upstream=$(git -C "${target_dir}" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
  if [[ -z "${upstream}" ]]; then
    log_info "EasyClaw 未配置上游分支，跳过版本检查"
    run_easyclaw_install_script "${container_name}"
    return
  fi

  local counts ahead behind
  counts=$(git -C "${target_dir}" rev-list --left-right --count HEAD...@{upstream})
  read -r ahead behind <<<"${counts}"

  if [[ -n "${behind}" && "${behind}" -gt 0 ]]; then
    log_info "检测到 EasyClaw 可升级（落后 ${behind} 个提交），开始升级"
    run_cmd git -C "${target_dir}" pull --ff-only
  else
    log_info "EasyClaw 已是最新"
  fi
  run_easyclaw_install_script "${container_name}"
}

run_optional_software_script() {
  local container_name="$1"
  local label="$2"
  local script="$3"
  run_cmd_brief "docker exec ${container_name} bash -lc <${label}>" \
    docker exec "${container_name}" bash -lc "${script}"
}

install_software_gh() {
  local container_name="$1"
  local script='set -e
target_bin=/root/.openclaw/software/bin
mkdir -p "$target_bin"
arch_raw=$(uname -m 2>/dev/null || echo unknown)
arch="amd64"
case "$arch_raw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
esac
ver=""
if command -v curl >/dev/null 2>&1; then
  ver=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest 2>/dev/null | grep -m1 "\"tag_name\":" | sed -E "s/.*\"v?([^\"]+)\".*/\\1/" || true)
fi
[ -n "$ver" ] || ver="2.67.0"
url="https://github.com/cli/cli/releases/download/v${ver}/gh_${ver}_linux_${arch}.tar.gz"
tmpd=$(mktemp -d)
cleanup() { rm -rf "$tmpd"; }
trap cleanup EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmpd/gh.tgz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmpd/gh.tgz" "$url"
else
  echo "[software] gh install requires curl or wget"
  exit 1
fi
tar -xzf "$tmpd/gh.tgz" -C "$tmpd"
bin_path=$(find "$tmpd" -type f -path "*/bin/gh" | head -n1)
[ -n "$bin_path" ] || { echo "[software] gh binary not found in archive"; exit 1; }
install -m 0755 "$bin_path" "${target_bin}/gh"
ln -sf "${target_bin}/gh" /usr/local/bin/gh || true'
  run_optional_software_script "${container_name}" "software-gh-install-script" "${script}"
}

install_software_npm_package() {
  local container_name="$1"
  local package_name="$2"
  local binary_name="$3"
  local script='set -e
if ! command -v npm >/dev/null 2>&1; then
  echo "[software] npm not found"
  exit 1
fi
mkdir -p /root/.openclaw/software/bin /root/.openclaw/software/lib
npm install -g --prefix /root/.openclaw/software '"${package_name}"'
[ -x /root/.openclaw/software/bin/'"${binary_name}"' ] && ln -sf /root/.openclaw/software/bin/'"${binary_name}"' /usr/local/bin/'"${binary_name}"' || true'
  run_optional_software_script "${container_name}" "software-npm-${binary_name}-install-script" "${script}"
}

install_software_notebooklm() {
  local container_name="$1"
  local script='set -e
if ! command -v python3 >/dev/null 2>&1; then
  echo "[software] python3 not found for notebooklm"
  exit 1
fi
mkdir -p /root/.openclaw/software/python /root/.openclaw/software/bin
python3 -m pip install --no-cache-dir --target /root/.openclaw/software/python "notebooklm-py[browser]"
cat > /root/.openclaw/software/bin/notebooklm << "EOF"
#!/usr/bin/env bash
PYTHONPATH=/root/.openclaw/software/python python3 -m notebooklm "$@"
EOF
chmod +x /root/.openclaw/software/bin/notebooklm
ln -sf /root/.openclaw/software/bin/notebooklm /usr/local/bin/notebooklm || true
python3 -m playwright install chromium >/dev/null 2>&1 || true'
  run_optional_software_script "${container_name}" "software-notebooklm-install-script" "${script}"
}

install_software_guidance_wrapper() {
  local container_name="$1"
  local command_name="$2"
  local guidance="$3"
  local script='set -e
mkdir -p /root/.openclaw/software/bin
cat > /root/.openclaw/software/bin/'"${command_name}"' << "EOF"
#!/usr/bin/env bash
echo "'"$(printf '%s' "${guidance}" | sed 's/"/\\"/g')"'"
exit 1
EOF
chmod +x /root/.openclaw/software/bin/'"${command_name}"'
ln -sf /root/.openclaw/software/bin/'"${command_name}"' /usr/local/bin/'"${command_name}"' || true'
  run_optional_software_script "${container_name}" "software-guidance-${command_name}-install-script" "${script}"
}

install_software_claudecodeui() {
  local container_name="$1"
  local container_ui_port="${2:-${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}}"
  local script='set -e
if ! command -v npm >/dev/null 2>&1; then
  echo "[software] npm not found"
  exit 1
fi
mkdir -p /root/.openclaw/software/bin /root/.openclaw/software/claudecodeui
npm install -g --prefix /root/.openclaw/software '"${CLAUDECODEUI_NPM_PACKAGE}"' '"${TASKMASTER_NPM_PACKAGE}"'
for bin_name in cloudcli claude-code-ui task-master task-master-ai; do
  if [ -x "/root/.openclaw/software/bin/${bin_name}" ]; then
    ln -sf "/root/.openclaw/software/bin/${bin_name}" "/usr/local/bin/${bin_name}" || true
  fi
done
cat > /root/.openclaw/software/bin/claudecodeui-start << "EOF"
#!/usr/bin/env bash
exec cloudcli --port '"${container_ui_port}"' "$@"
EOF
chmod +x /root/.openclaw/software/bin/claudecodeui-start
ln -sf /root/.openclaw/software/bin/claudecodeui-start /usr/local/bin/claudecodeui-start || true
printf "CONTAINER_PORT=%s\n" '"${container_ui_port}"' > /root/.openclaw/software/claudecodeui/runtime.env

claude_cfg="/root/.claude.json"
if [ ! -f "$claude_cfg" ]; then
  printf "{}\n" > "$claude_cfg"
fi
node - "$claude_cfg" << "NODE"
const fs = require("fs");
const cfgPath = process.argv[2];
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) {
    cfg = {};
  }
} catch (_) {
  cfg = {};
}

if (!cfg.mcpServers || typeof cfg.mcpServers !== "object" || Array.isArray(cfg.mcpServers)) {
  cfg.mcpServers = {};
}

const existing = cfg.mcpServers["task-master-ai"];
if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
  cfg.mcpServers["task-master-ai"] = {
    command: "npx",
    args: ["-y", "task-master-ai"]
  };
} else {
  if (!existing.command) {
    existing.command = "npx";
  }
  if (!Array.isArray(existing.args) || existing.args.length === 0) {
    existing.args = ["-y", "task-master-ai"];
  }
  cfg.mcpServers["task-master-ai"] = existing;
}

fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\\n");
NODE'
  run_optional_software_script "${container_name}" "software-claudecodeui-install-script" "${script}"
}

install_selected_software() {
  local container_name="$1"
  local data_dir="$2"
  local selected
  selected=$(normalize_software_set "${3:-}")
  local extra_ports="${6:-}"
  [[ -n "${selected}" ]] || {
    log_info "未选择可选软件，跳过安装"
    return 0
  }

  local failed=0
  local token
  for token in ${selected}; do
    local kind arg1 arg2
    kind=$(catalog_field_for_id "software" "${token}" "kind")
    arg1=$(catalog_field_for_id "software" "${token}" "arg1")
    arg2=$(catalog_field_for_id "software" "${token}" "arg2")

    case "${kind}" in
      gh_binary)
        install_software_gh "${container_name}" || failed=1
        ;;
      npm_package)
        if [[ -z "${arg1}" || -z "${arg2}" ]]; then
          log_error "软件定义缺少 npm 参数: ${token}"
          failed=1
        else
          install_software_npm_package "${container_name}" "${arg1}" "${arg2}" || failed=1
        fi
        ;;
      notebooklm)
        install_software_notebooklm "${container_name}" || failed=1
        ;;
      easyclaw)
        install_easyclaw "${container_name}" "${data_dir}" || failed=1
        ;;
      claudecodeui)
        local claudecodeui_mapping claudecodeui_container_port
        claudecodeui_mapping=$(detect_claudecodeui_reserved_mapping "${extra_ports}" || true)
        claudecodeui_container_port="${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}"
        if [[ -n "${claudecodeui_mapping}" ]]; then
          claudecodeui_container_port="${claudecodeui_mapping#*:}"
        fi
        install_software_claudecodeui "${container_name}" "${claudecodeui_container_port}" || failed=1
        ;;
      guidance)
        if [[ -z "${arg1}" ]]; then
          arg1="该工具依赖桌面环境，当前仅写入说明 wrapper。"
        fi
        install_software_guidance_wrapper "${container_name}" "${token}" "${arg1}" || failed=1
        ;;
      "")
        log_error "未找到软件定义: ${token}"
        failed=1
        ;;
      *)
        log_error "不支持的软件安装类型: ${kind} (${token})"
        failed=1
        ;;
    esac
  done

  [[ "${failed}" -eq 0 ]]
}

skills_workspace_dir() {
  local data_dir="$1"
  echo "${data_dir}/workspace/skills"
}

install_skill_obsidian() {
  local data_dir="$1"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/obsidian-skills"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
  else
    run_cmd git clone --depth=1 "https://github.com/kepano/obsidian-skills.git" "${target}"
  fi
}

install_skill_security_checker() {
  local data_dir="$1"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/security-checker"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
    return
  fi

  run_cmd git clone --depth=1 --filter=blob:none --sparse "https://github.com/moshall/skill_collcet.git" "${target}"
  run_cmd git -C "${target}" sparse-checkout set security-checker
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "shopt -s dotglob nullglob; mv '${target}/security-checker/'* '${target}/' 2>/dev/null || true; rm -rf '${target}/security-checker'"
  else
    if [[ -d "${target}/security-checker" ]]; then
      shopt -s dotglob nullglob
      mv "${target}/security-checker/"* "${target}/" 2>/dev/null || true
      shopt -u dotglob nullglob
      rm -rf "${target}/security-checker"
    fi
  fi
}

install_skill_git_clone() {
  local data_dir="$1"
  local target_id="$2"
  local repo_url="$3"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/${target_id}"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
  else
    run_cmd git clone --depth=1 "${repo_url}" "${target}"
  fi
}

install_skill_sparse_checkout() {
  local data_dir="$1"
  local target_id="$2"
  local repo_url="$3"
  local sparse_dir="$4"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/${target_id}"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
    return
  fi
  run_cmd git clone --depth=1 --filter=blob:none --sparse "${repo_url}" "${target}"
  run_cmd git -C "${target}" sparse-checkout set "${sparse_dir}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "shopt -s dotglob nullglob; mv '${target}/${sparse_dir}/'* '${target}/' 2>/dev/null || true; rm -rf '${target}/${sparse_dir}'"
  else
    if [[ -d "${target}/${sparse_dir}" ]]; then
      shopt -s dotglob nullglob
      mv "${target}/${sparse_dir}/"* "${target}/" 2>/dev/null || true
      shopt -u dotglob nullglob
      rm -rf "${target:?}/${sparse_dir}"
    fi
  fi
}

install_selected_skills() {
  local data_dir="$1"
  local selected
  selected=$(normalize_skill_set "${2:-}")
  [[ -n "${selected}" ]] || {
    log_info "未选择 Skill，跳过安装"
    return 0
  }

  local failed=0
  local token
  for token in ${selected}; do
    local kind arg1 arg2
    kind=$(catalog_field_for_id "skill" "${token}" "kind")
    arg1=$(catalog_field_for_id "skill" "${token}" "arg1")
    arg2=$(catalog_field_for_id "skill" "${token}" "arg2")
    case "${kind}" in
      git_clone)
        if [[ -z "${arg1}" ]]; then
          log_error "Skill 定义缺少仓库地址: ${token}"
          failed=1
        else
          install_skill_git_clone "${data_dir}" "${token}" "${arg1}" || failed=1
        fi
        ;;
      sparse_checkout)
        if [[ -z "${arg1}" || -z "${arg2}" ]]; then
          log_error "Skill 定义缺少 sparse 参数: ${token}"
          failed=1
        else
          install_skill_sparse_checkout "${data_dir}" "${token}" "${arg1}" "${arg2}" || failed=1
        fi
        ;;
      "")
        log_error "未找到 Skill 定义: ${token}"
        failed=1
        ;;
      *)
        log_error "不支持的 Skill 安装类型: ${kind} (${token})"
        failed=1
        ;;
    esac
  done

  [[ "${failed}" -eq 0 ]]
}

normalize_dep_list() {
  local raw="$*"
  raw="${raw//,/ }"
  raw=$(echo "${raw}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  if [[ -z "${raw}" ]]; then
    echo "${DEFAULT_DEP_SET}"
    return
  fi

  local out=""
  local token
  for token in ${raw}; do
    token=$(echo "${token}" | tr '[:upper:]' '[:lower:]')
    [[ -z "${token}" ]] && continue
    case " ${out} " in
      *" ${token} "*) ;;
      *) out="${out}${out:+ }${token}" ;;
    esac
  done
  if [[ -z "${out}" ]]; then
    echo "${DEFAULT_DEP_SET}"
  else
    echo "${out}"
  fi
}

token_in_list() {
  local token="$1"
  shift
  local item
  for item in "$@"; do
    [[ "${item}" == "${token}" ]] && return 0
  done
  return 1
}

normalize_optional_list() {
  local raw="$1"
  shift
  local allowed=("$@")

  raw="${raw//,/ }"
  raw=$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')

  local out=""
  local token
  for token in ${raw}; do
    if ! token_in_list "${token}" "${allowed[@]}"; then
      continue
    fi
    case " ${out} " in
      *" ${token} "*) ;;
      *) out="${out}${out:+ }${token}" ;;
    esac
  done
  echo "${out}"
}

append_catalog_line() {
  local current="$1"
  local line="$2"
  if [[ -z "${current}" ]]; then
    printf '%s\n' "${line}"
  else
    printf '%s\n%s\n' "${current}" "${line}"
  fi
}

catalog_records_for_mode() {
  local mode="$1"
  if [[ "${mode}" == "software" ]]; then
    printf '%s\n' "${OPTIONAL_SOFTWARE_CATALOG}"
  else
    printf '%s\n' "${OPTIONAL_SKILL_CATALOG}"
  fi
}

catalog_record_for_id() {
  local mode="$1"
  local wanted_id="$2"
  local line id label kind arg1 arg2 deps
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    IFS='|' read -r id label kind arg1 arg2 deps <<< "${line}"
    if [[ "${id}" == "${wanted_id}" ]]; then
      printf '%s\n' "${line}"
      return 0
    fi
  done < <(catalog_records_for_mode "${mode}")
  return 1
}

catalog_field_for_id() {
  local mode="$1"
  local id="$2"
  local field="$3"
  local line
  line=$(catalog_record_for_id "${mode}" "${id}" || true)
  [[ -n "${line}" ]] || {
    printf '%s\n' ""
    return 0
  }

  local rid label kind arg1 arg2 deps
  IFS='|' read -r rid label kind arg1 arg2 deps <<< "${line}"
  case "${field}" in
    id) printf '%s\n' "${rid}" ;;
    label) printf '%s\n' "${label}" ;;
    kind) printf '%s\n' "${kind}" ;;
    arg1) printf '%s\n' "${arg1}" ;;
    arg2) printf '%s\n' "${arg2}" ;;
    deps) printf '%s\n' "${deps}" ;;
    *) printf '%s\n' "" ;;
  esac
}

catalog_ids_for_mode() {
  local mode="$1"
  local out=""
  local line id label kind arg1 arg2 deps
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    IFS='|' read -r id label kind arg1 arg2 deps <<< "${line}"
    [[ -z "${id}" ]] && continue
    out="${out}${out:+ }${id}"
  done < <(catalog_records_for_mode "${mode}")
  printf '%s\n' "${out}"
}

load_optional_component_catalog() {
  OPTIONAL_SOFTWARE_CATALOG=""
  OPTIONAL_SKILL_CATALOG=""
  OPTIONAL_SOFTWARE_ALL="${DEFAULT_OPTIONAL_SOFTWARE_ALL}"
  OPTIONAL_SKILL_ALL="${DEFAULT_OPTIONAL_SKILL_ALL}"

  if [[ ! -f "${OPTIONAL_COMPONENTS_FILE}" ]]; then
    log_info "可选组件目录文件不存在，使用内置默认列表: ${OPTIONAL_COMPONENTS_FILE}"
    return 0
  fi

  local line
  while IFS= read -r line; do
    line=$(sanitize_user_input "${line}")
    line=$(trim_surrounding_spaces "${line}")
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^# ]] && continue

    local mode id label kind arg1 arg2 deps
    IFS='|' read -r mode id label kind arg1 arg2 deps <<< "${line}"
    mode=$(trim_surrounding_spaces "${mode}")
    id=$(trim_surrounding_spaces "${id}")
    label=$(trim_surrounding_spaces "${label}")
    kind=$(trim_surrounding_spaces "${kind}")
    arg1=$(trim_surrounding_spaces "${arg1}")
    arg2=$(trim_surrounding_spaces "${arg2}")
    deps=$(trim_surrounding_spaces "${deps}")

    [[ -n "${mode}" && -n "${id}" && -n "${label}" && -n "${kind}" ]] || continue
    local normalized_line="${id}|${label}|${kind}|${arg1}|${arg2}|${deps}"

    case "${mode}" in
      software)
        OPTIONAL_SOFTWARE_CATALOG=$(append_catalog_line "${OPTIONAL_SOFTWARE_CATALOG}" "${normalized_line}")
        ;;
      skill)
        OPTIONAL_SKILL_CATALOG=$(append_catalog_line "${OPTIONAL_SKILL_CATALOG}" "${normalized_line}")
        ;;
    esac
  done < "${OPTIONAL_COMPONENTS_FILE}"

  local loaded_software loaded_skill
  loaded_software=$(catalog_ids_for_mode "software")
  loaded_skill=$(catalog_ids_for_mode "skill")
  [[ -n "${loaded_software}" ]] && OPTIONAL_SOFTWARE_ALL="${loaded_software}"
  [[ -n "${loaded_skill}" ]] && OPTIONAL_SKILL_ALL="${loaded_skill}"
}

normalize_software_set() {
  normalize_optional_list "$*" ${OPTIONAL_SOFTWARE_ALL}
}

normalize_skill_set() {
  normalize_optional_list "$*" ${OPTIONAL_SKILL_ALL}
}

optional_software_label() {
  local token="$1"
  local label
  label=$(catalog_field_for_id "software" "${token}" "label")
  if [[ -n "${label}" ]]; then
    echo "${label}"
  else
    echo "${token}"
  fi
}

optional_skill_label() {
  local token="$1"
  local label
  label=$(catalog_field_for_id "skill" "${token}" "label")
  if [[ -n "${label}" ]]; then
    echo "${label}"
  else
    echo "${token}"
  fi
}

optional_list_summary() {
  local mode="$1"
  shift
  local raw="$*"
  raw=$(echo "${raw}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  [[ -n "${raw}" ]] || {
    echo "无"
    return
  }

  local out=""
  local token label
  for token in ${raw}; do
    if [[ "${mode}" == "software" ]]; then
      label=$(optional_software_label "${token}")
    else
      label=$(optional_skill_label "${token}")
    fi
    out="${out}${out:+、}${label}"
  done
  echo "${out}"
}

software_set_summary() {
  optional_list_summary "software" "$(normalize_software_set "$*")"
}

skill_set_summary() {
  optional_list_summary "skill" "$(normalize_skill_set "$*")"
}

ensure_dep_set_for_software() {
  local dep_set="$1"
  local software_set
  software_set=$(normalize_software_set "${2:-}")
  local result
  result=$(normalize_dep_list "${dep_set}")

  local additional_deps=""
  local token
  for token in ${software_set}; do
    local dep_tokens
    dep_tokens=$(catalog_field_for_id "software" "${token}" "deps")
    dep_tokens="${dep_tokens//,/ }"
    dep_tokens=$(echo "${dep_tokens}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
    [[ -z "${dep_tokens}" || "${dep_tokens}" == "none" ]] && continue
    additional_deps="${additional_deps}${additional_deps:+ }${dep_tokens}"
  done

  additional_deps=$(echo "${additional_deps}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  if [[ -n "${additional_deps}" ]]; then
    local dep_token
    for dep_token in ${additional_deps}; do
      if ! dep_enabled "${result}" "${dep_token}"; then
        result=$(normalize_dep_list "${result} ${dep_token}")
        printf '[INFO] 已自动补充依赖: %s（因所选可选软件需要）\n' "${dep_token}" >&2
      fi
    done
  fi

  echo "${result}"
}

deps_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/deps.profile"
}

software_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/software.profile"
}

skill_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/skills.profile"
}

persistence_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/persistence.profile"
}

apt_manual_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/apt-manual.list"
}

apt_sources_persist_dir() {
  local data_dir="$1"
  echo "${data_dir}/runtime/etc-apt-sources-list-d"
}

apt_keyrings_persist_dir() {
  local data_dir="$1"
  echo "${data_dir}/runtime/etc-apt-keyrings"
}

dir_has_content() {
  local d="$1"
  [[ -d "${d}" ]] || return 1
  find "${d}" -mindepth 1 -print -quit 2>/dev/null | grep -q .
}

validate_apt_sources_persist_files() {
  local data_dir="$1"
  local sources_dir
  sources_dir=$(apt_sources_persist_dir "${data_dir}")
  run_cmd mkdir -p "${sources_dir}"

  log_info "[apt] APT 源文件格式校验: ${sources_dir}"
  [[ -d "${sources_dir}" ]] || {
    log_info "[apt] APT 源文件格式校验通过（目录不存在）"
    return 0
  }

  local invalid_count=0
  local src_file invalid_line quarantined_file
  while IFS= read -r -d '' src_file; do
    invalid_line=$(grep -nEv "^[[:space:]]*($|#|deb(-src)?([[:space:]]+\\[[^]]+\\])?[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+.*)$" "${src_file}" | head -n1 || true)
    [[ -n "${invalid_line}" ]] || continue

    invalid_count=$((invalid_count + 1))
    quarantined_file="${src_file}.disabled-invalid"
    run_cmd mv "${src_file}" "${quarantined_file}"
    if [[ "${DRY_RUN}" -eq 0 ]]; then
      printf 'quarantined_by=openclawctl\ninvalid_line=%s\n' "${invalid_line}" > "${quarantined_file}.reason"
    fi
    log_error "[apt] 检测到异常源文件并已隔离: ${src_file} (${invalid_line})"
  done < <(find "${sources_dir}" -maxdepth 1 -type f -name '*.list' -print0 2>/dev/null)

  if [[ "${invalid_count}" -eq 0 ]]; then
    log_info "[apt] APT 源文件格式校验通过"
  else
    log_info "[apt] APT 源文件格式校验完成，已隔离异常文件数量: ${invalid_count}"
  fi
  return 0
}

ensure_apt_config_seeded_from_image() {
  local image="$1"
  local data_dir="$2"
  local sources_dir keyrings_dir
  sources_dir=$(apt_sources_persist_dir "${data_dir}")
  keyrings_dir=$(apt_keyrings_persist_dir "${data_dir}")

  run_cmd mkdir -p "${sources_dir}" "${keyrings_dir}"

  if dir_has_content "${sources_dir}" || dir_has_content "${keyrings_dir}"; then
    return 0
  fi

  log_info "[apt] 检测到 APT 源持久化目录为空，开始从目标镜像初始化默认 sources/keyrings"
  local tmp_container
  tmp_container="openclawctl-aptseed-$$"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd docker create --name "${tmp_container}" --entrypoint sh "${image}" -lc 'sleep 1'
    run_cmd docker cp "${tmp_container}:/etc/apt/sources.list.d/." "${sources_dir}/"
    run_cmd docker cp "${tmp_container}:/etc/apt/keyrings/." "${keyrings_dir}/"
    run_cmd docker rm -f "${tmp_container}"
    return 0
  fi

  run_cmd docker create --name "${tmp_container}" --entrypoint sh "${image}" -lc 'sleep 1'
  set +e
  docker cp "${tmp_container}:/etc/apt/sources.list.d/." "${sources_dir}/" >/dev/null 2>&1
  local rc_sources=$?
  docker cp "${tmp_container}:/etc/apt/keyrings/." "${keyrings_dir}/" >/dev/null 2>&1
  local rc_keys=$?
  docker rm -f "${tmp_container}" >/dev/null 2>&1 || true
  set -e
  if [[ "${rc_sources}" -ne 0 ]]; then
    log_error "[apt] 初始化 sources.list.d 失败"
    return 1
  fi
  if [[ "${rc_keys}" -ne 0 ]]; then
    log_info "[apt] 目标镜像未提供 /etc/apt/keyrings 或复制失败，已继续"
  fi
  log_info "[apt] 已完成 APT 源目录初始化"
}

load_dep_profile() {
  local data_dir="$1"
  local profile
  profile=$(deps_profile_path "${data_dir}")
  if [[ -f "${profile}" ]]; then
    normalize_dep_list "$(tr '\n' ' ' < "${profile}")"
  else
    echo "${DEFAULT_DEP_SET}"
  fi
}

save_dep_profile() {
  local data_dir="$1"
  shift
  local deps
  deps=$(normalize_dep_list "$*")
  local profile
  profile=$(deps_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "依赖档案将保存到: ${profile}"
    log_info "依赖档案内容: ${deps}"
    return
  fi
  printf '%s\n' ${deps} > "${profile}"
}

load_software_profile() {
  local data_dir="$1"
  local profile
  profile=$(software_profile_path "${data_dir}")
  if [[ -f "${profile}" ]]; then
    normalize_software_set "$(tr '\n' ' ' < "${profile}")"
  else
    echo ""
  fi
}

save_software_profile() {
  local data_dir="$1"
  shift
  local software
  software=$(normalize_software_set "$*")
  local profile
  profile=$(software_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "软件档案将保存到: ${profile}"
    log_info "软件档案内容: ${software:-<empty>}"
    return
  fi
  printf '%s\n' ${software} > "${profile}"
}

load_skill_profile() {
  local data_dir="$1"
  local profile
  profile=$(skill_profile_path "${data_dir}")
  if [[ -f "${profile}" ]]; then
    normalize_skill_set "$(tr '\n' ' ' < "${profile}")"
  else
    echo ""
  fi
}

save_skill_profile() {
  local data_dir="$1"
  shift
  local skills
  skills=$(normalize_skill_set "$*")
  local profile
  profile=$(skill_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "Skill 档案将保存到: ${profile}"
    log_info "Skill 档案内容: ${skills:-<empty>}"
    return
  fi
  printf '%s\n' ${skills} > "${profile}"
}

load_persistence_choice() {
  local data_dir="$1"
  local key="$2"
  local default_value="$3"
  local profile
  profile=$(persistence_profile_path "${data_dir}")
  if [[ ! -f "${profile}" ]]; then
    echo "${default_value}"
    return
  fi

  local value
  value=$(awk -F '=' -v k="${key}" '$1==k {print $2}' "${profile}" | tail -n1 | tr -d '[:space:]')
  if [[ "${value}" == "1" || "${value}" == "2" ]]; then
    echo "${value}"
  else
    echo "${default_value}"
  fi
}

save_persistence_profile() {
  local data_dir="$1"
  local bin_choice="$2"
  local env_choice="$3"
  local apt_cfg_choice="${4:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local cache_choice="${5:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local profile
  profile=$(persistence_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "持久化档案将保存到: ${profile}"
    log_info "持久化档案内容: bin=${bin_choice}, env=${env_choice}, aptcfg=${apt_cfg_choice}, cache=${cache_choice}"
    return
  fi
  cat > "${profile}" <<EOF
BIN_PERSIST=${bin_choice}
ENV_PERSIST=${env_choice}
APT_CFG_PERSIST=${apt_cfg_choice}
CACHE_PERSIST=${cache_choice}
EOF
}

snapshot_apt_manual_packages() {
  local container_name="$1"
  local data_dir="$2"
  local profile
  profile=$(apt_manual_profile_path "${data_dir}")
  local snapshot_script='if command -v apt-mark >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then apt-mark showmanual | sort -u; fi'

  run_cmd mkdir -p "${data_dir}/runtime"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd_brief "docker exec ${container_name} sh -lc <apt-manual-snapshot-script>" \
      docker exec "${container_name}" sh -lc "${snapshot_script}"
    return 0
  fi

  if ! container_exists "${container_name}"; then
    log_info "[apt] 容器不存在，跳过 APT 手工包清单快照"
    return 0
  fi

  local packages
  packages=$(docker exec "${container_name}" sh -lc "${snapshot_script}" 2>/dev/null || true)
  if [[ -z "${packages}" ]]; then
    : > "${profile}"
    log_info "[apt] 未检测到 apt 手工包清单或容器非 apt 系，已写入空档案"
    return 0
  fi
  printf '%s\n' "${packages}" | sed '/^[[:space:]]*$/d' > "${profile}"
  log_info "[apt] 已保存 APT 手工包清单: ${profile}"
}

restore_apt_manual_packages() {
  local container_name="$1"
  local data_dir="$2"
  local profile
  profile=$(apt_manual_profile_path "${data_dir}")
  local restore_script='
if ! command -v apt-get >/dev/null 2>&1; then
  echo "[apt] skip restore: apt-get not found"
  exit 0
fi
if [ ! -s /root/.openclaw/runtime/apt-manual.list ]; then
  echo "[apt] skip restore: apt-manual.list empty"
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
report=/root/.openclaw/runtime/apt-restore.report
{
  echo "time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "phase=precheck"
} > "$report"
invalid_sources=0
for src_file in /etc/apt/sources.list.d/*.list; do
  [ -e "$src_file" ] || continue
  invalid_line=$(grep -nEv "^[[:space:]]*($|#|deb(-src)?([[:space:]]+\\[[^]]+\\])?[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+.*)$" "$src_file" | head -n1 || true)
  [ -n "$invalid_line" ] || continue
  mv "$src_file" "${src_file}.disabled-invalid" || true
  invalid_sources=$((invalid_sources + 1))
  echo "[apt] quarantined invalid source: $src_file ($invalid_line)"
done
if [ "$invalid_sources" -gt 0 ]; then
  echo "quarantined_sources=$invalid_sources" >> "$report"
fi
if ! apt-get update; then
  echo "phase=failed"
  echo "reason=apt-update-failed"
  echo "[apt] source check failed, please verify sources/keyrings/network"
  exit 21
fi
total=$(sed "/^[[:space:]]*$/d" /root/.openclaw/runtime/apt-manual.list | wc -l | tr -d " ")
missing=""
while IFS= read -r pkg; do
  [ -n "$pkg" ] || continue
  dpkg -s "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done < /root/.openclaw/runtime/apt-manual.list
missing=$(echo "$missing" | xargs -n1 2>/dev/null | sort -u | xargs 2>/dev/null || true)
missing_count=0
[ -n "$missing" ] && missing_count=$(echo "$missing" | xargs -n1 2>/dev/null | wc -l | tr -d " ")
{
  echo "phase=resolved"
  echo "total=$total"
  echo "missing=$missing_count"
} >> "$report"
if [ "$missing_count" -eq 0 ]; then
  echo "[apt] all manual packages already satisfied"
  echo "status=ok" >> "$report"
  exit 0
fi
if apt-get install -y --no-install-recommends $missing; then
  echo "status=ok" >> "$report"
  echo "[apt] restore done: installed_missing=$missing_count total=$total"
else
  echo "status=failed" >> "$report"
  echo "[apt] restore failed while installing missing packages"
  exit 22
fi'

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd_brief "docker exec ${container_name} sh -lc <apt-manual-restore-script>" \
      docker exec "${container_name}" sh -lc "${restore_script}"
    return 0
  fi

  if [[ ! -s "${profile}" ]]; then
    log_info "[apt] APT 手工包档案为空，跳过回放安装"
    return 0
  fi

  if ! container_exists "${container_name}"; then
    log_info "[apt] 容器不存在，跳过 APT 手工包回放安装"
    return 0
  fi

  run_cmd_brief "docker exec ${container_name} sh -lc <apt-manual-restore-script>" \
    docker exec "${container_name}" sh -lc "${restore_script}"
}

repair_runtime_command_paths() {
  local container_name="$1"
  local script='
set -e
ensure_path_now() {
  for d in "$@"; do
    [ -d "$d" ] || continue
    case ":$PATH:" in
      *":$d:"*) ;;
      *) PATH="$d:$PATH" ;;
    esac
  done
}
persist_path_dir() {
  local d="$1"
  [ -d "$d" ] || return 0
  local profile="/etc/profile.d/openclaw-runtime-path.sh"
  mkdir -p /etc/profile.d || true
  touch "$profile" || return 0
  grep -F "export PATH=\"$d:\$PATH\"" "$profile" >/dev/null 2>&1 || \
    echo "export PATH=\"$d:\$PATH\"" >> "$profile"
}
sync_user_bin_dir() {
  local src="$1"
  [ -d "$src" ] || return 0
  [ -d /usr/local/bin ] || return 0
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    ln -sf "$f" "/usr/local/bin/$(basename "$f")" || true
  done
}
ensure_path_now /root/.local/bin /usr/local/go/bin /root/go/bin /root/.cargo/bin /usr/local/bin
persist_path_dir /root/.local/bin
persist_path_dir /usr/local/go/bin
persist_path_dir /root/go/bin
persist_path_dir /root/.cargo/bin
[ -x /usr/local/go/bin/go ] && ln -sf /usr/local/go/bin/go /usr/local/bin/go || true
[ -x /root/.local/bin/uv ] && ln -sf /root/.local/bin/uv /usr/local/bin/uv || true
[ -x /root/.cargo/bin/cargo ] && ln -sf /root/.cargo/bin/cargo /usr/local/bin/cargo || true
[ -x /root/.cargo/bin/rustc ] && ln -sf /root/.cargo/bin/rustc /usr/local/bin/rustc || true
sync_user_bin_dir /root/.local/bin
sync_user_bin_dir /root/go/bin
sync_user_bin_dir /root/.cargo/bin
true'

  run_cmd_brief "docker exec ${container_name} sh -lc <runtime-path-repair-script>" \
    docker exec "${container_name}" sh -lc "${script}"
}

configure_npm_runtime_prefix() {
  local container_name="$1"
  local image="$2"
  local script='
if ! command -v npm >/dev/null 2>&1; then
  echo "[npm] npm not found, skip runtime prefix setup"
  exit 0
fi
mkdir -p /root/.local/bin /root/.local/lib/node_modules
npm config set prefix /root/.local >/dev/null 2>&1 || true
prefix_now=$(npm config get prefix 2>/dev/null || true)
echo "[npm] global prefix=${prefix_now}"
if [ -d /root/.local/bin ] && [ -d /usr/local/bin ]; then
  for f in /root/.local/bin/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    ln -sf "$f" "/usr/local/bin/$(basename "$f")" || true
  done
fi
true'

  if ! is_openclaw_zh_image_ref "${image}"; then
    return 0
  fi

  run_cmd_brief "docker exec ${container_name} sh -lc <npm-runtime-prefix-script>" \
    docker exec "${container_name}" sh -lc "${script}"
}

repair_persisted_auth_permissions() {
  local container_name="$1"
  local script='
[ -d /root/.ssh ] && chmod 700 /root/.ssh || true
[ -d /root/.ssh ] && find /root/.ssh -type f -exec chmod 600 {} + 2>/dev/null || true
[ -f /root/.gitconfig ] && chmod 600 /root/.gitconfig || true
[ -f /root/.netrc ] && chmod 600 /root/.netrc || true
[ -f /root/.npmrc ] && chmod 600 /root/.npmrc || true
[ -f /root/.pypirc ] && chmod 600 /root/.pypirc || true
[ -d /root/.aws ] && chmod 700 /root/.aws || true
[ -d /root/.aws ] && find /root/.aws -type f -exec chmod 600 {} + 2>/dev/null || true
[ -d /root/.kube ] && chmod 700 /root/.kube || true
[ -d /root/.kube ] && find /root/.kube -type f -exec chmod 600 {} + 2>/dev/null || true
[ -d /root/.docker ] && chmod 700 /root/.docker || true
[ -d /root/.docker ] && find /root/.docker -type f -exec chmod 600 {} + 2>/dev/null || true
true'

  run_cmd_brief "docker exec ${container_name} sh -lc <auth-perms-fix-script>" \
    docker exec "${container_name}" sh -lc "${script}"
}

dep_enabled() {
  local dep_set="$1"
  local dep_name="$2"
  [[ " ${dep_set} " == *" ${dep_name} "* ]]
}

build_dep_set_from_choices() {
  local npm_choice="$1"
  local uv_choice="$2"
  local go_choice="$3"
  local rust_choice="$4"
  local extra_deps="$5"
  local deps=""

  if [[ "${npm_choice}" == "1" ]]; then
    deps="${deps} npm"
  fi
  if [[ "${uv_choice}" == "1" ]]; then
    deps="${deps} uv"
  fi
  if [[ "${go_choice}" == "1" ]]; then
    deps="${deps} go"
  fi
  if [[ "${rust_choice}" == "1" ]]; then
    deps="${deps} rust"
  fi
  deps="${deps} ${extra_deps}"
  normalize_dep_list "${deps}"
}

manage_container_runtime_deps() {
  local container_name="$1"
  local mode="$2" # install | check
  local deps_spec_raw="${3:-${DEFAULT_DEP_SET}}"
  if [[ "${OPENCLAWCTL_TEST_FORCE_DEPS_FAIL:-0}" == "1" ]]; then
    log_error "测试注入: 强制依赖补齐失败"
    return 1
  fi
  local deps_spec
  deps_spec=$(normalize_dep_list "${deps_spec_raw}")
  local mode_label
  mode_label=$([[ "${mode}" == "install" ]] && echo "检测并自动安装缺失项" || echo "仅检测，不安装")
  log_info "开始检测容器依赖: ${deps_spec}"
  log_info "依赖检测模式: ${mode_label}"
  if [[ " ${deps_spec} " == *" uv "* ]]; then
    log_info "uv兼容模式: Debian/Ubuntu 遇到 PEP668 时自动回退安装"
  fi

  local inner_script
  inner_script=$(cat <<'EOS'
set -e
MODE="__MODE__"
DEPS_SPEC="__DEPS__"

has() { command -v "$1" >/dev/null 2>&1; }
has_effective() {
  local cmd="$1"
  if has "$cmd"; then
    return 0
  fi
  case "$cmd" in
    go)
      [ -x /usr/local/go/bin/go ] || [ -x /root/go/bin/go ] || [ -x /usr/local/bin/go ]
      ;;
    uv)
      [ -x /root/.local/bin/uv ] || [ -x /usr/local/bin/uv ] || [ -x /usr/bin/uv ]
      ;;
    npm)
      [ -x /usr/bin/npm ] || [ -x /usr/local/bin/npm ]
      ;;
    rust|cargo|rustc)
      [ -x /root/.cargo/bin/cargo ] || [ -x /root/.cargo/bin/rustc ] || [ -x /usr/local/bin/cargo ] || [ -x /usr/local/bin/rustc ]
      ;;
    python3)
      [ -x /usr/bin/python3 ] || [ -x /usr/local/bin/python3 ]
      ;;
    *)
      return 1
      ;;
  esac
}
python_has_pip() {
  if has pip3; then
    return 0
  fi
  if has python3 && python3 -m pip --version >/dev/null 2>&1; then
    return 0
  fi
  return 1
}
python_can_create_venv() {
  if ! has python3; then
    return 1
  fi
  local tmpd
  tmpd=$(mktemp -d /tmp/openclaw-runtime-venv-check.XXXXXX 2>/dev/null || true)
  if [ -z "$tmpd" ]; then
    python3 -m venv -h >/dev/null 2>&1
    return $?
  fi
  local rc=0
  python3 -m venv "$tmpd/probe" >/dev/null 2>&1 || rc=$?
  rm -rf "$tmpd" >/dev/null 2>&1 || true
  [ "$rc" -eq 0 ]
}
python_has_venv() {
  python_can_create_venv
}
dep_status() {
  local cmd="$1"
  if has "$cmd"; then
    echo "FOUND"
    return
  fi
  if has_effective "$cmd"; then
    echo "FOUND_BUT_NOT_IN_PATH"
    return
  fi
  echo "MISSING"
}
normalize_deps() {
  echo "$1" | tr ',' ' ' | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'
}
DEPS="$(normalize_deps "$DEPS_SPEC")"
[ -n "$DEPS" ] || DEPS="npm uv"
contains_dep() {
  local target="$1"
  for d in $DEPS; do
    [ "$d" = "$target" ] && return 0
  done
  return 1
}

ensure_path_now() {
  for d in "$@"; do
    [ -d "$d" ] || continue
    case ":$PATH:" in
      *":$d:"*) ;;
      *) PATH="$d:$PATH" ;;
    esac
  done
}

persist_path_dir() {
  local d="$1"
  [ -d "$d" ] || return 0
  [ "$MODE" = "install" ] || return 0
  local profile="/etc/profile.d/openclaw-runtime-path.sh"
  mkdir -p /etc/profile.d || true
  touch "$profile" || return 0
  grep -F "export PATH=\"$d:\$PATH\"" "$profile" >/dev/null 2>&1 || \
    echo "export PATH=\"$d:\$PATH\"" >> "$profile"
}

sync_user_bin_dir() {
  local src="$1"
  [ -d "$src" ] || return 0
  [ -d /usr/local/bin ] || return 0
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    ln -sf "$f" "/usr/local/bin/$(basename "$f")" || true
  done
}

fix_uv_path() {
  local cand
  if has uv; then
    return 0
  fi
  for cand in /root/.local/bin/uv /usr/local/bin/uv /usr/bin/uv; do
    if [ -x "$cand" ]; then
      ensure_path_now "$(dirname "$cand")"
      persist_path_dir "$(dirname "$cand")"
      if ! has uv && [ "$cand" != "/usr/local/bin/uv" ] && [ -d /usr/local/bin ]; then
        ln -sf "$cand" /usr/local/bin/uv || true
        ensure_path_now /usr/local/bin
      fi
      break
    fi
  done
  sync_user_bin_dir /root/.local/bin
}

fix_go_path() {
  ensure_path_now /usr/local/go/bin /root/go/bin /usr/local/bin
  persist_path_dir /usr/local/go/bin
  persist_path_dir /root/go/bin
  if ! has go && [ -x /usr/local/go/bin/go ] && [ -d /usr/local/bin ]; then
    ln -sf /usr/local/go/bin/go /usr/local/bin/go || true
    ensure_path_now /usr/local/bin
  fi
  sync_user_bin_dir /root/go/bin
}

fix_rust_path() {
  ensure_path_now /root/.cargo/bin /usr/local/bin
  persist_path_dir /root/.cargo/bin
  if ! has cargo && [ -x /root/.cargo/bin/cargo ] && [ -d /usr/local/bin ]; then
    ln -sf /root/.cargo/bin/cargo /usr/local/bin/cargo || true
    ensure_path_now /usr/local/bin
  fi
  if ! has rustc && [ -x /root/.cargo/bin/rustc ] && [ -d /usr/local/bin ]; then
    ln -sf /root/.cargo/bin/rustc /usr/local/bin/rustc || true
    ensure_path_now /usr/local/bin
  fi
  sync_user_bin_dir /root/.cargo/bin
}

# Best-effort PATH repair for "installed but not in PATH" cases (especially go/uv/rust)
ensure_path_now /root/.local/bin /usr/local/bin /usr/local/go/bin /root/go/bin /root/.cargo/bin

is_mountpoint_path() {
  local p="$1"
  [ -n "$p" ] || return 1
  [ -f /proc/mounts ] || return 1
  grep -Eq "[[:space:]]${p}[[:space:]]" /proc/mounts
}

clear_dir_contents() {
  local d="$1"
  [ -d "$d" ] || return 0
  if has find; then
    find "$d" -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
    return 0
  fi
  # fallback when find is unavailable
  for f in "$d"/* "$d"/.[!.]* "$d"/..?*; do
    [ -e "$f" ] || continue
    rm -rf "$f" || true
  done
}

echo "[deps] checking: ${DEPS}"
for cmd in $DEPS; do
  echo "$(dep_status "$cmd"):$cmd"
done

if [ "$MODE" = "check" ]; then
  exit 0
fi

need_node=0
need_python=0
need_python_pip=0
need_python_venv=0
need_uv=0
need_go=0
need_rust=0
contains_dep npm && ! has_effective npm && need_node=1
if ! has_effective python3 && (contains_dep python3 || contains_dep uv); then
  need_python=1
fi
if contains_dep python3 || contains_dep uv; then
  if [ "$need_python" -eq 1 ]; then
    need_python_pip=1
    need_python_venv=1
  else
    python_has_pip || need_python_pip=1
    python_has_venv || need_python_venv=1
  fi
fi
contains_dep uv && ! has_effective uv && need_uv=1
contains_dep go && ! has_effective go && need_go=1
contains_dep rust && ! has_effective rust && need_rust=1

if [ "$need_node" -eq 0 ] && [ "$need_python" -eq 0 ] && [ "$need_python_pip" -eq 0 ] && [ "$need_python_venv" -eq 0 ] && [ "$need_uv" -eq 0 ] && [ "$need_go" -eq 0 ] && [ "$need_rust" -eq 0 ]; then
  echo "[deps] all required runtimes already installed"
fi

pm=""
if command -v apt-get >/dev/null 2>&1; then
  pm="apt"
elif command -v apk >/dev/null 2>&1; then
  pm="apk"
elif command -v dnf >/dev/null 2>&1; then
  pm="dnf"
elif command -v yum >/dev/null 2>&1; then
  pm="yum"
fi

os_id=""
os_like=""
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-}"
  os_like="${ID_LIKE:-}"
fi
is_debian_like=0
case " ${os_id} ${os_like} " in
  *" debian "*|*" ubuntu "*)
    is_debian_like=1
    ;;
esac

install_uv_by_official_script() {
  if has curl; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    return $?
  fi
  if has wget; then
    wget -qO- https://astral.sh/uv/install.sh | sh
    return $?
  fi
  return 1
}

install_base_deps() {
  if [ -z "$pm" ]; then
    echo "[deps] no supported package manager found (apt/apk/dnf/yum)"
    return 1
  fi

  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3"
      [ "$need_python_pip" -eq 1 ] && pkgs="$pkgs python3-pip"
      [ -n "$pkgs" ] && apt-get install -y $pkgs
      if [ "$need_python_venv" -eq 1 ]; then
        apt-get install -y python3-venv || true
        if has python3 && ! python_has_venv; then
          py_minor="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || true)"
          if [ -n "$py_minor" ]; then
            apt-get install -y "python${py_minor}-venv" || true
          fi
        fi
      fi
      ;;
    apk)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3"
      [ "$need_python_pip" -eq 1 ] && pkgs="$pkgs py3-pip"
      [ "$need_python_venv" -eq 1 ] && pkgs="$pkgs py3-virtualenv"
      [ -n "$pkgs" ] && apk add --no-cache $pkgs
      ;;
    dnf)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3"
      [ "$need_python_pip" -eq 1 ] && pkgs="$pkgs python3-pip"
      if [ "$need_python_venv" -eq 1 ]; then
        if [ -n "$pkgs" ]; then
          dnf install -y $pkgs python3-virtualenv || dnf install -y $pkgs
        else
          dnf install -y python3-virtualenv || true
        fi
      elif [ -n "$pkgs" ]; then
        dnf install -y $pkgs
      fi
      ;;
    yum)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3"
      [ "$need_python_pip" -eq 1 ] && pkgs="$pkgs python3-pip"
      if [ "$need_python_venv" -eq 1 ]; then
        if [ -n "$pkgs" ]; then
          yum install -y $pkgs python3-virtualenv || yum install -y $pkgs
        else
          yum install -y python3-virtualenv || true
        fi
      elif [ -n "$pkgs" ]; then
        yum install -y $pkgs
      fi
      ;;
  esac

  if has python3 && [ "$need_python_pip" -eq 1 ] && ! python_has_pip; then
    python3 -m ensurepip --upgrade || true
  fi
  if has python3 && [ "$need_python_venv" -eq 1 ] && ! python_has_venv; then
    python3 -m ensurepip --upgrade || true
  fi
}

if [ "$need_node" -eq 1 ] || [ "$need_python" -eq 1 ] || [ "$need_python_pip" -eq 1 ] || [ "$need_python_venv" -eq 1 ]; then
  install_base_deps
fi

if [ "$need_uv" -eq 1 ]; then
  uv_ok=0
  has uv && uv_ok=1

  if [ "$uv_ok" -eq 0 ] && [ "$is_debian_like" -eq 1 ]; then
    echo "[deps] uv compat(debian/ubuntu): try official installer first"
    if install_uv_by_official_script; then
      fix_uv_path
      has uv && uv_ok=1
    fi
  fi

  if [ "$uv_ok" -eq 0 ] && has pip3; then
    if pip3 install --no-cache-dir -U uv; then
      fix_uv_path
      has uv && uv_ok=1
    elif [ "$is_debian_like" -eq 1 ]; then
      echo "[deps] uv compat: retry pip3 with --break-system-packages"
      if pip3 install --no-cache-dir -U uv --break-system-packages; then
        fix_uv_path
        has uv && uv_ok=1
      fi
    fi
  fi

  if [ "$uv_ok" -eq 0 ] && has python3; then
    python3 -m ensurepip --upgrade || true
    if python3 -m pip install --no-cache-dir -U uv; then
      fix_uv_path
      has uv && uv_ok=1
    elif [ "$is_debian_like" -eq 1 ]; then
      echo "[deps] uv compat: retry python -m pip with --break-system-packages"
      if python3 -m pip install --no-cache-dir -U uv --break-system-packages; then
        fix_uv_path
        has uv && uv_ok=1
      fi
    fi
  fi

  if [ "$uv_ok" -eq 0 ] && [ "$is_debian_like" -eq 0 ]; then
    echo "[deps] uv fallback: try official installer"
    if install_uv_by_official_script; then
      fix_uv_path
      has uv && uv_ok=1
    fi
  fi

  if [ "$uv_ok" -eq 0 ]; then
    echo "[deps] uv installation skipped/failed after compatibility attempts"
  fi
fi

if [ "$need_go" -eq 1 ]; then
  arch_raw="$(uname -m 2>/dev/null || echo unknown)"
  go_arch=""
  case "$arch_raw" in
    x86_64|amd64) go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
  esac
  echo "[deps] detected arch: ${arch_raw}"

  go_ok=0
  if [ -n "$go_arch" ] && (has curl || has wget) && has tar; then
    GO_INSTALL_VERSION="${GO_INSTALL_VERSION:-1.23.8}"
    go_tar="go${GO_INSTALL_VERSION}.linux-${go_arch}.tar.gz"
    go_url="https://go.dev/dl/${go_tar}"
    go_pkg="/tmp/${go_tar}"
    echo "[deps] try installing go from official tarball: ${go_url}"
    if has curl; then
      curl -fsSL -o "$go_pkg" "$go_url" || true
    else
      wget -q -O "$go_pkg" "$go_url" || true
    fi

    if [ -f "$go_pkg" ]; then
      if [ -d /usr/local/go ] && is_mountpoint_path /usr/local/go; then
        echo "[deps] /usr/local/go is a mountpoint, clearing contents only"
        clear_dir_contents /usr/local/go
      else
        rm -rf /usr/local/go || true
      fi
      tar -C /usr/local -xzf "$go_pkg" || true
      rm -f "$go_pkg" || true
      fix_go_path
      has go && go_ok=1
    fi
  fi

  if [ "$go_ok" -eq 0 ] && [ -n "$pm" ]; then
    echo "[deps] fallback to package manager for go"
    case "$pm" in
      apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y golang-go
        ;;
      apk)
        apk add --no-cache go
        ;;
      dnf)
        dnf install -y golang
        ;;
      yum)
        yum install -y golang
        ;;
    esac
    fix_go_path
  fi
fi

install_rust_with_rustup() {
  if has curl; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    return $?
  fi
  if has wget; then
    wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    return $?
  fi
  return 1
}

if [ "$need_rust" -eq 1 ]; then
  rust_ok=0
  if has rustc && has cargo; then
    rust_ok=1
  fi

  if [ "$rust_ok" -eq 0 ]; then
    echo "[deps] try installing rust via rustup"
    if install_rust_with_rustup; then
      fix_rust_path
      has rustc && has cargo && rust_ok=1
    fi
  fi

  if [ "$rust_ok" -eq 0 ] && [ -n "$pm" ]; then
    echo "[deps] fallback to package manager for rust"
    case "$pm" in
      apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y rustc cargo
        ;;
      apk)
        apk add --no-cache rust cargo
        ;;
      dnf)
        dnf install -y rust cargo
        ;;
      yum)
        yum install -y rust cargo
        ;;
    esac
    fix_rust_path
  fi
fi

for dep in $DEPS; do
  case "$dep" in
    npm|python3|uv|go|rust) ;;
    *)
      if [ "$MODE" = "install" ] && ! has "$dep" && [ -n "$pm" ]; then
        echo "[deps] try installing custom command via package manager: $dep"
        case "$pm" in
          apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || true
            apt-get install -y "$dep" || true
            ;;
          apk) apk add --no-cache "$dep" || true ;;
          dnf) dnf install -y "$dep" || true ;;
          yum) yum install -y "$dep" || true ;;
        esac
      fi
      ;;
  esac
done

fix_uv_path
fix_go_path
fix_rust_path
sync_user_bin_dir /root/.local/bin
sync_user_bin_dir /root/go/bin
sync_user_bin_dir /root/.cargo/bin

echo "[deps] final status:"
for cmd in $DEPS; do
  echo "$(dep_status "$cmd"):$cmd"
done
echo "PATH:$PATH"
EOS
)
  inner_script="${inner_script/__MODE__/${mode}}"
  inner_script="${inner_script/__DEPS__/${deps_spec}}"
  run_cmd_brief "docker exec ${container_name} sh -lc <runtime-deps-script>" \
    docker exec "${container_name}" sh -lc "${inner_script}"
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

  if [[ -n "${OPENCLAWCTL_TEST_EXISTING_DATA_DIR:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_EXISTING_DATA_DIR}"
    return
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s\n' "${fallback}"
    return
  fi

  local mounts_output=""
  mounts_output=$(docker inspect -f '{{range .Mounts}}{{println .Source "|" .Destination}}{{end}}' "${name}" 2>/dev/null || true)

  local source destination
  while IFS='|' read -r source destination; do
    source=$(sanitize_user_input "${source}")
    destination=$(sanitize_user_input "${destination}")
    source=$(trim_surrounding_spaces "${source}")
    destination=$(trim_surrounding_spaces "${destination}")
    [[ -z "${source}" || -z "${destination}" ]] && continue
    if [[ "${destination}" == "/root/.openclaw" ]]; then
      if is_safe_path_text "${source}"; then
        printf '%s\n' "${source}"
        return
      fi
      log_info "检测到 /root/.openclaw 挂载路径包含异常字符，继续尝试其他候选目录"
    fi
  done <<< "${mounts_output}"

  while IFS='|' read -r source destination; do
    source=$(sanitize_user_input "${source}")
    destination=$(sanitize_user_input "${destination}")
    source=$(trim_surrounding_spaces "${source}")
    destination=$(trim_surrounding_spaces "${destination}")
    [[ -z "${source}" || -z "${destination}" ]] && continue
    if [[ "${destination}" == *".openclaw"* || "${destination}" == "/data" || "${destination}" == "/config" ]]; then
      if is_safe_path_text "${source}"; then
        printf '%s\n' "${source}"
        return
      fi
    fi
  done <<< "${mounts_output}"

  while IFS='|' read -r source destination; do
    source=$(sanitize_user_input "${source}")
    destination=$(sanitize_user_input "${destination}")
    source=$(trim_surrounding_spaces "${source}")
    destination=$(trim_surrounding_spaces "${destination}")
    [[ -z "${source}" || -z "${destination}" ]] && continue
    [[ "${destination}" == "/root/.local/bin" || "${destination}" == "/root/go/bin" ]] && continue
    if [[ -f "${source}/openclaw.json" || -d "${source}/backups" ]]; then
      if is_safe_path_text "${source}"; then
        printf '%s\n' "${source}"
        return
      fi
    fi
  done <<< "${mounts_output}"

  if [[ -n "${fallback}" ]]; then
    printf '%s\n' "${fallback}"
    return
  fi

  printf '%s\n' "$(default_data_dir_for_name "${name}")"
}

detect_existing_image() {
  local name="$1"
  local fallback="$2"

  if [[ -n "${OPENCLAWCTL_TEST_CURRENT_IMAGE:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_CURRENT_IMAGE}"
    return
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s\n' "${fallback}"
    return
  fi

  local detected
  detected=$(docker inspect -f '{{.Config.Image}}' "${name}" 2>/dev/null || true)
  if [[ -n "${detected}" ]]; then
    printf '%s\n' "${detected}"
  else
    printf '%s\n' "${fallback}"
  fi
}

image_source_kind() {
  local image="$1"
  if [[ "${image}" == *"openclaw-zh"* ]]; then
    echo "chinese"
  elif [[ "${image}" == *"openclaw"* ]]; then
    echo "official"
  else
    echo "unknown"
  fi
}

prepare_source_switch_transition() {
  local data_dir="$1"
  local from_image="$2"
  local to_image="$3"
  local from_source to_source
  from_source=$(image_source_kind "${from_image}")
  to_source=$(image_source_kind "${to_image}")

  if [[ "${from_source}" == "${to_source}" || "${from_source}" == "unknown" || "${to_source}" == "unknown" ]]; then
    return 0
  fi

  log_info "[source-switch] 检测到版本源切换: ${from_source} -> ${to_source}"
  if [[ -f "${data_dir}/openclaw.json" ]]; then
    local backup_file="${data_dir}/openclaw.json.bak.$(date +%Y%m%d%H%M%S)"
    run_cmd cp "${data_dir}/openclaw.json" "${backup_file}"
  fi

  if [[ "${to_source}" == "official" ]]; then
    run_cmd chmod -R g+rw "${data_dir}" || true
    log_info "[source-switch] 已执行权限兼容修正（official 方向）"
  else
    run_cmd chown -R "$(id -u):$(id -g)" "${data_dir}" || true
    log_info "[source-switch] 已执行权限兼容修正（chinese 方向）"
  fi
  return 0
}

container_path_exists() {
  local name="$1"
  local path="$2"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi
  if ! container_exists "${name}"; then
    return 1
  fi
  docker exec "${name}" sh -lc "test -e '${path}'" >/dev/null 2>&1
}

container_path_has_data() {
  local name="$1"
  local path="$2"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi
  if ! container_exists "${name}"; then
    return 1
  fi
  docker exec "${name}" sh -lc "
if [ -d '${path}' ]; then
  find '${path}' -mindepth 1 -print -quit 2>/dev/null | grep -q .
elif [ -f '${path}' ]; then
  [ -s '${path}' ]
else
  false
fi" >/dev/null 2>&1
}

detect_existing_ports() {
  local name="$1"
  local fallback_host="$2"
  local fallback_container="$3"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
    return
  fi

  local output
  output=$(docker port "${name}" 2>/dev/null || true)
  if [[ -z "${output}" ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
    return
  fi

  local first_line=""
  local first_tcp_line=""
  local preferred_line=""
  local line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    [[ -z "${first_line}" ]] && first_line="${line}"
    if [[ "${line}" == *"/tcp"* && -z "${first_tcp_line}" ]]; then
      first_tcp_line="${line}"
    fi
    if [[ "${line}" == "${fallback_container}/tcp"* ]]; then
      preferred_line="${line}"
      break
    fi
  done <<< "${output}"

  local chosen_line="${preferred_line}"
  [[ -z "${chosen_line}" ]] && chosen_line="${first_tcp_line}"
  [[ -z "${chosen_line}" ]] && chosen_line="${first_line}"
  [[ -z "${chosen_line}" ]] && {
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
    return
  }

  local container_port host_port
  container_port=$(printf '%s' "${chosen_line}" | sed -E 's#^([0-9]+)/[a-z]+.*#\1#')
  host_port=$(printf '%s' "${chosen_line}" | sed -E 's#.*:([0-9]+)$#\1#')

  if [[ -z "${container_port}" || -z "${host_port}" ]]; then
    printf '%s,%s\n' "${fallback_host}" "${fallback_container}"
  else
    printf '%s,%s\n' "${host_port}" "${container_port}"
  fi
}

detect_existing_extra_ports() {
  local name="$1"
  local main_host_port="$2"
  local main_container_port="$3"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo ""
    return
  fi

  local output
  output=$(docker port "${name}" 2>/dev/null || true)
  [[ -z "${output}" ]] && {
    echo ""
    return
  }

  local result=""
  local line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue

    local container_proto="${line%% ->*}"   # e.g. 18789/tcp
    local container_part="${container_proto%%/*}"
    local proto="${container_proto##*/}"
    local host_part="${line##*:}"           # last :<port>
    host_part="${host_part//[$'\r\n']}"

    [[ -z "${container_part}" || -z "${host_part}" ]] && continue
    [[ ! "${container_part}" =~ ^[0-9]+$ || ! "${host_part}" =~ ^[0-9]+$ ]] && continue

    if [[ "${host_part}" == "${main_host_port}" && "${container_part}" == "${main_container_port}" && "${proto}" == "tcp" ]]; then
      continue
    fi

    local token="${host_part}:${container_part}"
    [[ "${proto}" != "tcp" ]] && token="${token}/${proto}"
    case " ${result} " in
      *" ${token} "*) ;;
      *) result="${result}${result:+ }${token}" ;;
    esac
  done <<< "${output}"

  echo "${result}"
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

has_mount_destination() {
  local name="$1"
  local destination="$2"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi

  docker inspect -f '{{range .Mounts}}{{println .Destination}}{{end}}' "${name}" 2>/dev/null | grep -Fxq "${destination}"
}

detect_persist_choice_from_container() {
  local name="$1"
  local target="$2" # bin | env | aptcfg | cache
  local default_value="$3"

  if [[ "${target}" == "bin" ]]; then
    if has_mount_destination "${name}" "/root/.local/bin" || has_mount_destination "${name}" "/root/go/bin" || has_mount_destination "${name}" "/root/.cargo/bin"; then
      echo "1"
      return
    fi
  fi

  if [[ "${target}" == "env" ]]; then
    if has_mount_destination "${name}" "/usr/local/go" || \
      has_mount_destination "${name}" "/usr/local/lib/node_modules" || \
      has_mount_destination "${name}" "/root/.local/lib" || \
      has_mount_destination "${name}" "/root/.local/share/uv" || \
      has_mount_destination "${name}" "/root/.local/pipx" || \
      has_mount_destination "${name}" "/root/.local/share/pipx" || \
      has_mount_destination "${name}" "/root/.rustup" || \
      has_mount_destination "${name}" "/root/.config" || \
      has_mount_destination "${name}" "/root/.ssh" || \
      has_mount_destination "${name}" "/root/.gitconfig" || \
      has_mount_destination "${name}" "/root/.docker" || \
      has_mount_destination "${name}" "/root/.aws" || \
      has_mount_destination "${name}" "/root/.kube" || \
      has_mount_destination "${name}" "/root/.netrc" || \
      has_mount_destination "${name}" "/root/.npmrc" || \
      has_mount_destination "${name}" "/root/.pypirc"; then
      echo "1"
      return
    fi
  fi

  if [[ "${target}" == "aptcfg" ]]; then
    if has_mount_destination "${name}" "/etc/apt/sources.list.d" || has_mount_destination "${name}" "/etc/apt/keyrings"; then
      echo "1"
      return
    fi
  fi

  if [[ "${target}" == "cache" ]]; then
    if has_mount_destination "${name}" "/root/.npm" || has_mount_destination "${name}" "/root/go/pkg/mod" || has_mount_destination "${name}" "/root/.cargo/registry" || has_mount_destination "${name}" "/root/.cargo/git"; then
      echo "1"
      return
    fi
  fi

  echo "${default_value}"
}

container_exists() {
  local name="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fxq "${name}"
}

detect_installed_deps_in_container() {
  local name="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "${DEFAULT_DEP_SET}"
    return
  fi
  if ! container_exists "${name}"; then
    echo "${DEFAULT_DEP_SET}"
    return
  fi

  local detected
  detected=$(docker exec "${name}" sh -lc '
for c in npm uv go rust python3; do
  if command -v "$c" >/dev/null 2>&1; then
    printf "%s " "$c"
    continue
  fi
  case "$c" in
    go)
      [ -x /usr/local/go/bin/go ] || [ -x /root/go/bin/go ] || [ -x /usr/local/bin/go ] && printf "%s " "$c"
      ;;
    uv)
      [ -x /root/.local/bin/uv ] || [ -x /usr/local/bin/uv ] || [ -x /usr/bin/uv ] && printf "%s " "$c"
      ;;
    npm)
      [ -x /usr/bin/npm ] || [ -x /usr/local/bin/npm ] && printf "%s " "$c"
      ;;
    rust)
      [ -x /root/.cargo/bin/cargo ] || [ -x /root/.cargo/bin/rustc ] || [ -x /usr/local/bin/cargo ] || [ -x /usr/local/bin/rustc ] && printf "%s " "$c"
      ;;
    python3)
      [ -x /usr/bin/python3 ] || [ -x /usr/local/bin/python3 ] && printf "%s " "$c"
      ;;
  esac
done' 2>/dev/null || true)
  normalize_dep_list "${detected}"
}

print_upgrade_discovery_summary() {
  local name="$1"
  local data_dir="$2"

  local exists_text="否"
  local runtime_dir_text="否"
  local deps_text="未知"
  local bin_mounted="否"
  local env_mounted="否"
  local node_mod_mounted="否"
  local py_user_lib_mounted="否"
  local auth_cfg_mounted="否"
  local apt_cfg_mounted="否"
  local cache_mounted="否"

  if container_exists "${name}"; then
    exists_text="是"
    deps_text=$(detect_installed_deps_in_container "${name}")
    [[ -z "${deps_text}" ]] && deps_text="未检测到"

    if has_mount_destination "${name}" "/root/.local/bin" || has_mount_destination "${name}" "/root/go/bin" || has_mount_destination "${name}" "/root/.cargo/bin"; then
      bin_mounted="是"
    fi

    if has_mount_destination "${name}" "/usr/local/go" || \
      has_mount_destination "${name}" "/root/.local/share/uv" || \
      has_mount_destination "${name}" "/root/.local/pipx" || \
      has_mount_destination "${name}" "/root/.local/share/pipx" || \
      has_mount_destination "${name}" "/root/.rustup" || \
      has_mount_destination "${name}" "/usr/local/lib/node_modules" || \
      has_mount_destination "${name}" "/root/.local/lib" || \
      has_mount_destination "${name}" "/root/.config" || \
      has_mount_destination "${name}" "/root/.ssh" || \
      has_mount_destination "${name}" "/root/.gitconfig" || \
      has_mount_destination "${name}" "/root/.docker" || \
      has_mount_destination "${name}" "/root/.aws" || \
      has_mount_destination "${name}" "/root/.kube" || \
      has_mount_destination "${name}" "/root/.netrc" || \
      has_mount_destination "${name}" "/root/.npmrc" || \
      has_mount_destination "${name}" "/root/.pypirc"; then
      env_mounted="是"
    fi

    has_mount_destination "${name}" "/usr/local/lib/node_modules" && node_mod_mounted="是"
    has_mount_destination "${name}" "/root/.local/lib" && py_user_lib_mounted="是"
    if has_mount_destination "${name}" "/root/.config" || \
      has_mount_destination "${name}" "/root/.ssh" || \
      has_mount_destination "${name}" "/root/.gitconfig" || \
      has_mount_destination "${name}" "/root/.docker" || \
      has_mount_destination "${name}" "/root/.aws" || \
      has_mount_destination "${name}" "/root/.kube" || \
      has_mount_destination "${name}" "/root/.netrc" || \
      has_mount_destination "${name}" "/root/.npmrc" || \
      has_mount_destination "${name}" "/root/.pypirc"; then
      auth_cfg_mounted="是"
    fi
    if has_mount_destination "${name}" "/etc/apt/sources.list.d" || has_mount_destination "${name}" "/etc/apt/keyrings"; then
      apt_cfg_mounted="是"
    fi
    if has_mount_destination "${name}" "/root/.npm" || has_mount_destination "${name}" "/root/go/pkg/mod" || has_mount_destination "${name}" "/root/.cargo/registry" || has_mount_destination "${name}" "/root/.cargo/git"; then
      cache_mounted="是"
    fi
  fi

  [[ -d "${data_dir}/runtime" ]] && runtime_dir_text="是"

  printf '\n=== 升级前环境检测 ===\n'
  echo "容器存在: ${exists_text}"
  echo "runtime 目录存在: ${runtime_dir_text} (${data_dir}/runtime)"
  echo "已检测依赖: ${deps_text}"
  echo "当前持久化挂载: bin=${bin_mounted}, env=${env_mounted}"
  echo "扩展环境挂载: npm全局(node_modules)=${node_mod_mounted}, pip用户库(/root/.local/lib)=${py_user_lib_mounted}, 授权配置(.config/.ssh/.gitconfig/.docker/.aws/.kube/.netrc/.npmrc/.pypirc)=${auth_cfg_mounted}, APT源Key(${apt_cfg_mounted}), 缓存(.npm/go mod/cargo)=${cache_mounted}"

  local -a hints=()
  if [[ "${exists_text}" == "是" ]]; then
    if dep_enabled "${deps_text}" "go" && [[ "${env_mounted}" != "是" ]]; then
      hints+=("检测到 go 已安装但 env 未持久化，建议在本次升级开启 env。")
    fi
    if dep_enabled "${deps_text}" "rust" && [[ "${bin_mounted}" != "是" || "${env_mounted}" != "是" ]]; then
      hints+=("检测到 rust 已安装，建议同时开启 bin/env（持久化 /root/.cargo/bin 与 /root/.rustup）。")
    fi
    if dep_enabled "${deps_text}" "uv" && [[ "${bin_mounted}" != "是" && "${env_mounted}" != "是" ]]; then
      hints+=("检测到 uv 已安装但未持久化，建议在本次升级开启 bin/env。")
    fi
    if dep_enabled "${deps_text}" "npm" && [[ "${node_mod_mounted}" != "是" ]]; then
      hints+=("检测到 npm 可用，若依赖 npm -g 包建议开启 env（官方镜像走 /usr/local/lib/node_modules，zh 镜像走 /root/.local/lib）。")
    fi
    if dep_enabled "${deps_text}" "python3" && [[ "${py_user_lib_mounted}" != "是" ]]; then
      hints+=("检测到 python3 可用，若依赖 pip --user 包建议开启 env（持久化 /root/.local/lib）。")
    fi
    if [[ "${auth_cfg_mounted}" != "是" ]]; then
      hints+=("若依赖 gh/ssh/docker/aws/kube 等登录态，建议开启 env（持久化常见授权配置目录）。")
    fi
    if [[ "${apt_cfg_mounted}" != "是" ]]; then
      hints+=("若依赖第三方 apt 源或 key，建议开启 APT源Key 持久化（/etc/apt/sources.list.d 与 /etc/apt/keyrings）。")
    fi
    if [[ "${cache_mounted}" != "是" ]]; then
      hints+=("若希望减少 npm/go/rust 二次下载时间，可开启缓存持久化（/root/.npm、/root/go/pkg/mod、/root/.cargo/{registry,git}）。")
    fi
  fi

  if [[ "${#hints[@]}" -gt 0 ]]; then
    echo "建议:"
    local item
    for item in "${hints[@]}"; do
      echo " - ${item}"
    done
    echo "说明: 若本次开启了 bin/env/aptcfg/cache，脚本会在删除旧容器前自动尝试迁移对应 runtime 数据。"
  else
    echo "建议: 当前状态无明显风险，可继续升级。"
  fi
}

install_docker_if_missing() {
  local platform
  platform=$(host_platform)

  if [[ "${platform}" == "linux" ]]; then
    local install_choice="${OPENCLAWCTL_AUTO_INSTALL_DOCKER:-}"
    if [[ -z "${install_choice}" && is_interactive_session ]]; then
      printf '检测到未安装 Docker，是否自动安装 Docker Engine? (y/N): '
      IFS= read -r install_choice
    fi
    if [[ "${install_choice}" != "1" ]] && ! validate_yes_no "${install_choice:-n}"; then
      log_error "Docker 未安装。可设置 OPENCLAWCTL_AUTO_INSTALL_DOCKER=1 自动安装，或手工执行: curl -fsSL https://get.docker.com | sh"
      return 1
    fi

    run_cmd sh -lc 'curl -fsSL https://get.docker.com | sh'
    if command -v systemctl >/dev/null 2>&1; then
      run_cmd systemctl enable --now docker || true
    elif command -v service >/dev/null 2>&1; then
      run_cmd service docker start || true
    fi
    return 0
  fi

  if [[ "${platform}" == "darwin" ]]; then
    if command -v brew >/dev/null 2>&1; then
      local install_choice_mac="${OPENCLAWCTL_AUTO_INSTALL_DOCKER:-}"
      if [[ -z "${install_choice_mac}" && is_interactive_session ]]; then
        printf '检测到未安装 Docker，是否通过 Homebrew 安装 Docker Desktop? (y/N): '
        IFS= read -r install_choice_mac
      fi
      if [[ "${install_choice_mac}" == "1" ]] || validate_yes_no "${install_choice_mac:-n}"; then
        run_cmd brew install --cask docker
        log_info "安装完成后请手动启动 Docker Desktop: open -a Docker"
        return 0
      fi
    fi
    log_error "macOS 环境请先安装并启动 Docker Desktop 后重试。"
    return 1
  fi

  log_error "当前系统暂不支持自动安装 Docker，请手工安装后重试。"
  return 1
}

run_preflight_checks() {
  local action="$1"
  local container_name="$2"
  local data_dir="$3"
  local image="${4:-}"
  local host_port="${5:-}"
  local container_port="${6:-}"

  log_info "[preflight] action=${action}"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log_info "[preflight] host_os=${ID:-unknown} ${VERSION_ID:-unknown}"
  fi

  if ! command -v docker >/dev/null 2>&1; then
    log_info "[preflight] docker 命令不可用，尝试自动安装/引导"
    if ! install_docker_if_missing; then
      log_error "[preflight] docker 命令不可用"
      return 1
    fi
  fi

  if ! command -v docker >/dev/null 2>&1; then
    log_error "[preflight] docker 安装后仍不可用"
    return 1
  fi

  if [[ "${DRY_RUN}" -eq 0 ]]; then
    if ! docker info >/dev/null 2>&1; then
      log_error "[preflight] 无法连接 Docker Daemon"
      return 1
    fi
    local docker_server
    docker_server=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true)
    [[ -n "${docker_server}" ]] && log_info "[preflight] docker_server=${docker_server}"
  else
    log_info "[preflight] dry-run 模式，跳过 daemon 连通性校验"
  fi

  if [[ -n "${data_dir}" ]]; then
    if [[ "${DRY_RUN}" -eq 0 ]]; then
      run_cmd mkdir -p "${data_dir}"
      if [[ ! -w "${data_dir}" ]]; then
        log_error "[preflight] 持久化目录不可写: ${data_dir}"
        return 1
      fi
    fi
    append_diagnostics_log "${data_dir}" "preflight action=${action} container=${container_name} host_port=${host_port} container_port=${container_port}"
  fi

  if [[ -n "${image}" ]]; then
    local registry="${image%%/*}"
    if [[ "${registry}" != *.* && "${registry}" != "localhost" ]]; then
      registry="docker.io"
    fi
    log_info "[preflight] target_registry=${registry}"
  fi

  if [[ -n "${container_name}" && -n "${data_dir}" && "${DRY_RUN}" -eq 0 ]] && container_exists "${container_name}"; then
    local existing_data
    existing_data=$(detect_existing_data_dir "${container_name}" "")
    existing_data=$(trim_surrounding_spaces "${existing_data}")
    local expected_data
    expected_data=$(trim_surrounding_spaces "${data_dir}")
    if [[ -n "${existing_data}" && "${existing_data}" != "${expected_data}" ]]; then
      if [[ "${OPENCLAWCTL_ALLOW_DATA_DIR_MISMATCH:-0}" == "1" ]]; then
        log_info "[preflight] 注意: 当前容器数据目录为 ${existing_data}，与本次选择不同（已按 OPENCLAWCTL_ALLOW_DATA_DIR_MISMATCH=1 放行）"
      else
        log_error "[preflight] 当前容器数据目录为 ${existing_data}，与本次选择 ${expected_data} 不一致。为避免错挂载导致升级失败，已终止。"
        log_info "[preflight] 如确认要迁移新目录，请设置 OPENCLAWCTL_ALLOW_DATA_DIR_MISMATCH=1 后重试。"
        return 1
      fi
    fi
    if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
      log_info "[preflight] 检测到可能是旧安装（无 persistence.profile），将启用兼容迁移识别"
    fi
  fi

  return 0
}

prompt_dep_set() {
  local base_dep_set="$1"
  local normalized_base
  normalized_base=$(normalize_dep_list "${base_dep_set}")

  local npm_default="2"
  local uv_default="2"
  local go_default="2"
  local rust_default="2"

  dep_enabled "${normalized_base}" "npm" && npm_default="1"
  dep_enabled "${normalized_base}" "uv" && uv_default="1"
  dep_enabled "${normalized_base}" "go" && go_default="1"
  dep_enabled "${normalized_base}" "rust" && rust_default="1"

  echo "依赖选择（默认 npm+uv，go/rust 可选）:" >&2
  echo "是否包含 npm:" >&2
  echo "  1) 是" >&2
  echo "  2) 否" >&2
  local npm_choice
  npm_choice=$(read_choice_default "请选择" "${npm_default}")

  echo "是否包含 uv:" >&2
  echo "  1) 是" >&2
  echo "  2) 否" >&2
  local uv_choice
  uv_choice=$(read_choice_default "请选择" "${uv_default}")

  echo "是否包含 go:" >&2
  echo "  1) 是" >&2
  echo "  2) 否" >&2
  local go_choice
  go_choice=$(read_choice_default "请选择" "${go_default}")

  echo "是否包含 rust:" >&2
  echo "  1) 是" >&2
  echo "  2) 否" >&2
  local rust_choice
  rust_choice=$(read_choice_default "请选择" "${rust_default}")

  local extra_deps
  extra_deps=$(read_with_default "额外依赖命令（逗号分隔，可留空）" "")

  build_dep_set_from_choices "${npm_choice}" "${uv_choice}" "${go_choice}" "${rust_choice}" "${extra_deps}"
}

value_or_unset() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    echo "${value}"
  else
    echo "未选择"
  fi
}

bind_choice_label() {
  local bind_choice="$1"
  if [[ "${bind_choice}" == "1" ]]; then
    echo "local"
  else
    echo "lan"
  fi
}

token_mode_label() {
  local token_mode="$1"
  local token_manual="$2"
  if [[ "${token_mode}" == "2" ]]; then
    if [[ -n "${token_manual}" ]]; then
      echo "手动输入（已设置）"
    else
      echo "手动输入（未设置）"
    fi
  else
    echo "自动生成"
  fi
}

source_choice_label() {
  local source_choice="${1:-}"
  case "${source_choice}" in
    1) echo "官方" ;;
    2) echo "中文版" ;;
    *) echo "未选择" ;;
  esac
}

channel_choice_label() {
  local channel_choice="${1:-}"
  case "${channel_choice}" in
    1) echo "稳定版" ;;
    2) echo "最新版" ;;
    3) echo "指定版本" ;;
    *) echo "未选择" ;;
  esac
}

display_port_mappings() {
  local mappings="${1:-}"
  if [[ -z "${mappings}" ]]; then
    echo "未配置"
  else
    printf '%s\n' "${mappings}" | sed 's/ /, /g'
  fi
}

install_default_data_dir_desc() {
  local name="${1:-}"
  local root
  root=$(default_data_root)
  if [[ -n "${name}" ]]; then
    echo "${root}/${name}"
  else
    echo "${root}/<容器名>"
  fi
}

install_version_group_summary() {
  local image="$1"
  local source_choice="${2:-}"
  local channel_choice="${3:-}"
  local official_tag="${4:-}"
  if [[ -n "${source_choice}" || -n "${channel_choice}" ]]; then
    if [[ "${source_choice}" == "1" && "${channel_choice}" == "3" && -n "${official_tag}" ]]; then
      echo "$(source_choice_label "${source_choice}") · $(channel_choice_label "${channel_choice}")(${official_tag})"
      return
    fi
    echo "$(source_choice_label "${source_choice}") · $(channel_choice_label "${channel_choice}")"
    return
  fi
  value_or_unset "${image}"
}

data_persistence_group_summary() {
  local data_dir="$1"
  local bin_choice="$2"
  local env_choice="$3"
  local apt_cfg_choice="${4:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local cache_choice="${5:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local default_desc="${6:-}"
  local dir_display="${data_dir}"
  [[ -z "${dir_display}" ]] && dir_display="${default_desc}"
  echo "目录=${dir_display} | bin=$(choice_to_yes_no "${bin_choice}") | env=$(choice_to_yes_no "${env_choice}") | APT源Key=$(choice_to_yes_no "${apt_cfg_choice}") | 缓存=$(choice_to_yes_no "${cache_choice}")"
}

network_group_summary() {
  local bind_choice="$1"
  local host_port="$2"
  local container_port="$3"
  local extra_ports="${4:-}"
  local easyclaw_enabled="${5:-0}"
  local extra_desc
  extra_desc=$(display_port_mappings "${extra_ports}")
  if [[ "${easyclaw_enabled}" == "1" ]]; then
    echo "绑定=$(bind_choice_label "${bind_choice}") | 主端口=${host_port}:${container_port} | 补充端口=${extra_desc} | EasyClaw Web 将自动补 ${EASYCLAW_DEFAULT_WEB_PORT}"
  else
    echo "绑定=$(bind_choice_label "${bind_choice}") | 主端口=${host_port}:${container_port} | 补充端口=${extra_desc}"
  fi
}

network_group_summary_no_bind() {
  local host_port="$1"
  local container_port="$2"
  local extra_ports="${3:-}"
  local easyclaw_enabled="${4:-0}"
  local extra_desc
  extra_desc=$(display_port_mappings "${extra_ports}")
  if [[ "${easyclaw_enabled}" == "1" ]]; then
    echo "主端口=${host_port}:${container_port} | 补充端口=${extra_desc} | EasyClaw Web 将自动补 ${EASYCLAW_DEFAULT_WEB_PORT}"
  else
    echo "主端口=${host_port}:${container_port} | 补充端口=${extra_desc}"
  fi
}

feature_group_summary() {
  local easy_choice="$1"
  local deps_choice="$2"
  local dep_set="$3"
  if [[ "${deps_choice}" == "1" ]]; then
    echo "EasyClaw=$(choice_to_yes_no "${easy_choice}") | 依赖补齐=是 | $(deps_summary_line "${dep_set}")"
  else
    echo "EasyClaw=$(choice_to_yes_no "${easy_choice}") | 依赖补齐=否"
  fi
}

software_group_summary() {
  local software_set="$1"
  echo "软件=$(software_set_summary "${software_set}")"
}

skill_group_summary() {
  local skill_set="$1"
  echo "Skills=$(skill_set_summary "${skill_set}")"
}

auth_group_summary() {
  local token_mode="$1"
  local token_manual="$2"
  echo "Token=$(token_mode_label "${token_mode}" "${token_manual}")"
}

deps_summary_line() {
  local dep_set="$1"
  if [[ -z "${dep_set}" ]]; then
    echo "未配置"
    return
  fi
  echo "npm=$(dep_choice_label "${dep_set}" "npm"), uv=$(dep_choice_label "${dep_set}" "uv"), go=$(dep_choice_label "${dep_set}" "go"), rust=$(dep_choice_label "${dep_set}" "rust"), python3=$(dep_choice_label "${dep_set}" "python3")"
}

detect_access_host() {
  if [[ -n "${OPENCLAWCTL_ACCESS_HOST:-}" ]]; then
    echo "${OPENCLAWCTL_ACCESS_HOST}"
    return
  fi
  echo "Your Host IP"
}

get_container_status_text() {
  local container_name="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "预演模式（未实际启动）"
    return
  fi
  if ! container_exists "${container_name}"; then
    echo "未运行（容器不存在）"
    return
  fi

  local running
  running=$(docker inspect -f '{{.State.Running}}' "${container_name}" 2>/dev/null || true)
  if [[ "${running}" == "true" ]]; then
    echo "正常（running）"
  else
    echo "异常（容器未运行）"
  fi
}

detect_openclaw_version() {
  local container_name="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "预演模式"
    return
  fi
  if ! container_exists "${container_name}"; then
    echo "未知"
    return
  fi

  local version
  version=$(docker exec "${container_name}" sh -lc 'openclaw --version 2>/dev/null | head -n1' 2>/dev/null | tr -d '\r' || true)
  if [[ -z "${version}" ]]; then
    echo "未知"
  else
    echo "${version}"
  fi
}

detect_gateway_bind() {
  local container_name="$1"
  local data_dir="$2"
  local default_bind="$3"

  local bind=""
  if [[ "${DRY_RUN}" -eq 0 ]] && container_exists "${container_name}"; then
    bind=$(docker exec "${container_name}" sh -lc 'openclaw config get gateway.bind 2>/dev/null' 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]' || true)
    if [[ "${bind}" == *"local"* ]]; then
      echo "local"
      return
    fi
    if [[ "${bind}" == *"lan"* ]]; then
      echo "lan"
      return
    fi
  fi

  if [[ -f "${data_dir}/openclaw.json" ]]; then
    bind=$(grep -Eo '"bind"[[:space:]]*:[[:space:]]*"[^"]+"' "${data_dir}/openclaw.json" 2>/dev/null | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' | tr '[:upper:]' '[:lower:]' || true)
    if [[ "${bind}" == "local" || "${bind}" == "lan" ]]; then
      echo "${bind}"
      return
    fi
  fi

  echo "${default_bind}"
}

gateway_bind_desc() {
  local bind="$1"
  if [[ "${bind}" == "local" ]]; then
    echo "local（仅本机/内网代理访问）"
  else
    echo "lan（具备对外访问能力，取决于端口放行与防火墙）"
  fi
}

runtime_persist_paths_desc() {
  local data_dir="$1"
  local bin_choice="$2"
  local env_choice="$3"
  local apt_cfg_choice="${4:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local cache_choice="${5:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local image="${6:-}"
  local lines=()

  if [[ "${bin_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/root-local-bin")
    lines+=("${data_dir}/runtime/root-go-bin")
    lines+=("${data_dir}/runtime/root-cargo-bin")
  fi
  if [[ "${env_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/usr-local-go")
    if should_persist_node_modules_mount "${image}"; then
      lines+=("${data_dir}/runtime/usr-local-lib-node-modules")
    fi
    lines+=("${data_dir}/runtime/root-local-lib")
    lines+=("${data_dir}/runtime/root-local-share-uv")
    lines+=("${data_dir}/runtime/root-local-pipx")
    lines+=("${data_dir}/runtime/root-local-share-pipx")
    lines+=("${data_dir}/runtime/root-rustup")
    lines+=("${data_dir}/runtime/root-config")
    lines+=("${data_dir}/runtime/root-ssh")
    lines+=("${data_dir}/runtime/root-gitconfig")
    lines+=("${data_dir}/runtime/root-docker")
    lines+=("${data_dir}/runtime/root-aws")
    lines+=("${data_dir}/runtime/root-kube")
    lines+=("${data_dir}/runtime/root-netrc")
    lines+=("${data_dir}/runtime/root-npmrc")
    lines+=("${data_dir}/runtime/root-pypirc")
  fi
  if [[ "${apt_cfg_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/etc-apt-sources-list-d")
    lines+=("${data_dir}/runtime/etc-apt-keyrings")
  fi
  if [[ "${cache_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/root-npm-cache")
    lines+=("${data_dir}/runtime/root-go-pkg-mod")
    lines+=("${data_dir}/runtime/root-cargo-registry")
    lines+=("${data_dir}/runtime/root-cargo-git")
  fi
  if [[ "${#lines[@]}" -eq 0 ]]; then
    echo "未启用"
    return
  fi
  local joined
  joined=$(printf '%s; ' "${lines[@]}")
  joined="${joined%; }"
  echo "${joined}"
}

detect_installed_deps_summary() {
  local container_name="$1"
  local dep_set="$2"
  local normalized
  normalized=$(normalize_dep_list "${dep_set}")

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "预演模式（未实际检测）"
    return
  fi
  if ! container_exists "${container_name}"; then
    echo "未知（容器不存在）"
    return
  fi
  if [[ -z "${normalized}" ]]; then
    echo "未配置"
    return
  fi

  local summary_script
  summary_script=$(cat <<'EOS'
status() {
  c="$1"
  if command -v "$c" >/dev/null 2>&1; then
    printf "%s " "$c"
    return
  fi
  case "$c" in
    go)
      if [ -x /usr/local/go/bin/go ] || [ -x /root/go/bin/go ] || [ -x /usr/local/bin/go ]; then
        printf "%s(PATH需修复) " "$c"
      fi
      ;;
    uv)
      if [ -x /root/.local/bin/uv ] || [ -x /usr/local/bin/uv ] || [ -x /usr/bin/uv ]; then
        printf "%s(PATH需修复) " "$c"
      fi
      ;;
    npm)
      if [ -x /usr/bin/npm ] || [ -x /usr/local/bin/npm ]; then
        printf "%s(PATH需修复) " "$c"
      fi
      ;;
    rust)
      if [ -x /root/.cargo/bin/cargo ] || [ -x /root/.cargo/bin/rustc ] || [ -x /usr/local/bin/cargo ] || [ -x /usr/local/bin/rustc ]; then
        printf "%s(PATH需修复) " "$c"
      fi
      ;;
    python3)
      if [ -x /usr/bin/python3 ] || [ -x /usr/local/bin/python3 ]; then
        printf "%s(PATH需修复) " "$c"
      fi
      ;;
  esac
}
for c in __DEPS__; do
  status "$c"
done
EOS
)
  summary_script="${summary_script/__DEPS__/${normalized}}"
  local found
  found=$(docker exec "${container_name}" sh -lc "${summary_script}" 2>/dev/null || true)
  found=$(echo "${found}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  if [[ -z "${found}" ]]; then
    echo "未检测到"
  else
    echo "${found}"
  fi
}

detect_token_from_config() {
  local data_dir="$1"
  local cfg="${data_dir}/openclaw.json"
  if [[ ! -f "${cfg}" ]]; then
    echo ""
    return
  fi
  grep -Eo '"token"[[:space:]]*:[[:space:]]*"[^"]+"' "${cfg}" 2>/dev/null | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true
}

print_human_summary() {
  local action="$1"
  local container_name="$2"
  local version="$3"
  local status_text="$4"
  local data_dir="$5"
  local runtime_paths="$6"
  local deps_installed="$7"
  local gateway_bind="$8"
  local token="$9"
  local host_port="${10}"
  local extra_ports="${11:-}"

  local access_host access_url
  access_host=$(detect_access_host)
  access_url="http://${access_host}:${host_port}/"
  if [[ -n "${token}" ]]; then
    access_url="${access_url}?token=${token}"
  fi

  local installed_software_set software_summary skill_summary
  installed_software_set=$(load_software_profile "${data_dir}")
  software_summary=$(software_set_summary "${installed_software_set}")
  skill_summary=$(skill_set_summary "$(load_skill_profile "${data_dir}")")
  local easyclaw_mapping easyclaw_host_port
  easyclaw_mapping=$(detect_easyclaw_web_mapping "${extra_ports}" || true)
  easyclaw_host_port="${EASYCLAW_DEFAULT_WEB_PORT}"
  if [[ -n "${easyclaw_mapping}" ]]; then
    easyclaw_host_port="${easyclaw_mapping%%:*}"
  fi

  printf '\n===============================\n'
  if [[ "${action}" == "install" ]]; then
    echo "安装结果"
  elif [[ "${action}" == "rebuild" ]]; then
    echo "重建结果"
  else
    echo "升级结果"
  fi
  echo "==============================="
  if [[ "${action}" == "install" ]]; then
    echo "已完成主程序安装"
  elif [[ "${action}" == "rebuild" ]]; then
    echo "已完成容器安全重建"
  else
    echo "已完成主程序升级"
  fi
  echo "主程序版本：${version}"
  echo "启动状态：${status_text}"
  echo "持久化目录：${data_dir}"
  echo "运行环境持久化目录：${runtime_paths}"
  echo "已安装运行环境：${deps_installed}"
  echo "可选软件：${software_summary}"
  echo "已安装 Skills：${skill_summary}"
  echo "网络绑定：$(gateway_bind_desc "${gateway_bind}")"
  echo "扩展端口映射：$(value_or_unset "${extra_ports}")"
  if [[ -n "${token}" ]]; then
    echo "Token：${token}（请务必保留并妥善保存，是后续登录依据）"
  else
    echo "Token：沿用原配置（如需查看可在 ${data_dir}/openclaw.json 中确认）"
  fi
  echo "访问地址：${access_url}"
  echo
  echo "启动CLI配置流程："
  echo "官方Cli命令："
  echo "docker exec -it ${container_name} openclaw onboard"
  echo
  echo "EasyClaw 管理工具："
  echo "docker exec -it ${container_name} easyclaw tui"
  echo "docker exec -it ${container_name} easyclaw web --port ${EASYCLAW_DEFAULT_WEB_PORT}"
  echo "若已启动 Web UI，可访问：http://Your Host IP:${easyclaw_host_port}/"
  if token_in_list "claudecodeui" ${installed_software_set}; then
    local claudecodeui_mapping claudecodeui_host_port
    claudecodeui_mapping=$(detect_claudecodeui_reserved_mapping "${extra_ports}" || true)
    claudecodeui_host_port=""
    if [[ -n "${claudecodeui_mapping}" ]]; then
      claudecodeui_host_port="${claudecodeui_mapping%%:*}"
    fi
    echo
    echo "ClaudeCodeUI + TaskMaster："
    echo "docker exec -it ${container_name} claudecodeui-start"
    if [[ -n "${claudecodeui_host_port}" ]]; then
      echo "若已启动 CloudCLI UI，可访问：http://Your Host IP:${claudecodeui_host_port}/"
    fi
  fi
  echo
  echo "后续可使用本脚本进行更新检查并升级程序"
  echo "持久化信息在升级后会继续保留"
  echo "==============================="
}

execute_install_plan() {
  local image="$1"
  local name="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local gateway_bind="$6"
  local token="$7"
  local bin_persist_choice="$8"
  local env_persist_choice="$9"
  local apt_cfg_persist_choice="${10}"
  local cache_persist_choice="${11}"
  local easy_choice="${12}"
  local deps_install_choice="${13}"
  local target_deps="${14}"
  local extra_ports="${15:-}"
  local software_set="${16:-}"
  local skill_set="${17:-}"

  software_set=$(normalize_software_set "${software_set}")
  skill_set=$(normalize_skill_set "${skill_set}")
  if [[ -n "${software_set}" && "${deps_install_choice}" != "1" ]]; then
    log_info "检测到已选择可选软件，已自动开启依赖补齐流程"
    deps_install_choice="1"
  fi
  target_deps=$(ensure_dep_set_for_software "${target_deps}" "${software_set}")
  if token_in_list "easyclaw" ${software_set}; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if token_in_list "claudecodeui" ${software_set}; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "install" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "install" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi
  remove_container_if_exists "${name}"
  bootstrap_openclaw_config "${image}" "${data_dir}" "${container_port}" "${gateway_bind}" "${token}"
  local -a install_nonfatal_issues=()
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    install_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${gateway_bind}"; then
    install_nonfatal_issues+=("Control UI 兼容配置失败")
  fi
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止安装以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_software_profile "${data_dir}" "${software_set}"
  save_skill_profile "${data_dir}" "${skill_set}"
  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    install_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      install_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      install_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
  fi
  if [[ "${easy_choice}" == "1" ]]; then
    if ! run_optional_step "EasyClaw 安装/升级" install_easyclaw "${name}" "${data_dir}"; then
      install_nonfatal_issues+=("EasyClaw 安装/升级失败")
    fi
  fi
  if [[ "${deps_install_choice}" == "1" ]]; then
    if run_optional_step "依赖补齐" manage_container_runtime_deps "${name}" "install" "${target_deps}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${target_deps}" || true
    else
      install_nonfatal_issues+=("容器依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "可选软件安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      install_nonfatal_issues+=("可选软件安装失败")
    fi
  fi
  if [[ -n "${skill_set}" ]]; then
    if ! run_optional_step "Skill 安装" install_selected_skills "${data_dir}" "${skill_set}"; then
      install_nonfatal_issues+=("Skill 安装失败")
    fi
  fi

  printf 'TOKEN=%s\n' "${token}"
  printf 'URL=http://<server-ip>:%s/?token=%s\n' "${host_port}" "${token}"
  local install_version install_status_text install_runtime_paths install_deps_installed
  install_version=$(detect_openclaw_version "${name}")
  install_status_text=$(get_container_status_text "${name}")
  install_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  install_deps_installed=$(detect_installed_deps_summary "${name}" "${target_deps}")

  local install_status="success"
  if [[ "${#install_nonfatal_issues[@]}" -gt 0 ]]; then
    install_status="success_with_warnings"
    log_error "以下可选步骤失败（主应用已可用）:"
    local issue
    for issue in "${install_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi
  write_last_report "install" "${install_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${token}" "http://<server-ip>:${host_port}/?token=${token}" "${install_nonfatal_issues[@]}"
  print_human_summary "install" "${name}" "${install_version}" "${install_status_text}" "${data_dir}" "${install_runtime_paths}" "${install_deps_installed}" "${gateway_bind}" "${token}" "${host_port}" "${extra_ports}"
  write_deployment_info "install" "${install_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${token}" "${extra_ports}" || true
}

execute_upgrade_plan() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local bin_persist_choice="$6"
  local env_persist_choice="$7"
  local apt_cfg_persist_choice="$8"
  local cache_persist_choice="$9"
  local easyclaw_upgrade="${10}"
  local deps_repair_choice="${11}"
  local upgrade_dep_set="${12}"
  local extra_ports="${13:-}"
  local software_set

  software_set=$(load_software_profile "${data_dir}")
  software_set=$(normalize_software_set "${software_set}")
  if [[ -n "${software_set}" ]]; then
    log_info "检测到已保存的软件档案，升级后将自动保活: $(software_set_summary "${software_set}")"
    upgrade_dep_set=$(ensure_dep_set_for_software "${upgrade_dep_set}" "${software_set}")
    if [[ "${deps_repair_choice}" != "1" ]]; then
      log_info "已自动开启升级后依赖补齐流程"
      deps_repair_choice="1"
    fi
  fi

  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
    return 1
  fi
  if should_enable_easyclaw_web_port "${easyclaw_upgrade}" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "upgrade" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "upgrade" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi

  local -a upgrade_nonfatal_issues=()
  local current_image
  current_image=$(detect_existing_image "${name}" "")
  if ! run_optional_step "版本源切换兼容修正" prepare_source_switch_transition "${data_dir}" "${current_image}" "${image}"; then
    upgrade_nonfatal_issues+=("版本源切换兼容修正失败")
  fi
  local current_gateway_bind
  current_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")

  if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${image}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
    log_error "升级前 runtime 数据迁移失败；为避免数据丢失，已中止本次升级"
    return 1
  fi

  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包清单快照" snapshot_apt_manual_packages "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("APT 手工包清单快照失败")
    fi
  fi

  remove_container_if_exists "${name}"
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止升级以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    upgrade_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${current_gateway_bind}"; then
    upgrade_nonfatal_issues+=("Control UI 兼容配置失败")
  fi
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    upgrade_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      upgrade_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      upgrade_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包回放安装" restore_apt_manual_packages "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("APT 手工包回放安装失败")
    fi
  fi

  run_cmd docker ps --filter "name=${name}"
  run_cmd docker logs --tail 30 "${name}"
  run_cmd docker exec "${name}" openclaw --version

  if [[ "${easyclaw_upgrade}" == "1" ]]; then
    if ! run_optional_step "EasyClaw 检查升级" check_and_upgrade_easyclaw "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("EasyClaw 检查升级失败")
    fi
  fi
  if [[ "${deps_repair_choice}" == "1" ]]; then
    if run_optional_step "升级后依赖补齐" manage_container_runtime_deps "${name}" "install" "${upgrade_dep_set}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${upgrade_dep_set}" || true
    else
      upgrade_nonfatal_issues+=("升级后依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "升级后可选软件保活安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      upgrade_nonfatal_issues+=("升级后可选软件保活安装失败")
    fi
  fi

  if [[ "${#upgrade_nonfatal_issues[@]}" -gt 0 ]]; then
    log_error "以下可选步骤失败（升级主流程已完成）:"
    local issue
    for issue in "${upgrade_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi
  local upgrade_status="success"
  [[ "${#upgrade_nonfatal_issues[@]}" -gt 0 ]] && upgrade_status="success_with_warnings"
  write_last_report "upgrade" "${upgrade_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "" "${upgrade_nonfatal_issues[@]}"

  local upgrade_version upgrade_status_text upgrade_runtime_paths upgrade_deps_installed upgrade_gateway_bind upgrade_token
  upgrade_version=$(detect_openclaw_version "${name}")
  upgrade_status_text=$(get_container_status_text "${name}")
  upgrade_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  upgrade_deps_installed=$(detect_installed_deps_summary "${name}" "${upgrade_dep_set}")
  upgrade_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  upgrade_token=$(detect_token_from_config "${data_dir}")
  print_human_summary "upgrade" "${name}" "${upgrade_version}" "${upgrade_status_text}" "${data_dir}" "${upgrade_runtime_paths}" "${upgrade_deps_installed}" "${upgrade_gateway_bind}" "${upgrade_token}" "${host_port}" "${extra_ports}"
  write_deployment_info "upgrade" "${upgrade_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${upgrade_token}" "${extra_ports}" || true
}

execute_rebuild_plan() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local bin_persist_choice="$6"
  local env_persist_choice="$7"
  local apt_cfg_persist_choice="$8"
  local cache_persist_choice="$9"
  local deps_repair_choice="${10}"
  local rebuild_dep_set="${11}"
  local extra_ports="${12:-}"
  local software_set

  software_set=$(load_software_profile "${data_dir}")
  software_set=$(normalize_software_set "${software_set}")
  if [[ -n "${software_set}" ]]; then
    log_info "检测到已保存的软件档案，重建后将自动保活: $(software_set_summary "${software_set}")"
    rebuild_dep_set=$(ensure_dep_set_for_software "${rebuild_dep_set}" "${software_set}")
    if [[ "${deps_repair_choice}" != "1" ]]; then
      log_info "已自动开启重建后依赖补齐流程"
      deps_repair_choice="1"
    fi
  fi

  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
    return 1
  fi
  extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "rebuild" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "rebuild" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi

  local -a rebuild_nonfatal_issues=()
  local current_image
  current_image=$(detect_existing_image "${name}" "")
  if ! run_optional_step "版本源切换兼容修正" prepare_source_switch_transition "${data_dir}" "${current_image}" "${image}"; then
    rebuild_nonfatal_issues+=("版本源切换兼容修正失败")
  fi
  local current_gateway_bind
  current_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${image}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
    log_error "重建前 runtime 数据迁移失败；为避免数据丢失，已中止本次重建"
    return 1
  fi

  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包清单快照" snapshot_apt_manual_packages "${name}" "${data_dir}"; then
      rebuild_nonfatal_issues+=("APT 手工包清单快照失败")
    fi
  fi

  remove_container_if_exists "${name}"
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止重建以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    rebuild_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${current_gateway_bind}"; then
    rebuild_nonfatal_issues+=("Control UI 兼容配置失败")
  fi

  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"

  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    rebuild_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      rebuild_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      rebuild_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
    if ! run_optional_step "APT 手工包回放安装" restore_apt_manual_packages "${name}" "${data_dir}"; then
      rebuild_nonfatal_issues+=("APT 手工包回放安装失败")
    fi
  fi

  if [[ "${deps_repair_choice}" == "1" ]]; then
    if run_optional_step "重建后依赖补齐" manage_container_runtime_deps "${name}" "install" "${rebuild_dep_set}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${rebuild_dep_set}" || true
    else
      rebuild_nonfatal_issues+=("重建后依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "重建后可选软件保活安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      rebuild_nonfatal_issues+=("重建后可选软件保活安装失败")
    fi
  fi

  run_cmd docker ps --filter "name=${name}"
  run_cmd docker logs --tail 30 "${name}"
  run_cmd docker exec "${name}" openclaw --version

  if [[ "${#rebuild_nonfatal_issues[@]}" -gt 0 ]]; then
    log_error "以下可选步骤失败（重建主流程已完成）:"
    local issue
    for issue in "${rebuild_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi

  local rebuild_status="success"
  [[ "${#rebuild_nonfatal_issues[@]}" -gt 0 ]] && rebuild_status="success_with_warnings"
  write_last_report "rebuild" "${rebuild_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "" "${rebuild_nonfatal_issues[@]}"

  local rebuild_version rebuild_status_text rebuild_runtime_paths rebuild_deps_installed rebuild_gateway_bind rebuild_token
  rebuild_version=$(detect_openclaw_version "${name}")
  rebuild_status_text=$(get_container_status_text "${name}")
  rebuild_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  rebuild_deps_installed=$(detect_installed_deps_summary "${name}" "${rebuild_dep_set}")
  rebuild_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  rebuild_token=$(detect_token_from_config "${data_dir}")
  print_human_summary "rebuild" "${name}" "${rebuild_version}" "${rebuild_status_text}" "${data_dir}" "${rebuild_runtime_paths}" "${rebuild_deps_installed}" "${rebuild_gateway_bind}" "${rebuild_token}" "${host_port}" "${extra_ports}"
  write_deployment_info "rebuild" "${rebuild_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${rebuild_token}" "${extra_ports}" || true
}

load_simple_config_file() {
  local file_path="$1"
  [[ -f "${file_path}" ]] || {
    log_error "配置文件不存在: ${file_path}"
    return 1
  }
  while IFS='=' read -r raw_key raw_value; do
    [[ -z "${raw_key}" ]] && continue
    [[ "${raw_key}" =~ ^# ]] && continue
    local key value
    key=$(sanitize_user_input "${raw_key}")
    value="${raw_value}"
    case "${key}" in
      SOURCE_CHOICE) SOURCE_CHOICE_CFG="${value}" ;;
      CHANNEL_CHOICE) CHANNEL_CHOICE_CFG="${value}" ;;
      IMAGE) IMAGE_CFG="${value}" ;;
      HOST_PORT) HOST_PORT_CFG="${value}" ;;
      CONTAINER_PORT) CONTAINER_PORT_CFG="${value}" ;;
      NAME) NAME_CFG="${value}" ;;
      DATA_DIR) DATA_DIR_CFG="${value}" ;;
      MODE) MODE_CFG="${value}" ;;
      BIND_CHOICE) BIND_CHOICE_CFG="${value}" ;;
      BIN_PERSIST_CHOICE) BIN_PERSIST_CHOICE_CFG="${value}" ;;
      ENV_PERSIST_CHOICE) ENV_PERSIST_CHOICE_CFG="${value}" ;;
      APT_CFG_PERSIST_CHOICE) APT_CFG_PERSIST_CHOICE_CFG="${value}" ;;
      CACHE_PERSIST_CHOICE) CACHE_PERSIST_CHOICE_CFG="${value}" ;;
      EASY_CHOICE) EASY_CHOICE_CFG="${value}" ;;
      TOKEN_MODE) TOKEN_MODE_CFG="${value}" ;;
      TOKEN_MANUAL) TOKEN_MANUAL_CFG="${value}" ;;
      OFFICIAL_TAG) OFFICIAL_TAG_CFG="${value}" ;;
      DEPS_INSTALL_CHOICE) DEPS_INSTALL_CHOICE_CFG="${value}" ;;
      TARGET_DEPS) TARGET_DEPS_CFG="${value}" ;;
      SOFTWARE_SET) SOFTWARE_SET_CFG="${value}" ;;
      SKILL_SET) SKILL_SET_CFG="${value}" ;;
      NATIVE_PREFIX) NATIVE_PREFIX_CFG="${value}" ;;
      EXTRA_PORTS) EXTRA_PORTS_CFG="${value}" ;;
    esac
  done < "${file_path}"
}

run_install_from_config_file() {
  SOURCE_CHOICE_CFG=""
  CHANNEL_CHOICE_CFG=""
  IMAGE_CFG=""
  HOST_PORT_CFG="${DEFAULT_HOST_PORT}"
  CONTAINER_PORT_CFG="${DEFAULT_CONTAINER_PORT}"
  NAME_CFG=""
  DATA_DIR_CFG=""
  BIND_CHOICE_CFG="2"
  BIN_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_BIN_PERSIST}"
  ENV_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_ENV_PERSIST}"
  APT_CFG_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_APT_CONFIG_PERSIST}"
  CACHE_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_CACHE_PERSIST}"
  EASY_CHOICE_CFG="1"
  TOKEN_MODE_CFG="1"
  TOKEN_MANUAL_CFG=""
  OFFICIAL_TAG_CFG=""
  DEPS_INSTALL_CHOICE_CFG="1"
  TARGET_DEPS_CFG="${DEFAULT_DEP_SET}"
  SOFTWARE_SET_CFG=""
  SKILL_SET_CFG=""
  EXTRA_PORTS_CFG=""

  load_simple_config_file "${CONFIG_FILE}"

  local image="${IMAGE_CFG}"
  if [[ -z "${image}" && -n "${SOURCE_CHOICE_CFG}" && -n "${CHANNEL_CHOICE_CFG}" ]]; then
    image=$(resolve_image "${SOURCE_CHOICE_CFG}" "${CHANNEL_CHOICE_CFG}" "${OFFICIAL_TAG_CFG}") || image=""
  fi
  [[ -n "${image}" ]] || {
    log_error "配置文件缺少有效镜像"
    return 1
  }
  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local software_set skill_set
  software_set=$(normalize_software_set "${SOFTWARE_SET_CFG}")
  skill_set=$(normalize_skill_set "${SKILL_SET_CFG}")
  local token
  if [[ "${TOKEN_MODE_CFG}" == "2" ]]; then
    token="${TOKEN_MANUAL_CFG}"
  else
    token=$(generate_token)
  fi
  [[ -n "${token}" ]] || {
    log_error "配置文件缺少 token"
    return 1
  }

  local extra_ports="${EXTRA_PORTS_CFG}"
  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}"); then
    return 1
  fi
  if should_enable_easyclaw_web_port "${EASY_CHOICE_CFG}" "" "${data_dir}"; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${extra_ports}")
  fi
  if token_in_list "claudecodeui" ${software_set}; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${extra_ports}")
  fi
  if [[ -n "${software_set}" && "${DEPS_INSTALL_CHOICE_CFG}" != "1" ]]; then
    DEPS_INSTALL_CHOICE_CFG="1"
  fi
  TARGET_DEPS_CFG=$(ensure_dep_set_for_software "${TARGET_DEPS_CFG}" "${software_set}")
  local gateway_bind
  gateway_bind=$(bind_choice_label "${BIND_CHOICE_CFG}")

  printf '\n--- 执行清单（确认前） ---\n'
  echo "镜像: ${image}"
  echo "容器名: ${NAME_CFG}"
  echo "端口映射: ${HOST_PORT_CFG}:${CONTAINER_PORT_CFG}"
  echo "持久化目录: ${data_dir}"
  echo "网络绑定: ${gateway_bind}"
  echo "保留命令入口（bin）: $(choice_to_yes_no "${BIN_PERSIST_CHOICE_CFG}")"
  echo "保留运行环境（env）: $(choice_to_yes_no "${ENV_PERSIST_CHOICE_CFG}")"
  echo "APT源Key 持久化: $(choice_to_yes_no "${APT_CFG_PERSIST_CHOICE_CFG}")"
  echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${CACHE_PERSIST_CHOICE_CFG}")"
  echo "EasyClaw: $(choice_to_yes_no "${EASY_CHOICE_CFG}")"
  echo "可选软件: $(software_set_summary "${software_set}")"
  echo "Skills: $(skill_set_summary "${skill_set}")"
  echo "依赖补齐: $(choice_to_yes_no "${DEPS_INSTALL_CHOICE_CFG}")"
  if [[ "${DEPS_INSTALL_CHOICE_CFG}" == "1" ]]; then
    echo "依赖清单: ${TARGET_DEPS_CFG}"
  fi
  echo "扩展端口映射: $(value_or_unset "${extra_ports}")"

  execute_install_plan "${image}" "${NAME_CFG}" "${data_dir}" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${gateway_bind}" "${token}" "${BIN_PERSIST_CHOICE_CFG}" "${ENV_PERSIST_CHOICE_CFG}" "${APT_CFG_PERSIST_CHOICE_CFG}" "${CACHE_PERSIST_CHOICE_CFG}" "${EASY_CHOICE_CFG}" "${DEPS_INSTALL_CHOICE_CFG}" "${TARGET_DEPS_CFG}" "${extra_ports}" "${software_set}" "${skill_set}"
}

run_upgrade_from_config_file() {
  SOURCE_CHOICE_CFG=""
  CHANNEL_CHOICE_CFG=""
  IMAGE_CFG=""
  HOST_PORT_CFG="${DEFAULT_HOST_PORT}"
  CONTAINER_PORT_CFG="${DEFAULT_CONTAINER_PORT}"
  NAME_CFG=""
  DATA_DIR_CFG=""
  BIN_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_BIN_PERSIST}"
  ENV_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_ENV_PERSIST}"
  APT_CFG_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_APT_CONFIG_PERSIST}"
  CACHE_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_CACHE_PERSIST}"
  EASY_CHOICE_CFG="1"
  OFFICIAL_TAG_CFG=""
  DEPS_INSTALL_CHOICE_CFG="1"
  TARGET_DEPS_CFG="${DEFAULT_DEP_SET}"
  EXTRA_PORTS_CFG=""

  load_simple_config_file "${CONFIG_FILE}"

  local image="${IMAGE_CFG}"
  if [[ -z "${image}" && -n "${SOURCE_CHOICE_CFG}" && -n "${CHANNEL_CHOICE_CFG}" ]]; then
    image=$(resolve_image "${SOURCE_CHOICE_CFG}" "${CHANNEL_CHOICE_CFG}" "${OFFICIAL_TAG_CFG}") || image=""
  fi
  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }
  [[ -n "${image}" ]] || {
    log_error "配置文件缺少有效镜像"
    return 1
  }

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local preview_extra_ports="${EXTRA_PORTS_CFG}"
  if should_enable_easyclaw_web_port "${EASY_CHOICE_CFG}" "${NAME_CFG}" "${data_dir}"; then
    preview_extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${preview_extra_ports}")
  fi
  if should_enable_claudecodeui_reserved_port "0" "${NAME_CFG}" "${data_dir}"; then
    preview_extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${preview_extra_ports}")
  fi
  printf '\n--- 执行清单（确认前） ---\n'
  echo "容器名: ${NAME_CFG}"
  echo "目标镜像: ${image}"
  echo "端口映射: ${HOST_PORT_CFG}:${CONTAINER_PORT_CFG}"
  echo "持久化目录(保留): ${data_dir}"
  echo "保留命令入口（bin）: $(choice_to_yes_no "${BIN_PERSIST_CHOICE_CFG}")"
  echo "保留运行环境（env）: $(choice_to_yes_no "${ENV_PERSIST_CHOICE_CFG}")"
  echo "APT源Key 持久化: $(choice_to_yes_no "${APT_CFG_PERSIST_CHOICE_CFG}")"
  echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${CACHE_PERSIST_CHOICE_CFG}")"
  echo "EasyClaw 检查升级: $(choice_to_yes_no "${EASY_CHOICE_CFG}")"
  echo "升级后依赖补齐: $(choice_to_yes_no "${DEPS_INSTALL_CHOICE_CFG}")"
  if [[ "${DEPS_INSTALL_CHOICE_CFG}" == "1" ]]; then
    echo "依赖清单: ${TARGET_DEPS_CFG}"
  fi
  echo "扩展端口映射: $(value_or_unset "${preview_extra_ports}")"

  execute_upgrade_plan "${NAME_CFG}" "${image}" "${data_dir}" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${BIN_PERSIST_CHOICE_CFG}" "${ENV_PERSIST_CHOICE_CFG}" "${APT_CFG_PERSIST_CHOICE_CFG}" "${CACHE_PERSIST_CHOICE_CFG}" "${EASY_CHOICE_CFG}" "${DEPS_INSTALL_CHOICE_CFG}" "${TARGET_DEPS_CFG}" "${preview_extra_ports}"
}

run_rebuild_from_config_file() {
  IMAGE_CFG=""
  HOST_PORT_CFG="${DEFAULT_HOST_PORT}"
  CONTAINER_PORT_CFG="${DEFAULT_CONTAINER_PORT}"
  NAME_CFG=""
  DATA_DIR_CFG=""
  BIN_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_BIN_PERSIST}"
  ENV_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_ENV_PERSIST}"
  APT_CFG_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_APT_CONFIG_PERSIST}"
  CACHE_PERSIST_CHOICE_CFG="${DEFAULT_ENABLE_CACHE_PERSIST}"
  DEPS_INSTALL_CHOICE_CFG="1"
  TARGET_DEPS_CFG="${DEFAULT_DEP_SET}"
  EXTRA_PORTS_CFG=""

  load_simple_config_file "${CONFIG_FILE}"

  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }
  [[ -n "${IMAGE_CFG}" ]] || {
    log_error "配置文件缺少目标镜像"
    return 1
  }

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local preview_extra_ports="${EXTRA_PORTS_CFG}"
  preview_extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${preview_extra_ports}")
  if should_enable_claudecodeui_reserved_port "0" "${NAME_CFG}" "${data_dir}"; then
    preview_extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${preview_extra_ports}")
  fi
  printf '\n--- 执行清单（确认前） ---\n'
  echo "容器名: ${NAME_CFG}"
  echo "目标镜像: ${IMAGE_CFG}"
  echo "端口映射: ${HOST_PORT_CFG}:${CONTAINER_PORT_CFG}"
  echo "持久化目录(保留): ${data_dir}"
  echo "保留命令入口（bin）: $(choice_to_yes_no "${BIN_PERSIST_CHOICE_CFG}")"
  echo "保留运行环境（env）: $(choice_to_yes_no "${ENV_PERSIST_CHOICE_CFG}")"
  echo "APT源Key 持久化: $(choice_to_yes_no "${APT_CFG_PERSIST_CHOICE_CFG}")"
  echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${CACHE_PERSIST_CHOICE_CFG}")"
  echo "重建后依赖补齐: $(choice_to_yes_no "${DEPS_INSTALL_CHOICE_CFG}")"
  if [[ "${DEPS_INSTALL_CHOICE_CFG}" == "1" ]]; then
    echo "依赖清单: ${TARGET_DEPS_CFG}"
  fi
  echo "扩展端口映射: $(value_or_unset "${preview_extra_ports}")"

  execute_rebuild_plan "${NAME_CFG}" "${IMAGE_CFG}" "${data_dir}" "${HOST_PORT_CFG}" "${CONTAINER_PORT_CFG}" "${BIN_PERSIST_CHOICE_CFG}" "${ENV_PERSIST_CHOICE_CFG}" "${APT_CFG_PERSIST_CHOICE_CFG}" "${CACHE_PERSIST_CHOICE_CFG}" "${DEPS_INSTALL_CHOICE_CFG}" "${TARGET_DEPS_CFG}" "${preview_extra_ports}"
}

execute_easyclaw_upgrade_plan() {
  local name="$1"
  local data_dir="$2"

  if ! run_preflight_checks "easyclaw-upgrade" "${name}" "${data_dir}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  local -a easy_nonfatal_issues=()
  if ! run_optional_step "EasyClaw 检查升级" check_and_upgrade_easyclaw "${name}" "${data_dir}"; then
    easy_nonfatal_issues+=("EasyClaw 检查升级失败")
  fi
  local easy_status="success"
  [[ "${#easy_nonfatal_issues[@]}" -gt 0 ]] && easy_status="success_with_warnings"
  write_last_report "easyclaw-upgrade" "${easy_status}" "${name}" "${data_dir}" "" "" "" "" "" "${easy_nonfatal_issues[@]}"
}

run_uninstall_from_config_file() {
  NAME_CFG=""
  MODE_CFG="1"
  DATA_DIR_CFG=""
  load_simple_config_file "${CONFIG_FILE}"

  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }
  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  remove_container_if_exists "${NAME_CFG}"
  if [[ "${MODE_CFG}" == "2" ]]; then
    run_cmd rm -rf "${data_dir}"
  fi
}

run_easyclaw_from_config_file() {
  NAME_CFG=""
  DATA_DIR_CFG=""
  load_simple_config_file "${CONFIG_FILE}"

  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }
  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  printf '\n--- 当前操作：升级或重装 EasyClaw ---\n'
  echo "容器名: ${NAME_CFG}"
  echo "EasyClaw 目录: $(easyclaw_target_dir "${data_dir}")"
  execute_easyclaw_upgrade_plan "${NAME_CFG}" "${data_dir}"
}

run_deps_from_config_file() {
  NAME_CFG=""
  DATA_DIR_CFG=""
  MODE_CFG="install"
  TARGET_DEPS_CFG="${DEFAULT_DEP_SET}"
  load_simple_config_file "${CONFIG_FILE}"

  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }
  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local mode="${MODE_CFG}"
  local dep_set="${TARGET_DEPS_CFG}"

  if ! run_preflight_checks "deps-manage" "${NAME_CFG}" "${data_dir}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  local -a deps_nonfatal_issues=()
  if ! run_optional_step "依赖检测流程" manage_container_runtime_deps "${NAME_CFG}" "${mode}" "${dep_set}"; then
    deps_nonfatal_issues+=("依赖检测流程失败")
  fi
  if [[ "${mode}" == "install" ]]; then
    if ! run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${dep_set}"; then
      deps_nonfatal_issues+=("依赖档案保存失败")
    fi
  fi

  local deps_status="success"
  if [[ "${#deps_nonfatal_issues[@]}" -gt 0 ]]; then
    deps_status="success_with_warnings"
    log_error "以下步骤存在告警:"
    local issue
    for issue in "${deps_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
  fi
  write_last_report "deps-manage" "${deps_status}" "${NAME_CFG}" "${data_dir}" "" "" "" "" "" "${deps_nonfatal_issues[@]}"
}

info_wizard() {
  show_deployment_info
}

native_package_for_source_choice() {
  local source_choice="$1"
  if [[ "${source_choice}" == "1" ]]; then
    echo "openclaw"
  else
    echo "@qingchencloud/openclaw-zh"
  fi
}

native_tag_for_source_choice() {
  local source_choice="$1"
  local channel_choice="$2"
  local explicit_tag="${3:-}"
  if [[ -n "${explicit_tag}" ]]; then
    echo "${explicit_tag}"
    return
  fi
  if [[ "${source_choice}" == "1" ]]; then
    if [[ "${channel_choice}" == "2" ]]; then
      echo "beta"
    else
      echo "latest"
    fi
  else
    if [[ "${channel_choice}" == "2" ]]; then
      echo "nightly"
    else
      echo "latest"
    fi
  fi
}

detect_node_major() {
  if ! command -v node >/dev/null 2>&1; then
    echo "0"
    return
  fi
  node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || echo "0"
}

execute_native_install_plan() {
  local source_choice="$1"
  local channel_choice="$2"
  local explicit_tag="$3"
  local app_name="$4"
  local data_dir="$5"
  local native_prefix="$6"

  local package_name version_tag package_ref
  package_name=$(native_package_for_source_choice "${source_choice}")
  version_tag=$(native_tag_for_source_choice "${source_choice}" "${channel_choice}" "${explicit_tag}")
  package_ref="${package_name}"
  [[ -n "${version_tag}" ]] && package_ref="${package_name}@${version_tag}"

  if [[ "${DRY_RUN}" -eq 0 ]]; then
    local major
    major=$(detect_node_major)
    if [[ "${major}" =~ ^[0-9]+$ ]] && (( major < 22 )); then
      log_error "原生 npm 模式要求 Node.js >= 22，当前版本不满足"
      return 1
    fi
    if ! command -v npm >/dev/null 2>&1; then
      log_error "未检测到 npm，无法执行原生安装"
      return 1
    fi
  fi

  run_cmd mkdir -p "${data_dir}" "${native_prefix}"
  run_cmd npm install -g --prefix "${native_prefix}" "${package_ref}"

  local native_status="success"
  write_last_report "native-install" "${native_status}" "${app_name}" "${data_dir}" "${package_ref}" "" "" "" "" ""
  printf '\n===============================\n'
  echo "原生 npm 安装结果"
  echo "==============================="
  echo "应用名：${app_name}"
  echo "包名：${package_ref}"
  echo "数据目录：${data_dir}"
  echo "安装前缀：${native_prefix}"
  echo "启动示例：PATH=${native_prefix}/bin:\$PATH OPENCLAW_HOME=${data_dir} openclaw gateway run"
  echo "==============================="
}

run_native_from_config_file() {
  SOURCE_CHOICE_CFG="2"
  CHANNEL_CHOICE_CFG="1"
  OFFICIAL_TAG_CFG=""
  NAME_CFG="openclaw_native"
  DATA_DIR_CFG=""
  NATIVE_PREFIX_CFG=""

  load_simple_config_file "${CONFIG_FILE}"

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local native_prefix="${NATIVE_PREFIX_CFG:-${data_dir}/native}"

  execute_native_install_plan "${SOURCE_CHOICE_CFG}" "${CHANNEL_CHOICE_CFG}" "${OFFICIAL_TAG_CFG}" "${NAME_CFG}" "${data_dir}" "${native_prefix}"
}

native_npm_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_from_config_file
    return
  fi

  printf '\n=== 🧪 原生 npm 安装 ===\n'
  local source_choice channel_choice explicit_tag name data_dir native_prefix
  source_choice="2"
  channel_choice="1"
  explicit_tag=""
  name="openclaw_native"
  data_dir="$(default_data_dir_for_name "${name}")"
  native_prefix="${data_dir}/native"

  echo "版本来源:"
  echo "  1) 官方 npm(openclaw)"
  echo "  2) 中文版 npm(@qingchencloud/openclaw-zh)"
  source_choice=$(read_choice_default "请选择" "${source_choice}")

  echo "版本通道:"
  if [[ "${source_choice}" == "1" ]]; then
    echo "  1) stable(latest)"
    echo "  2) beta"
  else
    echo "  1) stable(latest)"
    echo "  2) nightly"
  fi
  channel_choice=$(read_choice_default "请选择" "${channel_choice}")
  explicit_tag=$(read_with_default "可选指定 tag（留空按通道）" "${explicit_tag}")
  explicit_tag=$(trim_surrounding_spaces "${explicit_tag}")
  name=$(read_container_name "应用名（仅用于配置记录）")
  data_dir=$(read_with_default "数据目录" "${data_dir}")
  native_prefix=$(read_with_default "npm 安装前缀目录" "${native_prefix}")

  printf '\n--- 执行清单（确认前） ---\n'
  echo "来源: $(source_choice_label "${source_choice}")"
  echo "通道: $(channel_choice_label "${channel_choice}")"
  echo "指定 tag: $(value_or_unset "${explicit_tag}")"
  echo "应用名: ${name}"
  echo "数据目录: ${data_dir}"
  echo "安装前缀: ${native_prefix}"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  execute_native_install_plan "${source_choice}" "${channel_choice}" "${explicit_tag}" "${name}" "${data_dir}" "${native_prefix}"
}

default_adopt_config_path() {
  echo "${HOME}/.openclaw-installer/config.env"
}

list_adopt_candidate_containers() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "openclaw"
    return
  fi
  docker ps -a --format '{{.Names}}|{{.Image}}' 2>/dev/null | awk -F'|' 'tolower($1) ~ /claw/ || tolower($2) ~ /openclaw/ {print $1}'
}

adopt_existing_container() {
  local name="$1"
  local output_file="$2"
  local fallback_data_dir
  fallback_data_dir=$(default_data_dir_for_name "${name}")

  if [[ "${DRY_RUN}" -eq 0 ]] && ! container_exists "${name}"; then
    log_error "容器不存在，无法接管: ${name}"
    return 1
  fi

  local image data_dir ports host_port container_port source_choice channel_choice
  image=$(detect_existing_image "${name}" "")
  if [[ "${DRY_RUN}" -eq 1 && -z "${image}" ]]; then
    image=$(official_openclaw_image "latest")
  fi
  [[ -n "${image}" ]] || {
    log_error "无法识别容器镜像，接管失败"
    return 1
  }
  data_dir=$(detect_existing_data_dir "${name}" "${fallback_data_dir}")
  ports=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  host_port="${ports%%,*}"
  container_port="${ports##*,}"

  source_choice="1"
  [[ "$(image_source_kind "${image}")" == "chinese" ]] && source_choice="2"
  if [[ "${image}" == *":beta"* || "${image}" == *":main"* || "${image}" == *":nightly"* ]]; then
    channel_choice="2"
  else
    channel_choice="1"
  fi

  run_cmd mkdir -p "$(dirname "${output_file}")"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "将生成接管配置: ${output_file}"
  else
    cat > "${output_file}" <<EOF
SOURCE_CHOICE=${source_choice}
CHANNEL_CHOICE=${channel_choice}
IMAGE=${image}
NAME=${name}
DATA_DIR=${data_dir}
HOST_PORT=${host_port}
CONTAINER_PORT=${container_port}
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=${DEFAULT_DEP_SET}
EOF
  fi

  printf '\n--- 接管结果 ---\n'
  echo "容器名: ${name}"
  echo "镜像: ${image}"
  echo "数据目录: ${data_dir}"
  echo "端口: ${host_port}:${container_port}"
  echo "配置文件: ${output_file}"
  echo "后续可执行: bash openclawctl.sh --wizard upgrade --config-file ${output_file}"
  local adopt_url
  adopt_url="http://<server-ip>:${host_port}/"
  write_last_report "adopt" "success" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "${adopt_url}" ""
  write_deployment_info "adopt" "success" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "" || true
}

adopt_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    NAME_CFG=""
    load_simple_config_file "${CONFIG_FILE}"
    [[ -n "${NAME_CFG}" ]] || {
      log_error "配置文件缺少容器名(NAME)"
      return 1
    }
    adopt_existing_container "${NAME_CFG}" "$(default_adopt_config_path)"
    return
  fi

  printf '\n=== 🔄 接管外部安装实例 ===\n'
  local candidates first_candidate name output_file
  candidates=$(list_adopt_candidate_containers || true)
  first_candidate=$(printf '%s\n' "${candidates}" | head -n1)
  if [[ -n "${candidates}" ]]; then
    echo "发现候选容器:"
    printf '%s\n' "${candidates}" | sed 's/^/  - /'
  else
    echo "未自动发现候选容器，请手动输入容器名。"
  fi
  name=$(read_with_default "请输入要接管的容器名" "${first_candidate:-openclaw}")
  output_file=$(read_with_default "接管配置输出路径" "$(default_adopt_config_path)")
  adopt_existing_container "${name}" "${output_file}"
}

persist_append_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_rebuild_from_config_file
    return
  fi

  printf '\n=== 🧩 为已有容器追加 Runtime 持久化 ===\n'
  local name
  name=$(read_container_name "请输入容器名")
  local data_dir
  data_dir=$(detect_existing_data_dir "${name}" "$(default_data_dir_for_name "${name}")")
  local image
  image=$(detect_existing_image "${name}" "$(official_openclaw_image "latest")")
  local port_pair host_port container_port
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  host_port="${port_pair%%,*}"
  container_port="${port_pair##*,}"
  local extra_ports
  extra_ports=$(detect_existing_extra_ports "${name}" "${host_port}" "${container_port}")

  printf '\n--- 执行清单（确认前） ---\n'
  echo "容器名: ${name}"
  echo "镜像: ${image}"
  echo "数据目录: ${data_dir}"
  echo "端口映射: ${host_port}:${container_port}"
  echo "扩展端口映射: $(value_or_unset "${extra_ports}")"
  echo "策略: 将通过安全重建追加 bin/env/APT/cache 全量持久化"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  execute_rebuild_plan "${name}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "1" "1" "1" "1" "1" "${DEFAULT_DEP_SET}" "${extra_ports}"
}

install_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_install_from_config_file
    return
  fi
  local source_choice=""
  local channel_choice=""
  local official_tag=""
  local image=""
  local host_port
  host_port=$(find_recommended_host_port 7100 7200)
  local container_port="${DEFAULT_CONTAINER_PORT}"
  local name=""
  local data_dir=""
  local bind_choice="2"
  local bin_persist_choice="${DEFAULT_ENABLE_BIN_PERSIST}"
  local env_persist_choice="${DEFAULT_ENABLE_ENV_PERSIST}"
  local apt_cfg_persist_choice="${DEFAULT_ENABLE_APT_CONFIG_PERSIST}"
  local cache_persist_choice="${DEFAULT_ENABLE_CACHE_PERSIST}"
  local easy_choice="1"
  local token_mode="1"
  local token_manual=""
  local deps_install_choice="1"
  local target_deps="${DEFAULT_DEP_SET}"
  local software_set=""
  local skill_set=""
  local extra_ports=""

  while true; do
    clear_interactive_screen
    printf '\n=== 🚀 安装新实例 ===\n'
    echo "按编号编辑，修改后会回到这张总表；c 确认执行，q 返回主菜单"
    echo
    echo "1) 📦 版本镜像选择: $(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}" "${official_tag}")"
    echo "2) 🐳 容器名: $(value_or_unset "${name}")"
    echo "3) 💾 持久化目录管理: $(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "$(install_default_data_dir_desc "${name}")")"
    echo "4) 🌐 网络设置: $(network_group_summary "${bind_choice}" "${host_port}" "${container_port}" "${extra_ports}" "${easy_choice}")"
    echo "5) 🧩 功能加强: $(feature_group_summary "${easy_choice}" "${deps_install_choice}" "${target_deps}")"
    echo "6) 🔐 鉴权方式管理: $(auth_group_summary "${token_mode}" "${token_manual}")"
    echo "7) 🧰 可选软件: $(software_group_summary "${software_set}")"
    echo "8) 📚 Skills: $(skill_group_summary "${skill_set}")"
    echo "c) 确认并执行安装"
    echo "q) 取消并返回"

    local action
    action=$(read_menu_choice "请选择分组")
    case "${action}" in
      1)
        echo "版本来源:"
        echo "  1) 官方"
        echo "  2) 中文版"
        source_choice=$(read_choice_default "请选择" "${source_choice:-2}")
        echo "版本通道:"
        if [[ "${source_choice}" == "1" ]]; then
          echo "  1) 稳定版(latest)"
          echo "  2) 最新版(beta)"
          echo "  3) 指定版本标签（自动拉取）"
          channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
          if [[ "${channel_choice}" == "3" ]]; then
            official_tag=$(prompt_official_openclaw_tag "${official_tag:-latest}")
          else
            official_tag=""
          fi
        else
          echo "  1) 稳定版"
          echo "  2) 最新版"
          channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
          official_tag=""
        fi
        image=$(resolve_image "${source_choice}" "${channel_choice}" "${official_tag}") || image=""
        log_info "已更新：$(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}" "${official_tag}")"
        ;;
      2)
        name=$(read_container_name "Docker 容器名")
        log_info "已更新：容器名=${name}"
        ;;
      3)
        data_dir=$(read_with_default "持久化目录" "${data_dir:-$(default_data_dir_for_name "${name:-openclaw}")}")
        echo "是否启用 内容持久化（bin）:"
        echo "  1) 是"
        echo "  2) 否"
        bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
        echo "是否启用 运行环境持久化（env）:"
        echo "  1) 是"
        echo "  2) 否"
        env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
        echo "是否启用 APT源Key 持久化:"
        echo "  1) 是"
        echo "  2) 否"
        apt_cfg_persist_choice=$(read_choice_default "请选择" "${apt_cfg_persist_choice}")
        echo "是否启用 缓存持久化(.npm/go mod/cargo):"
        echo "  1) 是"
        echo "  2) 否"
        cache_persist_choice=$(read_choice_default "请选择" "${cache_persist_choice}")
        log_info "已更新：$(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "$(install_default_data_dir_desc "${name}")")"
        ;;
      4)
        echo "网络绑定:"
        echo "  1) local"
        echo "  2) lan"
        bind_choice=$(read_choice_default "请选择" "${bind_choice}")
        host_port=$(read_with_default "宿主机端口" "${host_port}")
        container_port=$(read_with_default "OpenClaw 容器内部端口" "${container_port}")
        local input_extra_ports
        input_extra_ports=$(read_with_default "扩展端口映射（逗号分隔，如 5001:5001,6000:6000/udp）" "${extra_ports}")
        input_extra_ports=$(sanitize_port_mapping_input "${input_extra_ports}")
        if [[ -z "${input_extra_ports}" ]]; then
          extra_ports=""
        elif normalized_input_extra_ports=$(normalize_extra_ports "${input_extra_ports}" "${host_port}" "${container_port}"); then
          extra_ports="${normalized_input_extra_ports}"
        else
          log_error "扩展端口映射输入无效，已保留原配置: $(display_port_mappings "${extra_ports}")"
        fi
        log_info "已更新：$(network_group_summary "${bind_choice}" "${host_port}" "${container_port}" "${extra_ports}" "${easy_choice}")"
        ;;
      5)
        echo "是否安装 EasyClaw:"
        echo "  1) 是"
        echo "  2) 否"
        easy_choice=$(read_choice_default "请选择" "${easy_choice}")
        echo "是否自动检测并补齐容器依赖:"
        echo "  1) 是（推荐）"
        echo "  2) 否"
        deps_install_choice=$(read_choice_default "请选择" "${deps_install_choice}")
        if [[ "${deps_install_choice}" == "1" ]]; then
          target_deps=$(prompt_dep_set "${target_deps}")
        fi
        log_info "已更新：$(feature_group_summary "${easy_choice}" "${deps_install_choice}" "${target_deps}")"
        ;;
      6)
        echo "Token 方式:"
        echo "  1) 自动生成"
        echo "  2) 手动输入"
        token_mode=$(read_choice_default "请选择" "${token_mode}")
        if [[ "${token_mode}" == "2" ]]; then
          token_manual=$(read_required "请输入 token")
        fi
        log_info "已更新：$(auth_group_summary "${token_mode}" "${token_manual}")"
        ;;
      7)
        local selected=""
        local choice default_choice token label
        echo "请选择可选软件（1=安装, 2=跳过）:"
        for token in ${OPTIONAL_SOFTWARE_ALL}; do
          label=$(optional_software_label "${token}")
          default_choice="2"
          token_in_list "${token}" ${software_set} && default_choice="1"
          echo "${label}:"
          echo "  1) 安装"
          echo "  2) 跳过"
          choice=$(read_choice_default "请选择" "${default_choice}")
          [[ "${choice}" == "1" ]] && selected="${selected} ${token}"
        done

        software_set=$(normalize_software_set "${selected}")
        if [[ -n "${software_set}" ]]; then
          deps_install_choice="1"
          target_deps=$(ensure_dep_set_for_software "${target_deps}" "${software_set}")
        fi
        log_info "已更新：$(software_group_summary "${software_set}")"
        ;;
      8)
        local selected_skills=""
        local skill_choice skill_default token label
        echo "请选择预装 Skills（1=安装, 2=跳过）:"
        for token in ${OPTIONAL_SKILL_ALL}; do
          label=$(optional_skill_label "${token}")
          skill_default="2"
          token_in_list "${token}" ${skill_set} && skill_default="1"
          echo "${label}:"
          echo "  1) 安装"
          echo "  2) 跳过"
          skill_choice=$(read_choice_default "请选择" "${skill_default}")
          [[ "${skill_choice}" == "1" ]] && selected_skills="${selected_skills} ${token}"
        done

        skill_set=$(normalize_skill_set "${selected_skills}")
        log_info "已更新：$(skill_group_summary "${skill_set}")"
        ;;
      c|C)
        if [[ -z "${image}" ]]; then
          log_error "请先完成“版本镜像选择”"
          continue
        fi
        if [[ -z "${name}" ]]; then
          log_error "请先填写容器名"
          continue
        fi
        if [[ -z "${data_dir}" ]]; then
          data_dir=$(default_data_dir_for_name "${name}")
        fi
        if [[ "${token_mode}" == "2" && -z "${token_manual}" ]]; then
          log_error "Token 为手动模式，请先在“鉴权方式管理”中填写 token"
          continue
        fi
        if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
          continue
        fi

        local token gateway_bind
        if [[ "${token_mode}" == "2" ]]; then
          token="${token_manual}"
        else
          token=$(generate_token)
        fi
        gateway_bind=$(bind_choice_label "${bind_choice}")

        if should_enable_easyclaw_web_port "${easy_choice}" "" "${data_dir}"; then
          extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        fi
        if token_in_list "claudecodeui" ${software_set}; then
          extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        fi
        if [[ -n "${software_set}" && "${deps_install_choice}" != "1" ]]; then
          deps_install_choice="1"
        fi
        target_deps=$(ensure_dep_set_for_software "${target_deps}" "${software_set}")
        printf '\n--- 执行清单（确认前） ---\n'
        echo "镜像: ${image}"
        echo "容器名: ${name}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录: ${data_dir}"
        echo "网络绑定: ${gateway_bind}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${cache_persist_choice}")"
        echo "EasyClaw: $(choice_to_yes_no "${easy_choice}")"
        echo "可选软件: $(software_set_summary "${software_set}")"
        echo "Skills: $(skill_set_summary "${skill_set}")"
        echo "依赖补齐: $(choice_to_yes_no "${deps_install_choice}")"
        if [[ "${deps_install_choice}" == "1" ]]; then
          echo "依赖清单: ${target_deps}"
        fi
        echo "扩展端口映射: $(value_or_unset "${extra_ports}")"
        printf '确认执行? (y/N): '
        local confirm
        IFS= read -r confirm
        if ! validate_yes_no "${confirm}"; then
          log_info "已取消"
          continue
        fi

        execute_install_plan "${image}" "${name}" "${data_dir}" "${host_port}" "${container_port}" "${gateway_bind}" "${token}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${easy_choice}" "${deps_install_choice}" "${target_deps}" "${extra_ports}" "${software_set}" "${skill_set}" || continue
        return
        ;;
      q|Q)
        log_info "已取消"
        return
        ;;
      *)
        log_error "无效选择"
        ;;
    esac
  done
}

upgrade_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_upgrade_from_config_file
    return
  fi
  printf '\n=== 🔄 升级已有实例 ===\n'
  echo "按编号编辑，修改后会回到这张总表；升级会尽量保留原有数据、挂载和运行环境"
  local name
  name=$(read_container_name "请输入要升级的容器名")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  local detected_host_port="${port_pair%%,*}"
  local detected_container_port="${port_pair##*,}"

  local source_choice=""
  local channel_choice=""
  local official_tag=""
  local image=""

  local host_port
  host_port="${detected_host_port}"

  local container_port
  container_port="${detected_container_port}"

  local data_dir
  data_dir="${detected_data_dir}"

  local bin_persist_default
  bin_persist_default=$(load_persistence_choice "${data_dir}" "BIN_PERSIST" "${DEFAULT_ENABLE_BIN_PERSIST}")
  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    bin_persist_default=$(detect_persist_choice_from_container "${name}" "bin" "${bin_persist_default}")
  fi

  local env_persist_default
  env_persist_default=$(load_persistence_choice "${data_dir}" "ENV_PERSIST" "${DEFAULT_ENABLE_ENV_PERSIST}")
  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    env_persist_default=$(detect_persist_choice_from_container "${name}" "env" "${env_persist_default}")
  fi
  local apt_cfg_persist_default
  apt_cfg_persist_default=$(load_persistence_choice "${data_dir}" "APT_CFG_PERSIST" "${DEFAULT_ENABLE_APT_CONFIG_PERSIST}")
  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    apt_cfg_persist_default=$(detect_persist_choice_from_container "${name}" "aptcfg" "${apt_cfg_persist_default}")
  fi
  local cache_persist_default
  cache_persist_default=$(load_persistence_choice "${data_dir}" "CACHE_PERSIST" "${DEFAULT_ENABLE_CACHE_PERSIST}")
  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    cache_persist_default=$(detect_persist_choice_from_container "${name}" "cache" "${cache_persist_default}")
  fi

  local bin_persist_choice
  bin_persist_choice="${bin_persist_default}"

  local env_persist_choice
  env_persist_choice="${env_persist_default}"
  local apt_cfg_persist_choice
  apt_cfg_persist_choice="${apt_cfg_persist_default}"
  local cache_persist_choice
  cache_persist_choice="${cache_persist_default}"

  local easyclaw_upgrade
  easyclaw_upgrade="1"

  local saved_dep_set
  saved_dep_set=$(load_dep_profile "${data_dir}")
  if [[ ! -f "$(deps_profile_path "${data_dir}")" ]]; then
    local detected_dep_set
    detected_dep_set=$(detect_installed_deps_in_container "${name}")
    if [[ -n "${detected_dep_set}" ]]; then
      log_info "检测到旧安装依赖清单: ${detected_dep_set}"
      saved_dep_set=$(normalize_dep_list "${saved_dep_set} ${detected_dep_set}")
    fi
  fi
  local deps_repair_choice="1"
  local upgrade_dep_set="${saved_dep_set}"
  local extra_ports
  extra_ports=$(detect_existing_extra_ports "${name}" "${host_port}" "${container_port}")

  print_upgrade_discovery_summary "${name}" "${data_dir}"

  while true; do
    clear_interactive_screen
    printf '\n=== 🔄 升级已有实例：%s ===\n' "${name}"
    echo "1) 📦 目标版本: $(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}" "${official_tag}")"
    echo "2) 💾 数据保存: $(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${data_dir}")"
    echo "3) 🌐 网络访问: $(network_group_summary_no_bind "${host_port}" "${container_port}" "${extra_ports}" "${easyclaw_upgrade}")"
    echo "4) 🧩 功能加强: $(feature_group_summary "${easyclaw_upgrade}" "${deps_repair_choice}" "${upgrade_dep_set}")"
    echo "5) 🔎 查看升级前检测摘要"
    echo "c) 确认并执行升级"
    echo "q) 取消并返回"

    local action
    action=$(read_menu_choice "请选择分组")
    case "${action}" in
      1)
        echo "目标版本来源:"
        echo "  1) 官方"
        echo "  2) 中文版"
        source_choice=$(read_choice_default "请选择" "${source_choice:-2}")
        echo "目标版本通道:"
        if [[ "${source_choice}" == "1" ]]; then
          echo "  1) 稳定版(latest)"
          echo "  2) 最新版(beta)"
          echo "  3) 指定版本标签（自动拉取）"
          channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
          if [[ "${channel_choice}" == "3" ]]; then
            official_tag=$(prompt_official_openclaw_tag "${official_tag:-latest}")
          else
            official_tag=""
          fi
        else
          echo "  1) 稳定版"
          echo "  2) 最新版"
          channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
          official_tag=""
        fi
        image=$(resolve_image "${source_choice}" "${channel_choice}" "${official_tag}") || image=""
        log_info "已更新：$(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}" "${official_tag}")"
        ;;
      2)
        data_dir=$(read_with_default "持久化目录（安全升级会复用）" "${data_dir}")
        echo "是否启用 内容持久化（bin）:"
        echo "  1) 是"
        echo "  2) 否"
        bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
        echo "是否启用 运行环境持久化（env）:"
        echo "  1) 是"
        echo "  2) 否"
        env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
        echo "是否启用 APT源Key 持久化:"
        echo "  1) 是"
        echo "  2) 否"
        apt_cfg_persist_choice=$(read_choice_default "请选择" "${apt_cfg_persist_choice}")
        echo "是否启用 缓存持久化(.npm/go mod/cargo):"
        echo "  1) 是"
        echo "  2) 否"
        cache_persist_choice=$(read_choice_default "请选择" "${cache_persist_choice}")
        log_info "已更新：$(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${data_dir}")"
        ;;
      3)
        host_port=$(read_with_default "宿主机端口" "${host_port}")
        container_port=$(read_with_default "OpenClaw 容器内部端口" "${container_port}")
        local input_extra_ports
        input_extra_ports=$(read_with_default "扩展端口映射（逗号分隔，如 5001:5001,6000:6000/udp）" "${extra_ports}")
        input_extra_ports=$(sanitize_port_mapping_input "${input_extra_ports}")
        if [[ -z "${input_extra_ports}" ]]; then
          extra_ports=""
        elif normalized_input_extra_ports=$(normalize_extra_ports "${input_extra_ports}" "${host_port}" "${container_port}"); then
          extra_ports="${normalized_input_extra_ports}"
        else
          log_error "扩展端口映射输入无效，已保留原配置: $(display_port_mappings "${extra_ports}")"
        fi
        log_info "已更新：$(network_group_summary_no_bind "${host_port}" "${container_port}" "${extra_ports}" "${easyclaw_upgrade}")"
        ;;
      4)
        echo "是否检查并升级 EasyClaw:"
        echo "  1) 是"
        echo "  2) 否"
        easyclaw_upgrade=$(read_choice_default "请选择" "${easyclaw_upgrade}")
        echo "是否在升级完成后自动补齐依赖:"
        echo "  1) 是"
        echo "  2) 否"
        deps_repair_choice=$(read_choice_default "请选择" "${deps_repair_choice}")
        if [[ "${deps_repair_choice}" == "1" ]]; then
          upgrade_dep_set=$(prompt_dep_set "${upgrade_dep_set}")
        fi
        log_info "已更新：$(feature_group_summary "${easyclaw_upgrade}" "${deps_repair_choice}" "${upgrade_dep_set}")"
        ;;
      5)
        print_upgrade_discovery_summary "${name}" "${data_dir}"
        press_enter_to_continue
        ;;
      c|C)
        if [[ -z "${image}" ]]; then
          log_error "请先完成“目标版本”设置"
          continue
        fi
        if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
          continue
        fi
        if should_enable_easyclaw_web_port "${easyclaw_upgrade}" "${name}" "${data_dir}"; then
          extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        fi
        if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
          extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        fi

        printf '\n--- 执行清单（确认前） ---\n'
        echo "容器名: ${name}"
        echo "目标镜像: ${image}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录(保留): ${data_dir}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${cache_persist_choice}")"
        echo "EasyClaw 检查升级: $(choice_to_yes_no "${easyclaw_upgrade}")"
        echo "升级后依赖补齐: $(choice_to_yes_no "${deps_repair_choice}")"
        if [[ "${deps_repair_choice}" == "1" ]]; then
          echo "依赖清单: ${upgrade_dep_set}"
        fi
        echo "扩展端口映射: $(value_or_unset "${extra_ports}")"

        local running_now
        running_now="0"
        if is_container_running "${name}"; then
          running_now="1"
          log_info "检测到容器 ${name} 正在运行，升级会中断当前任务。"
        fi

        if [[ "${running_now}" == "1" ]]; then
          printf '容器正在运行，确认执行安全升级并中断当前任务? (y/N): '
        else
          printf '确认执行安全升级? (y/N): '
        fi
        local confirm
        IFS= read -r confirm
        if ! validate_yes_no "${confirm}"; then
          log_info "已取消"
          continue
        fi

        execute_upgrade_plan "${name}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${easyclaw_upgrade}" "${deps_repair_choice}" "${upgrade_dep_set}" "${extra_ports}" || continue
        return
        ;;
      q|Q)
        log_info "已取消"
        return
        ;;
      *)
        log_error "无效选择"
        ;;
    esac
  done
}

safe_rebuild_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_rebuild_from_config_file
    return
  fi
  printf '\n=== 🛠️ 调整或重建实例 ===\n'
  echo "适用于新增端口、补持久化、调整挂载后需要安全重建容器的场景"
  local name
  name=$(read_container_name "请输入要重建的容器名")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  local detected_host_port="${port_pair%%,*}"
  local detected_container_port="${port_pair##*,}"

  local image
  image=$(detect_existing_image "${name}" "$(official_openclaw_image "latest")")

  local host_port="${detected_host_port}"
  local container_port="${detected_container_port}"
  local data_dir="${detected_data_dir}"
  local extra_ports
  extra_ports=$(detect_existing_extra_ports "${name}" "${host_port}" "${container_port}")

  local bin_persist_default env_persist_default apt_cfg_persist_default cache_persist_default
  bin_persist_default=$(load_persistence_choice "${data_dir}" "BIN_PERSIST" "${DEFAULT_ENABLE_BIN_PERSIST}")
  env_persist_default=$(load_persistence_choice "${data_dir}" "ENV_PERSIST" "${DEFAULT_ENABLE_ENV_PERSIST}")
  apt_cfg_persist_default=$(load_persistence_choice "${data_dir}" "APT_CFG_PERSIST" "${DEFAULT_ENABLE_APT_CONFIG_PERSIST}")
  cache_persist_default=$(load_persistence_choice "${data_dir}" "CACHE_PERSIST" "${DEFAULT_ENABLE_CACHE_PERSIST}")
  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    bin_persist_default=$(detect_persist_choice_from_container "${name}" "bin" "${bin_persist_default}")
    env_persist_default=$(detect_persist_choice_from_container "${name}" "env" "${env_persist_default}")
    apt_cfg_persist_default=$(detect_persist_choice_from_container "${name}" "aptcfg" "${apt_cfg_persist_default}")
    cache_persist_default=$(detect_persist_choice_from_container "${name}" "cache" "${cache_persist_default}")
  fi

  local bin_persist_choice="${bin_persist_default}"
  local env_persist_choice="${env_persist_default}"
  local apt_cfg_persist_choice="${apt_cfg_persist_default}"
  local cache_persist_choice="${cache_persist_default}"

  local saved_dep_set
  saved_dep_set=$(load_dep_profile "${data_dir}")
  if [[ ! -f "$(deps_profile_path "${data_dir}")" ]]; then
    local detected_dep_set
    detected_dep_set=$(detect_installed_deps_in_container "${name}")
    if [[ -n "${detected_dep_set}" ]]; then
      saved_dep_set=$(normalize_dep_list "${saved_dep_set} ${detected_dep_set}")
    fi
  fi
  local deps_repair_choice="1"
  local rebuild_dep_set="${saved_dep_set}"

  print_upgrade_discovery_summary "${name}" "${data_dir}"

  local -a auto_enabled=()
  if [[ "${bin_persist_choice}" != "1" ]]; then
    if container_path_has_data "${name}" "/root/.local/bin" || container_path_has_data "${name}" "/root/go/bin"; then
      bin_persist_choice="1"
      auto_enabled+=("bin")
    fi
  fi
  if [[ "${env_persist_choice}" != "1" ]]; then
    if container_path_has_data "${name}" "/usr/local/go" || \
      container_path_has_data "${name}" "/usr/local/lib/node_modules" || \
      container_path_has_data "${name}" "/root/.local/lib" || \
      container_path_has_data "${name}" "/root/.local/share/uv" || \
      container_path_has_data "${name}" "/root/.local/pipx" || \
      container_path_has_data "${name}" "/root/.local/share/pipx" || \
      container_path_has_data "${name}" "/root/.config" || \
      container_path_has_data "${name}" "/root/.ssh" || \
      container_path_has_data "${name}" "/root/.gitconfig" || \
      container_path_has_data "${name}" "/root/.docker" || \
      container_path_has_data "${name}" "/root/.aws" || \
      container_path_has_data "${name}" "/root/.kube" || \
      container_path_has_data "${name}" "/root/.netrc" || \
      container_path_has_data "${name}" "/root/.npmrc" || \
      container_path_has_data "${name}" "/root/.pypirc"; then
      env_persist_choice="1"
      auto_enabled+=("env")
    fi
  fi
  if [[ "${apt_cfg_persist_choice}" != "1" ]]; then
    if container_path_has_data "${name}" "/etc/apt/sources.list.d" || container_path_has_data "${name}" "/etc/apt/keyrings"; then
      apt_cfg_persist_choice="1"
      auto_enabled+=("aptcfg")
    fi
  fi
  if [[ "${cache_persist_choice}" != "1" ]]; then
    if container_path_has_data "${name}" "/root/.npm" || container_path_has_data "${name}" "/root/go/pkg/mod"; then
      cache_persist_choice="1"
      auto_enabled+=("cache")
    fi
  fi
  if [[ "${#auto_enabled[@]}" -gt 0 ]]; then
    log_info "已根据环境检测自动开启未持久化项: ${auto_enabled[*]}"
  fi

  while true; do
    clear_interactive_screen
    printf '\n=== 🛠️ 调整或重建实例：%s ===\n' "${name}"
    echo "1) 🐳 实例信息: 容器=${name} | 镜像=${image}"
    echo "2) 💾 数据保存: $(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${data_dir}")"
    echo "3) 🌐 网络访问: $(network_group_summary_no_bind "${host_port}" "${container_port}" "${extra_ports}" "1")"
    echo "4) 🧩 功能加强: $(if [[ "${deps_repair_choice}" == "1" ]]; then echo "依赖补齐=是 | $(deps_summary_line "${rebuild_dep_set}")"; else echo "依赖补齐=否"; fi)"
    echo "5) 🔎 查看重建前检测摘要"
    echo "c) 确认并执行重建"
    echo "q) 取消并返回"

    local action
    action=$(read_menu_choice "请选择分组")
    case "${action}" in
      1)
        image=$(read_with_default "目标镜像（默认复用当前容器镜像）" "${image}")
        log_info "已更新：镜像=${image}"
        ;;
      2)
        data_dir=$(read_with_default "持久化目录（重建会复用）" "${data_dir}")
        echo "是否启用 内容持久化（bin）:"
        echo "  1) 是"
        echo "  2) 否"
        bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
        echo "是否启用 运行环境持久化（env）:"
        echo "  1) 是"
        echo "  2) 否"
        env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
        echo "是否启用 APT源Key 持久化:"
        echo "  1) 是"
        echo "  2) 否"
        apt_cfg_persist_choice=$(read_choice_default "请选择" "${apt_cfg_persist_choice}")
        echo "是否启用 缓存持久化(.npm/go mod/cargo):"
        echo "  1) 是"
        echo "  2) 否"
        cache_persist_choice=$(read_choice_default "请选择" "${cache_persist_choice}")
        log_info "已更新：$(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${data_dir}")"
        ;;
      3)
        host_port=$(read_with_default "宿主机端口" "${host_port}")
        container_port=$(read_with_default "OpenClaw 容器内部端口" "${container_port}")
        local input_extra_ports
        input_extra_ports=$(read_with_default "扩展端口映射（逗号分隔，如 5001:5001,6000:6000/udp）" "${extra_ports}")
        input_extra_ports=$(sanitize_port_mapping_input "${input_extra_ports}")
        if [[ -z "${input_extra_ports}" ]]; then
          extra_ports=""
        elif normalized_input_extra_ports=$(normalize_extra_ports "${input_extra_ports}" "${host_port}" "${container_port}"); then
          extra_ports="${normalized_input_extra_ports}"
        else
          log_error "扩展端口映射输入无效，已保留原配置: $(display_port_mappings "${extra_ports}")"
        fi
        log_info "已更新：$(network_group_summary_no_bind "${host_port}" "${container_port}" "${extra_ports}" "1")"
        ;;
      4)
        echo "是否在重建完成后自动补齐依赖:"
        echo "  1) 是"
        echo "  2) 否"
        deps_repair_choice=$(read_choice_default "请选择" "${deps_repair_choice}")
        if [[ "${deps_repair_choice}" == "1" ]]; then
          rebuild_dep_set=$(prompt_dep_set "${rebuild_dep_set}")
        fi
        log_info "已更新：$(if [[ "${deps_repair_choice}" == "1" ]]; then echo "依赖补齐=是 | $(deps_summary_line "${rebuild_dep_set}")"; else echo "依赖补齐=否"; fi)"
        ;;
      5)
        print_upgrade_discovery_summary "${name}" "${data_dir}"
        press_enter_to_continue
        ;;
      c|C)
        if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
          continue
        fi
        extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
          extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
        fi
        printf '\n--- 执行清单（确认前） ---\n'
        echo "容器名: ${name}"
        echo "目标镜像: ${image}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录(保留): ${data_dir}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${cache_persist_choice}")"
        echo "重建后依赖补齐: $(choice_to_yes_no "${deps_repair_choice}")"
        if [[ "${deps_repair_choice}" == "1" ]]; then
          echo "依赖清单: ${rebuild_dep_set}"
        fi
        echo "扩展端口映射: $(value_or_unset "${extra_ports}")"

        if is_container_running "${name}"; then
          log_info "检测到容器 ${name} 正在运行，重建会中断当前任务。"
          printf '容器正在运行，确认执行安全重建并中断当前任务? (y/N): '
        else
          printf '确认执行安全重建? (y/N): '
        fi
        local confirm
        IFS= read -r confirm
        if ! validate_yes_no "${confirm}"; then
          log_info "已取消"
          continue
        fi

        execute_rebuild_plan "${name}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${deps_repair_choice}" "${rebuild_dep_set}" "${extra_ports}" || continue
        return
        ;;
      q|Q)
        log_info "已取消"
        return
        ;;
      *)
        log_error "无效选择"
        ;;
    esac
  done
}

uninstall_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_uninstall_from_config_file
    return
  fi
  printf '\n=== 🗑️ 卸载实例 ===\n'
  echo "流程：选择卸载方式 -> 二次确认容器名 -> 执行"
  local name
  name=$(read_container_name "请输入要卸载的容器名")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  echo "卸载模式:"
  echo "  1) 安全卸载（仅删容器，保留持久化目录）"
  echo "  2) 完整卸载（删容器 + 删持久化目录）"
  local mode
  mode=$(read_choice_default "请选择" "1")

  echo "提示：直接回车使用默认持久化目录；如需修改请输入完整绝对路径。"
  local data_dir
  data_dir=$(read_with_default "持久化目录" "${detected_data_dir}")

  printf '\n二次确认：请输入容器名 %s\n' "${name}"
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

easyclaw_only_upgrade_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_easyclaw_from_config_file
    return
  fi
  printf '\n=== 📦 管理 EasyClaw 工具 ===\n'
  local name
  name=$(read_container_name "请输入容器名（用于定位持久化目录）")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local data_dir
  data_dir=$(read_with_default "EasyClaw 所在持久化目录" "${detected_data_dir}")

  printf '\n--- 当前操作：升级或重装 EasyClaw ---\n'
  echo "容器名: ${name}"
  echo "EasyClaw 目录: $(easyclaw_target_dir "${data_dir}")"
  printf '确认执行 EasyClaw 升级/重装? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  execute_easyclaw_upgrade_plan "${name}" "${data_dir}"
}

deps_manage_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_deps_from_config_file
    return
  fi
  printf '\n=== 🔧 检查或补齐运行环境 ===\n'
  echo "提示：用于单独检查或补齐容器依赖，不重建 OpenClaw 容器。"
  local name
  name=$(read_container_name "请输入容器名")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")
  local data_dir
  data_dir=$(read_with_default "持久化目录（用于读取/保存依赖档案）" "${detected_data_dir}")

  echo "执行模式:"
  echo "  1) 检测并安装缺失项（推荐）"
  echo "  2) 仅检测，不安装"
  local mode_choice
  mode_choice=$(read_choice_default "请选择" "1")
  local mode="install"
  if [[ "${mode_choice}" == "2" ]]; then
    mode="check"
  fi

  local saved_dep_set
  saved_dep_set=$(load_dep_profile "${data_dir}")
  local dep_set
  dep_set=$(prompt_dep_set "${saved_dep_set}")

  printf '确认执行依赖检测流程? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  if ! run_preflight_checks "deps-manage" "${name}" "${data_dir}"; then
    log_error "preflight 未通过，请修复后重试"
    return
  fi

  local -a deps_nonfatal_issues=()
  if ! run_optional_step "依赖检测流程" manage_container_runtime_deps "${name}" "${mode}" "${dep_set}"; then
    deps_nonfatal_issues+=("依赖检测流程失败")
  fi
  if [[ "${mode}" == "install" ]]; then
    if ! run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${dep_set}"; then
      deps_nonfatal_issues+=("依赖档案保存失败")
    fi
  fi

  local deps_status="success"
  if [[ "${#deps_nonfatal_issues[@]}" -gt 0 ]]; then
    deps_status="success_with_warnings"
    log_error "以下步骤存在告警:"
    local issue
    for issue in "${deps_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
  fi
  write_last_report "deps-manage" "${deps_status}" "${name}" "${data_dir}" "" "" "" "" "" "${deps_nonfatal_issues[@]}"
}

show_main_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " OpenClaw 部署助手"
  echo "==============================="
  echo "1) 🚀 安装新实例"
  echo "2) 🔄 升级已有实例"
  echo "3) 🛠️ 调整或重建实例"
  echo "4) 📦 管理 EasyClaw 工具"
  echo "5) 🔧 检查或补齐运行环境"
  echo "6) 🗑️ 卸载实例"
  echo "7) 🔄 接管外部安装实例"
  echo "8) 🧩 追加 Runtime 持久化"
  echo "9) 🧪 原生 npm 安装"
  echo "10) 📄 查看部署信息"
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
      3) safe_rebuild_wizard ;;
      4) easyclaw_only_upgrade_wizard ;;
      5) deps_manage_wizard ;;
      6) uninstall_wizard ;;
      7) adopt_wizard ;;
      8) persist_append_wizard ;;
      9) native_npm_wizard ;;
      10) info_wizard ;;
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
  local positional_wizard_set=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config-file)
        if [[ $# -lt 2 ]]; then
          log_error "--config-file 需要一个文件路径"
          exit 1
        fi
        CONFIG_FILE="$2"
        shift 2
        ;;
      --wizard)
        if [[ $# -lt 2 ]]; then
          log_error "--wizard 需要一个值"
          exit 1
        fi
        SELECTED_WIZARD="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --help|-h)
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|info] [--config-file path]"
        echo "或:   bash openclawctl.sh info --dry-run"
        echo "严格非交互模式: OPENCLAWCTL_STRICT_NONINTERACTIVE=1（要求同时传入 --wizard 与 --config-file）"
        echo "默认进入交互式菜单。"
        exit 0
        ;;
      *)
        if [[ "${positional_wizard_set}" -eq 0 && -z "${SELECTED_WIZARD}" ]]; then
          case "$1" in
            install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|info)
              SELECTED_WIZARD="$1"
              positional_wizard_set=1
              shift
              continue
              ;;
          esac
        fi
        log_error "未知参数: $1"
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|info] [--config-file path]"
        exit 1
        ;;
    esac
  done
}

run_selected_wizard() {
  case "${SELECTED_WIZARD}" in
    install) install_wizard ;;
    upgrade) upgrade_wizard ;;
    rebuild) safe_rebuild_wizard ;;
    easyclaw) easyclaw_only_upgrade_wizard ;;
    deps) deps_manage_wizard ;;
    uninstall) uninstall_wizard ;;
    adopt) adopt_wizard ;;
    persist) persist_append_wizard ;;
    native) native_npm_wizard ;;
    info) info_wizard ;;
    *)
      log_error "无效的 wizard: ${SELECTED_WIZARD}"
      exit 1
      ;;
  esac
}

load_optional_component_catalog
parse_global_flags "$@"
enforce_strict_noninteractive_mode
maybe_exec_tui "$@" || true
if [[ -n "${SELECTED_WIZARD}" ]]; then
  run_selected_wizard
  exit 0
fi
main_loop
