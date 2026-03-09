#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DRY_RUN=0
DEFAULT_HOST_PORT="4113"
DEFAULT_CONTAINER_PORT="18789"
DEFAULT_RESTART_POLICY="unless-stopped"
CLAWPANEL_NPM_PACKAGE="@milkkey/clawpanel"
EASYCLAW_DEFAULT_WEB_PORT="4231"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_1="7201"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_2="7202"
CLAUDECODEUI_RESERVED_CONTAINER_PORT_3="7203"
CLAUDECODEUI_NPM_PACKAGE="@siteboon/claude-code-ui"
TASKMASTER_NPM_PACKAGE="task-master-ai"
DEFAULT_DEP_SET="npm uv"
DEFAULT_ENABLE_BIN_PERSIST="2"
DEFAULT_ENABLE_ENV_PERSIST="2"
DEFAULT_ENABLE_APT_CONFIG_PERSIST="2"
DEFAULT_ENABLE_CACHE_PERSIST="2"
OFFICIAL_OPENCLAW_REPO_DEFAULT="1panel/openclaw"
OPENCLAWCTL_TUI_BIN="${OPENCLAWCTL_TUI_BIN:-}"
OPENCLAWCTL_1PANEL_LAST_OUTPUT=""
SELECTED_WIZARD=""
CONFIG_FILE=""
OPTIONAL_COMPONENTS_FILE="${OPENCLAWCTL_COMPONENTS_FILE:-${SCRIPT_DIR}/config/optional-components.conf}"
DEFAULT_OPTIONAL_SOFTWARE_ALL="gh claude codex opencode gemini notebooklm clawpanel claudecodeui obsidian ralph"
DEFAULT_OPTIONAL_SKILL_ALL="obsidian-skills security-checker"
OPTIONAL_SOFTWARE_ALL="${DEFAULT_OPTIONAL_SOFTWARE_ALL}"
OPTIONAL_SKILL_ALL="${DEFAULT_OPTIONAL_SKILL_ALL}"
OPTIONAL_SOFTWARE_CATALOG=""
OPTIONAL_SKILL_CATALOG=""

source "${SCRIPT_DIR}/lib/openclawctl/bootstrap.sh"
source "${SCRIPT_DIR}/lib/openclawctl/common.sh"
source "${SCRIPT_DIR}/lib/openclawctl/hostdeps.sh"
source "${SCRIPT_DIR}/lib/openclawctl/io.sh"
source "${SCRIPT_DIR}/lib/openclawctl/image.sh"
source "${SCRIPT_DIR}/lib/openclawctl/persist.sh"
source "${SCRIPT_DIR}/lib/openclawctl/components.sh"
source "${SCRIPT_DIR}/lib/openclawctl/deps.sh"
source "${SCRIPT_DIR}/lib/openclawctl/panel.sh"
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
  if [[ -n "${OPENCLAWCTL_TEST_HOST_PLATFORM:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_PLATFORM}"
    return
  fi
  local os
  os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
  case "${os}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    *) echo "unknown" ;;
  esac
}

has_docker_command() {
  if [[ "${OPENCLAWCTL_TEST_FORCE_DOCKER_MISSING:-0}" == "1" ]]; then
    return 1
  fi
  command -v docker >/dev/null 2>&1
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

instance_core_dir() {
  local data_dir="$1"
  printf '%s/.openclaw\n' "${data_dir}"
}

instance_runtime_dir() {
  local data_dir="$1"
  printf '%s/runtime\n' "${data_dir}"
}

instance_config_dir() {
  local data_dir="$1"
  printf '%s/config\n' "${data_dir}"
}

instance_software_dir() {
  local data_dir="$1"
  printf '%s/software\n' "${data_dir}"
}

layout_profile_path() {
  local data_dir="$1"
  printf '%s/layout.profile\n' "$(instance_runtime_dir "${data_dir}")"
}

save_layout_profile() {
  local data_dir="$1"
  local layout_version="${2:-2}"
  local mode="${3:-structured}"
  local profile
  profile=$(layout_profile_path "${data_dir}")
  run_cmd mkdir -p "$(instance_runtime_dir "${data_dir}")"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "布局档案将保存到: ${profile}"
    return 0
  fi
  cat > "${profile}" <<EOF
LAYOUT_VERSION=${layout_version}
MODE=${mode}
CORE_DIR=.openclaw
UPDATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
}

detect_data_layout_version() {
  local data_dir="$1"
  local profile core_dir
  core_dir=$(instance_core_dir "${data_dir}")
  profile=$(layout_profile_path "${data_dir}")

  if [[ -f "${profile}" ]]; then
    local version
    version=$(awk -F '=' '$1=="LAYOUT_VERSION"{print $2}' "${profile}" | tail -n1 | tr -d '[:space:]')
    if [[ "${version}" == "2" ]]; then
      printf '2\n'
      return 0
    fi
  fi

  if [[ -f "${core_dir}/openclaw.json" || -d "${core_dir}/backups" || -d "${core_dir}/workspace" ]]; then
    printf '2\n'
    return 0
  fi

  if [[ -f "${data_dir}/openclaw.json" || -d "${data_dir}/backups" || -d "${data_dir}/workspace" ]]; then
    printf '1\n'
    return 0
  fi

  printf '0\n'
}

openclaw_data_mount_dir() {
  local data_dir="$1"
  local layout_version
  layout_version=$(detect_data_layout_version "${data_dir}")
  if [[ "${layout_version}" == "1" ]]; then
    printf '%s\n' "${data_dir}"
  else
    printf '%s\n' "$(instance_core_dir "${data_dir}")"
  fi
}

openclaw_config_file_path() {
  local data_dir="$1"
  local core_cfg legacy_cfg
  core_cfg="$(instance_core_dir "${data_dir}")/openclaw.json"
  legacy_cfg="${data_dir}/openclaw.json"
  if [[ -f "${core_cfg}" ]]; then
    printf '%s\n' "${core_cfg}"
  elif [[ -f "${legacy_cfg}" ]]; then
    printf '%s\n' "${legacy_cfg}"
  else
    printf '%s\n' "${core_cfg}"
  fi
}

normalize_data_dir_from_mount_source() {
  local source="$1"
  local normalized
  normalized=$(trim_surrounding_spaces "${source}")
  if [[ "${normalized}" == */.openclaw ]]; then
    printf '%s\n' "${normalized%/.openclaw}"
    return 0
  fi
  printf '%s\n' "${normalized}"
}

prepare_structured_layout() {
  local data_dir="$1"
  local stage="${2:-prepare}"
  local core_dir
  core_dir=$(instance_core_dir "${data_dir}")

  run_cmd mkdir -p "${data_dir}" "$(instance_runtime_dir "${data_dir}")" "$(instance_config_dir "${data_dir}")" "$(instance_software_dir "${data_dir}")"

  local layout_version
  layout_version=$(detect_data_layout_version "${data_dir}")
  if [[ "${layout_version}" == "2" ]]; then
    run_cmd mkdir -p "${core_dir}"
    save_layout_profile "${data_dir}" "2" "structured"
    return 0
  fi

  if [[ "${layout_version}" == "0" ]]; then
    run_cmd mkdir -p "${core_dir}"
    save_layout_profile "${data_dir}" "2" "fresh-structured"
    return 0
  fi

  log_info "[layout] 检测到旧目录结构，准备迁移到: ${core_dir}"
  run_cmd mkdir -p "${core_dir}"

  local entry base
  local old_dotglob old_nullglob
  old_dotglob=$(shopt -p dotglob || true)
  old_nullglob=$(shopt -p nullglob || true)
  shopt -s dotglob nullglob
  for entry in "${data_dir}"/*; do
    [[ -e "${entry}" ]] || continue
    base=$(basename "${entry}")
    case "${base}" in
      "."|".."|".openclaw"|"runtime"|"config"|"software")
        continue
        ;;
    esac
    run_cmd mv "${entry}" "${core_dir}/${base}"
  done
  eval "${old_dotglob}"
  eval "${old_nullglob}"

  save_layout_profile "${data_dir}" "2" "${stage}-migrated-from-legacy"
  log_info "[layout] 目录结构迁移完成: ${data_dir} -> ${core_dir}"
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

enhanced_tui_enabled() {
  return 1
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

announce_startup_progress() {
  if ! is_interactive_session; then
    return 0
  fi

  log_info "系统环境检测中用于匹配功能..."
  if [[ "${OPENCLAWCTL_FORCE_SHELL:-0}" == "1" ]]; then
    return 0
  fi
  if ! enhanced_tui_enabled; then
    return 0
  fi
  log_info "正在构建TUI菜单中，即将呈现..."
}

is_tui_binary_up_to_date() {
  local root_dir="$1"
  local output_bin="$2"
  local go_mod="$3"
  local go_sum="$4"

  [[ -x "${output_bin}" && -f "${go_mod}" ]] || return 1
  [[ "${output_bin}" -nt "${go_mod}" ]] || return 1
  if [[ -f "${go_sum}" && "${output_bin}" -ot "${go_sum}" ]]; then
    return 1
  fi

  local newer_go_source=""
  newer_go_source=$(find "${root_dir}/cmd" "${root_dir}/internal" -type f -name '*.go' -newer "${output_bin}" -print -quit 2>/dev/null || true)
  [[ -z "${newer_go_source}" ]]
}

resolve_tui_binary() {
  if [[ -n "${OPENCLAWCTL_TUI_BIN}" && -x "${OPENCLAWCTL_TUI_BIN}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TUI_BIN}"
    return 0
  fi
  local root_dir
  root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  local built_tui_bin
  if built_tui_bin=$(build_tui_binary_if_possible "${root_dir}"); then
    printf '%s\n' "${built_tui_bin}"
    return 0
  fi

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
  return 1
}

build_tui_binary_if_possible() {
  local root_dir="$1"
  local source_file="${root_dir}/cmd/openclawctl/main.go"
  local output_bin="${root_dir}/.bin/openclawctl"
  local go_mod="${root_dir}/go.mod"
  local go_sum="${root_dir}/go.sum"

  [[ -f "${source_file}" && -f "${go_mod}" ]] || return 1
  if is_tui_binary_up_to_date "${root_dir}" "${output_bin}" "${go_mod}" "${go_sum}"; then
    printf '%s\n' "${output_bin}"
    return 0
  fi

  if [[ "${OPENCLAWCTL_DISABLE_TUI_BUILD:-0}" == "1" ]]; then
    return 1
  fi
  command -v go >/dev/null 2>&1 || return 1

  mkdir -p "${root_dir}/.bin" "${root_dir}/.gocache" "${root_dir}/.gomodcache"
  if GOCACHE="${root_dir}/.gocache" GOMODCACHE="${root_dir}/.gomodcache" GOTOOLCHAIN=auto go build -o "${output_bin}" "${root_dir}/cmd/openclawctl" >/dev/null 2>&1; then
    printf '%s\n' "${output_bin}"
    return 0
  fi
  return 1
}

maybe_exec_tui() {
  return 1
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

  local mount_dir
  mount_dir=$(openclaw_data_mount_dir "${data_dir}")

  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw setup
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set gateway.mode local
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set gateway.port "${container_port}"
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set gateway.bind "${gateway_bind}"
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.mode token
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set gateway.auth.token "${token}"
}

run_openclaw_doctor_fix() {
  local image="$1"
  local data_dir="$2"
  local mount_dir
  mount_dir=$(openclaw_data_mount_dir "${data_dir}")
  run_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw doctor --fix
}

run_openclaw_config_set_compat() {
  local image="$1"
  local data_dir="$2"
  local key="$3"
  local value="$4"
  local mount_dir
  mount_dir=$(openclaw_data_mount_dir "${data_dir}")

  print_cmd docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set "${key}" "${value}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi

  local output rc
  set +e
  output=$(docker run --rm --user root -v "${mount_dir}:/root/.openclaw" "${image}" openclaw config set "${key}" "${value}" 2>&1)
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
  local core_dir software_dir
  core_dir=$(instance_core_dir "${data_dir}")
  software_dir=$(instance_software_dir "${data_dir}")

  run_cmd mkdir -p "${core_dir}" "${software_dir}"
  volume_args+=("-v" "${software_dir}:/root/.openclaw/software")

  if [[ "${enable_bin_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/root-local-bin" "${data_dir}/runtime/root-go-bin" "${data_dir}/runtime/root-cargo-bin"
    volume_args+=("-v" "${data_dir}/runtime/root-local-bin:/root/.local/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-go-bin:/root/go/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-cargo-bin:/root/.cargo/bin")
  fi

  if [[ "${enable_bin_persist}" == "1" || "${enable_env_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/path-shims" "${data_dir}/runtime/path-decls"
    run_cmd touch "${data_dir}/runtime/path-decls/openclaw-runtime-path.sh"
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
    -v "${core_dir}:/root/.openclaw" \
    "${volume_args[@]}" \
    --add-host=host.docker.internal:host-gateway \
    "${image}" \
    openclaw gateway run
}

compose_yaml_escape() {
  local raw="${1:-}"
  printf '%s' "${raw}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

compose_export_default_path() {
  local data_dir="$1"
  printf '%s\n' "${data_dir}/runtime/docker-compose.generated.yml"
}

compose_detect_persistence_defaults() {
  local name="$1"
  local data_dir="$2"

  local bin_choice env_choice apt_cfg_choice cache_choice
  bin_choice=$(load_persistence_choice "${data_dir}" "BIN_PERSIST" "${DEFAULT_ENABLE_BIN_PERSIST}")
  env_choice=$(load_persistence_choice "${data_dir}" "ENV_PERSIST" "${DEFAULT_ENABLE_ENV_PERSIST}")
  apt_cfg_choice=$(load_persistence_choice "${data_dir}" "APT_CFG_PERSIST" "${DEFAULT_ENABLE_APT_CONFIG_PERSIST}")
  cache_choice=$(load_persistence_choice "${data_dir}" "CACHE_PERSIST" "${DEFAULT_ENABLE_CACHE_PERSIST}")

  if [[ ! -f "$(persistence_profile_path "${data_dir}")" ]]; then
    bin_choice=$(detect_persist_choice_from_container "${name}" "bin" "${bin_choice}")
    env_choice=$(detect_persist_choice_from_container "${name}" "env" "${env_choice}")
    apt_cfg_choice=$(detect_persist_choice_from_container "${name}" "aptcfg" "${apt_cfg_choice}")
    cache_choice=$(detect_persist_choice_from_container "${name}" "cache" "${cache_choice}")
  fi

  printf '%s,%s,%s,%s\n' "${bin_choice}" "${env_choice}" "${apt_cfg_choice}" "${cache_choice}"
}

compose_collect_port_mappings() {
  local host_port="$1"
  local container_port="$2"
  local extra_ports="${3:-}"
  local mapping

  printf '%s\n' "${host_port}:${container_port}"
  for mapping in ${extra_ports}; do
    [[ -n "${mapping}" ]] || continue
    printf '%s\n' "${mapping}"
  done
}

compose_collect_volume_mappings() {
  local image="$1"
  local data_dir="$2"
  local enable_bin_persist="$3"
  local enable_env_persist="$4"
  local enable_apt_cfg_persist="$5"
  local enable_cache_persist="$6"

  printf '%s\n' "$(instance_core_dir "${data_dir}"):/root/.openclaw"
  printf '%s\n' "$(instance_software_dir "${data_dir}"):/root/.openclaw/software"

  if [[ "${enable_bin_persist}" == "1" ]]; then
    printf '%s\n' "${data_dir}/runtime/root-local-bin:/root/.local/bin"
    printf '%s\n' "${data_dir}/runtime/root-go-bin:/root/go/bin"
    printf '%s\n' "${data_dir}/runtime/root-cargo-bin:/root/.cargo/bin"
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    printf '%s\n' "${data_dir}/runtime/usr-local-go:/usr/local/go"
    if should_persist_node_modules_mount "${image}"; then
      printf '%s\n' "${data_dir}/runtime/usr-local-lib-node-modules:/usr/local/lib/node_modules"
    fi
    printf '%s\n' "${data_dir}/runtime/root-local-lib:/root/.local/lib"
    printf '%s\n' "${data_dir}/runtime/root-local-share-uv:/root/.local/share/uv"
    printf '%s\n' "${data_dir}/runtime/root-local-pipx:/root/.local/pipx"
    printf '%s\n' "${data_dir}/runtime/root-local-share-pipx:/root/.local/share/pipx"
    printf '%s\n' "${data_dir}/runtime/root-rustup:/root/.rustup"
    printf '%s\n' "${data_dir}/runtime/root-config:/root/.config"
    printf '%s\n' "${data_dir}/runtime/root-ssh:/root/.ssh"
    printf '%s\n' "${data_dir}/runtime/root-gitconfig:/root/.gitconfig"
    printf '%s\n' "${data_dir}/runtime/root-docker:/root/.docker"
    printf '%s\n' "${data_dir}/runtime/root-aws:/root/.aws"
    printf '%s\n' "${data_dir}/runtime/root-kube:/root/.kube"
    printf '%s\n' "${data_dir}/runtime/root-netrc:/root/.netrc"
    printf '%s\n' "${data_dir}/runtime/root-npmrc:/root/.npmrc"
    printf '%s\n' "${data_dir}/runtime/root-pypirc:/root/.pypirc"
  fi

  if [[ "${enable_apt_cfg_persist}" == "1" ]]; then
    printf '%s\n' "${data_dir}/runtime/etc-apt-sources-list-d:/etc/apt/sources.list.d"
    printf '%s\n' "${data_dir}/runtime/etc-apt-keyrings:/etc/apt/keyrings"
  fi

  if [[ "${enable_cache_persist}" == "1" ]]; then
    printf '%s\n' "${data_dir}/runtime/root-npm-cache:/root/.npm"
    printf '%s\n' "${data_dir}/runtime/root-go-pkg-mod:/root/go/pkg/mod"
    printf '%s\n' "${data_dir}/runtime/root-cargo-registry:/root/.cargo/registry"
    printf '%s\n' "${data_dir}/runtime/root-cargo-git:/root/.cargo/git"
  fi
}

render_openclaw_compose_yaml() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local extra_ports="$6"
  local enable_bin_persist="$7"
  local enable_env_persist="$8"
  local enable_apt_cfg_persist="$9"
  local enable_cache_persist="${10}"

  local -a port_lines=()
  local -a volume_lines=()
  local mapping

  while IFS= read -r mapping; do
    [[ -n "${mapping}" ]] || continue
    port_lines+=("      - \"$(compose_yaml_escape "${mapping}")\"")
  done < <(compose_collect_port_mappings "${host_port}" "${container_port}" "${extra_ports}")

  while IFS= read -r mapping; do
    [[ -n "${mapping}" ]] || continue
    volume_lines+=("      - \"$(compose_yaml_escape "${mapping}")\"")
  done < <(compose_collect_volume_mappings "${image}" "${data_dir}" "${enable_bin_persist}" "${enable_env_persist}" "${enable_apt_cfg_persist}" "${enable_cache_persist}")

  cat <<EOF
version: "3.9"
services:
  openclaw:
    container_name: $(compose_yaml_escape "${name}")
    image: $(compose_yaml_escape "${image}")
    user: "root"
    restart: "$(compose_yaml_escape "${DEFAULT_RESTART_POLICY}")"
    command: ["openclaw", "gateway", "run"]
    extra_hosts:
      - "host.docker.internal:host-gateway"
    ports:
$(printf '%s\n' "${port_lines[@]}")
    volumes:
$(printf '%s\n' "${volume_lines[@]}")
EOF
}

export_openclaw_compose_file() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local extra_ports="$6"
  local enable_bin_persist="$7"
  local enable_env_persist="$8"
  local enable_apt_cfg_persist="$9"
  local enable_cache_persist="${10}"
  local output_file="${11}"
  local compose_yaml

  compose_yaml=$(render_openclaw_compose_yaml "${name}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "${extra_ports}" "${enable_bin_persist}" "${enable_env_persist}" "${enable_apt_cfg_persist}" "${enable_cache_persist}")
  run_cmd mkdir -p "$(dirname "${output_file}")"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "Compose 文件(预览)将写入: ${output_file}"
    echo
    echo "===== docker-compose.yml (preview) ====="
    printf '%s\n' "${compose_yaml}"
    echo "======================================="
    log_info "仅导出 compose 文件，不会执行 docker compose up/down"
    log_info "后续可手动校验: docker compose -f ${output_file} config"
    return 0
  fi

  printf '%s\n' "${compose_yaml}" > "${output_file}"
  log_info "Compose 文件已导出: ${output_file}"
  log_info "仅导出 compose 文件，不会执行 docker compose up/down"
  log_info "可手动执行: docker compose -f ${output_file} config"
}

easyclaw_target_dir() {
  local data_dir="$1"
  echo "${data_dir}/software/clawpanel"
}

easyclaw_container_install_dir() {
  echo "/root/.openclaw/software/clawpanel"
}

run_easyclaw_install_script() {
  local container_name="$1"
  local script='set -e
need_npm=0
if ! command -v npm >/dev/null 2>&1; then
  need_npm=1
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
if [ "$need_npm" -eq 1 ]; then
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y nodejs npm
      ;;
    apk)
      apk add --no-cache nodejs npm
      ;;
    dnf)
      dnf install -y nodejs npm
      ;;
    yum)
      yum install -y nodejs npm
      ;;
    *)
      echo "[clawpanel] no supported package manager found for nodejs/npm"
      exit 1
      ;;
  esac
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "[clawpanel] npm is unavailable after dependency install"
  exit 1
fi

npm install -g '"${CLAWPANEL_NPM_PACKAGE}"'
if command -v clawpanel >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
  ln -sf "$(command -v clawpanel)" /usr/local/bin/clawpanel || true
fi'
  run_cmd_brief "docker exec ${container_name} sh -lc <clawpanel-install-script>" \
    docker exec "${container_name}" sh -lc "${script}"
}

install_easyclaw() {
  local container_name="$1"
  local data_dir="$2"
  run_cmd mkdir -p "$(dirname "$(easyclaw_target_dir "${data_dir}")")"

  if [[ "${OPENCLAWCTL_TEST_FORCE_EASYCLI_FAIL:-0}" == "1" ]]; then
    return 1
  fi

  log_info "开始安装/升级 ClawPanel（npm: ${CLAWPANEL_NPM_PACKAGE}）"
  run_easyclaw_install_script "${container_name}"
}

check_and_upgrade_easyclaw() {
  local container_name="$1"
  local data_dir="$2"
  log_info "开始检查并升级 ClawPanel（npm: ${CLAWPANEL_NPM_PACKAGE}）"
  run_cmd mkdir -p "$(dirname "$(easyclaw_target_dir "${data_dir}")")"
  run_easyclaw_install_script "${container_name}"
}

persistence_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/persistence.profile"
}

image_lock_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/image-lock.profile"
}

resolve_locked_image_ref() {
  local image="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s\n' "${image}"
    return 0
  fi
  if ! has_docker_command; then
    printf '%s\n' "${image}"
    return 0
  fi

  local locked
  locked=$(docker image inspect --format '{{index .RepoDigests 0}}' "${image}" 2>/dev/null || true)
  locked=$(trim_surrounding_spaces "${locked}")
  if [[ -z "${locked}" || "${locked}" == "<no value>" || "${locked}" == "<nil>" ]]; then
    printf '%s\n' "${image}"
    return 0
  fi
  printf '%s\n' "${locked}"
}

detect_local_locked_image_ref() {
  local image="$1"
  if ! has_docker_command; then
    return 1
  fi
  local locked
  locked=$(docker image inspect --format '{{index .RepoDigests 0}}' "${image}" 2>/dev/null || true)
  locked=$(trim_surrounding_spaces "${locked}")
  [[ -n "${locked}" && "${locked}" != "<no value>" && "${locked}" != "<nil>" ]] || return 1
  printf '%s\n' "${locked}"
}

save_image_lock_profile() {
  local data_dir="$1"
  local requested_image="$2"
  local effective_image="$3"
  local locked_image="$4"
  local profile
  profile=$(image_lock_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "镜像锁定档案将保存到: ${profile}"
    log_info "镜像锁定档案内容: requested=${requested_image}, effective=${effective_image}, locked=${locked_image}"
    return 0
  fi

  cat > "${profile}" <<EOF
REQUESTED_IMAGE=${requested_image}
EFFECTIVE_IMAGE=${effective_image}
LOCKED_IMAGE=${locked_image}
UPDATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
}

load_image_lock_profile_value() {
  local data_dir="$1"
  local key="$2"
  local profile
  profile=$(image_lock_profile_path "${data_dir}")
  if [[ ! -f "${profile}" ]]; then
    return 1
  fi
  local value
  value=$(awk -F '=' -v k="${key}" '$1==k {print substr($0, index($0, "=") + 1)}' "${profile}" | tail -n1)
  value=$(trim_surrounding_spaces "${value}")
  [[ -n "${value}" ]] || return 1
  printf '%s\n' "${value}"
}

detect_locked_image_from_profile() {
  local data_dir="$1"
  local locked
  locked=$(load_image_lock_profile_value "${data_dir}" "LOCKED_IMAGE" || true)
  if [[ -n "${locked}" ]]; then
    printf '%s\n' "${locked}"
    return 0
  fi
  local effective
  effective=$(load_image_lock_profile_value "${data_dir}" "EFFECTIVE_IMAGE" || true)
  if [[ -n "${effective}" ]]; then
    printf '%s\n' "${effective}"
    return 0
  fi
  return 1
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
    printf '%s\n' "$(normalize_data_dir_from_mount_source "${OPENCLAWCTL_TEST_EXISTING_DATA_DIR}")"
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
        printf '%s\n' "$(normalize_data_dir_from_mount_source "${source}")"
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
        printf '%s\n' "$(normalize_data_dir_from_mount_source "${source}")"
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
        printf '%s\n' "$(normalize_data_dir_from_mount_source "${source}")"
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
  local data_dir="${3:-}"

  if [[ -n "${OPENCLAWCTL_TEST_CURRENT_IMAGE:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_CURRENT_IMAGE}"
    return
  fi

  if [[ -n "${data_dir}" ]]; then
    local locked_image
    locked_image=$(detect_locked_image_from_profile "${data_dir}" || true)
    if [[ -n "${locked_image}" ]]; then
      printf '%s\n' "${locked_image}"
      return
    fi
  fi

  local detected=""
  if has_docker_command; then
    detected=$(docker inspect -f '{{.Config.Image}}' "${name}" 2>/dev/null || true)
  fi
  if [[ -n "${detected}" ]]; then
    if [[ -n "${data_dir}" ]]; then
      local local_locked
      local_locked=$(detect_local_locked_image_ref "${detected}" || true)
      if [[ -n "${local_locked}" ]]; then
        printf '%s\n' "${local_locked}"
        return
      fi
    fi
    printf '%s\n' "${detected}"
    return
  fi

  if [[ -n "${data_dir}" ]]; then
    local report_image
    report_image=$(detect_image_from_last_report "${data_dir}" || true)
    if [[ -n "${report_image}" ]]; then
      printf '%s\n' "${report_image}"
      return
    fi
  fi

  local deployment_image
  deployment_image=$(detect_image_from_deployment_info "${name}" "${data_dir}" || true)
  if [[ -n "${deployment_image}" ]]; then
    printf '%s\n' "${deployment_image}"
    return
  fi

  printf '%s\n' "${fallback}"
}

detect_image_from_last_report() {
  local data_dir="$1"
  local report_file="${data_dir}/runtime/last_report.json"
  if [[ ! -f "${report_file}" ]]; then
    return 1
  fi

  local image
  image=$(sed -n 's/.*"image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${report_file}" | head -n1)
  image=$(trim_surrounding_spaces "${image}")
  [[ -n "${image}" ]] || return 1
  printf '%s\n' "${image}"
}

detect_image_from_deployment_info() {
  local wanted_name="$1"
  local wanted_data_dir="${2:-}"
  local info_file
  info_file=$(deployment_info_path)
  if [[ ! -f "${info_file}" ]]; then
    return 1
  fi

  local info_name info_data_dir info_image
  info_name=$(sed -n 's/^[[:space:]]*容器名：[[:space:]]*//p' "${info_file}" | head -n1)
  info_data_dir=$(sed -n 's/^[[:space:]]*数据目录：[[:space:]]*//p' "${info_file}" | head -n1)
  info_image=$(sed -n 's/^[[:space:]]*镜像：[[:space:]]*//p' "${info_file}" | head -n1)

  info_name=$(trim_surrounding_spaces "${info_name}")
  info_data_dir=$(trim_surrounding_spaces "${info_data_dir}")
  info_image=$(trim_surrounding_spaces "${info_image}")
  [[ -n "${info_image}" ]] || return 1

  if [[ -n "${wanted_name}" && -n "${info_name}" && "${wanted_name}" != "${info_name}" ]]; then
    if [[ -z "${wanted_data_dir}" || -z "${info_data_dir}" || "${wanted_data_dir}" != "${info_data_dir}" ]]; then
      return 1
    fi
  fi

  if [[ -n "${wanted_data_dir}" && -n "${info_data_dir}" && "${wanted_data_dir}" != "${info_data_dir}" ]]; then
    return 1
  fi

  printf '%s\n' "${info_image}"
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
  local cfg_path
  cfg_path=$(openclaw_config_file_path "${data_dir}")
  if [[ -f "${cfg_path}" ]]; then
    local backup_file="${cfg_path}.bak.$(date +%Y%m%d%H%M%S)"
    run_cmd cp "${cfg_path}" "${backup_file}"
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
    hostdeps_warn_if_eol_linux || true
    local install_choice="${OPENCLAWCTL_AUTO_INSTALL_DOCKER:-1}"
    if [[ -z "${OPENCLAWCTL_AUTO_INSTALL_DOCKER:-}" ]]; then
      log_info "检测到未安装 Docker，将自动安装 Docker Engine（可设置 OPENCLAWCTL_AUTO_INSTALL_DOCKER=0 关闭）"
    elif [[ "${install_choice}" == "0" && is_interactive_session ]]; then
      printf '检测到未安装 Docker，是否改为自动安装 Docker Engine? (y/N): '
      IFS= read -r install_choice
    fi
    if [[ "${install_choice}" != "1" ]] && ! validate_yes_no "${install_choice:-n}"; then
      log_error "Docker 未安装。可设置 OPENCLAWCTL_AUTO_INSTALL_DOCKER=1 自动安装，或手工执行: curl -fsSL https://get.docker.com | sh"
      return 1
    fi

    set +e
    run_cmd sh -lc 'curl -fsSL https://get.docker.com | sh'
    local docker_install_rc=$?
    set -e
    if [[ "${docker_install_rc}" -ne 0 ]]; then
      log_error "get.docker.com 安装失败，尝试回退为系统包管理器安装 Docker"
      if ! hostdeps_install_docker_via_package_manager; then
        log_error "Docker 自动安装失败（含系统包管理器回退）"
        return 1
      fi
    fi
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

  if ! has_docker_command; then
    log_info "[preflight] docker 命令不可用，尝试自动安装/引导"
    if ! install_docker_if_missing; then
      log_error "[preflight] docker 命令不可用"
      return 1
    fi
  fi

  if ! has_docker_command; then
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
  local python_default="2"

  dep_enabled "${normalized_base}" "npm" && npm_default="1"
  dep_enabled "${normalized_base}" "uv" && uv_default="1"
  dep_enabled "${normalized_base}" "go" && go_default="1"
  dep_enabled "${normalized_base}" "rust" && rust_default="1"
  dep_enabled "${normalized_base}" "python3" && python_default="1"

  echo "依赖选择（默认 npm+uv，go/rust/python3 可选）:" >&2
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

  echo "是否包含 python3:" >&2
  echo "  1) 是" >&2
  echo "  2) 否" >&2
  local python_choice
  python_choice=$(read_choice_default "请选择" "${python_default}")

  local extra_deps
  extra_deps=$(read_with_default "额外依赖命令（逗号分隔，可留空）" "")

  build_dep_set_from_choices "${npm_choice}" "${uv_choice}" "${go_choice}" "${rust_choice}" "${python_choice}" "${extra_deps}"
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

is_valid_port_number() {
  local value="${1:-}"
  [[ "${value}" =~ ^[0-9]+$ ]] || return 1
  if [[ "${value}" -lt 1 || "${value}" -gt 65535 ]]; then
    return 1
  fi
  return 0
}

collect_extra_ports_guided() {
  local main_host_port="$1"
  local main_container_port="$2"
  local collected=""
  local host_entry container_entry proto_choice proto token candidate normalized continue_choice

  while true; do
    printf '宿主机扩展端口（留空结束）: ' >&2
    IFS= read -r host_entry
    host_entry=$(sanitize_user_input "${host_entry}")
    host_entry=$(trim_surrounding_spaces "${host_entry}")
    if [[ -z "${host_entry}" ]]; then
      break
    fi
    if ! is_valid_port_number "${host_entry}"; then
      log_error "宿主机端口无效: ${host_entry}（范围 1-65535）"
      continue
    fi

    container_entry=$(read_required "容器内部扩展端口")
    container_entry=$(trim_surrounding_spaces "${container_entry}")
    if ! is_valid_port_number "${container_entry}"; then
      log_error "容器内部端口无效: ${container_entry}（范围 1-65535）"
      continue
    fi

    echo "协议类型:" >&2
    echo "  1) tcp（默认）" >&2
    echo "  2) udp" >&2
    proto_choice=$(read_choice_default "请选择" "1")
    case "${proto_choice}" in
      1) proto="tcp" ;;
      2) proto="udp" ;;
      *)
        log_error "无效选择，默认按 tcp 处理"
        proto="tcp"
        ;;
    esac

    token="${host_entry}:${container_entry}"
    [[ "${proto}" == "udp" ]] && token="${token}/udp"
    candidate="${collected}${collected:+ }${token}"

    if normalized=$(normalize_extra_ports "${candidate}" "${main_host_port}" "${main_container_port}"); then
      collected="${normalized}"
      printf '[INFO] 已加入扩展端口: %s\n' "${token}" >&2
      printf '[INFO] 当前扩展端口: %s\n' "$(display_port_mappings "${collected}")" >&2
    else
      log_error "扩展端口条目无效，已忽略: ${token}"
      continue
    fi

    echo "继续添加扩展端口:" >&2
    echo "  1) 是" >&2
    echo "  2) 否" >&2
    continue_choice=$(read_choice_default "请选择" "2")
    case "${continue_choice}" in
      1) ;;
      2) break ;;
      *)
        log_error "无效选择，默认结束添加"
        break
        ;;
    esac
  done

  printf '%s\n' "${collected}"
}

prompt_extra_ports_configuration() {
  local current_extra_ports="${1:-}"
  local main_host_port="$2"
  local main_container_port="$3"
  local choice raw_input normalized

  while true; do
    echo "扩展端口映射管理:" >&2
    echo "  当前: $(display_port_mappings "${current_extra_ports}")" >&2
    echo "  1) 保留当前" >&2
    echo "  2) 清空映射" >&2
    echo "  3) 问答式重设（逐条添加）" >&2
    echo "  m) 手动输入（兼容旧格式）" >&2

    choice=$(read_choice_default "请选择（也可直接输入端口串）" "3")
    choice=$(trim_surrounding_spaces "${choice}")

    case "${choice}" in
      1)
        printf '%s\n' "${current_extra_ports}"
        return 0
        ;;
      2)
        printf '\n'
        return 0
        ;;
      3)
        collect_extra_ports_guided "${main_host_port}" "${main_container_port}"
        return 0
        ;;
      m|M)
        raw_input=$(read_with_default "扩展端口映射（逗号分隔，如 5001:5001,6000:6000/udp）" "${current_extra_ports}")
        raw_input=$(sanitize_port_mapping_input "${raw_input}")
        if [[ -z "${raw_input}" ]]; then
          printf '\n'
          return 0
        fi
        if normalized=$(normalize_extra_ports "${raw_input}" "${main_host_port}" "${main_container_port}"); then
          printf '%s\n' "${normalized}"
          return 0
        fi
        log_error "扩展端口映射输入无效，请重试"
        ;;
      "")
        printf '%s\n' "${current_extra_ports}"
        return 0
        ;;
      *)
        raw_input=$(sanitize_port_mapping_input "${choice}")
        if [[ -n "${raw_input}" && "${raw_input}" == *:* ]]; then
          if normalized=$(normalize_extra_ports "${raw_input}" "${main_host_port}" "${main_container_port}"); then
            printf '%s\n' "${normalized}"
            return 0
          fi
          log_error "扩展端口映射输入无效，请重试"
        else
          log_error "无效选择"
        fi
        ;;
    esac
  done
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
    echo "绑定=$(bind_choice_label "${bind_choice}") | 主端口=${host_port}:${container_port} | 补充端口=${extra_desc} | ClawPanel Web 将自动补 ${EASYCLAW_DEFAULT_WEB_PORT}"
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
    echo "主端口=${host_port}:${container_port} | 补充端口=${extra_desc} | ClawPanel Web 将自动补 ${EASYCLAW_DEFAULT_WEB_PORT}"
  else
    echo "主端口=${host_port}:${container_port} | 补充端口=${extra_desc}"
  fi
}

feature_group_summary() {
  local easy_choice="$1"
  local deps_choice="$2"
  local dep_set="$3"
  if [[ "${deps_choice}" == "1" ]]; then
    echo "ClawPanel=$(choice_to_yes_no "${easy_choice}") | 依赖补齐=是 | $(deps_summary_line "${dep_set}")"
  else
    echo "ClawPanel=$(choice_to_yes_no "${easy_choice}") | 依赖补齐=否"
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

  local cfg_path
  cfg_path=$(openclaw_config_file_path "${data_dir}")
  if [[ -f "${cfg_path}" ]]; then
    bind=$(grep -Eo '"bind"[[:space:]]*:[[:space:]]*"[^"]+"' "${cfg_path}" 2>/dev/null | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' | tr '[:upper:]' '[:lower:]' || true)
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
  if [[ "${bin_choice}" == "1" || "${env_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/path-shims")
    lines+=("${data_dir}/runtime/path-decls/openclaw-runtime-path.sh")
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
  local cfg
  cfg=$(openclaw_config_file_path "${data_dir}")
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
    echo "Token：沿用原配置（如需查看可在 $(openclaw_config_file_path "${data_dir}") 中确认）"
  fi
  echo "访问地址：${access_url}"
  echo
  echo "启动CLI配置流程："
  echo "官方Cli命令："
  echo "docker exec -it ${container_name} openclaw onboard"
  echo
  echo "ClawPanel 管理工具："
  echo "docker exec -it ${container_name} clawpanel tui"
  echo "docker exec -it ${container_name} clawpanel web --port ${EASYCLAW_DEFAULT_WEB_PORT}"
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
      OUTPUT_FILE) OUTPUT_FILE_CFG="${value}" ;;
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
  echo "ClawPanel: $(choice_to_yes_no "${EASY_CHOICE_CFG}")"
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
  echo "ClawPanel 检查升级: $(choice_to_yes_no "${EASY_CHOICE_CFG}")"
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

  if ! run_preflight_checks "clawpanel-upgrade" "${name}" "${data_dir}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  local -a easy_nonfatal_issues=()
  if ! run_optional_step "ClawPanel 检查升级" check_and_upgrade_easyclaw "${name}" "${data_dir}"; then
    easy_nonfatal_issues+=("ClawPanel 检查升级失败")
  fi
  local easy_status="success"
  [[ "${#easy_nonfatal_issues[@]}" -gt 0 ]] && easy_status="success_with_warnings"
  write_last_report "clawpanel-upgrade" "${easy_status}" "${name}" "${data_dir}" "" "" "" "" "" "${easy_nonfatal_issues[@]}"
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
  printf '\n--- 当前操作：升级或重装 ClawPanel ---\n'
  echo "容器名: ${NAME_CFG}"
  echo "ClawPanel 目录: $(easyclaw_target_dir "${data_dir}")"
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

run_compose_export_from_config_file() {
  NAME_CFG=""
  IMAGE_CFG=""
  DATA_DIR_CFG=""
  HOST_PORT_CFG=""
  CONTAINER_PORT_CFG=""
  BIN_PERSIST_CHOICE_CFG=""
  ENV_PERSIST_CHOICE_CFG=""
  APT_CFG_PERSIST_CHOICE_CFG=""
  CACHE_PERSIST_CHOICE_CFG=""
  EXTRA_PORTS_CFG=""
  OUTPUT_FILE_CFG=""
  load_simple_config_file "${CONFIG_FILE}"

  [[ -n "${NAME_CFG}" ]] || {
    log_error "配置文件缺少容器名"
    return 1
  }

  local data_dir
  data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"

  local port_pair host_port container_port
  port_pair=$(detect_existing_ports "${NAME_CFG}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  host_port="${HOST_PORT_CFG:-${port_pair%%,*}}"
  container_port="${CONTAINER_PORT_CFG:-${port_pair##*,}}"

  local image
  image="${IMAGE_CFG:-$(detect_existing_image "${NAME_CFG}" "$(official_openclaw_image "latest")" "${data_dir}")}"

  local persist_defaults bin_persist_choice env_persist_choice apt_cfg_persist_choice cache_persist_choice
  persist_defaults=$(compose_detect_persistence_defaults "${NAME_CFG}" "${data_dir}")
  bin_persist_choice="${BIN_PERSIST_CHOICE_CFG:-${persist_defaults%%,*}}"
  env_persist_choice="${ENV_PERSIST_CHOICE_CFG:-$(printf '%s' "${persist_defaults}" | cut -d',' -f2)}"
  apt_cfg_persist_choice="${APT_CFG_PERSIST_CHOICE_CFG:-$(printf '%s' "${persist_defaults}" | cut -d',' -f3)}"
  cache_persist_choice="${CACHE_PERSIST_CHOICE_CFG:-$(printf '%s' "${persist_defaults}" | cut -d',' -f4)}"

  local extra_ports
  extra_ports="${EXTRA_PORTS_CFG:-$(detect_existing_extra_ports "${NAME_CFG}" "${host_port}" "${container_port}")}"
  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
    return 1
  fi
  if should_enable_easyclaw_web_port "0" "${NAME_CFG}" "${data_dir}"; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if should_enable_claudecodeui_reserved_port "0" "${NAME_CFG}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  local output_file
  output_file="${OUTPUT_FILE_CFG:-$(compose_export_default_path "${data_dir}")}"

  printf '\n=== 📄 导出 Docker Compose 编排文件 ===\n'
  echo "容器名: ${NAME_CFG}"
  echo "镜像: ${image}"
  echo "端口映射: ${host_port}:${container_port}"
  echo "扩展端口映射: $(value_or_unset "${extra_ports}")"
  echo "持久化目录: ${data_dir}"
  echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
  echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
  echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
  echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${cache_persist_choice}")"
  echo "Compose 导出路径: ${output_file}"

  export_openclaw_compose_file "${NAME_CFG}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "${extra_ports}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${output_file}"
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
  local software_set="${7:-}"
  local skill_set="${8:-}"
  local native_action="${9:-native-install}"
  local native_title="${10:-原生 npm 安装结果}"

  local package_name version_tag package_ref
  package_name=$(native_package_for_source_choice "${source_choice}")
  version_tag=$(native_tag_for_source_choice "${source_choice}" "${channel_choice}" "${explicit_tag}")
  package_ref="${package_name}"
  [[ -n "${version_tag}" ]] && package_ref="${package_name}@${version_tag}"

  if ! ensure_native_host_dependencies "${native_action}"; then
    log_error "宿主机依赖检查未通过，原生 npm 安装已终止"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}" "${native_prefix}"
  run_cmd npm install -g --prefix "${native_prefix}" "${package_ref}"

  software_set=$(normalize_software_set "${software_set}")
  skill_set=$(normalize_skill_set "${skill_set}")
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "宿主机可选软件安装" install_selected_software_host "${data_dir}" "${native_prefix}" "${software_set}"; then
      log_error "宿主机可选软件安装存在告警，可稍后重试"
    fi
  fi
  if [[ -n "${skill_set}" ]]; then
    if ! run_optional_step "Skill 安装" install_selected_skills "${data_dir}" "${skill_set}"; then
      log_error "Skill 安装存在告警，可稍后重试"
    fi
  fi
  save_software_profile "${data_dir}" "${software_set}"
  save_skill_profile "${data_dir}" "${skill_set}"
  save_config_manifest "${data_dir}" "${native_action}" "2" "2" "2" "2" "${software_set}" "${skill_set}"

  local native_status="success"
  write_last_report "${native_action}" "${native_status}" "${app_name}" "${data_dir}" "${package_ref}" "" "" "" "" ""
  printf '\n===============================\n'
  echo "${native_title}"
  echo "==============================="
  echo "应用名：${app_name}"
  echo "包名：${package_ref}"
  echo "数据目录：${data_dir}"
  echo "安装前缀：${native_prefix}"
  echo "可选软件：$(software_set_summary "${software_set}")"
  echo "Skills：$(skill_set_summary "${skill_set}")"
  echo "启动示例：PATH=${native_prefix}/bin:\$PATH OPENCLAW_HOME=${data_dir} openclaw gateway run"
  echo "==============================="
}

native_report_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/last_report.json"
}

show_native_report() {
  local app_name="$1"
  local data_dir="$2"
  local report_file
  report_file=$(native_report_path "${data_dir}")

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Native 应用：${app_name}"
    echo "Native 数据目录：${data_dir}"
    echo "Native 报告路径：${report_file}"
    return 0
  fi
  if [[ ! -f "${report_file}" ]]; then
    log_error "未找到 Native 部署报告: ${report_file}"
    return 1
  fi

  printf '\n=== Native 部署信息 ===\n'
  echo "应用名：${app_name}"
  echo "数据目录：${data_dir}"
  cat "${report_file}"
}

normalize_native_repair_mode() {
  local mode_raw="${1:-all}"
  mode_raw=$(echo "${mode_raw}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
  case "${mode_raw}" in
    1|node|node-npm|nodejs|npm) echo "node" ;;
    2|build|toolchain|python|cmake) echo "build" ;;
    3|swap|memory|mem) echo "swap" ;;
    4|all|"") echo "all" ;;
    *)
      echo "all"
      ;;
  esac
}

execute_native_repair_plan() {
  local mode_raw="${1:-all}"
  local mode
  mode=$(normalize_native_repair_mode "${mode_raw}")

  printf '\n=== 🔧 修复 Native 运行环境 ===\n'
  local failed=0
  case "${mode}" in
    node)
      hostdeps_repair_node_npm || failed=1
      ;;
    build)
      hostdeps_repair_build_toolchain || failed=1
      ;;
    swap)
      hostdeps_repair_swap || failed=1
      ;;
    all)
      ensure_native_host_dependencies "native-repair" || failed=1
      ;;
  esac

  local status="success"
  if [[ "${failed}" -ne 0 ]]; then
    status="failed"
    log_error "Native 运行环境修复未完全通过，请按提示处理后重试"
  else
    log_info "Native 运行环境修复完成"
  fi
  write_last_report "native-repair" "${status}" "openclaw_native" "" "" "" "" "" "" ""
  [[ "${failed}" -eq 0 ]]
}

execute_native_uninstall_plan() {
  local app_name="$1"
  local data_dir="$2"
  local native_prefix="$3"
  local mode="${4:-1}"

  printf '\n=== 🗑️ 卸载 Native 实例 ===\n'
  echo "应用名：${app_name}"
  echo "数据目录：${data_dir}"
  echo "安装前缀：${native_prefix}"

  if ! run_optional_step "卸载 Native npm 包" run_cmd npm uninstall -g --prefix "${native_prefix}" openclaw @qingchencloud/openclaw-zh; then
    log_error "Native npm 包卸载存在告警（可能未安装），已继续清理流程"
  fi
  if [[ "${mode}" == "2" ]]; then
    run_cmd rm -rf "${data_dir}"
  fi
  write_last_report "native-uninstall" "success" "${app_name}" "${data_dir}" "" "" "" "" "" ""
}

run_native_from_config_file() {
  SOURCE_CHOICE_CFG="2"
  CHANNEL_CHOICE_CFG="1"
  OFFICIAL_TAG_CFG=""
  NAME_CFG="openclaw_native"
  DATA_DIR_CFG=""
  NATIVE_PREFIX_CFG=""
  SOFTWARE_SET_CFG=""
  SKILL_SET_CFG=""

  load_simple_config_file "${CONFIG_FILE}"

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local native_prefix="${NATIVE_PREFIX_CFG:-${data_dir}/native}"
  local software_set
  software_set=$(normalize_software_set "${SOFTWARE_SET_CFG}")
  local skill_set
  skill_set=$(normalize_skill_set "${SKILL_SET_CFG}")

  execute_native_install_plan "${SOURCE_CHOICE_CFG}" "${CHANNEL_CHOICE_CFG}" "${OFFICIAL_TAG_CFG}" "${NAME_CFG}" "${data_dir}" "${native_prefix}" "${software_set}" "${skill_set}" "native-install" "原生 npm 安装结果"
}

run_native_upgrade_from_config_file() {
  SOURCE_CHOICE_CFG="2"
  CHANNEL_CHOICE_CFG="1"
  OFFICIAL_TAG_CFG=""
  MODE_CFG="1"
  NAME_CFG="openclaw_native"
  DATA_DIR_CFG=""
  NATIVE_PREFIX_CFG=""
  SOFTWARE_SET_CFG=""
  SKILL_SET_CFG=""
  load_simple_config_file "${CONFIG_FILE}"

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local native_prefix="${NATIVE_PREFIX_CFG:-${data_dir}/native}"
  local software_set
  software_set=$(normalize_software_set "${SOFTWARE_SET_CFG}")
  if [[ -z "${software_set}" ]]; then
    software_set=$(load_software_profile "${data_dir}")
    software_set=$(normalize_software_set "${software_set}")
  fi
  local skill_set
  skill_set=$(normalize_skill_set "${SKILL_SET_CFG}")
  if [[ -z "${skill_set}" ]]; then
    skill_set=$(load_skill_profile "${data_dir}")
    skill_set=$(normalize_skill_set "${skill_set}")
  fi

  local mode
  mode=$(echo "${MODE_CFG}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
  local action="native-upgrade"
  local title="原生 npm 升级结果"
  local remove_data="0"
  case "${mode}" in
    2|reinstall|reinstall-keep)
      action="native-reinstall"
      title="原生 npm 重装结果"
      ;;
    3|reinstall-reset|reset)
      action="native-reinstall"
      title="原生 npm 重装结果"
      remove_data="1"
      ;;
  esac
  if [[ "${remove_data}" == "1" ]]; then
    run_cmd rm -rf "${data_dir}"
  fi

  execute_native_install_plan "${SOURCE_CHOICE_CFG}" "${CHANNEL_CHOICE_CFG}" "${OFFICIAL_TAG_CFG}" "${NAME_CFG}" "${data_dir}" "${native_prefix}" "${software_set}" "${skill_set}" "${action}" "${title}"
}

run_native_repair_from_config_file() {
  MODE_CFG="all"
  load_simple_config_file "${CONFIG_FILE}"
  execute_native_repair_plan "${MODE_CFG}"
}

run_native_info_from_config_file() {
  NAME_CFG="openclaw_native"
  DATA_DIR_CFG=""
  load_simple_config_file "${CONFIG_FILE}"
  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  show_native_report "${NAME_CFG}" "${data_dir}"
}

run_native_uninstall_from_config_file() {
  NAME_CFG="openclaw_native"
  DATA_DIR_CFG=""
  NATIVE_PREFIX_CFG=""
  MODE_CFG="1"
  load_simple_config_file "${CONFIG_FILE}"

  local data_dir="${DATA_DIR_CFG:-$(default_data_dir_for_name "${NAME_CFG}")}"
  local native_prefix="${NATIVE_PREFIX_CFG:-${data_dir}/native}"
  execute_native_uninstall_plan "${NAME_CFG}" "${data_dir}" "${native_prefix}" "${MODE_CFG}"
}

run_1panel_quickstart_script() {
  local mode="${1:-install}"
  local script_url="${OPENCLAWCTL_1PANEL_SCRIPT_URL:-https://resource.fit2cloud.com/1panel/package/quick_start.sh}"
  local install_cmd
  if [[ -n "${OPENCLAWCTL_1PANEL_INSTALL_CMD:-}" ]]; then
    install_cmd=(bash -lc "${OPENCLAWCTL_1PANEL_INSTALL_CMD}")
  else
    install_cmd=(bash -lc "curl -fsSL '${script_url}' | bash")
    if ! command -v curl >/dev/null 2>&1; then
      install_cmd=(bash -lc "wget -qO- '${script_url}' | bash")
    fi
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ "${mode}" == "repair" ]]; then
      log_info "将执行 1Panel 修复命令: $(print_cmd "${install_cmd[@]}")"
    else
      log_info "将执行 1Panel 安装命令: $(print_cmd "${install_cmd[@]}")"
    fi
    return 0
  fi

  local output_file rc
  output_file=$(mktemp)
  set +e
  "${install_cmd[@]}" 2>&1 | tee "${output_file}"
  rc=${PIPESTATUS[0]}
  set -e

  OPENCLAWCTL_1PANEL_LAST_OUTPUT="$(cat "${output_file}")"
  rm -f "${output_file}"
  return "${rc}"
}

panel_install_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel 安装仅支持 Linux 主机"
    return 1
  fi
  if [[ "${DRY_RUN}" -eq 0 && "${EUID}" -ne 0 ]]; then
    log_error "1Panel 安装需要 root 权限，请使用 sudo/root 运行"
    return 1
  fi

  printf '\n=== 📥 安装 1Panel ===\n'
  echo "将使用官方 quick_start 脚本安装 1Panel。"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return 0
  fi

  if ! run_1panel_quickstart_script "install"; then
    log_error "1Panel 安装命令执行失败"
    return 1
  fi

  local parsed panel_url panel_user panel_password info_path
  parsed=$(extract_1panel_install_summary_fields "${OPENCLAWCTL_1PANEL_LAST_OUTPUT:-}")
  panel_url="${parsed%%|*}"
  parsed="${parsed#*|}"
  panel_user="${parsed%%|*}"
  panel_password="${parsed#*|}"
  info_path=$(panel_install_info_path)

  echo
  render_1panel_install_summary_text "${panel_url}" "${panel_user}" "${panel_password}" "${info_path}"
  write_1panel_install_archive "${panel_url}" "${panel_user}" "${panel_password}" "${OPENCLAWCTL_1PANEL_LAST_OUTPUT:-}" || true
}

panel_repair_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel 修复仅支持 Linux 主机"
    return 1
  fi
  if [[ "${DRY_RUN}" -eq 0 && "${EUID}" -ne 0 ]]; then
    log_error "1Panel 修复需要 root 权限，请使用 sudo/root 运行"
    return 1
  fi

  printf '\n=== 🔧 升级/修复 1Panel ===\n'
  if command -v 1panel >/dev/null 2>&1; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      run_cmd 1panel version
      run_cmd 1panel update
      return 0
    fi
    if ! run_cmd 1panel update; then
      log_error "1panel update 执行失败，尝试官方修复脚本"
      run_1panel_quickstart_script "repair"
    fi
    return 0
  fi

  log_error "未检测到 1panel 命令，尝试官方修复脚本"
  run_1panel_quickstart_script "repair"
}

panel_openclaw_install_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel OpenClaw 安装仅支持 Linux 主机"
    return 1
  fi
  OPENCLAWCTL_DATA_ROOT="/opt/1panel/apps" install_wizard
}

panel_openclaw_adopt_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel OpenClaw 接管仅支持 Linux 主机"
    return 1
  fi
  OPENCLAWCTL_DATA_ROOT="/opt/1panel/apps" adopt_wizard
}

repair_1panel_environment_dependencies() {
  local host_port="$1"
  local failed=0
  local auto_fix="${OPENCLAWCTL_AUTO_FIX_HOST_DEPS:-1}"

  if ! has_docker_command; then
    log_error "[panel] 缺少 docker 命令"
    if [[ "${auto_fix}" == "1" ]]; then
      hostdeps_install_docker_via_package_manager || failed=1
    else
      failed=1
    fi
  fi

  run_cmd docker info
  if [[ "${DRY_RUN}" -eq 0 ]] && has_docker_command; then
    if ! docker info >/dev/null 2>&1; then
      log_error "[panel] Docker Daemon 未就绪，尝试拉起服务"
      if command -v systemctl >/dev/null 2>&1; then
        run_cmd systemctl enable --now docker || true
      elif command -v service >/dev/null 2>&1; then
        run_cmd service docker start || true
      fi
      if ! docker info >/dev/null 2>&1; then
        log_error "[panel] Docker Daemon 仍不可用"
        failed=1
      fi
    fi
  fi

  log_info "[panel] 端口检查: ${host_port}"
  if ! is_host_port_available "${host_port}"; then
    log_error "[panel] 宿主机端口已被占用: ${host_port}"
    failed=1
  else
    log_info "[panel] 宿主机端口可用: ${host_port}"
  fi

  if command -v curl >/dev/null 2>&1; then
    run_cmd curl -fsSLI "${OPENCLAWCTL_1PANEL_SCRIPT_URL:-https://resource.fit2cloud.com/1panel/package/quick_start.sh}"
  else
    log_info "[panel] 未检测到 curl，跳过外网连通性探测"
  fi

  [[ "${failed}" -eq 0 ]]
}

run_panel_deps_from_config_file() {
  HOST_PORT_CFG="${DEFAULT_HOST_PORT}"
  load_simple_config_file "${CONFIG_FILE}"
  repair_1panel_environment_dependencies "${HOST_PORT_CFG}"
}

panel_deps_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel 环境依赖修复仅支持 Linux 主机"
    return 1
  fi

  printf '\n=== 🧰 1Panel 环境依赖修复 ===\n'
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_panel_deps_from_config_file
    return
  fi

  local host_port
  host_port=$(read_with_default "用于检查的 OpenClaw 宿主机端口" "${DEFAULT_HOST_PORT}")
  printf '确认执行 1Panel 环境依赖修复? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return 0
  fi
  repair_1panel_environment_dependencies "${host_port}"
}

panel_info_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel 部署信息查看仅支持 Linux 主机"
    return 1
  fi
  OPENCLAWCTL_DATA_ROOT="/opt/1panel/apps" info_wizard
}

panel_uninstall_wizard() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel OpenClaw 卸载仅支持 Linux 主机"
    return 1
  fi
  OPENCLAWCTL_DATA_ROOT="/opt/1panel/apps" uninstall_wizard
}

native_npm_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_from_config_file
    return
  fi

  printf '\n=== 🧪 原生 npm 安装 ===\n'
  local source_choice channel_choice explicit_tag name data_dir native_prefix software_set skill_set
  source_choice="2"
  channel_choice="1"
  explicit_tag=""
  name="openclaw_native"
  data_dir="$(default_data_dir_for_name "${name}")"
  native_prefix="${data_dir}/native"
  software_set=""
  skill_set=""

  echo "版本来源:"
  echo "  1) 官方 npm(openclaw)"
  echo "  2) 中文版 npm(@qingchencloud/openclaw-zh)"
  source_choice=$(read_choice_default "请选择" "${source_choice}")

  echo "版本通道:"
  if [[ "${source_choice}" == "1" ]]; then
    echo "  1) stable(latest)"
    echo "  2) beta"
    echo "  3) 指定版本（列表选择）"
  else
    echo "  1) stable(latest)"
    echo "  2) nightly"
    echo "  3) 指定版本（列表选择）"
  fi
  channel_choice=$(read_choice_default "请选择" "${channel_choice}")
  local package_name default_tag
  package_name=$(native_package_for_source_choice "${source_choice}")
  default_tag=$(native_tag_for_source_choice "${source_choice}" "1" "")
  if [[ "${channel_choice}" == "3" ]]; then
    explicit_tag=$(prompt_native_npm_version_choice "${package_name}" "${source_choice}" "${channel_choice}" "${default_tag}" "1")
  else
    explicit_tag=""
  fi
  explicit_tag=$(trim_surrounding_spaces "${explicit_tag}")
  name=$(read_container_name "应用名（仅用于配置记录）")
  local previous_data_dir="${data_dir}"
  data_dir=$(read_with_default "数据目录" "${data_dir}")
  if [[ "${native_prefix}" == "${previous_data_dir}/native" ]]; then
    native_prefix="${data_dir}/native"
  fi
  echo "说明：npm 安装前缀目录用于存放 openclaw 命令，最终可执行文件位于 <前缀>/bin（通常直接回车默认即可）。"
  native_prefix=$(read_with_default "npm 安装前缀目录（用于命令安装）" "${native_prefix}")
  software_set=$(prompt_software_set_selection "${software_set}")
  skill_set=$(prompt_skill_set_selection "${skill_set}")

  printf '\n--- 执行清单（确认前） ---\n'
  local resolved_version_tag
  resolved_version_tag=$(native_tag_for_source_choice "${source_choice}" "${channel_choice}" "${explicit_tag}")
  echo "来源: $(source_choice_label "${source_choice}")"
  echo "通道: $(channel_choice_label "${channel_choice}")"
  echo "版本号: ${resolved_version_tag}"
  echo "应用名: ${name}"
  echo "数据目录: ${data_dir}"
  echo "安装前缀: ${native_prefix}"
  echo "可选软件: $(software_set_summary "${software_set}")"
  echo "Skills: $(skill_set_summary "${skill_set}")"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  execute_native_install_plan "${source_choice}" "${channel_choice}" "${explicit_tag}" "${name}" "${data_dir}" "${native_prefix}" "${software_set}" "${skill_set}"
}

native_upgrade_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_upgrade_from_config_file
    return
  fi

  printf '\n=== 🔄 升级/重装 Native 实例 ===\n'
  echo "模式:"
  echo "  1) 保留数据升级"
  echo "  2) 全新重装（可选删除数据）"
  local mode_choice
  mode_choice=$(read_choice_default "请选择" "1")

  local source_choice channel_choice explicit_tag name data_dir native_prefix
  source_choice="2"
  channel_choice="1"
  explicit_tag=""
  name="openclaw_native"
  name=$(read_with_default "应用名（用于配置记录）" "${name}")
  name=$(trim_surrounding_spaces "${name}")
  [[ -n "${name}" ]] || name="openclaw_native"
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
    echo "  3) 指定版本（列表选择）"
  else
    echo "  1) stable(latest)"
    echo "  2) nightly"
    echo "  3) 指定版本（列表选择）"
  fi
  channel_choice=$(read_choice_default "请选择" "${channel_choice}")
  local package_name default_tag
  package_name=$(native_package_for_source_choice "${source_choice}")
  default_tag=$(native_tag_for_source_choice "${source_choice}" "1" "")
  if [[ "${channel_choice}" == "3" ]]; then
    explicit_tag=$(prompt_native_npm_version_choice "${package_name}" "${source_choice}" "${channel_choice}" "${default_tag}" "1")
  else
    explicit_tag=""
  fi
  explicit_tag=$(trim_surrounding_spaces "${explicit_tag}")
  local previous_data_dir="${data_dir}"
  data_dir=$(read_with_default "数据目录" "${data_dir}")
  if [[ "${native_prefix}" == "${previous_data_dir}/native" ]]; then
    native_prefix="${data_dir}/native"
  fi
  echo "说明：npm 安装前缀目录用于存放 openclaw 命令，最终可执行文件位于 <前缀>/bin（通常直接回车默认即可）。"
  native_prefix=$(read_with_default "npm 安装前缀目录（用于命令安装）" "${native_prefix}")

  local software_set skill_set
  software_set=$(load_software_profile "${data_dir}")
  skill_set=$(load_skill_profile "${data_dir}")
  software_set=$(prompt_software_set_selection "${software_set}")
  skill_set=$(prompt_skill_set_selection "${skill_set}")

  local reinstall_data_mode="1"
  if [[ "${mode_choice}" == "2" ]]; then
    echo "重装数据策略:"
    echo "  1) 保留数据目录（重装程序）"
    echo "  2) 删除数据目录后重装"
    reinstall_data_mode=$(read_choice_default "请选择" "1")
  fi

  printf '\n--- 执行清单（确认前） ---\n'
  local resolved_version_tag
  resolved_version_tag=$(native_tag_for_source_choice "${source_choice}" "${channel_choice}" "${explicit_tag}")
  if [[ "${mode_choice}" == "2" ]]; then
    echo "模式: 全新重装"
    echo "重装数据策略: $(choice_to_yes_no "${reinstall_data_mode}")（是=保留）"
  else
    echo "模式: 保留数据升级"
  fi
  echo "来源: $(source_choice_label "${source_choice}")"
  echo "通道: $(channel_choice_label "${channel_choice}")"
  echo "版本号: ${resolved_version_tag}"
  echo "应用名: ${name}"
  echo "数据目录: ${data_dir}"
  echo "安装前缀: ${native_prefix}"
  echo "可选软件: $(software_set_summary "${software_set}")"
  echo "Skills: $(skill_set_summary "${skill_set}")"
  printf '确认执行? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  if [[ "${mode_choice}" == "2" && "${reinstall_data_mode}" == "2" ]]; then
    run_cmd rm -rf "${data_dir}"
  fi

  if [[ "${mode_choice}" == "2" ]]; then
    execute_native_install_plan "${source_choice}" "${channel_choice}" "${explicit_tag}" "${name}" "${data_dir}" "${native_prefix}" "${software_set}" "${skill_set}" "native-reinstall" "原生 npm 重装结果"
  else
    execute_native_install_plan "${source_choice}" "${channel_choice}" "${explicit_tag}" "${name}" "${data_dir}" "${native_prefix}" "${software_set}" "${skill_set}" "native-upgrade" "原生 npm 升级结果"
  fi
}

native_repair_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_repair_from_config_file
    return
  fi

  printf '\n=== 🔧 修复 Native 运行环境 ===\n'
  echo "修复项:"
  echo "  1) Node/npm"
  echo "  2) Python/cmake/构建工具"
  echo "  3) swap/低内存优化"
  echo "  4) 全部"
  local mode_choice
  mode_choice=$(read_choice_default "请选择" "4")
  local mode
  mode=$(normalize_native_repair_mode "${mode_choice}")

  printf '确认执行 Native 运行环境修复? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return
  fi

  execute_native_repair_plan "${mode}"
}

native_info_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_info_from_config_file
    return
  fi

  printf '\n=== 📄 查看 Native 部署信息 ===\n'
  local name data_dir
  name=$(read_with_default "应用名（用于定位数据目录）" "openclaw_native")
  name=$(trim_surrounding_spaces "${name}")
  [[ -n "${name}" ]] || name="openclaw_native"
  data_dir=$(read_with_default "数据目录" "$(default_data_dir_for_name "${name}")")
  show_native_report "${name}" "${data_dir}"
}

native_uninstall_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_native_uninstall_from_config_file
    return
  fi

  printf '\n=== 🗑️ 卸载 Native 实例 ===\n'
  local name data_dir native_prefix mode
  name=$(read_with_default "应用名（用于配置记录）" "openclaw_native")
  name=$(trim_surrounding_spaces "${name}")
  [[ -n "${name}" ]] || name="openclaw_native"
  data_dir=$(read_with_default "数据目录" "$(default_data_dir_for_name "${name}")")
  native_prefix=$(read_with_default "npm 安装前缀目录" "${data_dir}/native")

  echo "卸载模式:"
  echo "  1) 仅卸载 Native npm 包（保留数据）"
  echo "  2) 卸载 Native npm 包并删除数据目录"
  mode=$(read_choice_default "请选择" "1")

  printf '二次确认：请输入应用名 %s\n' "${name}"
  local confirm_name
  confirm_name=$(read_required "确认应用名")
  if [[ "${confirm_name}" != "${name}" ]]; then
    log_error "二次确认失败，已取消"
    return 1
  fi

  execute_native_uninstall_plan "${name}" "${data_dir}" "${native_prefix}" "${mode}"
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
  image=$(detect_existing_image "${name}" "$(official_openclaw_image "latest")" "${data_dir}")
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
        extra_ports=$(prompt_extra_ports_configuration "${extra_ports}" "${host_port}" "${container_port}")
        log_info "已更新：$(network_group_summary "${bind_choice}" "${host_port}" "${container_port}" "${extra_ports}" "${easy_choice}")"
        ;;
      5)
        echo "是否安装 ClawPanel:"
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
        echo "ClawPanel: $(choice_to_yes_no "${easy_choice}")"
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
        extra_ports=$(prompt_extra_ports_configuration "${extra_ports}" "${host_port}" "${container_port}")
        log_info "已更新：$(network_group_summary_no_bind "${host_port}" "${container_port}" "${extra_ports}" "${easyclaw_upgrade}")"
        ;;
      4)
        echo "是否检查并升级 ClawPanel:"
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
        echo "ClawPanel 检查升级: $(choice_to_yes_no "${easyclaw_upgrade}")"
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

  local host_port="${detected_host_port}"
  local container_port="${detected_container_port}"
  local data_dir="${detected_data_dir}"

  local image
  image=$(detect_existing_image "${name}" "$(official_openclaw_image "latest")" "${data_dir}")

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
        local next_image
        next_image="${image}"
        local parts repo current_tag
        parts=$(split_image_repo_and_tag "${image}")
        repo="${parts%%|*}"
        current_tag="${parts#*|}"
        [[ -n "${current_tag}" ]] || current_tag="latest"

        if is_official_openclaw_image_ref "${image}"; then
          echo "镜像调整方式:"
          echo "  1) 保持当前固定镜像（推荐）"
          echo "  2) 按 latest 方式重建（可能升级）"
          echo "  3) 官方版本列表选择"
          echo "  4) 手动输入镜像"
          local image_edit_mode
          image_edit_mode=$(read_choice_default "请选择" "1")
          case "${image_edit_mode}" in
            2)
              next_image="${repo}:latest"
              ;;
            3)
              local selected_tag
              selected_tag=$(prompt_official_openclaw_tag "${current_tag}")
              next_image="${repo}:${selected_tag}"
              ;;
            4)
              next_image=$(read_with_default "目标镜像（默认复用当前容器镜像）" "${image}")
              ;;
            *)
              ;;
          esac
        else
          echo "镜像调整方式:"
          echo "  1) 保持当前固定镜像（推荐）"
          echo "  2) 按 latest 方式重建（可能升级）"
          echo "  3) 手动输入镜像"
          local image_edit_mode
          image_edit_mode=$(read_choice_default "请选择" "1")
          case "${image_edit_mode}" in
            2)
              next_image="${repo}:latest"
              ;;
            3)
              next_image=$(read_with_default "目标镜像（默认复用当前容器镜像）" "${image}")
              ;;
            *)
              ;;
          esac
        fi
        image=$(trim_surrounding_spaces "${next_image}")
        [[ -n "${image}" ]] || image="${next_image}"
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
        extra_ports=$(prompt_extra_ports_configuration "${extra_ports}" "${host_port}" "${container_port}")
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

compose_export_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_compose_export_from_config_file
    return
  fi

  printf '\n=== 📄 导出 Docker Compose 编排文件 ===\n'
  echo "说明：仅导出 compose 文件，不会执行 docker compose up/down。"

  local name
  name=$(read_container_name "请输入容器名（用于识别现有配置）")

  local default_data_dir detected_data_dir data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")
  data_dir=$(read_with_default "持久化目录" "${detected_data_dir}")

  local detected_ports host_port container_port port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  detected_ports="${port_pair}"
  host_port=$(read_with_default "宿主机端口" "${detected_ports%%,*}")
  container_port=$(read_with_default "OpenClaw 容器内部端口" "${detected_ports##*,}")

  local image
  image=$(detect_existing_image "${name}" "$(official_openclaw_image "latest")" "${data_dir}")
  image=$(read_with_default "镜像（仅用于 compose 展示）" "${image}")

  local persist_defaults bin_persist_choice env_persist_choice apt_cfg_persist_choice cache_persist_choice
  persist_defaults=$(compose_detect_persistence_defaults "${name}" "${data_dir}")
  bin_persist_choice=$(printf '%s' "${persist_defaults}" | cut -d',' -f1)
  env_persist_choice=$(printf '%s' "${persist_defaults}" | cut -d',' -f2)
  apt_cfg_persist_choice=$(printf '%s' "${persist_defaults}" | cut -d',' -f3)
  cache_persist_choice=$(printf '%s' "${persist_defaults}" | cut -d',' -f4)

  echo "保留命令入口（bin）:"
  echo "  1) 是"
  echo "  2) 否"
  bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
  echo "保留运行环境（env）:"
  echo "  1) 是"
  echo "  2) 否"
  env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
  echo "APT源Key 持久化:"
  echo "  1) 是"
  echo "  2) 否"
  apt_cfg_persist_choice=$(read_choice_default "请选择" "${apt_cfg_persist_choice}")
  echo "缓存持久化(.npm/go mod/cargo):"
  echo "  1) 是"
  echo "  2) 否"
  cache_persist_choice=$(read_choice_default "请选择" "${cache_persist_choice}")

  local detected_extra_ports extra_ports_raw extra_ports
  detected_extra_ports=$(detect_existing_extra_ports "${name}" "${host_port}" "${container_port}")
  extra_ports_raw=$(read_with_default "扩展端口映射（逗号分隔，可留空）" "${detected_extra_ports}")
  if ! extra_ports=$(normalize_extra_ports "${extra_ports_raw}" "${host_port}" "${container_port}"); then
    return 1
  fi
  if should_enable_easyclaw_web_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  local output_file
  output_file=$(read_with_default "Compose 导出路径" "$(compose_export_default_path "${data_dir}")")

  printf '\n--- 导出清单（确认前） ---\n'
  echo "容器名: ${name}"
  echo "镜像: ${image}"
  echo "端口映射: ${host_port}:${container_port}"
  echo "扩展端口映射: $(value_or_unset "${extra_ports}")"
  echo "持久化目录: ${data_dir}"
  echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
  echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
  echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
  echo "缓存持久化(.npm/go mod/cargo): $(choice_to_yes_no "${cache_persist_choice}")"
  echo "Compose 导出路径: ${output_file}"

  printf '确认导出 compose 文件? (y/N): '
  local confirm
  IFS= read -r confirm
  if ! validate_yes_no "${confirm}"; then
    log_info "已取消"
    return 0
  fi

  export_openclaw_compose_file "${name}" "${image}" "${data_dir}" "${host_port}" "${container_port}" "${extra_ports}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${output_file}"
}

easyclaw_only_upgrade_wizard() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    run_easyclaw_from_config_file
    return
  fi
  printf '\n=== 📦 管理 ClawPanel 工具 ===\n'
  local name
  name=$(read_container_name "请输入容器名（用于定位持久化目录）")

  local default_data_dir
  default_data_dir=$(default_data_dir_for_name "${name}")
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local data_dir
  data_dir=$(read_with_default "ClawPanel 所在持久化目录" "${detected_data_dir}")

  printf '\n--- 当前操作：升级或重装 ClawPanel ---\n'
  echo "容器名: ${name}"
  echo "ClawPanel 目录: $(easyclaw_target_dir "${data_dir}")"
  printf '确认执行 ClawPanel 升级/重装? (y/N): '
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

load_optional_component_catalog
parse_global_flags "$@"
enforce_strict_noninteractive_mode
announce_startup_progress
maybe_exec_tui "$@" || true
if [[ -n "${SELECTED_WIZARD}" ]]; then
  run_selected_wizard
  exit 0
fi
main_loop
