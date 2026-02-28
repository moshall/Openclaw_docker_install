#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
DEFAULT_HOST_PORT="4113"
DEFAULT_CONTAINER_PORT="18789"
DEFAULT_RESTART_POLICY="unless-stopped"
EASYCLAW_REPO="https://github.com/moshall/easyclaw.git"
EASYCLAW_DEFAULT_WEB_PORT="4231"
DEFAULT_DEP_SET="npm uv"
DEFAULT_ENABLE_BIN_PERSIST="1"
DEFAULT_ENABLE_ENV_PERSIST="2"
DEFAULT_ENABLE_APT_CONFIG_PERSIST="2"
DEFAULT_ENABLE_CACHE_PERSIST="2"

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

run_cmd_brief() {
  local label="$1"
  shift
  printf '[RUN] %s\n' "${label}"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    "$@"
  fi
}

run_optional_step() {
  local label="$1"
  shift
  local rc
  set +e
  "$@"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log_error "${label}失败（已跳过，不影响主流程）"
    return "${rc}"
  fi
  return 0
}

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_error() {
  printf '[ERROR] %s\n' "$*" >&2
}

json_escape() {
  local raw="${1:-}"
  printf '%s' "${raw}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r//g; s/\n/\\n/g'
}

join_with_semicolon() {
  local out=""
  local item
  for item in "$@"; do
    [[ -z "${item}" ]] && continue
    if [[ -z "${out}" ]]; then
      out="${item}"
    else
      out="${out}; ${item}"
    fi
  done
  printf '%s\n' "${out}"
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
  printf '%s [%s] (回车使用默认值): ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
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
    value=$(sanitize_user_input "${value}")
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
    log_error "该项不能为空"
  done
}

read_container_name() {
  local prompt="$1"
  local value
  while true; do
    value=$(read_required "${prompt}")
    if [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
      printf '%s\n' "${value}"
      return
    fi
    log_error "容器名仅允许字母、数字、点、下划线、短横线，且必须以字母或数字开头"
  done
}

is_safe_path_text() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_./-]+$ ]]
}

read_choice_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  printf '%s [%s]: ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
}

read_menu_choice() {
  local prompt="$1"
  local value
  printf '%s: ' "${prompt}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
  printf '%s\n' "${value}"
}

clear_interactive_screen() {
  if [[ -t 1 && "${OPENCLAWCTL_NO_CLEAR:-0}" != "1" ]]; then
    printf '\033[H\033[2J'
  fi
}

press_enter_to_continue() {
  printf '按回车返回: ' >&2
  local dummy
  IFS= read -r dummy
}

sanitize_user_input() {
  local raw="${1:-}"
  # Remove control chars (e.g. ESC sequences from arrow keys) to avoid menu corruption.
  printf '%s' "${raw}" | awk '{gsub(/[[:cntrl:]]/, ""); printf "%s", $0}'
}

sanitize_port_mapping_input() {
  local raw="${1:-}"
  raw=$(sanitize_user_input "${raw}")
  # Remove common ANSI cursor fragments that may remain after ESC stripping (e.g. [A, [D).
  raw=$(printf '%s' "${raw}" | sed -E 's/\[[0-9;]*[A-Za-z]//g')
  printf '%s\n' "${raw}"
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
  local enable_bin_persist="${6:-${DEFAULT_ENABLE_BIN_PERSIST}}"
  local enable_env_persist="${7:-${DEFAULT_ENABLE_ENV_PERSIST}}"
  local extra_ports="${8:-}"
  local enable_apt_cfg_persist="${9:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local enable_cache_persist="${10:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local volume_args=()
  local port_args=("-p" "${host_port}:${container_port}")

  if [[ "${enable_bin_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/root-local-bin" "${data_dir}/runtime/root-go-bin"
    volume_args+=("-v" "${data_dir}/runtime/root-local-bin:/root/.local/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-go-bin:/root/go/bin")
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/usr-local-go" \
      "${data_dir}/runtime/usr-local-lib-node-modules" \
      "${data_dir}/runtime/root-local-lib" \
      "${data_dir}/runtime/root-local-share-uv" \
      "${data_dir}/runtime/root-local-pipx" \
      "${data_dir}/runtime/root-local-share-pipx" \
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
    volume_args+=("-v" "${data_dir}/runtime/usr-local-lib-node-modules:/usr/local/lib/node_modules")
    volume_args+=("-v" "${data_dir}/runtime/root-local-lib:/root/.local/lib")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-uv:/root/.local/share/uv")
    volume_args+=("-v" "${data_dir}/runtime/root-local-pipx:/root/.local/pipx")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-pipx:/root/.local/share/pipx")
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
    run_cmd mkdir -p "${data_dir}/runtime/root-npm-cache" "${data_dir}/runtime/root-go-pkg-mod"
    volume_args+=("-v" "${data_dir}/runtime/root-npm-cache:/root/.npm")
    volume_args+=("-v" "${data_dir}/runtime/root-go-pkg-mod:/root/go/pkg/mod")
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
    --restart "${DEFAULT_RESTART_POLICY}" \
    "${port_args[@]}" \
    -v "${data_dir}:/root/.openclaw" \
    "${volume_args[@]}" \
    --add-host=host.docker.internal:host-gateway \
    "${image}" \
    openclaw gateway run
}

normalize_extra_ports() {
  local raw="$1"
  local main_host_port="$2"
  local main_container_port="$3"
  local normalized=""
  local token

  raw="${raw//,/ }"
  raw=$(echo "${raw}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  [[ -z "${raw}" ]] && {
    echo ""
    return 0
  }

  for token in ${raw}; do
    token=$(echo "${token}" | tr '[:upper:]' '[:lower:]')
    if [[ ! "${token}" =~ ^[0-9]+:[0-9]+(/(tcp|udp))?$ ]]; then
      log_error "扩展端口格式无效: ${token}（示例: 5001:5001 或 6000:6000/udp）"
      return 1
    fi

    local host_part="${token%%:*}"
    local rest="${token#*:}"
    local container_part="${rest%%/*}"
    local proto="tcp"
    if [[ "${rest}" == *"/"* ]]; then
      proto="${rest##*/}"
    fi

    # Skip duplicates with primary mapping.
    if [[ "${host_part}" == "${main_host_port}" && "${container_part}" == "${main_container_port}" && "${proto}" == "tcp" ]]; then
      continue
    fi

    local canonical="${host_part}:${container_part}"
    [[ "${proto}" != "tcp" ]] && canonical="${canonical}/${proto}"

    case " ${normalized} " in
      *" ${canonical} "*) ;;
      *) normalized="${normalized}${normalized:+ }${canonical}" ;;
    esac
  done

  echo "${normalized}"
}

copy_dir_from_container_to_host() {
  local container_name="$1"
  local src_dir="$2"
  local dest_dir="$3"
  local label="$4"
  local rc

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd mkdir -p "${dest_dir}"
    run_cmd docker cp "${container_name}:${src_dir}/." "${dest_dir}/"
    return 0
  fi

  if ! container_exists "${container_name}"; then
    log_info "[迁移] 容器 ${container_name} 不存在，跳过 ${label}"
    return 0
  fi

  if ! docker exec "${container_name}" sh -lc "test -d '${src_dir}'" >/dev/null 2>&1; then
    log_info "[迁移] 未检测到 ${src_dir}，跳过 ${label}"
    return 0
  fi

  run_cmd mkdir -p "${dest_dir}"
  set +e
  print_cmd docker cp "${container_name}:${src_dir}/." "${dest_dir}/"
  docker cp "${container_name}:${src_dir}/." "${dest_dir}/"
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi

  log_info "[迁移] ${label} 复制遇到兼容性问题（常见于符号链接，如 node_modules），已自动切换兼容迁移模式"
  if ! docker exec "${container_name}" sh -lc 'command -v tar >/dev/null 2>&1'; then
    log_error "[迁移] 容器内缺少 tar，无法执行兼容迁移: ${label}"
    return 1
  fi

  local stream_script
  stream_script="cd '${src_dir}' && tar -cf - ."
  printf '[RUN] docker exec %s sh -lc <tar-stream-copy:%s> | tar -xf - -C %s\n' "${container_name}" "${src_dir}" "${dest_dir}"
  set +e
  docker exec "${container_name}" sh -lc "${stream_script}" | tar -xf - -C "${dest_dir}"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log_error "[迁移] tar 流兼容迁移失败: ${label}"
    return "${rc}"
  fi
  log_info "[迁移] 兼容迁移完成: ${label}"
  return 0
}

copy_file_from_container_to_host() {
  local container_name="$1"
  local src_file="$2"
  local dest_file="$3"
  local label="$4"
  local rc

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd mkdir -p "$(dirname "${dest_file}")"
    run_cmd docker cp "${container_name}:${src_file}" "${dest_file}"
    return 0
  fi

  if ! container_exists "${container_name}"; then
    log_info "[迁移] 容器 ${container_name} 不存在，跳过 ${label}"
    return 0
  fi

  if ! docker exec "${container_name}" sh -lc "test -f '${src_file}'" >/dev/null 2>&1; then
    log_info "[迁移] 未检测到 ${src_file}，跳过 ${label}"
    return 0
  fi

  run_cmd mkdir -p "$(dirname "${dest_file}")"
  set +e
  print_cmd docker cp "${container_name}:${src_file}" "${dest_file}"
  docker cp "${container_name}:${src_file}" "${dest_file}"
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi

  log_info "[迁移] ${label} 文件复制遇到兼容性问题，尝试 cat 流兼容迁移"
  set +e
  docker exec "${container_name}" sh -lc "cat '${src_file}'" > "${dest_file}"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log_error "[迁移] 文件兼容迁移失败: ${label}"
    return "${rc}"
  fi
  log_info "[迁移] 文件兼容迁移完成: ${label}"
  return 0
}

normalize_path_for_compare() {
  local path="$1"
  while [[ "${path}" != "/" && "${path}" == */ ]]; do
    path="${path%/}"
  done
  printf '%s\n' "${path}"
}

get_mount_source_for_destination() {
  local container_name="$1"
  local destination="$2"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi
  if ! container_exists "${container_name}"; then
    return 1
  fi

  local source
  source=$(docker inspect -f "{{range .Mounts}}{{if eq .Destination \"${destination}\"}}{{.Source}}{{end}}{{end}}" "${container_name}" 2>/dev/null || true)
  if [[ -n "${source}" ]]; then
    printf '%s\n' "${source}"
    return 0
  fi
  return 1
}

validate_runtime_target_path() {
  local data_dir="$1"
  local target_path="$2"
  case "${target_path}" in
    "${data_dir}/runtime/"*) return 0 ;;
    *)
      log_error "[迁移] 目标路径不在 runtime 目录下，已拒绝: ${target_path}"
      return 1
      ;;
  esac
}

should_skip_migration_for_path() {
  local container_name="$1"
  local destination="$2"
  local target_source="$3"
  local label="$4"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi

  local current_source
  current_source=$(get_mount_source_for_destination "${container_name}" "${destination}" || true)
  if [[ -z "${current_source}" ]]; then
    return 1
  fi

  local norm_current norm_target
  norm_current=$(normalize_path_for_compare "${current_source}")
  norm_target=$(normalize_path_for_compare "${target_source}")

  if [[ "${norm_current}" == "${norm_target}" ]]; then
    log_info "[迁移] ${label} 已持久化且路径一致，跳过迁移"
    return 0
  fi

  log_info "[迁移] ${label} 检测到持久化路径变化：${norm_current} -> ${norm_target}，将执行迁移"
  return 1
}

pre_upgrade_migrate_runtime_data() {
  local container_name="$1"
  local data_dir="$2"
  local enable_bin_persist="$3"
  local enable_env_persist="$4"
  local enable_apt_cfg_persist="${5:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local enable_cache_persist="${6:-${DEFAULT_ENABLE_CACHE_PERSIST}}"

  if [[ "${enable_bin_persist}" != "1" && "${enable_env_persist}" != "1" && "${enable_apt_cfg_persist}" != "1" && "${enable_cache_persist}" != "1" ]]; then
    log_info "[迁移] 本次未启用 runtime 持久化，跳过升级前迁移"
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 0 ]] && ! container_exists "${container_name}"; then
    log_info "[迁移] 未找到历史容器，跳过升级前迁移"
    return 0
  fi

  log_info "[迁移] 开始执行升级前 runtime 数据迁移（删除旧容器前）"

  local target_root_local_bin="${data_dir}/runtime/root-local-bin"
  local target_root_go_bin="${data_dir}/runtime/root-go-bin"
  local target_usr_local_go="${data_dir}/runtime/usr-local-go"
  local target_usr_local_lib_node_modules="${data_dir}/runtime/usr-local-lib-node-modules"
  local target_root_local_lib="${data_dir}/runtime/root-local-lib"
  local target_root_local_share_uv="${data_dir}/runtime/root-local-share-uv"
  local target_root_local_pipx="${data_dir}/runtime/root-local-pipx"
  local target_root_local_share_pipx="${data_dir}/runtime/root-local-share-pipx"
  local target_root_config="${data_dir}/runtime/root-config"
  local target_root_ssh="${data_dir}/runtime/root-ssh"
  local target_root_gitconfig="${data_dir}/runtime/root-gitconfig"
  local target_root_docker="${data_dir}/runtime/root-docker"
  local target_root_aws="${data_dir}/runtime/root-aws"
  local target_root_kube="${data_dir}/runtime/root-kube"
  local target_root_netrc="${data_dir}/runtime/root-netrc"
  local target_root_npmrc="${data_dir}/runtime/root-npmrc"
  local target_root_pypirc="${data_dir}/runtime/root-pypirc"
  local target_etc_apt_sources_list_d="${data_dir}/runtime/etc-apt-sources-list-d"
  local target_etc_apt_keyrings="${data_dir}/runtime/etc-apt-keyrings"
  local target_root_npm_cache="${data_dir}/runtime/root-npm-cache"
  local target_root_go_pkg_mod="${data_dir}/runtime/root-go-pkg-mod"

  validate_runtime_target_path "${data_dir}" "${target_root_local_bin}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_go_bin}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_usr_local_go}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_usr_local_lib_node_modules}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_lib}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_share_uv}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_pipx}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_share_pipx}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_config}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_ssh}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_gitconfig}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_docker}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_aws}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_kube}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_netrc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_npmrc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_pypirc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_etc_apt_sources_list_d}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_etc_apt_keyrings}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_npm_cache}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_go_pkg_mod}" || return 1

  if [[ "${enable_bin_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/bin" "${target_root_local_bin}" "bin:/root/.local/bin"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/bin" "${target_root_local_bin}" "bin:/root/.local/bin" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/go/bin" "${target_root_go_bin}" "bin:/root/go/bin"; then
      copy_dir_from_container_to_host "${container_name}" "/root/go/bin" "${target_root_go_bin}" "bin:/root/go/bin" || return 1
    fi
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/usr/local/go" "${target_usr_local_go}" "env:/usr/local/go"; then
      copy_dir_from_container_to_host "${container_name}" "/usr/local/go" "${target_usr_local_go}" "env:/usr/local/go" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/usr/local/lib/node_modules" "${target_usr_local_lib_node_modules}" "env:/usr/local/lib/node_modules"; then
      copy_dir_from_container_to_host "${container_name}" "/usr/local/lib/node_modules" "${target_usr_local_lib_node_modules}" "env:/usr/local/lib/node_modules" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/lib" "${target_root_local_lib}" "env:/root/.local/lib"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/lib" "${target_root_local_lib}" "env:/root/.local/lib" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/share/uv" "${target_root_local_share_uv}" "env:/root/.local/share/uv"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/share/uv" "${target_root_local_share_uv}" "env:/root/.local/share/uv" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/pipx" "${target_root_local_pipx}" "env:/root/.local/pipx"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/pipx" "${target_root_local_pipx}" "env:/root/.local/pipx" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/share/pipx" "${target_root_local_share_pipx}" "env:/root/.local/share/pipx"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/share/pipx" "${target_root_local_share_pipx}" "env:/root/.local/share/pipx" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.config" "${target_root_config}" "env:/root/.config"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.config" "${target_root_config}" "env:/root/.config" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.ssh" "${target_root_ssh}" "env:/root/.ssh"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.ssh" "${target_root_ssh}" "env:/root/.ssh" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.gitconfig" "${target_root_gitconfig}" "env:/root/.gitconfig"; then
      copy_file_from_container_to_host "${container_name}" "/root/.gitconfig" "${target_root_gitconfig}" "env:/root/.gitconfig" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.docker" "${target_root_docker}" "env:/root/.docker"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.docker" "${target_root_docker}" "env:/root/.docker" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.aws" "${target_root_aws}" "env:/root/.aws"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.aws" "${target_root_aws}" "env:/root/.aws" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.kube" "${target_root_kube}" "env:/root/.kube"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.kube" "${target_root_kube}" "env:/root/.kube" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.netrc" "${target_root_netrc}" "env:/root/.netrc"; then
      copy_file_from_container_to_host "${container_name}" "/root/.netrc" "${target_root_netrc}" "env:/root/.netrc" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.npmrc" "${target_root_npmrc}" "env:/root/.npmrc"; then
      copy_file_from_container_to_host "${container_name}" "/root/.npmrc" "${target_root_npmrc}" "env:/root/.npmrc" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.pypirc" "${target_root_pypirc}" "env:/root/.pypirc"; then
      copy_file_from_container_to_host "${container_name}" "/root/.pypirc" "${target_root_pypirc}" "env:/root/.pypirc" || return 1
    fi
  fi

  if [[ "${enable_apt_cfg_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/etc/apt/sources.list.d" "${target_etc_apt_sources_list_d}" "aptcfg:/etc/apt/sources.list.d"; then
      copy_dir_from_container_to_host "${container_name}" "/etc/apt/sources.list.d" "${target_etc_apt_sources_list_d}" "aptcfg:/etc/apt/sources.list.d" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/etc/apt/keyrings" "${target_etc_apt_keyrings}" "aptcfg:/etc/apt/keyrings"; then
      copy_dir_from_container_to_host "${container_name}" "/etc/apt/keyrings" "${target_etc_apt_keyrings}" "aptcfg:/etc/apt/keyrings" || return 1
    fi
  fi

  if [[ "${enable_cache_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/root/.npm" "${target_root_npm_cache}" "cache:/root/.npm"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.npm" "${target_root_npm_cache}" "cache:/root/.npm" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/go/pkg/mod" "${target_root_go_pkg_mod}" "cache:/root/go/pkg/mod"; then
      copy_dir_from_container_to_host "${container_name}" "/root/go/pkg/mod" "${target_root_go_pkg_mod}" "cache:/root/go/pkg/mod" || return 1
    fi
  fi

  log_info "[迁移] 升级前 runtime 数据迁移完成"
  return 0
}

easyclaw_target_dir() {
  local data_dir="$1"
  echo "${data_dir}/software/easyclaw"
}

easyclaw_container_install_dir() {
  echo "/root/.openclaw/software/easyclaw"
}

ensure_easyclaw_web_port_mapping() {
  local enabled="$1"
  local host_port="$2"
  local container_port="$3"
  local extra_ports="${4:-}"

  if [[ "${enabled}" != "1" ]]; then
    echo "${extra_ports}"
    return
  fi

  if [[ "${host_port}" == "${EASYCLAW_DEFAULT_WEB_PORT}" || "${container_port}" == "${EASYCLAW_DEFAULT_WEB_PORT}" ]]; then
    echo "${extra_ports}"
    return
  fi

  local token host_part container_part proto
  for token in ${extra_ports}; do
    [[ -z "${token}" ]] && continue
    host_part="${token%%:*}"
    container_part="${token#*:}"
    proto="tcp"
    if [[ "${container_part}" == */* ]]; then
      proto="${container_part#*/}"
      container_part="${container_part%%/*}"
    fi
    if [[ "${host_part}" == "${EASYCLAW_DEFAULT_WEB_PORT}" || "${container_part}" == "${EASYCLAW_DEFAULT_WEB_PORT}" ]]; then
      echo "${extra_ports}"
      return
    fi
  done

  echo "${extra_ports}${extra_ports:+ }${EASYCLAW_DEFAULT_WEB_PORT}:${EASYCLAW_DEFAULT_WEB_PORT}"
}

should_enable_easyclaw_web_port() {
  local requested="$1"
  local container_name="${2:-}"
  local data_dir="${3:-}"

  if [[ "${requested}" == "1" ]]; then
    return 0
  fi

  if [[ -n "${data_dir}" && -e "$(easyclaw_target_dir "${data_dir}")" ]]; then
    return 0
  fi

  if [[ -n "${container_name}" ]] && docker exec "${container_name}" sh -lc 'command -v easyclaw >/dev/null 2>&1 || [ -e /root/.openclaw/software/easyclaw/install.sh ]' >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

run_easyclaw_install_script() {
  local container_name="$1"
  local script='set -e
need_python=0
if ! command -v python3 >/dev/null 2>&1; then
  need_python=1
fi
need_venv=0
if command -v python3 >/dev/null 2>&1; then
  python3 -m venv -h >/dev/null 2>&1 || need_venv=1
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
if [ "$need_python" -eq 1 ] || [ "$need_venv" -eq 1 ]; then
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y python3 python3-venv
      ;;
    apk)
      apk add --no-cache python3 py3-pip
      ;;
    dnf)
      dnf install -y python3 python3-pip python3-virtualenv || dnf install -y python3 python3-pip
      ;;
    yum)
      yum install -y python3 python3-pip python3-virtualenv || yum install -y python3 python3-pip
      ;;
    *)
      echo "[easyclaw] no supported package manager found for python3/python3-venv"
      exit 1
      ;;
  esac
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

deps_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/deps.profile"
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
ensure_path_now /root/.local/bin /usr/local/go/bin /root/go/bin /usr/local/bin
persist_path_dir /root/.local/bin
persist_path_dir /usr/local/go/bin
persist_path_dir /root/go/bin
[ -x /usr/local/go/bin/go ] && ln -sf /usr/local/go/bin/go /usr/local/bin/go || true
[ -x /root/.local/bin/uv ] && ln -sf /root/.local/bin/uv /usr/local/bin/uv || true
sync_user_bin_dir /root/.local/bin
sync_user_bin_dir /root/go/bin
true'

  run_cmd_brief "docker exec ${container_name} sh -lc <runtime-path-repair-script>" \
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
  local extra_deps="$4"
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
    python3)
      [ -x /usr/bin/python3 ] || [ -x /usr/local/bin/python3 ]
      ;;
    *)
      return 1
      ;;
  esac
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

# Best-effort PATH repair for "installed but not in PATH" cases (especially go/uv)
ensure_path_now /root/.local/bin /usr/local/bin /usr/local/go/bin /root/go/bin

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
need_uv=0
need_go=0
contains_dep npm && ! has_effective npm && need_node=1
if ! has_effective python3 && (contains_dep python3 || contains_dep uv); then
  need_python=1
fi
contains_dep uv && ! has_effective uv && need_uv=1
contains_dep go && ! has_effective go && need_go=1

if [ "$need_node" -eq 0 ] && [ "$need_python" -eq 0 ] && [ "$need_uv" -eq 0 ] && [ "$need_go" -eq 0 ]; then
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
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3 python3-pip"
      [ -n "$pkgs" ] && apt-get install -y $pkgs
      ;;
    apk)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3 py3-pip"
      [ -n "$pkgs" ] && apk add --no-cache $pkgs
      ;;
    dnf)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3 python3-pip"
      [ -n "$pkgs" ] && dnf install -y $pkgs
      ;;
    yum)
      pkgs=""
      [ "$need_node" -eq 1 ] && pkgs="$pkgs nodejs npm"
      [ "$need_python" -eq 1 ] && pkgs="$pkgs python3 python3-pip"
      [ -n "$pkgs" ] && yum install -y $pkgs
      ;;
  esac
}

if [ "$need_node" -eq 1 ] || [ "$need_python" -eq 1 ]; then
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

for dep in $DEPS; do
  case "$dep" in
    npm|python3|uv|go) ;;
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
sync_user_bin_dir /root/.local/bin
sync_user_bin_dir /root/go/bin

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

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '%s\n' "${fallback}"
    return
  fi

  local detected
  detected=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/root/.openclaw"}}{{.Source}}{{end}}{{end}}' "${name}" 2>/dev/null || true)
  if [[ -n "${detected}" ]] && is_safe_path_text "${detected}"; then
    printf '%s\n' "${detected}"
  else
    if [[ -n "${detected}" ]]; then
      log_info "检测到持久化目录包含异常字符，已回退到默认目录"
    fi
    printf '%s\n' "${fallback}"
  fi
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
    if has_mount_destination "${name}" "/root/.local/bin" || has_mount_destination "${name}" "/root/go/bin"; then
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
    if has_mount_destination "${name}" "/root/.npm" || has_mount_destination "${name}" "/root/go/pkg/mod"; then
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
for c in npm uv go python3; do
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

    if has_mount_destination "${name}" "/root/.local/bin" || has_mount_destination "${name}" "/root/go/bin"; then
      bin_mounted="是"
    fi

    if has_mount_destination "${name}" "/usr/local/go" || \
      has_mount_destination "${name}" "/root/.local/share/uv" || \
      has_mount_destination "${name}" "/root/.local/pipx" || \
      has_mount_destination "${name}" "/root/.local/share/pipx" || \
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
    if has_mount_destination "${name}" "/root/.npm" || has_mount_destination "${name}" "/root/go/pkg/mod"; then
      cache_mounted="是"
    fi
  fi

  [[ -d "${data_dir}/runtime" ]] && runtime_dir_text="是"

  printf '\n=== 升级前环境检测 ===\n'
  echo "容器存在: ${exists_text}"
  echo "runtime 目录存在: ${runtime_dir_text} (${data_dir}/runtime)"
  echo "已检测依赖: ${deps_text}"
  echo "当前持久化挂载: bin=${bin_mounted}, env=${env_mounted}"
  echo "扩展环境挂载: npm全局(node_modules)=${node_mod_mounted}, pip用户库(/root/.local/lib)=${py_user_lib_mounted}, 授权配置(.config/.ssh/.gitconfig/.docker/.aws/.kube/.netrc/.npmrc/.pypirc)=${auth_cfg_mounted}, APT源Key(${apt_cfg_mounted}), 缓存(.npm/go mod)=${cache_mounted}"

  local -a hints=()
  if [[ "${exists_text}" == "是" ]]; then
    if dep_enabled "${deps_text}" "go" && [[ "${env_mounted}" != "是" ]]; then
      hints+=("检测到 go 已安装但 env 未持久化，建议在本次升级开启 env。")
    fi
    if dep_enabled "${deps_text}" "uv" && [[ "${bin_mounted}" != "是" && "${env_mounted}" != "是" ]]; then
      hints+=("检测到 uv 已安装但未持久化，建议在本次升级开启 bin/env。")
    fi
    if dep_enabled "${deps_text}" "npm" && [[ "${node_mod_mounted}" != "是" ]]; then
      hints+=("检测到 npm 可用，若依赖 npm -g 包建议开启 env（持久化 /usr/local/lib/node_modules）。")
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
      hints+=("若希望减少 npm/go 二次下载时间，可开启缓存持久化（/root/.npm 与 /root/go/pkg/mod）。")
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
    log_error "[preflight] docker 命令不可用"
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
    if [[ -n "${existing_data}" && "${existing_data}" != "${data_dir}" ]]; then
      log_info "[preflight] 注意: 当前容器数据目录为 ${existing_data}，与本次选择不同"
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

  dep_enabled "${normalized_base}" "npm" && npm_default="1"
  dep_enabled "${normalized_base}" "uv" && uv_default="1"
  dep_enabled "${normalized_base}" "go" && go_default="1"

  echo "依赖选择（默认 npm+uv，go 可选）:" >&2
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

  local extra_deps
  extra_deps=$(read_with_default "额外依赖命令（逗号分隔，可留空）" "")

  build_dep_set_from_choices "${npm_choice}" "${uv_choice}" "${go_choice}" "${extra_deps}"
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
  if [[ -n "${name}" ]]; then
    echo "/opt/1panel/apps/${name}"
  else
    echo "/opt/1panel/apps/<容器名>"
  fi
}

install_version_group_summary() {
  local image="$1"
  local source_choice="${2:-}"
  local channel_choice="${3:-}"
  if [[ -n "${source_choice}" || -n "${channel_choice}" ]]; then
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
  echo "npm=$(dep_choice_label "${dep_set}" "npm"), uv=$(dep_choice_label "${dep_set}" "uv"), go=$(dep_choice_label "${dep_set}" "go")"
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
  local lines=()

  if [[ "${bin_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/root-local-bin")
    lines+=("${data_dir}/runtime/root-go-bin")
  fi
  if [[ "${env_choice}" == "1" ]]; then
    lines+=("${data_dir}/runtime/usr-local-go")
    lines+=("${data_dir}/runtime/usr-local-lib-node-modules")
    lines+=("${data_dir}/runtime/root-local-lib")
    lines+=("${data_dir}/runtime/root-local-share-uv")
    lines+=("${data_dir}/runtime/root-local-pipx")
    lines+=("${data_dir}/runtime/root-local-share-pipx")
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
  echo "若已启动 Web UI，可访问：http://Your Host IP:${EASYCLAW_DEFAULT_WEB_PORT}/"
  echo
  echo "后续可使用本脚本进行更新检查并升级程序"
  echo "持久化信息在升级后会继续保留"
  echo "==============================="
}

install_wizard() {
  local source_choice=""
  local channel_choice=""
  local image=""
  local host_port="${DEFAULT_HOST_PORT}"
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
  local extra_ports=""

  while true; do
    clear_interactive_screen
    printf '\n=== 🚀 安装新实例 ===\n'
    echo "按编号编辑，修改后会回到这张总表；c 确认执行，q 返回主菜单"
    echo
    echo "1) 📦 版本镜像选择: $(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}")"
    echo "2) 🐳 容器名: $(value_or_unset "${name}")"
    echo "3) 💾 持久化目录管理: $(data_persistence_group_summary "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "$(install_default_data_dir_desc "${name}")")"
    echo "4) 🌐 网络设置: $(network_group_summary "${bind_choice}" "${host_port}" "${container_port}" "${extra_ports}" "${easy_choice}")"
    echo "5) 🧩 功能加强: $(feature_group_summary "${easy_choice}" "${deps_install_choice}" "${target_deps}")"
    echo "6) 🔐 鉴权方式管理: $(auth_group_summary "${token_mode}" "${token_manual}")"
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
        echo "  1) 稳定版"
        echo "  2) 最新版"
        channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
        image=$(resolve_image "${source_choice}" "${channel_choice}") || image=""
        log_info "已更新：$(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}")"
        ;;
      2)
        name=$(read_container_name "Docker 容器名")
        log_info "已更新：容器名=${name}"
        ;;
      3)
        data_dir=$(read_with_default "持久化目录" "${data_dir:-/opt/1panel/apps/${name:-openclaw}}")
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
        echo "是否启用 缓存持久化(.npm/go mod):"
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
          data_dir="/opt/1panel/apps/${name}"
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
        printf '\n--- 执行清单（确认前） ---\n'
        echo "镜像: ${image}"
        echo "容器名: ${name}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录: ${data_dir}"
        echo "网络绑定: ${gateway_bind}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod): $(choice_to_yes_no "${cache_persist_choice}")"
        echo "EasyClaw: $(choice_to_yes_no "${easy_choice}")"
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

        if ! run_preflight_checks "install" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
          log_error "preflight 未通过，请修复后重试"
          continue
        fi

        run_cmd mkdir -p "${data_dir}"
        run_cmd docker pull "${image}"
        remove_container_if_exists "${name}"
        bootstrap_openclaw_config "${image}" "${data_dir}" "${container_port}" "${gateway_bind}" "${token}"
        if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
          if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
            log_error "APT 源目录初始化失败，已中止安装以避免空源配置"
            continue
          fi
        fi
        run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
        save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
        local -a install_nonfatal_issues=()
        if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
          install_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
        fi
        if [[ "${env_persist_choice}" == "1" ]]; then
          if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
            install_nonfatal_issues+=("授权目录权限修正失败")
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

        printf 'TOKEN=%s\n' "${token}"
        printf 'URL=http://<server-ip>:%s/?token=%s\n' "${host_port}" "${token}"
        local install_version install_status_text install_runtime_paths install_deps_installed
        install_version=$(detect_openclaw_version "${name}")
        install_status_text=$(get_container_status_text "${name}")
        install_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}")
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
  printf '\n=== 🔄 升级已有实例 ===\n'
  echo "按编号编辑，修改后会回到这张总表；升级会尽量保留原有数据、挂载和运行环境"
  local name
  name=$(read_container_name "请输入要升级的容器名")

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  local detected_host_port="${port_pair%%,*}"
  local detected_container_port="${port_pair##*,}"

  local source_choice=""
  local channel_choice=""
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
    echo "1) 📦 目标版本: $(value_or_unset "${image}")"
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
        echo "  1) 稳定版"
        echo "  2) 最新版"
        channel_choice=$(read_choice_default "请选择" "${channel_choice:-1}")
        image=$(resolve_image "${source_choice}" "${channel_choice}") || image=""
        log_info "已更新：$(install_version_group_summary "${image}" "${source_choice}" "${channel_choice}")"
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
        echo "是否启用 缓存持久化(.npm/go mod):"
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

        printf '\n--- 执行清单（确认前） ---\n'
        echo "容器名: ${name}"
        echo "目标镜像: ${image}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录(保留): ${data_dir}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod): $(choice_to_yes_no "${cache_persist_choice}")"
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

        if ! run_preflight_checks "upgrade" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
          log_error "preflight 未通过，请修复后重试"
          continue
        fi

        run_cmd mkdir -p "${data_dir}"
        run_cmd docker pull "${image}"

        local -a upgrade_nonfatal_issues=()

        if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
          log_error "升级前 runtime 数据迁移失败；为避免数据丢失，已中止本次升级"
          continue
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
            continue
          fi
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
        upgrade_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}")
        upgrade_deps_installed=$(detect_installed_deps_summary "${name}" "${upgrade_dep_set}")
        upgrade_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
        upgrade_token=$(detect_token_from_config "${data_dir}")
        print_human_summary "upgrade" "${name}" "${upgrade_version}" "${upgrade_status_text}" "${data_dir}" "${upgrade_runtime_paths}" "${upgrade_deps_installed}" "${upgrade_gateway_bind}" "${upgrade_token}" "${host_port}" "${extra_ports}"
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
  printf '\n=== 🛠️ 调整或重建实例 ===\n'
  echo "适用于新增端口、补持久化、调整挂载后需要安全重建容器的场景"
  local name
  name=$(read_container_name "请输入要重建的容器名")

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local port_pair
  port_pair=$(detect_existing_ports "${name}" "${DEFAULT_HOST_PORT}" "${DEFAULT_CONTAINER_PORT}")
  local detected_host_port="${port_pair%%,*}"
  local detected_container_port="${port_pair##*,}"

  local image
  image=$(detect_existing_image "${name}" "docker.io/openclaw/openclaw:latest")

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
        echo "是否启用 缓存持久化(.npm/go mod):"
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

        printf '\n--- 执行清单（确认前） ---\n'
        echo "容器名: ${name}"
        echo "目标镜像: ${image}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录(保留): ${data_dir}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "APT源Key 持久化: $(choice_to_yes_no "${apt_cfg_persist_choice}")"
        echo "缓存持久化(.npm/go mod): $(choice_to_yes_no "${cache_persist_choice}")"
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

        if ! run_preflight_checks "rebuild" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
          log_error "preflight 未通过，请修复后重试"
          continue
        fi

        run_cmd mkdir -p "${data_dir}"
        run_cmd docker pull "${image}"

        local -a rebuild_nonfatal_issues=()
        if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
          log_error "重建前 runtime 数据迁移失败；为避免数据丢失，已中止本次重建"
          continue
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
            continue
          fi
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
        rebuild_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}")
        rebuild_deps_installed=$(detect_installed_deps_summary "${name}" "${rebuild_dep_set}")
        rebuild_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
        rebuild_token=$(detect_token_from_config "${data_dir}")
        print_human_summary "rebuild" "${name}" "${rebuild_version}" "${rebuild_status_text}" "${data_dir}" "${rebuild_runtime_paths}" "${rebuild_deps_installed}" "${rebuild_gateway_bind}" "${rebuild_token}" "${host_port}" "${extra_ports}"
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
  printf '\n=== 🗑️ 卸载实例 ===\n'
  echo "流程：选择卸载方式 -> 二次确认容器名 -> 执行"
  local name
  name=$(read_container_name "请输入要卸载的容器名")

  local default_data_dir="/opt/1panel/apps/${name}"
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
  printf '\n=== 📦 管理 EasyClaw 工具 ===\n'
  local name
  name=$(read_container_name "请输入容器名（用于定位持久化目录）")

  local default_data_dir="/opt/1panel/apps/${name}"
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

  if ! run_preflight_checks "easyclaw-upgrade" "${name}" "${data_dir}"; then
    log_error "preflight 未通过，请修复后重试"
    return
  fi

  local -a easy_nonfatal_issues=()
  if ! run_optional_step "EasyClaw 检查升级" check_and_upgrade_easyclaw "${name}" "${data_dir}"; then
    easy_nonfatal_issues+=("EasyClaw 检查升级失败")
  fi
  local easy_status="success"
  [[ "${#easy_nonfatal_issues[@]}" -gt 0 ]] && easy_status="success_with_warnings"
  write_last_report "easyclaw-upgrade" "${easy_status}" "${name}" "${data_dir}" "" "" "" "" "" "${easy_nonfatal_issues[@]}"
}

deps_manage_wizard() {
  printf '\n=== 🔧 检查或补齐运行环境 ===\n'
  echo "提示：用于单独检查或补齐容器依赖，不重建 OpenClaw 容器。"
  local name
  name=$(read_container_name "请输入容器名")

  local default_data_dir="/opt/1panel/apps/${name}"
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
