#!/usr/bin/env bash

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

is_host_port_available() {
  local port="$1"
  if [[ -n "${OPENCLAWCTL_TEST_OCCUPIED_PORTS:-}" ]]; then
    local occupied normalized_port
    normalized_port=$(printf '%s' "${port}" | tr -d '[:space:]')
    for occupied in ${OPENCLAWCTL_TEST_OCCUPIED_PORTS//,/ }; do
      occupied=$(printf '%s' "${occupied}" | tr -d '[:space:]')
      [[ -z "${occupied}" ]] && continue
      if [[ "${normalized_port}" == "${occupied}" ]]; then
        return 1
      fi
    done
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi

  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ":[0-9]*${port}[[:space:]]" && return 1
    ss -uln 2>/dev/null | grep -q ":[0-9]*${port}[[:space:]]" && return 1
    return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | grep -q ":${port}[[:space:]]" && return 1
    netstat -uln 2>/dev/null | grep -q ":${port}[[:space:]]" && return 1
    return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | awk '{print $9}' | grep -Eq "[:.]${port}$" && return 1
    lsof -iUDP -P -n 2>/dev/null | awk '{print $9}' | grep -Eq "[:.]${port}$" && return 1
    return 0
  fi
  return 0
}

discovered_config_mounts_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/discovered-config.mounts"
}

persist_trim_spaces() {
  local raw="${1:-}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  printf '%s\n' "${raw}"
}

discovered_config_host_rel_for_container_path() {
  local container_path="$1"
  container_path=$(normalize_path_for_compare "${container_path}")
  printf 'runtime/discovered-config%s\n' "${container_path}"
}

append_unique_lines() {
  local current="$1"
  local candidate="$2"
  [[ -n "${candidate}" ]] || {
    printf '%s\n' "${current}"
    return 0
  }
  if [[ -z "${current}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi
  while IFS= read -r line; do
    [[ "${line}" == "${candidate}" ]] && {
      printf '%s\n' "${current}"
      return 0
    }
  done <<< "${current}"
  printf '%s\n%s\n' "${current}" "${candidate}"
}

is_excluded_discovered_config_path() {
  local path="$1"
  case "${path}" in
    /root/.openclaw|/root/.local|/root/.cache|/root/.npm|/root/.cargo|/root/.rustup|/root/.config|/root/.ssh|/root/.docker|/root/.aws|/root/.kube|/root/.gitconfig|/root/.netrc|/root/.npmrc|/root/.pypirc|/root/.bash_history|/root/.bashrc|/root/.bash_logout|/root/.profile|/root/.zshrc|/root/.zprofile|/root/.wget-hsts|/root/.python_history)
      return 0
      ;;
  esac
  return 1
}

discover_additional_config_paths() {
  local container_name="$1"
  local raw=""
  local out=""

  if [[ -n "${OPENCLAWCTL_TEST_DISCOVERED_CONFIG_PATHS:-}" ]]; then
    raw=$(printf '%s\n' "${OPENCLAWCTL_TEST_DISCOVERED_CONFIG_PATHS}" | tr ',' '\n')
  else
    [[ -n "${container_name}" ]] || {
      printf '%s\n' ""
      return 0
    }
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      printf '%s\n' ""
      return 0
    fi
    command -v docker >/dev/null 2>&1 || {
      printf '%s\n' ""
      return 0
    }
    raw=$(docker exec "${container_name}" sh -lc 'find /root -maxdepth 1 -mindepth 1 -name ".*" 2>/dev/null | sort -u' 2>/dev/null || true)
  fi

  local path
  while IFS= read -r path; do
    path=$(persist_trim_spaces "${path}")
    [[ -n "${path}" ]] || continue
    [[ "${path}" == /root/.* ]] || continue
    is_excluded_discovered_config_path "${path}" && continue
    out=$(append_unique_lines "${out}" "$(normalize_path_for_compare "${path}")")
  done <<< "${raw}"

  printf '%s\n' "${out}"
}

list_discovered_config_mount_pairs() {
  local data_dir="$1"
  local mounts_file
  mounts_file=$(discovered_config_mounts_path "${data_dir}")
  [[ -f "${mounts_file}" ]] || return 0

  local line container_path host_rel host_abs
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    IFS='|' read -r container_path host_rel <<< "${line}"
    container_path=$(persist_trim_spaces "${container_path}")
    host_rel=$(persist_trim_spaces "${host_rel}")
    [[ -n "${container_path}" && -n "${host_rel}" ]] || continue
    [[ "${container_path}" == /root/* ]] || continue
    host_abs="${data_dir}/${host_rel}"
    if [[ "${DRY_RUN}" -eq 0 && ! -e "${host_abs}" ]]; then
      continue
    fi
    printf '%s|%s\n' "${host_abs}" "${container_path}"
  done < "${mounts_file}"
}

save_discovered_config_mounts() {
  local data_dir="$1"
  local entries="$2"
  local mounts_file
  mounts_file=$(discovered_config_mounts_path "${data_dir}")

  if [[ -z "${entries}" ]]; then
    return 0
  fi

  run_cmd mkdir -p "$(dirname "${mounts_file}")"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "[迁移] 额外配置挂载清单将写入: ${mounts_file}"
    return 0
  fi

  printf '%s\n' "${entries}" > "${mounts_file}"
}

collect_and_migrate_discovered_config_paths() {
  local container_name="$1"
  local data_dir="$2"
  local discovered_paths
  discovered_paths=$(discover_additional_config_paths "${container_name}")
  [[ -n "${discovered_paths}" ]] || return 0

  log_info "[迁移] 发现额外配置路径候选（将写入清单并迁移）"

  local entries=""
  local path
  while IFS= read -r path; do
    path=$(persist_trim_spaces "${path}")
    [[ -n "${path}" ]] || continue
    [[ "${path}" == /root/* ]] || continue

    local host_rel host_abs
    host_rel=$(discovered_config_host_rel_for_container_path "${path}")
    host_abs="${data_dir}/${host_rel}"
    validate_runtime_target_path "${data_dir}" "${host_abs}" || return 1

    if [[ "${DRY_RUN}" -eq 1 ]]; then
      run_cmd mkdir -p "$(dirname "${host_abs}")"
      run_cmd docker cp "${container_name}:${path}" "${host_abs}"
      entries=$(append_unique_lines "${entries}" "${path}|${host_rel}")
      continue
    fi

    if docker exec "${container_name}" sh -lc "test -d '${path}'" >/dev/null 2>&1; then
      copy_dir_from_container_to_host "${container_name}" "${path}" "${host_abs}" "config:${path}" || return 1
      entries=$(append_unique_lines "${entries}" "${path}|${host_rel}")
      continue
    fi
    if docker exec "${container_name}" sh -lc "test -f '${path}'" >/dev/null 2>&1; then
      copy_file_from_container_to_host "${container_name}" "${path}" "${host_abs}" "config:${path}" || return 1
      entries=$(append_unique_lines "${entries}" "${path}|${host_rel}")
      continue
    fi
  done <<< "${discovered_paths}"

  save_discovered_config_mounts "${data_dir}" "${entries}"
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
  local image="$3"
  local enable_bin_persist="$4"
  local enable_env_persist="$5"
  local enable_apt_cfg_persist="${6:-${DEFAULT_ENABLE_APT_CONFIG_PERSIST}}"
  local enable_cache_persist="${7:-${DEFAULT_ENABLE_CACHE_PERSIST}}"
  local persist_node_modules_mount="1"

  if should_persist_node_modules_mount "${image}"; then
    persist_node_modules_mount="1"
  else
    persist_node_modules_mount="0"
  fi

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
  local target_root_cargo_bin="${data_dir}/runtime/root-cargo-bin"
  local target_usr_local_go="${data_dir}/runtime/usr-local-go"
  local target_usr_local_lib_node_modules="${data_dir}/runtime/usr-local-lib-node-modules"
  local target_root_local_lib="${data_dir}/runtime/root-local-lib"
  local target_root_local_share_uv="${data_dir}/runtime/root-local-share-uv"
  local target_root_local_pipx="${data_dir}/runtime/root-local-pipx"
  local target_root_local_share_pipx="${data_dir}/runtime/root-local-share-pipx"
  local target_root_pip_config="${data_dir}/runtime/root-pip-config"
  local target_root_rustup="${data_dir}/runtime/root-rustup"
  local target_root_config="${data_dir}/runtime/root-config"
  local target_root_ssh="${data_dir}/runtime/root-ssh"
  local target_root_gitconfig="${data_dir}/runtime/root-gitconfig"
  local target_root_docker="${data_dir}/runtime/root-docker"
  local target_root_aws="${data_dir}/runtime/root-aws"
  local target_root_kube="${data_dir}/runtime/root-kube"
  local target_root_netrc="${data_dir}/runtime/root-netrc"
  local target_root_npmrc="${data_dir}/runtime/root-npmrc"
  local target_root_pypirc="${data_dir}/runtime/root-pypirc"
  local target_root_cargo_config="${data_dir}/runtime/root-cargo-config"
  local target_root_cargo_config_toml="${data_dir}/runtime/root-cargo-config-toml"
  local target_etc_apt_sources_list_d="${data_dir}/runtime/etc-apt-sources-list-d"
  local target_etc_apt_keyrings="${data_dir}/runtime/etc-apt-keyrings"
  local target_root_npm_cache="${data_dir}/runtime/root-npm-cache"
  local target_root_go_pkg_mod="${data_dir}/runtime/root-go-pkg-mod"
  local target_root_cargo_registry="${data_dir}/runtime/root-cargo-registry"
  local target_root_cargo_git="${data_dir}/runtime/root-cargo-git"

  validate_runtime_target_path "${data_dir}" "${target_root_local_bin}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_go_bin}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_cargo_bin}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_usr_local_go}" || return 1
  if [[ "${persist_node_modules_mount}" == "1" ]]; then
    validate_runtime_target_path "${data_dir}" "${target_usr_local_lib_node_modules}" || return 1
  fi
  validate_runtime_target_path "${data_dir}" "${target_root_local_lib}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_share_uv}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_pipx}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_local_share_pipx}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_pip_config}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_rustup}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_config}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_ssh}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_gitconfig}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_docker}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_aws}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_kube}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_netrc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_npmrc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_pypirc}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_cargo_config}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_cargo_config_toml}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_etc_apt_sources_list_d}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_etc_apt_keyrings}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_npm_cache}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_go_pkg_mod}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_cargo_registry}" || return 1
  validate_runtime_target_path "${data_dir}" "${target_root_cargo_git}" || return 1

  if [[ "${enable_bin_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/root/.local/bin" "${target_root_local_bin}" "bin:/root/.local/bin"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.local/bin" "${target_root_local_bin}" "bin:/root/.local/bin" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/go/bin" "${target_root_go_bin}" "bin:/root/go/bin"; then
      copy_dir_from_container_to_host "${container_name}" "/root/go/bin" "${target_root_go_bin}" "bin:/root/go/bin" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.cargo/bin" "${target_root_cargo_bin}" "bin:/root/.cargo/bin"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.cargo/bin" "${target_root_cargo_bin}" "bin:/root/.cargo/bin" || return 1
    fi
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    if ! should_skip_migration_for_path "${container_name}" "/usr/local/go" "${target_usr_local_go}" "env:/usr/local/go"; then
      copy_dir_from_container_to_host "${container_name}" "/usr/local/go" "${target_usr_local_go}" "env:/usr/local/go" || return 1
    fi
    if [[ "${persist_node_modules_mount}" == "1" ]]; then
      if ! should_skip_migration_for_path "${container_name}" "/usr/local/lib/node_modules" "${target_usr_local_lib_node_modules}" "env:/usr/local/lib/node_modules"; then
        copy_dir_from_container_to_host "${container_name}" "/usr/local/lib/node_modules" "${target_usr_local_lib_node_modules}" "env:/usr/local/lib/node_modules" || return 1
      fi
    else
      log_info "[迁移] 检测到 zh 镜像策略，已跳过 env:/usr/local/lib/node_modules 迁移"
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
    if ! should_skip_migration_for_path "${container_name}" "/root/.pip" "${target_root_pip_config}" "env:/root/.pip"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.pip" "${target_root_pip_config}" "env:/root/.pip" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.rustup" "${target_root_rustup}" "env:/root/.rustup"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.rustup" "${target_root_rustup}" "env:/root/.rustup" || return 1
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
    if ! should_skip_migration_for_path "${container_name}" "/root/.cargo/config" "${target_root_cargo_config}" "env:/root/.cargo/config"; then
      copy_file_from_container_to_host "${container_name}" "/root/.cargo/config" "${target_root_cargo_config}" "env:/root/.cargo/config" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.cargo/config.toml" "${target_root_cargo_config_toml}" "env:/root/.cargo/config.toml"; then
      copy_file_from_container_to_host "${container_name}" "/root/.cargo/config.toml" "${target_root_cargo_config_toml}" "env:/root/.cargo/config.toml" || return 1
    fi

    collect_and_migrate_discovered_config_paths "${container_name}" "${data_dir}" || return 1
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
    if ! should_skip_migration_for_path "${container_name}" "/root/.cargo/registry" "${target_root_cargo_registry}" "cache:/root/.cargo/registry"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.cargo/registry" "${target_root_cargo_registry}" "cache:/root/.cargo/registry" || return 1
    fi
    if ! should_skip_migration_for_path "${container_name}" "/root/.cargo/git" "${target_root_cargo_git}" "cache:/root/.cargo/git"; then
      copy_dir_from_container_to_host "${container_name}" "/root/.cargo/git" "${target_root_cargo_git}" "cache:/root/.cargo/git" || return 1
    fi
  fi

  log_info "[迁移] 升级前 runtime 数据迁移完成"
  return 0
}

extra_ports_has_host_or_container_conflict() {
  local extra_ports="$1"
  local target_host="$2"
  local target_container="$3"
  local token host_part container_part
  for token in ${extra_ports}; do
    [[ -z "${token}" ]] && continue
    host_part="${token%%:*}"
    container_part="${token#*:}"
    if [[ "${container_part}" == */* ]]; then
      container_part="${container_part%%/*}"
    fi
    if [[ "${host_part}" == "${target_host}" || "${container_part}" == "${target_container}" ]]; then
      return 0
    fi
  done
  return 1
}

detect_claudecodeui_reserved_mapping() {
  local extra_ports="${1:-}"
  local token host_part container_part
  for token in ${extra_ports}; do
    [[ -z "${token}" ]] && continue
    host_part="${token%%:*}"
    container_part="${token#*:}"
    if [[ "${container_part}" == */* ]]; then
      container_part="${container_part%%/*}"
    fi
    case "${container_part}" in
      "${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}"|"${CLAUDECODEUI_RESERVED_CONTAINER_PORT_2}"|"${CLAUDECODEUI_RESERVED_CONTAINER_PORT_3}")
        printf '%s:%s\n' "${host_part}" "${container_part}"
        return 0
        ;;
    esac
  done
  return 1
}

detect_easyclaw_web_mapping() {
  local extra_ports="${1:-}"
  local token host_part container_part
  for token in ${extra_ports}; do
    [[ -z "${token}" ]] && continue
    host_part="${token%%:*}"
    container_part="${token#*:}"
    if [[ "${container_part}" == */* ]]; then
      container_part="${container_part%%/*}"
    fi
    if [[ "${container_part}" == "${EASYCLAW_DEFAULT_WEB_PORT}" ]]; then
      printf '%s:%s\n' "${host_part}" "${container_part}"
      return 0
    fi
  done
  return 1
}

choose_easyclaw_web_mapping() {
  local host_port="$1"
  local container_port="$2"
  local extra_ports="${3:-}"

  [[ "${host_port}" =~ ^[0-9]+$ ]] || return 1

  local -a host_candidates=("${EASYCLAW_DEFAULT_WEB_PORT}" "5231")
  local port_candidate
  for port_candidate in $(seq 4232 4299); do
    host_candidates+=("${port_candidate}")
  done

  local host_candidate
  for host_candidate in "${host_candidates[@]}"; do
    if [[ "${host_candidate}" == "${host_port}" ]]; then
      continue
    fi
    if extra_ports_has_host_or_container_conflict "${extra_ports}" "${host_candidate}" "${EASYCLAW_DEFAULT_WEB_PORT}"; then
      continue
    fi
    if ! is_host_port_available "${host_candidate}"; then
      continue
    fi
    printf '%s:%s\n' "${host_candidate}" "${EASYCLAW_DEFAULT_WEB_PORT}"
    return 0
  done

  return 1
}

choose_claudecodeui_reserved_mapping() {
  local host_port="$1"
  local container_port="$2"
  local extra_ports="${3:-}"

  [[ "${host_port}" =~ ^[0-9]+$ ]] || return 1

  local -a container_candidates=(
    "${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}"
    "${CLAUDECODEUI_RESERVED_CONTAINER_PORT_2}"
    "${CLAUDECODEUI_RESERVED_CONTAINER_PORT_3}"
  )

  local idx host_candidate container_candidate
  for idx in 0 1 2; do
    host_candidate=$((10#${host_port} + idx + 1))
    container_candidate="${container_candidates[$idx]}"

    if [[ "${container_candidate}" == "${container_port}" ]]; then
      continue
    fi
    if extra_ports_has_host_or_container_conflict "${extra_ports}" "${host_candidate}" "${container_candidate}"; then
      continue
    fi
    if [[ "${DRY_RUN}" -eq 0 ]] && ! is_host_port_available "${host_candidate}"; then
      continue
    fi
    printf '%s:%s\n' "${host_candidate}" "${container_candidate}"
    return 0
  done
  return 1
}

ensure_claudecodeui_reserved_port_mapping() {
  local enabled="$1"
  local host_port="$2"
  local container_port="$3"
  local extra_ports="${4:-}"

  if [[ "${enabled}" != "1" ]]; then
    echo "${extra_ports}"
    return
  fi

  local current
  current=$(detect_claudecodeui_reserved_mapping "${extra_ports}" || true)
  if [[ -n "${current}" ]]; then
    echo "${extra_ports}"
    return
  fi

  local selected
  selected=$(choose_claudecodeui_reserved_mapping "${host_port}" "${container_port}" "${extra_ports}" || true)
  if [[ -z "${selected}" ]]; then
    echo "${extra_ports}"
    return
  fi

  echo "${extra_ports}${extra_ports:+ }${selected}"
}

should_enable_claudecodeui_reserved_port() {
  local requested="$1"
  local container_name="${2:-}"
  local data_dir="${3:-}"

  if [[ "${requested}" == "1" ]]; then
    return 0
  fi

  if [[ -n "${data_dir}" ]]; then
    if [[ -x "${data_dir}/software/bin/cloudcli" || -x "${data_dir}/software/bin/claude-code-ui" || -x "${data_dir}/software/bin/task-master" ]]; then
      return 0
    fi
  fi

  if [[ -n "${container_name}" ]] && docker exec "${container_name}" sh -lc 'command -v cloudcli >/dev/null 2>&1 || command -v claude-code-ui >/dev/null 2>&1' >/dev/null 2>&1; then
    return 0
  fi

  return 1
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

  local current
  current=$(detect_easyclaw_web_mapping "${extra_ports}" || true)
  if [[ -n "${current}" ]]; then
    echo "${extra_ports}"
    return
  fi

  local selected
  selected=$(choose_easyclaw_web_mapping "${host_port}" "${container_port}" "${extra_ports}" || true)
  if [[ -z "${selected}" ]]; then
    log_error "ClawPanel Web 端口自动映射失败，已保留当前端口配置"
    echo "${extra_ports}"
    return
  fi

  if [[ "${selected}" != "${EASYCLAW_DEFAULT_WEB_PORT}:${EASYCLAW_DEFAULT_WEB_PORT}" ]]; then
    printf '[INFO] 检测到 ClawPanel Web 默认端口冲突，已改用 %s\n' "${selected}" >&2
  fi

  echo "${extra_ports}${extra_ports:+ }${selected}"
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

  if [[ -n "${container_name}" ]] && docker exec "${container_name}" sh -lc 'command -v clawpanel >/dev/null 2>&1 || command -v easyclaw >/dev/null 2>&1 || [ -d /root/.openclaw/software/clawpanel ] || [ -e /root/.openclaw/software/easyclaw/install.sh ]' >/dev/null 2>&1; then
    return 0
  fi

  return 1
}
