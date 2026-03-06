#!/usr/bin/env bash

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
path_profile="/root/.openclaw/runtime/path-decls/openclaw-runtime-path.sh"
shim_dir="/root/.openclaw/runtime/path-shims"
ensure_path_now() {
  for d in "$@"; do
    [ -d "$d" ] || continue
    case ":$PATH:" in
      *":$d:"*) ;;
      *) PATH="$d:$PATH" ;;
    esac
  done
}
ensure_path_profile_loader() {
  local loader="/etc/profile.d/openclaw-runtime-path.sh"
  mkdir -p /etc/profile.d || true
  printf "%s\n" "[ -f ${path_profile} ] && . ${path_profile}" > "$loader" || true
}
persist_path_dir() {
  local d="$1"
  [ -d "$d" ] || return 0
  mkdir -p "$(dirname "$path_profile")" || true
  touch "$path_profile" || return 0
  grep -F "export PATH=\"$d:\$PATH\"" "$path_profile" >/dev/null 2>&1 || \
    echo "export PATH=\"$d:\$PATH\"" >> "$path_profile"
}
ensure_shim_dir() {
  mkdir -p "$shim_dir" || true
}
link_shim() {
  local src="$1"
  local name="$2"
  [ -x "$src" ] || return 0
  ensure_shim_dir
  ln -sf "$src" "$shim_dir/$name" || true
  if [ -d /usr/local/bin ]; then
    ln -sf "$src" "/usr/local/bin/$name" || true
  fi
}
sync_user_bin_dir() {
  local src="$1"
  [ -d "$src" ] || return 0
  ensure_shim_dir
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    ln -sf "$f" "$shim_dir/$(basename "$f")" || true
    if [ -d /usr/local/bin ]; then
      ln -sf "$f" "/usr/local/bin/$(basename "$f")" || true
    fi
  done
}
ensure_path_profile_loader
ensure_path_now /root/.local/bin /usr/local/go/bin /root/go/bin /root/.cargo/bin "$shim_dir" /usr/local/bin
persist_path_dir /root/.local/bin
persist_path_dir /usr/local/go/bin
persist_path_dir /root/go/bin
persist_path_dir /root/.cargo/bin
persist_path_dir "$shim_dir"
link_shim /usr/local/go/bin/go go
link_shim /root/.local/bin/uv uv
link_shim /root/.cargo/bin/cargo cargo
link_shim /root/.cargo/bin/rustc rustc
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
path_profile="/root/.openclaw/runtime/path-decls/openclaw-runtime-path.sh"
shim_dir="/root/.openclaw/runtime/path-shims"
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

ensure_path_profile_loader() {
  local loader="/etc/profile.d/openclaw-runtime-path.sh"
  mkdir -p /etc/profile.d || true
  printf "%s\n" "[ -f ${path_profile} ] && . ${path_profile}" > "$loader" || true
}

persist_path_dir() {
  local d="$1"
  [ -d "$d" ] || return 0
  [ "$MODE" = "install" ] || return 0
  mkdir -p "$(dirname "$path_profile")" || true
  touch "$path_profile" || return 0
  grep -F "export PATH=\"$d:\$PATH\"" "$path_profile" >/dev/null 2>&1 || \
    echo "export PATH=\"$d:\$PATH\"" >> "$path_profile"
}

ensure_shim_dir() {
  mkdir -p "$shim_dir" || true
}

link_shim() {
  local src="$1"
  local name="$2"
  [ -x "$src" ] || return 0
  ensure_shim_dir
  ln -sf "$src" "$shim_dir/$name" || true
  if [ -d /usr/local/bin ]; then
    ln -sf "$src" "/usr/local/bin/$name" || true
  fi
}

sync_user_bin_dir() {
  local src="$1"
  [ -d "$src" ] || return 0
  ensure_shim_dir
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    ln -sf "$f" "$shim_dir/$(basename "$f")" || true
    if [ -d /usr/local/bin ]; then
      ln -sf "$f" "/usr/local/bin/$(basename "$f")" || true
    fi
  done
}

fix_uv_path() {
  local cand
  if has uv; then
    return 0
  fi
  for cand in /root/.local/bin/uv "$shim_dir/uv" /usr/local/bin/uv /usr/bin/uv; do
    if [ -x "$cand" ]; then
      ensure_path_now "$(dirname "$cand")"
      persist_path_dir "$(dirname "$cand")"
      if ! has uv && [ "$cand" != "$shim_dir/uv" ]; then
        link_shim "$cand" uv
        ensure_path_now "$shim_dir" /usr/local/bin
      fi
      break
    fi
  done
  sync_user_bin_dir /root/.local/bin
}

fix_go_path() {
  ensure_path_profile_loader
  ensure_path_now /usr/local/go/bin /root/go/bin "$shim_dir" /usr/local/bin
  persist_path_dir /usr/local/go/bin
  persist_path_dir /root/go/bin
  persist_path_dir "$shim_dir"
  if ! has go && [ -x /usr/local/go/bin/go ]; then
    link_shim /usr/local/go/bin/go go
    ensure_path_now "$shim_dir" /usr/local/bin
  fi
  sync_user_bin_dir /root/go/bin
}

fix_rust_path() {
  ensure_path_profile_loader
  ensure_path_now /root/.cargo/bin "$shim_dir" /usr/local/bin
  persist_path_dir /root/.cargo/bin
  persist_path_dir "$shim_dir"
  if ! has cargo && [ -x /root/.cargo/bin/cargo ]; then
    link_shim /root/.cargo/bin/cargo cargo
    ensure_path_now "$shim_dir" /usr/local/bin
  fi
  if ! has rustc && [ -x /root/.cargo/bin/rustc ]; then
    link_shim /root/.cargo/bin/rustc rustc
    ensure_path_now "$shim_dir" /usr/local/bin
  fi
  sync_user_bin_dir /root/.cargo/bin
}

# Best-effort PATH repair for "installed but not in PATH" cases (especially go/uv/rust)
ensure_path_profile_loader
ensure_path_now /root/.local/bin "$shim_dir" /usr/local/bin /usr/local/go/bin /root/go/bin /root/.cargo/bin

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
          py_minor="$(python3 -c 'import sys; print(f\"{sys.version_info[0]}.{sys.version_info[1]}\")' 2>/dev/null || true)"
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
