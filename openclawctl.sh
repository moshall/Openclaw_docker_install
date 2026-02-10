#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
DEFAULT_HOST_PORT="4113"
DEFAULT_CONTAINER_PORT="18789"
DEFAULT_RESTART_POLICY="unless-stopped"
EASY_CLI_REPO="https://github.com/moshall/Openclaw_Easy_Cli"
DEFAULT_DEP_SET="npm uv"
DEFAULT_ENABLE_BIN_PERSIST="1"
DEFAULT_ENABLE_ENV_PERSIST="2"

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
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
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
  local volume_args=()

  if [[ "${enable_bin_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/root-local-bin" "${data_dir}/runtime/root-go-bin"
    volume_args+=("-v" "${data_dir}/runtime/root-local-bin:/root/.local/bin")
    volume_args+=("-v" "${data_dir}/runtime/root-go-bin:/root/go/bin")
  fi

  if [[ "${enable_env_persist}" == "1" ]]; then
    run_cmd mkdir -p "${data_dir}/runtime/usr-local-go" \
      "${data_dir}/runtime/root-local-share-uv" \
      "${data_dir}/runtime/root-local-pipx" \
      "${data_dir}/runtime/root-local-share-pipx"
    volume_args+=("-v" "${data_dir}/runtime/usr-local-go:/usr/local/go")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-uv:/root/.local/share/uv")
    volume_args+=("-v" "${data_dir}/runtime/root-local-pipx:/root/.local/pipx")
    volume_args+=("-v" "${data_dir}/runtime/root-local-share-pipx:/root/.local/share/pipx")
  fi

  run_cmd docker run -d \
    --name "${name}" \
    --restart "${DEFAULT_RESTART_POLICY}" \
    -p "${host_port}:${container_port}" \
    -v "${data_dir}:/root/.openclaw" \
    "${volume_args[@]}" \
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
  local profile
  profile=$(persistence_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "持久化档案将保存到: ${profile}"
    log_info "持久化档案内容: bin=${bin_choice}, env=${env_choice}"
    return
  fi
  cat > "${profile}" <<EOF
BIN_PERSIST=${bin_choice}
ENV_PERSIST=${env_choice}
EOF
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

echo "[deps] checking: ${DEPS}"
for cmd in $DEPS; do
  if has "$cmd"; then
    echo "FOUND:$cmd"
  else
    echo "MISSING:$cmd"
  fi
done

if [ "$MODE" = "check" ]; then
  exit 0
fi

need_node=0
need_python=0
need_uv=0
need_go=0
contains_dep npm && ! has npm && need_node=1
if ! has python3 && (contains_dep python3 || contains_dep uv); then
  need_python=1
fi
contains_dep uv && ! has uv && need_uv=1
contains_dep go && ! has go && need_go=1

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
      rm -rf /usr/local/go
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
  if has "$cmd"; then
    echo "FOUND:$cmd"
  else
    echo "MISSING:$cmd"
  fi
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
  local target="$2" # bin | env
  local default_value="$3"

  if [[ "${target}" == "bin" ]]; then
    if has_mount_destination "${name}" "/root/.local/bin" || has_mount_destination "${name}" "/root/go/bin"; then
      echo "1"
      return
    fi
  fi

  if [[ "${target}" == "env" ]]; then
    if has_mount_destination "${name}" "/usr/local/go" || \
      has_mount_destination "${name}" "/root/.local/share/uv" || \
      has_mount_destination "${name}" "/root/.local/pipx" || \
      has_mount_destination "${name}" "/root/.local/share/pipx"; then
      echo "1"
      return
    fi
  fi

  echo "${default_value}"
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

deps_summary_line() {
  local dep_set="$1"
  if [[ -z "${dep_set}" ]]; then
    echo "未配置"
    return
  fi
  echo "npm=$(dep_choice_label "${dep_set}" "npm"), uv=$(dep_choice_label "${dep_set}" "uv"), go=$(dep_choice_label "${dep_set}" "go")"
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
  local easy_choice="1"
  local token_mode="1"
  local token_manual=""
  local deps_install_choice="1"
  local target_deps="${DEFAULT_DEP_SET}"

  while true; do
    printf '\n=== 新装（清单模式） ===\n'
    echo "按编号编辑，c确认执行，q返回主菜单"
    echo
    echo "1) 版本镜像: $(value_or_unset "${image}")"
    echo "2) 容器名: $(value_or_unset "${name}")"
    echo "3) 端口映射: ${host_port}:${container_port}"
    if [[ -n "${data_dir}" ]]; then
      echo "4) 持久化目录: ${data_dir}"
    else
      echo "4) 持久化目录: 未选择（默认 /opt/1panel/apps/<容器名>）"
    fi
    echo "5) 网络绑定: $(bind_choice_label "${bind_choice}")"
    echo "6) 持久化策略: bin=$(choice_to_yes_no "${bin_persist_choice}"), env=$(choice_to_yes_no "${env_persist_choice}")"
    echo "7) Easy CLI: $(choice_to_yes_no "${easy_choice}")"
    echo "8) Token: $(token_mode_label "${token_mode}" "${token_manual}")"
    echo "9) 依赖补齐: $(choice_to_yes_no "${deps_install_choice}")"
    if [[ "${deps_install_choice}" == "1" ]]; then
      echo "10) 依赖清单: $(deps_summary_line "${target_deps}")"
    else
      echo "10) 依赖清单: 未启用"
    fi
    echo "c) 确认并执行安装"
    echo "q) 取消并返回"

    local action
    action=$(read_choice_default "请选择" "")
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
        ;;
      2)
        name=$(read_container_name "Docker 容器名")
        ;;
      3)
        host_port=$(read_with_default "宿主机端口" "${host_port}")
        container_port=$(read_with_default "OpenClaw 容器内部端口" "${container_port}")
        ;;
      4)
        data_dir=$(read_with_default "持久化目录" "${data_dir:-/opt/1panel/apps/${name:-openclaw}}")
        ;;
      5)
        echo "网络绑定:"
        echo "  1) local"
        echo "  2) lan"
        bind_choice=$(read_choice_default "请选择" "${bind_choice}")
        ;;
      6)
        echo "持久化策略说明："
        echo "  - 保留命令入口（bin）：升级后命令更不容易丢失（推荐）"
        echo "  - 保留运行环境（env）：升级后更少重装，但占用更高"
        echo "是否启用 保留命令入口（bin）:"
        echo "  1) 是"
        echo "  2) 否"
        bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
        echo "是否启用 保留运行环境（env）:"
        echo "  1) 是"
        echo "  2) 否"
        env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
        ;;
      7)
        echo "是否安装 Easy CLI:"
        echo "  1) 是"
        echo "  2) 否"
        easy_choice=$(read_choice_default "请选择" "${easy_choice}")
        ;;
      8)
        echo "Token 方式:"
        echo "  1) 自动生成"
        echo "  2) 手动输入"
        token_mode=$(read_choice_default "请选择" "${token_mode}")
        if [[ "${token_mode}" == "2" ]]; then
          token_manual=$(read_required "请输入 token")
        fi
        ;;
      9)
        echo "是否自动检测并补齐容器依赖:"
        echo "  1) 是（推荐）"
        echo "  2) 否"
        deps_install_choice=$(read_choice_default "请选择" "${deps_install_choice}")
        ;;
      10)
        if [[ "${deps_install_choice}" == "1" ]]; then
          target_deps=$(prompt_dep_set "${target_deps}")
        else
          log_info "当前依赖补齐未启用，请先在第9项启用"
        fi
        ;;
      c|C)
        if [[ -z "${image}" ]]; then
          log_error "请先在第1项选择版本镜像"
          continue
        fi
        if [[ -z "${name}" ]]; then
          log_error "请先在第2项填写容器名"
          continue
        fi
        if [[ -z "${data_dir}" ]]; then
          data_dir="/opt/1panel/apps/${name}"
        fi
        if [[ "${token_mode}" == "2" && -z "${token_manual}" ]]; then
          log_error "Token 为手动模式，请在第8项填写 token"
          continue
        fi

        local token gateway_bind
        if [[ "${token_mode}" == "2" ]]; then
          token="${token_manual}"
        else
          token=$(generate_token)
        fi
        gateway_bind=$(bind_choice_label "${bind_choice}")

        printf '\n--- 执行清单（确认前） ---\n'
        echo "镜像: ${image}"
        echo "容器名: ${name}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录: ${data_dir}"
        echo "网络绑定: ${gateway_bind}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "Easy CLI: $(choice_to_yes_no "${easy_choice}")"
        echo "依赖补齐: $(choice_to_yes_no "${deps_install_choice}")"
        if [[ "${deps_install_choice}" == "1" ]]; then
          echo "依赖清单: ${target_deps}"
        fi
        printf '确认执行? (y/N): '
        local confirm
        IFS= read -r confirm
        if ! validate_yes_no "${confirm}"; then
          log_info "已取消"
          continue
        fi

        run_cmd mkdir -p "${data_dir}"
        run_cmd docker pull "${image}"
        remove_container_if_exists "${name}"
        bootstrap_openclaw_config "${image}" "${data_dir}" "${container_port}" "${gateway_bind}" "${token}"
        run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}"
        save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}"

        if [[ "${easy_choice}" == "1" ]]; then
          install_easy_cli "${data_dir}"
        fi

        if [[ "${deps_install_choice}" == "1" ]]; then
          manage_container_runtime_deps "${name}" "install" "${target_deps}"
          save_dep_profile "${data_dir}" "${target_deps}"
        fi

        printf 'TOKEN=%s\n' "${token}"
        printf 'URL=http://<server-ip>:%s/?token=%s\n' "${host_port}" "${token}"
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
  printf '\n=== 升级（安全升级 / 清单模式） ===\n'
  echo "按编号编辑，c确认执行，q返回主菜单"
  local name
  name=$(read_container_name "请输入要升级的容器名")

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

  local bin_persist_choice
  bin_persist_choice="${bin_persist_default}"

  local env_persist_choice
  env_persist_choice="${env_persist_default}"

  local easy_cli_upgrade
  easy_cli_upgrade="1"

  local saved_dep_set
  saved_dep_set=$(load_dep_profile "${data_dir}")
  local deps_repair_choice="1"
  local upgrade_dep_set="${saved_dep_set}"

  while true; do
    printf '\n=== 升级清单：%s ===\n' "${name}"
    echo "1) 目标版本镜像: $(value_or_unset "${image}")"
    echo "2) 端口映射: ${host_port}:${container_port}"
    echo "3) 持久化目录: ${data_dir}"
    echo "4) 持久化策略: bin=$(choice_to_yes_no "${bin_persist_choice}"), env=$(choice_to_yes_no "${env_persist_choice}")"
    echo "5) Easy CLI 检查升级: $(choice_to_yes_no "${easy_cli_upgrade}")"
    echo "6) 升级后依赖补齐: $(choice_to_yes_no "${deps_repair_choice}")"
    if [[ "${deps_repair_choice}" == "1" ]]; then
      echo "7) 依赖清单: $(deps_summary_line "${upgrade_dep_set}")"
    else
      echo "7) 依赖清单: 未启用"
    fi
    echo "c) 确认并执行升级"
    echo "q) 取消并返回"

    local action
    action=$(read_choice_default "请选择" "")
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
        ;;
      2)
        host_port=$(read_with_default "宿主机端口" "${host_port}")
        container_port=$(read_with_default "OpenClaw 容器内部端口" "${container_port}")
        ;;
      3)
        data_dir=$(read_with_default "持久化目录（安全升级会复用）" "${data_dir}")
        ;;
      4)
        echo "是否启用 保留命令入口（bin）:"
        echo "  1) 是"
        echo "  2) 否"
        bin_persist_choice=$(read_choice_default "请选择" "${bin_persist_choice}")
        echo "是否启用 保留运行环境（env）:"
        echo "  1) 是"
        echo "  2) 否"
        env_persist_choice=$(read_choice_default "请选择" "${env_persist_choice}")
        ;;
      5)
        echo "是否检查并升级 Easy CLI:"
        echo "  1) 是"
        echo "  2) 否"
        easy_cli_upgrade=$(read_choice_default "请选择" "${easy_cli_upgrade}")
        ;;
      6)
        echo "是否在升级完成后自动补齐依赖:"
        echo "  1) 是"
        echo "  2) 否"
        deps_repair_choice=$(read_choice_default "请选择" "${deps_repair_choice}")
        ;;
      7)
        if [[ "${deps_repair_choice}" == "1" ]]; then
          upgrade_dep_set=$(prompt_dep_set "${upgrade_dep_set}")
        else
          log_info "当前依赖补齐未启用，请先在第6项启用"
        fi
        ;;
      c|C)
        if [[ -z "${image}" ]]; then
          log_error "请先在第1项选择目标版本镜像"
          continue
        fi
        printf '\n--- 执行清单（确认前） ---\n'
        echo "容器名: ${name}"
        echo "目标镜像: ${image}"
        echo "端口映射: ${host_port}:${container_port}"
        echo "持久化目录(保留): ${data_dir}"
        echo "保留命令入口（bin）: $(choice_to_yes_no "${bin_persist_choice}")"
        echo "保留运行环境（env）: $(choice_to_yes_no "${env_persist_choice}")"
        echo "Easy CLI 检查升级: $(choice_to_yes_no "${easy_cli_upgrade}")"
        echo "升级后依赖补齐: $(choice_to_yes_no "${deps_repair_choice}")"
        if [[ "${deps_repair_choice}" == "1" ]]; then
          echo "依赖清单: ${upgrade_dep_set}"
        fi
        printf '确认执行安全升级? (y/N): '
        local confirm
        IFS= read -r confirm
        if ! validate_yes_no "${confirm}"; then
          log_info "已取消"
          continue
        fi

        run_cmd mkdir -p "${data_dir}"
        run_cmd docker pull "${image}"
        remove_container_if_exists "${name}"
        run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}"
        save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}"

        run_cmd docker ps --filter "name=${name}"
        run_cmd docker logs --tail 30 "${name}"
        run_cmd docker exec "${name}" openclaw --version

        if [[ "${easy_cli_upgrade}" == "1" ]]; then
          check_and_upgrade_easy_cli "${data_dir}"
        fi

        if [[ "${deps_repair_choice}" == "1" ]]; then
          manage_container_runtime_deps "${name}" "install" "${upgrade_dep_set}"
          save_dep_profile "${data_dir}" "${upgrade_dep_set}"
        fi
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
  printf '\n=== 卸载（快捷模式） ===\n'
  echo "流程：选择模式 -> 二次确认容器名 -> 执行"
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

easy_cli_only_upgrade_wizard() {
  printf '\n=== 仅升级 Easy CLI ===\n'
  local name
  name=$(read_container_name "请输入容器名（用于定位持久化目录）")

  local default_data_dir="/opt/1panel/apps/${name}"
  local detected_data_dir
  detected_data_dir=$(detect_existing_data_dir "${name}" "${default_data_dir}")

  local data_dir
  data_dir=$(read_with_default "Easy CLI 所在持久化目录" "${detected_data_dir}")

  printf '\n--- 任务预览 ---\n'
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

deps_manage_wizard() {
  printf '\n=== 组件与依赖管理 ===\n'
  echo "提示：用于单独补齐容器依赖，不重建 OpenClaw 容器。"
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

  manage_container_runtime_deps "${name}" "${mode}" "${dep_set}"
  if [[ "${mode}" == "install" ]]; then
    save_dep_profile "${data_dir}" "${dep_set}"
  fi
}

show_main_menu() {
  echo
  echo "==============================="
  echo " OpenClaw 交互式部署助手（清单）"
  echo "==============================="
  echo "1) 新装（清单模式）"
  echo "2) 升级（安全升级 / 清单模式）"
  echo "3) 卸载（快捷模式）"
  echo "4) 仅升级 Easy CLI"
  echo "5) 组件与依赖管理"
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
      5) deps_manage_wizard ;;
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
