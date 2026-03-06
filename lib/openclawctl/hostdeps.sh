#!/usr/bin/env bash

hostdeps_current_os() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_OS:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_OS}"
    return
  fi
  local os
  os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
  case "${os}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    *) echo "${os:-unknown}" ;;
  esac
}

hostdeps_linux_os_release_field() {
  local field="$1"
  case "${field}" in
    ID)
      if [[ -n "${OPENCLAWCTL_TEST_HOST_OS_ID:-}" ]]; then
        printf '%s\n' "${OPENCLAWCTL_TEST_HOST_OS_ID}"
        return
      fi
      ;;
    VERSION_ID)
      if [[ -n "${OPENCLAWCTL_TEST_HOST_OS_VERSION:-}" ]]; then
        printf '%s\n' "${OPENCLAWCTL_TEST_HOST_OS_VERSION}"
        return
      fi
      ;;
  esac

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${field}" in
      ID) printf '%s\n' "${ID:-unknown}" ;;
      VERSION_ID) printf '%s\n' "${VERSION_ID:-unknown}" ;;
      *) printf '%s\n' "unknown" ;;
    esac
    return
  fi
  printf '%s\n' "unknown"
}

hostdeps_has_command() {
  local cmd="$1"
  local override=""
  case "${cmd}" in
    node) override="${OPENCLAWCTL_TEST_HOST_HAS_NODE:-}" ;;
    npm) override="${OPENCLAWCTL_TEST_HOST_HAS_NPM:-}" ;;
    gcc) override="${OPENCLAWCTL_TEST_HOST_HAS_GCC:-}" ;;
    g++) override="${OPENCLAWCTL_TEST_HOST_HAS_GPP:-}" ;;
    make) override="${OPENCLAWCTL_TEST_HOST_HAS_MAKE:-}" ;;
    git) override="${OPENCLAWCTL_TEST_HOST_HAS_GIT:-}" ;;
    pkg-config) override="${OPENCLAWCTL_TEST_HOST_HAS_PKG_CONFIG:-}" ;;
    python3) override="${OPENCLAWCTL_TEST_HOST_HAS_PYTHON3:-}" ;;
    pip3) override="${OPENCLAWCTL_TEST_HOST_HAS_PIP3:-}" ;;
    curl) override="${OPENCLAWCTL_TEST_HOST_HAS_CURL:-}" ;;
    *)
      override=""
      ;;
  esac
  if [[ -n "${override}" ]]; then
    [[ "${override}" == "1" ]]
    return
  fi
  command -v "${cmd}" >/dev/null 2>&1
}

hostdeps_detect_package_manager() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_PM:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_PM}"
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "yum"
    return
  fi
  if command -v apk >/dev/null 2>&1; then
    echo "apk"
    return
  fi
  if command -v zypper >/dev/null 2>&1; then
    echo "zypper"
    return
  fi
  echo ""
}

hostdeps_detect_node_major() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_NODE_MAJOR:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_NODE_MAJOR}"
    return
  fi
  if ! hostdeps_has_command node; then
    echo "0"
    return
  fi
  node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || echo "0"
}

hostdeps_detect_cmake_version() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_CMAKE_VERSION:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_CMAKE_VERSION}"
    return
  fi
  if ! command -v cmake >/dev/null 2>&1; then
    echo ""
    return
  fi
  cmake --version 2>/dev/null | head -n1 | sed -E 's/^cmake version[[:space:]]+//' || true
}

hostdeps_version_gte() {
  local left="$1"
  local right="$2"
  [[ -n "${left}" ]] || return 1
  [[ "${left}" == "${right}" ]] && return 0
  local min
  min=$(printf '%s\n%s\n' "${left}" "${right}" | sort -V | head -n1)
  [[ "${min}" == "${right}" ]]
}

hostdeps_read_mem_kb() {
  local key="$1"
  if [[ -r /proc/meminfo ]]; then
    awk -v k="${key}" '$1==k":" {print $2; exit}' /proc/meminfo
    return
  fi
  echo "0"
}

hostdeps_total_mem_mb() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_MEM_MB:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_MEM_MB}"
    return
  fi
  local mem_kb
  mem_kb=$(hostdeps_read_mem_kb "MemTotal")
  echo $((mem_kb / 1024))
}

hostdeps_total_swap_mb() {
  if [[ -n "${OPENCLAWCTL_TEST_HOST_SWAP_MB:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_HOST_SWAP_MB}"
    return
  fi
  local swap_kb
  swap_kb=$(hostdeps_read_mem_kb "SwapTotal")
  echo $((swap_kb / 1024))
}

hostdeps_warn_if_eol_linux() {
  if [[ "$(hostdeps_current_os)" != "linux" ]]; then
    return 0
  fi
  local os_id version_id
  os_id=$(hostdeps_linux_os_release_field "ID")
  version_id=$(hostdeps_linux_os_release_field "VERSION_ID")

  local eol=0
  case "${os_id}" in
    ubuntu)
      case "${version_id}" in
        24.04|22.04|20.04) ;;
        *) eol=1 ;;
      esac
      ;;
    debian)
      case "${version_id}" in
        12|11) ;;
        *) eol=1 ;;
      esac
      ;;
    centos|rhel|almalinux|rocky|fedora|opensuse*|sles|amzn)
      ;;
  esac

  if [[ "${eol}" -eq 1 ]]; then
    log_info "[hostdeps] 检测到系统可能已 EOL: ${os_id} ${version_id}，将优先使用包管理器进行兼容补齐"
  fi
}

hostdeps_install_docker_via_package_manager() {
  local pm
  pm=$(hostdeps_detect_package_manager)
  [[ -n "${pm}" ]] || {
    log_error "[hostdeps] 未识别到受支持的包管理器，无法自动安装 Docker"
    return 1
  }

  case "${pm}" in
    apt)
      run_cmd apt-get update
      run_cmd apt-get install -y docker.io
      ;;
    dnf)
      run_cmd dnf install -y docker
      ;;
    yum)
      run_cmd yum install -y docker
      ;;
    apk)
      run_cmd apk add --no-cache docker docker-cli
      ;;
    zypper)
      run_cmd zypper --non-interactive install docker
      ;;
    *)
      log_error "[hostdeps] 当前包管理器不支持 Docker 自动安装: ${pm}"
      return 1
      ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    run_cmd systemctl enable --now docker || true
  elif command -v service >/dev/null 2>&1; then
    run_cmd service docker start || true
  fi
  return 0
}

hostdeps_install_node_runtime() {
  local pm="$1"
  case "${pm}" in
    apt)
      run_cmd apt-get update
      run_cmd apt-get install -y curl ca-certificates gnupg
      run_cmd sh -lc 'curl -fsSL https://deb.nodesource.com/setup_22.x | bash -'
      run_cmd apt-get install -y nodejs
      ;;
    dnf)
      run_cmd dnf install -y curl ca-certificates
      run_cmd sh -lc 'curl -fsSL https://deb.nodesource.com/setup_22.x | bash -'
      run_cmd dnf install -y nodejs
      ;;
    yum)
      run_cmd yum install -y curl ca-certificates
      run_cmd sh -lc 'curl -fsSL https://deb.nodesource.com/setup_22.x | bash -'
      run_cmd yum install -y nodejs
      ;;
    apk)
      run_cmd apk add --no-cache nodejs npm
      ;;
    zypper)
      run_cmd zypper --non-interactive install nodejs22 nodejs22-npm || run_cmd zypper --non-interactive install nodejs npm
      ;;
    *)
      log_error "[hostdeps] 当前包管理器不支持 Node.js 自动补齐: ${pm}"
      return 1
      ;;
  esac
  return 0
}

hostdeps_install_build_toolchain() {
  local pm="$1"
  case "${pm}" in
    apt)
      run_cmd apt-get update
      run_cmd apt-get install -y build-essential cmake git pkg-config python3 python3-pip
      ;;
    dnf)
      run_cmd dnf install -y gcc gcc-c++ make cmake git pkgconf-pkg-config python3 python3-pip
      ;;
    yum)
      run_cmd yum install -y gcc gcc-c++ make cmake git pkgconfig python3 python3-pip
      ;;
    apk)
      run_cmd apk add --no-cache build-base cmake git pkgconfig python3 py3-pip
      ;;
    zypper)
      run_cmd zypper --non-interactive install gcc gcc-c++ make cmake git pkg-config python3 python3-pip
      ;;
    *)
      log_error "[hostdeps] 当前包管理器不支持构建链自动补齐: ${pm}"
      return 1
      ;;
  esac
  return 0
}

hostdeps_upgrade_cmake_if_needed() {
  local minimum_version="$1"
  local current_version
  current_version=$(hostdeps_detect_cmake_version)
  if hostdeps_version_gte "${current_version}" "${minimum_version}"; then
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd python3 -m pip install --upgrade pip
    run_cmd python3 -m pip install --upgrade cmake ninja
    return 0
  fi

  if ! hostdeps_has_command python3; then
    log_error "[hostdeps] cmake 版本过低且未检测到 python3，无法自动升级 cmake"
    return 1
  fi
  if ! hostdeps_has_command pip3; then
    run_cmd sh -lc 'python3 -m ensurepip --upgrade || true'
  fi
  run_cmd python3 -m pip install --upgrade pip
  run_cmd python3 -m pip install --upgrade cmake ninja

  current_version=$(hostdeps_detect_cmake_version)
  if ! hostdeps_version_gte "${current_version}" "${minimum_version}"; then
    log_error "[hostdeps] cmake 升级后仍低于 ${minimum_version}（当前: ${current_version:-unknown}）"
    return 1
  fi
  return 0
}

hostdeps_ensure_swap_if_needed() {
  local auto_swap="${OPENCLAWCTL_AUTO_SETUP_SWAP:-1}"
  [[ "${auto_swap}" == "1" ]] || return 0
  [[ "$(hostdeps_current_os)" == "linux" ]] || return 0

  local total_mem_mb total_swap_mb threshold_mb
  total_mem_mb=$(hostdeps_total_mem_mb)
  total_swap_mb=$(hostdeps_total_swap_mb)
  threshold_mb="${OPENCLAWCTL_MIN_TOTAL_MEM_SWAP_MB:-6144}"

  if (( total_mem_mb + total_swap_mb >= threshold_mb )); then
    return 0
  fi

  log_info "[hostdeps] 检测到宿主机内存+Swap不足(${total_mem_mb}+${total_swap_mb} MB)，尝试补充 Swap"
  local swap_size_mb
  swap_size_mb="${OPENCLAWCTL_AUTO_SWAP_SIZE_MB:-4096}"
  run_cmd sh -lc "(fallocate -l ${swap_size_mb}M /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=${swap_size_mb})"
  run_cmd chmod 600 /swapfile
  run_cmd mkswap /swapfile
  run_cmd swapon /swapfile
  return 0
}

hostdeps_repair_node_npm() {
  local node_major
  node_major=$(hostdeps_detect_node_major)
  if [[ "${node_major}" =~ ^[0-9]+$ ]] && (( node_major >= 22 )) && hostdeps_has_command npm; then
    log_info "[hostdeps] Node.js/npm 已满足要求"
    return 0
  fi

  log_error "[hostdeps] Node.js/npm 未满足要求（Node >=22 且包含 npm）"
  local auto_fix="${OPENCLAWCTL_AUTO_FIX_HOST_DEPS:-1}"
  if [[ "${auto_fix}" != "1" ]]; then
    log_error "[hostdeps] 已禁用自动修复(OPENCLAWCTL_AUTO_FIX_HOST_DEPS!=1)"
    return 1
  fi
  if [[ "$(hostdeps_current_os)" != "linux" ]]; then
    log_error "[hostdeps] 非 Linux 系统请先手工安装 Node.js >= 22 与 npm"
    return 1
  fi

  local pm
  pm=$(hostdeps_detect_package_manager)
  [[ -n "${pm}" ]] || {
    log_error "[hostdeps] 未识别到受支持的 Linux 包管理器，无法自动补齐 Node.js/npm"
    return 1
  }

  hostdeps_install_node_runtime "${pm}" || return 1
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "[hostdeps] dry-run 模式：Node.js/npm 自动补齐命令已输出"
    return 0
  fi

  node_major=$(hostdeps_detect_node_major)
  if [[ ! "${node_major}" =~ ^[0-9]+$ ]] || (( node_major < 22 )) || ! hostdeps_has_command npm; then
    log_error "[hostdeps] 自动补齐后 Node.js/npm 仍不满足要求"
    return 1
  fi
  return 0
}

hostdeps_repair_build_toolchain() {
  local need_build_toolchain=0
  local need_modern_cmake=0
  local cmake_version
  cmake_version=$(hostdeps_detect_cmake_version)

  if ! hostdeps_has_command gcc || ! hostdeps_has_command g++ || ! hostdeps_has_command make || ! hostdeps_has_command git || ! hostdeps_has_command pkg-config; then
    need_build_toolchain=1
    log_error "[hostdeps] 构建工具链不完整（gcc/g++/make/git/pkg-config）"
  fi
  if ! hostdeps_version_gte "${cmake_version}" "3.19"; then
    need_modern_cmake=1
    log_error "[hostdeps] cmake 版本过低（需要 >= 3.19，当前: ${cmake_version:-not-found}）"
  fi

  if [[ "${need_build_toolchain}" -eq 0 && "${need_modern_cmake}" -eq 0 ]]; then
    log_info "[hostdeps] Python/cmake/构建工具链已满足要求"
    return 0
  fi

  local auto_fix="${OPENCLAWCTL_AUTO_FIX_HOST_DEPS:-1}"
  if [[ "${auto_fix}" != "1" ]]; then
    log_error "[hostdeps] 已禁用自动修复(OPENCLAWCTL_AUTO_FIX_HOST_DEPS!=1)"
    return 1
  fi

  if [[ "${need_build_toolchain}" -eq 1 ]]; then
    if [[ "$(hostdeps_current_os)" != "linux" ]]; then
      log_error "[hostdeps] 非 Linux 系统请先手工安装构建工具链"
      return 1
    fi
    local pm
    pm=$(hostdeps_detect_package_manager)
    [[ -n "${pm}" ]] || {
      log_error "[hostdeps] 未识别到受支持的 Linux 包管理器，无法自动补齐构建工具链"
      return 1
    }
    hostdeps_install_build_toolchain "${pm}" || return 1
  fi

  if [[ "${need_modern_cmake}" -eq 1 ]]; then
    hostdeps_upgrade_cmake_if_needed "3.19" || return 1
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "[hostdeps] dry-run 模式：构建工具链自动补齐命令已输出"
    return 0
  fi

  cmake_version=$(hostdeps_detect_cmake_version)
  if ! hostdeps_has_command gcc || ! hostdeps_has_command g++ || ! hostdeps_has_command make || ! hostdeps_has_command git || ! hostdeps_has_command pkg-config; then
    log_error "[hostdeps] 自动补齐后构建工具链仍不完整"
    return 1
  fi
  if ! hostdeps_version_gte "${cmake_version}" "3.19"; then
    log_error "[hostdeps] 自动补齐后 cmake 仍低于 3.19"
    return 1
  fi
  return 0
}

hostdeps_repair_swap() {
  log_info "[hostdeps] 检查低内存/Swap 优化"
  hostdeps_ensure_swap_if_needed
}

ensure_native_host_dependencies() {
  local action="${1:-native-install}"
  log_info "[hostdeps] native 宿主机依赖检查(action=${action})"
  hostdeps_warn_if_eol_linux

  local node_major cmake_version
  node_major=$(hostdeps_detect_node_major)
  cmake_version=$(hostdeps_detect_cmake_version)

  local need_node=0
  local need_build_toolchain=0
  local need_modern_cmake=0

  if [[ ! "${node_major}" =~ ^[0-9]+$ ]] || (( node_major < 22 )); then
    need_node=1
    log_error "[hostdeps] 缺少或版本过低: Node.js >= 22（当前: ${node_major:-0}）"
  fi
  if ! hostdeps_has_command npm; then
    need_node=1
    log_error "[hostdeps] 缺少命令: npm"
  fi

  if ! hostdeps_has_command gcc || ! hostdeps_has_command g++ || ! hostdeps_has_command make || ! hostdeps_has_command git || ! hostdeps_has_command pkg-config; then
    need_build_toolchain=1
    log_error "[hostdeps] 缺少构建工具链，建议安装: build-essential + git + pkg-config"
  fi

  if ! hostdeps_version_gte "${cmake_version}" "3.19"; then
    need_modern_cmake=1
    log_error "[hostdeps] 缺少或版本过低: cmake >= 3.19（当前: ${cmake_version:-not-found}）"
  fi

  if [[ "${need_node}" -eq 0 && "${need_build_toolchain}" -eq 0 && "${need_modern_cmake}" -eq 0 ]]; then
    log_info "[hostdeps] native 宿主机依赖已满足"
    return 0
  fi

  local auto_fix="${OPENCLAWCTL_AUTO_FIX_HOST_DEPS:-1}"
  if [[ "${auto_fix}" != "1" ]]; then
    log_error "[hostdeps] 宿主机依赖缺失，且已禁用自动修复(OPENCLAWCTL_AUTO_FIX_HOST_DEPS!=1)"
    return 1
  fi

  local pm
  pm=$(hostdeps_detect_package_manager)
  if [[ "$(hostdeps_current_os)" == "linux" && -z "${pm}" ]]; then
    log_error "[hostdeps] 未识别到受支持的 Linux 包管理器，无法自动补齐依赖"
    return 1
  fi

  if [[ "${need_node}" -eq 1 ]]; then
    if [[ "$(hostdeps_current_os)" == "linux" ]]; then
      hostdeps_install_node_runtime "${pm}" || return 1
    else
      log_error "[hostdeps] 非 Linux 系统请先手工安装 Node.js >= 22 与 npm"
      return 1
    fi
  fi

  if [[ "${need_build_toolchain}" -eq 1 ]]; then
    if [[ "$(hostdeps_current_os)" == "linux" ]]; then
      hostdeps_install_build_toolchain "${pm}" || return 1
    else
      log_error "[hostdeps] 非 Linux 系统请先手工安装构建工具链(gcc/g++/make/git/pkg-config)"
      return 1
    fi
  fi

  if [[ "${need_modern_cmake}" -eq 1 ]]; then
    hostdeps_upgrade_cmake_if_needed "3.19" || return 1
  fi

  hostdeps_ensure_swap_if_needed || return 1

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "[hostdeps] dry-run 模式：已输出自动补齐命令"
    return 0
  fi

  node_major=$(hostdeps_detect_node_major)
  cmake_version=$(hostdeps_detect_cmake_version)
  if [[ ! "${node_major}" =~ ^[0-9]+$ ]] || (( node_major < 22 )) || ! hostdeps_has_command npm; then
    log_error "[hostdeps] 自动补齐后 Node/npm 仍不满足要求"
    return 1
  fi
  if ! hostdeps_has_command gcc || ! hostdeps_has_command g++ || ! hostdeps_has_command make || ! hostdeps_has_command git || ! hostdeps_has_command pkg-config; then
    log_error "[hostdeps] 自动补齐后构建工具链仍不完整"
    return 1
  fi
  if ! hostdeps_version_gte "${cmake_version}" "3.19"; then
    log_error "[hostdeps] 自动补齐后 cmake 仍低于 3.19"
    return 1
  fi

  log_info "[hostdeps] 宿主机依赖自动补齐完成"
  return 0
}
