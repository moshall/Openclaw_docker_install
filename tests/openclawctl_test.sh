#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
SCRIPT_PATH="${ROOT_DIR}/Openclaw_docker_install/openclawctl.sh"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
  SCRIPT_PATH="${ROOT_DIR}/openclawctl.sh"
fi
SCRIPT_HOME=$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)
export OPENCLAWCTL_DATA_ROOT="/opt/1panel/apps"
export OPENCLAW_OFFICIAL_REPO="1panel/openclaw"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    fail "expected output to contain: ${needle}"
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    fail "expected output NOT to contain: ${needle}"
  fi
}

# 0) entry script should load modular bootstrap in fixed order
assert_contains "$(cat "${SCRIPT_PATH}")" 'source "${SCRIPT_DIR}/lib/openclawctl/bootstrap.sh"'
assert_not_contains "$(cat "${SCRIPT_PATH}")" 'execute_install_plan() {'
assert_not_contains "$(cat "${SCRIPT_PATH}")" 'execute_upgrade_plan() {'
assert_not_contains "$(cat "${SCRIPT_PATH}")" 'execute_rebuild_plan() {'
assert_not_contains "$(cat "${SCRIPT_PATH}")" 'run_selected_wizard() {'
assert_not_contains "$(cat "${SCRIPT_PATH}")" 'main_loop() {'

# 0b) common helpers should provide escaped command rendering
common_print_cmd_output=$(DRY_RUN=1 SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; print_cmd "hello world" "*.txt"' 2>&1 || true)
assert_contains "${common_print_cmd_output}" "hello\\ world \\*.txt"

# 0c) io helpers should provide default choices and input sanitizing
io_default_choice_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; source "${SCRIPT_DIR}/lib/openclawctl/io.sh"; printf "\n" | read_choice_default "请选择" "2"' 2>/dev/null || true)
assert_contains "${io_default_choice_output}" "2"

io_sanitized_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c $'set -euo pipefail; source "${SCRIPT_DIR}/lib/openclawctl/io.sh"; sanitize_user_input "ab\tcd"' 2>&1 || true)
assert_contains "${io_sanitized_output}" "abcd"

# 0d) image helpers should fallback missing official tag to nearest available tag
image_fallback_output=$(OPENCLAWCTL_TEST_OFFICIAL_TAGS='latest,beta,2026.2.26,2026.2.20' SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/image.sh"; official_openclaw_repo_path(){ printf "1panel/openclaw\n"; }; resolve_official_tag_with_fallback "upgrade" "docker.io/1panel/openclaw:260226"' 2>&1 || true)
assert_contains "${image_fallback_output}" "docker.io/1panel/openclaw:2026.2.26"

# 0e) persist helpers should fallback easyclaw web host port on conflict
persist_easyclaw_mapping_output=$(OPENCLAWCTL_TEST_OCCUPIED_PORTS='4231' SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; DRY_RUN=0; EASYCLAW_DEFAULT_WEB_PORT=4231; CLAUDECODEUI_RESERVED_CONTAINER_PORT_1=7201; CLAUDECODEUI_RESERVED_CONTAINER_PORT_2=7202; CLAUDECODEUI_RESERVED_CONTAINER_PORT_3=7203; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/persist.sh"; ensure_easyclaw_web_port_mapping "1" "4113" "18789" ""' 2>&1 || true)
assert_contains "${persist_easyclaw_mapping_output}" "5231:4231"

# 0f) components helpers should load optional catalog and resolve labels
components_catalog_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; DEFAULT_OPTIONAL_SOFTWARE_ALL="gh claude codex opencode gemini notebooklm easyclaw claudecodeui obsidian ralph"; DEFAULT_OPTIONAL_SKILL_ALL="obsidian-skills security-checker"; OPTIONAL_SOFTWARE_ALL="${DEFAULT_OPTIONAL_SOFTWARE_ALL}"; OPTIONAL_SKILL_ALL="${DEFAULT_OPTIONAL_SKILL_ALL}"; OPTIONAL_SOFTWARE_CATALOG=""; OPTIONAL_SKILL_CATALOG=""; OPTIONAL_COMPONENTS_FILE="${SCRIPT_DIR}/config/optional-components.conf"; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/io.sh"; source "${SCRIPT_DIR}/lib/openclawctl/components.sh"; load_optional_component_catalog; optional_software_label "easyclaw"' 2>&1 || true)
assert_contains "${components_catalog_output}" "EasyClaw"

# 0g) deps helpers should expose runtime dependency checker workflow
deps_manage_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; DRY_RUN=1; DEFAULT_DEP_SET="npm uv"; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/deps.sh"; manage_container_runtime_deps "openclaw_deps_test" "check" "npm uv go"' 2>&1 || true)
assert_contains "${deps_manage_output}" "开始检测容器依赖: npm uv go"
assert_contains "${deps_manage_output}" "依赖检测模式: 仅检测，不安装"

# 0h) ops/wizard modules should expose execution and routing functions
ops_wizard_symbol_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/io.sh"; source "${SCRIPT_DIR}/lib/openclawctl/image.sh"; source "${SCRIPT_DIR}/lib/openclawctl/persist.sh"; source "${SCRIPT_DIR}/lib/openclawctl/components.sh"; source "${SCRIPT_DIR}/lib/openclawctl/deps.sh"; source "${SCRIPT_DIR}/lib/openclawctl/ops.sh"; source "${SCRIPT_DIR}/lib/openclawctl/wizard.sh"; declare -F execute_install_plan >/dev/null; declare -F run_selected_wizard >/dev/null; echo "ops-wizard-ready"' 2>&1 || true)
assert_contains "${ops_wizard_symbol_output}" "ops-wizard-ready"

# 0i) hostdeps helpers should report native host dependency gaps
hostdeps_diag_output=$(SCRIPT_DIR="${SCRIPT_HOME}" bash -c 'set -euo pipefail; DRY_RUN=0; OPENCLAWCTL_AUTO_FIX_HOST_DEPS=0; OPENCLAWCTL_TEST_HOST_OS=linux; OPENCLAWCTL_TEST_HOST_OS_ID=ubuntu; OPENCLAWCTL_TEST_HOST_OS_VERSION=20.10; OPENCLAWCTL_TEST_HOST_PM=apt; OPENCLAWCTL_TEST_HOST_NODE_MAJOR=20; OPENCLAWCTL_TEST_HOST_HAS_NPM=0; OPENCLAWCTL_TEST_HOST_CMAKE_VERSION=3.16.3; OPENCLAWCTL_TEST_HOST_HAS_GCC=0; OPENCLAWCTL_TEST_HOST_HAS_GPP=0; OPENCLAWCTL_TEST_HOST_HAS_MAKE=0; OPENCLAWCTL_TEST_HOST_HAS_GIT=0; OPENCLAWCTL_TEST_HOST_HAS_PKG_CONFIG=0; source "${SCRIPT_DIR}/lib/openclawctl/common.sh"; source "${SCRIPT_DIR}/lib/openclawctl/hostdeps.sh"; ensure_native_host_dependencies "native-install"' 2>&1 || true)
assert_contains "${hostdeps_diag_output}" "native 宿主机依赖检查"
assert_contains "${hostdeps_diag_output}" "Node.js >= 22"
assert_contains "${hostdeps_diag_output}" "cmake >= 3.19"
assert_contains "${hostdeps_diag_output}" "build-essential"

# 0j) launcher should track go source freshness before reusing cached TUI binary
assert_contains "$(cat "${SCRIPT_PATH}")" 'is_tui_binary_up_to_date() {'
assert_contains "$(cat "${SCRIPT_PATH}")" 'find "${root_dir}/cmd" "${root_dir}/internal" -type f -name '\''*.go'\'' -newer "${output_bin}"'

# 1) launcher should prefer TUI binary in interactive mode but fall back in non-TTY mode
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT
fake_tui="${tmpdir}/fake-openclawctl-tui"
cat > "${fake_tui}" <<'EOF'
#!/usr/bin/env bash
echo "FAKE_TUI:$*"
EOF
chmod +x "${fake_tui}"

launcher_tui_output=$(OPENCLAWCTL_ASSUME_TTY=1 OPENCLAWCTL_TUI_BIN="${fake_tui}" bash "${SCRIPT_PATH}" --dry-run 2>&1 || true)
assert_contains "${launcher_tui_output}" "FAKE_TUI:"
assert_contains "${launcher_tui_output}" "系统环境检测中用于匹配功能"
assert_contains "${launcher_tui_output}" "正在构建TUI菜单中，即将呈现"
assert_contains "${launcher_tui_output}" $'\033[H\033[2J'

launcher_shell_output=$(printf '0\n' | OPENCLAWCTL_TUI_BIN="${fake_tui}" bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${launcher_shell_output}" "OpenClaw 部署助手"
assert_contains "${launcher_shell_output}" "Native 实体机安装与管理"
assert_contains "${launcher_shell_output}" "Docker 隔离环境安装与管理"
assert_contains "${launcher_shell_output}" "远程 VPS 1Panel 版 Docker"
assert_not_contains "${launcher_shell_output}" "FAKE_TUI:"

# 0b) shell should support direct wizard entrypoints for Go delegation
wizard_install_output=$(printf 'q\n' | bash "${SCRIPT_PATH}" --dry-run --wizard install)
assert_contains "${wizard_install_output}" "=== 🚀 安装新实例 ==="

wizard_rebuild_output=$(printf 'openclaw_rebuild\nq\n' | bash "${SCRIPT_PATH}" --dry-run --wizard rebuild)
assert_contains "${wizard_rebuild_output}" "=== 🛠️ 调整或重建实例 ==="

wizard_install_cfg="${tmpdir}/install.cfg"
cat > "${wizard_install_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4113
CONTAINER_PORT=18789
NAME=openclaw_cfg
DATA_DIR=/opt/1panel/apps/openclaw_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=2
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=1
TOKEN_MODE=2
TOKEN_MANUAL=testtoken123
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=5001:5001
EOF
wizard_install_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_cfg}")
assert_contains "${wizard_install_cfg_output}" "镜像: ghcr.io/1186258278/openclaw-zh:latest"
assert_contains "${wizard_install_cfg_output}" "容器名: openclaw_cfg"
assert_contains "${wizard_install_cfg_output}" "TOKEN=testtoken123"
assert_contains "${wizard_install_cfg_output}" "-p 5001:5001"
assert_not_contains "${wizard_install_cfg_output}" "=== 🚀 安装新实例 ==="

wizard_install_zh_nightly_cfg="${tmpdir}/install-zh-nightly.cfg"
cat > "${wizard_install_zh_nightly_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=2
IMAGE=ghcr.io/1186258278/openclaw-zh:nightly
HOST_PORT=4114
CONTAINER_PORT=18789
NAME=openclaw_cfg_zh_nightly
DATA_DIR=/opt/1panel/apps/openclaw_cfg_zh_nightly
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=testtoken456
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=
EOF
wizard_install_zh_nightly_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_zh_nightly_cfg}")
assert_contains "${wizard_install_zh_nightly_output}" "镜像: ghcr.io/1186258278/openclaw-zh:nightly"
assert_contains "${wizard_install_zh_nightly_output}" "/runtime/usr-local-go:/usr/local/go"
assert_not_contains "${wizard_install_zh_nightly_output}" "/runtime/usr-local-lib-node-modules:/usr/local/lib/node_modules"
assert_contains "${wizard_install_zh_nightly_output}" "docker exec openclaw_cfg_zh_nightly sh -lc <npm-runtime-prefix-script>"

wizard_upgrade_cfg="${tmpdir}/upgrade.cfg"
cat > "${wizard_upgrade_cfg}" <<'EOF'
NAME=openclaw_up_cfg
SOURCE_CHOICE=1
CHANNEL_CHOICE=2
IMAGE=docker.io/1panel/openclaw:beta
HOST_PORT=4222
CONTAINER_PORT=18789
DATA_DIR=/opt/1panel/apps/openclaw_up_cfg
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv go
EXTRA_PORTS=6000:6000/udp
EOF
wizard_upgrade_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard upgrade --config-file "${wizard_upgrade_cfg}")
assert_contains "${wizard_upgrade_cfg_output}" "目标镜像: docker.io/1panel/openclaw:beta"
assert_contains "${wizard_upgrade_cfg_output}" "容器名: openclaw_up_cfg"
assert_contains "${wizard_upgrade_cfg_output}" "docker pull docker.io/1panel/openclaw:beta"
assert_contains "${wizard_upgrade_cfg_output}" "APT 源文件格式校验"
assert_contains "${wizard_upgrade_cfg_output}" "openclaw doctor --fix"
assert_contains "${wizard_upgrade_cfg_output}" "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true"
assert_contains "${wizard_upgrade_cfg_output}" "-p 6000:6000/udp"
assert_not_contains "${wizard_upgrade_cfg_output}" "=== 🔄 升级已有实例"

wizard_rebuild_cfg="${tmpdir}/rebuild.cfg"
cat > "${wizard_rebuild_cfg}" <<'EOF'
NAME=openclaw_re_cfg
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4333
CONTAINER_PORT=18789
DATA_DIR=/opt/1panel/apps/openclaw_re_cfg
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EXTRA_PORTS=4999:18090
EOF
wizard_rebuild_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard rebuild --config-file "${wizard_rebuild_cfg}")
assert_contains "${wizard_rebuild_cfg_output}" "目标镜像: ghcr.io/1186258278/openclaw-zh:latest"
assert_contains "${wizard_rebuild_cfg_output}" "容器名: openclaw_re_cfg"
assert_contains "${wizard_rebuild_cfg_output}" "docker rm -f openclaw_re_cfg"
assert_contains "${wizard_rebuild_cfg_output}" "-p 4999:18090"
assert_not_contains "${wizard_rebuild_cfg_output}" "=== 🛠️ 调整或重建实例"

wizard_uninstall_cfg="${tmpdir}/uninstall.cfg"
cat > "${wizard_uninstall_cfg}" <<'EOF'
NAME=openclaw_del_cfg
MODE=2
DATA_DIR=/opt/1panel/apps/openclaw_del_cfg
EOF
wizard_uninstall_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard uninstall --config-file "${wizard_uninstall_cfg}")
assert_contains "${wizard_uninstall_cfg_output}" "docker rm -f openclaw_del_cfg"
assert_contains "${wizard_uninstall_cfg_output}" "rm -rf /opt/1panel/apps/openclaw_del_cfg"
assert_not_contains "${wizard_uninstall_cfg_output}" "=== 🗑️ 卸载实例 ==="

wizard_easyclaw_cfg="${tmpdir}/easyclaw.cfg"
cat > "${wizard_easyclaw_cfg}" <<'EOF'
NAME=openclaw_easy_cfg
DATA_DIR=/opt/1panel/apps/openclaw_easy_cfg
EOF
wizard_easyclaw_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard easyclaw --config-file "${wizard_easyclaw_cfg}")
assert_contains "${wizard_easyclaw_cfg_output}" "git -C /opt/1panel/apps/openclaw_easy_cfg/software/easyclaw fetch --all --prune"
assert_not_contains "${wizard_easyclaw_cfg_output}" "=== 📦 管理 EasyClaw 工具 ==="

wizard_deps_cfg="${tmpdir}/deps.cfg"
cat > "${wizard_deps_cfg}" <<'EOF'
NAME=openclaw_deps_cfg
DATA_DIR=/opt/1panel/apps/openclaw_deps_cfg
MODE=check
TARGET_DEPS=npm uv go
EOF
wizard_deps_cfg_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard deps --config-file "${wizard_deps_cfg}")
assert_contains "${wizard_deps_cfg_output}" "开始检测容器依赖: npm uv go"
assert_contains "${wizard_deps_cfg_output}" "依赖检测模式: 仅检测，不安装"
assert_not_contains "${wizard_deps_cfg_output}" "=== 🔧 检查或补齐运行环境 ==="

set +e
wizard_invalid_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard invalid 2>&1)
wizard_invalid_status=$?
set -e
if [[ "${wizard_invalid_status}" -eq 0 ]]; then
  fail "expected invalid wizard selector to fail"
fi
assert_contains "${wizard_invalid_output}" "无效的 wizard"

# 1) install wizard: single-screen grouped editing + chinese stable + deps default(npm/uv)
install_input=$'2\n1\n1\n2\n1\n2\nopenclaw_demo\n3\n/opt/1panel/apps/openclaw_demo\n1\n2\n2\n2\n4\n2\n4113\n18789\n\n5\n1\n1\n1\n1\n2\n2\n\n6\n1\nc\ny\n0\n'
install_output=$(printf "%s" "${install_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${install_output}" "1) 🚀 安装新实例"
assert_contains "${install_output}" "=== 🚀 安装新实例 ==="
assert_contains "${install_output}" "1) 📦 版本镜像选择: 未选择"
assert_contains "${install_output}" "2) 🐳 容器名: 未选择"
assert_contains "${install_output}" "3) 💾 持久化目录管理:"
assert_contains "${install_output}" "4) 🌐 网络设置:"
assert_contains "${install_output}" "5) 🧩 功能加强:"
assert_contains "${install_output}" "6) 🔐 鉴权方式管理:"
assert_not_contains "${install_output}" "--- 📦 版本镜像选择 ---"
assert_contains "${install_output}" "ghcr.io/1186258278/openclaw-zh:latest"
assert_contains "${install_output}" "docker run --rm --user root -v /opt/1panel/apps/openclaw_demo:/root/.openclaw"
assert_contains "${install_output}" "openclaw config set gateway.bind lan"
assert_contains "${install_output}" "docker run -d --name openclaw_demo"
assert_contains "${install_output}" "docker exec openclaw_demo sh -lc <runtime-path-repair-script>"
assert_contains "${install_output}" "git clone https://github.com/moshall/easyclaw.git /opt/1panel/apps/openclaw_demo/software/easyclaw"
assert_contains "${install_output}" "docker exec openclaw_demo bash -lc <easyclaw-install-script>"
assert_contains "${install_output}" "docker exec -it openclaw_demo easyclaw tui"
assert_contains "${install_output}" "docker exec -it openclaw_demo easyclaw web --port 4231"
assert_contains "${install_output}" "开始检测容器依赖: npm uv"
assert_contains "${install_output}" "/runtime/root-local-bin:/root/.local/bin"
assert_contains "${install_output}" "/runtime/root-go-bin:/root/go/bin"
assert_contains "${install_output}" "/runtime/path-shims"
assert_contains "${install_output}" "/runtime/path-decls/openclaw-runtime-path.sh"
assert_not_contains "${install_output}" "/runtime/usr-local-go:/usr/local/go"
assert_contains "${install_output}" "-p 4231:4231"
assert_contains "${install_output}" "TOKEN="
assert_not_contains "${install_output}" "Openclaw_Easy_Cli"

# 2) upgrade wizard: single-screen grouped editing + official beta + env persistence(on) + deps include go
upgrade_input=$'2\n2\nopenclaw_demo\n1\n1\n2\n2\n/opt/1panel/apps/openclaw_demo\n1\n1\n1\n1\n3\n4113\n18789\n\n4\n1\n1\n1\n1\n1\n2\n\n5\n\nc\ny\n0\n'
upgrade_output=$(printf "%s" "${upgrade_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${upgrade_output}" "2) 🔄 升级已有实例"
assert_contains "${upgrade_output}" "=== 🔄 升级已有实例：openclaw_demo ==="
assert_contains "${upgrade_output}" "=== 升级前环境检测 ==="
assert_contains "${upgrade_output}" "1) 📦 目标版本:"
assert_contains "${upgrade_output}" "2) 💾 数据保存:"
assert_contains "${upgrade_output}" "3) 🌐 网络访问:"
assert_contains "${upgrade_output}" "4) 🧩 功能加强:"
assert_contains "${upgrade_output}" "5) 🔎 查看升级前检测摘要"
assert_not_contains "${upgrade_output}" "--- 📦 目标版本 ---"
assert_contains "${upgrade_output}" "docker pull docker.io/1panel/openclaw:beta"
assert_contains "${upgrade_output}" "mkdir -p /opt/1panel/apps/openclaw_demo/runtime/root-local-bin"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/root/.local/bin/. /opt/1panel/apps/openclaw_demo/runtime/root-local-bin/"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/usr/local/go/. /opt/1panel/apps/openclaw_demo/runtime/usr-local-go/"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/usr/local/lib/node_modules/. /opt/1panel/apps/openclaw_demo/runtime/usr-local-lib-node-modules/"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/root/.local/lib/. /opt/1panel/apps/openclaw_demo/runtime/root-local-lib/"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/root/.config/. /opt/1panel/apps/openclaw_demo/runtime/root-config/"
assert_contains "${upgrade_output}" "docker cp openclaw_demo:/root/.docker/. /opt/1panel/apps/openclaw_demo/runtime/root-docker/"
assert_contains "${upgrade_output}" "docker exec openclaw_demo sh -lc <apt-manual-snapshot-script>"
assert_contains "${upgrade_output}" "docker rm -f openclaw_demo"
assert_contains "${upgrade_output}" "-v /opt/1panel/apps/openclaw_demo:/root/.openclaw"
assert_contains "${upgrade_output}" "/runtime/usr-local-go:/usr/local/go"
assert_contains "${upgrade_output}" "/runtime/usr-local-lib-node-modules:/usr/local/lib/node_modules"
assert_contains "${upgrade_output}" "/runtime/root-local-lib:/root/.local/lib"
assert_contains "${upgrade_output}" "/runtime/root-config:/root/.config"
assert_contains "${upgrade_output}" "/runtime/root-docker:/root/.docker"
assert_contains "${upgrade_output}" "/runtime/root-aws:/root/.aws"
assert_contains "${upgrade_output}" "/runtime/root-kube:/root/.kube"
assert_contains "${upgrade_output}" "/runtime/root-netrc:/root/.netrc"
assert_contains "${upgrade_output}" "/runtime/root-npmrc:/root/.npmrc"
assert_contains "${upgrade_output}" "/runtime/root-pypirc:/root/.pypirc"
assert_contains "${upgrade_output}" "/runtime/path-shims"
assert_contains "${upgrade_output}" "/runtime/path-decls/openclaw-runtime-path.sh"
assert_contains "${upgrade_output}" "docker exec openclaw_demo sh -lc <auth-perms-fix-script>"
assert_contains "${upgrade_output}" "docker exec openclaw_demo sh -lc <apt-manual-restore-script>"
assert_contains "${upgrade_output}" "docker exec openclaw_demo sh -lc <runtime-path-repair-script>"
assert_contains "${upgrade_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw fetch --all --prune"
assert_contains "${upgrade_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw pull --ff-only"
assert_contains "${upgrade_output}" "docker exec openclaw_demo bash -lc <easyclaw-install-script>"
assert_contains "${upgrade_output}" "开始检测容器依赖: npm uv go"
assert_contains "${upgrade_output}" "依赖档案将保存到:"
assert_contains "${upgrade_output}" "-p 4231:4231"
assert_not_contains "${upgrade_output}" "software/easy_cli"

# 3) uninstall wizard: safe mode keeps data directory
uninstall_safe_input=$'2\n6\nopenclaw_demo\n1\n\nopenclaw_demo\n0\n'
uninstall_safe_output=$(printf "%s" "${uninstall_safe_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${uninstall_safe_output}" "docker rm -f openclaw_demo"
assert_not_contains "${uninstall_safe_output}" "rm -rf /opt/1panel/apps/openclaw_demo"

# 4) uninstall wizard: full mode deletes data directory
uninstall_full_input=$'2\n6\nopenclaw_demo\n2\n\nopenclaw_demo\n0\n'
uninstall_full_output=$(printf "%s" "${uninstall_full_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${uninstall_full_output}" "docker rm -f openclaw_demo"
assert_contains "${uninstall_full_output}" "rm -rf /opt/1panel/apps/openclaw_demo"

# 5) easyclaw-only upgrade
easy_cli_only_input=$'2\n4\nopenclaw_demo\n\ny\n0\n'
easy_cli_only_output=$(printf "%s" "${easy_cli_only_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${easy_cli_only_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw fetch --all --prune"
assert_contains "${easy_cli_only_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw pull --ff-only"
assert_contains "${easy_cli_only_output}" "docker exec openclaw_demo bash -lc <easyclaw-install-script>"

# 6) upgrade should allow abort when container is detected as running
upgrade_abort_input=$'2\n2\nopenclaw_demo\n1\n1\n2\nc\nn\nq\n0\n'
upgrade_abort_output=$(printf "%s" "${upgrade_abort_input}" | OPENCLAWCTL_RUNNING_STATE=running bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${upgrade_abort_output}" "检测到容器 openclaw_demo 正在运行，升级会中断当前任务。"
assert_contains "${upgrade_abort_output}" "已取消"
assert_not_contains "${upgrade_abort_output}" "docker pull"

# 7) standalone dependency check/install menu (default npm/uv, go optional)
deps_menu_input=$'2\n5\nopenclaw_demo\n/opt/1panel/apps/openclaw_demo\n1\n1\n1\n2\n2\n\ny\n0\n'
deps_menu_output=$(printf "%s" "${deps_menu_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${deps_menu_output}" "开始检测容器依赖: npm uv"
assert_contains "${deps_menu_output}" "uv兼容模式: Debian/Ubuntu 遇到 PEP668 时自动回退安装"
assert_contains "${deps_menu_output}" "[RUN] docker exec openclaw_demo sh -lc <runtime-deps-script>"

# 8) install should still print TOKEN/URL when optional deps step fails
install_fail_output=$(printf "%s" "${install_input}" | OPENCLAWCTL_TEST_FORCE_DEPS_FAIL=1 bash "${SCRIPT_PATH}" --dry-run 2>&1)
assert_contains "${install_fail_output}" "TOKEN="
assert_contains "${install_fail_output}" "URL=http://<server-ip>:4113/?token="
assert_contains "${install_fail_output}" "以下可选步骤失败（主应用已可用）"

# 9) install wizard should support extra port mappings in one run
install_extra_ports_input=$'2\n1\n1\n2\n1\n2\nopenclaw_ports\n4\n2\n4113\n18789\n5001:5001,6000:6000/udp\nc\ny\n0\n'
install_extra_ports_output=$(printf "%s" "${install_extra_ports_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_extra_ports_output}" "-p 4113:18789"
assert_contains "${install_extra_ports_output}" "-p 5001:5001"
assert_contains "${install_extra_ports_output}" "-p 6000:6000/udp"

# 10) extra ports input should ignore control chars and not corrupt menu output
install_extra_ports_ctrl_input=$'2\n1\n1\n2\n1\n2\nopenclaw_ports_ctrl\n4\n2\n4113\n18789\n5002:5002\e[D\e[A\nc\ny\n0\n'
install_extra_ports_ctrl_output=$(printf "%b" "${install_extra_ports_ctrl_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_extra_ports_ctrl_output}" "-p 5002:5002"
assert_not_contains "${install_extra_ports_ctrl_output}" $'\e'

# 11) install should support optional apt-config/cache persistence mounts
install_ext_persist_input=$'2\n1\n1\n2\n1\n2\nopenclaw_extpersist\n3\n/opt/1panel/apps/openclaw_extpersist\n1\n2\n1\n1\nc\ny\n0\n'
install_ext_persist_output=$(printf "%s" "${install_ext_persist_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_ext_persist_output}" "/runtime/etc-apt-sources-list-d:/etc/apt/sources.list.d"
assert_contains "${install_ext_persist_output}" "/runtime/etc-apt-keyrings:/etc/apt/keyrings"
assert_contains "${install_ext_persist_output}" "/runtime/root-npm-cache:/root/.npm"
assert_contains "${install_ext_persist_output}" "/runtime/root-go-pkg-mod:/root/go/pkg/mod"

# 12) safe rebuild should run migration then recreate container
rebuild_input=$'2\n3\nopenclaw_rebuild\nc\ny\n0\n'
rebuild_output=$(printf "%s" "${rebuild_input}" | OPENCLAWCTL_TEST_CURRENT_IMAGE=ghcr.io/1186258278/openclaw-zh:latest bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${rebuild_output}" "3) 🛠️ 调整或重建实例"
assert_contains "${rebuild_output}" "=== 🛠️ 调整或重建实例：openclaw_rebuild ==="
assert_contains "${rebuild_output}" "=== 升级前环境检测 ==="
assert_contains "${rebuild_output}" "ghcr.io/1186258278/openclaw-zh:latest"
assert_contains "${rebuild_output}" "docker rm -f openclaw_rebuild"
assert_contains "${rebuild_output}" "docker run -d --name openclaw_rebuild"
assert_contains "${rebuild_output}" "-p 4231:4231"
assert_contains "${rebuild_output}" "docker exec openclaw_rebuild sh -lc <runtime-path-repair-script>"

# 13) install should support official source custom tag selection via fetched tags
install_official_tag_input=$'2\n1\n1\n1\n3\n3\n2\nopenclaw_official_tag\nc\ny\n0\n'
install_official_tag_output=$(printf "%s" "${install_official_tag_input}" | OPENCLAWCTL_TEST_OFFICIAL_TAGS='latest,beta,2026.2.26,2026.2.20' bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_official_tag_output}" "docker pull docker.io/1panel/openclaw:2026.2.26"
assert_contains "${install_official_tag_output}" "镜像: docker.io/1panel/openclaw:2026.2.26"

# 14) default data root should follow OPENCLAWCTL_DATA_ROOT
custom_data_root="${tmpdir}/custom-data-root"
install_custom_root_input=$'2\n1\n1\n2\n1\n2\nopenclaw_custom_root\nc\ny\n0\n'
install_custom_root_output=$(printf "%s" "${install_custom_root_input}" | OPENCLAWCTL_DATA_ROOT="${custom_data_root}" bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_custom_root_output}" "持久化目录: ${custom_data_root}/openclaw_custom_root"

# 15) strict non-interactive mode should require wizard + config-file
set +e
strict_missing_flags_output=$(printf '0\n' | OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash "${SCRIPT_PATH}" --dry-run 2>&1)
strict_missing_flags_status=$?
set -e
if [[ "${strict_missing_flags_status}" -eq 0 ]]; then
  fail "expected strict non-interactive mode without wizard/config to fail"
fi
assert_contains "${strict_missing_flags_output}" "STRICT_NONINTERACTIVE 模式要求同时提供 --wizard 与 --config-file"

# 16) strict non-interactive install should emit deterministic strict report path
strict_install_output=$(OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_cfg}")
assert_contains "${strict_install_output}" "STRICT_REPORT_PATH="
assert_contains "${strict_install_output}" "/runtime/strict-report.json"

# 17) official custom tag should fallback to nearest available tag before pull
tag_fallback_cfg="${tmpdir}/tag-fallback.cfg"
cat > "${tag_fallback_cfg}" <<'EOF'
SOURCE_CHOICE=1
CHANNEL_CHOICE=3
OFFICIAL_TAG=260226
NAME=openclaw_tag_fallback
DATA_DIR=/opt/1panel/apps/openclaw_tag_fallback
HOST_PORT=4113
CONTAINER_PORT=18789
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
DEPS_INSTALL_CHOICE=2
EOF
tag_fallback_output=$(OPENCLAWCTL_TEST_OFFICIAL_TAGS='latest,beta,2026.2.26,2026.2.20' bash "${SCRIPT_PATH}" --dry-run --wizard upgrade --config-file "${tag_fallback_cfg}" 2>&1)
assert_contains "${tag_fallback_output}" "官方标签 260226 不存在"
assert_contains "${tag_fallback_output}" "docker pull docker.io/1panel/openclaw:2026.2.26"
assert_not_contains "${tag_fallback_output}" "docker pull docker.io/1panel/openclaw:260226"

# 18) install should support optional software/skill selections via config file
wizard_install_feature_cfg="${tmpdir}/install-feature.cfg"
cat > "${wizard_install_feature_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4115
CONTAINER_PORT=18789
NAME=openclaw_feature_cfg
DATA_DIR=/opt/1panel/apps/openclaw_feature_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=token-feature
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
SOFTWARE_SET=gh,codex
SKILL_SET=obsidian-skills,security-checker
EXTRA_PORTS=
EOF
wizard_install_feature_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_feature_cfg}")
assert_contains "${wizard_install_feature_output}" "可选软件: GitHub CLI(gh)、Codex CLI"
assert_contains "${wizard_install_feature_output}" "Skills: Obsidian Skills、Skill 安全检查"
assert_contains "${wizard_install_feature_output}" "docker exec openclaw_feature_cfg bash -lc <software-gh-install-script>"
assert_contains "${wizard_install_feature_output}" "docker exec openclaw_feature_cfg bash -lc <software-npm-codex-install-script>"
assert_contains "${wizard_install_feature_output}" "git clone --depth=1 https://github.com/kepano/obsidian-skills.git /opt/1panel/apps/openclaw_feature_cfg/workspace/skills/obsidian-skills"
assert_contains "${wizard_install_feature_output}" "git clone --depth=1 --filter=blob:none --sparse https://github.com/moshall/skill_collcet.git /opt/1panel/apps/openclaw_feature_cfg/workspace/skills/security-checker"

# 19) native npm mode should support dry-run config execution
native_cfg="${tmpdir}/native.cfg"
cat > "${native_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=2
OFFICIAL_TAG=
NAME=openclaw_native_cfg
DATA_DIR=/opt/1panel/apps/openclaw_native_cfg
NATIVE_PREFIX=/opt/1panel/apps/openclaw_native_cfg/native
SOFTWARE_SET=codex,gh
SKILL_SET=obsidian-skills
EOF
native_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard native --config-file "${native_cfg}")
assert_contains "${native_output}" "npm install -g --prefix /opt/1panel/apps/openclaw_native_cfg/native @qingchencloud/openclaw-zh@nightly"
assert_contains "${native_output}" "npm install -g --prefix /opt/1panel/apps/openclaw_native_cfg/native @openai/codex"
assert_contains "${native_output}" "[RUN] host software gh install"
assert_contains "${native_output}" "git clone --depth=1 https://github.com/kepano/obsidian-skills.git /opt/1panel/apps/openclaw_native_cfg/workspace/skills/obsidian-skills"
assert_contains "${native_output}" "可选软件："
assert_contains "${native_output}" "Codex CLI"
assert_contains "${native_output}" "GitHub CLI(gh)"
assert_contains "${native_output}" "Skills：Obsidian Skills"
assert_contains "${native_output}" "原生 npm 安装结果"

native_hostdeps_output=$(OPENCLAWCTL_AUTO_FIX_HOST_DEPS=1 OPENCLAWCTL_TEST_HOST_OS=linux OPENCLAWCTL_TEST_HOST_OS_ID=ubuntu OPENCLAWCTL_TEST_HOST_OS_VERSION=20.10 OPENCLAWCTL_TEST_HOST_PM=apt OPENCLAWCTL_TEST_HOST_NODE_MAJOR=20 OPENCLAWCTL_TEST_HOST_HAS_NPM=0 OPENCLAWCTL_TEST_HOST_CMAKE_VERSION=3.16.3 OPENCLAWCTL_TEST_HOST_HAS_GCC=0 OPENCLAWCTL_TEST_HOST_HAS_GPP=0 OPENCLAWCTL_TEST_HOST_HAS_MAKE=0 OPENCLAWCTL_TEST_HOST_HAS_GIT=0 OPENCLAWCTL_TEST_HOST_HAS_PKG_CONFIG=0 OPENCLAWCTL_TEST_HOST_HAS_PYTHON3=0 OPENCLAWCTL_TEST_HOST_HAS_PIP3=0 bash "${SCRIPT_PATH}" --dry-run --wizard native --config-file "${native_cfg}")
assert_contains "${native_hostdeps_output}" "native 宿主机依赖检查"
assert_contains "${native_hostdeps_output}" "deb.nodesource.com/setup_22.x"
assert_contains "${native_hostdeps_output}" "build-essential"
assert_contains "${native_hostdeps_output}" "python3-pip"

# 19b) 1panel wizard should support linux dry-run install and reject non-linux
panel_install_linux_output=$(OPENCLAWCTL_TEST_HOST_PLATFORM=linux bash "${SCRIPT_PATH}" --dry-run --wizard panel-install <<< $'y\n')
assert_contains "${panel_install_linux_output}" "=== 📥 安装 1Panel ==="
assert_contains "${panel_install_linux_output}" "quick_start.sh"

panel_install_nonlinux_output=$(OPENCLAWCTL_TEST_HOST_PLATFORM=darwin bash "${SCRIPT_PATH}" --dry-run --wizard panel-install 2>&1 || true)
assert_contains "${panel_install_nonlinux_output}" "1Panel 安装仅支持 Linux 主机"

# 20) adopt mode should output inferred config summary in dry-run
adopt_cfg="${tmpdir}/adopt.cfg"
cat > "${adopt_cfg}" <<'EOF'
NAME=openclaw_adopt_cfg
EOF
adopt_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard adopt --config-file "${adopt_cfg}")
assert_contains "${adopt_output}" "接管结果"
assert_contains "${adopt_output}" "容器名: openclaw_adopt_cfg"
assert_contains "${adopt_output}" "配置文件:"

# 21) persist mode should route through rebuild flow in config mode
persist_cfg="${tmpdir}/persist.cfg"
cat > "${persist_cfg}" <<'EOF'
NAME=openclaw_persist_cfg
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4334
CONTAINER_PORT=18789
DATA_DIR=/opt/1panel/apps/openclaw_persist_cfg
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EOF
persist_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard persist --config-file "${persist_cfg}")
assert_contains "${persist_output}" "docker rm -f openclaw_persist_cfg"
assert_contains "${persist_output}" "/runtime/etc-apt-sources-list-d:/etc/apt/sources.list.d"

# 22) deployment info wizard should print deterministic deployment-info path
info_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard info)
assert_contains "${info_output}" "deployment-info.txt"
assert_contains "${info_output}" ".openclaw-installer"

# 23) install config should accept catalog-driven software extensions (easyclaw/obsidian)
wizard_install_catalog_cfg="${tmpdir}/install-catalog.cfg"
cat > "${wizard_install_catalog_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4116
CONTAINER_PORT=18789
NAME=openclaw_catalog_cfg
DATA_DIR=/opt/1panel/apps/openclaw_catalog_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=token-catalog
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
SOFTWARE_SET=easyclaw,obsidian
SKILL_SET=obsidian-skills
EXTRA_PORTS=
EOF
wizard_install_catalog_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_catalog_cfg}")
assert_contains "${wizard_install_catalog_output}" "可选软件: EasyClaw、Obsidian CLI"

# 24) positional info command should be accepted (openclaw info style)
set +e
positional_info_output=$(bash "${SCRIPT_PATH}" info --dry-run 2>&1)
positional_info_status=$?
set -e
if [[ "${positional_info_status}" -ne 0 ]]; then
  fail "expected positional info command to succeed"
fi
assert_contains "${positional_info_output}" "deployment-info.txt"

# 25) install config should support claudecodeui + taskmaster and auto reserved port mapping
wizard_install_claudecodeui_cfg="${tmpdir}/install-claudecodeui.cfg"
cat > "${wizard_install_claudecodeui_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4117
CONTAINER_PORT=18789
NAME=openclaw_claudecodeui_cfg
DATA_DIR=/opt/1panel/apps/openclaw_claudecodeui_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=token-claudecodeui
DEPS_INSTALL_CHOICE=2
TARGET_DEPS=uv
SOFTWARE_SET=claudecodeui
SKILL_SET=
EXTRA_PORTS=
EOF
wizard_install_claudecodeui_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_claudecodeui_cfg}")
assert_contains "${wizard_install_claudecodeui_output}" "可选软件: ClaudeCodeUI(TaskMaster AI)"
assert_contains "${wizard_install_claudecodeui_output}" "-p 4118:7201"
assert_contains "${wizard_install_claudecodeui_output}" "docker exec openclaw_claudecodeui_cfg bash -lc <software-claudecodeui-install-script>"

# 26) install config should support rust deps and rust runtime persistence mounts
wizard_install_rust_cfg="${tmpdir}/install-rust.cfg"
cat > "${wizard_install_rust_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4119
CONTAINER_PORT=18789
NAME=openclaw_rust_cfg
DATA_DIR=/opt/1panel/apps/openclaw_rust_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=token-rust
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv rust
SOFTWARE_SET=
SKILL_SET=
EXTRA_PORTS=
EOF
wizard_install_rust_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_rust_cfg}")
assert_contains "${wizard_install_rust_output}" "开始检测容器依赖: npm uv rust"
assert_contains "${wizard_install_rust_output}" "依赖清单: npm uv rust"
assert_contains "${wizard_install_rust_output}" "/runtime/root-cargo-bin:/root/.cargo/bin"
assert_contains "${wizard_install_rust_output}" "/runtime/root-rustup:/root/.rustup"
assert_contains "${wizard_install_rust_output}" "/runtime/root-cargo-registry:/root/.cargo/registry"
assert_contains "${wizard_install_rust_output}" "/runtime/root-cargo-git:/root/.cargo/git"

# 27) install config should support ralph-orchestrator optional software
wizard_install_ralph_cfg="${tmpdir}/install-ralph.cfg"
cat > "${wizard_install_ralph_cfg}" <<'EOF'
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4120
CONTAINER_PORT=18789
NAME=openclaw_ralph_cfg
DATA_DIR=/opt/1panel/apps/openclaw_ralph_cfg
BIND_CHOICE=2
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=2
CACHE_PERSIST_CHOICE=2
EASY_CHOICE=2
TOKEN_MODE=2
TOKEN_MANUAL=token-ralph
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=uv
SOFTWARE_SET=ralph
SKILL_SET=
EXTRA_PORTS=
EOF
wizard_install_ralph_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard install --config-file "${wizard_install_ralph_cfg}")
assert_contains "${wizard_install_ralph_output}" "可选软件: Ralph Orchestrator"
assert_contains "${wizard_install_ralph_output}" "docker exec openclaw_ralph_cfg bash -lc <software-npm-ralph-install-script>"

# 28) upgrade should reload software profile and auto-keepalive selected software
upgrade_profile_data_dir="${tmpdir}/openclaw_upgrade_profile"
mkdir -p "${upgrade_profile_data_dir}/runtime"
cat > "${upgrade_profile_data_dir}/runtime/software.profile" <<'EOF'
notebooklm
EOF
wizard_upgrade_profile_cfg="${tmpdir}/upgrade-profile.cfg"
cat > "${wizard_upgrade_profile_cfg}" <<EOF
NAME=openclaw_upgrade_profile
SOURCE_CHOICE=2
CHANNEL_CHOICE=1
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4340
CONTAINER_PORT=18789
DATA_DIR=${upgrade_profile_data_dir}
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
EASY_CHOICE=2
DEPS_INSTALL_CHOICE=2
TARGET_DEPS=npm uv
EXTRA_PORTS=
EOF
wizard_upgrade_profile_output=$(bash "${SCRIPT_PATH}" --dry-run --wizard upgrade --config-file "${wizard_upgrade_profile_cfg}")
assert_contains "${wizard_upgrade_profile_output}" "检测到已保存的软件档案，升级后将自动保活"
assert_contains "${wizard_upgrade_profile_output}" "已自动开启升级后依赖补齐流程"
assert_contains "${wizard_upgrade_profile_output}" "开始检测容器依赖: npm uv python3"
assert_contains "${wizard_upgrade_profile_output}" "docker exec openclaw_upgrade_profile bash -lc <software-notebooklm-install-script>"

# 29) persist should auto avoid easyclaw web host-port conflicts
persist_conflict_cfg="${tmpdir}/persist-conflict.cfg"
cat > "${persist_conflict_cfg}" <<'EOF'
NAME=openclaw_persist_conflict
IMAGE=ghcr.io/1186258278/openclaw-zh:latest
HOST_PORT=4335
CONTAINER_PORT=18789
DATA_DIR=/opt/1panel/apps/openclaw_persist_conflict
BIN_PERSIST_CHOICE=1
ENV_PERSIST_CHOICE=1
APT_CFG_PERSIST_CHOICE=1
CACHE_PERSIST_CHOICE=1
DEPS_INSTALL_CHOICE=1
TARGET_DEPS=npm uv
EOF
persist_conflict_output=$(OPENCLAWCTL_TEST_OCCUPIED_PORTS=4231 bash "${SCRIPT_PATH}" --dry-run --wizard persist --config-file "${persist_conflict_cfg}")
assert_contains "${persist_conflict_output}" "-p 5231:4231"
assert_not_contains "${persist_conflict_output}" "-p 4231:4231"

# 30) strict non-interactive adopt should emit strict report path
strict_adopt_output=$(OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash "${SCRIPT_PATH}" --dry-run --wizard adopt --config-file "${adopt_cfg}")
assert_contains "${strict_adopt_output}" "STRICT_REPORT_PATH="
assert_contains "${strict_adopt_output}" "/runtime/strict-report.json"

echo "[PASS] interactive openclawctl tests"
