#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
SCRIPT_PATH="${ROOT_DIR}/Openclaw_docker_install/openclawctl.sh"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
  SCRIPT_PATH="${ROOT_DIR}/openclawctl.sh"
fi
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

# 0) launcher should prefer TUI binary in interactive mode but fall back in non-TTY mode
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

launcher_shell_output=$(printf '0\n' | OPENCLAWCTL_TUI_BIN="${fake_tui}" bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${launcher_shell_output}" "OpenClaw 部署助手"
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
install_input=$'1\n1\n2\n1\n2\nopenclaw_demo\n3\n/opt/1panel/apps/openclaw_demo\n1\n2\n2\n2\n4\n2\n4113\n18789\n\n5\n1\n1\n1\n1\n2\n\n6\n1\nc\ny\n0\n'
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
assert_not_contains "${install_output}" "/runtime/usr-local-go:/usr/local/go"
assert_contains "${install_output}" "-p 4231:4231"
assert_contains "${install_output}" "TOKEN="
assert_not_contains "${install_output}" "Openclaw_Easy_Cli"

# 2) upgrade wizard: single-screen grouped editing + official beta + env persistence(on) + deps include go
upgrade_input=$'2\nopenclaw_demo\n1\n1\n2\n2\n/opt/1panel/apps/openclaw_demo\n1\n1\n1\n1\n3\n4113\n18789\n\n4\n1\n1\n1\n1\n1\n\n5\n\nc\ny\n0\n'
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
uninstall_safe_input=$'6\nopenclaw_demo\n1\n\nopenclaw_demo\n0\n'
uninstall_safe_output=$(printf "%s" "${uninstall_safe_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${uninstall_safe_output}" "docker rm -f openclaw_demo"
assert_not_contains "${uninstall_safe_output}" "rm -rf /opt/1panel/apps/openclaw_demo"

# 4) uninstall wizard: full mode deletes data directory
uninstall_full_input=$'6\nopenclaw_demo\n2\n\nopenclaw_demo\n0\n'
uninstall_full_output=$(printf "%s" "${uninstall_full_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${uninstall_full_output}" "docker rm -f openclaw_demo"
assert_contains "${uninstall_full_output}" "rm -rf /opt/1panel/apps/openclaw_demo"

# 5) easyclaw-only upgrade
easy_cli_only_input=$'4\nopenclaw_demo\n\ny\n0\n'
easy_cli_only_output=$(printf "%s" "${easy_cli_only_input}" | bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${easy_cli_only_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw fetch --all --prune"
assert_contains "${easy_cli_only_output}" "git -C /opt/1panel/apps/openclaw_demo/software/easyclaw pull --ff-only"
assert_contains "${easy_cli_only_output}" "docker exec openclaw_demo bash -lc <easyclaw-install-script>"

# 6) upgrade should allow abort when container is detected as running
upgrade_abort_input=$'2\nopenclaw_demo\n1\n1\n2\nc\nn\nq\n0\n'
upgrade_abort_output=$(printf "%s" "${upgrade_abort_input}" | OPENCLAWCTL_RUNNING_STATE=running bash "${SCRIPT_PATH}" --dry-run)

assert_contains "${upgrade_abort_output}" "检测到容器 openclaw_demo 正在运行，升级会中断当前任务。"
assert_contains "${upgrade_abort_output}" "已取消"
assert_not_contains "${upgrade_abort_output}" "docker pull"

# 7) standalone dependency check/install menu (default npm/uv, go optional)
deps_menu_input=$'5\nopenclaw_demo\n/opt/1panel/apps/openclaw_demo\n1\n1\n1\n2\n\ny\n0\n'
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
install_extra_ports_input=$'1\n1\n2\n1\n2\nopenclaw_ports\n4\n2\n4113\n18789\n5001:5001,6000:6000/udp\nc\ny\n0\n'
install_extra_ports_output=$(printf "%s" "${install_extra_ports_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_extra_ports_output}" "-p 4113:18789"
assert_contains "${install_extra_ports_output}" "-p 5001:5001"
assert_contains "${install_extra_ports_output}" "-p 6000:6000/udp"

# 10) extra ports input should ignore control chars and not corrupt menu output
install_extra_ports_ctrl_input=$'1\n1\n2\n1\n2\nopenclaw_ports_ctrl\n4\n2\n4113\n18789\n5002:5002\e[D\e[A\nc\ny\n0\n'
install_extra_ports_ctrl_output=$(printf "%b" "${install_extra_ports_ctrl_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_extra_ports_ctrl_output}" "-p 5002:5002"
assert_not_contains "${install_extra_ports_ctrl_output}" $'\e'

# 11) install should support optional apt-config/cache persistence mounts
install_ext_persist_input=$'1\n1\n2\n1\n2\nopenclaw_extpersist\n3\n/opt/1panel/apps/openclaw_extpersist\n1\n2\n1\n1\nc\ny\n0\n'
install_ext_persist_output=$(printf "%s" "${install_ext_persist_input}" | bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_ext_persist_output}" "/runtime/etc-apt-sources-list-d:/etc/apt/sources.list.d"
assert_contains "${install_ext_persist_output}" "/runtime/etc-apt-keyrings:/etc/apt/keyrings"
assert_contains "${install_ext_persist_output}" "/runtime/root-npm-cache:/root/.npm"
assert_contains "${install_ext_persist_output}" "/runtime/root-go-pkg-mod:/root/go/pkg/mod"

# 12) safe rebuild should run migration then recreate container
rebuild_input=$'3\nopenclaw_rebuild\nc\ny\n0\n'
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
install_official_tag_input=$'1\n1\n1\n3\n3\n2\nopenclaw_official_tag\nc\ny\n0\n'
install_official_tag_output=$(printf "%s" "${install_official_tag_input}" | OPENCLAWCTL_TEST_OFFICIAL_TAGS='latest,beta,2026.2.26,2026.2.20' bash "${SCRIPT_PATH}" --dry-run)
assert_contains "${install_official_tag_output}" "docker pull docker.io/1panel/openclaw:2026.2.26"
assert_contains "${install_official_tag_output}" "镜像: docker.io/1panel/openclaw:2026.2.26"

# 14) default data root should follow OPENCLAWCTL_DATA_ROOT
custom_data_root="${tmpdir}/custom-data-root"
install_custom_root_input=$'1\n1\n2\n1\n2\nopenclaw_custom_root\nc\ny\n0\n'
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

echo "[PASS] interactive openclawctl tests"
