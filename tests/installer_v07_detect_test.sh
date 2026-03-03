#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
CONFIG_LIB="${ROOT_DIR}/installer/v07/lib/config.sh"
DETECT_LIB="${ROOT_DIR}/installer/v07/lib/detect.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "${expected}" != "${actual}" ]]; then
    fail "${label}: expected='${expected}' actual='${actual}'"
  fi
}

[[ -f "${COMMON_LIB}" ]] || fail "missing common lib"
[[ -f "${CONFIG_LIB}" ]] || fail "missing config lib"
[[ -f "${DETECT_LIB}" ]] || fail "missing detect lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/config.sh
source "${CONFIG_LIB}"
# shellcheck source=installer/v07/lib/detect.sh
source "${DETECT_LIB}"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

mkdir -p "${tmpdir}/bin"
cat > "${tmpdir}/bin/uname" <<'EOT'
#!/usr/bin/env bash
if [[ "$1" == "-s" ]]; then
  echo "Linux"
elif [[ "$1" == "-m" ]]; then
  echo "x86_64"
else
  echo "Linux test"
fi
EOT
chmod +x "${tmpdir}/bin/uname"

cat > "${tmpdir}/bin/docker" <<'EOT'
#!/usr/bin/env bash
if [[ "$1" == "info" ]]; then
  exit 0
fi
if [[ "$1" == "--version" ]]; then
  echo "Docker version 27.1.1"
  exit 0
fi
if [[ "$1" == "compose" && "$2" == "version" ]]; then
  echo "Docker Compose version v2.29.0"
  exit 0
fi
exit 0
EOT
chmod +x "${tmpdir}/bin/docker"

cat > "${tmpdir}/bin/1pctl" <<'EOT'
#!/usr/bin/env bash
echo "1Panel v2.0.0"
EOT
chmod +x "${tmpdir}/bin/1pctl"

cat > "${tmpdir}/bin/node" <<'EOT'
#!/usr/bin/env bash
echo "v22.16.0"
EOT
chmod +x "${tmpdir}/bin/node"

cat > "${tmpdir}/os-release" <<'EOT'
ID=ubuntu
VERSION_ID="22.04"
EOT

mkdir -p "${tmpdir}/home/.openclaw-installer"
cat > "${tmpdir}/home/.openclaw-installer/config.env" <<'EOT'
CFG_APP_NAME=openclaw
EOT

OLD_PATH="${PATH}"
export PATH="${tmpdir}/bin:${OLD_PATH}"
export HOME="${tmpdir}/home"
export V07_TEST_OS_RELEASE_FILE="${tmpdir}/os-release"

v07_detect_environment

assert_eq "linux" "${ENV_OS}" "ENV_OS"
assert_eq "ubuntu" "${ENV_DISTRO}" "ENV_DISTRO"
assert_eq "amd64" "${ENV_ARCH}" "ENV_ARCH"
assert_eq "1" "${ENV_1PANEL}" "ENV_1PANEL"
assert_eq "1" "${ENV_DOCKER}" "ENV_DOCKER"
assert_eq "1" "${ENV_DOCKER_COMPOSE}" "ENV_DOCKER_COMPOSE"
assert_eq "1" "${ENV_EXISTING_INSTALL}" "ENV_EXISTING_INSTALL"
assert_eq "v22.16.0" "${ENV_NODE}" "ENV_NODE"

echo "[PASS] installer v0.7 detect tests"
