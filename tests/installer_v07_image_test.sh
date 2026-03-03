#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
IMAGE_LIB="${ROOT_DIR}/installer/v07/lib/image.sh"

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
[[ -f "${IMAGE_LIB}" ]] || fail "missing image lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/image.sh
source "${IMAGE_LIB}"

v07_resolve_source_profile "chinese"
assert_eq "ghcr.io/1186258278/openclaw-zh" "${CFG_IMAGE_BASE}" "chinese image base"
assert_eq "root" "${CFG_CONTAINER_USER}" "chinese user"
assert_eq "/root" "${CFG_CONTAINER_HOME}" "chinese home"
assert_eq "@qingchencloud/openclaw-zh" "${CFG_NPM_PACKAGE}" "chinese npm"

v07_resolve_source_profile "official"
assert_eq "ghcr.io/openclaw/openclaw" "${CFG_IMAGE_BASE}" "official image base"
assert_eq "node" "${CFG_CONTAINER_USER}" "official user"
assert_eq "/home/node" "${CFG_CONTAINER_HOME}" "official home"
assert_eq "openclaw" "${CFG_NPM_PACKAGE}" "official npm"

assert_eq "2026.2.26" "$(v07_compact_tag_to_dotted 260226)" "compact tag map"
assert_eq "latest" "$(v07_compact_tag_to_dotted latest)" "non-compact keeps self"

export OPENCLAWCTL_TEST_OFFICIAL_TAGS="latest,2026.2.26,2026.2.25"
resolved=$(v07_resolve_official_tag_with_fallback "upgrade" "260226")
assert_eq "2026.2.26" "${resolved}" "fallback map"
unset OPENCLAWCTL_TEST_OFFICIAL_TAGS

# verify_official_version should use docker manifest inspect
mock_tmp=$(mktemp -d)
trap 'rm -rf "${mock_tmp}"' EXIT
cat > "${mock_tmp}/docker" <<'EOT'
#!/usr/bin/env bash
if [[ "$1" == "manifest" && "$2" == "inspect" ]]; then
  if [[ "$3" == "ghcr.io/openclaw/openclaw:2026.3.1" ]]; then
    exit 0
  fi
  exit 1
fi
exit 0
EOT
chmod +x "${mock_tmp}/docker"
OLD_PATH="${PATH}"
export PATH="${mock_tmp}:${OLD_PATH}"
ENV_ARCH="amd64"
v07_verify_official_version "2026.3.1" || fail "expected official version valid"
if v07_verify_official_version "2099.1.1"; then
  fail "expected missing version to fail"
fi

echo "[PASS] installer v0.7 image tests"
