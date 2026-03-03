#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMON_LIB="${ROOT_DIR}/installer/v07/lib/common.sh"
ONEPANEL_LIB="${ROOT_DIR}/installer/v07/lib/onepanel.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_contains() {
  local text="$1"
  local needle="$2"
  local label="$3"
  if [[ "${text}" != *"${needle}"* ]]; then
    fail "${label}: expected to contain '${needle}'"
  fi
}

[[ -f "${COMMON_LIB}" ]] || fail "missing common lib"
[[ -f "${ONEPANEL_LIB}" ]] || fail "missing onepanel lib"

# shellcheck source=installer/v07/lib/common.sh
source "${COMMON_LIB}"
# shellcheck source=installer/v07/lib/onepanel.sh
source "${ONEPANEL_LIB}"

payload=$(v07_1panel_build_compose_payload "openclaw_api_demo" "services:\n  app:\n    image: demo:latest")
assert_contains "${payload}" '"name":"openclaw_api_demo"' "payload app"
assert_contains "${payload}" '"compose":"services:\\n  app:\\n    image: demo:latest"' "payload compose"

mock_tmp=$(mktemp -d)
trap 'rm -rf "${mock_tmp}"' EXIT
cat > "${mock_tmp}/curl" <<'EOT'
#!/usr/bin/env bash
if printf '%s ' "$@" | grep -q '/health'; then
  echo '{"code":0}'
  exit 0
fi
if printf '%s ' "$@" | grep -q '/compose/create'; then
  echo '{"code":0,"message":"ok"}'
  exit 0
fi
exit 1
EOT
chmod +x "${mock_tmp}/curl"
OLD_PATH="${PATH}"
export PATH="${mock_tmp}:${OLD_PATH}"

v07_1panel_api_available "http://127.0.0.1:9999" || fail "expected api available"
v07_1panel_apply_compose_api "http://127.0.0.1:9999" "token-demo" "${payload}" || fail "expected apply success"

echo "[PASS] installer v0.7 1panel tests"
