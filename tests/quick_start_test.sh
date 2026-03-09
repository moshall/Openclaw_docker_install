#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
QUICK_START="${ROOT_DIR}/quick_start.sh"

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

[[ -f "${QUICK_START}" ]] || fail "missing quick_start script: ${QUICK_START}"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

fake_repo="${tmpdir}/fake-repo"
mkdir -p "${fake_repo}/lib/openclawctl"
cat > "${fake_repo}/openclawctl.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "FAKE_OPENCLAWCTL_ARGS:$*"
EOF
chmod +x "${fake_repo}/openclawctl.sh"

quick_start_local_output=$(OPENCLAWCTL_QUICKSTART_SOURCE_DIR="${fake_repo}" OPENCLAWCTL_QUICKSTART_QUIET=1 bash "${QUICK_START}" --dry-run --wizard info 2>&1)
assert_contains "${quick_start_local_output}" "FAKE_OPENCLAWCTL_ARGS:--dry-run --wizard info"

set +e
quick_start_missing_source_output=$(OPENCLAWCTL_QUICKSTART_SOURCE_DIR="${tmpdir}/not-found" OPENCLAWCTL_QUICKSTART_QUIET=1 bash "${QUICK_START}" 2>&1)
quick_start_missing_source_status=$?
set -e
if [[ "${quick_start_missing_source_status}" -eq 0 ]]; then
  fail "expected quick_start to fail when source dir is missing"
fi
assert_contains "${quick_start_missing_source_output}" "指定的本地源码目录不存在"

echo "[PASS] quick_start tests"
