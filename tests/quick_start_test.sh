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

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    fail "expected output NOT to contain: ${needle}"
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

quick_start_local_stdout="${tmpdir}/quick_start.stdout"
quick_start_local_stderr="${tmpdir}/quick_start.stderr"
OPENCLAWCTL_QUICKSTART_SOURCE_DIR="${fake_repo}" bash "${QUICK_START}" --dry-run >"${quick_start_local_stdout}" 2>"${quick_start_local_stderr}"
assert_contains "$(cat "${quick_start_local_stdout}")" "FAKE_OPENCLAWCTL_ARGS:--dry-run"
assert_not_contains "$(cat "${quick_start_local_stdout}")" "[quick-start]"
assert_contains "$(cat "${quick_start_local_stderr}")" "[quick-start] 启动 OpenClaw 菜单"

archive_parent="${tmpdir}/archive-root"
archive_repo="${archive_parent}/Openclaw_docker_install-test"
archive_file="${tmpdir}/quick-start-test.tar.gz"
mkdir -p "${archive_repo}/lib/openclawctl"
cp "${fake_repo}/openclawctl.sh" "${archive_repo}/openclawctl.sh"
tar -czf "${archive_file}" -C "${archive_parent}" "Openclaw_docker_install-test"

set +e
quick_start_remote_archive_output=$(OPENCLAWCTL_QUICKSTART_ARCHIVE_URLS="file://${archive_file}" OPENCLAWCTL_QUICKSTART_QUIET=1 bash "${QUICK_START}" --dry-run --wizard info 2>&1)
quick_start_remote_archive_status=$?
set -e
if [[ "${quick_start_remote_archive_status}" -ne 0 ]]; then
  fail "expected quick_start remote-archive mode to run successfully"
fi
assert_contains "${quick_start_remote_archive_output}" "FAKE_OPENCLAWCTL_ARGS:--dry-run --wizard info"

set +e
quick_start_missing_source_output=$(OPENCLAWCTL_QUICKSTART_SOURCE_DIR="${tmpdir}/not-found" OPENCLAWCTL_QUICKSTART_QUIET=1 bash "${QUICK_START}" 2>&1)
quick_start_missing_source_status=$?
set -e
if [[ "${quick_start_missing_source_status}" -eq 0 ]]; then
  fail "expected quick_start to fail when source dir is missing"
fi
assert_contains "${quick_start_missing_source_output}" "指定的本地源码目录不存在"

echo "[PASS] quick_start tests"
