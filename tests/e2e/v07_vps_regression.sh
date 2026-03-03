#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   TARGET_HOST=1.2.3.4 TARGET_USER=root TARGET_PASS=xxx ./tests/e2e/v07_vps_regression.sh

for k in TARGET_HOST TARGET_USER TARGET_PASS; do
  [[ -n "${!k:-}" ]] || {
    echo "missing required env: ${k}" >&2
    exit 2
  }
done

if ! command -v expect >/dev/null 2>&1; then
  echo "expect is required" >&2
  exit 2
fi

SCRIPT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOCAL_SCRIPT="${SCRIPT_ROOT}/installer/v07/openclaw-install.sh"
[[ -f "${LOCAL_SCRIPT}" ]] || {
  echo "missing local script: ${LOCAL_SCRIPT}" >&2
  exit 2
}

REMOTE_SCRIPT="/root/openclaw-install-v07.sh"
REMOTE_WORKDIR="/root/openclaw-v07-e2e"

expect <<EXPECT
set timeout 180
spawn scp -o StrictHostKeyChecking=no ${LOCAL_SCRIPT} ${TARGET_USER}@${TARGET_HOST}:${REMOTE_SCRIPT}
expect {
  "yes/no" { send -- "yes\r"; exp_continue }
  "*assword:*" { send -- "${TARGET_PASS}\r" }
}
expect eof
EXPECT

expect <<'EXPECT'
set timeout -1
spawn ssh -o StrictHostKeyChecking=no $env(TARGET_USER)@$env(TARGET_HOST) "bash -lc '
set -euo pipefail
chmod +x /root/openclaw-install-v07.sh
mkdir -p /root/openclaw-v07-e2e
cat > /root/openclaw-v07-e2e/install-linux.cfg <<CFG
CFG_ACTION=install
CFG_APP_NAME=openclaw_v07_linux
CFG_SOURCE=official
CFG_CHANNEL=custom
CFG_VERSION_REQUEST=260205
CFG_DATA_DIR=/data/openclaw_v07_linux
CFG_HOST_PORT=4313
CFG_PORT_RESERVED_1=4314
CFG_PORT_RESERVED_2=4315
CFG_PORT_RESERVED_3=4316
CFG_EASYCLAW_ENABLED=0
CFG_ACCESS_MODE=remote
CFG_AUTH_TOKEN=v07-linux-token
CFG_1PANEL_MODE=force_off
CFG_1PANEL_DEPLOY_MODE=compose
CFG
OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash /root/openclaw-install-v07.sh --wizard install --config-file /root/openclaw-v07-e2e/install-linux.cfg
'
"
expect {
  "yes/no" { send -- "yes\r"; exp_continue }
  "*assword:*" { send -- "$env(TARGET_PASS)\r"; exp_continue }
  eof
}
EXPECT

echo "[PASS] v0.7 VPS regression script completed (linux install stage)"
