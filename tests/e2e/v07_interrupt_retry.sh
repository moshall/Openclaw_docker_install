#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   TARGET_HOST=1.2.3.4 TARGET_USER=root TARGET_PASS=xxx ./tests/e2e/v07_interrupt_retry.sh

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

expect <<'EXPECT'
set timeout -1
spawn ssh -o StrictHostKeyChecking=no $env(TARGET_USER)@$env(TARGET_HOST) "bash -lc '
set -euo pipefail
cat > /root/openclaw-v07-e2e/upgrade.cfg <<CFG
CFG_ACTION=upgrade
CFG_APP_NAME=openclaw_v07_linux
CFG_SOURCE=official
CFG_CHANNEL=custom
CFG_VERSION_REQUEST=260226
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
OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash /root/openclaw-install-v07.sh --wizard upgrade --config-file /root/openclaw-v07-e2e/upgrade.cfg > /root/openclaw-v07-e2e/upgrade-interrupt.log 2>&1 &
UP_PID=$!
for i in $(seq 1 120); do
  if grep -q "docker compose -f" /root/openclaw-v07-e2e/upgrade-interrupt.log 2>/dev/null; then
    kill -9 "$UP_PID" || true
    break
  fi
  sleep 1
done
OPENCLAWCTL_STRICT_NONINTERACTIVE=1 bash /root/openclaw-install-v07.sh --wizard upgrade --config-file /root/openclaw-v07-e2e/upgrade.cfg
'
"
expect {
  "yes/no" { send -- "yes\r"; exp_continue }
  "*assword:*" { send -- "$env(TARGET_PASS)\r"; exp_continue }
  eof
}
EXPECT

echo "[PASS] v0.7 interrupt-retry script completed"
