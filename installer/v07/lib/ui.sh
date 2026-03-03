#!/usr/bin/env bash

set -euo pipefail

v07_print_banner() {
  cat <<'BANNER'
╔══════════════════════════════════════════════╗
║   🦞 OpenClaw 一键安装向导 v0.7              ║
╚══════════════════════════════════════════════╝
BANNER
}

v07_print_usage() {
  cat <<'USAGE'
OpenClaw 一键安装向导 v0.7

用法:
  bash installer/v07/openclaw-install.sh [--dry-run] [--non-interactive] [--config-file PATH] [--wizard ACTION]

参数:
  --dry-run           仅输出执行计划，不真正执行
  --non-interactive   非交互模式（要求提供 --config-file）
  --config-file PATH  配置文件路径
  --wizard ACTION     直接执行动作（install|upgrade|rebuild|status|logs|uninstall）
  --help, -h          显示帮助
USAGE
}
