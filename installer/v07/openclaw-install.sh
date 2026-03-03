#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR="${SCRIPT_DIR}/lib"

# shellcheck source=installer/v07/lib/common.sh
source "${LIB_DIR}/common.sh"
# shellcheck source=installer/v07/lib/ui.sh
source "${LIB_DIR}/ui.sh"
# shellcheck source=installer/v07/lib/config.sh
source "${LIB_DIR}/config.sh"
# shellcheck source=installer/v07/lib/detect.sh
source "${LIB_DIR}/detect.sh"
# shellcheck source=installer/v07/lib/image.sh
source "${LIB_DIR}/image.sh"
# shellcheck source=installer/v07/lib/port.sh
source "${LIB_DIR}/port.sh"
# shellcheck source=installer/v07/lib/persist.sh
source "${LIB_DIR}/persist.sh"
# shellcheck source=installer/v07/lib/compose.sh
source "${LIB_DIR}/compose.sh"
# shellcheck source=installer/v07/lib/docker.sh
source "${LIB_DIR}/docker.sh"
# shellcheck source=installer/v07/lib/report.sh
source "${LIB_DIR}/report.sh"
# shellcheck source=installer/v07/lib/onepanel.sh
source "${LIB_DIR}/onepanel.sh"
# shellcheck source=installer/v07/lib/action.sh
source "${LIB_DIR}/action.sh"

V07_DRY_RUN=0
V07_NON_INTERACTIVE=0
V07_CONFIG_FILE=""
V07_WIZARD_ACTION=""

v07_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        V07_DRY_RUN=1
        shift
        ;;
      --non-interactive)
        V07_NON_INTERACTIVE=1
        shift
        ;;
      --config-file)
        [[ $# -ge 2 ]] || {
          v07_log_error "--config-file 需要路径参数"
          exit 1
        }
        V07_CONFIG_FILE="$2"
        shift 2
        ;;
      --wizard)
        [[ $# -ge 2 ]] || {
          v07_log_error "--wizard 需要动作参数"
          exit 1
        }
        V07_WIZARD_ACTION="$2"
        shift 2
        ;;
      --help|-h)
        v07_print_usage
        exit 0
        ;;
      *)
        v07_log_error "未知参数: $1"
        v07_print_usage
        exit 1
        ;;
    esac
  done
}

v07_enforce_strict_noninteractive() {
  if ! v07_strict_noninteractive_enabled; then
    return 0
  fi
  V07_NON_INTERACTIVE=1
  if [[ -z "${V07_WIZARD_ACTION}" || -z "${V07_CONFIG_FILE}" ]]; then
    v07_log_error "STRICT_NONINTERACTIVE 模式要求同时提供 --wizard 与 --config-file"
    exit 1
  fi
}

v07_validate_args() {
  if [[ "${V07_NON_INTERACTIVE}" == "1" && -z "${V07_CONFIG_FILE}" ]]; then
    v07_log_error "非交互模式要求提供 --config-file"
    exit 1
  fi
}

v07_load_optional_config() {
  if [[ -z "${V07_CONFIG_FILE}" ]]; then
    return 0
  fi
  if ! v07_load_config_file "${V07_CONFIG_FILE}"; then
    v07_log_error "配置文件不存在或不可读: ${V07_CONFIG_FILE}"
    return 1
  fi
  v07_log_info "已加载配置文件: ${V07_CONFIG_FILE}"
  return 0
}

v07_pick_interactive_action() {
  cat <<'MENU'
请选择安装方式：
  [1] install
  [2] upgrade
  [3] rebuild
  [4] status
  [5] logs
  [6] uninstall
  [0] exit
MENU
  local action_choice=""
  read -r -p "请输入动作编号 [0]: " action_choice || true
  case "${action_choice:-0}" in
    1) printf 'install\n' ;;
    2) printf 'upgrade\n' ;;
    3) printf 'rebuild\n' ;;
    4) printf 'status\n' ;;
    5) printf 'logs\n' ;;
    6) printf 'uninstall\n' ;;
    0|"") printf 'exit\n' ;;
    *)
      v07_log_error "无效选择: ${action_choice}"
      return 1
      ;;
  esac
}

v07_run_entrypoint() {
  v07_print_banner
  v07_print_env_summary

  v07_load_optional_config || return 1

  if [[ -z "${V07_WIZARD_ACTION}" && -n "${CFG_ACTION:-}" ]]; then
    V07_WIZARD_ACTION="${CFG_ACTION}"
  fi

  local action="${V07_WIZARD_ACTION}"
  if [[ -z "${action}" ]]; then
    if [[ "${V07_NON_INTERACTIVE}" == "1" ]]; then
      v07_log_error "非交互模式下必须提供 --wizard"
      return 1
    fi
    action=$(v07_pick_interactive_action) || return 1
  fi

  if [[ "${action}" == "exit" ]]; then
    v07_log_info "已退出"
    return 0
  fi

  v07_log_info "执行动作: ${action}"
  v07_run_action "${action}"
}

main() {
  v07_parse_args "$@"
  v07_enforce_strict_noninteractive
  v07_validate_args
  v07_detect_environment
  v07_run_entrypoint
}

main "$@"
