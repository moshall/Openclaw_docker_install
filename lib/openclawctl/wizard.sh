#!/usr/bin/env bash

openclawctl_wizard_unavailable() {
  log_error "wizard 模块函数应由入口脚本完整加载后使用"
  return 1
}

load_simple_config_file() { openclawctl_wizard_unavailable; }
run_install_from_config_file() { openclawctl_wizard_unavailable; }
run_upgrade_from_config_file() { openclawctl_wizard_unavailable; }
run_rebuild_from_config_file() { openclawctl_wizard_unavailable; }
run_uninstall_from_config_file() { openclawctl_wizard_unavailable; }
run_easyclaw_from_config_file() { openclawctl_wizard_unavailable; }
run_deps_from_config_file() { openclawctl_wizard_unavailable; }
run_native_from_config_file() { openclawctl_wizard_unavailable; }
info_wizard() { openclawctl_wizard_unavailable; }
native_npm_wizard() { openclawctl_wizard_unavailable; }
native_upgrade_wizard() { openclawctl_wizard_unavailable; }
native_repair_wizard() { openclawctl_wizard_unavailable; }
native_info_wizard() { openclawctl_wizard_unavailable; }
native_uninstall_wizard() { openclawctl_wizard_unavailable; }
adopt_wizard() { openclawctl_wizard_unavailable; }
persist_append_wizard() { openclawctl_wizard_unavailable; }
install_wizard() { openclawctl_wizard_unavailable; }
upgrade_wizard() { openclawctl_wizard_unavailable; }
safe_rebuild_wizard() { openclawctl_wizard_unavailable; }
uninstall_wizard() { openclawctl_wizard_unavailable; }
easyclaw_only_upgrade_wizard() { openclawctl_wizard_unavailable; }
deps_manage_wizard() { openclawctl_wizard_unavailable; }
panel_install_wizard() { openclawctl_wizard_unavailable; }
panel_repair_wizard() { openclawctl_wizard_unavailable; }
panel_openclaw_install_wizard() { openclawctl_wizard_unavailable; }
panel_openclaw_adopt_wizard() { openclawctl_wizard_unavailable; }
panel_deps_wizard() { openclawctl_wizard_unavailable; }
panel_info_wizard() { openclawctl_wizard_unavailable; }
panel_uninstall_wizard() { openclawctl_wizard_unavailable; }

show_main_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " OpenClaw 部署助手"
  echo "==============================="
  echo "1) 🧪 Native 实体机安装与管理（Mac/Linux）"
  echo "2) 🐳 Docker 隔离环境安装与管理（Mac/Linux）"
  echo "3) ☁️ 远程 VPS 1Panel 版 Docker 隔离环境安装与管理（Linux）"
  echo "9) 🧰 高级模式（开发者）"
  echo "0) 退出"
}

show_native_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Native 实体机安装与管理"
  echo "==============================="
  echo "1) 🚀 新安装 OpenClaw（Native npm）"
  echo "2) 🔄 升级/重装 Native 实例"
  echo "3) 🔧 修复 Native 运行环境"
  echo "4) 📄 查看 Native 部署信息"
  echo "5) 🗑️ 卸载 Native 实例"
  echo "0) 返回上级"
}

show_docker_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Docker 隔离环境安装与管理"
  echo "==============================="
  echo "1) 🚀 新安装 Docker 实例（推荐）"
  echo "2) 🔄 升级 Docker 实例"
  echo "3) 🛠️ 调整配置并重建"
  echo "4) 🔧 运行环境维护"
  echo "5) 🔄 接管已有 Docker 实例"
  echo "6) 📄 查看 Docker 部署信息"
  echo "7) 🗑️ 卸载 Docker 实例"
  echo "0) 返回上级"
}

show_docker_rebuild_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Docker 调整配置并重建"
  echo "==============================="
  echo "1) 🛠️ 修改端口/数据目录后重建"
  echo "2) 🧩 追加 Runtime 持久化"
  echo "0) 返回上级"
}

show_docker_maintenance_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Docker 运行环境维护"
  echo "==============================="
  echo "1) 🔧 容器依赖检测/补齐（npm/uv/go/rust）"
  echo "2) 📦 ClawPanel 升级/修复"
  echo "0) 返回上级"
}

show_panel_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " 1Panel VPS 专区（Linux）"
  echo "==============================="
  echo "1) 📥 安装 1Panel"
  echo "2) 🔧 升级/修复 1Panel"
  echo "3) 🚀 在 1Panel 环境安装 OpenClaw（Docker）"
  echo "4) 🔄 接管已有 1Panel/OpenClaw 实例"
  echo "5) 🧰 1Panel 环境依赖修复（Docker/网络/端口）"
  echo "6) 📄 查看 1Panel + OpenClaw 部署信息"
  echo "7) 🗑️ 卸载 1Panel 环境下 OpenClaw 实例"
  echo "0) 返回上级"
}

native_menu_loop() {
  local choice
  while true; do
    show_native_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) native_npm_wizard ;;
      2) native_upgrade_wizard ;;
      3) native_repair_wizard ;;
      4) native_info_wizard ;;
      5) native_uninstall_wizard ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

docker_menu_loop() {
  local choice
  while true; do
    show_docker_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) install_wizard ;;
      2) upgrade_wizard ;;
      3) docker_rebuild_menu_loop ;;
      4) docker_maintenance_menu_loop ;;
      5) adopt_wizard ;;
      6) info_wizard ;;
      7) uninstall_wizard ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

docker_rebuild_menu_loop() {
  local choice
  while true; do
    show_docker_rebuild_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) safe_rebuild_wizard ;;
      2) persist_append_wizard ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

docker_maintenance_menu_loop() {
  local choice
  while true; do
    show_docker_maintenance_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) deps_manage_wizard ;;
      2) easyclaw_only_upgrade_wizard ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

panel_menu_loop() {
  local platform original_test_host_platform="" original_test_host_platform_set=0 preview_mode_enabled=0
  platform="$(host_platform)"
  if [[ -n "${OPENCLAWCTL_TEST_HOST_PLATFORM+x}" ]]; then
    original_test_host_platform_set=1
    original_test_host_platform="${OPENCLAWCTL_TEST_HOST_PLATFORM}"
  fi

  if [[ "${platform}" != "linux" ]]; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      preview_mode_enabled=1
      export OPENCLAWCTL_TEST_HOST_PLATFORM="linux"
      log_info "检测到当前主机为 ${platform}，已启用 1Panel 菜单预演模式（仅 dry-run）"
    else
      log_error "1Panel 专区仅支持 Linux 主机，请先 SSH 到 Linux VPS 后运行本脚本"
      return
    fi
  fi

  local choice
  while true; do
    show_panel_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) panel_install_wizard ;;
      2) panel_repair_wizard ;;
      3) panel_openclaw_install_wizard ;;
      4) panel_openclaw_adopt_wizard ;;
      5) panel_deps_wizard ;;
      6) panel_info_wizard ;;
      7) panel_uninstall_wizard ;;
      0)
        if [[ "${preview_mode_enabled}" -eq 1 ]]; then
          if [[ "${original_test_host_platform_set}" -eq 1 ]]; then
            export OPENCLAWCTL_TEST_HOST_PLATFORM="${original_test_host_platform}"
          else
            unset OPENCLAWCTL_TEST_HOST_PLATFORM
          fi
        fi
        return
        ;;
      *) log_error "无效选择" ;;
    esac
  done
}

advanced_menu_loop() {
  local choice
  while true; do
    show_advanced_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) advanced_wizard_direct_menu_loop ;;
      2) advanced_config_exec_menu_loop ;;
      3) advanced_dry_run_menu_loop ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

show_advanced_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " 高级模式（开发者）"
  echo "==============================="
  echo "1) 🧭 Wizard 直达（install/upgrade/rebuild/...）"
  echo "2) 📄 配置文件非交互执行"
  echo "3) 🧪 Dry-run 预演"
  echo "0) 返回上级"
}

show_advanced_wizard_selector_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Advanced · Wizard 直达"
  echo "==============================="
  echo "1) install"
  echo "2) upgrade"
  echo "3) rebuild"
  echo "4) clawpanel"
  echo "5) deps"
  echo "6) uninstall"
  echo "7) adopt"
  echo "8) persist"
  echo "9) native"
  echo "10) native-upgrade"
  echo "11) native-repair"
  echo "12) native-info"
  echo "13) native-uninstall"
  echo "14) info"
  echo "15) panel-install"
  echo "16) panel-repair"
  echo "17) panel-openclaw-install"
  echo "18) panel-openclaw-adopt"
  echo "19) panel-deps"
  echo "20) panel-info"
  echo "21) panel-uninstall"
  echo "0) 返回上级"
}

advanced_wizard_key_from_choice() {
  local choice="${1:-}"
  case "${choice}" in
    1) printf 'install\n' ;;
    2) printf 'upgrade\n' ;;
    3) printf 'rebuild\n' ;;
    4) printf 'clawpanel\n' ;;
    5) printf 'deps\n' ;;
    6) printf 'uninstall\n' ;;
    7) printf 'adopt\n' ;;
    8) printf 'persist\n' ;;
    9) printf 'native\n' ;;
    10) printf 'native-upgrade\n' ;;
    11) printf 'native-repair\n' ;;
    12) printf 'native-info\n' ;;
    13) printf 'native-uninstall\n' ;;
    14) printf 'info\n' ;;
    15) printf 'panel-install\n' ;;
    16) printf 'panel-repair\n' ;;
    17) printf 'panel-openclaw-install\n' ;;
    18) printf 'panel-openclaw-adopt\n' ;;
    19) printf 'panel-deps\n' ;;
    20) printf 'panel-info\n' ;;
    21) printf 'panel-uninstall\n' ;;
    0) printf '__BACK__\n' ;;
    *) printf '\n' ;;
  esac
}

advanced_choose_wizard_key() {
  local choice wizard_key
  while true; do
    show_advanced_wizard_selector_menu >&2
    choice=$(read_choice_default "请选择向导" "0")
    wizard_key="$(advanced_wizard_key_from_choice "${choice}")"
    if [[ "${wizard_key}" == "__BACK__" ]]; then
      printf '\n'
      return 0
    fi
    if [[ -n "${wizard_key}" ]]; then
      printf '%s\n' "${wizard_key}"
      return 0
    fi
    log_error "无效选择"
  done
}

run_selected_wizard_with_context() {
  local wizard_key="$1"
  local config_path="${2:-}"
  local force_dry_run="${3:-0}"
  local prev_wizard="${SELECTED_WIZARD}"
  local prev_config="${CONFIG_FILE}"
  local prev_dry_run="${DRY_RUN}"

  SELECTED_WIZARD="${wizard_key}"
  CONFIG_FILE="${config_path}"
  if [[ "${force_dry_run}" == "1" ]]; then
    DRY_RUN=1
  fi

  run_selected_wizard

  SELECTED_WIZARD="${prev_wizard}"
  CONFIG_FILE="${prev_config}"
  DRY_RUN="${prev_dry_run}"
}

advanced_wizard_direct_menu_loop() {
  local wizard_key
  wizard_key="$(advanced_choose_wizard_key)"
  if [[ -z "${wizard_key}" ]]; then
    return
  fi
  run_selected_wizard_with_context "${wizard_key}" "" "0"
}

advanced_config_exec_menu_loop() {
  local wizard_key config_path
  wizard_key="$(advanced_choose_wizard_key)"
  if [[ -z "${wizard_key}" ]]; then
    return
  fi

  config_path=$(read_required "请输入配置文件路径")
  config_path=$(trim_surrounding_spaces "${config_path}")
  if [[ ! -f "${config_path}" ]]; then
    log_error "配置文件不存在: ${config_path}"
    press_enter_to_continue
    return
  fi

  run_selected_wizard_with_context "${wizard_key}" "${config_path}" "0"
}

show_advanced_dry_run_menu() {
  clear_interactive_screen
  echo
  echo "==============================="
  echo " Advanced · Dry-run 预演"
  echo "==============================="
  echo "1) 🧪 预演指定 Wizard（交互）"
  echo "2) 📄 预演指定 Wizard（配置文件）"
  echo "0) 返回上级"
}

advanced_dry_run_menu_loop() {
  local choice
  while true; do
    show_advanced_dry_run_menu
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1)
        local wizard_key
        wizard_key="$(advanced_choose_wizard_key)"
        if [[ -n "${wizard_key}" ]]; then
          run_selected_wizard_with_context "${wizard_key}" "" "1"
        fi
        ;;
      2)
        local wizard_key config_path
        wizard_key="$(advanced_choose_wizard_key)"
        if [[ -z "${wizard_key}" ]]; then
          continue
        fi
        config_path=$(read_required "请输入配置文件路径")
        config_path=$(trim_surrounding_spaces "${config_path}")
        if [[ ! -f "${config_path}" ]]; then
          log_error "配置文件不存在: ${config_path}"
          press_enter_to_continue
          continue
        fi
        run_selected_wizard_with_context "${wizard_key}" "${config_path}" "1"
        ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

main_loop() {
  local choice
  while true; do
    show_main_menu
    choice=$(read_choice_default "请选择功能" "0")

    case "${choice}" in
      1) native_menu_loop ;;
      2) docker_menu_loop ;;
      3) panel_menu_loop ;;
      9) advanced_menu_loop ;;
      0)
        log_info "已退出"
        return
        ;;
      *)
        log_error "无效选择"
        ;;
    esac
  done
}

parse_global_flags() {
  local positional_wizard_set=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config-file)
        if [[ $# -lt 2 ]]; then
          log_error "--config-file 需要一个文件路径"
          exit 1
        fi
        CONFIG_FILE="$2"
        shift 2
        ;;
      --wizard)
        if [[ $# -lt 2 ]]; then
          log_error "--wizard 需要一个值"
          exit 1
        fi
        SELECTED_WIZARD="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --help|-h)
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|clawpanel|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall] [--config-file path]"
        echo "或:   bash openclawctl.sh info --dry-run"
        echo "严格非交互模式: OPENCLAWCTL_STRICT_NONINTERACTIVE=1（要求同时传入 --wizard 与 --config-file）"
        echo "默认进入交互式菜单。"
        exit 0
        ;;
      *)
        if [[ "${positional_wizard_set}" -eq 0 && -z "${SELECTED_WIZARD}" ]]; then
          case "$1" in
            install|upgrade|rebuild|clawpanel|easyclaw|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall)
              SELECTED_WIZARD="$1"
              positional_wizard_set=1
              shift
              continue
              ;;
          esac
        fi
        log_error "未知参数: $1"
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|clawpanel|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall] [--config-file path]"
        exit 1
        ;;
    esac
  done
}

run_selected_wizard() {
  case "${SELECTED_WIZARD}" in
    install) install_wizard ;;
    upgrade) upgrade_wizard ;;
    rebuild) safe_rebuild_wizard ;;
    clawpanel|easyclaw) easyclaw_only_upgrade_wizard ;;
    deps) deps_manage_wizard ;;
    uninstall) uninstall_wizard ;;
    adopt) adopt_wizard ;;
    persist) persist_append_wizard ;;
    native) native_npm_wizard ;;
    native-upgrade) native_upgrade_wizard ;;
    native-repair) native_repair_wizard ;;
    native-info) native_info_wizard ;;
    native-uninstall) native_uninstall_wizard ;;
    info) info_wizard ;;
    panel-install) panel_install_wizard ;;
    panel-repair) panel_repair_wizard ;;
    panel-openclaw-install) panel_openclaw_install_wizard ;;
    panel-openclaw-adopt) panel_openclaw_adopt_wizard ;;
    panel-deps) panel_deps_wizard ;;
    panel-info) panel_info_wizard ;;
    panel-uninstall) panel_uninstall_wizard ;;
    *)
      log_error "无效的 wizard: ${SELECTED_WIZARD}"
      exit 1
      ;;
  esac
}
