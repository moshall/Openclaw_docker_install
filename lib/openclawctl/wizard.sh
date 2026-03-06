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
  echo "9) 🧰 高级模式（兼容旧菜单）"
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
  echo "1) 🚀 安装新实例"
  echo "2) 🔄 升级已有实例"
  echo "3) 🛠️ 调整或重建实例"
  echo "4) 📦 管理 EasyClaw 工具"
  echo "5) 🔧 检查或补齐运行环境"
  echo "6) 🗑️ 卸载实例"
  echo "7) 🔄 接管外部安装实例"
  echo "8) 🧩 追加 Runtime 持久化"
  echo "9) 📄 查看部署信息"
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
      3) safe_rebuild_wizard ;;
      4) easyclaw_only_upgrade_wizard ;;
      5) deps_manage_wizard ;;
      6) uninstall_wizard ;;
      7) adopt_wizard ;;
      8) persist_append_wizard ;;
      9) info_wizard ;;
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

panel_menu_loop() {
  if [[ "$(host_platform)" != "linux" ]]; then
    log_error "1Panel 专区仅支持 Linux 主机"
    return
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
      0) return ;;
      *) log_error "无效选择" ;;
    esac
  done
}

advanced_menu_loop() {
  local choice
  while true; do
    clear_interactive_screen
    echo
    echo "==============================="
    echo " 高级模式（兼容旧菜单）"
    echo "==============================="
    echo "1) 🚀 安装新实例"
    echo "2) 🔄 升级已有实例"
    echo "3) 🛠️ 调整或重建实例"
    echo "4) 📦 管理 EasyClaw 工具"
    echo "5) 🔧 检查或补齐运行环境"
    echo "6) 🗑️ 卸载实例"
    echo "7) 🔄 接管外部安装实例"
    echo "8) 🧩 追加 Runtime 持久化"
    echo "9) 🧪 原生 npm 安装"
    echo "10) 📄 查看部署信息"
    echo "0) 返回上级"
    choice=$(read_choice_default "请选择功能" "0")
    case "${choice}" in
      1) install_wizard ;;
      2) upgrade_wizard ;;
      3) safe_rebuild_wizard ;;
      4) easyclaw_only_upgrade_wizard ;;
      5) deps_manage_wizard ;;
      6) uninstall_wizard ;;
      7) adopt_wizard ;;
      8) persist_append_wizard ;;
      9) native_npm_wizard ;;
      10) info_wizard ;;
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
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall] [--config-file path]"
        echo "或:   bash openclawctl.sh info --dry-run"
        echo "严格非交互模式: OPENCLAWCTL_STRICT_NONINTERACTIVE=1（要求同时传入 --wizard 与 --config-file）"
        echo "默认进入交互式菜单。"
        exit 0
        ;;
      *)
        if [[ "${positional_wizard_set}" -eq 0 && -z "${SELECTED_WIZARD}" ]]; then
          case "$1" in
            install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall)
              SELECTED_WIZARD="$1"
              positional_wizard_set=1
              shift
              continue
              ;;
          esac
        fi
        log_error "未知参数: $1"
        echo "用法: bash openclawctl.sh [--dry-run] [--wizard install|upgrade|rebuild|easyclaw|deps|uninstall|adopt|persist|native|native-upgrade|native-repair|native-info|native-uninstall|info|panel-install|panel-repair|panel-openclaw-install|panel-openclaw-adopt|panel-deps|panel-info|panel-uninstall] [--config-file path]"
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
    easyclaw) easyclaw_only_upgrade_wizard ;;
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
