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
adopt_wizard() { openclawctl_wizard_unavailable; }
persist_append_wizard() { openclawctl_wizard_unavailable; }
install_wizard() { openclawctl_wizard_unavailable; }
upgrade_wizard() { openclawctl_wizard_unavailable; }
safe_rebuild_wizard() { openclawctl_wizard_unavailable; }
uninstall_wizard() { openclawctl_wizard_unavailable; }
easyclaw_only_upgrade_wizard() { openclawctl_wizard_unavailable; }
deps_manage_wizard() { openclawctl_wizard_unavailable; }
show_main_menu() { openclawctl_wizard_unavailable; }
main_loop() { openclawctl_wizard_unavailable; }
parse_global_flags() { openclawctl_wizard_unavailable; }
run_selected_wizard() { openclawctl_wizard_unavailable; }
