#!/usr/bin/env bash

openclawctl_ops_unavailable() {
  log_error "ops 模块函数应由入口脚本完整加载后使用"
  return 1
}

execute_install_plan() { openclawctl_ops_unavailable; }
execute_upgrade_plan() { openclawctl_ops_unavailable; }
execute_rebuild_plan() { openclawctl_ops_unavailable; }
execute_easyclaw_upgrade_plan() { openclawctl_ops_unavailable; }
execute_native_install_plan() { openclawctl_ops_unavailable; }
