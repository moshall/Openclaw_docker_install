#!/usr/bin/env bash

execute_install_plan() {
  local image="$1"
  local name="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local gateway_bind="$6"
  local token="$7"
  local bin_persist_choice="$8"
  local env_persist_choice="$9"
  local apt_cfg_persist_choice="${10}"
  local cache_persist_choice="${11}"
  local easy_choice="${12}"
  local deps_install_choice="${13}"
  local target_deps="${14}"
  local extra_ports="${15:-}"
  local software_set="${16:-}"
  local skill_set="${17:-}"
  local requested_image="${image}"

  software_set=$(normalize_software_set "${software_set}")
  skill_set=$(normalize_skill_set "${skill_set}")
  if [[ -n "${software_set}" && "${deps_install_choice}" != "1" ]]; then
    log_info "检测到已选择可选软件，已自动开启依赖补齐流程"
    deps_install_choice="1"
  fi
  target_deps=$(ensure_dep_set_for_software "${target_deps}" "${software_set}")
  if token_in_list "clawpanel" ${software_set} || token_in_list "easyclaw" ${software_set}; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if token_in_list "claudecodeui" ${software_set}; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "install" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "install" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi
  local locked_image
  locked_image=$(resolve_locked_image_ref "${image}")
  remove_container_if_exists "${name}"
  bootstrap_openclaw_config "${image}" "${data_dir}" "${container_port}" "${gateway_bind}" "${token}"
  local -a install_nonfatal_issues=()
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    install_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${gateway_bind}"; then
    install_nonfatal_issues+=("Control UI 兼容配置失败")
  fi
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止安装以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_software_profile "${data_dir}" "${software_set}"
  save_skill_profile "${data_dir}" "${skill_set}"
  save_config_manifest "${data_dir}" "docker-install" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${software_set}" "${skill_set}"
  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    install_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      install_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      install_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
  fi
  if [[ "${easy_choice}" == "1" ]]; then
    if ! run_optional_step "ClawPanel 安装/升级" install_easyclaw "${name}" "${data_dir}"; then
      install_nonfatal_issues+=("ClawPanel 安装/升级失败")
    fi
  fi
  if [[ "${deps_install_choice}" == "1" ]]; then
    if run_optional_step "依赖补齐" manage_container_runtime_deps "${name}" "install" "${target_deps}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${target_deps}" || true
    else
      install_nonfatal_issues+=("容器依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "可选软件安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      install_nonfatal_issues+=("可选软件安装失败")
    fi
  fi
  if [[ -n "${skill_set}" ]]; then
    if ! run_optional_step "Skill 安装" install_selected_skills "${data_dir}" "${skill_set}"; then
      install_nonfatal_issues+=("Skill 安装失败")
    fi
  fi

  printf 'TOKEN=%s\n' "${token}"
  printf 'URL=http://<server-ip>:%s/?token=%s\n' "${host_port}" "${token}"
  local install_version install_status_text install_runtime_paths install_deps_installed
  install_version=$(detect_openclaw_version "${name}")
  install_status_text=$(get_container_status_text "${name}")
  install_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  install_deps_installed=$(detect_installed_deps_summary "${name}" "${target_deps}")

  local install_status="success"
  if [[ "${#install_nonfatal_issues[@]}" -gt 0 ]]; then
    install_status="success_with_warnings"
    log_error "以下可选步骤失败（主应用已可用）:"
    local issue
    for issue in "${install_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi
  save_image_lock_profile "${data_dir}" "${requested_image}" "${image}" "${locked_image}"
  write_last_report "install" "${install_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${token}" "http://<server-ip>:${host_port}/?token=${token}" "${install_nonfatal_issues[@]}"
  print_human_summary "install" "${name}" "${install_version}" "${install_status_text}" "${data_dir}" "${install_runtime_paths}" "${install_deps_installed}" "${gateway_bind}" "${token}" "${host_port}" "${extra_ports}"
  write_deployment_info "install" "${install_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${token}" "${extra_ports}" || true
}

execute_upgrade_plan() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local bin_persist_choice="$6"
  local env_persist_choice="$7"
  local apt_cfg_persist_choice="$8"
  local cache_persist_choice="$9"
  local easyclaw_upgrade="${10}"
  local deps_repair_choice="${11}"
  local upgrade_dep_set="${12}"
  local extra_ports="${13:-}"
  local software_set
  local skill_set
  local requested_image="${image}"

  software_set=$(load_software_profile "${data_dir}")
  software_set=$(normalize_software_set "${software_set}")
  skill_set=$(load_skill_profile "${data_dir}")
  skill_set=$(normalize_skill_set "${skill_set}")
  if [[ -n "${software_set}" ]]; then
    log_info "检测到已保存的软件档案，升级后将自动保活: $(software_set_summary "${software_set}")"
    upgrade_dep_set=$(ensure_dep_set_for_software "${upgrade_dep_set}" "${software_set}")
    if [[ "${deps_repair_choice}" != "1" ]]; then
      log_info "已自动开启升级后依赖补齐流程"
      deps_repair_choice="1"
    fi
  fi

  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
    return 1
  fi
  if should_enable_easyclaw_web_port "${easyclaw_upgrade}" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi
  if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "upgrade" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "upgrade" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi
  local locked_image
  locked_image=$(resolve_locked_image_ref "${image}")

  local -a upgrade_nonfatal_issues=()
  local current_image
  current_image=$(detect_existing_image "${name}" "" "${data_dir}")
  if ! run_optional_step "版本源切换兼容修正" prepare_source_switch_transition "${data_dir}" "${current_image}" "${image}"; then
    upgrade_nonfatal_issues+=("版本源切换兼容修正失败")
  fi
  local current_gateway_bind
  current_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")

  if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${image}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
    log_error "升级前 runtime 数据迁移失败；为避免数据丢失，已中止本次升级"
    return 1
  fi

  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包清单快照" snapshot_apt_manual_packages "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("APT 手工包清单快照失败")
    fi
  fi

  remove_container_if_exists "${name}"
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止升级以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    upgrade_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${current_gateway_bind}"; then
    upgrade_nonfatal_issues+=("Control UI 兼容配置失败")
  fi
  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_software_manifest "${data_dir}" "${software_set}"
  save_config_manifest "${data_dir}" "docker-upgrade" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${software_set}" "${skill_set}"
  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    upgrade_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      upgrade_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      upgrade_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包回放安装" restore_apt_manual_packages "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("APT 手工包回放安装失败")
    fi
  fi

  run_cmd docker ps --filter "name=${name}"
  run_cmd docker logs --tail 30 "${name}"
  run_cmd docker exec "${name}" openclaw --version

  if [[ "${easyclaw_upgrade}" == "1" ]]; then
    if ! run_optional_step "ClawPanel 检查升级" check_and_upgrade_easyclaw "${name}" "${data_dir}"; then
      upgrade_nonfatal_issues+=("ClawPanel 检查升级失败")
    fi
  fi
  if [[ "${deps_repair_choice}" == "1" ]]; then
    if run_optional_step "升级后依赖补齐" manage_container_runtime_deps "${name}" "install" "${upgrade_dep_set}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${upgrade_dep_set}" || true
    else
      upgrade_nonfatal_issues+=("升级后依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "升级后可选软件保活安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      upgrade_nonfatal_issues+=("升级后可选软件保活安装失败")
    fi
  fi

  if [[ "${#upgrade_nonfatal_issues[@]}" -gt 0 ]]; then
    log_error "以下可选步骤失败（升级主流程已完成）:"
    local issue
    for issue in "${upgrade_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi
  local upgrade_status="success"
  [[ "${#upgrade_nonfatal_issues[@]}" -gt 0 ]] && upgrade_status="success_with_warnings"
  save_image_lock_profile "${data_dir}" "${requested_image}" "${image}" "${locked_image}"
  write_last_report "upgrade" "${upgrade_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "" "${upgrade_nonfatal_issues[@]}"

  local upgrade_version upgrade_status_text upgrade_runtime_paths upgrade_deps_installed upgrade_gateway_bind upgrade_token
  upgrade_version=$(detect_openclaw_version "${name}")
  upgrade_status_text=$(get_container_status_text "${name}")
  upgrade_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  upgrade_deps_installed=$(detect_installed_deps_summary "${name}" "${upgrade_dep_set}")
  upgrade_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  upgrade_token=$(detect_token_from_config "${data_dir}")
  print_human_summary "upgrade" "${name}" "${upgrade_version}" "${upgrade_status_text}" "${data_dir}" "${upgrade_runtime_paths}" "${upgrade_deps_installed}" "${upgrade_gateway_bind}" "${upgrade_token}" "${host_port}" "${extra_ports}"
  write_deployment_info "upgrade" "${upgrade_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${upgrade_token}" "${extra_ports}" || true
}

execute_rebuild_plan() {
  local name="$1"
  local image="$2"
  local data_dir="$3"
  local host_port="$4"
  local container_port="$5"
  local bin_persist_choice="$6"
  local env_persist_choice="$7"
  local apt_cfg_persist_choice="$8"
  local cache_persist_choice="$9"
  local deps_repair_choice="${10}"
  local rebuild_dep_set="${11}"
  local extra_ports="${12:-}"
  local software_set
  local skill_set
  local requested_image="${image}"

  software_set=$(load_software_profile "${data_dir}")
  software_set=$(normalize_software_set "${software_set}")
  skill_set=$(load_skill_profile "${data_dir}")
  skill_set=$(normalize_skill_set "${skill_set}")
  if [[ -n "${software_set}" ]]; then
    log_info "检测到已保存的软件档案，重建后将自动保活: $(software_set_summary "${software_set}")"
    rebuild_dep_set=$(ensure_dep_set_for_software "${rebuild_dep_set}" "${software_set}")
    if [[ "${deps_repair_choice}" != "1" ]]; then
      log_info "已自动开启重建后依赖补齐流程"
      deps_repair_choice="1"
    fi
  fi

  if ! extra_ports=$(normalize_extra_ports "${extra_ports}" "${host_port}" "${container_port}"); then
    return 1
  fi
  extra_ports=$(ensure_easyclaw_web_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  if should_enable_claudecodeui_reserved_port "0" "${name}" "${data_dir}"; then
    extra_ports=$(ensure_claudecodeui_reserved_port_mapping "1" "${host_port}" "${container_port}" "${extra_ports}")
  fi

  if ! run_preflight_checks "rebuild" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}"; then
    log_error "preflight 未通过，请修复后重试"
    return 1
  fi

  run_cmd mkdir -p "${data_dir}"
  if ! image=$(resolve_official_tag_with_fallback "rebuild" "${image}"); then
    return 1
  fi
  if ! docker_pull_image_checked "${image}"; then
    return 1
  fi
  local locked_image
  locked_image=$(resolve_locked_image_ref "${image}")

  local -a rebuild_nonfatal_issues=()
  local current_image
  current_image=$(detect_existing_image "${name}" "" "${data_dir}")
  if ! run_optional_step "版本源切换兼容修正" prepare_source_switch_transition "${data_dir}" "${current_image}" "${image}"; then
    rebuild_nonfatal_issues+=("版本源切换兼容修正失败")
  fi
  local current_gateway_bind
  current_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  if ! pre_upgrade_migrate_runtime_data "${name}" "${data_dir}" "${image}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"; then
    log_error "重建前 runtime 数据迁移失败；为避免数据丢失，已中止本次重建"
    return 1
  fi

  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 手工包清单快照" snapshot_apt_manual_packages "${name}" "${data_dir}"; then
      rebuild_nonfatal_issues+=("APT 手工包清单快照失败")
    fi
  fi

  remove_container_if_exists "${name}"
  if [[ "${apt_cfg_persist_choice}" == "1" ]]; then
    if ! run_optional_step "APT 源目录初始化" ensure_apt_config_seeded_from_image "${image}" "${data_dir}"; then
      log_error "APT 源目录初始化失败，已中止重建以避免空源配置"
      return 1
    fi
    run_optional_step "APT 源文件格式校验" validate_apt_sources_persist_files "${data_dir}" || true
  fi
  if ! run_optional_step "配置兼容修复(doctor --fix)" run_openclaw_doctor_fix "${image}" "${data_dir}"; then
    rebuild_nonfatal_issues+=("配置兼容修复失败")
  fi
  if ! run_optional_step "Control UI 兼容配置" ensure_gateway_controlui_compat "${image}" "${data_dir}" "${current_gateway_bind}"; then
    rebuild_nonfatal_issues+=("Control UI 兼容配置失败")
  fi

  run_gateway_container "${name}" "${image}" "${host_port}" "${container_port}" "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${extra_ports}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_persistence_profile "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}"
  save_software_manifest "${data_dir}" "${software_set}"
  save_config_manifest "${data_dir}" "docker-rebuild" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${software_set}" "${skill_set}"

  if ! run_optional_step "运行时 PATH/命令入口修正" repair_runtime_command_paths "${name}"; then
    rebuild_nonfatal_issues+=("运行时 PATH/命令入口修正失败")
  fi
  if [[ "${env_persist_choice}" == "1" ]]; then
    if ! run_optional_step "授权目录权限修正" repair_persisted_auth_permissions "${name}"; then
      rebuild_nonfatal_issues+=("授权目录权限修正失败")
    fi
    if ! run_optional_step "NPM 全局前缀持久化配置" configure_npm_runtime_prefix "${name}" "${image}"; then
      rebuild_nonfatal_issues+=("NPM 全局前缀持久化配置失败")
    fi
    if ! run_optional_step "APT 手工包回放安装" restore_apt_manual_packages "${name}" "${data_dir}"; then
      rebuild_nonfatal_issues+=("APT 手工包回放安装失败")
    fi
  fi

  if [[ "${deps_repair_choice}" == "1" ]]; then
    if run_optional_step "重建后依赖补齐" manage_container_runtime_deps "${name}" "install" "${rebuild_dep_set}"; then
      run_optional_step "依赖档案保存" save_dep_profile "${data_dir}" "${rebuild_dep_set}" || true
    else
      rebuild_nonfatal_issues+=("重建后依赖补齐失败")
    fi
  fi
  if [[ -n "${software_set}" ]]; then
    if ! run_optional_step "重建后可选软件保活安装" install_selected_software "${name}" "${data_dir}" "${software_set}" "${host_port}" "${container_port}" "${extra_ports}"; then
      rebuild_nonfatal_issues+=("重建后可选软件保活安装失败")
    fi
  fi

  run_cmd docker ps --filter "name=${name}"
  run_cmd docker logs --tail 30 "${name}"
  run_cmd docker exec "${name}" openclaw --version

  if [[ "${#rebuild_nonfatal_issues[@]}" -gt 0 ]]; then
    log_error "以下可选步骤失败（重建主流程已完成）:"
    local issue
    for issue in "${rebuild_nonfatal_issues[@]}"; do
      log_error " - ${issue}"
    done
    log_info "可稍后通过菜单 5) 🔧 检查或补齐运行环境 重新执行补齐"
  fi

  local rebuild_status="success"
  [[ "${#rebuild_nonfatal_issues[@]}" -gt 0 ]] && rebuild_status="success_with_warnings"
  save_image_lock_profile "${data_dir}" "${requested_image}" "${image}" "${locked_image}"
  write_last_report "rebuild" "${rebuild_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "" "" "${rebuild_nonfatal_issues[@]}"

  local rebuild_version rebuild_status_text rebuild_runtime_paths rebuild_deps_installed rebuild_gateway_bind rebuild_token
  rebuild_version=$(detect_openclaw_version "${name}")
  rebuild_status_text=$(get_container_status_text "${name}")
  rebuild_runtime_paths=$(runtime_persist_paths_desc "${data_dir}" "${bin_persist_choice}" "${env_persist_choice}" "${apt_cfg_persist_choice}" "${cache_persist_choice}" "${image}")
  rebuild_deps_installed=$(detect_installed_deps_summary "${name}" "${rebuild_dep_set}")
  rebuild_gateway_bind=$(detect_gateway_bind "${name}" "${data_dir}" "lan")
  rebuild_token=$(detect_token_from_config "${data_dir}")
  print_human_summary "rebuild" "${name}" "${rebuild_version}" "${rebuild_status_text}" "${data_dir}" "${rebuild_runtime_paths}" "${rebuild_deps_installed}" "${rebuild_gateway_bind}" "${rebuild_token}" "${host_port}" "${extra_ports}"
  write_deployment_info "rebuild" "${rebuild_status}" "${name}" "${data_dir}" "${image}" "${host_port}" "${container_port}" "${rebuild_token}" "${extra_ports}" || true
}
