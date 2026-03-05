#!/usr/bin/env bash

read_with_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  printf '%s [%s] (回车使用默认值): ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
}

read_required() {
  local prompt="$1"
  local value
  while true; do
    printf '%s: ' "${prompt}" >&2
    IFS= read -r value
    value=$(sanitize_user_input "${value}")
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return
    fi
    log_error "该项不能为空"
  done
}

read_container_name() {
  local prompt="$1"
  local value
  while true; do
    value=$(read_required "${prompt}")
    if [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
      printf '%s\n' "${value}"
      return
    fi
    log_error "容器名仅允许字母、数字、点、下划线、短横线，且必须以字母或数字开头"
  done
}

read_choice_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  printf '%s [%s]: ' "${prompt}" "${default_value}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
  if [[ -z "${value}" ]]; then
    printf '%s\n' "${default_value}"
  else
    printf '%s\n' "${value}"
  fi
}

read_menu_choice() {
  local prompt="$1"
  local value
  printf '%s: ' "${prompt}" >&2
  IFS= read -r value
  value=$(sanitize_user_input "${value}")
  printf '%s\n' "${value}"
}

clear_interactive_screen() {
  if [[ "${OPENCLAWCTL_NO_CLEAR:-0}" == "1" ]]; then
    return
  fi
  if [[ "${OPENCLAWCTL_ASSUME_TTY:-0}" == "1" || -t 1 ]]; then
    printf '\033[H\033[2J'
  fi
}

press_enter_to_continue() {
  printf '按回车返回: ' >&2
  local dummy
  IFS= read -r dummy
}

sanitize_user_input() {
  local raw="${1:-}"
  printf '%s' "${raw}" | awk '{gsub(/[[:cntrl:]]/, ""); printf "%s", $0}'
}

trim_surrounding_spaces() {
  local raw="${1:-}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  printf '%s\n' "${raw}"
}

sanitize_port_mapping_input() {
  local raw="${1:-}"
  raw=$(sanitize_user_input "${raw}")
  raw=$(printf '%s' "${raw}" | sed -E 's/\[[0-9;]*[A-Za-z]//g')
  printf '%s\n' "${raw}"
}
