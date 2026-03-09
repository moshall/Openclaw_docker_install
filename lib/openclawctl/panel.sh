#!/usr/bin/env bash

panel_install_info_path() {
  printf '%s\n' "${HOME}/.openclaw-installer/1panel-install-info.txt"
}

strip_ansi_escape_sequences() {
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g'
}

extract_first_url_from_text() {
  local text="$1"
  printf '%s\n' "${text}" | strip_ansi_escape_sequences | \
    grep -Eo 'https?://[^[:space:]"<>]+' | \
    sed -E 's/[),.;]+$//' | \
    head -n1
}

extract_labeled_value_from_text() {
  local text="$1"
  local key_regex="$2"
  local line lowered value

  while IFS= read -r line; do
    line=$(printf '%s\n' "${line}" | strip_ansi_escape_sequences)
    line=$(trim_surrounding_spaces "${line}")
    [[ -z "${line}" ]] && continue

    lowered=$(printf '%s\n' "${line}" | tr '[:upper:]' '[:lower:]')
    if ! printf '%s\n' "${lowered}" | grep -Eq "${key_regex}"; then
      continue
    fi

    value=$(printf '%s\n' "${line}" | sed -E 's/^[^:：]+[:：][[:space:]]*//')
    value=$(trim_surrounding_spaces "${value}")
    if [[ -n "${value}" && "${value}" != "${line}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi

    value=$(printf '%s\n' "${line}" | sed -E 's/^[^[:space:]]+[[:space:]]+//')
    value=$(trim_surrounding_spaces "${value}")
    if [[ -n "${value}" && "${value}" != "${line}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
  done < <(printf '%s\n' "${text}")

  return 1
}

extract_1panel_install_summary_fields() {
  local output_text="$1"
  local panel_url panel_user panel_password

  panel_url=$(extract_labeled_value_from_text "${output_text}" '(panel|面板|访问|地址|url).*https?://' || true)
  if [[ -z "${panel_url}" ]]; then
    panel_url=$(extract_first_url_from_text "${output_text}" || true)
  fi

  panel_user=$(extract_labeled_value_from_text "${output_text}" '(username|user name|用户名|账号|账户)' || true)
  panel_password=$(extract_labeled_value_from_text "${output_text}" '(password|passwd|pass word|密码|初始密码|登录密码)' || true)

  panel_url=$(trim_surrounding_spaces "${panel_url}")
  panel_user=$(trim_surrounding_spaces "${panel_user}")
  panel_password=$(trim_surrounding_spaces "${panel_password}")

  printf '%s|%s|%s\n' "${panel_url}" "${panel_user}" "${panel_password}"
}

render_1panel_install_summary_text() {
  local panel_url="$1"
  local panel_user="$2"
  local panel_password="$3"
  local archive_path="$4"

  cat <<EOF_SUMMARY
===============================
 1Panel 安装汇总
===============================
访问地址：${panel_url:-<未解析到，请查看原始安装日志>}
用户名：${panel_user:-<未解析到，请查看原始安装日志>}
密码：${panel_password:-<未解析到，请查看原始安装日志>}
存档文件：${archive_path}
===============================
EOF_SUMMARY
}

write_1panel_install_archive() {
  local panel_url="$1"
  local panel_user="$2"
  local panel_password="$3"
  local raw_output="$4"
  local archive_path
  archive_path=$(panel_install_info_path)

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "1PANEL_INSTALL_INFO_PATH=${archive_path}"
    return 0
  fi

  run_cmd mkdir -p "$(dirname "${archive_path}")"
  cat > "${archive_path}" <<EOF_INFO
1Panel 安装信息
生成时间：$(date '+%Y-%m-%d %H:%M:%S %Z')
═══════════════════════════════════════════════════════════
访问地址：${panel_url:-<未解析到，请查看原始安装日志>}
用户名：${panel_user:-<未解析到，请查看原始安装日志>}
密码：${panel_password:-<未解析到，请查看原始安装日志>}

原始安装输出：
${raw_output}
═══════════════════════════════════════════════════════════
EOF_INFO

  echo "1PANEL_INSTALL_INFO_PATH=${archive_path}"
}
