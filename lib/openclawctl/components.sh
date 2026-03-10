#!/usr/bin/env bash

token_in_list() {
  local token="$1"
  shift
  local item
  for item in "$@"; do
    [[ "${item}" == "${token}" ]] && return 0
  done
  return 1
}

normalize_optional_list() {
  local raw="$1"
  shift
  local allowed=("$@")

  raw="${raw//,/ }"
  raw=$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')

  local out=""
  local token
  for token in ${raw}; do
    case "${token}" in
      easyclaw) token="clawpanel" ;;
    esac
    if ! token_in_list "${token}" "${allowed[@]}"; then
      continue
    fi
    case " ${out} " in
      *" ${token} "*) ;;
      *) out="${out}${out:+ }${token}" ;;
    esac
  done
  echo "${out}"
}

append_catalog_line() {
  local current="$1"
  local line="$2"
  if [[ -z "${current}" ]]; then
    printf '%s\n' "${line}"
  else
    printf '%s\n%s\n' "${current}" "${line}"
  fi
}

catalog_records_for_mode() {
  local mode="$1"
  if [[ "${mode}" == "software" ]]; then
    printf '%s\n' "${OPTIONAL_SOFTWARE_CATALOG}"
  else
    printf '%s\n' "${OPTIONAL_SKILL_CATALOG}"
  fi
}

catalog_record_for_id() {
  local mode="$1"
  local wanted_id="$2"
  local line id label kind arg1 arg2 deps
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    IFS='|' read -r id label kind arg1 arg2 deps <<< "${line}"
    if [[ "${id}" == "${wanted_id}" ]]; then
      printf '%s\n' "${line}"
      return 0
    fi
  done < <(catalog_records_for_mode "${mode}")
  return 1
}

catalog_field_for_id() {
  local mode="$1"
  local id="$2"
  local field="$3"
  local line
  line=$(catalog_record_for_id "${mode}" "${id}" || true)
  [[ -n "${line}" ]] || {
    printf '%s\n' ""
    return 0
  }

  local rid label kind arg1 arg2 deps
  IFS='|' read -r rid label kind arg1 arg2 deps <<< "${line}"
  case "${field}" in
    id) printf '%s\n' "${rid}" ;;
    label) printf '%s\n' "${label}" ;;
    kind) printf '%s\n' "${kind}" ;;
    arg1) printf '%s\n' "${arg1}" ;;
    arg2) printf '%s\n' "${arg2}" ;;
    deps) printf '%s\n' "${deps}" ;;
    *) printf '%s\n' "" ;;
  esac
}

catalog_ids_for_mode() {
  local mode="$1"
  local out=""
  local line id label kind arg1 arg2 deps
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    IFS='|' read -r id label kind arg1 arg2 deps <<< "${line}"
    [[ -z "${id}" ]] && continue
    out="${out}${out:+ }${id}"
  done < <(catalog_records_for_mode "${mode}")
  printf '%s\n' "${out}"
}

load_optional_component_catalog() {
  OPTIONAL_SOFTWARE_CATALOG=""
  OPTIONAL_SKILL_CATALOG=""
  OPTIONAL_SOFTWARE_ALL="${DEFAULT_OPTIONAL_SOFTWARE_ALL}"
  OPTIONAL_SKILL_ALL="${DEFAULT_OPTIONAL_SKILL_ALL}"

  if [[ ! -f "${OPTIONAL_COMPONENTS_FILE}" ]]; then
    log_info "可选组件目录文件不存在，使用内置默认列表: ${OPTIONAL_COMPONENTS_FILE}"
    return 0
  fi

  local line
  while IFS= read -r line; do
    line=$(sanitize_user_input "${line}")
    line=$(trim_surrounding_spaces "${line}")
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^# ]] && continue

    local mode id label kind arg1 arg2 deps
    IFS='|' read -r mode id label kind arg1 arg2 deps <<< "${line}"
    mode=$(trim_surrounding_spaces "${mode}")
    id=$(trim_surrounding_spaces "${id}")
    label=$(trim_surrounding_spaces "${label}")
    kind=$(trim_surrounding_spaces "${kind}")
    arg1=$(trim_surrounding_spaces "${arg1}")
    arg2=$(trim_surrounding_spaces "${arg2}")
    deps=$(trim_surrounding_spaces "${deps}")

    [[ -n "${mode}" && -n "${id}" && -n "${label}" && -n "${kind}" ]] || continue
    local normalized_line="${id}|${label}|${kind}|${arg1}|${arg2}|${deps}"

    case "${mode}" in
      software)
        OPTIONAL_SOFTWARE_CATALOG=$(append_catalog_line "${OPTIONAL_SOFTWARE_CATALOG}" "${normalized_line}")
        ;;
      skill)
        OPTIONAL_SKILL_CATALOG=$(append_catalog_line "${OPTIONAL_SKILL_CATALOG}" "${normalized_line}")
        ;;
    esac
  done < "${OPTIONAL_COMPONENTS_FILE}"

  local loaded_software loaded_skill
  loaded_software=$(catalog_ids_for_mode "software")
  loaded_skill=$(catalog_ids_for_mode "skill")
  [[ -n "${loaded_software}" ]] && OPTIONAL_SOFTWARE_ALL="${loaded_software}"
  [[ -n "${loaded_skill}" ]] && OPTIONAL_SKILL_ALL="${loaded_skill}"
}

normalize_software_set() {
  normalize_optional_list "$*" ${OPTIONAL_SOFTWARE_ALL}
}

normalize_skill_set() {
  normalize_optional_list "$*" ${OPTIONAL_SKILL_ALL}
}

optional_software_label() {
  local token="$1"
  local label
  label=$(catalog_field_for_id "software" "${token}" "label")
  if [[ -n "${label}" ]]; then
    echo "${label}"
  else
    echo "${token}"
  fi
}

optional_skill_label() {
  local token="$1"
  local label
  label=$(catalog_field_for_id "skill" "${token}" "label")
  if [[ -n "${label}" ]]; then
    echo "${label}"
  else
    echo "${token}"
  fi
}

optional_list_summary() {
  local mode="$1"
  shift
  local raw="$*"
  raw=$(echo "${raw}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  [[ -n "${raw}" ]] || {
    echo "无"
    return
  }

  local out=""
  local token label
  for token in ${raw}; do
    if [[ "${mode}" == "software" ]]; then
      label=$(optional_software_label "${token}")
    else
      label=$(optional_skill_label "${token}")
    fi
    out="${out}${out:+、}${label}"
  done
  echo "${out}"
}

software_set_summary() {
  optional_list_summary "software" "$(normalize_software_set "$*")"
}

skill_set_summary() {
  optional_list_summary "skill" "$(normalize_skill_set "$*")"
}

prompt_optional_component_selection() {
  local mode="$1"
  local current_raw="${2:-}"
  local current selected token label default_choice choice
  selected=""

  if [[ "${mode}" == "software" ]]; then
    current=$(normalize_software_set "${current_raw}")
    echo "请选择可选软件（1=安装, 2=跳过）:" >&2
    for token in ${OPTIONAL_SOFTWARE_ALL}; do
      label=$(optional_software_label "${token}")
      default_choice="2"
      token_in_list "${token}" ${current} && default_choice="1"
      echo "${label}:" >&2
      echo "  1) 安装" >&2
      echo "  2) 跳过" >&2
      choice=$(read_choice_default "请选择" "${default_choice}")
      [[ "${choice}" == "1" ]] && selected="${selected} ${token}"
    done
    normalize_software_set "${selected}"
    return
  fi

  current=$(normalize_skill_set "${current_raw}")
  echo "请选择预装 Skills（1=安装, 2=跳过）:" >&2
  for token in ${OPTIONAL_SKILL_ALL}; do
    label=$(optional_skill_label "${token}")
    default_choice="2"
    token_in_list "${token}" ${current} && default_choice="1"
    echo "${label}:" >&2
    echo "  1) 安装" >&2
    echo "  2) 跳过" >&2
    choice=$(read_choice_default "请选择" "${default_choice}")
    [[ "${choice}" == "1" ]] && selected="${selected} ${token}"
  done
  normalize_skill_set "${selected}"
}

prompt_software_set_selection() {
  prompt_optional_component_selection "software" "${1:-}"
}

prompt_skill_set_selection() {
  prompt_optional_component_selection "skill" "${1:-}"
}

ensure_dep_set_for_software() {
  local dep_set="$1"
  local software_set
  software_set=$(normalize_software_set "${2:-}")
  local result
  result=$(normalize_dep_list "${dep_set}")

  local additional_deps=""
  local token
  for token in ${software_set}; do
    local dep_tokens
    dep_tokens=$(catalog_field_for_id "software" "${token}" "deps")
    dep_tokens="${dep_tokens//,/ }"
    dep_tokens=$(echo "${dep_tokens}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
    [[ -z "${dep_tokens}" || "${dep_tokens}" == "none" ]] && continue
    additional_deps="${additional_deps}${additional_deps:+ }${dep_tokens}"
  done

  additional_deps=$(echo "${additional_deps}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  if [[ -n "${additional_deps}" ]]; then
    local dep_token
    for dep_token in ${additional_deps}; do
      if ! dep_enabled "${result}" "${dep_token}"; then
        result=$(normalize_dep_list "${result} ${dep_token}")
        printf '[INFO] 已自动补充依赖: %s（因所选可选软件需要）\n' "${dep_token}" >&2
      fi
    done
  fi

  echo "${result}"
}

software_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/software.profile"
}

software_manifest_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/software-manifest.json"
}

skill_profile_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/skills.profile"
}

config_manifest_path() {
  local data_dir="$1"
  echo "${data_dir}/runtime/config-manifest.json"
}

choice_to_json_bool() {
  local choice="${1:-2}"
  if [[ "${choice}" == "1" ]]; then
    printf 'true\n'
  else
    printf 'false\n'
  fi
}

software_install_method_from_kind() {
  local kind="$1"
  case "${kind}" in
    npm_package|clawpanel|easyclaw|claudecodeui) printf 'npm\n' ;;
    gh_binary) printf 'gh_release\n' ;;
    notebooklm) printf 'pip\n' ;;
    guidance) printf 'guidance\n' ;;
    *) printf '%s\n' "${kind}" ;;
  esac
}

json_array_from_tokens() {
  local out=""
  local token
  for token in "$@"; do
    [[ -n "${token}" ]] || continue
    if [[ -n "${out}" ]]; then
      out="${out}, "
    fi
    out="${out}\"$(json_escape "${token}")\""
  done
  printf '[%s]' "${out}"
}

extract_manifest_software_ids() {
  local manifest="$1"
  [[ -f "${manifest}" ]] || {
    printf '\n'
    return 0
  }
  grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]+"' "${manifest}" 2>/dev/null \
    | sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
    | tr '\n' ' '
}

save_software_manifest() {
  local data_dir="$1"
  shift
  local software_set
  software_set=$(normalize_software_set "$*")
  local manifest
  manifest=$(software_manifest_path "${data_dir}")

  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "软件清单(manifest)将保存到: ${manifest}"
    log_info "软件清单(manifest)内容: ${software_set:-<empty>}"
    return 0
  fi

  local item_lines=""
  local token
  for token in ${software_set}; do
    local label kind arg1 arg2 deps method
    label=$(catalog_field_for_id "software" "${token}" "label")
    kind=$(catalog_field_for_id "software" "${token}" "kind")
    arg1=$(catalog_field_for_id "software" "${token}" "arg1")
    arg2=$(catalog_field_for_id "software" "${token}" "arg2")
    deps=$(catalog_field_for_id "software" "${token}" "deps")
    method=$(software_install_method_from_kind "${kind}")
    deps="${deps//,/ }"
    deps=$(echo "${deps}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
    [[ "${deps}" == "none" ]] && deps=""

    local dep_array
    if [[ -n "${deps}" ]]; then
      # shellcheck disable=SC2086
      dep_array=$(json_array_from_tokens ${deps})
    else
      dep_array='[]'
    fi

    local record
    record=$(cat <<EOF
    {
      "id": "$(json_escape "${token}")",
      "label": "$(json_escape "${label}")",
      "kind": "$(json_escape "${kind}")",
      "install_method": "$(json_escape "${method}")",
      "package": "$(json_escape "${arg1}")",
      "binary": "$(json_escape "${arg2}")",
      "deps": ${dep_array},
      "selected": true
    }
EOF
)
    if [[ -n "${item_lines}" ]]; then
      item_lines="${item_lines},\n${record}"
    else
      item_lines="${record}"
    fi
  done

  cat > "${manifest}" <<EOF
{
  "schema_version": 1,
  "generated_at_utc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "software": [
${item_lines}
  ]
}
EOF
}

software_detection_binaries_for_token() {
  local token="$1"
  local kind arg1 arg2
  kind=$(catalog_field_for_id "software" "${token}" "kind")
  arg1=$(catalog_field_for_id "software" "${token}" "arg1")
  arg2=$(catalog_field_for_id "software" "${token}" "arg2")

  case "${kind}" in
    npm_package)
      if [[ -n "${arg2}" ]]; then
        printf '%s\n' "${arg2}"
      elif [[ -n "${arg1}" ]]; then
        printf '%s\n' "${arg1##*/}"
      else
        printf '%s\n' "${token}"
      fi
      ;;
    gh_binary)
      printf '%s\n' "gh"
      ;;
    notebooklm)
      printf '%s\n' "notebooklm"
      ;;
    clawpanel|easyclaw)
      printf '%s\n' "clawpanel"
      printf '%s\n' "easyclaw"
      ;;
    claudecodeui)
      printf '%s\n' "cloudcli"
      printf '%s\n' "claude-code-ui"
      printf '%s\n' "task-master"
      printf '%s\n' "task-master-ai"
      printf '%s\n' "claudecodeui-start"
      ;;
    guidance)
      printf '%s\n' "${token}"
      ;;
    *)
      if [[ -n "${arg2}" ]]; then
        printf '%s\n' "${arg2}"
      else
        printf '%s\n' "${token}"
      fi
      ;;
  esac
}

software_token_detected_from_paths() {
  local token="$1"
  local data_dir="$2"
  local binary
  local -a path_candidates=(
    "${data_dir}/software/bin"
    "${data_dir}/runtime/root-local-bin"
    "${data_dir}/runtime/path-shims"
    "${data_dir}/.openclaw/software/bin"
  )

  for binary in $(software_detection_binaries_for_token "${token}"); do
    [[ -n "${binary}" ]] || continue
    local base
    for base in "${path_candidates[@]}"; do
      if [[ -x "${base}/${binary}" ]]; then
        return 0
      fi
    done
  done

  case "${token}" in
    clawpanel|easyclaw)
      [[ -d "${data_dir}/software/clawpanel" || -f "${data_dir}/software/clawpanel/install.sh" || -d "${data_dir}/.openclaw/software/clawpanel" ]] && return 0
      ;;
    claudecodeui)
      [[ -d "${data_dir}/software/claudecodeui" || -f "${data_dir}/software/claudecodeui/runtime.env" || -d "${data_dir}/.openclaw/software/claudecodeui" ]] && return 0
      ;;
  esac

  return 1
}

software_token_detected_in_container() {
  local token="$1"
  local container_name="$2"

  [[ -n "${container_name}" ]] || return 1
  if [[ -n "${OPENCLAWCTL_TEST_DISCOVERED_SOFTWARE:-}" ]]; then
    token_in_list "${token}" ${OPENCLAWCTL_TEST_DISCOVERED_SOFTWARE} && return 0
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 1
  fi
  command -v docker >/dev/null 2>&1 || return 1

  local binary
  for binary in $(software_detection_binaries_for_token "${token}"); do
    [[ -n "${binary}" ]] || continue
    if docker exec "${container_name}" sh -lc "command -v '${binary}' >/dev/null 2>&1" >/dev/null 2>&1; then
      return 0
    fi
  done

  case "${token}" in
    clawpanel|easyclaw)
      docker exec "${container_name}" sh -lc 'command -v clawpanel >/dev/null 2>&1 || command -v easyclaw >/dev/null 2>&1 || [ -d /root/.openclaw/software/clawpanel ] || [ -e /root/.openclaw/software/easyclaw/install.sh ]' >/dev/null 2>&1 && return 0
      ;;
    claudecodeui)
      docker exec "${container_name}" sh -lc 'command -v cloudcli >/dev/null 2>&1 || command -v claude-code-ui >/dev/null 2>&1 || [ -f /root/.openclaw/software/claudecodeui/runtime.env ]' >/dev/null 2>&1 && return 0
      ;;
  esac

  return 1
}

discover_software_set() {
  local container_name="$1"
  local data_dir="$2"
  local current_set
  current_set=$(normalize_software_set "${3:-}")
  local discovered="${current_set}"
  local token

  for token in ${OPTIONAL_SOFTWARE_ALL}; do
    token_in_list "${token}" ${discovered} && continue
    if software_token_detected_from_paths "${token}" "${data_dir}" || software_token_detected_in_container "${token}" "${container_name}"; then
      discovered="${discovered}${discovered:+ }${token}"
    fi
  done

  normalize_software_set "${discovered}"
}

load_software_profile() {
  local data_dir="$1"
  local profile
  profile=$(software_profile_path "${data_dir}")
  if [[ -f "${profile}" ]]; then
    normalize_software_set "$(tr '\n' ' ' < "${profile}")"
    return 0
  fi

  local manifest
  manifest=$(software_manifest_path "${data_dir}")
  if [[ -f "${manifest}" ]]; then
    normalize_software_set "$(extract_manifest_software_ids "${manifest}")"
  else
    echo ""
  fi
}

save_software_profile() {
  local data_dir="$1"
  shift
  local software
  software=$(normalize_software_set "$*")
  local profile
  profile=$(software_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "软件档案将保存到: ${profile}"
    log_info "软件档案内容: ${software:-<empty>}"
    save_software_manifest "${data_dir}" "${software}"
    return 0
  fi
  if [[ -n "${software}" ]]; then
    printf '%s\n' ${software} > "${profile}"
  else
    : > "${profile}"
  fi
  save_software_manifest "${data_dir}" "${software}"
}

load_skill_profile() {
  local data_dir="$1"
  local profile
  profile=$(skill_profile_path "${data_dir}")
  if [[ -f "${profile}" ]]; then
    normalize_skill_set "$(tr '\n' ' ' < "${profile}")"
  else
    echo ""
  fi
}

save_skill_profile() {
  local data_dir="$1"
  shift
  local skills
  skills=$(normalize_skill_set "$*")
  local profile
  profile=$(skill_profile_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "Skill 档案将保存到: ${profile}"
    log_info "Skill 档案内容: ${skills:-<empty>}"
    return
  fi
  if [[ -n "${skills}" ]]; then
    printf '%s\n' ${skills} > "${profile}"
  else
    : > "${profile}"
  fi
}

save_config_manifest() {
  local data_dir="$1"
  local mode="${2:-docker-install}"
  local bin_persist_choice="${3:-2}"
  local env_persist_choice="${4:-2}"
  local apt_cfg_persist_choice="${5:-2}"
  local cache_persist_choice="${6:-2}"
  local software_set
  software_set=$(normalize_software_set "${7:-}")
  local skill_set
  skill_set=$(normalize_skill_set "${8:-}")

  local manifest
  manifest=$(config_manifest_path "${data_dir}")
  run_cmd mkdir -p "${data_dir}/runtime"

  local -a software_tokens=()
  local -a skill_tokens=()
  local token
  for token in ${software_set}; do
    software_tokens+=("${token}")
  done
  for token in ${skill_set}; do
    skill_tokens+=("${token}")
  done

  local software_array
  software_array=$(json_array_from_tokens "${software_tokens[@]}")
  local skill_array
  skill_array=$(json_array_from_tokens "${skill_tokens[@]}")
  local bin_bool env_bool apt_bool cache_bool
  bin_bool=$(choice_to_json_bool "${bin_persist_choice}")
  env_bool=$(choice_to_json_bool "${env_persist_choice}")
  apt_bool=$(choice_to_json_bool "${apt_cfg_persist_choice}")
  cache_bool=$(choice_to_json_bool "${cache_persist_choice}")

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "配置清单(config-manifest)将保存到: ${manifest}"
    log_info "配置清单(config-manifest)模式: ${mode}"
    return 0
  fi

  cat > "${manifest}" <<EOF
{
  "schema_version": 1,
  "generated_at_utc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "mode": "$(json_escape "${mode}")",
  "data_dir": "$(json_escape "${data_dir}")",
  "manifests": {
    "software_profile": "runtime/software.profile",
    "software_manifest": "runtime/software-manifest.json",
    "skill_profile": "runtime/skills.profile",
    "persistence_profile": "runtime/persistence.profile",
    "image_lock_profile": "runtime/image-lock.profile"
  },
  "persistence": {
    "bin": ${bin_bool},
    "env": ${env_bool},
    "apt_config": ${apt_bool},
    "cache": ${cache_bool}
  },
  "selected": {
    "software": ${software_array},
    "skills": ${skill_array}
  },
  "config_paths": [
    {"id":"workspace-skills","path":"workspace/skills","purpose":"skills"},
    {"id":"software-root","path":"software","purpose":"software_home"},
    {"id":"runtime-path-decls","path":"runtime/path-decls/openclaw-runtime-path.sh","purpose":"runtime_path_declarations"},
    {"id":"runtime-path-shims","path":"runtime/path-shims","purpose":"runtime_path_shims"}
  ]
}
EOF
}

run_optional_software_script() {
  local container_name="$1"
  local label="$2"
  local script="$3"
  run_cmd_brief "docker exec ${container_name} bash -lc <${label}>" \
    docker exec "${container_name}" bash -lc "${script}"
}

install_software_gh() {
  local container_name="$1"
  local script='set -e
target_bin=/root/.openclaw/software/bin
mkdir -p "$target_bin"
arch_raw=$(uname -m 2>/dev/null || echo unknown)
arch="amd64"
case "$arch_raw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
esac
ver=""
if command -v curl >/dev/null 2>&1; then
  ver=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest 2>/dev/null | grep -m1 "\"tag_name\":" | sed -E "s/.*\"v?([^\"]+)\".*/\\1/" || true)
fi
[ -n "$ver" ] || ver="2.67.0"
url="https://github.com/cli/cli/releases/download/v${ver}/gh_${ver}_linux_${arch}.tar.gz"
tmpd=$(mktemp -d)
cleanup() { rm -rf "$tmpd"; }
trap cleanup EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmpd/gh.tgz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmpd/gh.tgz" "$url"
else
  echo "[software] gh install requires curl or wget"
  exit 1
fi
tar -xzf "$tmpd/gh.tgz" -C "$tmpd"
bin_path=$(find "$tmpd" -type f -path "*/bin/gh" | head -n1)
[ -n "$bin_path" ] || { echo "[software] gh binary not found in archive"; exit 1; }
install -m 0755 "$bin_path" "${target_bin}/gh"
ln -sf "${target_bin}/gh" /usr/local/bin/gh || true'
  run_optional_software_script "${container_name}" "software-gh-install-script" "${script}"
}

install_software_npm_package() {
  local container_name="$1"
  local package_name="$2"
  local binary_name="$3"
  local script='set -e
if ! command -v npm >/dev/null 2>&1; then
  echo "[software] npm not found"
  exit 1
fi
mkdir -p /root/.openclaw/software/bin /root/.openclaw/software/lib
npm install -g --prefix /root/.openclaw/software '"${package_name}"'
[ -x /root/.openclaw/software/bin/'"${binary_name}"' ] && ln -sf /root/.openclaw/software/bin/'"${binary_name}"' /usr/local/bin/'"${binary_name}"' || true'
  run_optional_software_script "${container_name}" "software-npm-${binary_name}-install-script" "${script}"
}

install_software_notebooklm() {
  local container_name="$1"
  local script='set -e
if ! command -v python3 >/dev/null 2>&1; then
  echo "[software] python3 not found for notebooklm"
  exit 1
fi
mkdir -p /root/.openclaw/software/python /root/.openclaw/software/bin
python3 -m pip install --no-cache-dir --target /root/.openclaw/software/python "notebooklm-py[browser]"
cat > /root/.openclaw/software/bin/notebooklm << "EOF"
#!/usr/bin/env bash
PYTHONPATH=/root/.openclaw/software/python python3 -m notebooklm "$@"
EOF
chmod +x /root/.openclaw/software/bin/notebooklm
ln -sf /root/.openclaw/software/bin/notebooklm /usr/local/bin/notebooklm || true
python3 -m playwright install chromium >/dev/null 2>&1 || true'
  run_optional_software_script "${container_name}" "software-notebooklm-install-script" "${script}"
}

install_software_guidance_wrapper() {
  local container_name="$1"
  local command_name="$2"
  local guidance="$3"
  local script='set -e
mkdir -p /root/.openclaw/software/bin
cat > /root/.openclaw/software/bin/'"${command_name}"' << "EOF"
#!/usr/bin/env bash
echo "'"$(printf '%s' "${guidance}" | sed 's/"/\\"/g')"'"
exit 1
EOF
chmod +x /root/.openclaw/software/bin/'"${command_name}"'
ln -sf /root/.openclaw/software/bin/'"${command_name}"' /usr/local/bin/'"${command_name}"' || true'
  run_optional_software_script "${container_name}" "software-guidance-${command_name}-install-script" "${script}"
}

install_software_claudecodeui() {
  local container_name="$1"
  local container_ui_port="${2:-${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}}"
  local script='set -e
if ! command -v npm >/dev/null 2>&1; then
  echo "[software] npm not found"
  exit 1
fi
mkdir -p /root/.openclaw/software/bin /root/.openclaw/software/claudecodeui
npm install -g --prefix /root/.openclaw/software '"${CLAUDECODEUI_NPM_PACKAGE}"' '"${TASKMASTER_NPM_PACKAGE}"'
for bin_name in cloudcli claude-code-ui task-master task-master-ai; do
  if [ -x "/root/.openclaw/software/bin/${bin_name}" ]; then
    ln -sf "/root/.openclaw/software/bin/${bin_name}" "/usr/local/bin/${bin_name}" || true
  fi
done
cat > /root/.openclaw/software/bin/claudecodeui-start << "EOF"
#!/usr/bin/env bash
exec cloudcli --port '"${container_ui_port}"' "$@"
EOF
chmod +x /root/.openclaw/software/bin/claudecodeui-start
ln -sf /root/.openclaw/software/bin/claudecodeui-start /usr/local/bin/claudecodeui-start || true
printf "CONTAINER_PORT=%s\n" '"${container_ui_port}"' > /root/.openclaw/software/claudecodeui/runtime.env

claude_cfg="/root/.claude.json"
if [ ! -f "$claude_cfg" ]; then
  printf "{}\n" > "$claude_cfg"
fi
node - "$claude_cfg" << "NODE"
const fs = require("fs");
const cfgPath = process.argv[2];
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) {
    cfg = {};
  }
} catch (_) {
  cfg = {};
}

if (!cfg.mcpServers || typeof cfg.mcpServers !== "object" || Array.isArray(cfg.mcpServers)) {
  cfg.mcpServers = {};
}

const existing = cfg.mcpServers["task-master-ai"];
if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
  cfg.mcpServers["task-master-ai"] = {
    command: "npx",
    args: ["-y", "task-master-ai"]
  };
} else {
  if (!existing.command) {
    existing.command = "npx";
  }
  if (!Array.isArray(existing.args) || existing.args.length === 0) {
    existing.args = ["-y", "task-master-ai"];
  }
  cfg.mcpServers["task-master-ai"] = existing;
}

fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\\n");
NODE'
  run_optional_software_script "${container_name}" "software-claudecodeui-install-script" "${script}"
}

install_selected_software() {
  local container_name="$1"
  local data_dir="$2"
  local selected
  selected=$(normalize_software_set "${3:-}")
  local extra_ports="${6:-}"
  [[ -n "${selected}" ]] || {
    log_info "未选择可选软件，跳过安装"
    return 0
  }

  local failed=0
  local token
  for token in ${selected}; do
    local kind arg1 arg2
    kind=$(catalog_field_for_id "software" "${token}" "kind")
    arg1=$(catalog_field_for_id "software" "${token}" "arg1")
    arg2=$(catalog_field_for_id "software" "${token}" "arg2")

    case "${kind}" in
      gh_binary)
        install_software_gh "${container_name}" || failed=1
        ;;
      npm_package)
        if [[ -z "${arg1}" || -z "${arg2}" ]]; then
          log_error "软件定义缺少 npm 参数: ${token}"
          failed=1
        else
          install_software_npm_package "${container_name}" "${arg1}" "${arg2}" || failed=1
        fi
        ;;
      notebooklm)
        install_software_notebooklm "${container_name}" || failed=1
        ;;
      clawpanel|easyclaw)
        install_easyclaw "${container_name}" "${data_dir}" || failed=1
        ;;
      claudecodeui)
        local claudecodeui_mapping claudecodeui_container_port
        claudecodeui_mapping=$(detect_claudecodeui_reserved_mapping "${extra_ports}" || true)
        claudecodeui_container_port="${CLAUDECODEUI_RESERVED_CONTAINER_PORT_1}"
        if [[ -n "${claudecodeui_mapping}" ]]; then
          claudecodeui_container_port="${claudecodeui_mapping#*:}"
        fi
        install_software_claudecodeui "${container_name}" "${claudecodeui_container_port}" || failed=1
        ;;
      guidance)
        if [[ -z "${arg1}" ]]; then
          arg1="该工具依赖桌面环境，当前仅写入说明 wrapper。"
        fi
        install_software_guidance_wrapper "${container_name}" "${token}" "${arg1}" || failed=1
        ;;
      "")
        log_error "未找到软件定义: ${token}"
        failed=1
        ;;
      *)
        log_error "不支持的软件安装类型: ${kind} (${token})"
        failed=1
        ;;
    esac
  done

  [[ "${failed}" -eq 0 ]]
}

host_software_dir() {
  local data_dir="$1"
  echo "${data_dir}/software"
}

install_host_software_gh() {
  local native_prefix="$1"
  if [[ "${DRY_RUN}" -eq 0 ]] && command -v gh >/dev/null 2>&1; then
    log_info "宿主机已存在 gh，跳过安装"
    return 0
  fi
  local script='set -e
target_bin="'"${native_prefix}"'/bin"
mkdir -p "$target_bin"
arch_raw=$(uname -m 2>/dev/null || echo unknown)
arch="amd64"
case "$arch_raw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
esac
ver=""
if command -v curl >/dev/null 2>&1; then
  ver=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest 2>/dev/null | grep -m1 "\"tag_name\":" | sed -E "s/.*\"v?([^\"]+)\".*/\\1/" || true)
fi
[ -n "$ver" ] || ver="2.67.0"
url="https://github.com/cli/cli/releases/download/v${ver}/gh_${ver}_linux_${arch}.tar.gz"
tmpd=$(mktemp -d)
cleanup() { rm -rf "$tmpd"; }
trap cleanup EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmpd/gh.tgz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmpd/gh.tgz" "$url"
else
  echo "[software] gh install requires curl or wget"
  exit 1
fi
tar -xzf "$tmpd/gh.tgz" -C "$tmpd"
bin_path=$(find "$tmpd" -type f -path "*/bin/gh" | head -n1)
[ -n "$bin_path" ] || { echo "[software] gh binary not found in archive"; exit 1; }
install -m 0755 "$bin_path" "${target_bin}/gh"'
  run_cmd_brief "host software gh install" bash -lc "${script}"
}

install_host_software_npm_package() {
  local native_prefix="$1"
  local package_name="$2"
  run_cmd npm install -g --prefix "${native_prefix}" "${package_name}"
}

install_host_software_notebooklm() {
  local data_dir="$1"
  local native_prefix="$2"
  local python_target
  python_target="$(host_software_dir "${data_dir}")/python"
  run_cmd mkdir -p "${python_target}" "${native_prefix}/bin"
  run_cmd python3 -m pip install --no-cache-dir --target "${python_target}" "notebooklm-py[browser]"
  local wrapper="${native_prefix}/bin/notebooklm"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "cat > '${wrapper}' <<'EOF'
#!/usr/bin/env bash
PYTHONPATH='${python_target}' python3 -m notebooklm \"\$@\"
EOF"
    run_cmd chmod +x "${wrapper}"
    return 0
  fi
  cat > "${wrapper}" <<EOF
#!/usr/bin/env bash
PYTHONPATH='${python_target}' python3 -m notebooklm "\$@"
EOF
  chmod +x "${wrapper}"
}

install_host_software_clawpanel() {
  local native_prefix="$1"
  run_cmd npm install -g --prefix "${native_prefix}" "@milkkey/clawpanel"
}

install_host_software_guidance_wrapper() {
  local native_prefix="$1"
  local command_name="$2"
  local guidance="$3"
  local wrapper="${native_prefix}/bin/${command_name}"
  run_cmd mkdir -p "${native_prefix}/bin"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "cat > '${wrapper}' <<'EOF'
#!/usr/bin/env bash
echo \"${guidance}\"
exit 1
EOF"
    run_cmd chmod +x "${wrapper}"
    return 0
  fi
  cat > "${wrapper}" <<EOF
#!/usr/bin/env bash
echo "${guidance}"
exit 1
EOF
  chmod +x "${wrapper}"
}

install_selected_software_host() {
  local data_dir="$1"
  local native_prefix="$2"
  local selected
  selected=$(normalize_software_set "${3:-}")
  [[ -n "${selected}" ]] || {
    log_info "未选择可选软件，跳过宿主机安装"
    return 0
  }

  local failed=0
  local token
  for token in ${selected}; do
    local kind arg1 arg2
    kind=$(catalog_field_for_id "software" "${token}" "kind")
    arg1=$(catalog_field_for_id "software" "${token}" "arg1")
    arg2=$(catalog_field_for_id "software" "${token}" "arg2")
    case "${kind}" in
      gh_binary)
        install_host_software_gh "${native_prefix}" || failed=1
        ;;
      npm_package)
        if [[ -z "${arg1}" ]]; then
          log_error "软件定义缺少 npm 参数: ${token}"
          failed=1
        else
          install_host_software_npm_package "${native_prefix}" "${arg1}" || failed=1
        fi
        ;;
      notebooklm)
        install_host_software_notebooklm "${data_dir}" "${native_prefix}" || failed=1
        ;;
      clawpanel|easyclaw)
        install_host_software_clawpanel "${native_prefix}" || failed=1
        ;;
      claudecodeui)
        install_host_software_npm_package "${native_prefix}" "${CLAUDECODEUI_NPM_PACKAGE}" || failed=1
        install_host_software_npm_package "${native_prefix}" "${TASKMASTER_NPM_PACKAGE}" || failed=1
        ;;
      guidance)
        if [[ -z "${arg1}" ]]; then
          arg1="该工具依赖桌面环境，当前仅写入说明 wrapper。"
        fi
        install_host_software_guidance_wrapper "${native_prefix}" "${token}" "${arg1}" || failed=1
        ;;
      "")
        log_error "未找到软件定义: ${token}"
        failed=1
        ;;
      *)
        log_error "宿主机模式暂不支持的软件安装类型: ${kind} (${token})"
        failed=1
        ;;
    esac
  done
  [[ "${failed}" -eq 0 ]]
}

skills_workspace_dir() {
  local data_dir="$1"
  echo "${data_dir}/workspace/skills"
}

install_skill_obsidian() {
  local data_dir="$1"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/obsidian-skills"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
  else
    run_cmd git clone --depth=1 "https://github.com/kepano/obsidian-skills.git" "${target}"
  fi
}

install_skill_security_checker() {
  local data_dir="$1"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/security-checker"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
    return
  fi

  run_cmd git clone --depth=1 --filter=blob:none --sparse "https://github.com/moshall/skill_collcet.git" "${target}"
  run_cmd git -C "${target}" sparse-checkout set security-checker
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "shopt -s dotglob nullglob; mv '${target}/security-checker/'* '${target}/' 2>/dev/null || true; rm -rf '${target}/security-checker'"
  else
    if [[ -d "${target}/security-checker" ]]; then
      shopt -s dotglob nullglob
      mv "${target}/security-checker/"* "${target}/" 2>/dev/null || true
      shopt -u dotglob nullglob
      rm -rf "${target}/security-checker"
    fi
  fi
}

install_skill_git_clone() {
  local data_dir="$1"
  local target_id="$2"
  local repo_url="$3"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/${target_id}"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
  else
    run_cmd git clone --depth=1 "${repo_url}" "${target}"
  fi
}

install_skill_sparse_checkout() {
  local data_dir="$1"
  local target_id="$2"
  local repo_url="$3"
  local sparse_dir="$4"
  local skills_dir
  skills_dir=$(skills_workspace_dir "${data_dir}")
  local target="${skills_dir}/${target_id}"

  run_cmd mkdir -p "${skills_dir}"
  if [[ -d "${target}/.git" ]]; then
    run_cmd git -C "${target}" pull --ff-only
    return
  fi
  run_cmd git clone --depth=1 --filter=blob:none --sparse "${repo_url}" "${target}"
  run_cmd git -C "${target}" sparse-checkout set "${sparse_dir}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd bash -lc "shopt -s dotglob nullglob; mv '${target}/${sparse_dir}/'* '${target}/' 2>/dev/null || true; rm -rf '${target}/${sparse_dir}'"
  else
    if [[ -d "${target}/${sparse_dir}" ]]; then
      shopt -s dotglob nullglob
      mv "${target}/${sparse_dir}/"* "${target}/" 2>/dev/null || true
      shopt -u dotglob nullglob
      rm -rf "${target:?}/${sparse_dir}"
    fi
  fi
}

install_selected_skills() {
  local data_dir="$1"
  local selected
  selected=$(normalize_skill_set "${2:-}")
  [[ -n "${selected}" ]] || {
    log_info "未选择 Skill，跳过安装"
    return 0
  }

  local failed=0
  local token
  for token in ${selected}; do
    local kind arg1 arg2
    kind=$(catalog_field_for_id "skill" "${token}" "kind")
    arg1=$(catalog_field_for_id "skill" "${token}" "arg1")
    arg2=$(catalog_field_for_id "skill" "${token}" "arg2")
    case "${kind}" in
      git_clone)
        if [[ -z "${arg1}" ]]; then
          log_error "Skill 定义缺少仓库地址: ${token}"
          failed=1
        else
          install_skill_git_clone "${data_dir}" "${token}" "${arg1}" || failed=1
        fi
        ;;
      sparse_checkout)
        if [[ -z "${arg1}" || -z "${arg2}" ]]; then
          log_error "Skill 定义缺少 sparse 参数: ${token}"
          failed=1
        else
          install_skill_sparse_checkout "${data_dir}" "${token}" "${arg1}" "${arg2}" || failed=1
        fi
        ;;
      "")
        log_error "未找到 Skill 定义: ${token}"
        failed=1
        ;;
      *)
        log_error "不支持的 Skill 安装类型: ${kind} (${token})"
        failed=1
        ;;
    esac
  done

  [[ "${failed}" -eq 0 ]]
}
