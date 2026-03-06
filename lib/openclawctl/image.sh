#!/usr/bin/env bash

fetch_official_openclaw_tags() {
  if [[ -n "${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_OFFICIAL_TAGS}" | tr ',' '\n' | awk 'NF {print $0}'
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi

  local repo_path
  repo_path=$(official_openclaw_repo_path)
  local api="https://hub.docker.com/v2/repositories/${repo_path}/tags?page_size=100"
  local raw
  raw=$(curl -fsSL "${api}" 2>/dev/null || true)
  if [[ -z "${raw}" ]]; then
    return 1
  fi

  printf '%s\n' "${raw}" | grep -Eo '"name":"[^"]+"' | sed -E 's/"name":"([^"]+)"/\1/' | awk '!seen[$0]++'
}

split_image_repo_and_tag() {
  local image="$1"
  local repo="${image}"
  local tag="latest"
  if [[ "${image}" == *@* ]]; then
    repo="${image%@*}"
    tag=""
  elif [[ "${image##*/}" == *:* ]]; then
    repo="${image%:*}"
    tag="${image##*:}"
  fi
  printf '%s|%s\n' "${repo}" "${tag}"
}

image_repo_without_registry() {
  local repo="$1"
  repo="${repo#docker.io/}"
  repo="${repo#/}"
  printf '%s\n' "${repo}"
}

is_official_openclaw_image_ref() {
  local image="$1"
  local parts repo
  parts=$(split_image_repo_and_tag "${image}")
  repo="${parts%%|*}"
  repo=$(image_repo_without_registry "${repo}")
  [[ "${repo}" == "$(official_openclaw_repo_path)" ]]
}

is_openclaw_zh_image_ref() {
  local image="$1"
  local parts repo
  parts=$(split_image_repo_and_tag "${image}")
  repo="${parts%%|*}"
  repo=$(printf '%s' "${repo}" | tr '[:upper:]' '[:lower:]')
  [[ "${repo}" == "openclaw-zh" || "${repo}" == */openclaw-zh ]]
}

should_persist_node_modules_mount() {
  local image="$1"
  if is_openclaw_zh_image_ref "${image}"; then
    return 1
  fi
  return 0
}

tag_exists_in_array() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    [[ "${item}" == "${needle}" ]] && return 0
  done
  return 1
}

compact_tag_to_dotted() {
  local tag="$1"
  if [[ "${tag}" =~ ^([0-9]{2})([0-9]{2})([0-9]{2})$ ]]; then
    local year month day
    year=$((2000 + 10#${BASH_REMATCH[1]}))
    month=$((10#${BASH_REMATCH[2]}))
    day=$((10#${BASH_REMATCH[3]}))
    printf '%d.%d.%d\n' "${year}" "${month}" "${day}"
    return 0
  fi
  printf '%s\n' "${tag}"
}

tag_to_date_key() {
  local tag="$1"
  local year month day
  if [[ "${tag}" =~ ^([0-9]{2})([0-9]{2})([0-9]{2})$ ]]; then
    year=$((2000 + 10#${BASH_REMATCH[1]}))
    month=$((10#${BASH_REMATCH[2]}))
    day=$((10#${BASH_REMATCH[3]}))
  elif [[ "${tag}" =~ ^([0-9]{4})[._-]([0-9]{1,2})[._-]([0-9]{1,2})$ ]]; then
    year=$((10#${BASH_REMATCH[1]}))
    month=$((10#${BASH_REMATCH[2]}))
    day=$((10#${BASH_REMATCH[3]}))
  else
    return 1
  fi
  if ((month < 1 || month > 12 || day < 1 || day > 31)); then
    return 1
  fi
  printf '%04d%02d%02d\n' "${year}" "${month}" "${day}"
}

format_tag_candidates_for_log() {
  local limit="${1:-8}"
  shift || true
  local out="" sep="" count=0
  local tag
  for tag in "$@"; do
    [[ -z "${tag}" ]] && continue
    out="${out}${sep}${tag}"
    sep=", "
    count=$((count + 1))
    [[ "${count}" -ge "${limit}" ]] && break
  done
  if [[ -z "${out}" ]]; then
    printf '无\n'
  else
    printf '%s\n' "${out}"
  fi
}

choose_nearest_official_tag() {
  local action="$1"
  local requested_tag="$2"
  shift 2 || true
  local tags=("$@")
  local requested_key
  requested_key=$(tag_to_date_key "${requested_tag}" 2>/dev/null || true)

  local first_non_alias=""
  local best_any=""
  local best_any_diff=-1
  local best_ge=""
  local best_ge_diff=-1
  local best_lt=""
  local best_lt_diff=-1

  local tag tag_key
  for tag in "${tags[@]}"; do
    [[ -z "${tag}" ]] && continue
    if [[ -z "${first_non_alias}" && "${tag}" != "latest" && "${tag}" != "beta" ]]; then
      first_non_alias="${tag}"
    fi

    tag_key=$(tag_to_date_key "${tag}" 2>/dev/null || true)
    [[ -n "${tag_key}" ]] || continue

    if [[ -z "${requested_key}" ]]; then
      [[ -z "${best_any}" ]] && best_any="${tag}"
      continue
    fi

    local diff=$((10#${tag_key} - 10#${requested_key}))
    local abs_diff="${diff#-}"
    if [[ -z "${best_any}" || "${abs_diff}" -lt "${best_any_diff}" ]]; then
      best_any="${tag}"
      best_any_diff="${abs_diff}"
    fi
    if ((diff >= 0)); then
      if [[ -z "${best_ge}" || "${diff}" -lt "${best_ge_diff}" ]]; then
        best_ge="${tag}"
        best_ge_diff="${diff}"
      fi
    else
      local lt_diff=$((-diff))
      if [[ -z "${best_lt}" || "${lt_diff}" -lt "${best_lt_diff}" ]]; then
        best_lt="${tag}"
        best_lt_diff="${lt_diff}"
      fi
    fi
  done

  if [[ "${action}" == "upgrade" ]]; then
    [[ -n "${best_ge}" ]] && {
      printf '%s\n' "${best_ge}"
      return
    }
    [[ -n "${best_lt}" ]] && {
      printf '%s\n' "${best_lt}"
      return
    }
  fi

  [[ -n "${best_any}" ]] && {
    printf '%s\n' "${best_any}"
    return
  }
  [[ -n "${first_non_alias}" ]] && {
    printf '%s\n' "${first_non_alias}"
    return
  }
  [[ "${#tags[@]}" -gt 0 ]] && printf '%s\n' "${tags[0]}"
}

resolve_official_tag_with_fallback() {
  local action="$1"
  local image="$2"
  if ! is_official_openclaw_image_ref "${image}"; then
    printf '%s\n' "${image}"
    return 0
  fi

  local parts repo requested_tag
  parts=$(split_image_repo_and_tag "${image}")
  repo="${parts%%|*}"
  requested_tag="${parts#*|}"
  if [[ -z "${requested_tag}" || "${requested_tag}" == "latest" || "${requested_tag}" == "beta" ]]; then
    printf '%s\n' "${image}"
    return 0
  fi

  local -a tags=()
  local tag
  while IFS= read -r tag; do
    [[ -z "${tag}" ]] && continue
    tags+=("${tag}")
  done < <(fetch_official_openclaw_tags || true)

  if [[ "${#tags[@]}" -eq 0 ]]; then
    printf '[INFO] [preflight] 未获取到官方标签列表，继续按原标签尝试: %s\n' "${requested_tag}" >&2
    printf '%s\n' "${image}"
    return 0
  fi

  if tag_exists_in_array "${requested_tag}" "${tags[@]}"; then
    printf '%s\n' "${image}"
    return 0
  fi

  local mapped_tag
  mapped_tag=$(compact_tag_to_dotted "${requested_tag}")
  if [[ "${mapped_tag}" != "${requested_tag}" ]] && tag_exists_in_array "${mapped_tag}" "${tags[@]}"; then
    printf '[INFO] [preflight] 官方标签 %s 不存在，已自动映射为 %s\n' "${requested_tag}" "${mapped_tag}" >&2
    printf '%s:%s\n' "${repo}" "${mapped_tag}"
    return 0
  fi

  local fallback_tag
  fallback_tag=$(choose_nearest_official_tag "${action}" "${requested_tag}" "${tags[@]}")
  if [[ -z "${fallback_tag}" ]]; then
    log_error "[preflight] 官方标签 ${requested_tag} 不存在，且未找到可用回退标签"
    log_error "[preflight] 可选标签(最近): $(format_tag_candidates_for_log 12 "${tags[@]}")"
    return 1
  fi

  printf '[INFO] [preflight] 官方标签 %s 不存在，可选标签(最近): %s\n' "${requested_tag}" "$(format_tag_candidates_for_log 12 "${tags[@]}")" >&2
  printf '[INFO] [preflight] 已自动回退到最近可用标签: %s\n' "${fallback_tag}" >&2
  printf '%s:%s\n' "${repo}" "${fallback_tag}"
}

docker_pull_image_checked() {
  local image="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    run_cmd docker pull "${image}"
    return 0
  fi

  print_cmd docker pull "${image}"
  local output rc
  set +e
  output=$(docker pull "${image}" 2>&1)
  rc=$?
  set -e
  [[ -n "${output}" ]] && printf '%s\n' "${output}"
  if [[ "${rc}" -ne 0 ]]; then
    log_error "镜像拉取失败: ${image}"
    return "${rc}"
  fi
  return 0
}

prompt_official_openclaw_tag() {
  local current_tag="${1:-latest}"
  local -a tags=()
  local tag
  while IFS= read -r tag; do
    [[ -z "${tag}" ]] && continue
    tags+=("${tag}")
    [[ "${#tags[@]}" -ge 20 ]] && break
  done < <(fetch_official_openclaw_tags || true)

  if [[ "${#tags[@]}" -eq 0 ]]; then
    printf '[INFO] 未能自动拉取官方标签，已回退到手动输入\n' >&2
    read_with_default "请输入官方镜像标签（例如 latest、beta、2026.2.26）" "${current_tag}"
    return
  fi

  echo "官方 openclaw 可选标签（最近）:" >&2
  local i
  for i in "${!tags[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${tags[$i]}" >&2
  done
  echo "  m) 手动输入标签" >&2

  local choice
  choice=$(read_choice_default "请选择标签" "1")
  if [[ "${choice}" == "m" || "${choice}" == "M" ]]; then
    read_with_default "请输入官方镜像标签（例如 latest、beta、2026.2.26）" "${current_tag}"
    return
  fi

  if [[ "${choice}" =~ ^[0-9]+$ ]] && ((choice >= 1)) && ((choice <= ${#tags[@]})); then
    printf '%s\n' "${tags[$((choice - 1))]}"
    return
  fi

  log_error "无效选择，已使用默认标签 ${current_tag}"
  printf '%s\n' "${current_tag}"
}

native_is_prerelease_version() {
  local version="$1"
  local lower
  lower=$(printf '%s' "${version}" | tr '[:upper:]' '[:lower:]')
  [[ "${lower}" == *"-"* || "${lower}" == *"beta"* || "${lower}" == *"nightly"* || "${lower}" == *"alpha"* || "${lower}" == *"rc"* || "${lower}" == *"canary"* || "${lower}" == *"dev"* ]]
}

fetch_native_npm_versions() {
  local package_name="$1"
  if [[ -n "${OPENCLAWCTL_TEST_NATIVE_NPM_VERSIONS:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_NATIVE_NPM_VERSIONS}" | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | awk 'NF && !seen[$0]++ {print $0}'
    return 0
  fi

  if ! command -v npm >/dev/null 2>&1; then
    return 1
  fi

  local raw
  raw=$(npm view "${package_name}" versions --json 2>/dev/null || true)
  if [[ -z "${raw}" ]]; then
    return 1
  fi

  printf '%s\n' "${raw}" | tr -d '[]"' | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | awk 'NF && !seen[$0]++ {print $0}'
}

list_native_npm_versions_for_selection() {
  local package_name="$1"
  local source_choice="$2"
  local channel_choice="$3"
  local limit="${4:-12}"
  local -a all_versions=()
  local -a filtered_versions=()
  local -a candidate_versions=()
  local version

  while IFS= read -r version; do
    version=$(printf '%s' "${version}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
    [[ -z "${version}" ]] && continue
    all_versions+=("${version}")
  done < <(fetch_native_npm_versions "${package_name}" || true)

  if [[ "${#all_versions[@]}" -eq 0 ]]; then
    return 1
  fi

  local wants_prerelease="0"
  if [[ "${channel_choice}" == "2" ]]; then
    wants_prerelease="1"
  fi
  if [[ "${source_choice}" != "1" && "${source_choice}" != "2" ]]; then
    wants_prerelease="0"
  fi

  local item
  for item in "${all_versions[@]}"; do
    if [[ "${wants_prerelease}" == "1" ]]; then
      if native_is_prerelease_version "${item}"; then
        filtered_versions+=("${item}")
      fi
    else
      if ! native_is_prerelease_version "${item}"; then
        filtered_versions+=("${item}")
      fi
    fi
  done

  if [[ "${#filtered_versions[@]}" -gt 0 ]]; then
    candidate_versions=("${filtered_versions[@]}")
  else
    candidate_versions=("${all_versions[@]}")
  fi

  local count=0
  local idx
  for ((idx=${#candidate_versions[@]} - 1; idx>=0; idx--)); do
    item="${candidate_versions[$idx]}"
    [[ -z "${item}" ]] && continue
    printf '%s\n' "${item}"
    count=$((count + 1))
    if [[ "${count}" -ge "${limit}" ]]; then
      break
    fi
  done
}

prompt_native_npm_version_choice() {
  local package_name="$1"
  local source_choice="$2"
  local channel_choice="$3"
  local default_tag="$4"

  echo "版本策略:" >&2
  echo "  1) 通道默认（推荐）" >&2
  echo "  2) 指定版本（列表选择）" >&2

  local mode_choice
  mode_choice=$(read_choice_default "请选择" "1")
  mode_choice=$(printf '%s' "${mode_choice}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
  if [[ "${mode_choice}" != "2" ]]; then
    printf '%s\n' ""
    return
  fi

  local -a versions=()
  local version
  while IFS= read -r version; do
    version=$(printf '%s' "${version}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
    [[ -z "${version}" ]] && continue
    versions+=("${version}")
  done < <(list_native_npm_versions_for_selection "${package_name}" "${source_choice}" "${channel_choice}" "12" || true)

  if [[ "${#versions[@]}" -eq 0 ]]; then
    log_error "暂未拉取到可选版本，已回退到通道默认（${default_tag}）"
    printf '%s\n' ""
    return
  fi

  echo "可选版本（最近）:" >&2
  local i
  for i in "${!versions[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${versions[$i]}" >&2
  done

  local selected
  selected=$(read_choice_default "请选择版本" "1")
  selected=$(printf '%s' "${selected}" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
  if [[ "${selected}" =~ ^[0-9]+$ ]] && ((selected >= 1)) && ((selected <= ${#versions[@]})); then
    printf '%s\n' "${versions[$((selected - 1))]}"
    return
  fi

  log_error "无效选择，已回退到通道默认（${default_tag}）"
  printf '%s\n' ""
}

resolve_image() {
  local source_choice="$1"
  local channel_choice="$2"
  local explicit_tag="${3:-}"

  if [[ "${source_choice}" == "1" && "${channel_choice}" == "1" ]]; then
    official_openclaw_image "latest"
    return
  fi

  if [[ "${source_choice}" == "1" && "${channel_choice}" == "2" ]]; then
    official_openclaw_image "beta"
    return
  fi

  if [[ "${source_choice}" == "1" && "${channel_choice}" == "3" ]]; then
    if [[ -z "${explicit_tag}" ]]; then
      log_error "官方指定版本缺少标签"
      return 1
    fi
    official_openclaw_image "${explicit_tag}"
    return
  fi

  if [[ "${source_choice}" == "2" && "${channel_choice}" == "1" ]]; then
    printf '%s\n' "ghcr.io/1186258278/openclaw-zh:latest"
    return
  fi

  if [[ "${source_choice}" == "2" && "${channel_choice}" == "2" ]]; then
    printf '%s\n' "ghcr.io/1186258278/openclaw-zh:nightly"
    return
  fi

  log_error "版本选择无效"
  return 1
}
