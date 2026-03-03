#!/usr/bin/env bash

set -euo pipefail

CFG_SOURCE=""
CFG_IMAGE_BASE=""
CFG_CONTAINER_USER=""
CFG_CONTAINER_HOME=""
CFG_NPM_PACKAGE=""
CFG_VERSION_TAG=""
CFG_DOCKER_IMAGE=""

v07_resolve_source_profile() {
  local source_choice="${1:-chinese}"
  case "${source_choice}" in
    chinese)
      CFG_SOURCE="chinese"
      CFG_IMAGE_BASE="ghcr.io/1186258278/openclaw-zh"
      CFG_CONTAINER_USER="root"
      CFG_CONTAINER_HOME="/root"
      CFG_NPM_PACKAGE="@qingchencloud/openclaw-zh"
      ;;
    official)
      CFG_SOURCE="official"
      CFG_IMAGE_BASE="ghcr.io/openclaw/openclaw"
      CFG_CONTAINER_USER="node"
      CFG_CONTAINER_HOME="/home/node"
      CFG_NPM_PACKAGE="openclaw"
      ;;
    *)
      v07_log_error "未知镜像源: ${source_choice}"
      return 1
      ;;
  esac
}

v07_compact_tag_to_dotted() {
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

v07_tag_to_date_key() {
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

v07_fetch_official_tags() {
  if [[ -n "${OPENCLAWCTL_TEST_OFFICIAL_TAGS:-}" ]]; then
    printf '%s\n' "${OPENCLAWCTL_TEST_OFFICIAL_TAGS}" | tr ',' '\n' | awk 'NF {print $0}'
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi

  local api="${V07_OFFICIAL_TAG_LIST_API:-https://registry.hub.docker.com/v2/repositories/alpine/openclaw/tags?page_size=100}"
  local raw
  raw=$(curl -fsSL "${api}" 2>/dev/null || true)
  [[ -n "${raw}" ]] || return 1
  printf '%s\n' "${raw}" | grep -Eo '"name":"[^"]+"' | sed -E 's/"name":"([^"]+)"/\1/' | awk '!seen[$0]++'
}

v07_tag_exists_in_array() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    [[ "${item}" == "${needle}" ]] && return 0
  done
  return 1
}

v07_choose_nearest_tag() {
  local action="$1"
  local requested_tag="$2"
  shift 2 || true
  local tags=("$@")
  local requested_key
  requested_key=$(v07_tag_to_date_key "${requested_tag}" 2>/dev/null || true)

  local best_any=""
  local best_any_diff=-1
  local best_ge=""
  local best_ge_diff=-1
  local best_lt=""
  local best_lt_diff=-1

  local tag tag_key
  for tag in "${tags[@]}"; do
    [[ -z "${tag}" ]] && continue
    tag_key=$(v07_tag_to_date_key "${tag}" 2>/dev/null || true)
    [[ -n "${tag_key}" ]] || continue

    if [[ -z "${requested_key}" ]]; then
      [[ -z "${best_any}" ]] && best_any="${tag}"
      continue
    fi

    local diff=$((10#${tag_key} - 10#${requested_key}))
    local abs_diff="${diff#-}"

    if [[ -z "${best_any}" || "${abs_diff}" -lt "${best_any_diff}" ]]; then
      best_any="${tag}"
      best_any_diff=${abs_diff}
    fi

    if ((diff >= 0)); then
      if [[ -z "${best_ge}" || "${diff}" -lt "${best_ge_diff}" ]]; then
        best_ge="${tag}"
        best_ge_diff=${diff}
      fi
    else
      local lt_diff=$((-diff))
      if [[ -z "${best_lt}" || "${lt_diff}" -lt "${best_lt_diff}" ]]; then
        best_lt="${tag}"
        best_lt_diff=${lt_diff}
      fi
    fi
  done

  if [[ "${action}" == "upgrade" ]]; then
    [[ -n "${best_ge}" ]] && {
      printf '%s\n' "${best_ge}"
      return 0
    }
    [[ -n "${best_lt}" ]] && {
      printf '%s\n' "${best_lt}"
      return 0
    }
  fi

  if [[ -n "${best_any}" ]]; then
    printf '%s\n' "${best_any}"
  fi
}

v07_format_tag_candidates() {
  local limit="${1:-12}"
  shift || true
  local out=""
  local count=0
  local tag
  for tag in "$@"; do
    [[ -z "${tag}" ]] && continue
    if [[ -z "${out}" ]]; then
      out="${tag}"
    else
      out="${out}, ${tag}"
    fi
    count=$((count + 1))
    [[ "${count}" -ge "${limit}" ]] && break
  done
  [[ -n "${out}" ]] && printf '%s\n' "${out}" || printf '无\n'
}

v07_resolve_official_tag_with_fallback() {
  local action="$1"
  local requested_tag="$2"

  if [[ -z "${requested_tag}" || "${requested_tag}" == "latest" || "${requested_tag}" == "main" ]]; then
    printf '%s\n' "${requested_tag:-latest}"
    return 0
  fi

  local -a tags=()
  local tag
  while IFS= read -r tag; do
    [[ -z "${tag}" ]] && continue
    tags+=("${tag}")
  done < <(v07_fetch_official_tags || true)

  if [[ "${#tags[@]}" -eq 0 ]]; then
    local mapped
    mapped=$(v07_compact_tag_to_dotted "${requested_tag}")
    if [[ "${mapped}" != "${requested_tag}" ]]; then
      printf '[INFO] [preflight] 官方标签 %s 不存在，已自动映射为 %s\n' "${requested_tag}" "${mapped}" >&2
      printf '%s\n' "${mapped}"
      return 0
    fi
    printf '%s\n' "${requested_tag}"
    return 0
  fi

  if v07_tag_exists_in_array "${requested_tag}" "${tags[@]}"; then
    printf '%s\n' "${requested_tag}"
    return 0
  fi

  local mapped
  mapped=$(v07_compact_tag_to_dotted "${requested_tag}")
  if [[ "${mapped}" != "${requested_tag}" ]] && v07_tag_exists_in_array "${mapped}" "${tags[@]}"; then
    printf '[INFO] [preflight] 官方标签 %s 不存在，已自动映射为 %s\n' "${requested_tag}" "${mapped}" >&2
    printf '%s\n' "${mapped}"
    return 0
  fi

  local fallback
  fallback=$(v07_choose_nearest_tag "${action}" "${requested_tag}" "${tags[@]}")
  if [[ -n "${fallback}" ]]; then
    printf '[INFO] [preflight] 官方标签 %s 不存在，可选标签(最近): %s\n' "${requested_tag}" "$(v07_format_tag_candidates 12 "${tags[@]}")" >&2
    printf '[INFO] [preflight] 已自动回退到最近可用标签: %s\n' "${fallback}" >&2
    printf '%s\n' "${fallback}"
    return 0
  fi

  v07_log_error "[preflight] 官方标签 ${requested_tag} 不存在，且未找到可用回退标签"
  return 1
}

v07_verify_official_version() {
  local version_tag="$1"
  local image_tag="${version_tag}"
  if [[ "${ENV_ARCH:-amd64}" == "arm64" ]]; then
    image_tag="${version_tag}-arm64"
  fi
  docker manifest inspect "ghcr.io/openclaw/openclaw:${image_tag}" >/dev/null 2>&1
}

v07_resolve_image_tag() {
  local source="$1"
  local channel="$2"
  local requested_tag="${3:-}"

  if [[ "${source}" == "chinese" ]]; then
    case "${channel}" in
      stable) printf 'latest\n' ;;
      nightly) printf 'nightly\n' ;;
      *)
        if [[ -n "${requested_tag}" ]]; then
          printf '%s\n' "${requested_tag}"
        else
          printf 'latest\n'
        fi
        ;;
    esac
    return 0
  fi

  case "${channel}" in
    stable) printf 'latest\n' ;;
    beta) printf 'main\n' ;;
    custom)
      [[ -n "${requested_tag}" ]] || {
        v07_log_error "官方 custom 模式要求提供版本号"
        return 1
      }
      v07_resolve_official_tag_with_fallback "upgrade" "${requested_tag}"
      ;;
    *)
      printf 'latest\n'
      ;;
  esac
}

v07_resolve_image() {
  local source="$1"
  local channel="$2"
  local requested_tag="${3:-}"

  v07_resolve_source_profile "${source}"
  CFG_VERSION_TAG=$(v07_resolve_image_tag "${source}" "${channel}" "${requested_tag}")
  CFG_DOCKER_IMAGE="${CFG_IMAGE_BASE}:${CFG_VERSION_TAG}"
  printf '%s\n' "${CFG_DOCKER_IMAGE}"
}
