# v0.7 Migration Guide

## New Entry Point
- New installer script: `installer/v07/openclaw-install.sh`
- Legacy script kept intact: `openclawctl.sh`

## openclawctl 模块化（v0.7）
- `openclawctl.sh` 保持唯一外部入口。
- 业务函数按职责拆分到 `lib/openclawctl/*.sh`：
  - `common/io/image/persist/components/deps/ops/wizard`
- 入口按固定顺序 source 模块，避免隐式依赖。
- 详细映射见：`docs/rewrite-v0.7/openclawctl-modular-map.md`

## Task 9 验证记录（2026-03-05）
- `bash tests/openclawctl_test.sh` ✅
- `go test ./...` ✅
- `bash tests/installer_v07_smoke_test.sh` ✅
- `bash tests/installer_v07_1panel_test.sh` ✅

## Config Compatibility
- v0.7 uses key-value `config.env` inputs (`CFG_*` fields).
- Strict batch mode:
  - `OPENCLAWCTL_STRICT_NONINTERACTIVE=1`
  - must provide `--wizard` and `--config-file`

## Lifecycle Coverage
- Supported actions:
  - `install`
  - `upgrade`
  - `rebuild`
  - `status`
  - `logs`
  - `uninstall`
  - `adopt` (接管外部安装容器，生成配置)
  - `persist` (为已有容器追加 runtime 持久化重建)
  - `native` (原生 npm 安装入口)
  - `info` (查看 deployment-info)

## Rollback
- To rollback to previous stable behavior:
  1. checkout release tag `v1.3.0`
  2. run legacy flow through `openclawctl.sh`
- v0.7 work stays isolated in installer-specific paths and config.
