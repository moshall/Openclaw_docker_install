# v0.7 Migration Guide

## New Entry Point
- New installer script: `installer/v07/openclaw-install.sh`
- Legacy script kept intact: `openclawctl.sh`

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

## Rollback
- To rollback to previous stable behavior:
  1. checkout release tag `v1.3.0`
  2. run legacy flow through `openclawctl.sh`
- v0.7 work stays isolated in installer-specific paths and config.
