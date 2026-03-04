# v0.7 Release Checklist

## Local Verification
- [x] `bash -n installer/v07/openclaw-install.sh`
- [x] `bash tests/installer_v07_smoke_test.sh`
- [x] `bash tests/installer_v07_detect_test.sh`
- [x] `bash tests/installer_v07_image_test.sh`
- [x] `bash tests/installer_v07_port_test.sh`
- [x] `bash tests/installer_v07_persist_test.sh`
- [x] `bash tests/installer_v07_compose_test.sh`
- [x] `bash tests/installer_v07_install_flow_test.sh`
- [x] `bash tests/installer_v07_lifecycle_test.sh`
- [x] `bash tests/installer_v07_report_test.sh`
- [x] `bash tests/installer_v07_1panel_test.sh`
- [x] `bash tests/openclawctl_test.sh`
- [x] `GOCACHE=... GOMODCACHE=... go test ./...`
- [x] 模块映射文档更新：`docs/rewrite-v0.7/openclawctl-modular-map.md`
- [x] 迁移文档补齐模块化说明：`docs/rewrite-v0.7/migration.md`

## Real Host Verification
- [ ] Linux direct Docker install
- [ ] 1Panel compose install
- [ ] 1Panel API install
- [ ] low -> high version upgrade compatibility
- [ ] interrupted-upgrade retry
- [ ] optional software + skill real-host regression
- [ ] adopt/persist/native real-host regression
- [x] `openclaw-zh:nightly` runtime persistence issue resolved (see `docs/rewrite-v0.7/todo-known-issue-zh-nightly-runtime-persist.md`)

## Artifacts
- [x] strict report file generated (`STRICT_REPORT_PATH=`)
- [x] migration doc updated
- [ ] release tag notes updated
