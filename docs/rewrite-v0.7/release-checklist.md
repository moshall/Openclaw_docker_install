# v0.7 Release Checklist

## Local Verification
- [ ] `bash -n installer/v07/openclaw-install.sh`
- [ ] `bash tests/installer_v07_smoke_test.sh`
- [ ] `bash tests/installer_v07_detect_test.sh`
- [ ] `bash tests/installer_v07_image_test.sh`
- [ ] `bash tests/installer_v07_port_test.sh`
- [ ] `bash tests/installer_v07_persist_test.sh`
- [ ] `bash tests/installer_v07_compose_test.sh`
- [ ] `bash tests/installer_v07_install_flow_test.sh`
- [ ] `bash tests/installer_v07_lifecycle_test.sh`
- [ ] `bash tests/installer_v07_report_test.sh`
- [ ] `bash tests/installer_v07_1panel_test.sh`

## Real Host Verification
- [ ] Linux direct Docker install
- [ ] 1Panel compose install
- [ ] 1Panel API install
- [ ] low -> high version upgrade compatibility
- [ ] interrupted-upgrade retry

## Artifacts
- [ ] strict report file generated (`STRICT_REPORT_PATH=`)
- [ ] migration doc updated
- [ ] release tag notes updated
