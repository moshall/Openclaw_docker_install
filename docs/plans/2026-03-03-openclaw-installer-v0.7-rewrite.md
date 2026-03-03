# OpenClaw Installer v0.7 Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a new v0.7 installer flow that supports Linux Docker + 1Panel compose/API lifecycle with safe persistence, versioned upgrades, and strict non-interactive reporting.

**Architecture:** Keep the current project intact and introduce a new installer track under `installer/v07` with modular shell libraries plus an orchestration entry script. Reuse proven runtime/persistence logic from `openclawctl.sh`, but separate concerns into detect/image/port/persist/1panel/action modules and back them with dedicated regression scripts.

**Tech Stack:** Bash 4+, Docker CLI, docker compose v2, curl, jq, existing shell-based test harness (`tests/*.sh`).

---

### Task 1: Establish v0.7 scaffold (no behavior change)

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/common.sh`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/ui.sh`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/config.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_smoke_test.sh`

**Step 1: Write failing smoke test**
- Add test to assert `installer/v07/openclaw-install.sh --help` exits 0 and prints `OpenClaw 一键安装向导`.

**Step 2: Run test to verify it fails**
- Run: `bash tests/installer_v07_smoke_test.sh`
- Expected: FAIL (`file not found` or missing banner).

**Step 3: Write minimal scaffold**
- Implement entrypoint parsing (`--help`, `--dry-run`, `--non-interactive`).
- Source `lib/common.sh`, `lib/ui.sh`, `lib/config.sh`.

**Step 4: Run test to verify pass**
- Run: `bash tests/installer_v07_smoke_test.sh`
- Expected: PASS.

**Step 5: Commit**
- `git add installer/v07 tests/installer_v07_smoke_test.sh`
- `git commit -m "feat: scaffold v0.7 installer entry and libs"`

### Task 2: Environment detection module

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/detect.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_detect_test.sh`

**Step 1: Write failing tests**
- Mock `uname`, `/etc/os-release`, `docker info`, `1pctl` and assert variables:
  - `ENV_OS`, `ENV_DISTRO`, `ENV_ARCH`, `ENV_1PANEL`, `ENV_DOCKER`, `ENV_EXISTING_INSTALL`.

**Step 2: Run failing tests**
- Run: `bash tests/installer_v07_detect_test.sh`
- Expected: FAIL on missing detection functions.

**Step 3: Implement detect module**
- Add `detect_environment` with doc-defined outputs.
- Render compact environment summary banner.

**Step 4: Re-run tests**
- Run: `bash tests/installer_v07_detect_test.sh`
- Expected: PASS.

**Step 5: Commit**
- `git add installer/v07/lib/detect.sh installer/v07/openclaw-install.sh tests/installer_v07_detect_test.sh`
- `git commit -m "feat: add v0.7 environment detection"`

### Task 3: Source/version selection and GHCR tag verification

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/image.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_image_test.sh`

**Step 1: Write failing tests**
- Validate source matrix (`official/chinese`) and user/home mapping.
- Validate official custom version existence check (mock `docker manifest inspect`).
- Validate compact tag mapping fallback (`260226 -> 2026.2.26`).

**Step 2: Run tests (expect fail)**
- Run: `bash tests/installer_v07_image_test.sh`

**Step 3: Implement image module**
- Build `select_source`, `select_version`, `verify_official_version`, `resolve_image`.
- Emit clear candidate tags when requested tag missing.

**Step 4: Run tests (expect pass)**
- Run: `bash tests/installer_v07_image_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/image.sh installer/v07/openclaw-install.sh tests/installer_v07_image_test.sh`
- `git commit -m "feat: implement v0.7 source and version resolver"`

### Task 4: Port block allocator and reserved ports

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/port.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_port_test.sh`

**Step 1: Write failing tests**
- Assert scan prefers 7100-7200.
- Assert fallback to random high ports when range full.
- Assert 3 reserved ports are generated and skip occupied ports.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_port_test.sh`

**Step 3: Implement module**
- Add `check_port`, `find_free_port`, `allocate_port_block`.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_port_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/port.sh installer/v07/openclaw-install.sh tests/installer_v07_port_test.sh`
- `git commit -m "feat: add v0.7 port block allocator"`

### Task 5: Persistence paths and container-user compatibility

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/persist.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/config.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_persist_test.sh`

**Step 1: Write failing tests**
- Assert official image maps to `/home/node/.openclaw` and workspace path.
- Assert chinese image maps to `/root/.openclaw` and workspace path.
- Assert 1Panel path vs generic Linux path selection.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_persist_test.sh`

**Step 3: Implement module**
- Centralize host/container path maps and volume mount generation.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_persist_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/persist.sh installer/v07/lib/config.sh tests/installer_v07_persist_test.sh`
- `git commit -m "feat: unify v0.7 persistence path mapping"`

### Task 6: Compose generator (Linux + 1Panel compose mode)

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/compose.sh`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/templates/docker-compose.yml.tmpl`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_compose_test.sh`

**Step 1: Write failing template tests**
- Assert generated compose includes:
  - main service port and 3 reserved ports
  - correct data/workspace mounts
  - selected image tag
  - optional easyclaw port section when enabled.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_compose_test.sh`

**Step 3: Implement compose renderer**
- Build deterministic compose generation with variable interpolation and file write.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_compose_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/compose.sh installer/v07/templates tests/installer_v07_compose_test.sh`
- `git commit -m "feat: add v0.7 compose generator"`

### Task 7: Docker install/create/start lifecycle

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/docker.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_install_flow_test.sh`

**Step 1: Write failing flow tests**
- Assert install sequence order:
  1) ensure host dirs
  2) pull image
  3) generate compose
  4) start container
  5) wait healthy
  6) write config/env report.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_install_flow_test.sh`

**Step 3: Implement lifecycle module**
- Add idempotent pull/start/health-check/report methods.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_install_flow_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/docker.sh installer/v07/openclaw-install.sh tests/installer_v07_install_flow_test.sh`
- `git commit -m "feat: implement v0.7 docker lifecycle flow"`

### Task 8: Upgrade / rebuild / uninstall actions

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/action.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_lifecycle_test.sh`

**Step 1: Write failing lifecycle tests**
- Upgrade preserves data and bumps image tag.
- Rebuild changes port/token but keeps volumes.
- Uninstall supports safe/full modes.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_lifecycle_test.sh`

**Step 3: Implement action module**
- Add `action_upgrade`, `action_rebuild`, `action_uninstall` with strict preflight.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_lifecycle_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/action.sh installer/v07/openclaw-install.sh tests/installer_v07_lifecycle_test.sh`
- `git commit -m "feat: add v0.7 lifecycle actions"`

### Task 9: 1Panel API and compose import helpers

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/onepanel.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_1panel_test.sh`

**Step 1: Write failing tests**
- Validate token/login config parsing.
- Validate compose payload generation and API request body.
- Validate fallback path when API unavailable.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_1panel_test.sh`

**Step 3: Implement module**
- Add 1Panel env detect, API health check, app create/update abstraction.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_1panel_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/onepanel.sh installer/v07/openclaw-install.sh tests/installer_v07_1panel_test.sh`
- `git commit -m "feat: support v0.7 onepanel api/compose modes"`

### Task 10: Strict non-interactive mode and JSON report contract

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/lib/report.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/installer/v07/openclaw-install.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/installer_v07_report_test.sh`

**Step 1: Write failing tests**
- Assert strict mode requires full config input.
- Assert fixed output path for report.
- Assert report fields include action/status/requested/actual image and runtime status.

**Step 2: Run tests (fail)**
- Run: `bash tests/installer_v07_report_test.sh`

**Step 3: Implement report module**
- Add deterministic strict report output and console marker `STRICT_REPORT_PATH=`.

**Step 4: Run tests (pass)**
- Run: `bash tests/installer_v07_report_test.sh`

**Step 5: Commit**
- `git add installer/v07/lib/report.sh installer/v07/openclaw-install.sh tests/installer_v07_report_test.sh`
- `git commit -m "feat: add v0.7 strict noninteractive reporting"`

### Task 11: End-to-end regression scripts and VPS checklist

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/e2e/v07_vps_regression.sh`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/tests/e2e/v07_interrupt_retry.sh`
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/README.md`

**Step 1: Write failing e2e smoke wrappers**
- Add scripts returning non-zero until required env and commands provided.

**Step 2: Run wrappers (fail expected)**
- Run: `bash tests/e2e/v07_vps_regression.sh` and `bash tests/e2e/v07_interrupt_retry.sh`

**Step 3: Implement executable e2e scripts**
- Include Linux + 1Panel install/upgrade, forced interruption, retry success checks.

**Step 4: Run local dry-run checks**
- Run: `bash -n tests/e2e/v07_vps_regression.sh` and `bash -n tests/e2e/v07_interrupt_retry.sh`

**Step 5: Commit**
- `git add tests/e2e README.md`
- `git commit -m "test: add v0.7 e2e regression scripts"`

### Task 12: Migration docs and rollout switch

**Files:**
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/README.md`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/docs/rewrite-v0.7/migration.md`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/.worktrees/rewrite-v0.7/docs/rewrite-v0.7/release-checklist.md`

**Step 1: Write failing docs checklist test**
- Add script to verify docs mention v0.7 entrypoint, compatibility notes, rollback path.

**Step 2: Run docs check (fail)**
- Run: `bash tests/installer_v07_docs_test.sh`

**Step 3: Complete docs and rollout steps**
- Document differences between `openclawctl.sh` and new `installer/v07/openclaw-install.sh`.
- Add explicit rollback strategy to previous stable release tag.

**Step 4: Run full validation**
- Run:
  - `bash -n installer/v07/openclaw-install.sh`
  - `bash tests/openclawctl_test.sh`
  - `bash tests/installer_v07_*_test.sh`
  - `GOCACHE="$(pwd)/.gocache" GOMODCACHE="$(pwd)/.gomodcache" go test ./...`

**Step 5: Commit**
- `git add README.md docs/rewrite-v0.7 tests/installer_v07_docs_test.sh`
- `git commit -m "docs: add v0.7 migration and rollout guide"`

