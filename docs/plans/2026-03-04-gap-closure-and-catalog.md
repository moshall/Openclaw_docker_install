# Gap Closure + Catalog-Driven Optional Components Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close documented-but-missing installer features (except forced Skill security prompt) and make software/Skill lists config-driven for future extensibility.

**Architecture:** Keep `openclawctl.sh` as execution core; add a data file (`config/optional-components.conf`) as source of truth for optional software/skills and generic install dispatch. Add deployment-info write/read flow and `info` wizard. Extend v0.7 entry/action coverage and Go TUI action/config parity.

**Tech Stack:** Bash, Go (Bubble Tea/Huh forms), existing shell/go test suites.

---

### Task 1: Add failing tests for new behavior

**Files:**
- Modify: `tests/openclawctl_test.sh`
- Modify: `internal/app/app_test.go`
- Modify: `cmd/openclawctl/main_test.go`
- Modify: `tests/installer_v07_smoke_test.sh`

**Step 1: Add shell tests**
- Assert `--wizard info` works and prints deployment-info path.
- Assert optional software summary can include `EasyClaw` and `Obsidian CLI` from catalog config.
- Assert `info` positional command works (`openclawctl.sh info --dry-run` style).

**Step 2: Add Go tests**
- Assert action options include `adopt/persist/native/info`.
- Assert install config serialization includes `SOFTWARE_SET/SKILL_SET`.

**Step 3: Add v0.7 smoke expectation**
- Assert `--wizard` help includes `adopt|persist|native|info`.

### Task 2: Implement config-driven optional components

**Files:**
- Create: `config/optional-components.conf`
- Modify: `openclawctl.sh`

**Step 1: Add catalog file and parser**
- Define pipe-delimited records for software/skill items.
- Load at startup with fallback defaults.

**Step 2: Replace hardcoded software/skill definitions**
- Build `OPTIONAL_SOFTWARE_ALL` / `OPTIONAL_SKILL_ALL` from catalog.
- Resolve labels from catalog.
- Compute dependency auto-add from catalog-declared deps.

**Step 3: Generic install dispatch**
- Software kinds: `gh_binary`, `npm_package`, `notebooklm`, `easyclaw`, `guidance`.
- Skill kinds: `git_clone`, `sparse_checkout`.

### Task 3: Implement deployment-info and info entry

**Files:**
- Modify: `openclawctl.sh`

**Step 1: Write deployment-info file**
- Add writer to `~/.openclaw-installer/deployment-info.txt` after install/upgrade/rebuild/adopt success paths.

**Step 2: Add info viewer path**
- Add `--wizard info` and menu item.
- Add positional `info` compatibility for `openclaw info`-style invocation when script is symlinked.

### Task 4: Fill v0.7 + TUI parity gaps

**Files:**
- Modify: `installer/v07/openclaw-install.sh`
- Modify: `installer/v07/lib/action.sh`
- Modify: `installer/v07/lib/ui.sh`
- Modify: `internal/app/app.go`
- Modify: `cmd/openclawctl/main.go`

**Step 1: v0.7 action parity**
- Add `adopt/persist/native/info` actions with minimal safe semantics.
- Add 1Panel interactive API/compose prompt for install in interactive mode.

**Step 2: Go TUI parity**
- Expose new actions in menu.
- Add forms + config writers for adopt/persist/native/info bridges.
- Extend install form/config to carry `SOFTWARE_SET/SKILL_SET`.

### Task 5: Verification and docs sync

**Files:**
- Modify: `README.md`
- Modify: `docs/rewrite-v0.7/gap-review-20260303.md`
- Modify: `docs/rewrite-v0.7/todo-gap-tracking.md`

**Step 1: Run tests**
- `bash -n openclawctl.sh`
- `bash tests/openclawctl_test.sh`
- `go test ./...`
- `bash tests/installer_v07_*_test.sh`

**Step 2: Update docs**
- Reflect completed gaps and retained intentional exception (Skill forced confirm).
