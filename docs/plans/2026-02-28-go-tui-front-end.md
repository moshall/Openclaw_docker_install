# Go TUI Front End Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a Bubble Tea + Huh front end that becomes the preferred interactive entrypoint while preserving the existing shell workflow as the execution backend and as the automatic fallback for non-TTY or missing-TUI environments.

**Architecture:** Keep `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/openclawctl.sh` as the authoritative execution layer. Add a Go binary under `cmd/openclawctl/` that handles TTY detection, renders the new main menu and initial flow routing, and delegates execution back to the shell script. The shell script becomes a hybrid launcher: interactive TTY sessions prefer the Go TUI when available, otherwise they continue with the existing shell UI. Non-TTY sessions always stay in shell mode.

**Tech Stack:** Go 1.21+, Bubble Tea, Huh, existing Bash execution layer, shell-based regression tests.

---

### Task 1: Add failing tests for launcher behavior

**Files:**
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh`

**Step 1: Write the failing test**
- Add a test that runs the shell script with a fake TUI binary path and verifies the launcher prefers that binary in interactive mode.
- Add a test that runs the script with piped stdin and verifies it stays in shell mode.

**Step 2: Run test to verify it fails**
Run: `bash "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"`
Expected: FAIL because launcher delegation behavior does not exist yet.

**Step 3: Write minimal implementation**
- Add wrapper logic in `openclawctl.sh` that can detect TTY, detect an override binary path, and choose between TUI and shell modes.

**Step 4: Run test to verify it passes**
Run: `bash "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"`
Expected: PASS

**Step 5: Commit**
```bash
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" add openclawctl.sh "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" commit -m "add TUI launcher fallback"
```

### Task 2: Add failing tests for Go CLI routing contract

**Files:**
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/go.mod`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/cmd/openclawctl/main_test.go`
- Create: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/internal/app/app_test.go`

**Step 1: Write the failing test**
- Test that non-TTY execution routes to shell fallback.
- Test that interactive execution renders the intent-based main menu and returns the selected action.
- Test that delegated shell invocations include the expected `--wizard` selector and preserve `--dry-run`.

**Step 2: Run test to verify it fails**
Run: `go test ./...`
Expected: FAIL because Go module and launcher code do not exist yet.

**Step 3: Write minimal implementation**
- Add a small `internal/app` package with environment probing and delegate command construction.
- Add `cmd/openclawctl/main.go` with TTY detection and initial Bubble Tea/Huh menu.

**Step 4: Run test to verify it passes**
Run: `go test ./...`
Expected: PASS

**Step 5: Commit**
```bash
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" add go.mod go.sum cmd/openclawctl internal/app
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" commit -m "add Go TUI launcher skeleton"
```

### Task 3: Extend shell backend with delegated wizard entrypoints

**Files:**
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/openclawctl.sh`
- Test: `/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh`

**Step 1: Write the failing test**
- Add tests for `--wizard install|upgrade|rebuild|easyclaw|deps|uninstall`.
- Ensure each selector opens the expected shell flow directly and rejects invalid wizard names.

**Step 2: Run test to verify it fails**
Run: `bash "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"`
Expected: FAIL because `--wizard` is not supported.

**Step 3: Write minimal implementation**
- Extend global flag parsing with `--wizard` and a shell-only execution path.
- Reuse existing wizard functions without rewriting their internals.

**Step 4: Run test to verify it passes**
Run: `bash "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"`
Expected: PASS

**Step 5: Commit**
```bash
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" add openclawctl.sh "/Users/edy/Downloads/项目开发测试/openclaw docker/tests/openclawctl_test.sh"
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" commit -m "add shell wizard entrypoints"
```

### Task 4: Document build and runtime behavior

**Files:**
- Modify: `/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/README.md`

**Step 1: Write the failing test**
- Manual verification only: identify missing README sections for TUI usage, fallback behavior, and source-vs-binary execution.

**Step 2: Run verification to confirm the gap**
- Read current README and confirm it does not explain the Go TUI front end.

**Step 3: Write minimal implementation**
- Add sections for preferred entrypoint, non-TTY fallback, Go source build, and release binary usage.

**Step 4: Run verification to confirm it passes**
Run: `rg -n "Go TUI|非 TTY|fallback|Bubble Tea|Huh" "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install/README.md"`
Expected: matching lines present.

**Step 5: Commit**
```bash
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" add README.md
git -C "/Users/edy/Downloads/项目开发测试/openclaw docker/Openclaw_docker_install" commit -m "document Go TUI entrypoint"
```
