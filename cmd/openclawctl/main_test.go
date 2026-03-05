package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionOptionsIncludeExpectedFlows(t *testing.T) {
	t.Parallel()

	options := actionOptions()
	if len(options) != 11 {
		t.Fatalf("expected 11 action options, got %d", len(options))
	}
	if options[0].Key != "install" {
		t.Fatalf("expected first option to be install, got %q", options[0].Key)
	}
	if options[2].Key != "rebuild" {
		t.Fatalf("expected third option to be rebuild, got %q", options[2].Key)
	}
	if options[9].Key != "uninstall" {
		t.Fatalf("expected tenth option to be uninstall, got %q", options[9].Key)
	}
	if options[10].Key != "quit" {
		t.Fatalf("expected last option to be quit, got %q", options[10].Key)
	}
}

func TestWriteInstallConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := installConfig{
		SourceChoice:           "2",
		ChannelChoice:          "1",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4113",
		ContainerPort:          "18789",
		Name:                   "openclaw_demo",
		DataDir:                "/opt/1panel/apps/openclaw_demo",
		BindChoice:             "2",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "2",
		APTConfigPersistChoice: "2",
		CachePersistChoice:     "2",
		EasyChoice:             "1",
		TokenMode:              "2",
		TokenManual:            "token-123",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "5001:5001",
		SoftwareSet:            "gh codex",
		SkillSet:               "obsidian-skills security-checker",
	}

	path, err := writeInstallConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeInstallConfigFile returned error: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("expected config in %s, got %s", dir, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"IMAGE=ghcr.io/1186258278/openclaw-zh:latest",
		"NAME=openclaw_demo",
		"TOKEN_MANUAL=token-123",
		"TARGET_DEPS=npm uv",
		"SOFTWARE_SET=gh codex",
		"SKILL_SET=obsidian-skills security-checker",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteUpgradeConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := upgradeConfig{
		Name:                   "openclaw_up",
		SourceChoice:           "1",
		ChannelChoice:          "2",
		Image:                  "docker.io/1panel/openclaw:beta",
		HostPort:               "4222",
		ContainerPort:          "18789",
		DataDir:                "/opt/1panel/apps/openclaw_up",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "1",
		APTConfigPersistChoice: "1",
		CachePersistChoice:     "2",
		EasyChoice:             "1",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv go",
		ExtraPorts:             "6000:6000/udp",
	}

	path, err := writeUpgradeConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeUpgradeConfigFile returned error: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("expected config in %s, got %s", dir, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read upgrade config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"NAME=openclaw_up",
		"IMAGE=docker.io/1panel/openclaw:beta",
		"TARGET_DEPS=npm uv go",
		"EXTRA_PORTS=6000:6000/udp",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected upgrade config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteRebuildConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := rebuildConfig{
		Name:                   "openclaw_re",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4333",
		ContainerPort:          "18789",
		DataDir:                "/opt/1panel/apps/openclaw_re",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "1",
		APTConfigPersistChoice: "2",
		CachePersistChoice:     "1",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "4999:18090",
	}

	path, err := writeRebuildConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeRebuildConfigFile returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read rebuild config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"NAME=openclaw_re",
		"IMAGE=ghcr.io/1186258278/openclaw-zh:latest",
		"CACHE_PERSIST_CHOICE=1",
		"EXTRA_PORTS=4999:18090",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected rebuild config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteUninstallConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := uninstallConfig{
		Name:    "openclaw_del",
		Mode:    "2",
		DataDir: "/opt/1panel/apps/openclaw_del",
	}
	path, err := writeUninstallConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeUninstallConfigFile returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read uninstall config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"NAME=openclaw_del",
		"MODE=2",
		"DATA_DIR=/opt/1panel/apps/openclaw_del",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected uninstall config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteEasyClawConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := easyClawConfig{
		Name:    "openclaw_easy",
		DataDir: "/opt/1panel/apps/openclaw_easy",
	}
	path, err := writeEasyClawConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeEasyClawConfigFile returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read easyclaw config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"NAME=openclaw_easy",
		"DATA_DIR=/opt/1panel/apps/openclaw_easy",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected easyclaw config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteDepsConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := depsConfig{
		Name:       "openclaw_deps",
		DataDir:    "/opt/1panel/apps/openclaw_deps",
		Mode:       "check",
		TargetDeps: "npm uv go",
	}
	path, err := writeDepsConfigFile(dir, cfg)
	if err != nil {
		t.Fatalf("writeDepsConfigFile returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read deps config file: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"NAME=openclaw_deps",
		"MODE=check",
		"TARGET_DEPS=npm uv go",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected deps config file to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestDefaultDataRootPrefersEnvOverride(t *testing.T) {
	t.Setenv("OPENCLAWCTL_DATA_ROOT", "/tmp/openclaw-data-root")
	if got := defaultDataRoot(); got != "/tmp/openclaw-data-root" {
		t.Fatalf("expected env override root, got %q", got)
	}
}

func TestDefaultDataDirForName(t *testing.T) {
	t.Setenv("OPENCLAWCTL_DATA_ROOT", "/tmp/openclaw-data-root")
	if got := defaultDataDirForName("demo"); got != "/tmp/openclaw-data-root/demo" {
		t.Fatalf("unexpected default data dir: %q", got)
	}
}

func TestOfficialOpenclawRepoPathDefault(t *testing.T) {
	t.Setenv("OPENCLAW_OFFICIAL_REPO", "")
	if got := officialOpenclawRepoPath(); got != "1panel/openclaw" {
		t.Fatalf("expected default official repo, got %q", got)
	}
}

func TestOfficialOpenclawRepoPathSanitize(t *testing.T) {
	t.Setenv("OPENCLAW_OFFICIAL_REPO", "docker.io/1panel/openclaw")
	if got := officialOpenclawRepoPath(); got != "1panel/openclaw" {
		t.Fatalf("expected sanitized repo path, got %q", got)
	}
}

func TestOfficialOpenclawRepoPathFallbackForInvalidValue(t *testing.T) {
	t.Setenv("OPENCLAW_OFFICIAL_REPO", "openclaw")
	if got := officialOpenclawRepoPath(); got != "1panel/openclaw" {
		t.Fatalf("expected fallback repo path, got %q", got)
	}
}

func TestResolveImageChoiceUsesOfficialRepoOverride(t *testing.T) {
	t.Setenv("OPENCLAW_OFFICIAL_REPO", "1panel/openclaw")
	if got := resolveImageChoice("1", "2"); got != "docker.io/1panel/openclaw:beta" {
		t.Fatalf("unexpected official image: %q", got)
	}
}

func TestSelectedDepsSupportsRust(t *testing.T) {
	t.Parallel()

	if got := selectedDeps(true, true, false, true); got != "npm uv rust" {
		t.Fatalf("unexpected deps with rust: %q", got)
	}
	if got := selectedDeps(false, false, false, true); got != "rust" {
		t.Fatalf("unexpected rust-only deps: %q", got)
	}
}

func TestResolveInteractionModeFallsBackToShellWithoutTTY(t *testing.T) {
	t.Parallel()

	mode := resolveInteractionMode(false, true, "xterm-256color", "1")
	if mode != interactionModeShell {
		t.Fatalf("expected shell mode, got %v", mode)
	}
}

func TestResolveInteractionModeFallsBackToLegacyOnDumbTerm(t *testing.T) {
	t.Parallel()

	mode := resolveInteractionMode(true, true, "dumb", "1")
	if mode != interactionModeLegacyForm {
		t.Fatalf("expected legacy mode on dumb term, got %v", mode)
	}
}

func TestResolveInteractionModeUsesEnhancedOnCapableTerminal(t *testing.T) {
	t.Parallel()

	mode := resolveInteractionMode(true, true, "xterm-256color", "1")
	if mode != interactionModeEnhancedTUI {
		t.Fatalf("expected enhanced mode on capable term, got %v", mode)
	}
}

func TestResolveInteractionModeRespectsDisableFlag(t *testing.T) {
	t.Parallel()

	mode := resolveInteractionMode(true, true, "xterm-256color", "0")
	if mode != interactionModeLegacyForm {
		t.Fatalf("expected legacy mode when disabled, got %v", mode)
	}
}
