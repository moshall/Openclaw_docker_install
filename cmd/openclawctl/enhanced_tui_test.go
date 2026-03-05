package main

import (
	"os"
	"strings"
	"testing"
)

func TestBuildEnhancedFormsCoverCoreActions(t *testing.T) {
	t.Parallel()

	forms := buildEnhancedForms()
	for _, key := range []string{"install", "upgrade", "rebuild", "deps", "native", "uninstall", "info"} {
		if _, ok := forms[key]; !ok {
			t.Fatalf("expected enhanced forms to include %q", key)
		}
	}
}

func TestWriteConfigForEnhancedActionInstall(t *testing.T) {
	t.Parallel()

	cfgPath, err := writeConfigForEnhancedAction(t.TempDir(), enhancedSubmission{
		Action: "install",
		Values: map[string]string{
			"source":          "中文版",
			"channel":         "稳定版",
			"name":            "openclaw_enhanced",
			"data_dir":        "/opt/1panel/apps/openclaw_enhanced",
			"bind":            "lan",
			"host_port":       "5222",
			"container_port":  "18789",
			"bin_persist":     "1",
			"env_persist":     "2",
			"apt_persist":     "2",
			"cache_persist":   "2",
			"easy":            "1",
			"deps_install":    "1",
			"target_deps":     "npm uv",
			"token_mode":      "手动输入",
			"token_manual":    "abc123",
			"extra_ports":     "6000:6000/udp",
			"software_set":    "gh codex",
			"skill_set":       "obsidian-skills",
		},
	})
	if err != nil {
		t.Fatalf("writeConfigForEnhancedAction returned error: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}
	content := string(data)
	for _, needle := range []string{
		"IMAGE=ghcr.io/1186258278/openclaw-zh:latest",
		"NAME=openclaw_enhanced",
		"TOKEN_MODE=2",
		"TOKEN_MANUAL=abc123",
		"EXTRA_PORTS=6000:6000/udp",
		"SOFTWARE_SET=gh codex",
		"SKILL_SET=obsidian-skills",
	} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected generated config to contain %q, got:\n%s", needle, content)
		}
	}
}

func TestWriteConfigForEnhancedActionInfoSkipsConfigFile(t *testing.T) {
	t.Parallel()

	cfgPath, err := writeConfigForEnhancedAction(t.TempDir(), enhancedSubmission{
		Action: "info",
		Values: map[string]string{},
	})
	if err != nil {
		t.Fatalf("expected no error for info action, got: %v", err)
	}
	if cfgPath != "" {
		t.Fatalf("expected empty config path for info action, got %q", cfgPath)
	}
}

