package tui

import "testing"

func TestDetectColorProfile(t *testing.T) {
	t.Parallel()

	if got := DetectColorProfile("xterm-256color", "truecolor"); got != ColorProfileTrueColor {
		t.Fatalf("expected truecolor profile, got %q", got)
	}
	if got := DetectColorProfile("xterm-256color", ""); got != ColorProfileANSI256 {
		t.Fatalf("expected 256 profile, got %q", got)
	}
	if got := DetectColorProfile("linux", ""); got != ColorProfileANSI16 {
		t.Fatalf("expected ansi16 profile, got %q", got)
	}
}

func TestLayoutViewIncludesCoreRegions(t *testing.T) {
	t.Parallel()

	model := NewLayoutModel(
		[]Action{
			{Key: "install", Label: "🚀 安装新实例", Description: "创建新的 OpenClaw 实例"},
			{Key: "upgrade", Label: "🔄 升级已有实例", Description: "安全升级并保留数据"},
		},
		ColorProfileTrueColor,
	)
	model.SelectedAction = 0
	model.Status = "ready"
	model.PreviewLines = []string{"bash openclawctl.sh --wizard install --dry-run"}
	model.RightTitle = "安装配置"
	model.RightBodyLines = []string{"镜像: ghcr.io/1186258278/openclaw-zh:latest"}

	view := model.View(120, 32)
	for _, needle := range []string{
		"OpenClaw Control Center",
		"操作菜单",
		"安装配置",
		"命令预览",
		"bash openclawctl.sh --wizard install --dry-run",
	} {
		if !contains(view, needle) {
			t.Fatalf("expected view to contain %q, got:\n%s", needle, view)
		}
	}
}

func TestLayoutViewMarksSelectedAction(t *testing.T) {
	t.Parallel()

	model := NewLayoutModel(
		[]Action{
			{Key: "install", Label: "🚀 安装新实例"},
			{Key: "upgrade", Label: "🔄 升级已有实例"},
		},
		ColorProfileANSI16,
	)
	model.SelectedAction = 1
	view := model.View(100, 28)

	if !contains(view, "▶ 🔄 升级已有实例") {
		t.Fatalf("expected selected action marker, got:\n%s", view)
	}
}

func TestThemeUsesTerminalDefaultForegroundForBodyText(t *testing.T) {
	t.Parallel()

	theme := newTheme(ColorProfileTrueColor)
	if got := theme.menuNormal.Render("sample"); got != "sample" {
		t.Fatalf("expected menu normal render without forced color, got %q", got)
	}
	if got := theme.contentText.Render("sample"); got != "sample" {
		t.Fatalf("expected content text render without forced color, got %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && stringContains(haystack, needle))
}

func stringContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
