package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/moshall/Openclaw_docker_install/internal/app"
)

type actionOption struct {
	Key         string
	Label       string
	Description string
}

type installConfig struct {
	SourceChoice           string
	ChannelChoice          string
	Image                  string
	HostPort               string
	ContainerPort          string
	Name                   string
	DataDir                string
	BindChoice             string
	BinPersistChoice       string
	EnvPersistChoice       string
	APTConfigPersistChoice string
	CachePersistChoice     string
	EasyChoice             string
	TokenMode              string
	TokenManual            string
	DepsInstallChoice      string
	TargetDeps             string
	ExtraPorts             string
	SoftwareSet            string
	SkillSet               string
}

type upgradeConfig struct {
	Name                   string
	SourceChoice           string
	ChannelChoice          string
	Image                  string
	HostPort               string
	ContainerPort          string
	DataDir                string
	BinPersistChoice       string
	EnvPersistChoice       string
	APTConfigPersistChoice string
	CachePersistChoice     string
	EasyChoice             string
	DepsInstallChoice      string
	TargetDeps             string
	ExtraPorts             string
}

type rebuildConfig struct {
	Name                   string
	Image                  string
	HostPort               string
	ContainerPort          string
	DataDir                string
	BinPersistChoice       string
	EnvPersistChoice       string
	APTConfigPersistChoice string
	CachePersistChoice     string
	DepsInstallChoice      string
	TargetDeps             string
	ExtraPorts             string
}

type uninstallConfig struct {
	Name    string
	Mode    string
	DataDir string
}

type easyClawConfig struct {
	Name    string
	DataDir string
}

type depsConfig struct {
	Name       string
	DataDir    string
	Mode       string
	TargetDeps string
}

type adoptConfig struct {
	Name string
}

type persistConfig struct {
	Name                   string
	Image                  string
	HostPort               string
	ContainerPort          string
	DataDir                string
	BinPersistChoice       string
	EnvPersistChoice       string
	APTConfigPersistChoice string
	CachePersistChoice     string
	DepsInstallChoice      string
	TargetDeps             string
	ExtraPorts             string
}

type nativeConfig struct {
	SourceChoice  string
	ChannelChoice string
	OfficialTag   string
	Name          string
	DataDir       string
	NativePrefix  string
	SoftwareSet   string
	SkillSet      string
}

type interactionMode int

const (
	interactionModeShell interactionMode = iota
	interactionModeLegacyForm
	interactionModeEnhancedTUI
)

const officialOpenclawRepoDefault = "1panel/openclaw"

func actionOptions() []actionOption {
	options := app.ActionOptions()
	out := make([]actionOption, 0, len(options))
	for _, option := range options {
		out = append(out, actionOption{
			Key:         option.Key,
			Label:       option.Label,
			Description: option.Description,
		})
	}
	return out
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("openclawctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	shellScript := defaultShellScriptPath()
	dryRun := false
	fs.StringVar(&shellScript, "shell-script", shellScript, "path to openclawctl.sh")
	fs.BoolVar(&dryRun, "dry-run", false, "preview commands without executing them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if shellScript == "" {
		fmt.Fprintln(os.Stderr, "未找到 shell 执行入口，请通过 --shell-script 指定 openclawctl.sh")
		return 1
	}

	mode := resolveInteractionMode(
		stdinIsTTY(),
		stdoutIsTTY(),
		os.Getenv("TERM"),
		os.Getenv("OPENCLAWCTL_ENHANCED_TUI"),
	)
	if mode == interactionModeShell {
		return execShell(shellScript, "", dryRun, "")
	}
	if mode == interactionModeEnhancedTUI {
		submission, err := runEnhancedSubmission(dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "增强 TUI 启动失败，回退标准表单: %v\n", err)
		} else {
			if submission.Action == "quit" {
				return 0
			}
			cfgPath, cfgErr := writeConfigForEnhancedAction(os.TempDir(), submission)
			if cfgErr != nil {
				fmt.Fprintf(os.Stderr, "增强 TUI 配置生成失败: %v\n", cfgErr)
				return 1
			}
			if cfgPath != "" {
				defer os.Remove(cfgPath)
			}
			return execShell(shellScript, submission.Action, dryRun, cfgPath)
		}
	}

	action, err := promptAction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TUI 交互失败: %v\n", err)
		return 1
	}
	if action == "quit" {
		return 0
	}
	if action == "install" {
		cfg, err := promptInstallConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "安装表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeInstallConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入安装配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "upgrade" {
		cfg, err := promptUpgradeConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "升级表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeUpgradeConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入升级配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "rebuild" {
		cfg, err := promptRebuildConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "重建表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeRebuildConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入重建配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "uninstall" {
		cfg, err := promptUninstallConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "卸载表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeUninstallConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入卸载配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "easyclaw" {
		cfg, err := promptEasyClawConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "EasyClaw 表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeEasyClawConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入 EasyClaw 配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "deps" {
		cfg, err := promptDepsConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "依赖管理表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeDepsConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入依赖配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "adopt" {
		cfg, err := promptAdoptConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "接管表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeAdoptConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入接管配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "persist" {
		cfg, err := promptPersistConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "持久化重建表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writePersistConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入持久化重建配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "native" {
		cfg, err := promptNativeConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "原生 npm 表单失败: %v\n", err)
			return 1
		}
		cfgPath, err := writeNativeConfigFile(os.TempDir(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "写入原生 npm 配置失败: %v\n", err)
			return 1
		}
		defer os.Remove(cfgPath)
		return execShell(shellScript, action, dryRun, cfgPath)
	}
	if action == "info" {
		return execShell(shellScript, action, dryRun, "")
	}

	return execShell(shellScript, action, dryRun, "")
}

func resolveInteractionMode(stdinTTY, stdoutTTY bool, termName, enhancedFlag string) interactionMode {
	if app.ShouldFallbackToShell(stdinTTY, stdoutTTY) {
		return interactionModeShell
	}
	if strings.TrimSpace(enhancedFlag) == "0" {
		return interactionModeLegacyForm
	}
	if !terminalSupportsEnhancedTUI(termName) {
		return interactionModeLegacyForm
	}
	return interactionModeEnhancedTUI
}

func terminalSupportsEnhancedTUI(termName string) bool {
	term := strings.ToLower(strings.TrimSpace(termName))
	return term != "" && term != "dumb"
}

func defaultShellScriptPath() string {
	if exePath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exePath), "openclawctl.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "openclawctl.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func defaultDataRoot() string {
	if envRoot := strings.TrimSpace(os.Getenv("OPENCLAWCTL_DATA_ROOT")); envRoot != "" {
		return envRoot
	}
	if _, err := os.Stat("/opt/1panel/apps"); err == nil {
		return "/opt/1panel/apps"
	}
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, ".openclaw", "apps")
		}
		return "/opt/1panel/apps"
	case "linux":
		return "/opt/openclaw/apps"
	default:
		return "/opt/1panel/apps"
	}
}

func defaultDataDirForName(name string) string {
	return filepath.Join(defaultDataRoot(), name)
}

func defaultDataDirHint() string {
	return fmt.Sprintf("持久化目录（留空自动使用 %s/<容器名>）", defaultDataRoot())
}

func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func stdoutIsTTY() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func promptAction() (string, error) {
	selected := "install"
	options := make([]huh.Option[string], 0, len(actionOptions()))
	for _, option := range actionOptions() {
		options = append(options, huh.NewOption(option.Label+" · "+option.Description, option.Key))
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("OpenClaw 部署助手").
				Description("选择要执行的操作，非交互环境会自动回退到 shell 模式。").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return "", err
	}
	return selected, nil
}

func promptInstallConfig() (installConfig, error) {
	cfg := installConfig{
		SourceChoice:           "2",
		ChannelChoice:          "1",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4113",
		ContainerPort:          "18789",
		Name:                   "openclaw_demo",
		DataDir:                "",
		BindChoice:             "2",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "2",
		APTConfigPersistChoice: "2",
		CachePersistChoice:     "2",
		EasyChoice:             "1",
		TokenMode:              "1",
		TokenManual:            "",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "",
		SoftwareSet:            "",
		SkillSet:               "",
	}

	source := "中文版"
	channel := "稳定版"
	bind := "lan"
	binPersist := true
	envPersist := false
	aptPersist := false
	cachePersist := false
	easy := true
	depsRepair := true
	npmEnabled := true
	uvEnabled := true
	goEnabled := false
	rustEnabled := false
	tokenMode := "自动生成"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("版本来源").Options(
				huh.NewOption("官方", "官方"),
				huh.NewOption("中文版", "中文版"),
			).Value(&source),
			huh.NewSelect[string]().Title("版本通道").Options(
				huh.NewOption("稳定版", "稳定版"),
				huh.NewOption("最新版", "最新版"),
			).Value(&channel),
			huh.NewInput().Title("Docker 容器名").Value(&cfg.Name),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("网络绑定").Options(
				huh.NewOption("local", "local"),
				huh.NewOption("lan", "lan"),
			).Value(&bind),
			huh.NewInput().Title("宿主机端口").Value(&cfg.HostPort),
			huh.NewInput().Title("OpenClaw 容器内部端口").Value(&cfg.ContainerPort),
			huh.NewInput().Title("扩展端口映射（可留空，如 5001:5001,6000:6000/udp）").Value(&cfg.ExtraPorts),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("保留命令入口（bin）").Value(&binPersist),
			huh.NewConfirm().Title("保留运行环境（env）").Value(&envPersist),
			huh.NewConfirm().Title("保留 APT 源/Key").Value(&aptPersist),
			huh.NewConfirm().Title("保留缓存（.npm/go mod/cargo）").Value(&cachePersist),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("安装 EasyClaw").Value(&easy),
			huh.NewConfirm().Title("升级后自动补齐依赖").Value(&depsRepair),
			huh.NewConfirm().Title("包含 npm").Value(&npmEnabled),
			huh.NewConfirm().Title("包含 uv").Value(&uvEnabled),
			huh.NewConfirm().Title("包含 go").Value(&goEnabled),
			huh.NewConfirm().Title("包含 rust").Value(&rustEnabled),
		),
		huh.NewGroup(
			huh.NewInput().Title("可选软件（逗号或空格分隔，如 gh,codex）").Value(&cfg.SoftwareSet),
			huh.NewInput().Title("预装 Skills（逗号或空格分隔，如 obsidian-skills）").Value(&cfg.SkillSet),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Token 方式").Options(
				huh.NewOption("自动生成", "自动生成"),
				huh.NewOption("手动输入", "手动输入"),
			).Value(&tokenMode),
			huh.NewInput().Title("手动 Token（仅在上一步选择手动输入时填写）").Value(&cfg.TokenManual),
		),
	)

	if err := form.Run(); err != nil {
		return installConfig{}, err
	}

	cfg.SourceChoice = mapSourceChoice(source)
	cfg.ChannelChoice = mapChannelChoice(channel)
	cfg.Image = resolveImageChoice(cfg.SourceChoice, cfg.ChannelChoice)
	cfg.BindChoice = mapBindChoice(bind)
	cfg.BinPersistChoice = boolToChoice(binPersist)
	cfg.EnvPersistChoice = boolToChoice(envPersist)
	cfg.APTConfigPersistChoice = boolToChoice(aptPersist)
	cfg.CachePersistChoice = boolToChoice(cachePersist)
	cfg.EasyChoice = boolToChoice(easy)
	cfg.DepsInstallChoice = boolToChoice(depsRepair)
	cfg.TokenMode = mapTokenMode(tokenMode)
	cfg.TargetDeps = selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled)

	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func promptUpgradeConfig() (upgradeConfig, error) {
	cfg := upgradeConfig{
		Name:                   "openclaw_demo",
		SourceChoice:           "2",
		ChannelChoice:          "1",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4113",
		ContainerPort:          "18789",
		DataDir:                "",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "2",
		APTConfigPersistChoice: "2",
		CachePersistChoice:     "2",
		EasyChoice:             "1",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "",
	}

	source := "中文版"
	channel := "稳定版"
	binPersist := true
	envPersist := false
	aptPersist := false
	cachePersist := false
	easy := true
	depsRepair := true
	npmEnabled := true
	uvEnabled := true
	goEnabled := false
	rustEnabled := false

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("要升级的容器名").Value(&cfg.Name),
			huh.NewSelect[string]().Title("目标版本来源").Options(
				huh.NewOption("官方", "官方"),
				huh.NewOption("中文版", "中文版"),
			).Value(&source),
			huh.NewSelect[string]().Title("目标版本通道").Options(
				huh.NewOption("稳定版", "稳定版"),
				huh.NewOption("最新版", "最新版"),
			).Value(&channel),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
		huh.NewGroup(
			huh.NewInput().Title("宿主机端口").Value(&cfg.HostPort),
			huh.NewInput().Title("OpenClaw 容器内部端口").Value(&cfg.ContainerPort),
			huh.NewInput().Title("扩展端口映射（可留空，如 5001:5001,6000:6000/udp）").Value(&cfg.ExtraPorts),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("保留命令入口（bin）").Value(&binPersist),
			huh.NewConfirm().Title("保留运行环境（env）").Value(&envPersist),
			huh.NewConfirm().Title("保留 APT 源/Key").Value(&aptPersist),
			huh.NewConfirm().Title("保留缓存（.npm/go mod/cargo）").Value(&cachePersist),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("检查并升级 EasyClaw").Value(&easy),
			huh.NewConfirm().Title("升级后自动补齐依赖").Value(&depsRepair),
			huh.NewConfirm().Title("包含 npm").Value(&npmEnabled),
			huh.NewConfirm().Title("包含 uv").Value(&uvEnabled),
			huh.NewConfirm().Title("包含 go").Value(&goEnabled),
			huh.NewConfirm().Title("包含 rust").Value(&rustEnabled),
		),
	)

	if err := form.Run(); err != nil {
		return upgradeConfig{}, err
	}

	cfg.SourceChoice = mapSourceChoice(source)
	cfg.ChannelChoice = mapChannelChoice(channel)
	cfg.Image = resolveImageChoice(cfg.SourceChoice, cfg.ChannelChoice)
	cfg.BinPersistChoice = boolToChoice(binPersist)
	cfg.EnvPersistChoice = boolToChoice(envPersist)
	cfg.APTConfigPersistChoice = boolToChoice(aptPersist)
	cfg.CachePersistChoice = boolToChoice(cachePersist)
	cfg.EasyChoice = boolToChoice(easy)
	cfg.DepsInstallChoice = boolToChoice(depsRepair)
	cfg.TargetDeps = selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled)
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writeInstallConfigFile(dir string, cfg installConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-install-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()

	lines := []string{
		"SOURCE_CHOICE=" + cfg.SourceChoice,
		"CHANNEL_CHOICE=" + cfg.ChannelChoice,
		"IMAGE=" + cfg.Image,
		"HOST_PORT=" + cfg.HostPort,
		"CONTAINER_PORT=" + cfg.ContainerPort,
		"NAME=" + cfg.Name,
		"DATA_DIR=" + cfg.DataDir,
		"BIND_CHOICE=" + cfg.BindChoice,
		"BIN_PERSIST_CHOICE=" + cfg.BinPersistChoice,
		"ENV_PERSIST_CHOICE=" + cfg.EnvPersistChoice,
		"APT_CFG_PERSIST_CHOICE=" + cfg.APTConfigPersistChoice,
		"CACHE_PERSIST_CHOICE=" + cfg.CachePersistChoice,
		"EASY_CHOICE=" + cfg.EasyChoice,
		"TOKEN_MODE=" + cfg.TokenMode,
		"TOKEN_MANUAL=" + cfg.TokenManual,
		"DEPS_INSTALL_CHOICE=" + cfg.DepsInstallChoice,
		"TARGET_DEPS=" + cfg.TargetDeps,
		"SOFTWARE_SET=" + cfg.SoftwareSet,
		"SKILL_SET=" + cfg.SkillSet,
		"EXTRA_PORTS=" + cfg.ExtraPorts,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func writeUpgradeConfigFile(dir string, cfg upgradeConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-upgrade-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()

	lines := []string{
		"NAME=" + cfg.Name,
		"SOURCE_CHOICE=" + cfg.SourceChoice,
		"CHANNEL_CHOICE=" + cfg.ChannelChoice,
		"IMAGE=" + cfg.Image,
		"HOST_PORT=" + cfg.HostPort,
		"CONTAINER_PORT=" + cfg.ContainerPort,
		"DATA_DIR=" + cfg.DataDir,
		"BIN_PERSIST_CHOICE=" + cfg.BinPersistChoice,
		"ENV_PERSIST_CHOICE=" + cfg.EnvPersistChoice,
		"APT_CFG_PERSIST_CHOICE=" + cfg.APTConfigPersistChoice,
		"CACHE_PERSIST_CHOICE=" + cfg.CachePersistChoice,
		"EASY_CHOICE=" + cfg.EasyChoice,
		"DEPS_INSTALL_CHOICE=" + cfg.DepsInstallChoice,
		"TARGET_DEPS=" + cfg.TargetDeps,
		"EXTRA_PORTS=" + cfg.ExtraPorts,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptRebuildConfig() (rebuildConfig, error) {
	cfg := rebuildConfig{
		Name:                   "openclaw_demo",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4113",
		ContainerPort:          "18789",
		DataDir:                "",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "2",
		APTConfigPersistChoice: "2",
		CachePersistChoice:     "2",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "",
	}

	binPersist := true
	envPersist := false
	aptPersist := false
	cachePersist := false
	depsRepair := true
	npmEnabled := true
	uvEnabled := true
	goEnabled := false
	rustEnabled := false

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("要重建的容器名").Value(&cfg.Name),
			huh.NewInput().Title("目标镜像（默认复用当前镜像，可直接修改）").Value(&cfg.Image),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
		huh.NewGroup(
			huh.NewInput().Title("宿主机端口").Value(&cfg.HostPort),
			huh.NewInput().Title("OpenClaw 容器内部端口").Value(&cfg.ContainerPort),
			huh.NewInput().Title("扩展端口映射（可留空，如 5001:5001,6000:6000/udp）").Value(&cfg.ExtraPorts),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("保留命令入口（bin）").Value(&binPersist),
			huh.NewConfirm().Title("保留运行环境（env）").Value(&envPersist),
			huh.NewConfirm().Title("保留 APT 源/Key").Value(&aptPersist),
			huh.NewConfirm().Title("保留缓存（.npm/go mod/cargo）").Value(&cachePersist),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("重建后自动补齐依赖").Value(&depsRepair),
			huh.NewConfirm().Title("包含 npm").Value(&npmEnabled),
			huh.NewConfirm().Title("包含 uv").Value(&uvEnabled),
			huh.NewConfirm().Title("包含 go").Value(&goEnabled),
			huh.NewConfirm().Title("包含 rust").Value(&rustEnabled),
		),
	)

	if err := form.Run(); err != nil {
		return rebuildConfig{}, err
	}

	cfg.BinPersistChoice = boolToChoice(binPersist)
	cfg.EnvPersistChoice = boolToChoice(envPersist)
	cfg.APTConfigPersistChoice = boolToChoice(aptPersist)
	cfg.CachePersistChoice = boolToChoice(cachePersist)
	cfg.DepsInstallChoice = boolToChoice(depsRepair)
	cfg.TargetDeps = selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled)
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writeRebuildConfigFile(dir string, cfg rebuildConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-rebuild-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()

	lines := []string{
		"NAME=" + cfg.Name,
		"IMAGE=" + cfg.Image,
		"HOST_PORT=" + cfg.HostPort,
		"CONTAINER_PORT=" + cfg.ContainerPort,
		"DATA_DIR=" + cfg.DataDir,
		"BIN_PERSIST_CHOICE=" + cfg.BinPersistChoice,
		"ENV_PERSIST_CHOICE=" + cfg.EnvPersistChoice,
		"APT_CFG_PERSIST_CHOICE=" + cfg.APTConfigPersistChoice,
		"CACHE_PERSIST_CHOICE=" + cfg.CachePersistChoice,
		"DEPS_INSTALL_CHOICE=" + cfg.DepsInstallChoice,
		"TARGET_DEPS=" + cfg.TargetDeps,
		"EXTRA_PORTS=" + cfg.ExtraPorts,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptUninstallConfig() (uninstallConfig, error) {
	cfg := uninstallConfig{
		Name:    "openclaw_demo",
		Mode:    "1",
		DataDir: "",
	}
	mode := "安全卸载"
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("要卸载的容器名").Value(&cfg.Name),
			huh.NewSelect[string]().Title("卸载方式").Options(
				huh.NewOption("安全卸载（仅删容器）", "安全卸载"),
				huh.NewOption("完整卸载（删容器+删目录）", "完整卸载"),
			).Value(&mode),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
	)
	if err := form.Run(); err != nil {
		return uninstallConfig{}, err
	}
	if mode == "完整卸载" {
		cfg.Mode = "2"
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writeUninstallConfigFile(dir string, cfg uninstallConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-uninstall-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"NAME=" + cfg.Name,
		"MODE=" + cfg.Mode,
		"DATA_DIR=" + cfg.DataDir,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptEasyClawConfig() (easyClawConfig, error) {
	cfg := easyClawConfig{
		Name:    "openclaw_demo",
		DataDir: "",
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("容器名（用于定位 EasyClaw）").Value(&cfg.Name),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
	)
	if err := form.Run(); err != nil {
		return easyClawConfig{}, err
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writeEasyClawConfigFile(dir string, cfg easyClawConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-easyclaw-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"NAME=" + cfg.Name,
		"DATA_DIR=" + cfg.DataDir,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptDepsConfig() (depsConfig, error) {
	cfg := depsConfig{
		Name:       "openclaw_demo",
		DataDir:    "",
		Mode:       "install",
		TargetDeps: "npm uv",
	}
	mode := "检测并安装"
	npmEnabled := true
	uvEnabled := true
	goEnabled := false
	rustEnabled := false
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("容器名").Value(&cfg.Name),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
			huh.NewSelect[string]().Title("执行模式").Options(
				huh.NewOption("检测并安装缺失项", "检测并安装"),
				huh.NewOption("仅检测，不安装", "仅检测"),
			).Value(&mode),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("包含 npm").Value(&npmEnabled),
			huh.NewConfirm().Title("包含 uv").Value(&uvEnabled),
			huh.NewConfirm().Title("包含 go").Value(&goEnabled),
			huh.NewConfirm().Title("包含 rust").Value(&rustEnabled),
		),
	)
	if err := form.Run(); err != nil {
		return depsConfig{}, err
	}
	if mode == "仅检测" {
		cfg.Mode = "check"
	}
	cfg.TargetDeps = selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled)
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writeDepsConfigFile(dir string, cfg depsConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-deps-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"NAME=" + cfg.Name,
		"DATA_DIR=" + cfg.DataDir,
		"MODE=" + cfg.Mode,
		"TARGET_DEPS=" + cfg.TargetDeps,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptAdoptConfig() (adoptConfig, error) {
	cfg := adoptConfig{
		Name: "openclaw_demo",
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("要接管的容器名").Value(&cfg.Name),
		),
	)
	if err := form.Run(); err != nil {
		return adoptConfig{}, err
	}
	return cfg, nil
}

func writeAdoptConfigFile(dir string, cfg adoptConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-adopt-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"NAME=" + cfg.Name,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptPersistConfig() (persistConfig, error) {
	cfg := persistConfig{
		Name:                   "openclaw_demo",
		Image:                  "ghcr.io/1186258278/openclaw-zh:latest",
		HostPort:               "4113",
		ContainerPort:          "18789",
		DataDir:                "",
		BinPersistChoice:       "1",
		EnvPersistChoice:       "1",
		APTConfigPersistChoice: "1",
		CachePersistChoice:     "1",
		DepsInstallChoice:      "1",
		TargetDeps:             "npm uv",
		ExtraPorts:             "",
	}

	npmEnabled := true
	uvEnabled := true
	goEnabled := false
	rustEnabled := false
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("要追加持久化的容器名").Value(&cfg.Name),
			huh.NewInput().Title("目标镜像（默认复用）").Value(&cfg.Image),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
		),
		huh.NewGroup(
			huh.NewInput().Title("宿主机端口").Value(&cfg.HostPort),
			huh.NewInput().Title("OpenClaw 容器内部端口").Value(&cfg.ContainerPort),
			huh.NewInput().Title("扩展端口映射（可留空，如 5001:5001,6000:6000/udp）").Value(&cfg.ExtraPorts),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("包含 npm").Value(&npmEnabled),
			huh.NewConfirm().Title("包含 uv").Value(&uvEnabled),
			huh.NewConfirm().Title("包含 go").Value(&goEnabled),
			huh.NewConfirm().Title("包含 rust").Value(&rustEnabled),
		),
	)
	if err := form.Run(); err != nil {
		return persistConfig{}, err
	}
	cfg.TargetDeps = selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled)
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	return cfg, nil
}

func writePersistConfigFile(dir string, cfg persistConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-persist-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"NAME=" + cfg.Name,
		"IMAGE=" + cfg.Image,
		"HOST_PORT=" + cfg.HostPort,
		"CONTAINER_PORT=" + cfg.ContainerPort,
		"DATA_DIR=" + cfg.DataDir,
		"BIN_PERSIST_CHOICE=" + cfg.BinPersistChoice,
		"ENV_PERSIST_CHOICE=" + cfg.EnvPersistChoice,
		"APT_CFG_PERSIST_CHOICE=" + cfg.APTConfigPersistChoice,
		"CACHE_PERSIST_CHOICE=" + cfg.CachePersistChoice,
		"DEPS_INSTALL_CHOICE=" + cfg.DepsInstallChoice,
		"TARGET_DEPS=" + cfg.TargetDeps,
		"EXTRA_PORTS=" + cfg.ExtraPorts,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func promptNativeConfig() (nativeConfig, error) {
	cfg := nativeConfig{
		SourceChoice:  "2",
		ChannelChoice: "1",
		OfficialTag:   "",
		Name:          "openclaw_native",
		DataDir:       "",
		NativePrefix:  "",
		SoftwareSet:   "",
		SkillSet:      "",
	}

	source := "中文版"
	channel := "稳定版"
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("版本来源").Options(
				huh.NewOption("官方 npm(openclaw)", "官方"),
				huh.NewOption("中文版 npm(@qingchencloud/openclaw-zh)", "中文版"),
			).Value(&source),
			huh.NewSelect[string]().Title("版本通道").Options(
				huh.NewOption("稳定版", "稳定版"),
				huh.NewOption("最新版", "最新版"),
			).Value(&channel),
			huh.NewInput().Title("可选指定 tag（留空按通道）").Value(&cfg.OfficialTag),
		),
		huh.NewGroup(
			huh.NewInput().Title("应用名（用于配置记录）").Value(&cfg.Name),
			huh.NewInput().Title(defaultDataDirHint()).Value(&cfg.DataDir),
			huh.NewInput().Title("npm 安装前缀目录（留空自动用 <data_dir>/native）").Value(&cfg.NativePrefix),
			huh.NewInput().Title("可选软件（逗号或空格分隔，如 gh,codex）").Value(&cfg.SoftwareSet),
			huh.NewInput().Title("预装 Skills（逗号或空格分隔，如 obsidian-skills）").Value(&cfg.SkillSet),
		),
	)
	if err := form.Run(); err != nil {
		return nativeConfig{}, err
	}
	cfg.SourceChoice = mapSourceChoice(source)
	cfg.ChannelChoice = mapChannelChoice(channel)
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDirForName(cfg.Name)
	}
	if strings.TrimSpace(cfg.NativePrefix) == "" {
		cfg.NativePrefix = filepath.Join(cfg.DataDir, "native")
	}
	return cfg, nil
}

func writeNativeConfigFile(dir string, cfg nativeConfig) (string, error) {
	file, err := os.CreateTemp(dir, "openclawctl-native-*.cfg")
	if err != nil {
		return "", err
	}
	defer file.Close()
	lines := []string{
		"SOURCE_CHOICE=" + cfg.SourceChoice,
		"CHANNEL_CHOICE=" + cfg.ChannelChoice,
		"OFFICIAL_TAG=" + cfg.OfficialTag,
		"NAME=" + cfg.Name,
		"DATA_DIR=" + cfg.DataDir,
		"NATIVE_PREFIX=" + cfg.NativePrefix,
		"SOFTWARE_SET=" + cfg.SoftwareSet,
		"SKILL_SET=" + cfg.SkillSet,
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func officialOpenclawRepoPath() string {
	repo := strings.TrimSpace(os.Getenv("OPENCLAW_OFFICIAL_REPO"))
	if repo == "" {
		repo = officialOpenclawRepoDefault
	}
	repo = strings.TrimPrefix(repo, "docker.io/")
	repo = strings.TrimPrefix(repo, "/")
	if !strings.Contains(repo, "/") {
		repo = officialOpenclawRepoDefault
	}
	return repo
}

func officialOpenclawImage(tag string) string {
	return "docker.io/" + officialOpenclawRepoPath() + ":" + tag
}

func resolveImageChoice(sourceChoice, channelChoice string) string {
	switch {
	case sourceChoice == "1" && channelChoice == "1":
		return officialOpenclawImage("latest")
	case sourceChoice == "1" && channelChoice == "2":
		return officialOpenclawImage("beta")
	case sourceChoice == "2" && channelChoice == "1":
		return "ghcr.io/1186258278/openclaw-zh:latest"
	case sourceChoice == "2" && channelChoice == "2":
		return "ghcr.io/1186258278/openclaw-zh:nightly"
	default:
		return ""
	}
}

func mapSourceChoice(source string) string {
	if source == "官方" {
		return "1"
	}
	return "2"
}

func mapChannelChoice(channel string) string {
	if channel == "最新版" {
		return "2"
	}
	return "1"
}

func mapBindChoice(bind string) string {
	if bind == "local" {
		return "1"
	}
	return "2"
}

func mapTokenMode(mode string) string {
	if mode == "手动输入" {
		return "2"
	}
	return "1"
}

func boolToChoice(v bool) string {
	if v {
		return "1"
	}
	return "2"
}

func selectedDeps(npmEnabled, uvEnabled, goEnabled, rustEnabled bool) string {
	var deps []string
	if npmEnabled {
		deps = append(deps, "npm")
	}
	if uvEnabled {
		deps = append(deps, "uv")
	}
	if goEnabled {
		deps = append(deps, "go")
	}
	if rustEnabled {
		deps = append(deps, "rust")
	}
	return strings.Join(deps, " ")
}

func execShell(shellScript, wizard string, dryRun bool, configFile string) int {
	var cmdArgs []string
	if wizard == "" {
		cmdArgs = []string{shellScript}
		if dryRun {
			cmdArgs = append(cmdArgs, "--dry-run")
		}
	} else {
		cmdArgs = app.BuildShellCommand(shellScript, wizard, dryRun, configFile)
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "OPENCLAWCTL_FORCE_SHELL=1")

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "执行 shell 流程失败: %v\n", err)
		return 1
	}
	return 0
}
