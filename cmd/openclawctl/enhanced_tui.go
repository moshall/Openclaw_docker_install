package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moshall/Openclaw_docker_install/internal/tui"
)

type enhancedSubmission struct {
	Action string
	Values map[string]string
}

func runEnhancedSubmission(dryRun bool) (enhancedSubmission, error) {
	actions := buildEnhancedActions()
	forms := buildEnhancedForms()
	profile := tui.DetectColorProfile(os.Getenv("TERM"), os.Getenv("COLORTERM"))
	editor := tui.NewEditorModel(actions, profile, forms)

	result, err := tui.RunEditor(editor, dryRun)
	if err != nil {
		return enhancedSubmission{}, err
	}
	if result.Canceled {
		return enhancedSubmission{Action: "quit", Values: map[string]string{}}, nil
	}
	return enhancedSubmission{
		Action: result.Action,
		Values: result.Values,
	}, nil
}

func buildEnhancedActions() []tui.Action {
	return []tui.Action{
		{Key: "native", Label: "1.1 Native 新安装", Description: "Native 实体机安装与管理（Mac/Linux）"},
		{Key: "native-upgrade", Label: "1.2 Native 升级/重装", Description: "保留数据升级或重装"},
		{Key: "native-repair", Label: "1.3 Native 运行环境修复", Description: "Node/npm、构建链、swap 修复"},
		{Key: "native-info", Label: "1.4 查看 Native 部署信息", Description: "读取 Native 报告与目录信息"},
		{Key: "native-uninstall", Label: "1.5 卸载 Native 实例", Description: "卸载 npm 包，可选删除数据"},

		{Key: "install", Label: "2.1 Docker 新安装（推荐）", Description: "镜像/端口/持久化/可选软件/Skills"},
		{Key: "upgrade", Label: "2.2 Docker 升级实例", Description: "安全升级并保留数据"},
		{Key: "rebuild", Label: "2.3 调整配置并重建", Description: "修改端口/目录/挂载后重建"},
		{Key: "persist", Label: "2.3.1 追加 Runtime 持久化", Description: "对已有实例执行持久化重建"},
		{Key: "deps", Label: "2.4 容器运行环境维护", Description: "依赖检测/补齐（npm/uv/go/rust）"},
		{Key: "easyclaw", Label: "2.4.1 EasyClaw 升级/修复", Description: "检查并升级 EasyClaw"},
		{Key: "adopt", Label: "2.5 接管已有 Docker 实例", Description: "读取容器并生成可管理配置"},
		{Key: "info", Label: "2.6 查看 Docker 部署信息", Description: "读取 deployment-info.txt"},
		{Key: "uninstall", Label: "2.7 卸载 Docker 实例", Description: "安全卸载或完全删除实例"},

		{Key: "panel-install", Label: "3.1 安装 1Panel", Description: "环境检查 + 官方脚本安装"},
		{Key: "panel-repair", Label: "3.2 升级/修复 1Panel", Description: "1Panel 自身升级与异常修复"},
		{Key: "panel-openclaw-install", Label: "3.3 1Panel 安装 OpenClaw", Description: "复用 Docker 安装流程"},
		{Key: "panel-openclaw-adopt", Label: "3.4 接管 1Panel 实例", Description: "接管已有 1Panel/OpenClaw 容器"},
		{Key: "panel-deps", Label: "3.5 1Panel 环境依赖修复", Description: "Docker/网络/端口检查修复"},
		{Key: "panel-info", Label: "3.6 查看 1Panel 部署信息", Description: "查看 1Panel + OpenClaw 信息"},
		{Key: "panel-uninstall", Label: "3.7 卸载 1Panel OpenClaw", Description: "卸载 1Panel 下 OpenClaw 实例"},

		{Key: "quit", Label: "0. 退出", Description: "不执行任何变更并退出"},
	}
}

func buildEnhancedForms() map[string]tui.Form {
	return map[string]tui.Form{
		"install": {
			Title: "安装配置",
			Fields: []tui.Field{
				{Key: "source", Label: "版本来源", Type: tui.FieldTypeSelect, Value: "中文版", Options: []string{"官方", "中文版"}},
				{Key: "channel", Label: "版本通道", Type: tui.FieldTypeSelect, Value: "稳定版", Options: []string{"稳定版", "最新版"}},
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "bind", Label: "网络绑定", Type: tui.FieldTypeSelect, Value: "lan", Options: []string{"local", "lan"}},
				{Key: "host_port", Label: "宿主机端口", Type: tui.FieldTypeText, Value: "4113"},
				{Key: "container_port", Label: "容器端口", Type: tui.FieldTypeText, Value: "18789"},
				{Key: "extra_ports", Label: "扩展端口", Type: tui.FieldTypeText, Value: ""},
				{Key: "bin_persist", Label: "保留 bin", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "env_persist", Label: "保留 env", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "apt_persist", Label: "保留 APT 源/Key", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "cache_persist", Label: "保留缓存", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "easy", Label: "安装 EasyClaw", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "deps_install", Label: "自动补齐依赖", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "target_deps", Label: "依赖集合", Type: tui.FieldTypeText, Value: "npm uv"},
				{Key: "token_mode", Label: "Token 方式", Type: tui.FieldTypeSelect, Value: "自动生成", Options: []string{"自动生成", "手动输入"}},
				{Key: "token_manual", Label: "手动 Token", Type: tui.FieldTypeText, Value: ""},
				{Key: "software_set", Label: "可选软件", Type: tui.FieldTypeText, Value: ""},
				{Key: "skill_set", Label: "预装 Skills", Type: tui.FieldTypeText, Value: ""},
			},
		},
		"upgrade": {
			Title: "升级配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "source", Label: "目标来源", Type: tui.FieldTypeSelect, Value: "中文版", Options: []string{"官方", "中文版"}},
				{Key: "channel", Label: "目标通道", Type: tui.FieldTypeSelect, Value: "稳定版", Options: []string{"稳定版", "最新版"}},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "host_port", Label: "宿主机端口", Type: tui.FieldTypeText, Value: "4113"},
				{Key: "container_port", Label: "容器端口", Type: tui.FieldTypeText, Value: "18789"},
				{Key: "extra_ports", Label: "扩展端口", Type: tui.FieldTypeText, Value: ""},
				{Key: "bin_persist", Label: "保留 bin", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "env_persist", Label: "保留 env", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "apt_persist", Label: "保留 APT 源/Key", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "cache_persist", Label: "保留缓存", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "easy", Label: "升级 EasyClaw", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "deps_install", Label: "自动补齐依赖", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "target_deps", Label: "依赖集合", Type: tui.FieldTypeText, Value: "npm uv"},
			},
		},
		"rebuild": {
			Title: "重建配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "image", Label: "目标镜像", Type: tui.FieldTypeText, Value: "ghcr.io/1186258278/openclaw-zh:latest"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "host_port", Label: "宿主机端口", Type: tui.FieldTypeText, Value: "4113"},
				{Key: "container_port", Label: "容器端口", Type: tui.FieldTypeText, Value: "18789"},
				{Key: "extra_ports", Label: "扩展端口", Type: tui.FieldTypeText, Value: ""},
				{Key: "bin_persist", Label: "保留 bin", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "env_persist", Label: "保留 env", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "apt_persist", Label: "保留 APT 源/Key", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "cache_persist", Label: "保留缓存", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "deps_install", Label: "自动补齐依赖", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "target_deps", Label: "依赖集合", Type: tui.FieldTypeText, Value: "npm uv"},
			},
		},
		"easyclaw": {
			Title: "EasyClaw 配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
			},
		},
		"deps": {
			Title: "依赖配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "mode", Label: "模式", Type: tui.FieldTypeSelect, Value: "install", Options: []string{"install", "check"}},
				{Key: "target_deps", Label: "依赖集合", Type: tui.FieldTypeText, Value: "npm uv"},
			},
		},
		"adopt": {
			Title: "接管配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
			},
		},
		"persist": {
			Title: "持久化重建配置",
			Fields: []tui.Field{
				{Key: "source", Label: "目标来源", Type: tui.FieldTypeSelect, Value: "中文版", Options: []string{"官方", "中文版"}},
				{Key: "channel", Label: "目标通道", Type: tui.FieldTypeSelect, Value: "稳定版", Options: []string{"稳定版", "最新版"}},
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "host_port", Label: "宿主机端口", Type: tui.FieldTypeText, Value: "4113"},
				{Key: "container_port", Label: "容器端口", Type: tui.FieldTypeText, Value: "18789"},
				{Key: "extra_ports", Label: "扩展端口", Type: tui.FieldTypeText, Value: ""},
				{Key: "bin_persist", Label: "保留 bin", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "env_persist", Label: "保留 env", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "apt_persist", Label: "保留 APT 源/Key", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "cache_persist", Label: "保留缓存", Type: tui.FieldTypeToggle, Value: "2"},
				{Key: "deps_install", Label: "自动补齐依赖", Type: tui.FieldTypeToggle, Value: "1"},
				{Key: "target_deps", Label: "依赖集合", Type: tui.FieldTypeText, Value: "npm uv"},
			},
		},
		"native": {
			Title: "原生 npm 配置",
			Fields: []tui.Field{
				{Key: "source", Label: "版本来源", Type: tui.FieldTypeSelect, Value: "中文版", Options: []string{"官方", "中文版"}},
				{Key: "channel", Label: "版本通道", Type: tui.FieldTypeSelect, Value: "稳定版", Options: []string{"稳定版", "最新版"}},
				{Key: "official_tag", Label: "官方 tag（可空）", Type: tui.FieldTypeText, Value: ""},
				{Key: "name", Label: "应用名", Type: tui.FieldTypeText, Value: "openclaw_native"},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
				{Key: "native_prefix", Label: "npm 安装前缀", Type: tui.FieldTypeText, Value: ""},
				{Key: "software_set", Label: "可选软件", Type: tui.FieldTypeText, Value: ""},
				{Key: "skill_set", Label: "预装 Skills", Type: tui.FieldTypeText, Value: ""},
			},
		},
		"uninstall": {
			Title: "卸载配置",
			Fields: []tui.Field{
				{Key: "name", Label: "容器名", Type: tui.FieldTypeText, Value: "openclaw_demo"},
				{Key: "mode", Label: "卸载模式", Type: tui.FieldTypeSelect, Value: "1", Options: []string{"1", "2"}},
				{Key: "data_dir", Label: "持久化目录", Type: tui.FieldTypeText, Value: ""},
			},
		},
		"info": {
			Title:  "部署信息",
			Fields: []tui.Field{},
		},
		"quit": {
			Title:  "退出",
			Fields: []tui.Field{},
		},
	}
}

func writeConfigForEnhancedAction(dir string, submission enhancedSubmission) (string, error) {
	switch submission.Action {
	case "", "quit", "info":
		return "", nil
	case "native-upgrade", "native-repair", "native-info", "native-uninstall":
		return "", nil
	case "panel-install", "panel-repair", "panel-openclaw-install", "panel-openclaw-adopt", "panel-deps", "panel-info", "panel-uninstall":
		return "", nil
	case "install":
		cfg := installConfig{
			SourceChoice:           mapSourceChoice(valueOr(submission.Values, "source", "中文版")),
			ChannelChoice:          mapChannelChoice(valueOr(submission.Values, "channel", "稳定版")),
			HostPort:               valueOr(submission.Values, "host_port", "4113"),
			ContainerPort:          valueOr(submission.Values, "container_port", "18789"),
			Name:                   valueOr(submission.Values, "name", "openclaw_demo"),
			DataDir:                valueOr(submission.Values, "data_dir", ""),
			BindChoice:             mapBindChoice(valueOr(submission.Values, "bind", "lan")),
			BinPersistChoice:       valueOr(submission.Values, "bin_persist", "1"),
			EnvPersistChoice:       valueOr(submission.Values, "env_persist", "2"),
			APTConfigPersistChoice: valueOr(submission.Values, "apt_persist", "2"),
			CachePersistChoice:     valueOr(submission.Values, "cache_persist", "2"),
			EasyChoice:             valueOr(submission.Values, "easy", "1"),
			TokenMode:              mapTokenMode(valueOr(submission.Values, "token_mode", "自动生成")),
			TokenManual:            valueOr(submission.Values, "token_manual", ""),
			DepsInstallChoice:      valueOr(submission.Values, "deps_install", "1"),
			TargetDeps:             valueOr(submission.Values, "target_deps", "npm uv"),
			ExtraPorts:             valueOr(submission.Values, "extra_ports", ""),
			SoftwareSet:            valueOr(submission.Values, "software_set", ""),
			SkillSet:               valueOr(submission.Values, "skill_set", ""),
		}
		cfg.Image = resolveImageChoice(cfg.SourceChoice, cfg.ChannelChoice)
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeInstallConfigFile(dir, cfg)
	case "upgrade":
		cfg := upgradeConfig{
			Name:                   valueOr(submission.Values, "name", "openclaw_demo"),
			SourceChoice:           mapSourceChoice(valueOr(submission.Values, "source", "中文版")),
			ChannelChoice:          mapChannelChoice(valueOr(submission.Values, "channel", "稳定版")),
			HostPort:               valueOr(submission.Values, "host_port", "4113"),
			ContainerPort:          valueOr(submission.Values, "container_port", "18789"),
			DataDir:                valueOr(submission.Values, "data_dir", ""),
			BinPersistChoice:       valueOr(submission.Values, "bin_persist", "1"),
			EnvPersistChoice:       valueOr(submission.Values, "env_persist", "2"),
			APTConfigPersistChoice: valueOr(submission.Values, "apt_persist", "2"),
			CachePersistChoice:     valueOr(submission.Values, "cache_persist", "2"),
			EasyChoice:             valueOr(submission.Values, "easy", "1"),
			DepsInstallChoice:      valueOr(submission.Values, "deps_install", "1"),
			TargetDeps:             valueOr(submission.Values, "target_deps", "npm uv"),
			ExtraPorts:             valueOr(submission.Values, "extra_ports", ""),
		}
		cfg.Image = resolveImageChoice(cfg.SourceChoice, cfg.ChannelChoice)
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeUpgradeConfigFile(dir, cfg)
	case "rebuild":
		cfg := rebuildConfig{
			Name:                   valueOr(submission.Values, "name", "openclaw_demo"),
			Image:                  valueOr(submission.Values, "image", "ghcr.io/1186258278/openclaw-zh:latest"),
			HostPort:               valueOr(submission.Values, "host_port", "4113"),
			ContainerPort:          valueOr(submission.Values, "container_port", "18789"),
			DataDir:                valueOr(submission.Values, "data_dir", ""),
			BinPersistChoice:       valueOr(submission.Values, "bin_persist", "1"),
			EnvPersistChoice:       valueOr(submission.Values, "env_persist", "2"),
			APTConfigPersistChoice: valueOr(submission.Values, "apt_persist", "2"),
			CachePersistChoice:     valueOr(submission.Values, "cache_persist", "2"),
			DepsInstallChoice:      valueOr(submission.Values, "deps_install", "1"),
			TargetDeps:             valueOr(submission.Values, "target_deps", "npm uv"),
			ExtraPorts:             valueOr(submission.Values, "extra_ports", ""),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeRebuildConfigFile(dir, cfg)
	case "easyclaw":
		cfg := easyClawConfig{
			Name:    valueOr(submission.Values, "name", "openclaw_demo"),
			DataDir: valueOr(submission.Values, "data_dir", ""),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeEasyClawConfigFile(dir, cfg)
	case "deps":
		cfg := depsConfig{
			Name:       valueOr(submission.Values, "name", "openclaw_demo"),
			DataDir:    valueOr(submission.Values, "data_dir", ""),
			Mode:       valueOr(submission.Values, "mode", "install"),
			TargetDeps: valueOr(submission.Values, "target_deps", "npm uv"),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeDepsConfigFile(dir, cfg)
	case "adopt":
		cfg := adoptConfig{
			Name: valueOr(submission.Values, "name", "openclaw_demo"),
		}
		return writeAdoptConfigFile(dir, cfg)
	case "persist":
		sourceChoice := mapSourceChoice(valueOr(submission.Values, "source", "中文版"))
		channelChoice := mapChannelChoice(valueOr(submission.Values, "channel", "稳定版"))
		cfg := persistConfig{
			Name:                   valueOr(submission.Values, "name", "openclaw_demo"),
			Image:                  resolveImageChoice(sourceChoice, channelChoice),
			HostPort:               valueOr(submission.Values, "host_port", "4113"),
			ContainerPort:          valueOr(submission.Values, "container_port", "18789"),
			DataDir:                valueOr(submission.Values, "data_dir", ""),
			BinPersistChoice:       valueOr(submission.Values, "bin_persist", "1"),
			EnvPersistChoice:       valueOr(submission.Values, "env_persist", "2"),
			APTConfigPersistChoice: valueOr(submission.Values, "apt_persist", "2"),
			CachePersistChoice:     valueOr(submission.Values, "cache_persist", "2"),
			DepsInstallChoice:      valueOr(submission.Values, "deps_install", "1"),
			TargetDeps:             valueOr(submission.Values, "target_deps", "npm uv"),
			ExtraPorts:             valueOr(submission.Values, "extra_ports", ""),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writePersistConfigFile(dir, cfg)
	case "native":
		sourceChoice := mapSourceChoice(valueOr(submission.Values, "source", "中文版"))
		channelChoice := mapChannelChoice(valueOr(submission.Values, "channel", "稳定版"))
		cfg := nativeConfig{
			SourceChoice:  sourceChoice,
			ChannelChoice: channelChoice,
			OfficialTag:   valueOr(submission.Values, "official_tag", ""),
			Name:          valueOr(submission.Values, "name", "openclaw_native"),
			DataDir:       valueOr(submission.Values, "data_dir", ""),
			NativePrefix:  valueOr(submission.Values, "native_prefix", ""),
			SoftwareSet:   valueOr(submission.Values, "software_set", ""),
			SkillSet:      valueOr(submission.Values, "skill_set", ""),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		if strings.TrimSpace(cfg.NativePrefix) == "" {
			cfg.NativePrefix = filepath.Join(cfg.DataDir, "native")
		}
		return writeNativeConfigFile(dir, cfg)
	case "uninstall":
		cfg := uninstallConfig{
			Name:    valueOr(submission.Values, "name", "openclaw_demo"),
			Mode:    valueOr(submission.Values, "mode", "1"),
			DataDir: valueOr(submission.Values, "data_dir", ""),
		}
		if strings.TrimSpace(cfg.DataDir) == "" {
			cfg.DataDir = defaultDataDirForName(cfg.Name)
		}
		return writeUninstallConfigFile(dir, cfg)
	default:
		return "", fmt.Errorf("unsupported enhanced action: %s", submission.Action)
	}
}

func valueOr(values map[string]string, key, fallback string) string {
	if values == nil {
		return fallback
	}
	if value, ok := values[key]; ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}
