package app

type ActionOption struct {
	Key         string
	Label       string
	Description string
}

func ShouldFallbackToShell(stdinTTY, stdoutTTY bool) bool {
	return !stdinTTY || !stdoutTTY
}

func BuildShellCommand(shellScript, wizard string, dryRun bool, configFile string) []string {
	args := []string{shellScript, "--wizard", wizard}
	if configFile != "" {
		args = append(args, "--config-file", configFile)
	}
	if dryRun {
		args = append(args, "--dry-run")
	}
	return args
}

func ActionOptions() []ActionOption {
	return []ActionOption{
		{Key: "install", Label: "🚀 安装新实例", Description: "创建新的 OpenClaw 实例"},
		{Key: "upgrade", Label: "🔄 升级已有实例", Description: "安全升级并保留数据"},
		{Key: "rebuild", Label: "🛠️ 调整或重建实例", Description: "变更端口、挂载或持久化后重建"},
		{Key: "easyclaw", Label: "📦 管理 EasyClaw 工具", Description: "检查并升级 EasyClaw"},
		{Key: "deps", Label: "🔧 检查或补齐运行环境", Description: "处理 npm / uv / go 等依赖"},
		{Key: "uninstall", Label: "🗑️ 卸载实例", Description: "安全卸载或完全删除实例"},
		{Key: "quit", Label: "🚪 退出", Description: "不执行任何变更并退出"},
	}
}
