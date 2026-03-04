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
		{Key: "deps", Label: "🔧 检查或补齐运行环境", Description: "处理 npm / uv / go / rust 等依赖"},
		{Key: "adopt", Label: "🔄 接管外部安装实例", Description: "读取现有容器并生成可管理配置"},
		{Key: "persist", Label: "🧩 追加 Runtime 持久化", Description: "对已有实例执行持久化重建"},
		{Key: "native", Label: "🧪 原生 npm 安装", Description: "无 Docker 安装 OpenClaw npm 包"},
		{Key: "info", Label: "📄 查看部署信息", Description: "读取 deployment-info.txt"},
		{Key: "uninstall", Label: "🗑️ 卸载实例", Description: "安全卸载或完全删除实例"},
		{Key: "quit", Label: "🚪 退出", Description: "不执行任何变更并退出"},
	}
}
