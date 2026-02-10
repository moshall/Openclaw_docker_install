# OpenClaw Docker 交互式部署助手（中文）

一个面向 OpenClaw 的交互式 Shell 工具，用于在 Docker 环境中快速完成：
- 新装
- 安全升级（保留持久化数据）
- 卸载（保留或清理持久化数据）
- 仅升级 Openclaw_Easy_Cli

本项目核心目标：
- 减少重复输入冗长命令
- 降低误操作风险（提供预览与确认）
- 统一部署流程，便于长期维护

## 功能特性

- 交互式菜单
  - `1) 新装`
  - `2) 升级（安全升级）`
  - `3) 卸载`
  - `4) 仅升级 Easy CLI`
- 新装可配置项
  - 镜像来源与通道（官方/中文、稳定/最新版）
  - 宿主机端口、容器端口
  - 容器名
  - 持久化目录
  - `gateway.bind`（`local` / `lan`）
  - Token（自动生成/手动输入）
  - 可选安装 `Openclaw_Easy_Cli`
- 安全升级
  - 升级前检测容器运行状态（运行中会提示“将中断任务”并要求确认）
  - 复用原持久化目录
  - 重建容器后自动做基础检查（`ps/logs/version`）
  - 可选检查并升级 `Openclaw_Easy_Cli`
- 卸载模式
  - 安全卸载：仅删除容器
  - 完整卸载：删除容器 + 删除持久化目录（二次确认）
- Dry Run 预演
  - `--dry-run` 只打印命令，不执行

## 镜像映射规则

- 中文稳定：`ghcr.io/1186258278/openclaw-zh:latest`
- 中文最新版：`ghcr.io/1186258278/openclaw-zh:nightly`
- 官方稳定：`docker.io/openclaw/openclaw:latest`
- 官方最新版：`docker.io/openclaw/openclaw:beta`

## 环境要求

- Linux 服务器（推荐）
- Docker 已安装并可用
- Bash 可用（脚本使用了 `bash` 语法）
- 可选：`git`（用于安装/升级 `Openclaw_Easy_Cli`）

## 快速开始

### 1) 获取脚本

将本仓库克隆到服务器后，进入目录：

```bash
cd /你的路径/openclaw\ docker
```

### 2) 运行（重要）

请使用 `bash` 运行，不要用 `sh`：

```bash
bash ./openclawctl.sh
```

预演模式：

```bash
bash ./openclawctl.sh --dry-run
```

### 3) 按菜单完成操作

脚本会逐步询问参数并在关键步骤提供确认。

## 常见使用场景

### 场景 A：首次部署（中文版稳定）

1. 选择 `1) 新装`
2. 版本来源选“中文版”，通道选“稳定版”
3. 设置容器名、端口、持久化目录
4. 选择 Token 自动生成或手动设置
5. 确认执行

### 场景 B：升级 OpenClaw 且保留数据

1. 选择 `2) 升级（安全升级）`
2. 输入容器名
3. 若检测到容器运行中，确认是否继续（继续会中断当前任务）
4. 选择目标版本
5. 确认持久化目录（默认自动识别）
6. 确认执行

### 场景 C：只升级 Easy CLI，不动 OpenClaw 容器

1. 选择 `4) 仅升级 Easy CLI`
2. 输入容器名/目录
3. 确认执行

## 目录结构

```text
.
├── openclawctl.sh                # 主脚本（交互式菜单）
├── tests/
│   └── openclawctl_test.sh       # 交互流程测试
├── OpenClaw脚本化部署使用说明.md  # 详细中文说明
└── README.md                     # 当前文件
```

## 注意事项

- `sh openclawctl.sh` 报错 `Illegal option -o pipefail`：
  - 原因：`sh` 不支持该语法
  - 解决：改用 `bash openclawctl.sh`
- 出现多个 `openclaw.json.bak*`：
  - 属于配置写入时的备份行为，通常是正常现象
- 删除持久化目录是不可逆操作：
  - 完整卸载前请确认数据已备份

## 测试

运行测试：

```bash
bash ./tests/openclawctl_test.sh
```

## 许可证

当前仓库未单独声明 License。
如需开源发布，建议补充 `LICENSE` 文件（如 MIT/Apache-2.0）。

## 致谢

- OpenClaw 官方项目：<https://github.com/openclaw/openclaw>
- OpenClaw 中文版项目：<https://github.com/1186258278/OpenClawChineseTranslation>
- Openclaw_Easy_Cli：<https://github.com/moshall/Openclaw_Easy_Cli>
