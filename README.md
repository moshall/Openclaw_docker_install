# OpenClaw Docker 部署助手

一个面向 OpenClaw 的部署与运维工具，采用 `Shell 执行引擎 + Go TUI 前端` 架构，支持：

- 新装实例
- 升级实例（低版本 -> 高版本）
- 安全重建（端口/挂载调整）
- 卸载（安全卸载 / 完整卸载）
- EasyClaw 管理
- 容器依赖检测与补齐（默认 `npm uv`，可选 `go`）

## 目录结构

```text
.
├── openclawctl.sh              # 主脚本（真实执行入口）
├── cmd/
│   └── openclawctl/            # Go TUI（交互前端）
├── internal/
│   └── app/                    # TUI 公共模型/菜单配置
├── tests/
│   └── openclawctl_test.sh     # Shell 交互回归测试
├── docs/
│   └── plans/                  # 设计文档
├── go.mod
├── go.sum
└── README.md
```

## 运行方式

```bash
bash ./openclawctl.sh
```

说明：

- 交互式终端（TTY）中，默认优先启动 Go TUI。
- 非 TTY（管道、计划任务、脚本）自动回退到 Shell 菜单。
- 如需强制使用 Shell：

```bash
OPENCLAWCTL_FORCE_SHELL=1 bash ./openclawctl.sh
```

- 预演模式（仅打印命令，不执行）：

```bash
bash ./openclawctl.sh --dry-run
```

## 镜像策略

中文版镜像：

- 稳定版：`ghcr.io/1186258278/openclaw-zh:latest`
- 最新版：`ghcr.io/1186258278/openclaw-zh:nightly`

官方镜像（默认）：

- 稳定版：`docker.io/1panel/openclaw:latest`
- 最新版：`docker.io/1panel/openclaw:beta`

补充：

- 官方源支持自动拉取 tag 并手动选择具体版本（例如 `2026.2.26`）。
- 可通过 `OPENCLAW_OFFICIAL_REPO` 覆盖官方仓库（例如 `alpine/openclaw`）。
- 为保证 `.openclaw` 路径一致，脚本统一以 `--user root` 执行 OpenClaw 配置与容器启动。

## 持久化目录策略

默认目录按环境自动判断：

1. 若设置 `OPENCLAWCTL_DATA_ROOT`，优先使用该目录。
2. 检测到 1Panel 环境时：`/opt/1panel/apps/<容器名>`
3. 非 1Panel 环境：
   - Linux：`/opt/openclaw/apps/<容器名>`
   - macOS：`$HOME/.openclaw/apps/<容器名>`

## 关键安全机制

- Preflight 检查：Docker 可用性、目录可写、镜像仓库、端口信息。
- 目录错挂载保护：
  - 升级/重建时若检测“当前挂载目录”与“本次目录”不一致，默认中止。
  - 可显式放行：`OPENCLAWCTL_ALLOW_DATA_DIR_MISMATCH=1`
- 升级前兼容修复：`openclaw doctor --fix`
- `lan` 绑定下自动尝试写入 Control UI 兼容项（不支持的旧键会自动跳过，不阻断主流程）。

## Docker 与环境补齐

- Docker 缺失时：
  - Linux 可自动安装（`OPENCLAWCTL_AUTO_INSTALL_DOCKER=1` 可无交互）
  - macOS 提供 Docker Desktop 引导
- 依赖补齐：支持 apt/apk/dnf/yum 生态，支持 `npm uv go` 组合。
- runtime 持久化支持：bin/env/apt 配置/cache 分层选择。

## 常用环境变量

- `OPENCLAWCTL_DATA_ROOT`：自定义持久化根目录。
- `OPENCLAW_OFFICIAL_REPO`：覆盖官方镜像仓库。
- `OPENCLAWCTL_AUTO_INSTALL_DOCKER=1`：自动安装 Docker（Linux/macOS）。
- `OPENCLAWCTL_ALLOW_DATA_DIR_MISMATCH=1`：放行目录不一致升级。
- `OPENCLAWCTL_ALLOWED_ORIGINS`：Control UI 显式 allowed origins。
- `OPENCLAWCTL_TRUSTED_PROXIES`：网关 trusted proxies。
- `OPENCLAWCTL_FORCE_SHELL=1`：强制禁用 TUI，直接 Shell 菜单。

## 测试

在仓库根目录执行：

```bash
bash -n ./openclawctl.sh
go test ./...
bash ./tests/openclawctl_test.sh
```

## 已验证场景

以下链路已在真实机器验证（**2026-03-02**，Ubuntu 22.04）：

- 纯 Linux 路径：`/opt/openclaw/apps`
  - `2026.2.6 -> 2026.2.26` 升级通过
- 1Panel 路径：`/opt/1panel/apps`
  - `2026.2.6 -> 2026.2.26` 升级通过

说明：`2026.2.5` 在官方 tags 中不存在，因此低版本升级验证使用最接近可用版本 `2026.2.6`。

## 开发说明

手工构建 TUI：

```bash
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" GOTOOLCHAIN=auto go build -o ./.bin/openclawctl ./cmd/openclawctl
```

运行后脚本会自动优先发现并启动 `./.bin/openclawctl`。
