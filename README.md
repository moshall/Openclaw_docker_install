# OpenClaw 安装助手（openclawctl）

`openclawctl` 是 OpenClaw 的一键安装与运维脚本，面向小白用户设计。

当前版本交互方式已统一为：
- 仅保留 **简单 Shell 菜单**
- 不再启用复杂 TUI 前端

---

## 功能描述

### 1) Native 实体机安装与管理（Mac/Linux）
- 新安装 OpenClaw（Native npm）
- 升级/重装 Native 实例
- 修复 Native 运行环境（Node/npm、构建工具链等）
- 查看部署信息
- 卸载 Native 实例
- 支持可选软件安装与 Skills 预装

### 2) Docker 隔离环境安装与管理（Mac/Linux）
- 新安装 Docker 实例
- 安全升级 Docker 实例（保留数据）
- 调整配置并重建（端口、数据目录、Runtime 持久化）
- 运行环境维护（依赖检测/补齐、ClawPanel 升级修复）
- 接管已有 Docker 实例
- 查看部署信息
- 卸载 Docker 实例

### 3) 远程 VPS 1Panel 版 Docker 安装与管理（Linux）
- 安装 1Panel
- 升级/修复 1Panel
- 在 1Panel 环境安装 OpenClaw（Docker）
- 接管已有 1Panel/OpenClaw 实例
- 1Panel 环境依赖修复
- 查看部署信息
- 卸载 1Panel 环境下 OpenClaw 实例

### 核心能力（通用）
- 官方/中文版镜像与通道选择（stable/latest/nightly）
- 官方 tag 列表拉取与指定版本安装/升级
- 升级/重建前 runtime 数据预迁移与挂载一致性校验
- runtime 持久化策略：`bin/env/apt/cache`
- `path shim/symlink` 持久化清单支持
- Docker/Node/npm/构建工具自动检测与补齐（面向小白）
- `--dry-run` 全流程预演（不实际安装）

---

## 安装方法

### 方法 A：一键远程启动（推荐）

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/moshall/Openclaw_docker_install/main/quick_start.sh)"
```

仅预演（不执行真实安装）：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/moshall/Openclaw_docker_install/main/quick_start.sh)" -- --dry-run
```

指定分支/标签：

```bash
OPENCLAWCTL_REF=v0.7.2 bash -c "$(curl -fsSL https://raw.githubusercontent.com/moshall/Openclaw_docker_install/v0.7.2/quick_start.sh)" -- --dry-run
```

### 方法 B：本地源码运行

```bash
git clone https://github.com/moshall/Openclaw_docker_install.git
cd Openclaw_docker_install
bash ./openclawctl.sh
```

仅预演：

```bash
bash ./openclawctl.sh --dry-run
```

---

## 使用方法

### 启动菜单

```bash
bash ./openclawctl.sh
```

主菜单：

```text
OpenClaw 部署助手
1) Native 实体机安装与管理（Mac/Linux）
2) Docker 隔离环境安装与管理（Mac/Linux）
3) 远程 VPS 1Panel 版 Docker 隔离环境安装与管理（Linux）
9) 高级模式（开发者）
0) 退出
```

### 常用操作建议

- 第一次使用（Mac/Linux 普通用户）：优先走 `2) Docker 隔离环境安装与管理`
- 本机不装 Docker 的场景：走 `1) Native`
- 远程 Linux VPS + 面板管理：走 `3) 1Panel`

### 非交互执行（自动化/批量）

```bash
bash ./openclawctl.sh --dry-run --wizard install --config-file /path/to/install.cfg
```

支持的 `--wizard`：
- `install`
- `upgrade`
- `rebuild`
- `clawpanel`
- `deps`
- `uninstall`
- `adopt`
- `persist`
- `native`
- `native-upgrade`
- `native-repair`
- `native-info`
- `native-uninstall`
- `info`
- `panel-install`
- `panel-repair`
- `panel-openclaw-install`
- `panel-openclaw-adopt`
- `panel-deps`
- `panel-info`
- `panel-uninstall`

---

## 目录与数据说明

默认数据根目录：
- macOS：`$HOME/.openclaw/apps/<name>`
- Linux（非 1Panel）：`/opt/openclaw/apps/<name>`
- 1Panel：`/opt/1panel/apps/<name>`

部署信息：
- `~/.openclaw-installer/deployment-info.txt`

---

## 兼容性说明

- `1Panel` 功能真实执行仅支持 Linux 主机
- 在 macOS 下可做 `--dry-run` 预演
- 当前版本已强制统一为简单 Shell 菜单，避免双 UI 维护成本

---

## 测试与回归

在仓库根目录执行：

```bash
bash tests/quick_start_test.sh
bash tests/openclawctl_test.sh
bash tests/installer_v07_smoke_test.sh
bash tests/installer_v07_1panel_test.sh
go test ./...
```

---

## 项目结构

```text
.
├── openclawctl.sh
├── quick_start.sh
├── lib/openclawctl/
│   ├── bootstrap.sh
│   ├── common.sh
│   ├── io.sh
│   ├── image.sh
│   ├── persist.sh
│   ├── components.sh
│   ├── deps.sh
│   ├── hostdeps.sh
│   ├── ops.sh
│   └── wizard.sh
├── config/optional-components.conf
├── cmd/openclawctl/          # 代码保留，当前交互已统一为简单菜单
├── internal/
├── installer/v07/
├── tests/
└── docs/
```
