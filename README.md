# OpenClaw Docker 交互式部署助手（中文）

一个面向 OpenClaw 的交互式 Shell 工具，用于在 Docker 环境中快速完成：
- 新装
- 安全升级（保留持久化数据）
- 卸载（保留或清理持久化数据）
- 仅升级 Openclaw_Easy_Cli
- 容器环境依赖检测/安装（默认 `npm` + `uv`，`go` 可选）

本项目核心目标：
- 减少重复输入冗长命令
- 降低误操作风险（提供预览与确认）
- 统一部署流程，便于长期维护

## 功能特性

- 交互式菜单（清单式多层）
  - `1) 新装（清单模式）`
  - `2) 升级（安全升级 / 清单模式）`
  - `3) 卸载（快捷模式）`
  - `4) 仅升级 Easy CLI`
  - `5) 组件与依赖管理`
- 新装可配置项
  - 以“必要信息清单”形式展示，未填写项会显示 `未选择`
  - 按编号进入子菜单修改，避免长串连续提问
  - 镜像来源与通道（官方/中文、稳定/最新版）
  - 宿主机端口、容器端口
  - 容器名
  - 持久化目录
  - 运行时持久化策略（可选）
    - `bin` 持久化（默认开启）
    - 环境持久化（默认关闭，可按需开启）
  - `gateway.bind`（`local` / `lan`）
  - Token（自动生成/手动输入）
  - 可选安装 `Openclaw_Easy_Cli`
  - 可选自动补齐容器内常见依赖（默认 `npm` + `uv`，`go` 可选）
- 依赖检测/安装
  - 自动识别容器内包管理器：`apt` / `apk` / `dnf` / `yum`
  - 自动识别容器架构：`x86_64` / `aarch64`（安装 Go 时选择对应安装方式）
  - 自动修正 `uv` / `go` 的 PATH（当前会话 + 持久化 profile）
  - 当选择 `uv` 但容器缺失 Python 时，会自动补齐 `python3/pip`
  - 已内置 Debian/Ubuntu 兼容模式：若遇到 PEP668（`externally-managed-environment`），会自动回退安装策略
  - 自动将 `/root/.local/bin`、`/root/go/bin` 中可执行文件软链到 `/usr/local/bin`，避免 OpenClaw 找不到命令
  - 依赖清单会写入持久化目录（`runtime/deps.profile`），升级后自动沿用并补齐
  - 按选项挂载并持久化
    - `bin`：`/root/.local/bin`、`/root/go/bin`
    - 环境：`/usr/local/go`、`/root/.local/share/uv`、`/root/.local/pipx`、`/root/.local/share/pipx`
  - 支持两种模式：仅检测、检测并安装缺失项
  - 可在安装流程自动执行，也可菜单独立执行
- 安全升级
  - 以“升级清单”形式展示所有关键参数，支持逐项编辑
  - 升级前检测容器运行状态（运行中会提示“将中断任务”并要求确认）
  - 复用原持久化目录
  - 重建容器后自动做基础检查（`ps/logs/version`）
  - 可选检查并升级 `Openclaw_Easy_Cli`
  - 可继承并调整“bin/环境持久化”与依赖选择（配置保存于 `runtime/` 下）
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
cd /你的路径/openclaw\ docker/Openclaw_docker_install
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

1. 选择 `1) 新装（清单模式）`
2. 在清单中编辑 `1)版本`、`2)容器名`、`4)持久化目录` 等必要项
3. 未填写项会显示 `未选择`，可随时回改
4. 配置完成后输入 `c` 进入最终确认并执行

### 场景 B：升级 OpenClaw 且保留数据

1. 选择 `2) 升级（安全升级 / 清单模式）`
2. 输入容器名
3. 若检测到容器运行中，确认是否继续（继续会中断当前任务）
4. 在“升级清单”中按编号调整目标版本、持久化策略、依赖项
5. 输入 `c` 进入确认并执行

### 场景 C：只升级 Easy CLI，不动 OpenClaw 容器

1. 选择 `4) 仅升级 Easy CLI`
2. 输入容器名/目录
3. 确认执行

### 场景 D：只做容器依赖补齐（默认 npm+uv，go 可选）

1. 选择 `5) 组件与依赖管理`
2. 输入容器名
3. 选择“仅检测”或“检测并安装缺失项”
4. 确认执行

## 目录结构

```text
.
├── Openclaw_docker_install/
│   ├── openclawctl.sh            # 主脚本（交互式菜单）
│   └── README.md                 # 当前文件
└── tests/
    └── openclawctl_test.sh       # 交互流程测试
```

## 注意事项

- `sh openclawctl.sh` 报错 `Illegal option -o pipefail`：
  - 原因：`sh` 不支持该语法
  - 解决：改用 `bash openclawctl.sh`
- 出现多个 `openclaw.json.bak*`：
  - 属于配置写入时的备份行为，通常是正常现象
- 删除持久化目录是不可逆操作：
  - 完整卸载前请确认数据已备份
- 若使用 `pip install --user` 安装 Python 包：
  - 其 `site-packages` 常在 `/root/.local/lib/python*/site-packages`
  - 当前“环境持久化”未覆盖该目录，建议优先使用 `uv` / `pipx`，或自行增加该目录挂载

## 为什么建议开启持久化

- 开启 `bin` 持久化后：
  - 升级后已安装命令更不容易“丢失路径”（如 `uv`、`obsidian-cli`）
- 同时开启环境持久化后：
  - 升级后已安装运行环境可复用，减少重复安装
- 对 OpenClaw 使用的直接收益：
  - 升级时更不容易丢失已安装技能/插件所依赖的运行时命令

## 测试

运行测试：

```bash
bash ../tests/openclawctl_test.sh
```

## 许可证

当前仓库未单独声明 License。
如需开源发布，建议补充 `LICENSE` 文件（如 MIT/Apache-2.0）。

## 致谢

- OpenClaw 官方项目：<https://github.com/openclaw/openclaw>
- OpenClaw 中文版项目：<https://github.com/1186258278/OpenClawChineseTranslation>
- Openclaw_Easy_Cli：<https://github.com/moshall/Openclaw_Easy_Cli>
