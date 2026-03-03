# OpenClaw 一键安装脚本 — 开发文档 v0.2

> 状态：草稿 | 更新：2026-03-02
> v0.2 变更：修正官方镜像信息 / 确认双轨镜像策略 / 1Panel 独立 compose+API 路线 / 工作区路径双路兼容方案

---

## 目录

1. [项目目标](#1-项目目标)
2. [术语定义](#2-术语定义)
3. [整体架构](#3-整体架构)
4. [镜像生态全景](#4-镜像生态全景)
5. [主菜单流程](#5-主菜单流程)
6. [模块规格](#6-模块规格)
7. [目录与路径规范](#7-目录与路径规范)
8. [Volume 持久化设计](#8-volume-持久化设计)
9. [配置文件规范](#9-配置文件规范)
10. [错误处理规范](#10-错误处理规范)
11. [回归测试矩阵](#11-回归测试矩阵)
12. [开放问题与待决策项](#12-开放问题与待决策项)

---

## 1. 项目目标

### 1.1 背景

OpenClaw 是一个功能强大的个人 AI 助手平台，但安装过程对非技术用户阻力极大：Node.js 版本要求、Docker 配置、环境变量、持久化卷、远程访问配置……任何一步出错都会导致放弃。

本项目目标：**消除环境配置阻力**，让用户买完服务器 SSH 进去后，一条命令就能跑起来，把注意力放在真正使用 OpenClaw 上。

### 1.2 核心设计原则

| 原则 | 说明 |
|------|------|
| **小白友好** | 所有交互中文，有默认值，不让用户面对空白输入 |
| **幂等安全** | 同一操作重复执行结果一致，不破坏现有数据 |
| **数据不丢** | 升级、重建操作严格保留 `~/.openclaw/` 数据 |
| **可逆操作** | 每个操作前提示确认，提供回退路径 |
| **自我诊断** | 失败时给出具体原因和修复建议，不只输出堆栈 |
| **不依赖 App Store** | 我们自己的 compose+API 流程比 1Panel App Store 提供更多控制权（自定义端口/volume/版本） |

### 1.3 优先级排期

| 阶段 | 功能范围 | 目标 |
|------|----------|------|
| **P0（MVP）** | 1Panel compose+API 安装 + Linux Docker 安装（官方版+中文版） | 覆盖 80% 目标用户 |
| **P1** | 升级/重建/卸载完整生命周期 + Linux 原生 npm | 完整管理能力 |
| **P2** | macOS Docker + macOS 原生 npm + 预装环境/软件 | 开发者场景 |
| **P3** | 预装 Skills + 高级持久化 | 高级用户场景 |

---

## 2. 术语定义

| 术语 | 含义 |
|------|------|
| **宿主机** | 运行 Docker 的物理机或 VPS |
| **容器** | 运行 OpenClaw 的 Docker 容器 |
| **官方版** | `ghcr.io/openclaw/openclaw`，npm 包 `openclaw` |
| **中文版** | `ghcr.io/1186258278/openclaw-zh`，npm 包 `@qingchencloud/openclaw-zh` |
| **node 用户** | 官方版容器内运行用户（非 root），家目录 `/home/node/` |
| **root 用户** | 中文版容器内运行用户，家目录 `/root/` |
| **配置目录** | `~/.openclaw/`（宿主机），存储 openclaw.json、credentials |
| **工作区目录** | `~/openclaw/workspace/`（宿主机），存储 AGENTS.md、skills、工作文件 |
| **安装配置文件** | `~/.openclaw-installer/config.env`，记录本次安装参数 |
| **1Panel API 模式** | 调用 1Panel Open API 自动在面板内创建 Compose 应用 |
| **1Panel Compose 模式** | 生成标准 compose 文件，由用户在 1Panel 界面手动导入 |

---

## 3. 整体架构

### 3.1 脚本文件结构

```
openclaw-install.sh              # 单文件主脚本（curl | bash 可直接运行）
  ├── [内嵌] lib_ui.sh           # 交互 UI（菜单、颜色、进度条）
  ├── [内嵌] lib_detect.sh       # 环境探测
  ├── [内嵌] lib_docker.sh       # Docker 操作（pull/run/compose）
  ├── [内嵌] lib_compose.sh      # docker-compose.yml 生成器
  ├── [内嵌] lib_1panel.sh       # 1Panel API 调用
  └── [内嵌] lib_npm.sh          # 原生 npm 安装
```

> 单文件设计：方便 `curl | bash` 一键执行，无需下载多个文件。

### 3.2 主要依赖

| 依赖 | 用途 | 缺失时行为 |
|------|------|------------|
| `bash >= 4.0` | 脚本运行时 | 报错退出，提示升级 bash |
| `curl` 或 `wget` | 下载/API 调用 | 提示安装 |
| `docker` + `docker compose` (v2) | 容器管理 | 提示安装，可选自动安装 |
| `jq` | JSON 解析（1Panel API、版本查询） | 自动安装 |
| `ss` 或 `netstat` | 端口检测 | 跳过端口检测，提示手动确认 |
| `node >= 22` | 仅原生 npm 安装模式需要 | 提示通过 nvm 安装 |

---

## 4. 镜像生态全景

> **重要**：官方版 GHCR 镜像真实存在，每次发布自动构建，v0.1 文档中「官方无预构建镜像」的表述错误，本版已修正。

### 4.1 我们支持的镜像（双轨）

| 来源 | 镜像地址 | 用户 | 适用人群 |
|------|----------|------|----------|
| **官方版** | `ghcr.io/openclaw/openclaw` | `node` | 英文用户、需要官方原版 |
| **中文版** | `ghcr.io/1186258278/openclaw-zh` | `root` | 中文用户（推荐默认） |

### 4.2 官方版标签体系

| 标签 | 说明 | 对应脚本选项 |
|------|------|-------------|
| `:latest` | 最新稳定版 | 最新稳定版（默认推荐） |
| `:main` | main 分支（开发版） | 最新开发版 |
| `:<version>` | 如 `:2026.3.1` | 指定版本号 |
| `:latest-full` | 含额外工具的完整版 | （暂不暴露给用户，内部备用） |
| `:<version>-arm64` | arm64 专属标签 | 自动探测架构选择 |

> 官方版同时有 Docker Hub 镜像（`alpine/openclaw`），但我们统一使用 GHCR 源，避免混淆。

### 4.3 中文版标签体系

| 标签 | 说明 | 对应脚本选项 |
|------|------|-------------|
| `:latest` | 手动发布的稳定版 | 稳定版（推荐生产） |
| `:nightly` | 每小时同步官方，自动构建 | 最新版（追踪新功能） |

### 4.4 我们不涵盖的镜像（仅供参考）

| 镜像 | 说明 | 不涵盖原因 |
|------|------|------------|
| `1panel/openclaw` | 1Panel 官方 App Store 版 | 我们自己的流程比 App Store 有更多控制权 |
| `coollabsio/openclaw` | 含 nginx+工具的增强版 | 独立维护，行为差异大，增加测试负担 |
| `phioranex/openclaw-docker` | 社区 Windows 优化版 | 不在目标平台范围 |

### 4.5 关键差异：官方版 vs 中文版容器用户

这是影响 Volume 挂载的核心差异：

```
官方版容器                    中文版容器
├── 运行用户: node            ├── 运行用户: root
├── 家目录: /home/node/       ├── 家目录: /root/
├── 配置: /home/node/.openclaw/   ├── 配置: /root/.openclaw/
└── 工作区: /home/node/openclaw/workspace/  └── 工作区: /root/.openclaw/workspace/
```

脚本生成 compose 时，根据所选镜像源自动选择正确的容器内路径。

---

## 5. 主菜单流程

### 5.1 脚本入口判断逻辑

```
启动脚本
  │
  ├─ 环境探测（静默，约 2 秒）
  │    ├─ OS / 发行版 / 架构
  │    ├─ Docker 可用性
  │    └─ 1Panel 是否安装
  │
  ├─ 检测是否已安装（读取 ~/.openclaw-installer/config.env）
  │    ├─ 已安装 → 显示「管理菜单」
  │    └─ 未安装 → 显示「安装菜单」
  │
  └─ 显示对应菜单
```

### 5.2 安装菜单

```
╔══════════════════════════════════════════════╗
║   🦞 OpenClaw 一键安装向导 v1.0              ║
║   环境：Ubuntu 22.04 (x86_64)               ║
║   Docker: ✅ 27.x  |  1Panel: ✅ 2.x        ║
╚══════════════════════════════════════════════╝

选择安装方式：
  [1] 1Panel 面板安装  ← 检测到 1Panel，自定义端口/volume（推荐）
  [2] Linux Docker 安装（命令行管理）
  [3] Linux 原生 npm 安装（无 Docker，需 Node 22）

> _
```

> 若未检测到 1Panel，则不显示选项 [1]。

### 5.3 管理菜单（已安装）

```
╔══════════════════════════════════════════════╗
║   🦞 OpenClaw 管理控制台                      ║
║   版本：2026.2.25-zh.3（中文版 · nightly）   ║
║   状态：✅ 运行中  端口：{{CFG_PORT_HOST}}               ║
╚══════════════════════════════════════════════╝

  [1] 安全升级（保留数据，更新镜像）
  [2] 重建容器（保留数据，重新配置端口/参数）
  [3] 查看运行状态
  [4] 查看实时日志
  [5] 卸载 OpenClaw
  [6] 退出

> _
```

### 5.4 Docker 安装向导完整步骤

```
Step 1/6  选择镜像源（官方版 / 中文版）
Step 2/6  选择版本（标签）
Step 3/6  配置端口
Step 4/6  配置访问方式（本地 / 远程服务器）
Step 5/6  预装基础环境（可选：Node / Python / Go）
Step 6/6  确认配置 → 执行安装
```

---

## 6. 模块规格

### 6.1 环境探测模块

脚本启动时静默探测，结果存为全局变量。

| 变量名 | 探测内容 | 探测方法 |
|--------|----------|----------|
| `ENV_OS` | 操作系统 | `uname -s` → `linux`/`macos` |
| `ENV_DISTRO` | Linux 发行版 | `/etc/os-release` → `ubuntu`/`debian`/`centos`/`rocky` |
| `ENV_ARCH` | CPU 架构 | `uname -m` → `amd64`/`arm64` |
| `ENV_1PANEL` | 1Panel 安装状态 | `which 1pctl` 或检测 `/opt/1panel` |
| `ENV_1PANEL_VERSION` | 1Panel 版本 | `1pctl version` |
| `ENV_DOCKER` | Docker 可用性 | `docker info 2>/dev/null` 返回码 |
| `ENV_DOCKER_VERSION` | Docker 版本 | `docker --version` |
| `ENV_DOCKER_COMPOSE` | Compose v2 可用性 | `docker compose version 2>/dev/null` |
| `ENV_NODE` | Node.js 版本 | `node --version 2>/dev/null` |
| `ENV_EXISTING_INSTALL` | 是否已安装 | 读取 `~/.openclaw-installer/config.env` |
| `ENV_OPENCLAW_RUNNING` | 容器运行状态 | `docker ps --filter name=openclaw --format '{{.Status}}'` |

---

### 6.2 镜像源选择模块

```
📦 Step 1/6：选择 OpenClaw 版本源

  [1] 🀄 中文汉化版（推荐）
      镜像：ghcr.io/1186258278/openclaw-zh
      ✓ Dashboard 完整汉化  ✓ 每小时同步官方  ✓ 中文引导文档

  [2] 🌐 官方原版（英文界面）
      镜像：ghcr.io/openclaw/openclaw
      ✓ 官方直接维护  ✓ 第一时间获取新功能

请选择 [1/2]（默认：1）: _
```

**输出变量：**

| 变量 | 中文版值 | 官方版值 |
|------|----------|----------|
| `CFG_SOURCE` | `chinese` | `official` |
| `CFG_IMAGE_BASE` | `ghcr.io/1186258278/openclaw-zh` | `ghcr.io/openclaw/openclaw` |
| `CFG_CONTAINER_USER` | `root` | `node` |
| `CFG_CONTAINER_HOME` | `/root` | `/home/node` |
| `CFG_NPM_PACKAGE` | `@qingchencloud/openclaw-zh` | `openclaw` |

---

### 6.3 版本选择模块

**中文版：**
```
📦 Step 2/6：选择版本（中文汉化版）

  [1] 🟢 稳定版 :latest     手动发布，经过测试，推荐生产
  [2] 🟡 最新版 :nightly    每小时同步，追踪官方最新功能

请选择 [1/2]（默认：1）: _
```

**官方版：**
```
📦 Step 2/6：选择版本（官方原版）

  [1] 🟢 最新稳定版 :latest     官方 stable 频道（推荐）
  [2] 🟡 最新测试版 :main        开发分支，功能最新，可能不稳定
  [3] 🔧 指定版本号              输入版本，如 2026.3.1

请选择 [1-3]（默认：1）: _
```

选 [3] 后：
```
请输入版本号（格式：YYYY.M.D）: _

正在验证版本是否存在... ✅ 2026.2.25 可用
```

版本验证（官方版）：
```bash
verify_official_version() {
  local ver=$1
  # arm64 架构使用专属标签
  local tag="${ver}"
  [ "$ENV_ARCH" = "arm64" ] && tag="${ver}-arm64"
  
  docker manifest inspect "ghcr.io/openclaw/openclaw:${tag}" &>/dev/null
  return $?
}
```

**输出变量：**

| 变量 | 示例值 |
|------|--------|
| `CFG_VERSION_TAG` | `nightly` / `latest` / `2026.3.1` |
| `CFG_DOCKER_IMAGE` | `ghcr.io/1186258278/openclaw-zh:nightly` |

---

### 6.4 端口配置模块

#### 设计原则

**主服务端口**：从 7100–7200 段自动扫描第一个空闲端口，避免与 18789 等常见 OpenClaw 端口被端口扫描器关联。

**预留备用端口**：compose 默认额外映射 3 个连续备用端口（主端口 +1/+2/+3），用于后续扩展（EasyClaw Web UI、自定义 webhook、调试接口等）。用户需要新增端口映射时，直接修改容器内服务监听端口即可，**无需重建容器**。

#### 端口扫描 UI

```
🔌 Step 3/8：配置访问端口

  正在扫描 7100-7200 段空闲端口...

  ✅ 自动选定端口：7134（空闲）

  主服务端口：7134                 （OpenClaw 网关）
  备用端口：  7135 / 7136 / 7137  （预留，容器重建前可自由使用）

  [回车] 使用推荐端口 7134
  [1]    手动指定端口
  [2]    查看所有空闲端口（7100-7200）
  
  选择: _
```

手动指定端口：
```
  请输入主服务端口（建议 7100-7200，也可用其他范围）: 7150
  检测端口 7150... ✅ 空闲
  备用端口自动设置为：7151 / 7152 / 7153
```

端口冲突处理：
```
  检测端口 7134... ❌ 被占用（sshd, PID 1234）
  检测端口 7135... ❌ 被占用（nginx, PID 5678）
  检测端口 7136... ✅ 空闲 → 自动选定
  备用端口：7137 / 7138 / 7139
```

#### 端口扫描函数

```bash
# 从指定范围扫描第一个空闲端口
find_free_port() {
  local start=${1:-7100}
  local end=${2:-7200}
  
  for port in $(seq "$start" "$end"); do
    if check_port "$port"; then
      echo "$port"
      return 0
    fi
  done
  
  # 整段都满了，降级到随机高位端口
  log_warn "7100-7200 端口段已全部占用，尝试随机高位端口..."
  for _ in $(seq 1 20); do
    local rport=$(( RANDOM % 10000 + 50000 ))
    if check_port "$rport"; then
      echo "$rport"
      return 0
    fi
  done
  return 1
}

check_port() {
  local port=$1
  # ss 优先（更快），fallback 到 netstat
  if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep -q ":${port} " && return 1
  elif command -v netstat &>/dev/null; then
    netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 1
  else
    # 最后兜底：尝试绑定
    (echo > /dev/tcp/localhost/$port) 2>/dev/null && return 1
  fi
  return 0
}

# 选定端口后，自动分配 3 个备用端口（跳过已占用的）
allocate_port_block() {
  local main_port=$1
  local reserved=()
  local candidate=$(( main_port + 1 ))
  
  while [ ${#reserved[@]} -lt 3 ]; do
    if check_port "$candidate"; then
      reserved+=("$candidate")
    fi
    (( candidate++ ))
    [ $candidate -gt 65535 ] && break
  done
  
  CFG_PORT_HOST="$main_port"
  CFG_PORT_RESERVED_1="${reserved[0]:-}"
  CFG_PORT_RESERVED_2="${reserved[1]:-}"
  CFG_PORT_RESERVED_3="${reserved[2]:-}"
}
```

#### compose 中的预留端口块

```yaml
ports:
  - "{{CFG_PORT_HOST}}:18789"          # OpenClaw 主服务
  # ── 预留备用端口（重建前可自由分配，无需修改此文件）──
  - "{{CFG_PORT_RESERVED_1}}:7201"     # 备用 1（默认未使用）
  - "{{CFG_PORT_RESERVED_2}}:7202"     # 备用 2（默认未使用）
  - "{{CFG_PORT_RESERVED_3}}:7203"     # 备用 3（默认未使用）
  {{#if CFG_EASYCLAW}}
  - "{{CFG_EASYCLAW_PORT}}:4231"       # EasyClaw Web UI
  {{/if}}
```

> **使用备用端口的方式**：若需要在容器内启动一个新服务（如自定义 webhook），只需让新服务监听 `7201`，宿主机 `CFG_PORT_RESERVED_1` 端口即可访问，无需 `docker-compose up --force-recreate`。

---

### 6.5 访问方式配置模块

```
🌐 Step 4/6：配置访问方式

  [1] 本地访问（只在本机浏览器访问 Dashboard）
      gateway.bind = loopback
      访问地址：http://127.0.0.1:18789

  [2] 远程访问（从其他电脑/手机访问 Dashboard）⭐ 服务器推荐
      gateway.bind = lan
      需要设置访问 Token（安全认证）

请选择 [1/2]（默认：2，服务器场景推荐远程）: _
```

选择 [2] 后：
```
🔐 设置访问 Token（用于 Dashboard 登录认证）

  Token 将写入容器配置，Dashboard 连接时需要输入。
  
  请输入 Token（留空自动生成随机 Token）: _
  
  自动生成 Token：abc123xyz...（已复制到 config.env）
```

```bash
generate_token() {
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32
}
```

**输出变量：**

| 变量 | 本地值 | 远程值 |
|------|--------|--------|
| `CFG_ACCESS_MODE` | `local` | `remote` |
| `CFG_GATEWAY_BIND` | `loopback` | `lan` |
| `CFG_AUTH_TOKEN` | `""` | `<token>` |

---

### 6.6 预装基础环境模块

```
⚙️ Step 5/6：预装基础开发环境（可选）

  以下环境将安装在容器内，持久化到 Named Volume，重建后保留：

  [ ] Node.js 22 + npm（通过 nvm）
  [ ] Python 3 + uv
  [ ] Go 1.22+
  [ ] 全部跳过（默认）

  空格选择，回车确认: _
```

---

### 6.7 安装确认与执行模块

```
✅ Step 8/8：确认安装配置

  ┌──────────────────────────────────────────────────────┐
  │  版本源：中文汉化版                                    │
  │  镜像：  ghcr.io/1186258278/openclaw-zh:nightly      │
  │  访问方式：远程（Token 认证）                          │
  │                                                        │
  │  端口分配：                                            │
  │    主服务：    7134  →  容器 18789                    │
  │    备用 1：    7135  →  容器 7201（预留）              │
  │    备用 2：    7136  →  容器 7202（预留）              │
  │    备用 3：    7137  →  容器 7203（预留）              │
  │    EasyClaw：  7138  →  容器 4231                     │
  │                                                        │
  │  预装环境：Node.js 22、Python 3                       │
  │  预装软件：GitHub CLI、Claude Code CLI                │
  │  预装 Skill：obsidian-skills                          │
  │  数据目录：  ~/.openclaw/                             │
  └──────────────────────────────────────────────────────┘

  确认以上配置并开始安装？[Y/n]: _
```

**执行序列：**
```
[1/8] 初始化宿主机目录...                ✅
[2/8] 拉取 Docker 镜像...               ⏳ 142MB/350MB
[3/8] 生成 docker-compose.yml...        ✅
[4/8] 启动容器...                        ✅
[5/8] 健康检查（等待就绪）...            ✅ (12s)
[6/8] 安装预装环境（Node 22）...         ✅
[7/8] 安装预装软件（gh, claude）...      ✅
[8/8] 安装 Skill（obsidian-skills）...  ✅
```

**安装完成后，输出部署汇总卡（见 6.9 节），然后将汇总信息写入本地文件。**

---

### 6.8 操作执行模块

#### 6.8.1 安全升级（upgrade）

```bash
action_upgrade() {
  # 1. 读取当前配置
  source ~/.openclaw-installer/config.env
  
  # 2. 查询最新版本
  local latest=$(get_latest_tag "$CFG_SOURCE" "$CFG_VERSION_CHANNEL")
  
  # 3. 比较版本
  if [ "$latest" = "$CFG_VERSION_TAG" ]; then
    echo "✅ 已是最新版本 ($CFG_VERSION_TAG)"
    return 0
  fi
  
  echo "发现新版本：$CFG_VERSION_TAG → $latest"
  confirm "确认升级？" || return 1
  
  # 4. 后台拉取新镜像（不停服）
  docker pull "${CFG_IMAGE_BASE}:${latest}"
  
  # 5. 停服 → 替换 → 启动
  docker compose -f "$COMPOSE_FILE" stop
  # 更新 compose 中的 image tag
  sed -i "s|:${CFG_VERSION_TAG}|:${latest}|" "$COMPOSE_FILE"
  docker compose -f "$COMPOSE_FILE" up -d
  
  # 6. 健康检查
  wait_healthy 60
  
  # 7. 更新 config.env
  sed -i "s/CFG_VERSION_TAG=.*/CFG_VERSION_TAG=\"${latest}\"/" \
    ~/.openclaw-installer/config.env
    
  echo "✅ 升级完成：$latest"
}
```

#### 6.8.2 重建容器（rebuild）

**场景**：修改端口、切换访问方式、增删预装环境，不升级版本，数据完整保留。

```
当前配置：
  端口：{{CFG_PORT_HOST}}  访问方式：本地  预装：无

选择要修改的项：
  [1] 修改端口
  [2] 切换访问方式（本地/远程）
  [3] 添加/修改 Token
  [4] 管理预装环境
  [5] 确认重建（保留以上未修改项）
  [6] 取消
```

执行：
```bash
# docker compose down 仅停容器，不删 volume（关键！）
docker compose -f "$COMPOSE_FILE" down
# 重新生成 compose 文件
generate_compose_file
# 重启
docker compose -f "$COMPOSE_FILE" up -d
```

#### 6.8.3 卸载（uninstall）

```
⚠️  卸载 OpenClaw

  [1] 仅停止并删除容器（保留所有数据）
  [2] 完全卸载（删除容器 + 所有数据目录 ~/.openclaw/）

  选择卸载级别 [1-3]: _
```

选择 [3] 后强制二次确认：
```
⚠️  此操作将删除以下内容，且不可恢复：
    - OpenClaw 容器和 Docker 镜像
    - ~/.openclaw/ 目录（配置、凭据、runtime、工作区、所有数据）

请输入 "CONFIRM DELETE" 确认: _
```

---

### 6.9 部署完成汇总卡

#### 设计原则

安装/升级/重建完成后，脚本统一输出一张**部署汇总卡**，在终端高亮显示，
同时将完整信息写入 `~/.openclaw-installer/deployment-info.txt`，
确保用户随时可以查看，不被 Docker 拉取日志或安装进度淹没。

#### 终端输出样式

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🎉  OpenClaw 部署完成！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ▌ 访问信息

    Dashboard：  http://123.45.67.89:7134
    本地访问：   http://localhost:7134
    连接 Token： oc_tk_AbCd1234XyZ...（点击复制）

  ▌ 端口分配

    主服务：    7134 → 容器 18789  ✅ 运行中
    备用 1：    7135 → 容器 7201   （未使用，可自由分配）
    备用 2：    7136 → 容器 7202   （未使用，可自由分配）
    备用 3：    7137 → 容器 7203   （未使用，可自由分配）
    EasyClaw：  7138 → 容器 4231   ✅ 运行中

  ▌ 安装详情

    版本：      ghcr.io/1186258278/openclaw-zh:nightly
    数据目录：  ~/.openclaw/
    预装环境：  Node.js 22 ✅  Python 3.12 ✅
    预装软件：  gh ✅  claude ✅
    Skill：     obsidian-skills ✅

  ▌ 管理命令

    再次运行安装脚本：  bash openclaw-install.sh
    查看容器日志：      docker logs -f openclaw
    进入容器：          docker exec -it openclaw bash
    EasyClaw TUI：      docker exec -it openclaw easyclaw tui

  ▌ 完整信息已保存至：~/.openclaw-installer/deployment-info.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### deployment-info.txt 写入函数

每次安装/升级/重建后均覆盖写入，记录最新状态：

```bash
write_deployment_info() {
  local server_ip
  server_ip=$(curl -sf --max-time 3 https://api.ipify.org 2>/dev/null               || ip route get 1 | awk '{print $7; exit}' 2>/dev/null               || echo "未能获取 IP")

  local install_time
  install_time=$(date "+%Y-%m-%d %H:%M:%S %Z")

  local info_file="$HOME/.openclaw-installer/deployment-info.txt"
  
  cat > "$info_file" << EOF
OpenClaw 部署信息
生成时间：${install_time}
═══════════════════════════════════════════════════════════

【访问信息】
  Dashboard：  http://${server_ip}:${CFG_PORT_HOST}
  本地访问：   http://localhost:${CFG_PORT_HOST}
  连接 Token： ${CFG_AUTH_TOKEN}

【端口分配】
  主服务：    ${CFG_PORT_HOST} → 容器 18789
  备用 1：    ${CFG_PORT_RESERVED_1:-未分配} → 容器 7201
  备用 2：    ${CFG_PORT_RESERVED_2:-未分配} → 容器 7202
  备用 3：    ${CFG_PORT_RESERVED_3:-未分配} → 容器 7203
$([ -n "$CFG_EASYCLAW_PORT" ] && echo "  EasyClaw：  ${CFG_EASYCLAW_PORT} → 容器 4231")

【安装详情】
  版本：      ${CFG_DOCKER_IMAGE}
  数据目录：  ~/.openclaw/
  安装日期：  ${install_time}
  安装类型：  ${INSTALL_ACTION:-full}

【预装环境】
  Node.js：   $(docker exec openclaw bash -c 'source $NVM_DIR/nvm.sh 2>/dev/null && node --version 2>/dev/null' || echo "未安装")
  Python：    $(docker exec openclaw python3 --version 2>/dev/null || echo "未安装")
  Go：        $(docker exec openclaw go version 2>/dev/null | awk '{print $3}' || echo "未安装")

【管理命令】
  再次运行：  bash ${SCRIPT_PATH:-openclaw-install.sh}
  查看日志：  docker logs -f openclaw
  进入容器：  docker exec -it openclaw bash
  EasyClaw：  docker exec -it openclaw easyclaw tui（若已安装）

【相关文件】
  Compose：   ~/.openclaw-installer/docker-compose.yml
  配置：      ~/.openclaw-installer/config.env
  此文件：    ${info_file}

═══════════════════════════════════════════════════════════
EOF

  # 终端显示汇总卡（高亮分隔线）
  echo ""
  echo "$(tput bold 2>/dev/null)$(printf '%.0s━' {1..65})$(tput sgr0 2>/dev/null)"
  echo ""
  echo "  🎉  OpenClaw 部署完成！"
  echo ""
  echo "$(tput bold 2>/dev/null)$(printf '%.0s━' {1..65})$(tput sgr0 2>/dev/null)"
  echo ""
  echo "  Dashboard：  http://${server_ip}:${CFG_PORT_HOST}"
  echo "  Token：      ${CFG_AUTH_TOKEN}"
  echo ""
  echo "  端口分配："
  echo "    主服务  ${CFG_PORT_HOST} → 18789"
  [ -n "$CFG_PORT_RESERVED_1" ] && echo "    备用 1  ${CFG_PORT_RESERVED_1} → 7201 （可自由分配）"
  [ -n "$CFG_PORT_RESERVED_2" ] && echo "    备用 2  ${CFG_PORT_RESERVED_2} → 7202 （可自由分配）"
  [ -n "$CFG_PORT_RESERVED_3" ] && echo "    备用 3  ${CFG_PORT_RESERVED_3} → 7203 （可自由分配）"
  [ -n "$CFG_EASYCLAW_PORT"   ] && echo "    EasyClaw ${CFG_EASYCLAW_PORT} → 4231"
  echo ""
  echo "  完整信息已保存：${info_file}"
  echo ""
  echo "  管理：再次运行此脚本  |  日志：docker logs -f openclaw"
  echo ""
  echo "$(tput bold 2>/dev/null)$(printf '%.0s━' {1..65})$(tput sgr0 2>/dev/null)"
  echo ""
}
```

#### 触发时机

| 操作 | 是否写入 deployment-info.txt |
|------|------------------------------|
| 全新安装完成 | ✅ 写入 |
| 安全升级完成 | ✅ 覆盖写入（更新版本信息） |
| 重建容器完成 | ✅ 覆盖写入（更新端口/环境信息） |
| 接管外部安装后 | ✅ 写入（首次生成） |
| 安装失败/中断 | ❌ 不写入（不生成残缺信息） |

#### 查看历史信息

用户随时可通过管理菜单查看：

```
  [5] 查看部署信息
  
  → cat ~/.openclaw-installer/deployment-info.txt
```

或通过快捷命令：
```bash
openclaw info   # 若脚本已添加到 PATH（可选）
```

---

### 6.10 1Panel 集成模块

**设计原则**：我们提供比 1Panel App Store 更多控制权——自定义端口、自定义 volume 路径、选择版本源和版本号。

#### 6.9.1 探测到 1Panel 后的安装菜单

```
✅ 检测到 1Panel v2.x

  推荐使用 1Panel 安装，可在面板图形界面管理容器生命周期，
  同时支持自定义端口、版本和持久化路径。

选择 1Panel 集成方式：
  [1] API 自动安装（全自动，需提供 1Panel API Token）
  [2] 生成 Compose 文件（手动在 1Panel 导入，5 步操作）

> _
```

#### 6.9.2 API 自动安装模式

**获取 Token 引导：**
```
请在 1Panel 获取 API Token：
  1. 登录 1Panel → 点击右上角头像 → 个人中心
  2. 找到「API 密钥」→ 新建密钥
  3. 复制密钥粘贴到下方

1Panel 地址（默认：http://localhost:28888）: _
API Token: _
```

**验证并创建应用：**
```bash
create_1panel_app_via_api() {
  local api_base=$1
  local token=$2
  local compose_yaml=$3
  
  # 验证 Token
  local check=$(curl -sf -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${token}" \
    "${api_base}/api/v1/users/profile")
  [ "$check" != "200" ] && { echo "❌ Token 验证失败"; return 1; }
  
  # 创建 Compose 应用
  curl -sf -X POST "${api_base}/api/v1/containers/compose" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"openclaw\",
      \"file\": $(echo "$compose_yaml" | jq -Rs .),
      \"description\": \"OpenClaw AI 助手 - 由 openclaw-install.sh 创建\"
    }" | jq -r '.message'
}
```

> ⚠️ **待确认**：1Panel API 接口路径和请求格式需根据实际 1Panel 版本验证（见 Q1）。

#### 6.9.3 Compose 文件生成模式

```
✅ docker-compose.yml 已生成到：
   /opt/openclaw/docker-compose.yml

在 1Panel 中导入步骤：
  1. 打开 1Panel → 容器 → Compose
  2. 点击「创建」→「从文件上传」
  3. 上传：/opt/openclaw/docker-compose.yml
  4. 点击「部署」

按任意键继续...
```

---

## 7. 目录与路径规范

### 7.1 宿主机目录结构

**核心设计：单一 Bind Mount，覆盖全部持久化需求。**

```
$HOME/
├── .openclaw/                       # ★ 唯一 bind mount 根目录
│   ├── openclaw.json                # 主配置文件
│   ├── openclaw.json.bak.*          # 自动备份
│   ├── credentials/                 # 渠道认证凭据
│   │   ├── whatsapp-session.json
│   │   └── telegram-token.enc
│   ├── workspace/                   # 工作区（统一移入 .openclaw）
│   │   ├── AGENTS.md
│   │   ├── SOUL.md
│   │   ├── TOOLS.md
│   │   └── skills/                  # Skill 安装目录
│   │       ├── obsidian-skills/
│   │       └── security-checker/
│   ├── runtime/                     # 开发运行时（替代 Named Volume）
│   │   ├── nvm/                     # Node.js via nvm
│   │   ├── python/                  # Python via uv/pip
│   │   └── go/                      # Go
│   ├── software/                    # 预装工具（gh/claude/opencode 等）
│   │   ├── bin/                     # 二进制和 wrapper 脚本
│   │   └── lib/node_modules/        # npm global packages
│   └── logs/                        # 运行日志
│
└── .openclaw-installer/             # 安装脚本状态目录
    ├── config.env                   # 安装参数记录
    ├── docker-compose.yml           # 当前生效的 compose 文件
    └── install.log                  # 安装历史日志
```

**为什么废弃 `~/openclaw/workspace/` 独立路径？**

原官方规范把 workspace 放在 `~/openclaw/workspace/`（非隐藏），但这要求两条 bind mount。
将 workspace 统一移入 `~/.openclaw/workspace/`，单条挂载即可覆盖所有数据，
且中文版容器内路径 `/root/.openclaw/workspace/` 与此完全对应。

### 7.2 容器内路径（按版本区分）

单条 bind mount `~/.openclaw/ → <容器 home>/.openclaw/`，所有子路径自动对齐：

| 位置 | 官方版（node 用户） | 中文版（root 用户） |
|------|---------------------|---------------------|
| bind mount 根 | `/home/node/.openclaw/` | `/root/.openclaw/` |
| 工作区 | `/home/node/.openclaw/workspace/` | `/root/.openclaw/workspace/` |
| nvm | `/home/node/.openclaw/runtime/nvm/` | `/root/.openclaw/runtime/nvm/` |
| Python | `/home/node/.openclaw/runtime/python/` | `/root/.openclaw/runtime/python/` |
| Go | `/home/node/.openclaw/runtime/go/` | `/root/.openclaw/runtime/go/` |
| 预装软件 | `/home/node/.openclaw/software/` | `/root/.openclaw/software/` |

版本切换时，宿主机数据路径不变，只是容器内前缀从 `/home/node/` 变为 `/root/`。
nvm 等工具通过 compose 中的 `NVM_DIR` 环境变量指向正确路径，无硬编码依赖。

### 7.3 目录初始化脚本

```bash
init_host_directories() {
  local dirs=(
    "$HOME/.openclaw"
    "$HOME/.openclaw/credentials"
    "$HOME/.openclaw/logs"
    "$HOME/.openclaw/workspace"
    "$HOME/.openclaw/workspace/skills"
    "$HOME/.openclaw/runtime"
    "$HOME/.openclaw/runtime/nvm"
    "$HOME/.openclaw/runtime/python"
    "$HOME/.openclaw/runtime/go"
    "$HOME/.openclaw/software"
    "$HOME/.openclaw/software/bin"
    "$HOME/.openclaw-installer"
  )
  
  for dir in "${dirs[@]}"; do
    if mkdir -p "$dir" 2>/dev/null; then
      [ "$dir" = "$HOME/.openclaw" ] && chmod 700 "$dir"
      [ "$dir" = "$HOME/.openclaw/credentials" ] && chmod 700 "$dir"
    else
      log_error "无法创建目录：$dir（请检查权限）"
      return 1
    fi
  done
  
  log_success "目录结构初始化完成"
}
```

---

## 8. Volume 持久化设计

### 8.1 持久化策略（v0.5 重新设计：零 Named Volume）

**核心决策**：废弃 Named Volume，所有数据统一放在 `~/.openclaw/` 下，单条 Bind Mount 覆盖全部。

| 数据类型 | 挂载方式 | 宿主机路径 | 原因 |
|----------|----------|------------|------|
| 配置文件 / 凭据 | **Bind Mount** | `~/.openclaw/` | 宿主机直接可见可编辑 |
| 工作区 | **Bind Mount** (同上) | `~/.openclaw/workspace/` | 统一在单一 mount 内 |
| Node/npm 环境 | **Bind Mount** (同上) | `~/.openclaw/runtime/nvm/` | 消除 Named Volume，简化管理 |
| Python/uv 环境 | **Bind Mount** (同上) | `~/.openclaw/runtime/python/` | 同上 |
| Go 环境 | **Bind Mount** (同上) | `~/.openclaw/runtime/go/` | 同上 |
| 预装软件 | **Bind Mount** (同上) | `~/.openclaw/software/` | 同上 |

**与 Named Volume 方案对比：**

| 维度 | Named Volume 方案 | 单一 Bind Mount 方案（当前）|
|------|-------------------|---------------------------|
| 挂载数量 | 5+ 条 | **1 条** |
| 版本切换迁移 | 需 chown Volume | **无需操作** |
| 宿主机可见性 | Volume 不可直接浏览 | **全部可见** |
| 备份方式 | 需 docker volume export | **直接 tar ~/.openclaw** |
| 接管外部安装 | 需迁移 Volume | **只需确认 bind mount 路径** |

### 8.2 docker-compose.yml 生成模板

脚本根据所选镜像源（`CFG_SOURCE`）生成对应的容器内路径映射：

#### 中文版 compose（`CFG_SOURCE=chinese`）

```yaml
# 由 openclaw-install.sh 自动生成
# 生成时间：{{GENERATE_TIME}}
# 版本源：中文汉化版

version: "3.8"

services:
  openclaw:
    image: ghcr.io/1186258278/openclaw-zh:{{CFG_VERSION_TAG}}
    container_name: openclaw
    restart: unless-stopped
    ports:
      - "{{CFG_PORT_HOST}}:18789"
      {{#if CFG_EASYCLAW}}
      - "{{CFG_EASYCLAW_PORT}}:4231"
      {{/if}}
    volumes:
      # ★ 单条 Bind Mount 覆盖全部持久化（配置/工作区/runtime/软件）
      - ~/.openclaw:/root/.openclaw
    environment:
      {{#if CFG_AUTH_TOKEN}}
      - OPENCLAW_GATEWAY_TOKEN={{CFG_AUTH_TOKEN}}
      {{/if}}
      # runtime PATH 注入（根据所选环境动态生成）
      - PATH=/root/.openclaw/software/bin:/root/.openclaw/runtime/nvm/versions/node/current/bin:/root/.openclaw/runtime/python/bin:/root/.openclaw/runtime/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      - NVM_DIR=/root/.openclaw/runtime/nvm
      - GOPATH=/root/.openclaw/runtime/go
      - NPM_CONFIG_PREFIX=/root/.openclaw/software
      {{#if CFG_ENV_PYTHON}}
      - PYTHONPATH=/root/.openclaw/runtime/python/lib
      - UV_PYTHON_INSTALL_DIR=/root/.openclaw/runtime/python
      {{/if}}
    command: openclaw gateway run
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:18789/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  openclaw-cli:
    image: ghcr.io/1186258278/openclaw-zh:{{CFG_VERSION_TAG}}
    volumes:
      - ~/.openclaw:/root/.openclaw
    environment:
      - NVM_DIR=/root/.openclaw/runtime/nvm
      - GOPATH=/root/.openclaw/runtime/go
      - NPM_CONFIG_PREFIX=/root/.openclaw/software
    profiles: ["cli"]
# ★ 无 Named Volumes —— 所有数据均在 bind mount 内
```

#### 官方版 compose（`CFG_SOURCE=official`）

```yaml
# 由 openclaw-install.sh 自动生成
# 版本源：官方原版

version: "3.8"

services:
  openclaw:
    image: ghcr.io/openclaw/openclaw:{{CFG_VERSION_TAG}}
    container_name: openclaw
    restart: unless-stopped
    ports:
      - "{{CFG_PORT_HOST}}:18789"
      {{#if CFG_EASYCLAW}}
      - "{{CFG_EASYCLAW_PORT}}:4231"
      {{/if}}
    volumes:
      # ★ 单条 Bind Mount — 映射到 node 用户家目录下的 .openclaw
      - ~/.openclaw:/home/node/.openclaw
    environment:
      {{#if CFG_AUTH_TOKEN}}
      - OPENCLAW_GATEWAY_TOKEN={{CFG_AUTH_TOKEN}}
      {{/if}}
      # runtime PATH（与中文版对称，只是前缀不同）
      - PATH=/home/node/.openclaw/software/bin:/home/node/.openclaw/runtime/nvm/versions/node/current/bin:/home/node/.openclaw/runtime/python/bin:/home/node/.openclaw/runtime/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      - NVM_DIR=/home/node/.openclaw/runtime/nvm
      - GOPATH=/home/node/.openclaw/runtime/go
      - NPM_CONFIG_PREFIX=/home/node/.openclaw/software
      {{#if CFG_ENV_PYTHON}}
      - PYTHONPATH=/home/node/.openclaw/runtime/python/lib
      - UV_PYTHON_INSTALL_DIR=/home/node/.openclaw/runtime/python
      {{/if}}
    command: openclaw gateway run
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:18789/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  openclaw-cli:
    image: ghcr.io/openclaw/openclaw:{{CFG_VERSION_TAG}}
    volumes:
      - ~/.openclaw:/home/node/.openclaw
    environment:
      - NVM_DIR=/home/node/.openclaw/runtime/nvm
      - NPM_CONFIG_PREFIX=/home/node/.openclaw/software
    profiles: ["cli"]
# ★ 无 Named Volumes
```

### 8.3 初始化配置命令序列

```bash
run_openclaw_setup() {
  local image=$1
  local config_mount=$2       # 官方版：/home/node/.openclaw；中文版：/root/.openclaw
  # workspace 已在 config_mount 下（/root/.openclaw/workspace），无需单独参数

  log_info "正在初始化 OpenClaw 配置..."
  
  # Step 1: 运行 setup 向导（-T 禁用 pseudo-TTY，适合脚本调用）
  docker run --rm -it \
    -v "$HOME/.openclaw:${config_mount}" \
    -v "$HOME/openclaw/workspace:${workspace_mount}" \
    "$image" openclaw setup
    
  # Step 2: 配置 gateway.mode
  docker run --rm \
    -v "$HOME/.openclaw:${config_mount}" \
    "$image" openclaw config set gateway.mode local

  # Step 3: 配置远程访问（如需要）
  if [ "$CFG_ACCESS_MODE" = "remote" ]; then
    docker run --rm \
      -v "$HOME/.openclaw:${config_mount}" \
      "$image" openclaw config set gateway.bind lan
    
    docker run --rm \
      -v "$HOME/.openclaw:${config_mount}" \
      "$image" openclaw config set gateway.auth.token "$CFG_AUTH_TOKEN"
  fi
}
```

---

## 9. 配置文件规范

### 9.1 config.env 格式

```bash
# ~/.openclaw-installer/config.env
# 由 openclaw-install.sh 自动生成，请勿手动修改

INSTALL_DATE="2026-03-02T10:30:00"
INSTALLER_VERSION="1.0.0"

# 版本配置
CFG_SOURCE="chinese"                              # chinese / official
CFG_IMAGE_BASE="ghcr.io/1186258278/openclaw-zh"
CFG_DOCKER_IMAGE="ghcr.io/1186258278/openclaw-zh:nightly"
CFG_VERSION_TAG="nightly"
CFG_VERSION_CHANNEL="nightly"                    # nightly/latest/main/specified
CFG_INSTALL_MODE="docker"                        # docker / npm / 1panel-api / 1panel-compose
CFG_CONTAINER_USER="root"                        # root（中文版）/ node（官方版）

# 容器内路径（根据镜像用户自动设置）
CFG_CONTAINER_CONFIG_PATH="/root/.openclaw"
CFG_CONTAINER_WORKSPACE_PATH="/root/.openclaw/workspace"

# 网络配置
CFG_PORT_HOST="7134"   # 由脚本自动从 7100-7200 段选取
CFG_ACCESS_MODE="remote"                         # local / remote
CFG_GATEWAY_BIND="lan"
CFG_AUTH_TOKEN="abc123xyz456..."

# 预装配置
CFG_ENV_NODE="true"
CFG_ENV_PYTHON="false"
CFG_ENV_GO="false"

# 运行时信息
CONTAINER_NAME="openclaw"
COMPOSE_FILE="$HOME/.openclaw-installer/docker-compose.yml"
```

### 9.2 openclaw.json 最小配置

```json
{
  "agent": {
    "model": "anthropic/claude-opus-4-6"
  },
  "gateway": {
    "mode": "local",
    "bind": "lan",
    "auth": {
      "token": "your-secure-token"
    }
  }
}
```

---

## 10. 错误处理规范

### 10.1 错误分级

| 级别 | 标识 | 行为 |
|------|------|------|
| FATAL | 🔴 | 输出原因 + 修复建议，退出脚本 |
| ERROR | 🟠 | 输出原因，提供重试选项，可继续 |
| WARN | 🟡 | 输出警告，继续执行 |
| INFO | 🔵 | 普通日志 |
| SUCCESS | 🟢 | 操作成功 |

### 10.2 常见错误处理清单

| 错误场景 | 检测方式 | 用户提示 |
|----------|----------|----------|
| Docker 未安装 | `docker --version` 失败 | 显示对应发行版安装命令 |
| Docker 权限不足 | `docker info` 返回 permission denied | 提示 `sudo usermod -aG docker $USER` 并告知需重新登录 |
| Docker Compose v1（旧版） | `docker-compose version` 存在但 `docker compose version` 不存在 | 提示升级到 Compose v2 |
| 端口被占用 | `ss -tlnp` 检测 | 显示占用进程名和 PID，引导换端口 |
| 镜像拉取失败（GHCR 网络） | `docker pull` 超时 | 提示配置 Docker 镜像加速，给出常见加速器配置命令 |
| GHCR 认证错误 | `docker pull` 返回 unauthorized | 提示 `docker logout ghcr.io` 后重试 |
| 容器启动后健康检查失败 | healthcheck 超时 | 自动显示容器日志最后 30 行，列出常见原因 |
| 配置初始化失败 | `openclaw setup` 返回非 0 | 保留错误输出，提供重试选项 |
| 1Panel API Token 错误 | HTTP 401/403 | 提示重新获取 Token 步骤 |
| 1Panel API 接口路径不符 | 返回 404 | 提示 1Panel 版本可能不兼容，引导用 Compose 模式 |
| Node.js 版本 < 22（npm 安装） | `node -v` < 22 | 提示通过 nvm 安装 Node 22 |
| 磁盘空间不足 | `df -h` | 提示至少需要 5GB 可用空间（官方镜像约 4GB） |
| 升级时镜像拉取中断 | `docker pull` 失败 | 保留旧镜像，容器不中断，提示重试 |
| 重建时容器不存在 | `docker ps` 无结果 | 直接执行新装流程，不报错退出 |
| arm64 指定版本无专属标签 | `docker manifest inspect` 失败 | 提示该版本可能无 arm64 预构建，建议用 `latest` |

---

## 11. 回归测试矩阵

### 11.1 环境矩阵

| 环境 ID | 操作系统 | 架构 | Docker | 1Panel | 优先级 |
|---------|----------|------|--------|--------|--------|
| E01 | Ubuntu 22.04 | amd64 | 27.x | ✅ | **P0** |
| E02 | Ubuntu 22.04 | amd64 | 27.x | ❌ | **P0** |
| E03 | Ubuntu 24.04 | amd64 | 27.x | ❌ | **P0** |
| E04 | Debian 12 | amd64 | 27.x | ❌ | P1 |
| E05 | Rocky Linux 8 | amd64 | 27.x | ❌ | P1 |
| E06 | Ubuntu 22.04 | arm64 | 27.x | ❌ | P1 |
| E07 | macOS 14 (Sonoma) | arm64 | Desktop | ❌ | P2 |

### 11.2 核心功能测试用例

#### TC-INSTALL：安装测试

| 用例 ID | 安装方式 | 版本源 | 版本 | 访问模式 | 预装环境 | 期望结果 |
|---------|----------|--------|------|----------|----------|----------|
| TC-I001 | Docker | 中文版 | nightly | 本地 | 无 | 容器运行，Dashboard 可访问 |
| TC-I002 | Docker | 中文版 | latest | 远程 | 无 | Token 认证正常，从其他机器可连接 |
| TC-I003 | Docker | 官方版 | latest | 本地 | 无 | 官方镜像正常运行，路径映射正确 |
| TC-I004 | Docker | 官方版 | 2026.3.1 | 本地 | 无 | 指定版本正确拉取 |
| TC-I005 | Docker | 中文版 | nightly | 本地 | Node 22 | node 命令在容器内可用 |
| TC-I006 | Docker | 中文版 | nightly | 本地 | Python+uv | python3、uv 在容器内可用 |
| TC-I007 | Docker | 官方版 | latest | 本地 | Node 22 | 官方版 node 用户路径下 node 可用 |
| TC-I008 | Docker | 中文版 | nightly | 本地 | 无 | 自定义端口 18888 可访问 |
| TC-I009 | Docker | 中文版 | nightly | 本地 | 无 | 端口冲突检测，提示换端口 |
| TC-I010 | 1Panel API | 中文版 | nightly | 远程 | 无 | 1Panel 中出现 openclaw 应用 |
| TC-I011 | 1Panel Compose | 中文版 | nightly | 远程 | 无 | 生成 compose 文件，路径正确 |
| TC-I012 | npm | - | latest | 本地 | - | openclaw 命令可用，版本正确 |

#### TC-PATH：路径兼容性测试

| 用例 ID | 场景 | 期望结果 |
|---------|------|----------|
| TC-PA001 | 中文版：宿主机 `~/openclaw/workspace/AGENTS.md` | 容器内 `/root/.openclaw/workspace/AGENTS.md` 可读 |
| TC-PA002 | 官方版：宿主机 `~/openclaw/workspace/AGENTS.md` | 容器内 `/home/node/openclaw/workspace/AGENTS.md` 可读 |
| TC-PA003 | 中文版：容器内写文件到 `/root/.openclaw/workspace/` | 宿主机 `~/openclaw/workspace/` 下可见 |
| TC-PA004 | 官方版：容器内写文件到 `/home/node/openclaw/workspace/` | 宿主机 `~/openclaw/workspace/` 下可见 |
| TC-PA005 | 中文版：credentials 路径 | 宿主机 `~/.openclaw/credentials/` ↔ 容器 `/root/.openclaw/credentials/` |
| TC-PA006 | 官方版：credentials 路径 | 宿主机 `~/.openclaw/credentials/` ↔ 容器 `/home/node/.openclaw/credentials/` |

#### TC-PERSIST：持久化测试

| 用例 ID | 操作序列 | 期望结果 |
|---------|----------|----------|
| TC-P001 | 写配置 → 重建容器 → 读配置 | 配置一致 |
| TC-P002 | 配置 Telegram → 重建容器 | Telegram 不需要重新登录 |
| TC-P003 | 安装 Node 环境 → 重建容器 | `node` 命令仍可用 |
| TC-P004 | 创建 workspace 文件 → 升级镜像 → 检查文件 | 文件存在且内容完整 |
| TC-P005 | 宿主机重启 | 容器 60 秒内自动恢复（restart: unless-stopped） |
| TC-P006 | 中文版 → 重建为官方版（版本切换） | 工作区文件保留，配置需重新初始化（预期行为，需在 UI 中说明） |

#### TC-UPGRADE：升级测试

| 用例 ID | 场景 | 期望结果 |
|---------|------|----------|
| TC-U001 | 中文版 nightly 升级 | 镜像更新，服务恢复，数据完整 |
| TC-U002 | 官方版 latest 升级 | 同上 |
| TC-U003 | 已是最新版 | 提示已是最新，不操作 |
| TC-U004 | 升级中网络中断 | 保留旧镜像，服务不中断 |
| TC-U005 | credentials 升级后保留 | 已配置渠道不需重新登录 |

#### TC-REBUILD：重建测试

| 用例 ID | 变更内容 | 期望结果 |
|---------|----------|----------|
| TC-R001 | 端口 18789 → 18888 | 新端口生效，数据完整 |
| TC-R002 | 本地 → 远程（加 Token） | bind=lan，token 写入配置 |
| TC-R003 | 新增 Python 环境 | Python 可用，Node 仍可用（如已装） |
| TC-R004 | 不变更任何项，直接重建 | 容器重启，数据完整 |

#### TC-UNINSTALL：卸载测试

| 用例 ID | 级别 | 确认方式 | 期望结果 |
|---------|------|----------|----------|
| TC-X001 | Level 1（仅删容器） | Y 确认 | 容器消失，~/.openclaw 保留 |
| TC-X002 | Level 2（容器+Volume） | Y 确认 | Named Volumes 删除，目录保留 |
| TC-X003 | Level 3（完全卸载） | 输入 "CONFIRM DELETE" | 所有数据删除 |
| TC-X004 | Level 3 后重装 | - | 全新安装，无残留 |
| TC-X005 | 取消卸载（Level 3） | 不输入确认 | 取消，数据完整 |

#### TC-ERROR：错误处理测试

| 用例 ID | 触发场景 | 期望提示 |
|---------|----------|----------|
| TC-E001 | Docker 未安装 | 显示发行版对应安装命令 |
| TC-E002 | docker compose v1（旧版） | 提示升级方法 |
| TC-E003 | 端口已占用 | 显示占用进程，引导换端口 |
| TC-E004 | GHCR 拉取超时 | 提示配置镜像加速，给出命令 |
| TC-E005 | 1Panel Token 错误 | 提示重新获取 Token 步骤 |
| TC-E006 | 1Panel 版本不兼容（API 404） | 提示切换到 Compose 模式 |
| TC-E007 | arm64 指定版本无专属标签 | 提示使用 latest，或 pull 通用标签 |
| TC-E008 | 容器健康检查失败 | 显示日志最后 30 行 + 常见原因 |
| TC-E009 | 磁盘空间 < 5GB | 提示清理空间或更换目录 |

#### TC-1PANEL：1Panel 集成测试

| 用例 ID | 方式 | 场景 | 期望结果 |
|---------|------|------|----------|
| TC-1P001 | API 模式 | Token 正确 | 1Panel 中出现 openclaw 应用，状态运行中 |
| TC-1P002 | API 模式 | Token 错误 | 提示 401，引导重新获取 |
| TC-1P003 | API 模式 | 1Panel 离线 | 提示连接失败，切换到 Compose 模式 |
| TC-1P004 | Compose 模式 | 正常 | 生成 compose 文件，显示导入步骤 |
| TC-1P005 | API 模式 | 已存在同名应用 | 提示冲突，询问是否覆盖 |

### 11.3 每次发布前必跑清单

```
□ E02 + TC-I001  Ubuntu 22.04，中文版，Docker 标准安装
□ E02 + TC-I002  Ubuntu 22.04，中文版，远程访问模式
□ E02 + TC-I003  Ubuntu 22.04，官方版，Docker 标准安装
□ E01 + TC-I010  Ubuntu 22.04 + 1Panel，API 安装模式
□ E01 + TC-I011  Ubuntu 22.04 + 1Panel，Compose 模式
□ E02 + TC-PA001 中文版工作区路径双向读写验证
□ E02 + TC-PA002 官方版工作区路径双向读写验证
□ E02 + TC-P001  重建后配置保留
□ E02 + TC-P002  重建后 credentials 保留
□ E02 + TC-U001  中文版升级
□ E02 + TC-R001  修改端口重建
□ E02 + TC-X003  Level 3 完全卸载
□ E06 + TC-I001  arm64 架构标准安装
```

### 11.4 测试环境重置脚本

```bash
#!/bin/bash
# reset-test-env.sh - 快速重置测试环境

echo "⚠️  重置测试环境（保留 ~/.openclaw 目录）"

# 停止并删除容器
docker stop openclaw 2>/dev/null && echo "容器已停止"
docker rm openclaw 2>/dev/null && echo "容器已删除"

# 无 Named Volumes（v0.5+ 已废弃），无需清理

# 删除安装状态（但保留数据目录，模拟真实用户重装）
rm -rf ~/.openclaw-installer

echo "✅ 测试环境重置完成"
echo "   保留：~/.openclaw/（模拟用户数据）"
echo "   保留：~/openclaw/workspace/（模拟用户工作区）"
echo "   如需完全重置，请手动：rm -rf ~/.openclaw ~/openclaw"
```

---

## 12. 预装软件模块（6.10）

### 12.1 设计原则

**目标**：安装完成后，OpenClaw agent 在容器内直接调用这些工具（`github`、`claude`、`opencode` 等命令），无需用户手动配置 PATH。

**软件安装路径**：`~/.openclaw/software/`（Bind Mount，宿主机可见，重建容器后保留）

**PATH 注入机制**：
```bash
# compose.yml 中通过 environment 注入
environment:
  - PATH=/root/.openclaw/software/bin:/root/.nvm/versions/node/current/bin:/usr/local/go/bin:$PATH
```

**npm 全局包安装重定向**（避免写入镜像层，确保持久化）：
```bash
# 将 npm global prefix 指向持久化目录
docker exec openclaw npm config set prefix /root/.openclaw/software
# 安装后二进制在 /root/.openclaw/software/bin/
```

### 12.2 可选软件清单

#### 软件安装菜单

```
⚙️ 预装软件（可选）

  以下工具将安装在容器内，持久化到 ~/.openclaw/software/，
  重建容器后不需重新安装，agent 可直接调用。

  [ ] GitHub CLI          (gh)         版本控制、PR 管理
  [ ] Claude Code CLI     (claude)      Anthropic 官方编码代理
  [ ] Codex CLI           (codex)       OpenAI 编码代理
  [ ] OpenCode CLI        (opencode)    开源编码代理，多模型支持
  [ ] Gemini CLI          (gemini)      Google Gemini 代理
  [ ] Obsidian CLI        (obsidian)    控制 Obsidian vault（需 Obsidian 运行中）
  [ ] NotebookLM          (notebooklm)  Google NotebookLM 自动化（⚠️ 需 Python 环境）
  [ ] EasyClaw            (easyclaw)    OpenClaw 配置管理 WebUI + TUI
  [ ] 全部跳过（默认）

  空格选择，回车确认: _
```

### 12.3 各软件安装规格

#### 1. GitHub CLI (`gh`)

| 项目 | 内容 |
|------|------|
| 源 | https://cli.github.com |
| 安装方式 | 二进制直接下载（不依赖 npm/Node） |
| 依赖环境 | 无 |
| 持久化路径 | `~/.openclaw/software/bin/gh` |
| 首次 auth | 跳过，提示用户运行 `gh auth login` |

```bash
install_github_cli() {
  local arch=$1   # amd64 / arm64
  local ver
  ver=$(curl -sf "https://api.github.com/repos/cli/cli/releases/latest" \
    | jq -r '.tag_name' | tr -d 'v')
  
  local url="https://github.com/cli/cli/releases/download/v${ver}/gh_${ver}_linux_${arch}.tar.gz"
  
  docker exec openclaw bash -c "
    mkdir -p /root/.openclaw/software/bin
    curl -fsSL '${url}' | tar -xz -C /tmp gh_${ver}_linux_${arch}/bin/gh
    mv /tmp/gh_${ver}_linux_${arch}/bin/gh /root/.openclaw/software/bin/gh
    chmod +x /root/.openclaw/software/bin/gh
    echo '✅ GitHub CLI 安装完成'
    echo '   首次使用请运行：gh auth login'
  "
}
```

---

#### 2. Claude Code CLI (`claude`)

| 项目 | 内容 |
|------|------|
| 源 | `@anthropic-ai/claude-code` |
| 安装方式 | `npm install -g --prefix ~/.openclaw/software @anthropic-ai/claude-code` |
| 依赖环境 | **Node.js 22**（必须先装 nvm 环境） |
| 持久化路径 | `~/.openclaw/software/lib/node_modules/@anthropic-ai/claude-code/` |
| 首次 auth | 跳过，提示用户运行 `claude /login` |

> ⚠️ **依赖检查**：选择 Claude Code 时，若用户未勾选 Node.js 环境，自动补充提示并强制安装 Node 22。

---

#### 3. Codex CLI (`codex`)

| 项目 | 内容 |
|------|------|
| 源 | `@openai/codex` |
| 安装方式 | `npm install -g --prefix ~/.openclaw/software @openai/codex` |
| 依赖环境 | Node.js 22 |
| 持久化路径 | `~/.openclaw/software/lib/node_modules/` |
| 首次 auth | 跳过，提示设置 `OPENAI_API_KEY` 环境变量 |

---

#### 4. OpenCode CLI (`opencode`)

| 项目 | 内容 |
|------|------|
| 源 | `opencode-ai` (npm) |
| 安装方式 | `npm install -g --prefix ~/.openclaw/software opencode-ai` |
| 依赖环境 | Node.js 22 |
| 持久化路径 | `~/.openclaw/software/lib/node_modules/` |
| 首次 auth | 跳过，提示运行 `opencode` 后进行配置 |
| 备注 | 也支持二进制安装：`curl -fsSL https://opencode.ai/install \| OPENCODE_INSTALL_DIR=/root/.openclaw/software/bin bash` |

---

#### 5. Gemini CLI (`gemini`)

| 项目 | 内容 |
|------|------|
| 源 | `@google/gemini-cli` |
| 安装方式 | `npm install -g --prefix ~/.openclaw/software @google/gemini-cli` |
| 依赖环境 | Node.js 22 |
| 持久化路径 | `~/.openclaw/software/lib/node_modules/` |
| 首次 auth | 跳过，提示运行 `gemini` 后通过 Google OAuth 登录 |

---

#### 6. Obsidian CLI (`obsidian`)

| 项目 | 内容 |
|------|------|
| 源 | Obsidian 官方 CLI（随 Obsidian 客户端提供） |
| 安装方式 | 通过 obsidian-skills 的 CLI 组件安装，见 Skill 模块 |
| 依赖环境 | 需要 Obsidian 桌面客户端运行中（服务器无法使用） |
| 使用限制 | **⚠️ 仅限本地桌面环境**，Docker 服务器场景下此工具无实际用途 |

```
⚠️  Obsidian CLI 说明

  Obsidian CLI 需要 Obsidian 桌面应用正在运行，
  在无 GUI 的服务器环境下无法使用。

  建议：在本地桌面机器（非服务器）上使用此工具。
  是否仍要安装？[y/N]（默认：跳过）: _
```

---

#### 7. NotebookLM (`notebooklm`)

| 项目 | 内容 |
|------|------|
| 源 | `notebooklm-py`（PyPI），teng-lin/notebooklm-py |
| 安装方式 | `pip install "notebooklm-py[browser]"` + `playwright install chromium` |
| 依赖环境 | **Python 3**（必须先装 Python/uv 环境）+ Playwright（约 150MB） |
| 持久化路径 | `~/.openclaw/software/python/` |
| auth 处理 | **安装但跳过 auth**，显示登录引导（见下） |
| 稳定性风险 | ⚠️ 依赖 Google 未公开 RPC 接口，可能随时 break |
| API 违规风险 | ⚠️ 使用非官方接口，违反 Google ToS |

**auth 跳过提示：**
```
✅ NotebookLM CLI 已安装

  ⚠️  首次使用需要 Google 账号登录授权：
  
  在有 GUI 的机器上完成登录：
    1. pip install "notebooklm-py[browser]"
    2. notebooklm login          ← 会打开浏览器进行 OAuth
    3. 复制生成的 auth 文件：
       scp ~/.notebooklm/storage_state.json \
           <你的服务器>:~/.notebooklm/storage_state.json
  
  完成后在容器内测试：
    docker exec openclaw notebooklm list
    
  ⚠️  注意：notebooklm-py 使用非官方 Google API，
      接口可能随时失效，生产环境请谨慎使用。
```

**安装依赖检查**：
- 选择 NotebookLM → 自动补充勾选 Python 环境
- 若未勾选 Python 但选了 NotebookLM → 提示必须先装 Python

```bash
install_notebooklm() {
  docker exec openclaw bash -c "
    # 安装到持久化目录
    pip install --target /root/.openclaw/software/python \
      'notebooklm-py[browser]'
    
    # 安装 Playwright（Chromium）
    python -m playwright install chromium
    python -m playwright install-deps chromium 2>/dev/null || true
    
    # 创建 wrapper 脚本到 bin 目录
    cat > /root/.openclaw/software/bin/notebooklm << 'EOF'
#!/bin/bash
PYTHONPATH=/root/.openclaw/software/python python -m notebooklm \"\$@\"
EOF
    chmod +x /root/.openclaw/software/bin/notebooklm
    
    echo '✅ NotebookLM CLI 已安装（跳过 auth）'
  "
}
```

---

#### 8. EasyClaw (`easyclaw`)

| 项目 | 内容 |
|------|------|
| 源 | https://github.com/moshall/easyclaw（WIP） |
| 定位 | OpenClaw 配置管理增强工具，Web UI + TUI 双模式 |
| 语言 | Python（主体）+ JavaScript/HTML（Web UI） |
| 安装方式 | `git clone` + `bash install.sh` |
| 默认安装位置 | `~/.openclaw/easyclaw` |
| 依赖环境 | Python 3（需先勾选 Python 环境） |
| Web UI 端口 | 默认 **4231** |
| 主要功能 | 模型/供应商管理、Agent 新增与工作区绑定、派发配置、网关设置、配置备份与回滚 |
| 状态 | ⚠️ Work In Progress，功能持续开发中 |

**安装函数：**
```bash
install_easyclaw() {
  log_info "正在安装 EasyClaw..."

  if ! docker exec openclaw python3 --version &>/dev/null; then
    log_error "EasyClaw 依赖 Python 3，请先安装 Python 环境"
    return 1
  fi

  docker exec openclaw bash -c "
    # 克隆到持久化目录（随 ~/.openclaw 一起 bind mount）
    if [ -d /root/.openclaw/easyclaw/.git ]; then
      git -C /root/.openclaw/easyclaw pull --quiet
    else
      git clone --depth=1 https://github.com/moshall/easyclaw.git \
        /root/.openclaw/easyclaw
    fi
    cd /root/.openclaw/easyclaw && bash install.sh
    echo '✅ EasyClaw 安装完成'
    echo '   TUI 模式：docker exec -it openclaw easyclaw tui'
    echo '   Web UI：  easyclaw web --port 4231（需映射端口）'
  "
}
```

**端口映射**：用户选装 EasyClaw 时，compose 生成自动追加：
```yaml
ports:
  - "{{CFG_PORT_HOST}}:18789"      # OpenClaw 主服务
  - "{{CFG_EASYCLAW_PORT}}:4231"   # EasyClaw Web UI（选装时追加）
```
`CFG_EASYCLAW_PORT` 默认 `4231`，生成前检测端口冲突可自定义。

---

### 12.4 npm 包统一安装函数

```bash
install_npm_tool() {
  local package=$1    # e.g. "@anthropic-ai/claude-code"
  local display=$2    # e.g. "Claude Code CLI"

  # 检查 Node 环境（nvm 安装在 ~/.openclaw/runtime/nvm/）
  if ! docker exec openclaw bash -c "source \$NVM_DIR/nvm.sh && node --version" &>/dev/null; then
    log_error "Node.js 环境未安装，无法安装 ${display}"
    log_info  "请重建容器并选择安装 Node.js 环境"
    return 1
  fi

  log_info "正在安装 ${display}..."
  # NPM_CONFIG_PREFIX 已通过 compose environment 设置为 ~/.openclaw/software
  docker exec openclaw bash -c "
    source \$NVM_DIR/nvm.sh
    npm install -g '${package}' 2>&1 | tail -3
  "

  if [ $? -eq 0 ]; then
    log_success "${display} 安装完成"
  else
    log_error "${display} 安装失败，可事后手动运行：
      docker exec openclaw bash -c 'source \$NVM_DIR/nvm.sh && npm install -g ${package}'"
  fi
}
```

### 12.5 软件依赖关系矩阵

| 软件 | 需要 Node 22 | 需要 Python | 需要 Go | 备注 |
|------|:------------:|:-----------:|:-------:|------|
| GitHub CLI | ❌ | ❌ | ❌ | 纯二进制，无依赖 |
| Claude Code CLI | ✅ 必须 | ❌ | ❌ | |
| Codex CLI | ✅ 必须 | ❌ | ❌ | |
| OpenCode CLI | ✅ 必须（或用二进制） | ❌ | ❌ | |
| Gemini CLI | ✅ 必须 | ❌ | ❌ | |
| Obsidian CLI | ✅ 推荐 | ❌ | ❌ | 服务器无实际用途 |
| NotebookLM | ❌ | ✅ 必须 | ❌ | Playwright 需要额外 ~150MB |
| EasyClaw | ❌ | ✅ 必须 | ❌ | Python-based，依赖 Python 3 | |

**选软件时自动补依赖逻辑：**
```bash
check_software_env_deps() {
  local needs_node=false
  local needs_python=false
  
  for sw in "${SELECTED_SOFTWARE[@]}"; do
    case "$sw" in
      claude|codex|opencode|gemini|obsidian) needs_node=true ;;
      notebooklm) needs_python=true ;;
    esac
  done
  
  if $needs_node && [ "${CFG_ENV_NODE}" != "true" ]; then
    log_warn "所选软件需要 Node.js 22，已自动添加至预装环境"
    CFG_ENV_NODE=true
  fi
  
  if $needs_python && [ "${CFG_ENV_PYTHON}" != "true" ]; then
    log_warn "NotebookLM 需要 Python 环境，已自动添加至预装环境"
    CFG_ENV_PYTHON=true
  fi
}
```

### 12.6 持久化路径与 Volume 更新

软件安装使用 Bind Mount（随 `~/.openclaw/` 主目录一起挂载），**无需额外 Named Volume**：

```
宿主机（单一 bind mount 根）              容器内（中文版）
~/.openclaw/
  ├── software/              →    /root/.openclaw/software/
  │   ├── bin/                         ├── bin/（gh、notebooklm wrapper 等）
  │   │   ├── gh
  │   │   └── notebooklm
  │   └── lib/node_modules/            （npm global，由 NPM_CONFIG_PREFIX 控制）
  │       ├── @anthropic-ai/claude-code/
  │       ├── @openai/codex/
  │       ├── opencode-ai/
  │       └── @google/gemini-cli/
  └── runtime/               →    /root/.openclaw/runtime/
      ├── nvm/                         （nvm 安装目录，NVM_DIR 指向此处）
      ├── python/                      （uv/pip 安装，UV_PYTHON_INSTALL_DIR）
      └── go/                          （Go，GOPATH 指向此处）
```

**所有 PATH/环境变量已在 compose 模板中统一注入（见 8.2 节），此处无需重复配置。**

---

## 13. 预装 Skill 模块（6.11）

### 13.1 Skill 安全背景（必读）

> **安全警告**：Cisco AI Defense 研究（2026年2月）显示，已分析的 31,000 个 OpenClaw 社区 Skill 中 **26% 含有至少一个安全漏洞**。ClawHub 自 2026 年 1 月以来已记录 **230+ 恶意 Skill 上传**，含 prompt injection、数据外泄、工具投毒等恶意行为。
>
> Skill 可以：执行宿主机命令、读取 `.env` 文件和 API Keys、发起外部网络请求、通过 prompt injection 影响 agent 行为。
>
> **脚本处理原则**：对用户选择的每个 Skill，安装前强制显示安全提示，引导用户 `clawhub inspect <slug>` 审查内容。

### 13.2 Skill 安装位置

```
~/.openclaw/workspace/skills/       ← 官方规范路径，agent 自动发现
├── obsidian-skills/                 （git clone 整仓库）
│   └── skills/
│       ├── obsidian-markdown/SKILL.md
│       ├── obsidian-canvas/SKILL.md
│       └── obsidian-cli/SKILL.md
├── skill-security-check/            （git clone）
│   └── SKILL.md
└── <clawhub-slug>/                  （clawhub install）
    └── SKILL.md
```

> 路径已通过 `~/openclaw/workspace:/root/.openclaw/workspace`（中文版）或 `~/openclaw/workspace:/home/node/openclaw/workspace`（官方版）挂载，**无需额外 volume 配置**。

### 13.3 预装 Skill 菜单

```
📚 预装 Skill（可选）

  Skill 让 agent 获得专项能力，安装后立即生效。

  ⚠️  安全提示：安装前请通过 clawhub inspect 审查 Skill 内容。
      Skill 可执行命令和访问文件，请仅安装可信来源。

  ━━━━━━━ 官方内置（随 OpenClaw 自动安装，无需选择）━━━━━━━

  ✅ Coding Agent Skill        帮助 agent 进行代码任务（官方内置）
  ✅ ClawHub Skill             发现和安装更多 Skill（官方内置）

  ━━━━━━━ 可选安装 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [ ] Obsidian Skills          教 agent 操作 Obsidian vault
      来源：kepano/obsidian-skills（Obsidian CEO 出品，10.2k ⭐）
      包含：Markdown / Canvas / JSON Bases / CLI 操作

  [ ] Skill 安全检查 Skill     审查已安装 Skill 的安全性
      来源：moshall/skill_collcet（security-checker/ 子目录）
      功能：扫描 allowed-tools、检测可疑 prompt patterns

  空格选择，回车确认: _
```

### 13.4 各 Skill 安装规格

#### Skill 1：Obsidian Skills（kepano/obsidian-skills）

| 项目 | 内容 |
|------|------|
| 仓库 | https://github.com/kepano/obsidian-skills |
| 作者 | Obsidian CEO（kepano / Steph Ango），MIT 协议 |
| 内容 | Obsidian Markdown / Canvas / Bases / CLI 四个子 Skill |
| 安装方式 | `git clone`（需要整仓库，不能只拷内层 skills/ 目录） |
| 依赖软件 | 若使用 obsidian-cli Skill，需同时安装 Obsidian CLI 软件 |
| 服务器使用 | Markdown/Canvas/Bases 三个 Skill 可用；CLI 操作 Skill 服务器无效 |

```bash
install_skill_obsidian() {
  local skills_dir="$HOME/openclaw/workspace/skills"
  
  log_info "正在安装 Obsidian Skills..."
  
  # 如果已存在则 pull 最新
  if [ -d "${skills_dir}/obsidian-skills/.git" ]; then
    git -C "${skills_dir}/obsidian-skills" pull --quiet
    log_success "Obsidian Skills 已更新到最新版"
  else
    git clone --depth=1 \
      "https://github.com/kepano/obsidian-skills.git" \
      "${skills_dir}/obsidian-skills"
    log_success "Obsidian Skills 安装完成"
  fi
  
  echo ""
  echo "  包含以下子 Skill："
  echo "  ✓ obsidian-markdown  — Obsidian Markdown 语法规范"
  echo "  ✓ obsidian-canvas    — JSON Canvas 画布操作"
  echo "  ✓ obsidian-bases     — Bases 数据库视图"
  echo "  ✓ obsidian-cli       — CLI 命令控制 Obsidian（需桌面客户端）"
  echo ""
  echo "  ⚠️  obsidian-cli Skill 在服务器环境无实际用途，"
  echo "      但不影响其他三个 Skill 的使用。"
}
```

---

#### Skill 2：Coding Agent Skill（官方内置）

| 项目 | 内容 |
|------|------|
| 来源 | OpenClaw 官方 Skills 仓库（openclaw/skills） |
| 安装状态 | **随 OpenClaw 容器自动安装，无需操作** |
| 内容 | 帮助 agent 使用代码工具，编写、运行、调试代码 |

> 脚本仅在 Step 5 安装总结里列出「已内置」，不做任何安装操作。

---

#### Skill 3：Skill 安全检查 Skill（moshall/skill_collcet）

| 项目 | 内容 |
|------|------|
| 仓库 | https://github.com/moshall/skill_collcet |
| 子目录 | `security-checker/`（仅安装此子目录，不需整仓库） |
| 安装路径 | `~/openclaw/workspace/skills/security-checker/` |
| 功能 | 扫描已安装 Skill 的 `allowed-tools` 字段、检测可疑 prompt 注入模式、生成安全报告 |
| 安装方式 | sparse-checkout 仅拉取 `security-checker/` 子目录 |

```bash
install_skill_security_checker() {
  local skills_dir="$HOME/openclaw/workspace/skills"
  local target="${skills_dir}/security-checker"

  log_info "正在安装 Skill 安全检查 Skill..."

  if [ -d "${target}/.git" ]; then
    git -C "$target" pull --quiet
    log_success "security-checker 已更新"
    return 0
  fi

  # sparse-checkout：只拉取 security-checker/ 子目录
  git clone --depth=1 --filter=blob:none --sparse \
    "https://github.com/moshall/skill_collcet.git" "$target"
  git -C "$target" sparse-checkout set security-checker

  # 将子目录内容提升到 target 根（SKILL.md 需在 skills/security-checker/SKILL.md）
  if [ -d "${target}/security-checker" ]; then
    mv "${target}/security-checker/"* "$target/"
    rm -rf "${target}/security-checker"
  fi

  log_success "Skill 安全检查 Skill 安装完成"
  echo "  使用方式：对 Agent 说「扫描我已安装的 Skill 安全状况」"
}
```

---

#### Skill 4：ClawHub Skill（官方内置）

| 项目 | 内容 |
|------|------|
| 来源 | OpenClaw 官方 + ClawHub 官方目录 |
| 安装状态 | **随 OpenClaw 容器自动安装，无需操作** |
| 内容 | 允许 agent 通过对话搜索、安装、管理 ClawHub 上的 Skill |
| 使用方式 | 对 agent 说「搜索 GitHub 相关 Skill」，agent 自动调用 |

---

### 13.5 通用 Skill 安装函数

```bash
install_skill_from_github() {
  local repo=$1       # e.g. "kepano/obsidian-skills"
  local slug=$2       # 本地目录名
  local skills_dir="$HOME/openclaw/workspace/skills"
  
  # 安全提示（每次必显示）
  echo ""
  echo "  ⚠️  安全检查提醒"
  echo "  正在从 GitHub 安装 Skill：https://github.com/${repo}"
  echo "  Skill 可执行命令并访问您的文件系统。"
  echo ""
  echo "  建议安装后运行安全审查（需 clawhub）："
  echo "  docker exec openclaw npx clawhub inspect ${slug}"
  echo ""
  
  confirm "确认继续安装 ${slug}？" || { echo "跳过 ${slug}"; return 0; }
  
  mkdir -p "$skills_dir"
  
  if [ -d "${skills_dir}/${slug}/.git" ]; then
    git -C "${skills_dir}/${slug}" pull --quiet
    log_success "${slug} 更新完成"
  else
    git clone --depth=1 "https://github.com/${repo}.git" \
      "${skills_dir}/${slug}"
    log_success "${slug} 安装完成"
  fi
}

install_skill_from_clawhub() {
  local slug=$1
  
  # 安全提示
  echo ""
  echo "  ⚠️  安全检查提醒"
  echo "  正在从 ClawHub 安装 Skill：${slug}"
  echo "  建议先检查：https://clawhub.app/skills/${slug}"
  echo "  或在容器内运行：docker exec openclaw npx clawhub inspect ${slug}"
  echo ""
  
  confirm "确认继续安装 ${slug}？" || { echo "跳过 ${slug}"; return 0; }
  
  docker exec openclaw bash -c "
    npx clawhub@latest install ${slug} \
      --skills-dir /root/.openclaw/workspace/skills
  "
}
```

### 13.6 安装完成后的 Skill 提示

```
📚 Skill 安装完成

  安装位置：~/openclaw/workspace/skills/

  ┌────────────────────────────────────────────────┐
  │  已安装 Skill：                                  │
  │  ✓ obsidian-skills     (kepano/obsidian-skills)│
  │  ✓ 内置：coding-agent  (官方内置，无需操作)      │
  │  ✓ 内置：clawhub       (官方内置，无需操作)      │
  └────────────────────────────────────────────────┘

  ⚠️  安全建议：
  运行以下命令对社区 Skill 进行安全检查：
  docker exec openclaw npx clawhub inspect obsidian-skills

  Skill 生效：重启容器后自动加载
  docker compose -f ~/.openclaw-installer/docker-compose.yml restart
```

### 13.7 安装向导步骤更新

加入软件和 Skill 预装后，Docker 安装向导变为 **8 步**：

```
Step 1/8  选择镜像源（官方版 / 中文版）
Step 2/8  选择版本（标签）
Step 3/8  配置端口
Step 4/8  配置访问方式（本地 / 远程）
Step 5/8  预装基础环境（Node / Python / Go）
Step 6/8  预装软件（gh / claude / codex / opencode / gemini / notebooklm / easyclaw）
Step 7/8  预装 Skill（obsidian-skills / 安全检查 Skill）
Step 8/8  确认配置 → 执行安装
```

**Step 6 在 Step 5 之后**：软件菜单根据 Step 5 选择的环境动态调整（未选 Python 则灰化 NotebookLM；未选 Node 则灰化 npm 类软件）。

---

## 14. 开放问题与待决策项

| 问题 | 背景 | 待决策内容 | 优先级 |
|------|------|------------|--------|
| Q1：1Panel API 规范 | 不同版本 1Panel API 路径格式可能不同 | 需在真实 1Panel 环境验证接口；需确认最低支持版本 | **P0** |
| Q4：脚本托管地址 | `curl \| bash` 需要稳定 URL | GitHub Raw（可能被墙）/ jsDelivr CDN / 自托管？建议 jsDelivr | P1 |
| Q8：版本切换兼容性 | 中文版→官方版，容器用户 root→node | 配置文件权限冲突；是否支持版本源切换？ | P1 |
| ~~Q12~~：软件 PATH 注入 | **已解决** — 单 bind mount + NVM_DIR 环境变量，无需硬编码版本路径 | — | 已关闭 |
| Q6：Windows WSL2 | 部分用户在 WSL2 下操作 | 是否列入支持范围？ | P2 |
| Q7：多实例安装 | 一台服务器装多个 OpenClaw | container name 和端口管理策略 | P3 |

---

*文档版本：v0.7 | 状态：草稿 | 下一步：确认 Q1（1Panel API）→ 开始编码*

---

## 15. 极端场景处理规格

### 15.1 版本源切换：官方版 → 中文版（或反向）

#### 问题根源

两个镜像的容器运行用户不同，导致容器内路径完全不同：

| 维度 | 官方版 (node) | 中文版 (root) |
|------|--------------|--------------|
| 容器用户 | `node` (uid=1000) | `root` (uid=0) |
| 配置路径 | `/home/node/.openclaw/` | `/root/.openclaw/` |
| 工作区路径 | `/home/node/openclaw/workspace/` | `/root/.openclaw/workspace/` |
| 文件归属 | uid=1000 | uid=0 |

**宿主机数据安全性**：全部数据在 `~/.openclaw/` 单一 bind mount 内，版本切换时**宿主机路径不变，数据完全不动**。

**实际风险点（v0.5 单 bind mount 架构下大幅简化）**：

1. **文件权限方向**：root 读 uid=1000 的文件没问题；但切换后 root 写回文件，归属变 root，再切回官方版时 node 用户无法写（`Permission denied`）
2. **config 格式兼容性**：中文版可能有额外字段，切换回官方版时可能被忽略或解析失败
3. ~~**Named Volumes 归属**~~ ：**已消除**——v0.5 无 Named Volume，此风险不存在

#### 处理方案

脚本检测到版本源切换时，触发**切换向导**：

```
⚠️  检测到版本源变更

  当前：官方原版（node 用户）
  目标：中文汉化版（root 用户）

  容器内路径将发生变化，需要迁移数据。

  脚本将执行以下操作：
  [1] 备份当前配置到 ~/.openclaw/openclaw.json.bak
  [2] 修复宿主机目录文件归属（chown 到当前用户）
  [3] 迁移 Named Volumes（若有）中的文件归属
  [4] 以新镜像重建容器

  ⚠️  迁移过程容器将停止约 60 秒
  确认继续？[y/N]: _
```

**文件归属修复逻辑**：

```bash
fix_ownership_for_source_switch() {
  local from_source=$1  # official / chinese
  local to_source=$2

  # 官方版 → 中文版：文件归属从 uid=1000 改为当前宿主机用户（不强制 root）
  # 中文版 → 官方版：文件归属从 uid=0 改为 uid=1000（node 用户）

  log_info "修复宿主机目录文件归属..."

  if [ "$from_source" = "official" ] && [ "$to_source" = "chinese" ]; then
    # 宿主机文件归属改为当前用户（中文版容器以 root 运行，bind mount 下宿主机用户不影响读写）
    sudo chown -R "$(id -u):$(id -g)" "$HOME/.openclaw/" "$HOME/openclaw/workspace/" 2>/dev/null || true

  elif [ "$from_source" = "chinese" ] && [ "$to_source" = "official" ]; then
    # 官方版 node 用户 uid=1000，需要确保文件可被 1000 读写
    # 宿主机文件开放 group 读写权限（不改 owner，避免破坏宿主机权限）
    chmod -R g+rw "$HOME/.openclaw/" "$HOME/openclaw/workspace/" 2>/dev/null || true
    log_warn "建议：官方版容器使用 node(uid=1000) 运行，"
    log_warn "若出现权限问题，请运行：chown -R 1000:1000 ~/.openclaw/"
  fi

  # 备份配置
  cp "$HOME/.openclaw/openclaw.json" \
     "$HOME/.openclaw/openclaw.json.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

  log_success "归属修复完成，旧配置已备份"
}
```

**Named Volume 迁移**（若存在）：

```bash
migrate_volumes_for_source_switch() {
  local to_uid=$1  # 目标用户 uid（官方版=1000，中文版=0）

  # v0.5+ 无 Named Volume，只需修复 bind mount 目录的文件归属
  for dir in     "$HOME/.openclaw/runtime/nvm"     "$HOME/.openclaw/runtime/python"     "$HOME/.openclaw/runtime/go"     "$HOME/.openclaw/software"; do
    [ -d "$dir" ] || continue
    chown -R "${to_uid}:${to_uid}" "$dir" 2>/dev/null || true
    log_info "已修复 ${dir} 归属 → uid=${to_uid}"
  done
}
```

**测试用例（新增）**：

| 用例 ID | 场景 | 期望结果 |
|---------|------|----------|
| TC-SW001 | 官方版 → 中文版（无 Named Volume） | 配置备份、归属修复、新容器启动正常 |
| TC-SW002 | 官方版 → 中文版（有 runtime/nvm 数据） | 路径前缀修复、NVM_DIR 更新、新容器 Node 可用 |
| TC-SW003 | 中文版 → 官方版 | 权限警告，node 用户可读写 |
| TC-SW004 | 切换后取消 | 容器不变、数据不动 |
| TC-SW005 | 切换后 workspace 文件完整 | AGENTS.md 等文件内容不变 |

---

### 15.2 接管外部手动安装的容器

#### 场景描述

用户此前**未使用本脚本**安装 OpenClaw（直接 `docker run` 或自写 compose），现在希望用本脚本进行升级/管理。`~/.openclaw-installer/config.env` 不存在。

#### 探测与接管流程

```
启动脚本
  │
  ├─ 未找到 config.env
  │
  ├─ 探测是否存在 OpenClaw 容器（反向识别）
  │    ├─ 按镜像名过滤：ghcr.io/openclaw/openclaw 或 openclaw-zh
  │    ├─ 按容器名匹配：*openclaw* / *claw*
  │    └─ 按端口特征：18789
  │
  ├─ 找到候选容器 → 显示"发现已安装实例"菜单
  │    ├─ [1] 接管此实例（反推配置 → 生成 config.env）
  │    ├─ [2] 忽略，全新安装（可能产生端口冲突）
  │    └─ [3] 退出
  │
  └─ 未找到容器 → 显示全新安装菜单
```

**反推配置逻辑**：

```bash
adopt_existing_container() {
  local container_name=$1

  log_info "正在从容器 [${container_name}] 反推安装配置..."

  # 1. 读取镜像信息
  local image=$(docker inspect "$container_name" \
    --format '{{.Config.Image}}')

  # 2. 判断版本源
  local source="official"
  echo "$image" | grep -q "openclaw-zh" && source="chinese"
  local image_base="${image%:*}"
  local version_tag="${image##*:}"

  # 3. 读取端口映射
  local port_host=$(docker inspect "$container_name" \
    --format '{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}}{{end}}' \
    | grep -E '^[0-9]+$' | head -1)
  port_host="${port_host:-7134}"

  # 4. 读取 bind mounts（还原数据目录）
  local config_mount=$(docker inspect "$container_name" \
    --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}:{{.Destination}} {{end}}{{end}}')

  # 5. 读取环境变量（还原 token）
  local auth_token=$(docker inspect "$container_name" \
    --format '{{range .Config.Env}}{{.}} {{end}}' \
    | tr ' ' '\n' | grep GATEWAY_TOKEN | cut -d= -f2)

  # 6. 检测 runtime 是否已在 bind mount 路径下持久化
  local has_node_vol=false
  [ -d "$HOME/.openclaw/runtime/nvm" ] && has_node_vol=true
  local has_python_vol=false
  [ -d "$HOME/.openclaw/runtime/python" ] && has_python_vol=true
  local has_go_vol=false
  [ -d "$HOME/.openclaw/runtime/go" ] && has_go_vol=true

  # 7. 显示反推结果，请用户确认
  echo ""
  echo "  探测到以下配置："
  echo "  ┌──────────────────────────────────────────┐"
  echo "  │  容器名：${container_name}"
  echo "  │  版本源：${source}"
  echo "  │  镜像：  ${image}"
  echo "  │  端口：  ${port_host} → 18789"
  echo "  │  Token： ${auth_token:-(未检测到)}"
  echo "  │  Node：  $([ "$has_node_vol" = true ] && echo '✅ bind mount 有数据' || echo '❌ 无持久化')"
  echo "  │  Python：$([ "$has_python_vol" = true ] && echo '✅ bind mount 有数据' || echo '❌ 无持久化')"
  echo "  │  Go：    $([ "$has_go_vol" = true ] && echo '✅ bind mount 有数据' || echo '❌ 无持久化')"
  echo "  └──────────────────────────────────────────┘"
  echo ""

  confirm "以上配置正确，接管此实例？" || return 1

  # 8. 生成 config.env
  mkdir -p "$HOME/.openclaw-installer"
  cat > "$HOME/.openclaw-installer/config.env" << EOF
# 由脚本从现有容器反推生成（采纳外部安装）
INSTALL_DATE="$(date -Iseconds)"
INSTALLER_VERSION="1.0.0"
ADOPTED_FROM="manual"

CFG_SOURCE="${source}"
CFG_IMAGE_BASE="${image_base}"
CFG_DOCKER_IMAGE="${image}"
CFG_VERSION_TAG="${version_tag}"
CFG_INSTALL_MODE="docker"
CFG_CONTAINER_USER="$([ "$source" = "chinese" ] && echo root || echo node)"
CFG_PORT_HOST="${port_host}"
CFG_AUTH_TOKEN="${auth_token}"
CFG_ENV_NODE="${has_node_vol}"
CFG_ENV_PYTHON="${has_python_vol}"
CFG_ENV_GO="${has_go_vol}"
CONTAINER_NAME="${container_name}"
COMPOSE_FILE="$HOME/.openclaw-installer/docker-compose.yml"
EOF

  # 9. 反向生成 compose 文件（从 docker inspect 重建）
  regenerate_compose_from_inspect "$container_name"

  log_success "接管完成！现在可以正常使用升级/重建/卸载功能。"
}
```

**反推的已知限制**：

| 限制 | 说明 |
|------|------|
| 容器名不含 claw | 可能探测不到，需用户手动输入容器名 |
| 使用 docker run 而非 compose | compose 文件需重新生成（可能不完全还原） |
| bind mount 路径非标准 | 数据路径与脚本规范不一致，提示用户是否迁移路径 |
| 容器用 restart=always | 接管后改为 `unless-stopped`（脚本标准） |

**测试用例**：

| 用例 ID | 场景 | 期望结果 |
|---------|------|----------|
| TC-AD001 | 手动安装，标准容器名 `openclaw` | 自动探测并展示配置 |
| TC-AD002 | 手动安装，非标准容器名 `my-claw` | 探测不到时，提示手动输入容器名 |
| TC-AD003 | 接管后执行升级 | 升级成功，数据保留 |
| TC-AD004 | 接管后执行重建（修改端口） | 新端口生效，compose 文件更新 |
| TC-AD005 | 多个 openclaw 容器存在 | 列出所有候选，让用户选择接管哪一个 |

---

### 15.3 为已有容器追加 Runtime 持久化

#### 场景描述

用户之前运行的容器**没有 Named Volume 挂载**（nvm/python/go 安装在容器的可写层或镜像层），现在希望通过脚本升级并追加持久化，使 runtime 在重建容器后还在。

#### 核心挑战

**v0.5 单 bind mount 架构下，场景 C（全新安装+持久化）已自动满足。**
本节主要处理"已有容器但 runtime 装在容器可写层而非 bind mount 路径"的情况。

```
当前状态（外部手动安装，runtime 在容器可写层）：
  /root/.nvm/         ← 容器可写层，重建后丢失 ✗
  /root/.local/       ← 同上 ✗

目标状态（迁移到 bind mount 路径）：
  ~/.openclaw/runtime/nvm/    ← 宿主机 bind mount，重建后保留 ✓
  ~/.openclaw/runtime/python/ ← 同上 ✓

挑战：
  1. 容器可写层数据需 tar 导出再写入宿主机目录
  2. nvm 使用大量 symlink，需 tar 保全（不能直接 docker cp）
  3. 迁移过程容器必须停止（数据一致性）
  4. 迁移后需修复 nvm 内部的路径引用（用 NVM_DIR 覆盖即可）
```

#### 三种子场景

**子场景 A：容器内有手动安装的 runtime（非 nvm 管理）**

用户曾在容器内手动 `apt install nodejs` 或 `pip install` 等，数据在系统目录（如 `/usr/local/`），**不在用户家目录**。这种情况无法迁移到 Named Volume，脚本需要：
- 检测路径，判断是系统安装还是用户空间安装
- 系统安装：提示用户重装（在容器内用 nvm/uv 安装到用户目录）
- 用户空间安装（`/root/.nvm` 等）：可以迁移（见子场景 B）

**子场景 B：用户空间安装（如 `/root/.nvm`），迁移到 bind mount 路径**

```bash
migrate_runtime_to_bind_mount() {
  local runtime=$1   # node / python / go

  case $runtime in
    node)   local src_path="/root/.nvm" ;;
    python) local src_path="/root/.local" ;;
    go)     local src_path="/usr/local/go" ;;
  esac

  local dst_host="$HOME/.openclaw/runtime/${runtime}"

  docker exec openclaw bash -c "[ -d ${src_path} ]" || {
    log_warn "${runtime} 未在容器内找到（${src_path}），跳过"
    return 0
  }

  log_info "将 ${runtime} 迁移到 ~/.openclaw/runtime/${runtime}（bind mount）..."
  confirm "确认继续？（容器将停止约 30-60 秒）" || return 1

  docker stop openclaw
  mkdir -p "$dst_host"

  # tar 保全 symlink，写入宿主机 bind mount 目录
  docker run --rm \
    --volumes-from openclaw \
    -v "${dst_host}:/target" \
    alpine sh -c "cd ${src_path} && tar cf - . | tar xf - -C /target"

  # compose 无需修改，NVM_DIR 等已在 compose environment 中指向新路径
  docker compose -f "$HOME/.openclaw-installer/docker-compose.yml" up -d

  sleep 10
  case $runtime in
    node)   docker exec openclaw bash -c 'source $NVM_DIR/nvm.sh && node --version' \
              && log_success "Node 迁移验证通过" ;;
    python) docker exec openclaw python3 --version && log_success "Python 迁移验证通过" ;;
    go)     docker exec openclaw go version && log_success "Go 迁移验证通过" ;;
  esac

  sed -i "s/CFG_ENV_$(echo $runtime | tr a-z A-Z)=.*/CFG_ENV_$(echo $runtime | tr a-z A-Z)=true/" \
    "$HOME/.openclaw-installer/config.env"
}
```

**子场景 C：容器内完全没有 runtime，全新安装并持久化**

最简单情况，`~/.openclaw/runtime/` 已在 bind mount 内，新装的 runtime 直接写入即持久化：

```bash
# 重建时，用户在菜单选择新增 Node 环境
# → 重建容器（compose 已有 ~/.openclaw bind mount，无需修改）
# → 容器启动后：NVM_DIR=~/.openclaw/runtime/nvm nvm install 22
# → 写入 bind mount，后续重建无需重装 ✓
```

#### 升级菜单新增入口

在管理菜单的"安全升级"流程末尾，增加一个可选步骤：

```
升级完成后检测到以下 runtime 无持久化（不在 ~/.openclaw/runtime/）：
  ⚠️  Node.js：容器内已安装，但在容器可写层（重建后丢失）
  ⚠️  Python：容器内已安装，但在容器可写层（重建后丢失）

是否现在迁移到 bind mount 持久化？（推荐）
  [1] 是，迁移全部
  [2] 选择部分迁移
  [3] 跳过（下次重建后丢失）
```

#### 测试用例

| 用例 ID | 场景 | 期望结果 |
|---------|------|----------|
| TC-MP001 | 容器有 nvm（可写层）→ 迁移到 bind mount | 迁移后重建，node 命令可用 |
| TC-MP002 | 容器有 Python（可写层）→ 迁移 | 迁移后重建，python3 可用 |
| TC-MP003 | 容器完全无 runtime → 全新安装到 bind mount | 安装后重建，runtime 可用 |
| TC-MP004 | 迁移中断 | 宿主机目录保留已迁移数据，可继续 |
| TC-MP005 | 迁移后验证失败 | 提示排查，bind mount 数据保留供手动处理 |
| TC-MP006 | 系统路径安装（`apt install nodejs`） | 检测到后给出重装指引，不强行迁移 |
| TC-MP007 | 接管外部安装 + 追加持久化（组合） | 接管成功，迁移 runtime，重建后全部可用 |

