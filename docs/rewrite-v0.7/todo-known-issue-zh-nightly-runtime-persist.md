# TODO: `openclaw-zh:nightly` 与运行环境持久化冲突（真机）

- 记录时间：2026-03-03
- 环境：VPS `38.54.110.122`（Ubuntu 24.04.2, Docker 29.2.1）
- 场景：`--wizard install` + `IMAGE=ghcr.io/1186258278/openclaw-zh:nightly` + 开启运行环境持久化

## 现象

- 容器 `openclaw_cov_docker` 持续重启，`docker ps` 显示 `Restarting (1)`。
- 日志核心报错：`Error: Cannot find module '/app/openclaw'`。
- 脚本侧连带表现：
  - 端口映射断言失败（主容器未稳定运行）
  - PATH 修正、授权目录修正、依赖补齐步骤均因容器重启而跳过/失败

## 当前定位到的原因

- 运行环境持久化把宿主机空目录挂载到了容器 `/usr/local/lib/node_modules`。
- `openclaw-zh:nightly` 的 `openclaw` 可执行入口依赖该路径内的 npm 全局包。
- 被空目录覆盖后，`/usr/local/bin/openclaw` 链接失效，entrypoint 回退到 Node 启动并触发 `Cannot find module '/app/openclaw'`。

## 影响范围

- 影响中文版镜像（至少 `ghcr.io/1186258278/openclaw-zh:nightly`）在“首次安装 + 环境持久化”路径。
- 官方镜像 `docker.io/1panel/openclaw:*` 当前未复现该问题（已通过低版到高版升级链路验证）。

## 待调研

- [ ] 是否仅 `nightly` 受影响，`ghcr.io/1186258278/openclaw-zh:latest` 是否同样受影响。
- [ ] 是否可在首次启动前做“预热复制”（seed）再挂载，避免覆盖空目录。
- [ ] 中文版镜像是否应跳过 `/usr/local/lib/node_modules` 持久化，改为仅持久化用户级路径。
- [ ] 持久化策略是否需要按镜像来源差异化（official / zh 分开模板）。

## 待处理功能

- [ ] 在安装前新增“关键挂载冲突检测”，识别会覆盖镜像核心运行目录的挂载。
- [x] 为 `zh` 源增加专用运行环境持久化模板（避免覆盖 npm 全局包目录）。
- [ ] 增加回归测试：`zh nightly + 环境持久化 + install/rebuild/upgrade` 全链路真机用例。
- [ ] 严格非交互报告中新增 `runtime_mount_conflict` 字段，明确记录该类降级/跳过行为。

## 临时策略（已执行）

- 真机覆盖先继续跑官方镜像链路（Linux/Docker、端口扩口、补充依赖、数据持久化、环境持久化）。
- `zh` 镜像问题单独跟踪，待策略确定后再回补完整真机回归。

## 已完成回归（2026-03-03）

- 已落地脚本策略：`zh` 镜像启用 env 持久化时，自动跳过 `/usr/local/lib/node_modules` 挂载与迁移。
- 已补充 npm 持久化策略：自动执行 `npm prefix=/root/.local`，使 `npm -g` 包落到 runtime 持久化路径。
- 真机回归通过：`install(nightly) -> rebuild(nightly, 端口扩口) -> upgrade(latest)`。
- 真机回归通过（含 npm 全局包）：安装 `cowsay` 后跨 `rebuild/upgrade` 仍可用。
- 验证点通过：容器稳定运行、端口映射/扩口、依赖补齐、数据持久化、环境持久化、APT 异常源隔离、严格非交互报告 `status=success`。
- 回归日志目录（VPS）：`/root/openclaw-coverage-20260303-zh/logs`
- npm 持久化专项日志目录（VPS）：`/root/openclaw-coverage-20260303-zh-npm/logs`
