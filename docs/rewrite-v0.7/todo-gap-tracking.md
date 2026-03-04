# v0.7 Gap TODO

本清单用于追踪与 `openclaw-installer-dev-doc-v0.7.md` 的落地差异，按优先级推进。

## P0 / P1

- [x] 1Panel API 真适配
  - 对齐文档 API 语义：Token 校验 + Compose 创建
  - 对齐真实 1Panel 版本差异，失败回退 Compose 导入

- [x] Linux / macOS 原生 npm 安装链路
  - 增加非 Docker 安装入口（native install + 配置输出）
  - 对齐 Node 22 前置检查与配置目录持久化

- [x] 极端场景链路（第 15 章）
  - 版本源切换（official/chinese）兼容处理与权限修复
  - 接管外部手工安装容器（反推配置）
  - 为已有容器追加 runtime 持久化并重试验证

- [x] 可选软件 + Skill 模块（第 12/13 章）
  - 增加可选软件安装链路（gh/claude/codex/opencode/gemini/notebooklm/easyclaw/obsidian）
  - 增加 Skill 安装链路（obsidian-skills/security-checker）
  - 引入配置驱动目录文件（`config/optional-components.conf`），后续扩展无需改核心流程
  - 安装档案与回归用例补齐

- [x] 部署信息链路（第 6.9 节）
  - 安装/升级/重建/接管后写入 `~/.openclaw-installer/deployment-info.txt`
  - 增加 `--wizard info` 和菜单入口查看部署信息

- [x] v0.7/TUI 动作并轨
  - v0.7 增加 `adopt/persist/native/info` 动作
  - Go TUI 增加 `adopt/persist/native/info` 入口与配置文件桥接

- [x] 1Panel 交互引导补齐（v0.7）
  - 交互 install 时检测到 1Panel 可选择 API/Compose 模式并输入 API 参数

- [x] 端口推荐扫描补齐
  - 安装向导默认主端口改为优先扫描 7100-7200 可用端口

- [x] Skill 强制安全确认
  - 按当前需求暂不启用强制确认；保留 security-checker Skill 安装能力

## 回归与验收

- [x] 本地非实装回归（shell/go/v07）
- [ ] 真机回归：Linux 直装、1Panel 路径、低->高版本升级、异常中断重试
- [x] 完成后重新逐章对照需求文档并补齐遗漏
