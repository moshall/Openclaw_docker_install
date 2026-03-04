# Gap Review (2026-03-03)

对照文档：`docs/rewrite-v0.7/openclaw-installer-dev-doc-v0.7.md`

## 本次已补齐

- 1Panel API 路径与 token 校验链路（v0.7 installer）
  - 新增 `/api/v1/users/profile` token 校验
  - 新增 `/api/v1/containers/compose` 提交流程
  - 保留 legacy `/compose/create` 回退
- 原生 npm 安装入口（shell 主脚本）
  - 新增 `--wizard native` 与主菜单入口
  - 增加 Node22 前置检查（非 dry-run）
- 极端场景链路（shell 主脚本）
  - 新增版本源切换兼容修正（配置备份 + 权限修正）
  - 新增 `--wizard adopt`（接管外部容器并生成配置）
  - 新增 `--wizard persist`（为已有容器追加 runtime 持久化）
- 可选软件 + Skill（shell 主脚本）
  - 安装向导新增可选软件/Skill 选择与执行
  - 覆盖 `gh/claude/codex/opencode/gemini/notebooklm/easyclaw/obsidian`
  - 覆盖 `obsidian-skills/security-checker`
  - 增加 software/skill profile 持久化
- 可选组件目录化（shell 主脚本）
  - 新增 `config/optional-components.conf` 作为可选软件/Skill 单一来源
  - 软件/Skill 标签、安装类型、依赖声明改为配置驱动
- 部署信息链路（shell 主脚本）
  - 新增 `deployment-info.txt` 写入（install/upgrade/rebuild/adopt）
  - 新增 `--wizard info` 与主菜单“查看部署信息”
  - 支持位置参数 `info`（`openclaw info` 风格）
- v0.7 与 TUI 并轨
  - v0.7 支持 `adopt/persist/native/info` 动作
  - Go TUI 支持 `adopt/persist/native/info` 入口
  - 安装表单支持 `SOFTWARE_SET/SKILL_SET` 写入
- 1Panel 交互补齐（v0.7）
  - install 交互态检测 1Panel 后可选 API/Compose 模式，并可输入 API 地址/Token
- 端口推荐补齐（shell 主脚本）
  - 安装向导默认主端口改为优先扫描 `7100-7200`

## 仍存在的文档差异（后续迭代）

- 文档中的 Skill“安装前强制安全确认/inspect”流程按当前需求明确跳过，仅保留 security-checker 安装能力
- 文档中 1Panel API 的真实版本矩阵与最小支持版本仍需持续真机验证沉淀
