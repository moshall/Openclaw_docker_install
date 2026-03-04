# OpenClawctl Script Modularization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 `openclawctl.sh` 重构为“入口文件 + 多模块脚本”，在不改变行为的前提下提升可读性与可维护性。

**Architecture:** 保留 `openclawctl.sh` 作为唯一外部入口，新增 `lib/openclawctl/*.sh` 按领域拆分函数。入口负责常量、模块加载与主流程启动。各模块只暴露函数，不执行副作用代码；加载顺序显式固定，保证函数依赖可解析。

**Tech Stack:** Bash (`set -euo pipefail`), Git Worktree, 现有 shell/go 测试套件（`tests/openclawctl_test.sh`, `go test ./...`, installer v07 tests）。

---

### Task 1: 建立模块化骨架（不迁移函数）

**Files:**
- Create: `lib/openclawctl/bootstrap.sh`
- Create: `lib/openclawctl/common.sh`
- Create: `lib/openclawctl/io.sh`
- Create: `lib/openclawctl/image.sh`
- Create: `lib/openclawctl/persist.sh`
- Create: `lib/openclawctl/components.sh`
- Create: `lib/openclawctl/deps.sh`
- Create: `lib/openclawctl/ops.sh`
- Create: `lib/openclawctl/wizard.sh`
- Modify: `openclawctl.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写一个失败测试（入口需 source 模块）**

在 `tests/openclawctl_test.sh` 增加断言：`bash -n openclawctl.sh` 时可解析 `lib/openclawctl/bootstrap.sh` 的 source 路径（先不创建文件，测试应失败）。

**Step 2: 运行测试确认失败**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL（source 目标文件不存在）。

**Step 3: 最小实现**

创建上述空模块文件（仅含 shebang 注释或 no-op），在 `openclawctl.sh` 顶部加入固定顺序 `source`，但暂不移动任何函数。

**Step 4: 运行测试确认通过**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl tests/openclawctl_test.sh
git commit -m "refactor: add openclawctl modular skeleton"
```

---

### Task 2: 抽取“基础工具函数”到 `common.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/common.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

新增用例覆盖至少 1 个工具函数行为（例如 `print_cmd` 输出转义），先删除入口里该函数定义，验证失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL（函数未定义或输出不符合）。

**Step 3: 最小实现**

迁移这组函数到 `common.sh`：`print_cmd/run_cmd/run_cmd_brief/run_optional_step/log_info/log_error/json_escape/join_with_semicolon`。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/common.sh tests/openclawctl_test.sh
git commit -m "refactor: extract common shell helpers"
```

---

### Task 3: 抽取“输入/UI函数”到 `io.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/io.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

为交互路径新增断言（`read_choice_default`/`sanitize_user_input`）。先移除原函数，确认失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL。

**Step 3: 最小实现**

迁移 `read_with_default/read_required/read_container_name/read_choice_default/read_menu_choice/clear_interactive_screen/press_enter_to_continue/sanitize_user_input/trim_surrounding_spaces/sanitize_port_mapping_input`。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/io.sh tests/openclawctl_test.sh
git commit -m "refactor: extract interactive io utilities"
```

---

### Task 4: 抽取“镜像/tag决策函数”到 `image.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/image.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

增加 official tag 回退路径断言（已存在 case 可复用），先移除函数定义验证失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL（tag 选择链路断裂）。

**Step 3: 最小实现**

迁移 `fetch_official_openclaw_tags` 到 `resolve_image` 相关函数完整集合；保持函数名和日志完全一致。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/image.sh tests/openclawctl_test.sh
git commit -m "refactor: extract image and tag resolution logic"
```

---

### Task 5: 抽取“持久化/端口/迁移”到 `persist.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/persist.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

补充 `persist` 端口冲突 case（`4231` 冲突自动回退）并使其先失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL。

**Step 3: 最小实现**

迁移 `normalize_extra_ports`、迁移拷贝函数、`pre_upgrade_migrate_runtime_data`、EasyClaw/ClaudeCodeUI 端口映射函数。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/persist.sh tests/openclawctl_test.sh
git commit -m "refactor: extract persistence and port mapping logic"
```

---

### Task 6: 抽取“可选软件/Skill/档案”到 `components.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/components.sh`
- Modify: `config/optional-components.conf`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

使用已有 `SOFTWARE_SET/SKILL_SET` 场景，先断开 `load_optional_component_catalog` 调用并确认失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL（可选软件/Skill 摘要或安装命令缺失）。

**Step 3: 最小实现**

迁移 catalog 读取、normalize、summary、profile 读写、`install_selected_software`、`install_selected_skills` 相关函数。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/components.sh config/optional-components.conf tests/openclawctl_test.sh
git commit -m "refactor: extract optional components and profile logic"
```

---

### Task 7: 抽取“依赖补齐”到 `deps.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/deps.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

复用/新增 `python3 + pip + venv` 补齐场景，先断开 `manage_container_runtime_deps` 函数。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL。

**Step 3: 最小实现**

迁移 `manage_container_runtime_deps` 与相关依赖函数；保留 heredoc 内容与日志文本。

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/deps.sh tests/openclawctl_test.sh
git commit -m "refactor: extract runtime dependency management"
```

---

### Task 8: 抽取“执行计划与 wizard 路由”到 `ops.sh` + `wizard.sh`

**Files:**
- Modify: `openclawctl.sh`
- Modify: `lib/openclawctl/ops.sh`
- Modify: `lib/openclawctl/wizard.sh`
- Test: `tests/openclawctl_test.sh`

**Step 1: 写失败测试**

对 `--wizard install/upgrade/rebuild/adopt/persist/info` 入口做一次集中断言（已有 case 可汇总），先让路由失败。

**Step 2: 运行失败测试**

Run: `bash tests/openclawctl_test.sh`
Expected: FAIL。

**Step 3: 最小实现**

- `ops.sh`：`execute_install_plan/execute_upgrade_plan/execute_rebuild_plan` 等执行器
- `wizard.sh`：`install_wizard` 到 `run_selected_wizard/main_loop`
- 入口 `openclawctl.sh` 仅保留：常量、source、`main "$@"`

**Step 4: 回归测试**

Run: `bash tests/openclawctl_test.sh`
Expected: PASS。

**Step 5: Commit**

```bash
git add openclawctl.sh lib/openclawctl/ops.sh lib/openclawctl/wizard.sh tests/openclawctl_test.sh
git commit -m "refactor: split operation executors and wizard routes"
```

---

### Task 9: 全量验证与文档更新

**Files:**
- Modify: `README.md`
- Modify: `docs/rewrite-v0.7/migration.md`
- Modify: `docs/rewrite-v0.7/release-checklist.md`
- Create: `docs/rewrite-v0.7/openclawctl-modular-map.md`

**Step 1: 运行全量验证**

Run:
- `bash tests/openclawctl_test.sh`
- `go test ./...`
- `bash tests/installer_v07_smoke_test.sh`
- `bash tests/installer_v07_1panel_test.sh`

Expected: 全部 PASS。

**Step 2: 文档补齐**

记录模块职责图、source 顺序、二次开发入口、回归命令。

**Step 3: Commit**

```bash
git add README.md docs/rewrite-v0.7 docs/plans/2026-03-04-openclawctl-script-modularization.md
git commit -m "docs: add openclawctl modularization map and migration notes"
```

---

### Task 10: 真机回归（最小关键路径）

**Files:**
- Modify: `tests/e2e/openclawctl_realhost_regression_20260303.sh`
- Create: `tests/e2e/openclawctl_realhost_modular_regression.sh`

**Step 1: 执行关键链路**

- 低版本安装 -> 高版本升级
- 升级后软件保活
- persist 端口冲突规避
- strict non-interactive adopt 报告

**Step 2: 收集证据**

输出日志路径、容器端口映射、`strict-report.json` 关键字段。

**Step 3: Commit**

```bash
git add tests/e2e
git commit -m "test: add real-host regression for modularized openclawctl"
```

---

Plan complete and saved to `docs/plans/2026-03-04-openclawctl-script-modularization.md`. Two execution options:

1. Subagent-Driven (this session) - I dispatch fresh subagent per task, review between tasks, fast iteration
2. Parallel Session (separate) - Open new session with executing-plans, batch execution with checkpoints

Which approach?
