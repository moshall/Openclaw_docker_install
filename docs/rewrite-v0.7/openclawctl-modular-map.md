# openclawctl 模块化映射（v0.7）

## 目标

`openclawctl.sh` 保持为唯一外部入口；业务函数按职责拆分到 `lib/openclawctl/*.sh`，降低单文件复杂度并保持行为兼容。

## 入口加载顺序（固定）

1. `lib/openclawctl/bootstrap.sh`
2. `lib/openclawctl/common.sh`
3. `lib/openclawctl/io.sh`
4. `lib/openclawctl/image.sh`
5. `lib/openclawctl/persist.sh`
6. `lib/openclawctl/components.sh`
7. `lib/openclawctl/deps.sh`
8. `lib/openclawctl/ops.sh`
9. `lib/openclawctl/wizard.sh`

> 保持显式顺序可确保函数依赖在运行期可解析（例如 `components` 依赖 `deps`/`persist` 中的能力）。

## 模块职责

- `common.sh`：命令执行/日志/JSON 转义等通用工具函数
- `io.sh`：交互输入、菜单读值、输入清洗与端口字符串清洗
- `image.sh`：镜像来源决策、官方 tag 拉取与回退、镜像预检
- `persist.sh`：runtime 迁移、扩展端口规范化、EasyClaw/ClaudeCodeUI 端口映射
- `components.sh`：可选软件与 Skill 目录、归一化、摘要、档案读写、安装执行器
- `deps.sh`：依赖集合归一化、容器依赖补齐、APT 手工包快照/回放、PATH 修复
- `ops.sh`：操作执行器接口（install/upgrade/rebuild 等）
- `wizard.sh`：向导路由接口与主循环接口
- `bootstrap.sh`：预留启动阶段扩展点（当前无副作用）

## 二次开发入口

- 新增可选软件/Skill：编辑 `config/optional-components.conf`
- 新增模块函数：优先放入对应 `lib/openclawctl/*.sh`，避免回写入口文件
- 新增回归：优先补到 `tests/openclawctl_test.sh`，再扩展 `tests/e2e/*`

## 回归命令

```bash
bash tests/openclawctl_test.sh
go test ./...
bash tests/installer_v07_smoke_test.sh
bash tests/installer_v07_1panel_test.sh
```
