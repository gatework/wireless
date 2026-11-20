# wireless 开发说明

遵循 [gatework Go 工程规范（go-standards/STANDARD.md）](https://github.com/gatework/go-standards/blob/v1.2.0/STANDARD.md)；提交前运行 `make check`。

本模块面向无线网络管理员：汇聚多台无线控制器的 AP、射频、BSS、终端、802.1X/MAC 认证会话、IP 冲突与黑名单，提供跨控制器定位、分层诊断、全局巡检和受控处置（踢下线、静态黑名单）。设计与方法论见 [docs/design.md](docs/design.md)，术语见 [GLOSSARY.md](GLOSSARY.md)。

成熟度：v0，未投产，不承诺兼容（GEN-1）。

## 边界

- 共享机制来自 [netops](../netops)：设备与清单、采集与快照、缓存策略、解析、变更执行、凭据、CLI 工具。本模块不再依赖 go-netops 与 parser，也不得重新实现这些机制。
- 根包 `wireless` 是厂商无关的领域模型、跨控制器 `Index` 与 `Query`，不做 I/O，只依赖 netops 的 `evidence`、`capture` 等纯包。
- `vendors/h3c` 只负责 Comware 语法：命令表、回显解析、动作命令渲染与回读解析。新厂商在 `vendors/<vendor>` 实现 `wireless.Vendor` 与 `action.Renderer`。
- `diagnose`（单终端分层诊断）与 `health`（netops assess 规则目录，参数类型化）只依赖领域模型，不依赖厂商语法。
- `action` 把操作建模为 netops `change.Plan`，由 `ops.Deploy` 在单会话中执行一次：读回 → 已生效则跳过 → 下发 → 回读校验 → 日志与审计。踢下线按"消失或重新关联"验证；黑名单带回滚命令。不重试、不自动保存（`--save` 时在同一会话保存）。
- 设备会话只在 `internal/bootstrap` 组装 net-connector `connector`，其余代码只用 netops `ops.Dialer`/`ops.Session` 端口；快照目录只经 netops `store/snapshot`；`adapter/sightings` 只保存终端位置记录。
- `internal/workflow` 只使用注入的端口；`internal/bootstrap` 组装配置、凭据与清单；`internal/cli` 负责参数、渲染与确认。中文文案集中在各包 `messages.go`。

`architecture.yaml` 声明并由 `make check` 强制以上依赖方向。

## 安全语义

- 凭据只来自进程环境或权限 0600 的 `.env`，不进 `wireless.yml`、日志、报告或快照。
- 配置解析不读取 `key`、`password`、`preshared-key` 内容。
- SSH 默认严格校验主机密钥。
- 变更命令必须人工输入确认串（或显式 `--yes`），每次只针对一台控制器、一个单播 MAC。
- 设备回显中的控制字符与不可见格式字符在终端输出前转义。

## 测试

- 单元测试只用 `testdata/` 中的合成样例（RFC 5737/3849 地址、本地管理 MAC），真实回显不进仓库（TST-3）。
- 私有语料：`make corpus WIRELESS_CORPUS=<快照根目录>`，逐台断言所有维度完整且无未识别行，只输出聚合计数。
- 模糊测试：`make fuzz`。
