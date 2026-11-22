# Changelog

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循语义化版本。

## [Unreleased]

### Changed

- `wireless watch` 改用 netops `job` 调度：
  - 启动时立即采集一轮，之后按 `watch.interval`（或 `--interval`）执行；上一轮未结束不会开始下一轮，错过的时间点不补跑。
  - 可选 `watch.sweep`（cron 或 `@every`）按计划采集全部维度。
  - 每轮运行记入 `<数据目录>/runs`，`wireless status` 显示各作业上次运行的时间与结果。

### Added

- 运维事件：采集失败（`collect.failed`）与作业失败（`job.failed`）写入 `<数据目录>/events.jsonl`；可配置 `watch.events.webhook`，按 `min_severity` 过滤，使用 `$WIRELESS_WEBHOOK_SECRET` 做 HMAC 签名推送。
- 共享运维内核更新至 netops v0.5.1。

### Fixed

- `collect` 与 `status` 表格中的成功、未执行、已取消状态此前显示为空白。

## [0.2.1] - 2026-11-21

- 更新设备会话依赖至 net-connector v0.10.3，更新共享运维内核至 netops v0.4.0。

## [0.2.0] - 2026-11-20

### Changed

- 升级到 netops v0.3.0，默认配置改为 `~/.gatework/wireless.yml`。旧配置及同目录的 `.env` 可迁至 `~/.gatework/`，也可通过 `WIRELESS_CONFIG` 指定原配置。

## [0.1.1] - 2026-11-20

- 无线认证会话的 VLAN 过滤改用 `netops/set`。

## [0.1.0] - 2026-11-20

- 设备会话改由 net-connector v0.10.0 `connector` 提供（替代已删除的 netops `connect`）；`internal/bootstrap.Config.Dialer` 返回 `ops.Dialer` 端口，CLI 不再接触传输。
- SSH 改为 x/crypto/ssh 进程内实现（`~/.ssh/config` 的 ProxyCommand 不再生效，跳板机用 `ssh.jump_host`）；会话后的 `screen-length disable` 由 h3c 驱动发送。
- Netdisco 平台识别改为注入 net-connector `vendors.Builtin()`（netops `inventory.Classifier`）；解码并发改用 errgroup，终端位置日志改用 netops `store/disk`。

### Changed（迁移到 netops）

- 依赖由 go-netops v0.4.2 + parser v0.2.2 改为 netops（ADR：netops/docs/adr/0001-netops-kernel.md）。
- 删除 `adapter/snapshot`、`adapter/netconnector` 与 `internal/workflow` 中的通用逻辑，改用 netops `store/snapshot`、`connect`、`ops.Collect`/`ops.Refresh`/`ops.Deploy`；终端位置记录移到 `adapter/sightings`（数据目录不变）。
- `Capture`/`Output`/`RefreshStatus` 改用 netops `capture.Capture` 与 `cache.Status`；目标控制器改用 `device.Device`，`-c` 选择器支持 `role=`、`site=` 等完整语法。
- 动作改为 netops `change.Plan`：已生效的动作记为"无需变更"而不是失败；计划与审批信封、执行记录、审计写入 netops `store/journal`；黑名单动作带回滚命令。
- 巡检规则参数改为类型化声明；策略中类型不符的参数覆盖直接报错。
- `netdisco` 配置改为 netops `inventory.NetdiscoConfig`（选择字段并入 `netdisco` 段，`cache_ttl` 写成时长如 `72h`）；不再支持单独的 `inventory` 段。
- 不再写 `summary.json`（无读取方）。

### Added（第三轮）

- 本地缓存：`--snapshot` 只读导入，之后默认使用缓存；按维度设置有效期，过期自动刷新；刷新失败回退缓存、失败退避、按控制器加锁；新鲜度横幅，JSON 输出改为 `{freshness, result}`。
- `wireless status`；`wireless cache refresh|import|prune`；`--offline`、`--cache`、`--limit`、`--verbose`；watch 的 systemd 与 launchd 示例。
- 冲突模式分类（多 MAC 抢 IP / 两 MAC 互抢 / 偶发），识别非本网常用网段，按 OUI 找出同批设备。
- 粘滞判定的 `roaming.area_pattern`（按楼层或区域判断附近 AP），以及轨迹中"曾在更好的 AP 上关联"这一证据。
- Idle AP 区分"疑似从未上线或已拆除"，并附隧道断开原因。
- 中文帮助模板与命令分组；拼写提示；`-c` 未匹配时列出可选控制器；错误信息中文化。
- health 默认按规则汇总，加 `--detail`、`--fail-on`；终端面板默认只显示异常项，并对长行折行。

### Changed（第三轮）

- `Capture.Merge` 改为按命令取较新的回显，失败不再覆盖已有回显。
- `--snapshot` 的含义从"快照目录即数据源"改为"只读导入来源"；默认数据目录改为 `~/.local/share/wireless/cache`。
- JSON 输出中的空列表一律为 `[]`。

### Added

- 链路质量算法（quality）：五因子评分、短板约束、主因判定（弱信号、拥塞、干扰、底噪、老旧终端、省电、速率异常）。
- 漫游分析（roam）：粘滞判定（证据置信度、覆盖空洞区分）、射频策略冲突检查、轨迹事件提取与乒乓判定。
- 射频策略解析：ap-group/ap-model/radio 与 wlan ap 覆盖、RRM 开关、模板 BTM。
- 终端关联轨迹日志与 `wireless watch`；`display wlan mobility roam-track` 解析（`--live`）。
- `wireless rf`、`wireless roam`、不写子命令的直接查询；client 全景首行结论与评分。
- 目标解析 Resolve；全网封堵（默认全部 AC，在线处先封再踢）、`--file` 批量、`--all`、黑名单一致性检查；kick 按 IP/账号自动定位 AC。
- MAC 输入兼容全角、空格、0x 前缀与 `*` 通配。
- health 新规则：sticky_clients、poor_quality_share、cochannel_density、band_imbalance、policy_conflict、pingpong。

### Changed

- diagnose 的信号分级改为 quality 评分；`thresholds` 只保留 echo_loss、recent_reboot、dhcp_grace，新增 `quality`、`roaming`、`history_days` 配置。
- 噪声底只接受 -110…-60 dBm；射频 Down 时利用率不计。
- coverage_hole 仅在同组无其他在线 AP 时报出。

- 厂商无关的无线领域模型、跨控制器 Index 与多义 Query。
- H3C Comware V7 解析：终端、AP/射频、BSS、802.1X/MAC 会话、IP 冲突、block-mac、认证相关配置。
- 分层诊断（diagnose）与基于 go-netops assess 的全局巡检（health）。
- 动作计划：踢下线、静态黑名单增删，经 go-netops apply 执行与回读校验。
- 快照目录读写（sha256 校验、整目录原子替换、按命令合并）与 net-connector 在线采集。
- 命令行：collect、find、client、ap、auth、conflicts、summary、health、kick、block。
