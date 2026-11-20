# 设计：多控制器无线运维

## 1. 问题

园区无线由多台控制器（AC）分区管理。用户报障时，管理员手里通常只有一个线索：一个 IP、一个工号、手机上看到的 MAC 后几位，或者一个会议室的 AP 名。在 CLI 上排查要依次做三件事：

1. 猜是哪台 AC，逐台 `display wlan client`；
2. 在 802.1X 或 MAC 认证会话里核对账号、域和授权 VLAN；
3. 回到 AP 详情看射频的信道、利用率和噪声底。

一台 AC 上有上千终端时，`display wlan client verbose` 有数 MB，人工比对很慢，也容易漏。

本模块把这条排查链路固化成"定位 → 解释 → 判断 → 处置"。

## 2. 领域模型

```
Controller ─┬─ AccessPoint ── Radio ── BSS(SSID, 服务模板)
            ├─ Client ──(BSSID/AP/Radio)──▶ Radio
            │     └─(MAC)──▶ AuthSession (802.1X | MAC)
            ├─ IPConflict (IP, 新/旧 MAC, 时间)
            ├─ BlockedMAC
            └─ Configuration ── ServiceTemplate ─▶ Domain ─▶ RadiusScheme / PortalServer
```

- **Snapshot**：一台 AC 在一个时刻的全部观测。每个维度带 netops `evidence.Status`。
- **Index**：把多个 Snapshot 按 MAC、IP、账号、AP 关联起来。`Query` 只是一段文本，它可能同时是 IP、网段、完整 MAC、MAC 片段、账号或 AP 名，搜索时取所有解释的并集（例如 `18620346` 既可能是工号，也可能是 MAC 片段）。
- **ClientView**：一个终端连同解释它的全部关联：
  - 服务它的 AP 与射频；
  - 认证会话；
  - 服务模板与认证链路（域 → RADIUS 方案 → 服务器 / Portal）；
  - 入网方式；
  - 黑名单条目、IP 冲突记录；
  - 同一 MAC 在其他 AC 上的出现。

## 3. 入网方式判定

入网方式 = 链路安全（AKM）× 用户认证。

| 终端字段 / 模板配置 | 入网方式 | 认证会话 |
| --- | --- | --- |
| AKM 802.1X 或用户认证 802.1X | `802.1X` | dot1x |
| AKM PSK + 用户认证 MAC | `PSK+MAC` | mac |
| AKM PSK + 用户认证 Bypass | `PSK`（只有共享密钥，无身份） | 无 |
| 开放 + MAC 认证 + `portal enable` | `MAC+Portal`（MAC-trigger 无感知） | mac |
| 开放 + `portal enable` | `Portal` | portal |
| 开放 + MAC 认证 | `MAC` | mac |
| AKM `Not configured` + Bypass | `Open` | 无 |

终端记录未报告 AKM 时（空值）不下结论，入网方式保持 `未知`，这与 `Not configured`（开放）是两种情况。Portal 需要服务模板才能识别，因此 Index 用 SSID 关联启用中的模板来补全入网方式。

## 4. 分层诊断（diagnose）

从下往上排查，下层故障通常能解释上层症状：

| 层 | 检查 | 依据 |
| --- | --- | --- |
| 关联 | 漫游状态；同一 MAC 出现在多台 AC；随机 MAC（使用 MAC 认证时升级为警告）；粘滞或覆盖不足；乒乓漫游与漫游历史 | client、Index、轨迹 |
| 射频 | 链路质量分数与主因（见 4.1）；老旧 PHY；双频 AP 下停留在 2.4G | client + radio |
| 认证 | 入网方式与链路；需要认证却没有会话（仅当会话维度完整时才下结论）；RADIUS 下发 VLAN 与初始 VLAN 不同；终端 VLAN 与授权 VLAN 不一致；模板启用 TKIP/WPA | 会话 + 配置 |
| 地址 | 没有 IPv4（超过 DHCP 宽限）；169.254 地址；同一 IP 被多台终端使用；IP 冲突历史 | client + Index + 冲突表 |
| 管控 | 在黑名单中 | block-mac |
| AP | Echo 丢失率；最近重启 | AP 详情 |

H3C 的 RSSI 是相对噪声底的 dB 值，近似 SNR，因此估算信号 dBm ≈ 射频噪声底 + RSSI。阈值统一放在 `Thresholds` 中，可在 `wireless.yml` 中覆盖。

## 4.1 链路质量算法（quality）

每个终端算 5 个分项，每项 0–100 分，按分段线性锚点插值。锚点、权重和短板约束都可以在 `wireless.yml` 的 `quality:` 中调整。

| 分项 | 输入 | 默认锚点（值→分） | 权重 | 短板约束 |
| --- | --- | --- | --- | --- |
| 信号 | RSSI，即相对噪声底的 dB，近似 SNR | 10→0，15→25，20→45，25→65，35→90，40→100 | 0.40 | +15 |
| 速率效率 | max(Rx, Tx) ÷ 理论 PHY 上限 | 0.05→10，0.15→40，0.3→70，0.6→100 | 0.20 | +40 |
| 空口 | 服务射频利用率（仅射频 Up 时有效） | 30%→100，50→80，70→50，90→10 | 0.20 | +30 |
| 噪声 | 噪声底（只接受 -110…-60 dBm，0 或 -35 这类值视为未测量） | -90→100，-85→85，-80→60，-75→30，-70→10 | 0.10 | +40 |
| 负载 | 同一射频上的终端数 | 15→100，30→70，50→40 | 0.10 | +40 |

**理论 PHY 上限**：按代际和带宽查表，再乘以空间流数。

- 代际：802.11b 为 11，a/g 为 54；HT（11n）20/40MHz 为 72.2/150；VHT（11ac）20/40/80/160MHz 为 86.7/200/433.3/866.7；HE（11ax）20/40/80/160MHz 为 143.4/286.8/600.5/1201（单位 Mbps）。
- 空间流数：由终端通告的 MCS 集推出（HE/VHT 看 `NSSk`，HT 看最高 MCS/8+1），再受 AP 射频 MIMO 能力限制。

**合成**：`Q = Σ wᵢ·Sᵢ / Σ wᵢ`，再取 `min(Q, Sᵢ + slackᵢ)`。没有测到的分项不参与计算。效果是一个严重的短板会直接压住总分，不会被其他高分项平均掉；信号的约束最紧。

**分级**：≥80 优，60–79 良，40–59 中，<40 差。

**主因判定**：取得分最低、且低于 50 的分项，再结合上下文解释。

| 最低分项 | 上下文 | 主因 |
| --- | --- | --- |
| 信号 | — | 弱信号 |
| 空口 | 本射频终端 ≥ 20 | 拥塞 |
| 空口 | 本射频终端 < 20 | 干扰（空口忙但不是自己的业务，即同频或非 Wi-Fi 干扰） |
| 噪声 | — | 底噪高 |
| 负载 | — | 拥塞 |
| 速率效率 | 老旧 PHY 或单流 HT | 老旧终端 |
| 速率效率 | SM 省电开启 | 终端省电 |
| 速率效率 | 其他 | 速率异常（疑似重传） |

在 9 台控制器、6235 个有信号的终端上，分布为优 92%、良 4.8%、中 2.5%、差 0.4%。例如 CKG7-10F-AP11 radio2 利用率 90% 但只有 2 个终端，判为干扰；CKG5 实验室 AP 有 40 个终端，判为拥塞。

## 4.2 漫游分析（roam）

### 射频策略来源

配置中有两层，合并时 AP 自身的设置覆盖组内型号的设置：

- `wlan ap-group G` → `ap-model M` → `radio N` 下的 `option client reject enable rssi R`、`sacp anti-sticky enable [rssi S] interval I`、`option roam-navigation enable rssi`、`max-power`、`channel band-width`；
- `wlan ap X` → `radio N` 下的同类设置。

另外采集全局开关：band-navigation、load-balance、calibrate-channel/power，以及模板上的 `bss transition-management`（802.11v）。

### 粘滞终端（单快照可判定）

判定条件：RSSI 低于阈值（射频配置了 anti-sticky rssi 时取该值，否则取 25），关联时长超过 5 分钟，并且附近还有其他在线 AP。"附近"默认指同一 AP 组；配置 `roaming.area_pattern` 后，按 AP 名称提取出的楼层或区域判断，因为一个 AP 组可能覆盖整栋楼。

- **置信度只看终端自身的证据**，基础为"低"，每满足一条加一级：
  - 终端 BTM 为 Inactive（不支持 802.11v，无法被引导）；
  - 已停留 30 分钟以上；
  - RSSI 比阈值低 10 以上；
  - 轨迹显示该终端曾在其他 AP 上以明显更好的信号（阈值 +10 以上）关联过。
- **加重因素只列出，不计入置信度**：SSID 未开 BTM、射频未开 anti-sticky。它们说明环境为什么没有干预，但不能说明这个终端本身的情况。
- **覆盖空洞**：同组没有其他在线 AP 时，不判为粘滞，而是报覆盖不足。

### 策略冲突

| 冲突 | 后果 |
| --- | --- |
| anti-sticky rssi 高于 reject rssi | 区间内的终端被踢下线后又被同一 AP 接纳，反复掉线。真实语料中 SZX10 default-group 为 20/25，命中此问题 |
| 2.4G 功率高于 5G | 双频终端被吸附到 2.4G。语料中有 8 台 AP |
| 2.4G 使用 40MHz | 占用大部分 2.4G 频段，相邻 AP 必然同频干扰 |

### 轨迹与乒乓

**数据来源**有两个：

- `collect` 或 `watch` 每采到一次 clients，就向 `<snapshot>/journal/<UTC日期>.jsonl` 追加每个终端一条记录：`{t, ctrl, mac, ap, radio, ch, rssi, ip, online}`，保留 `history_days` 天；
- `--live` 时读取 `display wlan mobility roam-track mac-address M`，即 AC 自己的漫游历史。各列按内容识别，不依赖位置；同时兼容旧版 `d:h:m:s` / `-HOME AC-` 格式。

**事件提取**：在相邻两次观测之间判定。

| 变化 | 事件 |
| --- | --- |
| AP 变化 | 漫游 |
| AC 变化 | 跨 AC 漫游 |
| 同一 AP，但关联时长小于两次采样间隔（容差 30 秒） | 重关联 |

如果关联时长小于采样间隔，事件时间回推到关联开始的时刻。

**乒乓判定**：在 10 分钟窗口内出现 A→B→A，或 1 小时内漫游 ≥ 6 次且只涉及 ≤ 3 个 AP。附带两条诊断：

- 同频：两个 AP 在同一信道上；
- 边界信号：两侧 RSSI 都在 15–25 之间，说明覆盖重叠过大。

采样中位间隔大于窗口时，标为"采样不足"，不下结论。

## 4.3 定位与封堵的输入兼容

**MAC 写法**：以下写法都能识别。

- 分隔符：`-`、`:`、`.`、空格、`_`，或没有分隔符；
- `0x` 前缀、大小写混合；
- 全角字符（`ａａ：ｂｂ`、`－`），按 Unicode 宽度折叠成半角；
- MAB 账号写法（`98-40-5a-ad-57-0a`）。

**MAC 片段**（至少 4 位十六进制）：

- `d5c7` 为包含匹配；
- `aa32*` 为前缀匹配；
- `*d5c7` 为后缀匹配。

**目标解析（Resolve）**：比查询更严格，因为结果用于下发变更。

| 输入 | 解析结果 |
| --- | --- |
| 完整 MAC | 总是解析为它本身，即使当前不在任何 AC 上（允许预先封堵） |
| IP 或网段 | 当前持有该地址的终端和认证会话。只在 IP 冲突记录中出现过的 MAC 作为提示列出，不自动纳入 |
| 账号 | 精确匹配，从不做子串匹配 |
| 片段 | 命中多个 MAC 时必须加 `--all`，否则列出候选并退出 |

**全网封堵**：静态黑名单按 AC 生效，所以 `block add` 默认对所有已配置的控制器生成计划；没有配置控制器时，取快照中出现的全部控制器。

- 终端当前在线的 AC 上，计划为"先加黑名单，再踢下线"，避免已有关联继续保持；
- 所有计划一次确认后并发执行，每台 AC 独立写日志；
- 任意一台不是 verified 时退出码为 1；
- `block list` 汇总全网黑名单，并标出只存在于部分 AC 上的条目；
- `kick` 只对快照中终端在线的 AC 生效。

## 5. 全局巡检（health）

全局巡检基于 netops `assess`，每台 AC 独立运行规则。某个维度不完整时，依赖它的规则记为 skipped，不会因此得出"健康"的结论。

| 规则 | 类别 | 默认级别 |
| --- | --- | --- |
| `wireless.ap_not_running` | 运行态 | 高 |
| `wireless.ap_echo_loss`（>1%，至少 1000 次 Echo） | 运行态 | 中 |
| `wireless.radio_busy`（≥70%） | 容量 | 中 |
| `wireless.coverage_hole`（某 AP 下 RSSI<20 的终端占比 ≥30%，且至少 5 个终端） | 容量 | 中 |
| `wireless.license_low`（剩余 <5） | 容量 | 中 |
| `wireless.legacy_security`（TKIP/WPA） | 安全 | 中 |
| `wireless.client_no_ipv4` | 运行态 | 中 |
| `wireless.ip_conflict_recent`（近 7 天，按 AC 聚合） | 运行态 | 中 |
| `wireless.duplicate_mac`（跨 AC） | 一致性 | 低 |
| `wireless.client_no_session` | 一致性 | 低 |
| `wireless.radio_down`（按频段聚合；常为有意关闭） | 运行态 | 提示 |
| `wireless.shared_key_only` | 安全 | 提示 |
| `wireless.sticky_clients`（每个 AP 下 ≥2 个疑似粘滞终端） | 运行态 | 中 |
| `wireless.poor_quality_share`（AP 下质量为中或差的终端 ≥30%） | 容量 | 中 |
| `wireless.cochannel_density`（5G 同频占比 ≥40%；2.4G 使用非 1/6/11 信道） | 容量 | 低 |
| `wireless.band_imbalance`（双频 AP 上 2.4G 终端占比 ≥50%） | 容量 | 低 |
| `wireless.policy_conflict` | 配置 | 中 |
| `wireless.pingpong`（需要轨迹；没有轨迹时跳过并提示） | 运行态 | 中 |

`wireless.coverage_hole` 只在同 AP 组没有其他在线 AP 时报出；有邻居 AP 时，同样的现象归入粘滞规则。

## 6. 证据完整性

- 大表在打印过程中会变化：设备报告的总数与实际解析出的记录数相差不超过 max(2, 0.5%) 时记为 `count_drift`，维度仍为 complete；相差更大时记为 `count_mismatch`，维度降为 partial。
- 输出为空、也没有 Total 行时，视为 0 条记录，维度为 complete。
- 被设备拒绝的命令记为 failed；没有采集的维度记为 not_requested。
- 无法识别的行记为 issue，维度降为 partial；未建模但格式规范的字段保存在 `Extra` 中，供详情展示，不算问题。

## 7. 数据流

```
            ┌──────── collect / --live ────────┐
controllers ─▶ netops connect ─▶ capture.Capture ─┤ merge by command（ops.Collect / ops.Refresh）
                                                   ▼
                    netops store/snapshot <root>/<IP>/NN-<cmd>.output + .json (sha256)
                                                   │ LoadAll
                                                ▼
                          vendors/h3c.Decode ─▶ Snapshot × N ─▶ Index
                                                                 ├─ find / client / ap / auth / conflicts / summary
                                                                 ├─ diagnose.Client
                                                                 └─ health.Inspector (assess)
```

- 查询默认只读快照，9 台 AC、约 6300 个终端的全量解析在 1 秒以内完成。
- `--live` 先刷新所需维度，再按命令粒度合并进快照。例如 `find` 只采终端和认证会话，已有的 AP 和配置保持不动。
- 采集失败的 AC 也会保存已经收到的回显。

## 7.1 本地缓存与自动刷新

缓存目录默认是 `~/.local/share/wireless/cache`，格式与快照目录相同：每台控制器一个子目录，每条命令一份回显，各自带 `recorded_at`。

| 环节 | 规则 |
| --- | --- |
| 导入 | `--snapshot DIR` 或 `snapshot:` 配置的离线目录只读取，从不写入。每次运行按命令合并进缓存，较新的回显胜出；之后无需再指定 |
| 有效期 | 按维度设置：终端和会话 5m、黑名单 10m、AP/BSS 30m、冲突 1h、配置 24h。每个命令只检查自己用到的维度 |
| 刷新 | `auto` 只刷新过期维度；`--live` 强制刷新；`--offline` 绝不连接设备。没有凭据或该控制器不在配置中时，只用缓存 |
| 预算 | 一次查询的刷新最多 45s，超时的控制器视为本次刷新失败 |
| 回退 | 刷新失败时，旧回显不会被删除（Merge 的规则是失败不覆盖已有回显）；失败码写入 `.status/<ip>.json` |
| 退避 | 失败后 2m 内不再尝试该控制器，避免每次查询都等待，也避免反复认证失败导致账号被锁 |
| 并发 | 每台控制器一把写锁（`.locks/<ip>.lock`），watch 与交互查询可以同时运行 |
| 可见性 | stderr 横幅显示数据时间、已过期的控制器数、刷新失败的原因与回退的缓存时间；`--json` 的输出形如 `{freshness, result}` |
| 处置 | kick/block 解析目标前，强制刷新终端和会话数据 |

保持缓存常热：用 `wireless watch` 作为常驻服务（示例见 `examples/` 中的 systemd 和 launchd 配置）。这样交互查询几乎总能直接命中新鲜缓存。

## 7.2 冲突模式

| 模式 | 判定 | 结论 |
| --- | --- | --- |
| 多 MAC 抢同一 IP | 一个 IP 涉及 ≥ 3 个 MAC | 静态 IP 或私接 DHCP。若该地址不在本 AC 常用 /16 网段内（承载 ≥ 1% 的终端才算常用），判为私设或家用网段 |
| 两 MAC 反复互抢 | 同一对 MAC 冲突 ≥ 3 次 | 双网卡，或终端在随机 MAC 与真实 MAC 之间切换 |
| 偶发 | 其他情况 | 通常是 DHCP 租约残留 |

同时找出共享同一 OUI 的 MAC（随机 MAC 不参与），用于定位同一批设备。

实测结果：SZX9 上的 192.168.1.80 冲突 4551 次，判为"多 MAC 抢同一 IP / 非本网常用网段 / 5 个 MAC 同属 OUI 6879-c4"。

## 8. 处置闭环（action）

```
plan（渲染命令 + 回读命令，指纹）→ 人工确认（输入 "KICK aabb-ccdd-eeff"）
→ apply.Run：回读 → CheckBefore → 逐条写入（意图先入日志）→ 回读 → CheckAfter → configuration_verified
```

| 动作 | 命令（H3C） | 前置条件 | 验证 |
| --- | --- | --- | --- |
| kick | `reset wlan client mac-address M` | 终端在线 | 终端消失，或关联时长变短（已重新关联） |
| block add | `system-view` / `wlan static-blacklist mac-address M` / `return` | 不在黑名单中 | 在黑名单中 |
| block remove | `undo wlan static-blacklist mac-address M` | 在黑名单中 | 不在黑名单中 |

- 命令执行后才失败的情况记为 `uncertain`，不自动重试。
- 只有显式指定 `--save` 时才保存配置，且在执行变更的同一会话中进行。
- 这些命令在现有快照中没有样例，首次使用前应在测试 AC 上先用 `--plan` 预览并核对语法。

## 9. 复用

| 能力 | 模块 |
| --- | --- |
| SSH 会话、精确提示符、平台 `h3c_wireless`、原子写入 | net-connector |
| 证据、规则引擎、采集与缓存、快照、变更计划与执行、日志与审计、凭据、清单、CLI 表格与确认 | netops |
| 配置分段游标、字段标签表 | netops `parse` |
| VLAN 列表过滤 | gatework/netops/set |
| 东亚宽字符对齐 | netops `term` |
