# 术语

| 术语 | 含义 |
| --- | --- |
| 控制器（AC, Controller） | 集中管理 AP 的无线控制器，以管理 IP 标识，以 sysname 命名 |
| AP | 无线接入点；状态 Run 表示已加入 AC 并提供服务，Idle 表示未上线 |
| 射频（Radio） | AP 上的一个无线电，工作在 2.4G、5G 或 6G 的一个信道上 |
| BSS / BSSID | 某射频上广播的一个 SSID 实例及其 MAC |
| 服务模板（Service template） | H3C 的 SSID 配置单元：SSID、VLAN、AKM、用户认证方式、认证域 |
| AKM | 链路层密钥管理：802.1X（企业级）、PSK（预共享密钥）或无（开放） |
| 用户认证 | 链路之上的身份认证：802.1X、MAC（MAB）、Bypass（不认证）、Portal |
| 入网方式（Access method） | AKM × 用户认证的组合，例如 PSK+MAC、MAC+Portal |
| 认证会话（Auth session） | 802.1X 或 MAC 认证器持有的在线认证：账号、域、方式、初始/授权 VLAN |
| 授权 VLAN | RADIUS 下发的 VLAN；与 SSID 初始 VLAN 不同表示被重定向 |
| 认证链路（Auth chain） | 模板 → 域 → RADIUS 方案 → 服务器（或 Portal Web 服务器） |
| RSSI | H3C 报告的终端信号，单位为高于噪声底的 dB；估算 dBm = 噪声底 + RSSI |
| 噪声底（Noise floor） | 射频测得的背景噪声 dBm |
| 信道利用率 | 射频空口忙碌时间百分比 |
| IP 冲突 | AC 记录的"新终端使用了旧终端持有的地址"，时间无年份 |
| 随机 MAC | 本地管理位置 1 的 MAC，手机按 SSID 生成，会使基于 MAC 的认证失效 |
| 快照（Snapshot） | 一台 AC 在一个时刻的全部观测，每个维度带完整性状态 |
| 维度（Dimension） | 一类观测，如 clients、access_points、dot1x_sessions |
| 计数漂移（count_drift） | 设备报告总数与解析记录数的小幅差异，大表打印期间变化所致，不影响完整性 |
| 索引（Index） | 跨控制器按 MAC、IP、账号、AP 关联的只读视图 |
| 动作（Action） | 踢下线、加入或移出静态黑名单；以计划、确认、执行、回读校验的方式完成 |
| 链路质量（Quality） | 信号、速率效率、空口、噪声、负载五因子加权并受短板约束的 0–100 分 |
| 短板约束（Slack） | 总分不超过任一分项分数加其 slack，防止严重问题被平均掉 |
| 粘滞（Sticky） | 信号弱仍长时间停留在当前 AP、而同组另有可用 AP 的终端 |
| 覆盖空洞 | 信号弱且同组没有其他在线 AP，属覆盖不足而非终端问题 |
| 乒乓漫游 | 窗口内在两三个 AP 间来回漫游 |
| BTM | 802.11v BSS Transition Management，AC 引导终端漫游的机制 |
| anti-sticky | H3C `sacp anti-sticky`：低于阈值强制断开以促使漫游 |
| 接入拒绝阈值 | `option client reject enable rssi`：低于该值拒绝新关联 |
| 轨迹日志（Sightings） | 每次采集追加的终端位置记录，用于漫游事件提取 |
| 目标解析（Resolve） | 把 IP/MAC/账号/片段解析为待处置 MAC 的严格规则 |
| 本地缓存 | 每台 AC 每条命令最新一次回显的存放处，所有查询都读取它 |
| 有效期（TTL） | 某个维度的数据被视为最新的最长时间 |
| 新鲜度横幅 | 每次查询在 stderr 输出的数据时间、过期数量与刷新失败说明 |
| 退避 | 刷新失败后在一段时间内不再尝试该 AC |
| 冲突模式 | 按 IP 聚合的冲突历史分类：多 MAC 抢 IP、两 MAC 互抢、偶发 |
