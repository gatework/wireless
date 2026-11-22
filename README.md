# wireless

面向网络管理员的多控制器无线运维工具与 Go 库。它汇聚多台 H3C 无线控制器（Comware V7，R5474–R5814）的以下数据：

- AP、射频、BSS；
- 终端；
- 802.1X 与 MAC 认证会话；
- IP 冲突记录；
- 黑名单；
- 与认证相关的配置。

主要能力：

- 按 IP、网段、MAC、MAC 片段、账号或 AP 名跨控制器秒级定位；
- 展示终端的入网链路与信号质量，并做分层诊断；
- 全局巡检；
- 受控地踢下线或加入静态黑名单。

模块路径 `github.com/gatework/wireless`，要求 Go 1.26+。设计与方法论见 [docs/design.md](docs/design.md)。

## 构建

```sh
make build          # bin/wireless
make check          # 规范门禁：fmt、tidy、vet、lint、arch、test、vuln
```

## 配置

复制 [examples/wireless.yml](examples/wireless.yml) 到 `~/.gatework/wireless.yml`。凭据放在同目录的 `.env` 中（权限 0600，参考 [examples/credentials.env.example](examples/credentials.env.example)），也可以直接用环境变量 `NC_H3C_WIRELESS_USERNAME` / `NC_H3C_WIRELESS_PASSWORD`。

## 使用

```sh
wireless --snapshot ~/Documents/Snapshots/wireless summary   # 首次：导入离线快照到本地缓存
wireless 10.158.8.247                    # 之后：不写子命令，唯一命中直接给终端全景与结论
wireless status                          # 配置、凭据、缓存各维度数据时间、刷新失败
wireless collect                         # 并发采集全部控制器，写入本地缓存
wireless find 10.158.152.184             # IP
wireless find d5c7                       # MAC 片段
wireless find 10.158.8.0/24              # 网段
wireless find 18620346                   # 账号（同时按 MAC 片段匹配）
wireless client aa32-ed65-d5c7           # 终端全景 + 分层诊断
wireless client 10.158.8.247 --live      # 先实时刷新终端与会话再诊断
wireless ap 6FAP06 --weak 20             # AP 详情、射频、BSS 与弱信号终端
wireless auth --method dot1x --vlan 3100-3199
wireless conflicts --days 7              # 按模式归类：多 MAC 抢 IP / 两 MAC 互抢 / 偶发
wireless summary                         # 控制器概览与 SSID 分布
wireless health                          # 全局巡检（按规则汇总；--detail 明细；--fail-on high 用于监控）
wireless rf --band 5g                    # 信道规划、终端质量最差的 AP、射频策略问题
wireless roam                            # 全网乒乓与粘滞 Top N
wireless roam aa32-ed65-d5c7 --live      # 单终端漫游时间线（含 AC roam-track）
wireless watch --interval 2m             # 积累漫游轨迹
wireless kick 10.158.8.247 --plan        # 按 IP/MAC/账号踢下线，自动找到所在 AC
wireless block add 10.158.8.247 --save   # 默认全网所有 AC 封堵，在线处先封再踢
wireless block add -f incident.txt --yes # 批量
wireless block list                      # 全网黑名单一致性
```

通用参数：

- `--snapshot DIR`：离线快照目录，只读导入本地缓存；
- `--cache DIR`：本地缓存目录（默认 `~/.local/share/wireless/cache`）；
- `--offline` / `--live`：只用缓存 / 忽略有效期强制刷新；
- `--limit N`：列表最多 N 条（默认 50，0 为全部）；
- `--verbose`：终端面板显示全部诊断项；
- `--controller/-c`：按 IP、网段或名称片段限定控制器，可重复；
- `--json`：输出机器可读的 JSON；


退出码：

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 1 | 未找到、数据不完整或已取消 |
| 2 | 错误 |
| 130 | 中断 |

## 缓存与刷新

所有查询都读取本地缓存。配置了控制器和凭据后，过期的数据会自动刷新；刷新失败时继续使用缓存，并在 stderr 横幅里注明数据时间和失败原因。用 `wireless watch` 作为服务常驻运行（见 `examples/wireless-watch.service`），可以让缓存一直保持新鲜。watch 由 netops 调度器驱动：轮次不重叠，运行历史可在 `wireless status` 中查看；采集失败和作业失败写入事件日志 `events.jsonl`，并可推送到签名 Webhook（见 `examples/wireless.yml` 的 `watch` 段）。

## 快照格式

```
<snapshot>/<控制器IP>/NN-<命令>.output   设备回显原文
<snapshot>/<控制器IP>/NN-<命令>.json     command、success、bytes、sha256、prompt、recorded_at
<cache>/.status/<IP>.json                最近一次刷新的时间与失败码（退避依据）
<cache>/journal/<日期>.jsonl              终端位置记录（漫游分析）
```

快照目录由 netops `store/snapshot` 读写，兼容 net-connector 批量采集的目录。读取时逐个校验大小与 sha256。写入时整目录原子替换，并按命令合并，所以部分刷新不会丢掉其他维度。

## 作为库使用

```go
v := h3c.New(h3c.Options{})
st, _ := snapshot.NewStore(root)
captures, _ := st.ReadAll(ctx)
var snaps []*wireless.Snapshot
for _, c := range captures {
	snaps = append(snaps, v.Decode(c))
}
ix := wireless.NewIndex(snaps...)
q, _ := wireless.ParseQuery("aa32-ed65-d5c7")
for _, view := range ix.Find(q).Clients {
	fmt.Println(view.Controller.Label(), view.Client.APName, view.Access)
}
```

## 测试层次

| 层次 | 入口 | 说明 |
| --- | --- | --- |
| 单元 | `go test ./...` | 合成样例，不访问网络或设备 |
| 模糊 | `make fuzz` | 全部 H3C 解析器 |
| 私有语料 | `make corpus WIRELESS_CORPUS=~/Documents/Snapshots/wireless` | 真实快照，只输出聚合计数 |
