package diagnose

// Code identifies a finding independently of its wording.
type Code string

// Finding codes.
const (
	CodeRoam              Code = "roam"
	CodeElsewhere         Code = "elsewhere"
	CodeRandomizedMAC     Code = "randomized_mac"
	CodeRandomizedMACAuth Code = "randomized_mac_auth"
	CodeQuality           Code = "quality"
	CodeSticky            Code = "sticky"
	CodeCoverageGap       Code = "coverage_gap"
	CodePingPong          Code = "ping_pong"
	CodeRoamHistory       Code = "roam_history"
	CodeTrackSparse       Code = "track_sparse"
	CodePolicy            Code = "policy"
	CodeSignal            Code = "signal"
	CodeSignalUnknown     Code = "signal_unknown"
	CodeLegacyPHY         Code = "legacy_phy"
	CodeBand24            Code = "band_24"
	CodeAccess            Code = "access"
	CodeSharedKey         Code = "shared_key"
	CodeNoSession         Code = "no_session"
	CodeVLANOverride      Code = "vlan_override"
	CodeVLANMismatch      Code = "vlan_mismatch"
	CodeLegacySecurity    Code = "legacy_security"
	CodeNoIPv4            Code = "no_ipv4"
	CodeLinkLocal         Code = "link_local"
	CodeDuplicateIP       Code = "duplicate_ip"
	CodeConflicts         Code = "conflicts"
	CodeBlocked           Code = "blocked"
	CodeEchoLoss          Code = "echo_loss"
	CodeAPRebooted        Code = "ap_rebooted"
	CodeAPUnknown         Code = "ap_unknown"
	CodeEvidencePartial   Code = "evidence_partial"
)

// messages holds the operator-facing wording of every code. All Chinese
// output text of this package lives here.
var messages = map[Code]string{
	CodeRoam:              "漫游状态：%s",
	CodeElsewhere:         "同一 MAC 同时出现在其他控制器：%s（跨 AC 漫游中或 MAC 重复）",
	CodeRandomizedMAC:     "终端使用随机（私有）MAC，换 SSID 或重置网络后 MAC 会变化",
	CodeRandomizedMACAuth: "终端使用随机 MAC 且依赖 MAC 认证：登记的 MAC 与当前不一致将导致认证失败，请关闭该 SSID 的私有地址",
	CodeQuality:           "链路质量 %s（%d 分）：%s",
	CodeSticky:            "疑似粘滞（置信度 %s）：RSSI %d 低于 %d，%s另有 %d 台在线 AP；%s",
	CodeCoverageGap:       "信号弱（RSSI %d）且同 AP 组没有其他在线 AP：覆盖不足，需要补点或调整功率",
	CodePingPong:          "乒乓漫游：%s 往返 %d 次，最快 %s 一个来回%s",
	CodeRoamHistory:       "近 %s 内漫游 %d 次，未见乒乓",
	CodeTrackSparse:       "轨迹采样间隔过大，无法判断乒乓漫游；用 wireless watch 缩短采样间隔",
	CodePolicy:            "AP %s 射频策略：%s",
	CodeSignal:            "RSSI %d（约 %d dBm）",
	CodeSignalUnknown:     "信号 RSSI %d（射频噪声底未知，无法估算 dBm）",
	CodeLegacyPHY:         "终端以老旧模式 %s 接入，会拖慢同信道其他终端",
	CodeBand24:            "终端位于 2.4G，该 AP 有可用 5G 射频；若终端支持 5G 可考虑频段引导",
	CodeAccess:            "入网方式 %s：%s",
	CodeSharedKey:         "仅预共享密钥接入，无用户身份可追溯",
	CodeNoSession:         "入网方式需要认证，但未找到 %s 认证会话",
	CodeVLANOverride:      "RADIUS 授权 VLAN %d（SSID 初始 VLAN %d）",
	CodeVLANMismatch:      "终端 VLAN %d 与认证授权 VLAN %d 不一致",
	CodeLegacySecurity:    "服务模板 %s 仍启用 TKIP/WPA，影响安全与速率",
	CodeNoIPv4:            "已关联 %s 仍无 IPv4 地址：检查 DHCP、VLAN %d 网关与中继",
	CodeLinkLocal:         "IPv4 %s 为自动私有地址，DHCP 未成功",
	CodeDuplicateIP:       "IPv4 %s 同时被其他终端使用：%s",
	CodeConflicts:         "IP 冲突记录 %d 条，最近一次 %s",
	CodeBlocked:           "MAC 在黑名单中（%s）",
	CodeEchoLoss:          "AP %s 与 AC 的 Echo 丢失率 %.2f%%，链路不稳定",
	CodeAPRebooted:        "AP %s 最近重启（运行 %s，原因：%s）",
	CodeAPUnknown:         "未在 AP 列表中找到 %s，无法评估射频",
	CodeEvidencePartial:   "%s 数据不完整，结论可能缺失",
}

// Labels used inside composed messages.
const (
	labelAccount    = "账号"
	labelDomain     = "域"
	labelMethod     = "方式"
	labelTemplate   = "模板"
	labelUnknown    = "未知"
	detailSeparator = "，"
	labelNoCause    = "无明显问题"
	labelSameArea   = "同区域"
	labelSameGroup  = "同 AP 组"
	hintSameChannel = "；两 AP 同信道，相互干扰"
	hintEdge        = "；两侧信号都处在边界区，覆盖重叠过大，可降功率或调高 roam-navigation 阈值"
)
