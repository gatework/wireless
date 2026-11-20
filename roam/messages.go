package roam

// Operator-facing words. All Chinese text of this package lives here.

var confidenceWords = [...]string{ConfidenceNone: "", ConfidenceLow: "低", ConfidenceMedium: "中", ConfidenceHigh: "高"}

var reasonWords = map[Reason]string{
	ReasonWeakAndStaying: "信号弱仍长时间停留在当前 AP",
	ReasonNoBTM:          "终端不支持 802.11v BTM，AC 无法引导其漫游",
	ReasonLongDwell:      "弱信号下已停留 30 分钟以上",
	ReasonVeryWeak:       "信号远低于阈值",
	ReasonBetterAPSeen:   "轨迹显示终端曾在其他 AP 上以明显更好的信号关联",
	ReasonSSIDNoBTM:      "加重因素：该 SSID 未开启 bss transition-management",
	ReasonNoAntiSticky:   "加重因素：所在射频未开启 sacp anti-sticky",
	ReasonNoAlternative:  "附近没有其他在线 AP，属覆盖不足而非粘滞",
}

var policyWords = map[PolicyCode]string{
	PolicyStickyLoop:    "anti-sticky 阈值高于接入拒绝阈值：RSSI 介于两者之间的终端会被踢下线后又被同一 AP 接纳，反复掉线",
	PolicyPower24Above5: "2.4G 功率高于 5G：双频终端会被吸附到更慢的 2.4G",
	PolicyWide24:        "2.4G 使用 40MHz：占用大部分 2.4G 频段，相邻 AP 必然同频干扰",
}
