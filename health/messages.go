package health

// Operator-facing finding details. Rule titles live in the rule metadata;
// all other Chinese text of this package lives here.
const (
	detailAPNotRunning = "型号 %s，序列号 %s，IP %s"
	detailEchoLoss     = "Echo 请求 %d，丢失 %d"
	detailRadioBusy    = "%s 信道 %d"
	detailCoverageHole = "%d/%d 个终端 RSSI 低于 %d"
	detailLicense      = "License 总数 %d，剩余 %d，已接入 AP %d"
	detailNoIPv4       = "AP %s，SSID %s，VLAN %d，在线 %s"
	detailNoSession    = "SSID %s，AP %s"
	detailSSID         = "SSID %s"
	detailMore         = "%s 等（另有 %d 个）"
	detailTunnelDown   = "，隧道断开原因：%s"
	actualNeverOnline  = "（疑似从未上线或已拆除，可清理配置）"
	detailPoorQuality  = "%d/%d 个终端质量为中/差，主因 %s：%s"
	detailChannelShare = "信道 %d 承载 %d/%d 个 5G 射频"
	detailOverlap      = "使用非 1/6/11 的重叠信道：%s"
	detailBand         = "2.4G 终端 %d/%d"
	detailNoNavigation = "，且未开启 wlan band-navigation"
	detailPolicyValues = "%d 台 AP（%d / %d）"
)
