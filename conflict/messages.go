package conflict

// Operator-facing words. All Chinese text of this package lives here.

var patternWords = map[Pattern]string{
	PatternShared:   "多 MAC 抢同一 IP",
	PatternPair:     "两 MAC 反复互抢",
	PatternSporadic: "偶发",
}

var patternAdvice = map[Pattern]string{
	PatternShared:   "终端手工配置了静态 IP，或有私接 DHCP；按 MAC 找到设备改为自动获取，并核查 DHCP Snooping",
	PatternPair:     "同一设备的两块网卡，或手机在随机 MAC 与真实 MAC 间切换；确认为同一用户后可忽略或固定 MAC",
	PatternSporadic: "多为 DHCP 租约残留，通常无需处理",
}
