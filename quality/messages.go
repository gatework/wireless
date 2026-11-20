package quality

// Operator-facing words. All Chinese text of this package lives here.

var gradeWords = [...]string{GradeUnknown: "未知", GradeExcellent: "优", GradeGood: "良", GradeFair: "中", GradePoor: "差"}

var causeWords = map[Cause]string{
	CauseNone:         "",
	CauseWeakSignal:   "弱信号",
	CauseCongestion:   "空口拥塞",
	CauseInterference: "干扰",
	CauseNoise:        "底噪高",
	CauseLegacyClient: "老旧终端",
	CausePowerSave:    "终端省电",
	CauseLowRate:      "速率异常偏低",
}

var causeAdvice = map[Cause]string{
	CauseNone:         "",
	CauseWeakSignal:   "终端离 AP 太远或有遮挡：靠近 AP，检查覆盖与功率，确认是否粘滞在远端 AP",
	CauseCongestion:   "本射频终端多且空口忙：开启负载均衡/5G 优先，或增加 AP 分担",
	CauseInterference: "空口忙但本射频业务少：存在同频或非 Wi-Fi 干扰，调整信道或开启 calibrate-channel",
	CauseNoise:        "底噪高：排查微波炉、蓝牙、无线摄像头等非 Wi-Fi 干扰源",
	CauseLegacyClient: "终端只支持旧标准或单流：属终端能力限制，可考虑限制老旧速率",
	CausePowerSave:    "终端处于省电模式：速率低多为省电所致，通常不是网络故障",
	CauseLowRate:      "信号与空口良好但速率低：疑似重传/干扰或终端驱动问题，结合漫游与冲突记录排查",
}
