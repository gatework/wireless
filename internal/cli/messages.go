package cli

import (
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

// Operator-facing text. All Chinese output of the command line lives here.

const (
	shortRoot = "多控制器无线运维：终端定位、入网诊断、信号分析、巡检与处置"
	longRoot  = `wireless 面向无线网络管理员，汇聚多台无线控制器（H3C Comware V7）的
AP、射频、BSS、终端、802.1X/MAC 认证会话、IP 冲突与黑名单数据，
按 IP / 网段 / MAC / MAC 片段 / 账号 / AP 名快速定位，并给出分层诊断。

数据来源：本地缓存（~/.local/share/wireless/cache）。首次用 --snapshot <离线快照目录>
导入，之后直接查询；配置了控制器与凭据时，过期数据自动刷新，刷新失败回退缓存并在
横幅中注明数据时间。--live 强制刷新，--offline 只用缓存。运行 wireless status 查看状态。

最常用：wireless <IP|MAC|账号>  直接给出终端位置、入网链路、质量与诊断。

退出码：0 成功；1 未找到或数据不完整；2 参数、配置或 I/O 错误；130 中断。`

	shortCollect      = "并发采集控制器回显并写入快照目录"
	shortFind         = "跨控制器定位终端/AP（IP、网段、MAC、MAC 片段、账号、AP 名）"
	shortClient       = "终端全景：位置、入网链路、信号与分层诊断"
	shortAP           = "AP 列表或详情：状态、射频、BSS 与终端"
	shortAuth         = "认证会话查询与统计（802.1X / MAC）"
	shortConflicts    = "IP 冲突历史（按 IP 聚合）"
	shortSummary      = "控制器概览与 SSID 分布"
	shortHealth       = "全局巡检：AP、射频、覆盖、License、安全与地址"
	shortKick         = "将终端踢下线（reset wlan client），自动找到在线所在的控制器"
	shortRF           = "射频体检：信道规划、忙碌/噪声射频、AP 终端质量与漫游策略问题"
	shortRoam         = "漫游分析：全网乒乓与粘滞，或单终端漫游时间线"
	shortWatch        = "周期采集终端列表，保持缓存常热并积累漫游轨迹"
	shortStatus       = "运行状态：配置、凭据、缓存各维度数据时间、刷新失败与轨迹"
	shortCache        = "本地缓存：refresh / import / prune"
	shortCacheRefresh = "刷新已过有效期的数据（--all 全部刷新）"
	shortCacheImport  = "把离线快照目录导入本地缓存（只读来源，较新者胜）"
	shortCachePrune   = "清理中断写入留下的临时目录"
	shortHelp         = "查看帮助"
	shortBlock        = "静态黑名单：add / remove / list"
	shortBlockAdd     = "加入静态黑名单（MAC/IP/账号，默认全网所有 AC）"
	shortBlockDel     = "移出静态黑名单（MAC/IP/账号，默认全网所有 AC）"
	shortBlockList    = "实时查看控制器静态黑名单"

	flagConfig     = "配置文件（默认 $WIRELESS_CONFIG、./wireless.yml、~/.config/wireless/wireless.yml）"
	flagEnvFile    = "凭据文件（默认配置文件同目录 .env，权限须为 0600）"
	flagSnapshot   = "离线快照目录：只读导入本地缓存（之后无需再指定）"
	flagJSON       = "以 JSON 输出"
	flagLive       = "忽略缓存有效期，实时刷新所需数据"
	flagVerbose    = "显示全部诊断项（含正常项）"
	flagOffline    = "只用本地缓存，绝不连接设备"
	flagCache      = "本地缓存目录（默认 ~/.local/share/wireless/cache，或 $WIRELESS_CACHE）"
	flagController = "限定控制器：IP、网段或名称片段，可重复"
	flagDimension  = "只采集指定维度，可重复：clients dot1x_sessions mac_sessions access_points bss ip_conflicts blocked_macs configuration"
	flagParallel   = "并发控制器数（默认取配置 parallel）"
	flagMethod     = "认证方式：dot1x 或 mac"
	flagUser       = "账号片段"
	flagSSID       = "SSID（精确匹配）"
	flagVLAN       = "VLAN 列表，如 3100-3199,3267"
	flagIP         = "IP 或网段"
	flagDays       = "只看最近 N 天（0 表示全部）"
	flagYes        = "跳过交互确认（仅用于已审批的自动化）"
	flagPlanOnly   = "只显示计划，不执行"
	flagSave       = "成功后执行 save force 保存配置"
	flagWeak       = "只列出弱信号终端（RSSI 低于该值）"
	flagLimit      = "列表最多显示条数（0 表示全部）"
	flagSince      = "漫游轨迹的回看时长，如 1h、24h"
	flagInterval   = "采样间隔（乒乓判定需小于 10 分钟）"
	flagBand       = "只看某频段：2.4g 或 5g"
	flagFile       = "批量目标文件：每行一个 MAC、IP 或账号，# 开头为注释"
	flagAll        = "目标解析出多个 MAC 时全部执行"
	flagTop        = "列出前 N 个"
	flagRounds     = "采集轮数（0 表示直到 Ctrl-C）"
	flagRefreshAll = "忽略有效期，刷新全部维度"
	flagDetail     = "逐条列出每个发现（默认按规则汇总）"
	flagFailOn     = "发现达到该级别（info/low/medium/high/critical）时退出码为 1"
	flagHelp       = "查看帮助"
	flagVersion    = "显示版本"
)

// Table headers.
var (
	headFindClients    = []string{"控制器", "AP", "射频/信道", "SSID", "VLAN", "IPv4", "MAC", "账号", "入网", "RSSI", "在线"}
	headSessions       = []string{"控制器", "类型", "MAC", "账号", "域", "方式", "IPv4", "AP", "SSID", "授权VLAN", "在线"}
	headAPs            = []string{"控制器", "AP", "状态", "型号", "IP", "MAC", "终端", "在线", "版本"}
	headConflicts      = []string{"控制器", "IP", "次数", "最近", "涉及 MAC"}
	headConflictGroups = []string{"控制器", "IP", "次数", "最近", "模式", "MAC", "判断"}
	headBlocked        = []string{"控制器", "MAC", "来源", "说明"}
	headRadios         = []string{"射频", "状态", "类型", "信道", "带宽", "功率", "利用率", "噪声", "BSSID"}
	headBSS            = []string{"射频", "BSSID", "SSID", "模板", "VLAN", "AKM", "用户认证"}
	headAPClients      = []string{"MAC", "IPv4", "账号", "SSID", "射频", "RSSI", "速率 Rx/Tx", "入网", "在线"}
	headSummary        = []string{"控制器", "版本", "AP 在线/总", "License 余/总", "终端", "802.1X", "MAC", "冲突(7天)", "完整性"}
	headSSID           = []string{"SSID", "终端", "2.4G", "5G", "入网方式", "平均RSSI", "弱信号"}
	headHealth         = []string{"级别", "规则", "对象", "实际", "说明"}
	headHealthSummary  = []string{"级别", "规则", "数量", "控制器", "示例"}
	headCollect        = []string{"控制器", "状态", "耗时", "维度", "错误"}
	headStats          = []string{"维度", "取值", "会话数"}
	headChannels       = []string{"控制器", "AP 组", "频段", "射频", "信道:数量", "忙碌", "高噪声", "功率"}
	headAPQuality      = []string{"控制器", "AP", "终端", "2.4G/5G", "均分", "P10", "中差", "主因"}
	headPolicy         = []string{"控制器", "AP", "射频", "问题"}
	headPingPong       = []string{"MAC", "控制器", "往返 AP", "次数", "最快", "同频", "边界信号"}
	headSticky         = []string{"MAC", "控制器", "AP", "RSSI", "置信度", "依据"}
	headTimeline       = []string{"时间", "事件", "从", "到", "信道", "RSSI"}
	headPlan           = []string{"控制器", "MAC", "动作", "命令", "回读"}
	headOutcome        = []string{"控制器", "MAC", "结果", "日志", "保存"}
	headBlacklist      = []string{"MAC", "范围", "控制器"}
)

// Messages.
const (
	msgNotFound         = "未找到匹配 %q 的记录\n"
	msgNoCache          = "本地缓存 %s 中还没有数据：用 --snapshot <离线快照目录> 导入，或配置控制器与凭据后运行 wireless collect\n"
	msgNoMatch          = "-c %s 没有匹配的控制器；可选：%s\n"
	msgImported         = "已从 %[2]s 导入 %[1]d 台控制器的数据到本地缓存 %[3]s\n"
	msgTargetsFailed    = "读取控制器清单失败，本次只用缓存：%v\n"
	msgRefreshing       = "刷新 %s …\n"
	msgHiddenOK         = "  （另有 %d 项正常，--verbose 显示）\n"
	msgConflictPattern  = "  %s：%d 个 IP —— %s\n"
	noteForeign         = "非本网常用网段（疑似私设/家用网段）"
	noteBatch           = "%[2]d 个 MAC 同属 OUI %[1]s（同批设备）"
	msgTruncated        = "（显示前 %d 条，共 %d 条；--limit 0 显示全部）\n"
	msgDidYouMean       = "是否想用子命令 %[2]s？例如：wireless %[2]s %[3]s（%[1]q 被当作查询文本）\n"
	msgImportResult     = "读取 %d 台控制器，更新 %d 台，缓存目录 %s\n"
	msgPruned           = "已清理 %d 个临时目录\n"
	msgSectionClients   = "终端（%d）\n"
	msgSectionOrphans   = "仅有认证会话、当前未关联的终端（%d）\n"
	msgSectionAPs       = "AP（%d）\n"
	msgSectionConfl     = "IP 冲突（%d 个 IP）\n"
	msgSectionBlocked   = "黑名单（%d）\n"
	msgClientTitle      = "== 终端 %s @ %s ==\n"
	msgLocation         = "位置    AP %s（%s %s）Radio %d  %s 信道 %d %s  BSSID %s\n"
	msgNetwork          = "网络    SSID %s  VLAN %s  IPv4 %s  IPv6 %s  账号 %s\n"
	msgAccess           = "入网    %s"
	msgSession          = "认证    %s 会话：账号 %s  域 %s  方式 %s  初始VLAN %s → 授权VLAN %s  上线 %s（%s）\n"
	msgNoSession        = "认证    无认证会话\n"
	msgChain            = "链路    模板 %s  域 %s  方案 %s  服务器 %s%s\n"
	msgPortal           = "  Portal %s"
	msgLink             = "信号    RSSI %d%s  噪声 %s  信道利用率 %s  模式 %s %s  速率 Rx/Tx %.1f/%.1f Mbps  吞吐 %.1f/%.1f Kbps\n"
	msgDBm              = " ≈ %d dBm"
	msgOnline           = "在线    %s  漫游 %s  休眠计数 %d\n"
	msgDiagnosis        = "诊断（%s）\n"
	msgVerdict          = "结论    %s\n"
	msgPlanTitle        = "执行计划（%d 条）\n"
	msgResolveNone      = "%q 没有对应的终端%s\n"
	msgResolveMany      = "%q 对应 %d 个 MAC：%s；确认全部处理请加 --all，或改用完整 MAC\n"
	msgConflictHint     = "（IP 冲突记录中出现过：%s，未自动纳入）"
	msgNotOnline        = "%s 当前不在线（快照中没有关联记录），跳过踢下线；需要禁止接入请用 block add\n"
	msgSaveFailed       = "保存失败"
	msgSavedShort       = "已保存"
	msgBlacklist        = "静态黑名单：%d 个 MAC，读取 %d 台控制器\n"
	msgConsistent       = "全网一致"
	msgPartialBlock     = "仅 %d/%d 台"
	msgListFailed       = "读取 %s 失败：%v\n"
	msgLookupHint       = "可输入：IP、网段（10.1.0.0/16）、完整或部分 MAC（d5c7、aa32*、*d5c7，任意分隔符/全角均可）、账号、AP 名\n"
	msgRFChannels       = "信道规划（按 AP 组）\n"
	msgRFQuality        = "\n终端质量最差的 AP（按 P10 升序，前 %d）\n"
	msgRFPolicy         = "\n射频策略问题（%d）\n"
	msgRoamPingPong     = "乒乓漫游：%d / %d 个终端（近 %s）\n"
	msgRoamSticky       = "疑似粘滞终端（%d）\n"
	msgNoTrack          = "没有 %q 的漫游轨迹；用 wireless watch 积累，或加 --live 读取 AC 漫游记录\n"
	msgTrackTitle       = "== %s：%d 次采样，跨度 %s，事件 %d ==\n"
	msgTrackPingPong    = "乒乓漫游：%s 往返 %d 次，最快 %s\n"
	msgTrackSparse      = "采样间隔过大，可能漏掉乒乓；缩短 watch 间隔\n"
	msgWatchRound       = "第 %d 轮：%d 台控制器，%d 台完整，耗时 %s\n"
	msgWatchFailed      = "第 %d 轮失败：%v\n"
	msgNoHistory        = "提示：没有漫游轨迹，乒乓漫游未检查；运行 wireless watch 或定时 collect --dimension clients 积累轨迹\n\n"
	msgFactors          = "评分    %s\n"
	msgFinding          = "  [%s] %-4s %s\n"
	msgAPTitle          = "== AP %s @ %s ==\n"
	msgAPInfo           = "状态 %s  型号 %s  序列号 %s  IP %s  MAC %s  组 %s\n版本 %s  在线 %s  系统运行 %s  重启原因 %s  供电 %s  Echo 丢失 %d/%d\n"
	msgAPClientsTitle   = "终端（%d，按 RSSI 升序）\n"
	msgStatsTitle       = "统计\n"
	msgSSIDTitle        = "\nSSID 分布\n"
	msgHealthDetailHint = "\n逐条明细：wireless health --detail（可加 -c 限定控制器）\n"
	msgHealthNone       = "未发现问题（%d 条规则运行，%d 条跳过）\n"
	msgHealthSkipped    = "\n跳过的规则（证据不完整）：%s\n"
	msgConfirmLead      = "即将执行 %d 项变更，确认请输入下面的确认串"
	msgAborted          = "输入不匹配，已取消\n"
	msgNeedTTY          = "非交互环境需要 --yes 才能执行变更\n"
	msgProgressStart    = "采集 %s …\n"
	msgProgressDone     = "完成 %s：%s（%s）\n"
)

// outcomeWords name execution results.
var outcomeWords = map[string]string{
	"configuration_verified": "已生效并回读确认", "failed": "失败（未下发或前置条件不满足）",
	"uncertain": "不确定（可能已下发，请人工核对）", "executing": "执行中断", "confirmed": "未开始",
}

// kindWords name the object kinds of health subjects.
var kindWords = map[string]string{
	"ap": "AP", "radio": "射频", "client": "终端", "template": "模板", "group": "AP组", "band": "频段",
	"ip": "IP", "policy": "策略",
}

// policyShort names radio policy problems in summaries.
var policyShort = map[string]string{
	"anti_sticky_above_reject": "anti-sticky 高于接入拒绝阈值", "power_24_above_5": "2.4G 功率高于 5G", "wide_24": "2.4G 40MHz",
}

// statsWords name authentication statistics dimensions.
var statsWords = map[string]string{"type": "类型", "ssid": "SSID", "domain": "认证域", "vlan": "授权 VLAN"}

// wordYes marks a true flag in tables.
const wordYes = "是"

// eventWords name roaming events.
var eventWords = map[roam.EventKind]string{
	roam.EventRoam: "漫游", roam.EventInterAC: "跨 AC 漫游", roam.EventReassoc: "重关联",
}

// levelWords are the bracketed level labels of diagnosis findings.
var levelWords = map[string]string{"ok": "正常", "info": "提示", "warn": "警告", "fail": "故障"}

// layerWords name diagnosis layers.
var layerWords = map[string]string{
	"association": "关联", "radio": "射频", "auth": "认证", "address": "地址", "control": "管控", "ap": "AP",
}

// severityWords name health severities.
var severityWords = map[string]string{"info": "提示", "low": "低", "medium": "中", "high": "高", "critical": "严重"}

// statusWords name evidence statuses.
var statusWords = map[string]string{
	"complete": "完整", "partial": "部分", "failed": "失败", "unsupported": "不支持", "not_requested": "未采集",
}

// defaultLimit is how many rows a list shows unless --limit says otherwise.
const defaultLimit = 50

// Verdict fragments.
const (
	verdictQuality   = "质量 %s(%d)"
	verdictUnscored  = "质量 未知（无信号数据）"
	verdictCause     = "主因 %s"
	verdictSticky    = "疑似粘滞(%s)"
	verdictPingPong  = "乒乓漫游"
	verdictSeparator = "｜"
)

// factorWords name quality factors.
var factorWords = map[quality.Factor]string{
	quality.FactorSignal: "信号", quality.FactorEfficiency: "速率", quality.FactorAirtime: "空口",
	quality.FactorNoise: "噪声", quality.FactorLoad: "负载",
}

// Freshness banner.
const (
	bannerHead          = "数据：%d 台 AC，最旧 %s"
	bannerStale         = "，%d 台已过有效期"
	bannerSep           = "｜"
	bannerFailed        = "%s 刷新失败（%s），使用 %s 的缓存"
	bannerNotConfigured = "%s 未在配置中，无法刷新"
	bannerOffline       = "离线模式"
	bannerNoLogin       = "未配置设备凭据，仅用缓存"
	bannerLive          = "已实时刷新"
	ageUnknown          = "未知"
	ageJustNow          = "刚刚"
	ageMinutes          = "%d 分钟前"
	ageHours            = "%d 小时前"
	ageDays             = "%d 天前"
)

// Help groups and status labels.
const (
	titleFind         = "定位查询："
	titleAnalyze      = "诊断分析："
	titleCache        = "采集与缓存："
	titleAction       = "处置："
	statusController  = "控制器"
	statusClients     = "终端"
	statusSessions    = "认证会话"
	statusAPs         = "AP/BSS"
	statusConflicts   = "冲突/黑名单"
	statusConfig      = "配置"
	statusLastRefresh = "最近刷新"
	statusStaleMark   = "*"
	statusConfigLine  = "配置文件  %s\n"
	statusNoConfig    = "未找到（使用默认值；示例见 examples/wireless.yml）"
	statusLoginLine   = "设备凭据  %s，可刷新控制器 %d 台\n"
	statusCacheLine   = "本地缓存  %s（模式 %s，单次刷新预算 %s，失败后 %s 内不重试）\n"
	statusSourceLine  = "离线来源  %s（每次只读导入，较新者胜）\n"
	statusJournalLine = "漫游轨迹  %s 至 %s（%d 天）\n"
	statusNoJournal   = "漫游轨迹  无（运行 wireless watch 积累）\n"
	wordConfigured    = "已配置"
	wordMissing       = "未配置"
)

// Error wording.
const (
	errPrefix       = "错误："
	errEmptyQuery   = "错误：查询内容为空，请输入 IP、MAC、账号或 AP 名"
	errInvalidMAC   = "错误：无法识别的 MAC 地址；支持 aabb-ccdd-eeff、aa:bb:cc:dd:ee:ff、aabb.ccdd.eeff 等写法"
	errNoLogin      = "错误：未配置设备凭据：设置 NC_H3C_WIRELESS_USERNAME/PASSWORD（或 NC_DEVICE_*），可写在配置同目录的 0600 .env 中"
	errConfigPrefix = "配置错误："
	errUsagePrefix  = "参数错误："
	errUsageHint    = "（加 --help 查看用法）"
)

// panelWidth is the width long finding lines wrap at.
const panelWidth = 110
