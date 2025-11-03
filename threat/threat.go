// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/13 18:09
// @Description    : 威胁类型类
// -------------------------------------------
package threat

type Threat int8

const (
	// Undefined 是未定义的攻击类型
	Undefined Threat = iota - 1

	// Custom 表示使用者自定义的类型
	Custom

	// CommonWebAttack 代表常见的 Web 攻击类型
	CommonWebAttack

	// CVE 是常见的 Web CVE
	CVE

	// BadIPAddress 请求 IP 为一些恶意 IP
	// TODO 恶意 IP 的判断可以去接一些情报威胁平台的 API 来辅助判断
	BadIPAddress

	// BadReferrer 和 BadIPAddress 相似，有时请求的 Referrer 是恶意域名，这种的也可以直接排除
	BadReferrer

	// BadCrawler 指的是 UA 头为一些爬虫的特征
	BadCrawler

	// DirectoryBruteforce 表示敏感文件目录读取
	DirectoryBruteforce

	// MaliciousCommand 表示恶意的命令执行
	MaliciousCommand
)
