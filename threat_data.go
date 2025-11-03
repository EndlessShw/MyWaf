// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 23:50
// @Description    : ThreatData 为 threat.Threat 的上层装饰类，存放每种攻击的规则以及相关的配置等
// -------------------------------------------
package MyWaf

import (
	"MyWaf/entity"
	"MyWaf/threat"
	"github.com/dwisiswant0/pcregexp/pkg/regexp"
)

type ThreatData struct {

	// data 存放各种攻击的规则（单纯的字符串，也就是 raw）
	data map[threat.Threat]string

	// 根据不同攻击类型，规则解析的方式也有所不同，提前存储这些规则的解析形式

	// cwa 为 CommonWebAttack 所需要的结构体，其中的 Filters Struct Slice 存放所有的规则
	cwa *entity.CWA

	// cve 为 CVE 所需要的结构体，其中的 Templates Struct Slice 存放所有的规则
	cve *entity.CVE

	// threat.BadIPAddress 每一行就是一个 IP，不需要额外的种类来装饰，BadReferrer、DirectoryBruteforce 也是。

	// badCrawler 每行存放的是针对域名的正则表达式
	badCrawler []*regexp.Regexp

	// maliciousCommand 每行存放的是针对恶意命令的正则表达式
	maliciousCommand []*regexp.Regexp
}
