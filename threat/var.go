// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 15:22
// @Description    : 存放 Threat 相关的变量
// -------------------------------------------
package threat

var (
	DbFilename     = "myWaf.tar.zst"
	MD5SumFilename = "MD5SUMS"
	DbURL          = RepoURL + "/raw/master/db/" + DbFilename
	MD5SumURL      = RepoURL + "/raw/master/db/" + MD5SumFilename
)

// str 将 Threat 转换成 string
var str = map[Threat]string{
	Undefined:           "Undefined",
	Custom:              "Custom",
	CommonWebAttack:     "CommonWebAttack",
	CVE:                 "CVE",
	BadIPAddress:        "BadIPAddress",
	BadReferrer:         "BadReferrer",
	BadCrawler:          "BadCrawler",
	DirectoryBruteforce: "DirectoryBruteforce",
	MaliciousCommand:    "MaliciousCommand",
}

// file 中包含 Threat 和威胁库文件的对应关系
var file = map[Threat]string{
	CommonWebAttack:     "common-web-attacks.json",
	CVE:                 "cves.json",
	BadIPAddress:        "bad-ip-addresses.txt",
	BadReferrer:         "bad-referrers.txt",
	BadCrawler:          "bad-crawlers.txt",
	DirectoryBruteforce: "directory-bruteforces.txt",
	MaliciousCommand:    "malicious-commands.txt",
}

var InternalThreatList = []Threat{CommonWebAttack,
	CVE,
	BadIPAddress,
	BadReferrer,
	BadCrawler,
	DirectoryBruteforce,
	MaliciousCommand}
