// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/15 22:02
// @Description    : Threat 中涉及的常量
// -------------------------------------------
package threat

// point Go 中常量是驼峰命名法，不是全大写
const (
	CachePath    = "/MyWaf/"
	ThreatPath   = CachePath + "threat/"
	MyWafRes     = "myWaf-resources"
	TmpDirSuffix = "." + MyWafRes + "-%s"
	RepoURL      = "https://github.com/EndlessShw/waf-resource"
)
