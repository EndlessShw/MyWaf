// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/20 16:15
// @Description    : 常见的错误常量
// -------------------------------------------
package MyWaf

const (
	// 考虑到存放到 json 中，信息中包含特殊符号可能会妨碍 json 解析，因此用双引号包裹
	errLogFile        = "error opening log file: \"%s\""
	errCompileDSLExpr = "error compiling DSL expression: \"%s\"; Error is %v"
	errFindFile       = "error finding file: \"%s\"; Error is %v"
	errOpenFile       = "error while opening file: \"%s\"; Error is %v"

	errReadFile        = "error while reading file: \"%s\"; Error is %v"
	errUnmarshalYAML   = "error while unmarshalling YAML: \"%s\"; Error is %v"
	errInvalidYAMLRule = "invalid YAML rule: \"%v\"; Error is %v"
	errConvYAML        = "failed to convert YAML rule; Error is %v"

	errInvalidRuleName = "Rule name can't be blank! Please check out your rule config."
	errInvalidRuleCond = "invalid logical operator for \"%s\" rule Condition, valid values are \"and\" or \"or\", given is: %s"
	errRegPattern      = "error while compiling regex pattern: \"%s\", Error is %v"
	errResources       = "error while getting teler resources: %s"

	errBadIPAddress        = "bad IP address"
	errBadReferrer         = "bad referrer"
	errBadCrawler          = "bad crawler"
	errDirectoryBruteforce = "directory brute force"
	errMaliciousCommand    = "malicious command"
)
